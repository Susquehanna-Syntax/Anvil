package scanctl

// Regression tests for REVIEW-O.4, one test per finding, each named for the
// finding it closes.
//
// They are in their own file for the reason internal/record keeps
// critique03_regression_test.go separate: a defect that was found once is a
// defect that can return, and a test whose name does not say which defect it
// guards gets deleted during the next refactor by someone who cannot tell what
// it was protecting.
//
// EVERY TEST HERE RECONSTRUCTS THE CRITIC'S OWN PROBE, not a convenient
// approximation of it. Where the probe's construction has become impossible to
// express — the two blockers both rested on assigning to a field that no longer
// exists — the test asserts the impossibility instead, and says so, because
// "you cannot write that any more" is the actual fix and needs to be the thing
// that fails if somebody re-exports the field.
//
// The critic's own summary of why the green suite proved nothing: "three of the
// seven confirmed defects are reached only by holding an AuditRecord across a
// state change, and every test in the package constructs a fresh one and
// immediately consumes it." So these tests all hold a record across something.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/handoff"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// O4-B1 — the read gate must be asked about the LIVE audit
// ---------------------------------------------------------------------------

// Probe P3, reconstructed: Begin, one SAST finding, seal SAST, KEEP the returned
// record, advance the clock past the 8h claim window, tick on a different copy,
// then read through the stale record.
//
// The critic's result was "1 finding(s) read out of an EXPIRED audit through the
// stale record; AuditRecord.Readable()=true, errors.Is(err, ErrHalfNotSealed)=false"
// while record.Sealer.ReadHalf on the same audit refused. The read surface is now
// Controller.Findings, which re-Inspects and goes through
// record.Sealer.ReadHalf, so the stale record supplies an audit id and nothing
// the gate could be misled by.
func TestFindingsAreGatedAgainstTheLiveAuditNotAHeldSnapshot(t *testing.T) {
	ctl, clk := newTestController(t, sastOnlyPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "P3")
	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfSast, finding("a")))
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))

	// The stale record: sealed SAST half, audit not yet expired, readable.
	stale := rec
	if got, err := ctl.Findings(stale, record.HalfSast); err != nil || len(got) != 1 {
		t.Fatalf("precondition: Findings before expiry = (%d, %v), want (1, nil)", len(got), err)
	}
	if !ctl.Readable(stale, record.HalfSast) {
		t.Fatal("precondition: the sealed SAST half must be readable before the window closes")
	}

	// The claim window closes, and the tick lands on a DIFFERENT copy — which
	// is the whole construction. `stale` still says sast_sealed.
	clk.set(8 * time.Hour)
	live := mustTransition(t, ctl, rec, TickEvent())
	if live.State != record.StateExpired {
		t.Fatalf("live State = %q, want %q", live.State, record.StateExpired)
	}
	if stale.State == record.StateExpired {
		t.Fatal("the held record was mutated; the probe needs it to be stale, and " +
			"AuditRecord is meant to be an immutable snapshot")
	}

	// THE FINDING. Reading through the stale record must be refused, with the
	// same error record.Sealer.ReadHalf gives, because it IS that error.
	got, err := ctl.Findings(stale, record.HalfSast)
	if !errors.Is(err, record.ErrHalfNotSealed) {
		t.Fatalf("Findings through a stale record on an EXPIRED audit = (%d findings, %v); "+
			"want a read-gate refusal (O4-B1)", len(got), err)
	}
	if got != nil {
		t.Errorf("a refused read returned %d findings; it must return nothing", len(got))
	}
	if ctl.Readable(stale, record.HalfSast) {
		t.Error("Readable said true through a stale record on an expired audit (O4-B1)")
	}

	// And it agrees with the Sealer, asked directly. The critic's probe is
	// exactly the observation that these two disagreed.
	_, sealerErr := ctl.Sealer().ReadHalf(stale.AuditID, record.HalfSast)
	if (err == nil) != (sealerErr == nil) {
		t.Errorf("Controller.Findings and record.Sealer.ReadHalf disagree: %v vs %v", err, sealerErr)
	}
}

// The other half of O4-B1's fix: there is no snapshot-scoped read surface left
// to reach for. A future author who adds `func (r AuditRecord) Findings(...)`
// back re-opens the defect at the moment they add it, and this fails then.
//
// It is a reflection test rather than a source guard because the property is
// about the TYPE's method set, which is what a caller sees and what the mistake
// consists of.
func TestAuditRecordExposesNoUngatedReadSurface(t *testing.T) {
	banned := map[string]string{
		"Findings": "results must come from Controller.Findings, which gates against the live audit",
		"Readable": "readability must come from Controller.Readable, for the same reason",
		"HalfSeal": "a seal assembled from a snapshot's own fields is CRITIQUE O.4 blocker 1; " +
			"record.Sealer mints the only seals the gate will believe",
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(AuditRecord{}),
		reflect.TypeOf(&AuditRecord{}),
		reflect.TypeOf(HalfRecord{}),
	} {
		for i := 0; i < typ.NumMethod(); i++ {
			name := typ.Method(i).Name
			if why, bad := banned[name]; bad {
				t.Errorf("%s has method %s: %s", typ, name, why)
			}
		}
	}

	// The findings themselves stay unexported, so there is no ungated field
	// read either. FindingCount is the one deliberate exception and is
	// documented as metadata rather than results.
	half := reflect.TypeOf(HalfRecord{})
	for i := 0; i < half.NumField(); i++ {
		f := half.Field(i)
		if f.Type == reflect.TypeOf([]record.Result(nil)) && f.IsExported() {
			t.Errorf("HalfRecord.%s exports a []record.Result; an exported results slice is an ungated read", f.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// O4-B2 — clock 3 must not be movable by assignment
// ---------------------------------------------------------------------------

// Probe P10's first half: hold a record, move the DAST deadline out to t+7h59m,
// tick at t+5h, and observe that the forced seal does not fire. The critic's
// result was "dast=running dastStatus=running state=collecting" with the Sealer
// still holding the true dast_deadline_seconds=14400.
//
// The assignment the probe made is now a compile error, so the test makes the
// STRONGEST assignment still available — replacing the whole Deadlines value
// with one built by a different, much longer policy — and asserts clock 3 fires
// on the Sealer's schedule regardless.
func TestClockThreeCannotBeMovedByAssignment(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "P10")
	rec = mustTransition(t, ctl, rec, DastOutcomeEvent(bootedCleanOutcome()))

	at, ok := rec.Deadlines.DastDeadline()
	if !ok || !at.Equal(baseTime.Add(4*time.Hour)) {
		t.Fatalf("precondition: DastDeadline = (%s, %v), want (%s, true)", at, ok, baseTime.Add(4*time.Hour))
	}

	// The attack, in the only shape the type still permits: build a Deadlines
	// whose DAST clock is at t+7h30m and put it on the record.
	sevenHalf := int((7*time.Hour + 30*time.Minute).Seconds())
	slow, err := DeadlinePolicy{DastEnabled: true, DastDeadlineSeconds: &sevenHalf}.At(baseTime)
	if err != nil {
		t.Fatalf("building the attacker's Deadlines: %v", err)
	}
	rec.Deadlines = slow
	if at, _ := rec.Deadlines.DastDeadline(); !at.Equal(baseTime.Add(7*time.Hour + 30*time.Minute)) {
		t.Fatalf("the test did not manage to move the record's own copy: %s", at)
	}

	// THE FINDING. At the REAL deadline the half is forced terminal anyway,
	// because record.Sealer.SealDastIfDeadlineDue decides against the audit's
	// own startedAt + dast_deadline_seconds, which BeginAudit fixed.
	clk.set(4 * time.Hour)
	rec = mustTransition(t, ctl, rec, TickEvent())
	if rec.Dast.Status != record.HalfStatusTimedOut {
		t.Fatalf("Dast.Status = %q at the real clock 3, want %q; clock 3 was moved by assignment (O4-B2)",
			rec.Dast.Status, record.HalfStatusTimedOut)
	}
	if rec.DastStatus != record.DastStatusTimedOut {
		t.Errorf("DastStatus = %q, want %q", rec.DastStatus, record.DastStatusTimedOut)
	}
	// Probe P10's control, restated: clock 2 was never foolable, and still is
	// not. Pushing the whole Deadlines out does not postpone expiry.
	clk.set(8 * time.Hour)
	rec = mustTransition(t, ctl, rec, TickEvent())
	if rec.State != record.StateExpired {
		t.Errorf("State = %q at the claim deadline, want %q", rec.State, record.StateExpired)
	}
}

// The structural half of O4-B2. The critic's argument was that Deadlines'
// contract — "THE ONLY WAY TO CHANGE A DEADLINE IS TO START A NEW SCAN" — was
// enforced against METHODS and not against FIELDS, and that the field was
// exported. This asserts the enforcement rather than the prose.
func TestDeadlinesExposeNoAssignableClock(t *testing.T) {
	typ := reflect.TypeOf(Deadlines{})
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("Deadlines.%s is exported: a deadline a caller can assign to is CRITIQUE O.4 blocker 2, "+
				"and 'there is no method on it that mutates anything' is an argument about methods", f.Name)
		}
		// No pointer fields either: two copies of a Deadlines sharing a
		// *time.Time would be an assignable clock reached one dereference
		// further away.
		if k := typ.Field(i).Type.Kind(); k == reflect.Pointer || k == reflect.Slice || k == reflect.Map {
			t.Errorf("Deadlines.%s is a %s; a copy would share it, which is the same defect one indirection out",
				typ.Field(i).Name, k)
		}
	}

	// And there is no due-check here to be fooled. Clock 3's decision belongs to
	// record.Sealer.SealDastIfDeadlineDue; a predicate on this type would be a
	// third owner over an input nobody re-reads.
	for i := 0; i < typ.NumMethod(); i++ {
		if name := typ.Method(i).Name; name == "DastDeadlineElapsed" {
			t.Error("Deadlines.DastDeadlineElapsed is back: clock 3's due-check belongs to " +
				"record.Sealer.SealDastIfDeadlineDue, which owns the substrate (O4-B2)")
		}
	}
}

// ---------------------------------------------------------------------------
// O4-M1 — a redelivered seal event must not bump audit_version
// ---------------------------------------------------------------------------

// Probe P1: seal the same half with the same status three times. The critic
// measured version 2 -> 3 -> 4 with record.Sealer.SealHalf returning nil each
// time, having treated the second and third as idempotent no-ops.
//
// The cost is paid in two other packages: every bump obliges S6's queue re-cut
// (R.11), and internal/handoff re-checks audit_record.audit_version on every
// mutation and answers handoff.ErrRecordVersionChanged, so a duplicate delivery
// invalidated every in-flight lease on the audit.
func TestARedeliveredSealEventDoesNotBumpTheVersion(t *testing.T) {
	ctl, _ := newTestController(t, sastOnlyPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "P1")

	first := mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
	if !VersionBumped(rec, first) {
		t.Fatalf("the FIRST seal must publish: version %d -> %d", rec.Version, first.Version)
	}
	sealedAt := first.Sast.SealedAt
	if sealedAt == nil {
		t.Fatal("precondition: a sealed half carries anvil/sealedAt")
	}

	// The redeliveries. At-least-once delivery, a retried store write, or two
	// workers fanning the same seal in all produce this.
	prev := first
	for i := 0; i < 3; i++ {
		again, err := ctl.Transition(prev, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
		if err != nil {
			t.Fatalf("redelivery %d: %v", i, err)
		}
		if VersionBumped(prev, again) {
			t.Fatalf("redelivery %d bumped audit_version %d -> %d; the Sealer treated it as a no-op "+
				"and a bump re-cuts the queue (O4-M1)", i, prev.Version, again.Version)
		}
		if again.Sast.SealedAt == nil || !again.Sast.SealedAt.Equal(*sealedAt) {
			t.Errorf("redelivery %d moved anvil/sealedAt: %v -> %v", i, sealedAt, again.Sast.SealedAt)
		}
		prev = again
	}

	// NEGATIVE CONTROL. The suppression must be keyed on "nothing changed", not
	// on "the event was a seal": a seal that DOES change the record still
	// publishes. Without this the test above would pass if publication had been
	// removed from the seal path entirely.
	dast, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec2 := mustBegin(t, dast, "P1-control")
	rec2 = mustTransition(t, dast, rec2, DastOutcomeEvent(bootedCleanOutcome()))
	before := rec2
	rec2 = mustTransition(t, dast, rec2, SealHalfEvent(record.HalfDast, record.HalfStatusSealed))
	if !VersionBumped(before, rec2) {
		t.Error("a seal that really sealed did not publish; the O4-M1 fix has suppressed real bumps too")
	}
}

// A tick that finds nothing to do is the same class of no-op and must not
// publish either. Daemons wake on a schedule, so this is the highest-frequency
// path in the system and a spurious bump here would re-cut the queue every wake.
func TestAnIdleTickDoesNotBumpTheVersion(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "idle-ticks")

	for i := 1; i <= 5; i++ {
		clk.set(time.Duration(i) * time.Minute)
		before := rec
		rec = mustTransition(t, ctl, rec, TickEvent())
		if VersionBumped(before, rec) {
			t.Fatalf("tick %d bumped audit_version %d -> %d with nothing due", i, before.Version, rec.Version)
		}
	}
}

// ---------------------------------------------------------------------------
// O4-M2 — the write guards must consult the Sealer, not the caller's snapshot
// ---------------------------------------------------------------------------

// Probe P2: hold a record from before expiry and push findings and correlation
// through it. The critic's result was "findings accepted onto an EXPIRED audit
// via a stale record; projected state=expired, buffered sast findings=1" and the
// same for correlation — with acceptsWrites' own doc naming that as the thing it
// existed to prevent.
func TestWriteGuardsConsultTheSealerNotTheCallersSnapshot(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "P2")
	rec = mustTransition(t, ctl, rec, DastOutcomeEvent(bootedCleanOutcome()))
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfDast, record.HalfStatusSealed))

	stale := rec // state = dast_sealed, and it will stay saying that
	clk.set(8 * time.Hour)
	live := mustTransition(t, ctl, rec, TickEvent())
	if live.State != record.StateExpired || stale.State != record.StateDastSealed {
		t.Fatalf("precondition: live=%q stale=%q, want %q and %q",
			live.State, stale.State, record.StateExpired, record.StateDastSealed)
	}

	for _, tc := range []struct {
		name string
		ev   Event
	}{
		{"findings", FindingsEvent(record.HalfSast, finding("late"))},
		{"correlation", CorrelateEvent(record.Correlation{ClusterID: "c1", Role: record.HalfSast})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ctl.Transition(stale, tc.ev)
			if !errors.Is(err, record.ErrAuditTerminal) {
				t.Fatalf("%s onto an EXPIRED audit via a stale record = %v, want record.ErrAuditTerminal (O4-M2)",
					tc.name, err)
			}
			if out.AuditID != stale.AuditID || out.Version != stale.Version {
				t.Errorf("a refused transition did not return the input unchanged: %+v", out)
			}
		})
	}

	// Nothing landed. Combined with O4-B1, findings buffered after expiry would
	// also have been readable through the same stale record.
	current, ok := ctl.Record(stale.AuditID)
	if !ok {
		t.Fatal("Record: the audit vanished")
	}
	if current.Sast.FindingCount() != 0 {
		t.Errorf("Sast.FindingCount = %d after two refused writes, want 0", current.Sast.FindingCount())
	}
	if len(current.Correlation) != 0 {
		t.Errorf("Correlation has %d clusters after a refused write, want 0", len(current.Correlation))
	}
}

// ---------------------------------------------------------------------------
// O4-M3 — concurrent fan-in must not lose findings
// ---------------------------------------------------------------------------

// Probe P11: eight workers x three DAST findings, all transitioning the SAME
// record. The critic measured "the surviving record holds 3 ... PROBE HIT: 21 of
// 24 findings lost", on a security scanner, silently — while the type's doc
// called the failure mode "a skipped version bump, not a corrupt lifecycle".
//
// Every goroutine deliberately passes the same STALE snapshot, because that is
// what a fan-in caller has: eight workers that each took the record once and are
// now reporting independently. Serialising Transition externally would not have
// saved the old design, which is why the fix was to move the buffers onto the
// Controller rather than to write a warning.
//
// -race cannot run on the Windows dev host; CI runs this on ubuntu-latest, where
// this repository has already had one concurrency bug that passed every local
// run (internal/handoff/reaper.go:415).
func TestConcurrentFanInLosesNoFindings(t *testing.T) {
	const (
		workers        = 8
		perWorker      = 3
		wantTotal      = workers * perWorker
		bigEnoughForN  = 1000
		longEnoughForM = time.Hour
	)

	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{
		DastFindings: bigEnoughForN, Interval: longEnoughForM,
	})
	shared := mustBegin(t, ctl, "P11")
	shared = mustTransition(t, ctl, shared, DastOutcomeEvent(bootedCleanOutcome()))

	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				// The same stale record every time, from every goroutine.
				if _, err := ctl.Transition(shared, FindingsEvent(
					record.HalfDast, finding(fmt.Sprintf("w%d/%d", w, i)))); err != nil {
					errs <- fmt.Errorf("worker %d finding %d: %w", w, i, err)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	got, ok := ctl.Record(shared.AuditID)
	if !ok {
		t.Fatal("Record: the audit vanished")
	}
	if n := got.Dast.FindingCount(); n != wantTotal {
		t.Fatalf("%d of %d DAST findings survived concurrent fan-in; %d were lost (O4-M3)",
			n, wantTotal, wantTotal-n)
	}
	if got.PendingDastFindings != wantTotal {
		t.Errorf("PendingDastFindings = %d, want %d: the watermark counter must count every arrival too",
			got.PendingDastFindings, wantTotal)
	}
}

// The version counter must count publications rather than the last writer's
// opinion of how many there were. With N=1 every finding publishes, so the
// version after the fan-in is exactly 1 + the number of findings.
func TestConcurrentFanInCountsEveryPublication(t *testing.T) {
	const workers, perWorker = 6, 4

	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 1, Interval: time.Hour})
	shared := mustBegin(t, ctl, "P11-versions")
	shared = mustTransition(t, ctl, shared, DastOutcomeEvent(bootedCleanOutcome()))
	start := shared.Version

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if _, err := ctl.Transition(shared, FindingsEvent(
					record.HalfDast, finding(fmt.Sprintf("w%d/%d", w, i)))); err != nil {
					t.Errorf("worker %d finding %d: %v", w, i, err)
				}
			}
		}(w)
	}
	wg.Wait()

	got, _ := ctl.Record(shared.AuditID)
	if want := start + workers*perWorker; got.Version != want {
		t.Errorf("Version = %d after %d publishing transitions, want %d; bumps were lost to the "+
			"last-writer-wins counter (O4-M3)", got.Version, workers*perWorker, want)
	}
}

// O4-m4: SetClock wrote c.now with no lock while Transition, applyTick, publish
// and NextWake read it. record.Sealer.SetClock takes its mutex for the same
// assignment. This is the probe; the race detector on CI is what makes it
// meaningful, and locally it at least proves the two paths do not deadlock
// against each other under the documented lock order.
func TestSetClockIsSafeAgainstConcurrentTransitions(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 1000, Interval: time.Hour})
	rec := mustBegin(t, ctl, "reclocking")

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			// A daemon re-clocking at runtime is the case the finding names.
			ctl.SetClock((&testClock{at: baseTime.Add(time.Duration(i) * time.Minute)}).now)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if _, err := ctl.Transition(rec, FindingsEvent(record.HalfDast, finding("f"))); err != nil {
				t.Errorf("Transition: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			ctl.NextWake(rec)
			if _, err := ctl.Transition(rec, TickEvent()); err != nil {
				t.Errorf("tick: %v", err)
			}
		}
	}()
	wg.Wait()

	// Leave the controller on a determinate clock for anything that follows.
	ctl.SetClock(clk.now)
	if _, ok := ctl.Record(rec.AuditID); !ok {
		t.Fatal("the audit did not survive concurrent re-clocking")
	}
}

// ---------------------------------------------------------------------------
// O4-M5 — clock 2's two sweeps must be drivable together
// ---------------------------------------------------------------------------

// The critic's grep found ExpireClaimTimeouts named in four comments in this
// package and called from nowhere in the tree, so in-memory expiry and durable
// expiry were never driven together: the controller marks an audit `expired`
// while its handoff rows stay 'ready' and keep being leased (§6 ruling G10).
//
// This drives the wiring end to end against the real schema: a ready finding on
// an audit whose claim window has closed must reach 'expired' through the
// Consumer, and must do so through Reap — the entry point that runs BOTH sweeps
// in the reaper's own order.
func TestConsumerDrivesTheStoreSideClaimTimeoutSweep(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	audit := f.sealedAudit()
	_, row := f.enqueue(90, record.ConsumptionClassStaticOnly, audit, 3)

	if got := f.rowState(row.HandoffID); got != record.HandoffStateReady {
		t.Fatalf("precondition: row state = %q, want %q", got, record.HandoffStateReady)
	}

	// Inside the claim window nothing is swept. A sweep that expired a live
	// claim window would be a different and worse bug.
	f.clock.advance(hfPolicy().ClaimTimeout() - time.Minute)
	report, err := f.c.Reap()
	if err != nil {
		t.Fatalf("Reap inside the window: %v", err)
	}
	if len(report.Expired) != 0 {
		t.Fatalf("Reap expired %d rows inside the claim window", len(report.Expired))
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateReady {
		t.Fatalf("row state = %q inside the window, want %q", got, record.HandoffStateReady)
	}

	// Past `audit_record.deadline_at` the store side agrees with what
	// record.Sealer.ExpireIfDue would say in memory.
	f.clock.advance(2 * time.Minute)
	report, err = f.c.Reap()
	if err != nil {
		t.Fatalf("Reap past the deadline: %v", err)
	}
	if len(report.Expired) != 1 || report.Expired[0].HandoffID != row.HandoffID {
		t.Fatalf("Reap.Expired = %+v, want exactly the one row (O4-M5)", report.Expired)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateExpired {
		t.Fatalf("row state = %q after the claim window closed, want %q; the store-side sweep "+
			"is still unwired and the row would be re-leased forever (O4-M5)", got, record.HandoffStateExpired)
	}

	// The narrow entry point is reachable too, for a caller that owns the
	// ordering itself, and it is idempotent.
	if _, err := f.c.ExpireClaimTimeouts(); err != nil {
		t.Fatalf("ExpireClaimTimeouts: %v", err)
	}
}

// Reap must run BOTH sweeps, in the order reaper.go argues for: a crashed
// holder's row has to be reclaimed out of 'leased' before the claim-timeout
// sweep can see it as 'ready' and expire it. Running only the lease sweep, or
// running them in the other order, leaves the row alive for a whole extra
// interval — and running only the timeout sweep never sees it at all.
func TestReapRunsTheLeaseSweepBeforeTheClaimTimeoutSweep(t *testing.T) {
	f := newHFFixture(t, handoff.Options{Lease: 20 * time.Minute})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(91, record.ConsumptionClassStaticOnly, audit, 3)

	if _, err := f.c.Claim(fingerprint, "worker-doomed"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateLeased {
		t.Fatalf("precondition: row state = %q, want %q", got, record.HandoffStateLeased)
	}

	// The holder is OOM-killed AND the claim window closes: both clocks are due
	// on the same wake, which is the case the ordering exists for.
	f.clock.advance(hfPolicy().ClaimTimeout() + time.Minute)

	report, err := f.c.Reap()
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(report.Reclaimed) != 1 {
		t.Fatalf("Reap.Reclaimed = %+v, want the crashed holder's row", report.Reclaimed)
	}
	if len(report.Expired) != 1 {
		t.Fatalf("Reap.Expired = %+v, want the same row expired in the SAME sweep; the two sweeps "+
			"ran in the wrong order or only one of them ran", report.Expired)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateExpired {
		t.Fatalf("row state = %q, want %q after one Reap", got, record.HandoffStateExpired)
	}
}

// Run is the loop a daemon starts. It must sweep, hand each report to observe,
// and return ctx.Err() on cancellation rather than reporting the cancellation as
// a sweep failure.
func TestConsumerRunSweepsUntilCancelled(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	audit := f.sealedAudit()
	_, row := f.enqueue(92, record.ConsumptionClassStaticOnly, audit, 3)
	f.clock.advance(hfPolicy().ClaimTimeout() + time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	swept := make(chan handoff.ReapReport, 8)
	done := make(chan error, 1)
	go func() {
		done <- f.c.Run(ctx, time.Millisecond, func(r handoff.ReapReport, err error) {
			if err != nil {
				t.Errorf("sweep error: %v", err)
				return
			}
			select {
			case swept <- r:
			default:
			}
		})
	}()

	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-swept:
			if len(r.Expired) == 0 {
				continue
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Errorf("Run returned %v, want context.Canceled", err)
			}
			if got := f.rowState(row.HandoffID); got != record.HandoffStateExpired {
				t.Errorf("row state = %q, want %q", got, record.HandoffStateExpired)
			}
			return
		case <-deadline:
			cancel()
			<-done
			t.Fatal("Run never swept the due row within 10s")
		}
	}
}

// ---------------------------------------------------------------------------
// O4-m1 — a refused transition must change nothing
// ---------------------------------------------------------------------------

// The finding: applyTick sealed the DAST half and bumped the version, and only
// afterwards called something that could return an error — on which path the
// bump was discarded while the Sealer kept the seal, so "A refused transition
// changes nothing, in the Sealer or in the returned value" was not total.
//
// The fix is structural: Transition applies every event to a working copy and
// commits with one assignment below every error return. This asserts the
// resulting property over every refusal the package can actually produce, from
// every state, by comparing the CONTROLLER's own view before and after — which
// is the half the old test could not see, because it only compared the returned
// value.
func TestARefusedTransitionLeavesTheControllerUnchanged(t *testing.T) {
	type refusal struct {
		name string
		from record.State
		ev   Event
	}
	refusals := []refusal{
		{"seal as running", record.StateCollecting, SealHalfEvent(record.HalfSast, record.HalfStatusRunning)},
		{"seal an unknown half", record.StateCollecting, SealHalfEvent(record.Half("both"), record.HalfStatusSealed)},
		{"re-seal differently", record.StateSastSealed, SealHalfEvent(record.HalfSast, record.HalfStatusFailed)},
		{"seal a consumed audit", record.StateConsumed, SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
		{"seal an expired audit", record.StateExpired, SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
		{"consume too early", record.StateSastSealed, ConsumeEvent()},
		{"findings on a sealed half", record.StateSastSealed, FindingsEvent(record.HalfSast, finding("late"))},
		{"findings on an expired audit", record.StateExpired, FindingsEvent(record.HalfSast, finding("late"))},
		{"empty findings", record.StateCollecting, FindingsEvent(record.HalfSast)},
		{"empty correlation", record.StateCollecting, CorrelateEvent()},
		{"correlation on a consumed audit", record.StateConsumed, CorrelateEvent(record.Correlation{ClusterID: "c"})},
		{"outcome on a sealed half", record.StateDastSealed, DastOutcomeEvent(bootedCleanOutcome())},
		{"the zero event", record.StateCollecting, Event{}},
		{"an invented kind", record.StateCollecting, Event{Kind: EventKind("seal")}},
	}

	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
			rec, err := driveToState(t, ctl, clk, tc.from)
			if err != nil {
				t.Fatalf("driving to %q: %v", tc.from, err)
			}
			before, ok := ctl.Record(rec.AuditID)
			if !ok {
				t.Fatal("Record: the audit vanished")
			}

			if _, err := ctl.Transition(rec, tc.ev); err == nil {
				t.Fatalf("Transition(%s) from %q succeeded; this table is refusals only", tc.ev.Kind, tc.from)
			}

			after, ok := ctl.Record(rec.AuditID)
			if !ok {
				t.Fatal("Record: the audit vanished after a refusal")
			}
			if diff := describeDrift(before, after); diff != "" {
				t.Errorf("a refused transition changed the controller's own state: %s", diff)
			}
		})
	}
}

// describeDrift names the first field on which two projections of one audit
// disagree, or "" when they agree. It exists so a failure says WHICH field
// moved rather than dumping two structs.
func describeDrift(before, after AuditRecord) string {
	switch {
	case before.Version != after.Version:
		return fmt.Sprintf("Version %d -> %d", before.Version, after.Version)
	case before.State != after.State:
		return fmt.Sprintf("State %q -> %q", before.State, after.State)
	case before.Sast.Status != after.Sast.Status:
		return fmt.Sprintf("Sast.Status %q -> %q", before.Sast.Status, after.Sast.Status)
	case before.Dast.Status != after.Dast.Status:
		return fmt.Sprintf("Dast.Status %q -> %q", before.Dast.Status, after.Dast.Status)
	case before.DastStatus != after.DastStatus:
		return fmt.Sprintf("DastStatus %q -> %q", before.DastStatus, after.DastStatus)
	case before.Sast.FindingCount() != after.Sast.FindingCount():
		return fmt.Sprintf("Sast findings %d -> %d", before.Sast.FindingCount(), after.Sast.FindingCount())
	case before.Dast.FindingCount() != after.Dast.FindingCount():
		return fmt.Sprintf("Dast findings %d -> %d", before.Dast.FindingCount(), after.Dast.FindingCount())
	case len(before.Correlation) != len(after.Correlation):
		return fmt.Sprintf("correlation clusters %d -> %d", len(before.Correlation), len(after.Correlation))
	case before.PendingDastFindings != after.PendingDastFindings:
		return fmt.Sprintf("PendingDastFindings %d -> %d", before.PendingDastFindings, after.PendingDastFindings)
	case !before.PublishedAt.Equal(after.PublishedAt):
		return fmt.Sprintf("PublishedAt %s -> %s", before.PublishedAt, after.PublishedAt)
	case before.Deadlines != after.Deadlines:
		return "Deadlines moved"
	}
	return ""
}

// ---------------------------------------------------------------------------
// O4-m3 — the correlation contract, stated and tested
// ---------------------------------------------------------------------------

// The finding: applyCorrelation REPLACES rather than appends, research/21 §5's
// "populated as both sides land" reads incremental, and nothing said which
// contract R.12's correlator must honour. The contract is now written down on
// CorrelateEvent and on applyCorrelation; this is the two-batch case the critic
// asked for, asserted rather than left to the reader.
func TestACorrelationBatchReplacesTheWholeSet(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "correlation-batches")

	rec = mustTransition(t, ctl, rec, CorrelateEvent(
		record.Correlation{ClusterID: "c1", Role: record.HalfSast},
		record.Correlation{ClusterID: "c2", Role: record.HalfSast},
	))
	if len(rec.Correlation) != 2 {
		t.Fatalf("first batch: %d clusters, want 2", len(rec.Correlation))
	}

	// The second batch is the correlator's COMPLETE current answer, which
	// happens to include the first batch's clusters plus a DAST-side one.
	rec = mustTransition(t, ctl, rec, CorrelateEvent(
		record.Correlation{ClusterID: "c1", Role: record.HalfSast},
		record.Correlation{ClusterID: "c2", Role: record.HalfSast},
		record.Correlation{ClusterID: "c3", Role: record.HalfDast},
	))
	if len(rec.Correlation) != 3 {
		t.Fatalf("second batch: %d clusters, want 3", len(rec.Correlation))
	}

	// REPLACEMENT, not accumulation: a shorter batch shrinks the set, and the
	// earlier clusters do not survive. This is the assertion that makes the
	// contract testable — appending would leave five here.
	rec = mustTransition(t, ctl, rec, CorrelateEvent(
		record.Correlation{ClusterID: "c9", Role: record.HalfDast},
	))
	if len(rec.Correlation) != 1 || rec.Correlation[0].ClusterID != "c9" {
		t.Fatalf("third batch: %+v; each batch REPLACES the set (see CorrelateEvent) and this is "+
			"the case a correlator emitting partial batches would get wrong", rec.Correlation)
	}
}

// ---------------------------------------------------------------------------
// O4-m5 — a malformed DAST deadline is malformed whether or not DAST is on
// ---------------------------------------------------------------------------

// The finding: Resolve returned early when DastEnabled was false and never
// validated DastDeadlineSeconds, so `dastDeadlineSeconds: -1` with DAST off
// resolved clean and the config error survived until the tier was installed.
func TestResolveRejectsANegativeDastDeadlineEvenWithDastOff(t *testing.T) {
	for _, secs := range []int{-1, 0} {
		v := secs
		for _, enabled := range []bool{false, true} {
			p := DeadlinePolicy{DastEnabled: enabled, DastDeadlineSeconds: &v}
			if _, err := p.Resolve(); !errors.Is(err, ErrInvalidDeadlinePolicy) {
				t.Errorf("Resolve(dastDeadlineSeconds=%d, dastEnabled=%v) = %v, want ErrInvalidDeadlinePolicy "+
					"(O4-m5: a config error must not wait for the tier to be installed)", v, enabled, err)
			}
			// And it is refused everywhere Resolve is reached from, not only in
			// the one entry point a test happened to call.
			if _, err := NewController(p, WatermarkPolicy{}); !errors.Is(err, ErrInvalidDeadlinePolicy) {
				t.Errorf("NewController with dastDeadlineSeconds=%d, dastEnabled=%v = %v, want a refusal",
					v, enabled, err)
			}
			if _, err := p.At(baseTime); !errors.Is(err, ErrInvalidDeadlinePolicy) {
				t.Errorf("At with dastDeadlineSeconds=%d, dastEnabled=%v = %v, want a refusal", v, enabled, err)
			}
		}
	}

	// NEGATIVE CONTROL: a positive value with DAST off is still legal and still
	// produces no clock 3. The fix must reject malformed values, not values it
	// is not going to use.
	fine := 3600
	resolved, err := DeadlinePolicy{DastDeadlineSeconds: &fine}.Resolve()
	if err != nil {
		t.Fatalf("a positive dastDeadlineSeconds with DAST off must resolve: %v", err)
	}
	if resolved.DastDeadlineSeconds != nil {
		t.Errorf("DastDeadlineSeconds = %v with DAST off, want nil (there is no clock 3 to run)",
			*resolved.DastDeadlineSeconds)
	}
}
