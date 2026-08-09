package scanctl

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// baseTime is every test's `scan_run.started_at`. Both scan-scoped clocks are
// anchored to it, so every instant below is written as an offset from it and
// the arithmetic in a failure message is legible.
var baseTime = time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)

// testClock is a settable clock shared by the Controller and, via
// Controller.SetClock, by the record.Sealer underneath it. One clock: a test
// that advances time must not leave the Sealer stamping wall-clock seals.
type testClock struct{ at time.Time }

func (c *testClock) now() time.Time { return c.at }

func (c *testClock) set(d time.Duration) { c.at = baseTime.Add(d) }

// dastPolicy is the shipped-default policy WITH the DAST tier installed: an 8h
// claim window and a derived 4h DAST deadline, which binds.
func dastPolicy() DeadlinePolicy { return DeadlinePolicy{DastEnabled: true} }

// sastOnlyPolicy is the core `anvil` artifact (plan/00-SPINE.md S9-AMENDED):
// no `anvil-dast`, so no DAST half and no clock 3.
func sastOnlyPolicy() DeadlinePolicy { return DeadlinePolicy{} }

func newTestController(t *testing.T, p DeadlinePolicy, m WatermarkPolicy) (*Controller, *testClock) {
	t.Helper()
	ctl, err := NewController(p, m)
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	clk := &testClock{at: baseTime}
	ctl.SetClock(clk.now)
	return ctl, clk
}

func mustBegin(t *testing.T, ctl *Controller, auditID string) AuditRecord {
	t.Helper()
	rec, err := ctl.Begin(auditID, baseTime)
	if err != nil {
		t.Fatalf("Begin(%q): %v", auditID, err)
	}
	return rec
}

func mustTransition(t *testing.T, ctl *Controller, rec AuditRecord, ev Event) AuditRecord {
	t.Helper()
	out, err := ctl.Transition(rec, ev)
	if err != nil {
		t.Fatalf("Transition(%s) from state %s: %v", ev.Kind, rec.State, err)
	}
	return out
}

func finding(rule string) record.Result {
	return record.Result{RuleID: rule, Message: record.Message{Text: rule}}
}

func findings(n int) []record.Result {
	out := make([]record.Result, n)
	for i := range out {
		out[i] = finding(fmt.Sprintf("anvil.test.rule/%d", i))
	}
	return out
}

// bootedCleanOutcome is what the target lifecycle harness reports for a target
// that came up. Without it the default provenance is
// record.TargetProvenanceNoTargetDeclared, which record.DeriveDastStatus maps
// to record.DastStatusSkippedNoManifest regardless of the half's own status —
// deliberately, so an audit nobody reported a target for can never land on
// record.DastStatusCompletedClean by omission.
func bootedCleanOutcome() record.DastOutcome {
	return record.DastOutcome{
		TierInstalled: true,
		Provenance:    record.TargetProvenanceBootedClean,
	}
}

// ---------------------------------------------------------------------------
// Begin
// ---------------------------------------------------------------------------

func TestBeginStartsAtVersionOne(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-begin")

	if rec.Version != 1 {
		t.Errorf("Version = %d, want 1 (ck_audit_record_audit_version_positive requires >= 1)", rec.Version)
	}
	if rec.State != record.StateCollecting {
		t.Errorf("State = %q, want %q", rec.State, record.StateCollecting)
	}
	if rec.Sast.Status != record.HalfStatusRunning || rec.Dast.Status != record.HalfStatusRunning {
		t.Errorf("halves = (%q, %q), want both %q", rec.Sast.Status, rec.Dast.Status, record.HalfStatusRunning)
	}
	if rec.DastStatus != record.DastStatusRunning {
		t.Errorf("DastStatus = %q, want %q", rec.DastStatus, record.DastStatusRunning)
	}
	if got, want := rec.Deadlines.DeadlineAt(), baseTime.Add(8*time.Hour); !got.Equal(want) {
		t.Errorf("DeadlineAt = %s, want %s", got, want)
	}
	if at, ok := rec.Deadlines.DastDeadline(); !ok || !at.Equal(baseTime.Add(4*time.Hour)) {
		t.Errorf("DastDeadline = (%s, %v), want (%s, true)", at, ok, baseTime.Add(4*time.Hour))
	}
	if !rec.Deadlines.DastDeadlineBinds() {
		t.Error("the shipped defaults must bind: 4h < 8h")
	}
	if !rec.PublishedAt.Equal(baseTime) {
		t.Errorf("PublishedAt = %s, want scan start %s (version 1 is itself a publication)", rec.PublishedAt, baseTime)
	}
}

// A core `anvil` install has no `anvil-dast`, so record.Sealer.BeginAudit
// terminally seals the DAST half at scan start. The audit starts in
// record.StateDastSealed — which is one of the states O.2's struck four-state
// machine could not express at all.
func TestBeginWithoutDastTierStartsDastSealed(t *testing.T) {
	ctl, _ := newTestController(t, sastOnlyPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-sast-only")

	if rec.State != record.StateDastSealed {
		t.Errorf("State = %q, want %q", rec.State, record.StateDastSealed)
	}
	if rec.Dast.Status != record.HalfStatusSkipped {
		t.Errorf("Dast.Status = %q, want %q", rec.Dast.Status, record.HalfStatusSkipped)
	}
	if rec.DastStatus != record.DastStatusNotRun {
		t.Errorf("DastStatus = %q, want %q", rec.DastStatus, record.DastStatusNotRun)
	}
	if _, ok := rec.Deadlines.DastDeadline(); ok {
		t.Error("a DAST-disabled audit must have no clock 3")
	}

	// ...and it reaches both_sealed the moment SAST seals, with no DAST
	// worker in the process. Without that, every SAST-only audit wedges.
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
	if rec.State != record.StateBothSealed {
		t.Fatalf("State = %q, want %q", rec.State, record.StateBothSealed)
	}
	// TERMINAL IS NOT READABLE: the DAST half advanced the audit but there
	// are no DAST results, and "no findings recorded" is not "scanned clean".
	if ctl.Readable(rec, record.HalfDast) {
		t.Error("a skipped DAST half must never be readable")
	}
	if !ctl.Readable(rec, record.HalfSast) {
		t.Error("a sealed SAST half must be readable")
	}
}

func TestBeginRejectsZeroScanStart(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	if _, err := ctl.Begin("audit-zero", time.Time{}); !errors.Is(err, ErrZeroScanStart) {
		t.Fatalf("Begin(zero time) error = %v, want ErrZeroScanStart", err)
	}
}

func TestBeginRefusesDuplicateAudit(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	mustBegin(t, ctl, "audit-dup")
	if _, err := ctl.Begin("audit-dup", baseTime.Add(time.Hour)); !errors.Is(err, record.ErrDuplicateAudit) {
		t.Fatalf("second Begin error = %v, want record.ErrDuplicateAudit (re-beginning would recompute deadline_at)", err)
	}
}

// ---------------------------------------------------------------------------
// Every legal transition
// ---------------------------------------------------------------------------

// TestLegalTransitions drives one audit per row through a sequence of events
// and asserts the resulting anvil/state, the two per-half statuses and the
// audit-level anvil/dastStatus. Every arrow into each of R.1's six states
// appears at least once.
func TestLegalTransitions(t *testing.T) {
	type step struct {
		ev      Event
		advance time.Duration // clock offset from scan start BEFORE the event
	}
	tests := []struct {
		name       string
		policy     DeadlinePolicy
		steps      []step
		wantState  record.State
		wantSast   record.HalfStatus
		wantDast   record.HalfStatus
		wantDastSt record.DastStatus
	}{
		{
			name:   "collecting: nothing has sealed",
			policy: dastPolicy(),
			steps: []step{
				{ev: FindingsEvent(record.HalfSast, finding("a"))},
				{ev: DastOutcomeEvent(bootedCleanOutcome())},
			},
			wantState: record.StateCollecting, wantSast: record.HalfStatusRunning,
			wantDast: record.HalfStatusRunning, wantDastSt: record.DastStatusRunning,
		},
		{
			name:   "collecting -> sast_sealed: SAST seals first, DAST still running",
			policy: dastPolicy(),
			steps: []step{
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
			},
			wantState: record.StateSastSealed, wantSast: record.HalfStatusSealed,
			wantDast: record.HalfStatusRunning, wantDastSt: record.DastStatusRunning,
		},
		{
			name:   "collecting -> sast_sealed on a FAILED SAST half",
			policy: dastPolicy(),
			steps: []step{
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusFailed)},
			},
			wantState: record.StateSastSealed, wantSast: record.HalfStatusFailed,
			wantDast: record.HalfStatusRunning, wantDastSt: record.DastStatusRunning,
		},
		{
			name:   "collecting -> dast_sealed: THE DAST-FIRST SEAL the struck machine could not express",
			policy: dastPolicy(),
			steps: []step{
				{ev: DastOutcomeEvent(bootedCleanOutcome())},
				{ev: SealHalfEvent(record.HalfDast, record.HalfStatusSealed)},
			},
			wantState: record.StateDastSealed, wantSast: record.HalfStatusRunning,
			wantDast: record.HalfStatusSealed, wantDastSt: record.DastStatusCompletedClean,
		},
		{
			name:   "dast_sealed -> both_sealed",
			policy: dastPolicy(),
			steps: []step{
				{ev: DastOutcomeEvent(record.DastOutcome{
					TierInstalled: true,
					Provenance:    record.TargetProvenanceBootedClean,
					FindingCount:  3,
				})},
				{ev: FindingsEvent(record.HalfDast, findings(3)...)},
				{ev: SealHalfEvent(record.HalfDast, record.HalfStatusSealed)},
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
			},
			wantState: record.StateBothSealed, wantSast: record.HalfStatusSealed,
			wantDast: record.HalfStatusSealed, wantDastSt: record.DastStatusCompletedFindings,
		},
		{
			name:   "sast_sealed -> both_sealed",
			policy: dastPolicy(),
			steps: []step{
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
				{ev: DastOutcomeEvent(bootedCleanOutcome())},
				{ev: SealHalfEvent(record.HalfDast, record.HalfStatusSealed)},
			},
			wantState: record.StateBothSealed, wantSast: record.HalfStatusSealed,
			wantDast: record.HalfStatusSealed, wantDastSt: record.DastStatusCompletedClean,
		},
		{
			name:   "both_sealed -> consumed",
			policy: sastOnlyPolicy(),
			steps: []step{
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
				{ev: ConsumeEvent()},
			},
			wantState: record.StateConsumed, wantSast: record.HalfStatusSealed,
			wantDast: record.HalfStatusSkipped, wantDastSt: record.DastStatusNotRun,
		},
		{
			name:   "collecting -> expired: the claim window closed with nothing sealed",
			policy: sastOnlyPolicy(),
			steps: []step{
				{ev: TickEvent(), advance: 8 * time.Hour},
			},
			// A SAST-only audit starts in dast_sealed, so "nothing sealed"
			// here means the SAST half never sealed.
			wantState: record.StateExpired, wantSast: record.HalfStatusRunning,
			wantDast: record.HalfStatusSkipped, wantDastSt: record.DastStatusNotRun,
		},
		{
			name:   "clock 3 forces the DAST half terminal: timed_out, not stuck",
			policy: dastPolicy(),
			steps: []step{
				{ev: DastOutcomeEvent(bootedCleanOutcome())},
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
				{ev: TickEvent(), advance: 4 * time.Hour},
			},
			wantState: record.StateBothSealed, wantSast: record.HalfStatusSealed,
			wantDast: record.HalfStatusTimedOut, wantDastSt: record.DastStatusTimedOut,
		},
		{
			name:   "a DAST half that broke against a booted target is completed_failed, not completed_partial",
			policy: dastPolicy(),
			steps: []step{
				{ev: DastOutcomeEvent(bootedCleanOutcome())},
				{ev: SealHalfEvent(record.HalfDast, record.HalfStatusFailed)},
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
			},
			wantState: record.StateBothSealed, wantSast: record.HalfStatusSealed,
			wantDast: record.HalfStatusFailed, wantDastSt: record.DastStatusCompletedFailed,
		},
		{
			name:   "a target that failed to boot is distinguishable from scanned clean",
			policy: dastPolicy(),
			steps: []step{
				{ev: DastOutcomeEvent(record.DastOutcome{
					TierInstalled: true,
					Provenance:    record.TargetProvenanceBootFailed,
				})},
				{ev: SealHalfEvent(record.HalfDast, record.HalfStatusSealed)},
				{ev: SealHalfEvent(record.HalfSast, record.HalfStatusSealed)},
			},
			wantState: record.StateBothSealed, wantSast: record.HalfStatusSealed,
			wantDast: record.HalfStatusSealed, wantDastSt: record.DastStatusTargetBootFailed,
		},
		{
			name:   "correlation lands without advancing the lifecycle",
			policy: dastPolicy(),
			steps: []step{
				{ev: CorrelateEvent(record.Correlation{ClusterID: "c1", Role: record.HalfSast})},
			},
			wantState: record.StateCollecting, wantSast: record.HalfStatusRunning,
			wantDast: record.HalfStatusRunning, wantDastSt: record.DastStatusRunning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl, clk := newTestController(t, tt.policy, WatermarkPolicy{})
			rec := mustBegin(t, ctl, "audit-"+tt.name)
			for i, s := range tt.steps {
				if s.advance != 0 {
					clk.set(s.advance)
				}
				var err error
				rec, err = ctl.Transition(rec, s.ev)
				if err != nil {
					t.Fatalf("step %d (%s): %v", i, s.ev.Kind, err)
				}
			}
			if rec.State != tt.wantState {
				t.Errorf("State = %q, want %q", rec.State, tt.wantState)
			}
			if rec.Sast.Status != tt.wantSast {
				t.Errorf("Sast.Status = %q, want %q", rec.Sast.Status, tt.wantSast)
			}
			if rec.Dast.Status != tt.wantDast {
				t.Errorf("Dast.Status = %q, want %q", rec.Dast.Status, tt.wantDast)
			}
			if rec.DastStatus != tt.wantDastSt {
				t.Errorf("DastStatus = %q, want %q", rec.DastStatus, tt.wantDastSt)
			}
			if !rec.State.Valid() {
				t.Errorf("State %q is not one of R.1's six frozen literals", rec.State)
			}
			if !rec.DastStatus.Valid() || rec.DastStatus == "" {
				t.Errorf("DastStatus %q is not a legal literal; audit_record.dast_status is NOT NULL", rec.DastStatus)
			}
		})
	}
}

// Every one of R.1's six anvil/state values must be reachable through this
// controller. The struck four-state machine made `consumed` unreachable by
// making `sealed` terminal; this is the regression test for that ruling.
func TestEverySixthStateIsReachable(t *testing.T) {
	reached := map[record.State]bool{}
	for _, s := range record.StateValues() {
		ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
		rec, err := driveToState(t, ctl, clk, s)
		if err != nil {
			t.Errorf("state %q: %v", s, err)
			continue
		}
		if rec.State != s {
			t.Errorf("driveToState(%q) landed in %q", s, rec.State)
			continue
		}
		reached[s] = true
	}
	for _, s := range record.StateValues() {
		if !reached[s] {
			t.Errorf("anvil/state %q is unreachable through the controller", s)
		}
	}
}

// driveToState takes a freshly-begun audit to the named state. It is shared by
// the reachability test and by the illegal-transition table, so the two cannot
// disagree about how a state is reached.
func driveToState(t *testing.T, ctl *Controller, clk *testClock, want record.State) (AuditRecord, error) {
	t.Helper()
	rec := mustBegin(t, ctl, "audit-drive-"+string(want))

	switch want {
	case record.StateCollecting:
		return rec, nil
	case record.StateSastSealed:
		return ctl.Transition(rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
	case record.StateDastSealed:
		rec, err := ctl.Transition(rec, DastOutcomeEvent(bootedCleanOutcome()))
		if err != nil {
			return rec, err
		}
		return ctl.Transition(rec, SealHalfEvent(record.HalfDast, record.HalfStatusSealed))
	case record.StateBothSealed, record.StateConsumed:
		rec, err := ctl.Transition(rec, DastOutcomeEvent(bootedCleanOutcome()))
		if err != nil {
			return rec, err
		}
		rec, err = ctl.Transition(rec, SealHalfEvent(record.HalfDast, record.HalfStatusSealed))
		if err != nil {
			return rec, err
		}
		rec, err = ctl.Transition(rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
		if err != nil || want == record.StateBothSealed {
			return rec, err
		}
		return ctl.Transition(rec, ConsumeEvent())
	case record.StateExpired:
		clk.set(8 * time.Hour)
		return ctl.Transition(rec, TickEvent())
	}
	return rec, fmt.Errorf("no route defined to %q", want)
}

// ---------------------------------------------------------------------------
// Every illegal transition — an error, never a panic and never a silent no-op
// ---------------------------------------------------------------------------

func TestIllegalTransitionsReturnErrors(t *testing.T) {
	tests := []struct {
		name string
		from record.State
		ev   Event
		// wantErr is the sentinel errors.Is must reach. Leave nil and set
		// wantEnumField when the refusal is a *record.EnumError instead —
		// internal/record reports an illegal enum literal with a typed error
		// naming the field and every legal value, not with a sentinel.
		wantErr       error
		wantEnumField string
	}{
		{
			name: "sealing a half as running is not a seal",
			from: record.StateCollecting,
			ev:   SealHalfEvent(record.HalfSast, record.HalfStatusRunning),
			// `complete` is struck; `running` is the non-terminal value this
			// catches.
			wantErr: record.ErrNotSealable,
		},
		{
			name:          "sealing an unknown half",
			from:          record.StateCollecting,
			ev:            SealHalfEvent(record.Half("both"), record.HalfStatusSealed),
			wantEnumField: "anvil/half",
		},
		{
			name: "sealing with a status outside the frozen enum",
			from: record.StateCollecting,
			// `complete` is exactly the struck token ruling G5 removed. It
			// must be refused, not silently accepted as a seal.
			ev:            SealHalfEvent(record.HalfSast, record.HalfStatus("complete")),
			wantEnumField: "anvil/status",
		},
		{
			name:    "re-sealing a sealed half with a different status",
			from:    record.StateSastSealed,
			ev:      SealHalfEvent(record.HalfSast, record.HalfStatusFailed),
			wantErr: record.ErrHalfAlreadySealed,
		},
		{
			name:    "sealing a half of a consumed audit",
			from:    record.StateConsumed,
			ev:      SealHalfEvent(record.HalfSast, record.HalfStatusSealed),
			wantErr: record.ErrAuditTerminal,
		},
		{
			name:    "sealing a half of an expired audit",
			from:    record.StateExpired,
			ev:      SealHalfEvent(record.HalfSast, record.HalfStatusSealed),
			wantErr: record.ErrAuditTerminal,
		},
		{
			name:    "consuming before both halves sealed",
			from:    record.StateSastSealed,
			ev:      ConsumeEvent(),
			wantErr: record.ErrNotBothSealed,
		},
		{
			name:    "consuming a collecting audit",
			from:    record.StateCollecting,
			ev:      ConsumeEvent(),
			wantErr: record.ErrNotBothSealed,
		},
		{
			name:    "consuming an expired audit",
			from:    record.StateExpired,
			ev:      ConsumeEvent(),
			wantErr: record.ErrAuditTerminal,
		},
		{
			name:    "findings for a half that already sealed",
			from:    record.StateSastSealed,
			ev:      FindingsEvent(record.HalfSast, finding("late")),
			wantErr: ErrHalfNotAccepting,
		},
		{
			name:    "findings for an expired audit",
			from:    record.StateExpired,
			ev:      FindingsEvent(record.HalfSast, finding("late")),
			wantErr: record.ErrAuditTerminal,
		},
		{
			name:    "findings for a consumed audit",
			from:    record.StateConsumed,
			ev:      FindingsEvent(record.HalfSast, finding("late")),
			wantErr: record.ErrAuditTerminal,
		},
		{
			name:    "a findings event carrying no findings",
			from:    record.StateCollecting,
			ev:      FindingsEvent(record.HalfSast),
			wantErr: ErrEmptyEvent,
		},
		{
			name:          "findings for an unknown half",
			from:          record.StateCollecting,
			ev:            FindingsEvent(record.Half("host"), finding("x")),
			wantEnumField: "anvil/half",
		},
		{
			name:    "a correlate event carrying no clusters",
			from:    record.StateCollecting,
			ev:      CorrelateEvent(),
			wantErr: ErrEmptyEvent,
		},
		{
			name:    "correlation for an expired audit",
			from:    record.StateExpired,
			ev:      CorrelateEvent(record.Correlation{ClusterID: "c1"}),
			wantErr: record.ErrAuditTerminal,
		},
		{
			name:    "a DAST outcome for a sealed DAST half",
			from:    record.StateDastSealed,
			ev:      DastOutcomeEvent(bootedCleanOutcome()),
			wantErr: record.ErrHalfAlreadySealed,
		},
		{
			name:    "a DAST outcome for an expired audit",
			from:    record.StateExpired,
			ev:      DastOutcomeEvent(bootedCleanOutcome()),
			wantErr: record.ErrAuditTerminal,
		},
		{
			name:    "the zero Event",
			from:    record.StateCollecting,
			ev:      Event{},
			wantErr: ErrUnknownEvent,
		},
		{
			name:    "an invented event kind",
			from:    record.StateCollecting,
			ev:      Event{Kind: EventKind("seal")},
			wantErr: ErrUnknownEvent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
			before, err := driveToState(t, ctl, clk, tt.from)
			if err != nil {
				t.Fatalf("driving to %q: %v", tt.from, err)
			}

			after, err := ctl.Transition(before, tt.ev)
			if err == nil {
				t.Fatalf("Transition(%s) from %q succeeded; want a refusal (%v%s)",
					tt.ev.Kind, tt.from, tt.wantErr, tt.wantEnumField)
			}
			switch {
			case tt.wantEnumField != "":
				var ee *record.EnumError
				if !errors.As(err, &ee) {
					t.Fatalf("Transition(%s) error = %v, want a *record.EnumError", tt.ev.Kind, err)
				}
				if ee.Field != tt.wantEnumField {
					t.Fatalf("EnumError.Field = %q, want %q", ee.Field, tt.wantEnumField)
				}
			case !errors.Is(err, tt.wantErr):
				t.Fatalf("Transition(%s) error = %v, want errors.Is(..., %v)", tt.ev.Kind, err, tt.wantErr)
			}
			// NOT A SILENT NO-OP, and not a destroyed record either: the
			// returned value is the input, unchanged.
			if after.AuditID != before.AuditID || after.State != before.State ||
				after.Version != before.Version ||
				after.Sast.FindingCount() != before.Sast.FindingCount() ||
				after.Dast.FindingCount() != before.Dast.FindingCount() {
				t.Errorf("a refused transition changed the record: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestTransitionOnAnUnknownAudit(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	_, err := ctl.Transition(AuditRecord{AuditID: "never-begun"}, TickEvent())
	if !errors.Is(err, record.ErrUnknownAudit) {
		t.Fatalf("error = %v, want record.ErrUnknownAudit", err)
	}
	// The zero AuditRecord is also unknown, so a caller that forgot Begin
	// gets a refusal rather than a phantom audit.
	if _, err := ctl.Transition(AuditRecord{}, TickEvent()); !errors.Is(err, record.ErrUnknownAudit) {
		t.Fatalf("zero record error = %v, want record.ErrUnknownAudit", err)
	}
}

// ---------------------------------------------------------------------------
// SAST must not block on DAST — research/21 §5's whole point
// ---------------------------------------------------------------------------

func TestSastSealsAndIsConsumableWhileDastRuns(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-nonblocking")

	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfSast, findings(4)...))
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))

	if rec.State != record.StateSastSealed {
		t.Fatalf("State = %q, want %q", rec.State, record.StateSastSealed)
	}
	if rec.Dast.Status != record.HalfStatusRunning {
		t.Fatalf("Dast.Status = %q; the DAST half must be untouched", rec.Dast.Status)
	}

	// The SAST half's results are readable NOW, with DAST still running.
	got, err := ctl.Findings(rec, record.HalfSast)
	if err != nil {
		t.Fatalf("Findings(sast): %v", err)
	}
	if len(got) != 4 {
		t.Errorf("len(sast findings) = %d, want 4", len(got))
	}

	// And the DAST half's are not — R.6's read gate, asked through
	// record.HalfReadGate and not re-derived here.
	if _, err := ctl.Findings(rec, record.HalfDast); !errors.Is(err, record.ErrHalfNotSealed) {
		t.Errorf("Findings(dast) error = %v, want record.ErrHalfNotSealed", err)
	}

	// The consumption gate the handoff table keys on agrees, because it is
	// the same gate: record.Sealer.ReadyForConsumption.
	sastReady, dastReady := ctl.Sealer().ReadyForConsumption(rec.AuditID)
	if !sastReady {
		t.Error("ReadyForConsumption reports the sealed SAST half unready; static_only work would never be claimable")
	}
	if dastReady {
		t.Error("ReadyForConsumption reports a still-running DAST half ready")
	}
}

// The packet's stop condition, in its two shapes. A slow or never-terminating
// DAST run must never leave a stuck record.
func TestSlowDastNeverLeavesTheRecordStuck(t *testing.T) {
	t.Run("binding DAST deadline: sast_sealed then both_sealed at clock 3", func(t *testing.T) {
		ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
		rec := mustBegin(t, ctl, "audit-slow-binding")
		rec = mustTransition(t, ctl, rec, DastOutcomeEvent(bootedCleanOutcome()))
		rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
		if rec.State != record.StateSastSealed {
			t.Fatalf("State = %q, want %q", rec.State, record.StateSastSealed)
		}

		// Ticks before the DAST deadline change nothing.
		clk.set(3 * time.Hour)
		rec = mustTransition(t, ctl, rec, TickEvent())
		if rec.State != record.StateSastSealed {
			t.Fatalf("State = %q at t+3h, want %q (clock 3 is at t+4h)", rec.State, record.StateSastSealed)
		}

		clk.set(4 * time.Hour)
		rec = mustTransition(t, ctl, rec, TickEvent())
		if rec.State != record.StateBothSealed {
			t.Fatalf("State = %q at t+4h, want %q", rec.State, record.StateBothSealed)
		}
		if rec.Dast.Status != record.HalfStatusTimedOut {
			t.Errorf("Dast.Status = %q, want %q", rec.Dast.Status, record.HalfStatusTimedOut)
		}
		if rec.DastStatus != record.DastStatusTimedOut {
			t.Errorf("DastStatus = %q, want %q", rec.DastStatus, record.DastStatusTimedOut)
		}
		// A timed-out half is terminal but NOT readable.
		if ctl.Readable(rec, record.HalfDast) {
			t.Error("a timed-out DAST half must not be readable")
		}
		// The audit is consumable: the SAST findings are handed over with
		// four hours of claim window left, which is the whole point.
		rec = mustTransition(t, ctl, rec, ConsumeEvent())
		if rec.State != record.StateConsumed {
			t.Fatalf("State = %q, want %q", rec.State, record.StateConsumed)
		}
	})

	t.Run("non-binding DAST deadline: sast_sealed then expired, never stuck-collecting", func(t *testing.T) {
		// deadlines.go documents this configuration and what it costs:
		// "a never-terminating DAST run leaves the audit in
		// record.StateSastSealed until clock 2 expires it, and the SAST
		// findings are then lost to the claim window rather than handed
		// over. Callers should surface a warning; the controller must not
		// fail the scan over it." This is that path, asserted.
		twelveHours := 12 * 60 * 60
		policy := DeadlinePolicy{DastEnabled: true, DastDeadlineSeconds: &twelveHours}
		ctl, clk := newTestController(t, policy, WatermarkPolicy{})
		rec := mustBegin(t, ctl, "audit-slow-nonbinding")
		if rec.Deadlines.DastDeadlineBinds() {
			t.Fatal("a 12h DAST deadline inside an 8h claim window must not bind")
		}

		rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
		if rec.State != record.StateSastSealed {
			t.Fatalf("State = %q, want %q", rec.State, record.StateSastSealed)
		}

		clk.set(8 * time.Hour)
		rec = mustTransition(t, ctl, rec, TickEvent())
		if rec.State != record.StateExpired {
			t.Fatalf("State = %q at the claim deadline, want %q — NOT stuck", rec.State, record.StateExpired)
		}
		// CRITIQUE-03 M1: an expired audit is not readable even though its
		// SAST half is cleanly sealed. One gate, both arms.
		if rec.Sast.Status != record.HalfStatusSealed {
			t.Fatalf("Sast.Status = %q; the seal itself survives expiry", rec.Sast.Status)
		}
		if _, err := ctl.Findings(rec, record.HalfSast); !errors.Is(err, record.ErrHalfNotSealed) {
			t.Errorf("Findings(sast) on an expired audit = %v, want a read-gate refusal", err)
		}
		if ctl.Readable(rec, record.HalfSast) {
			t.Error("Readable said true on an expired audit; the expiry arm was skipped")
		}
	})
}

// Ticking is idempotent and a tick on a settled audit is not an error: a
// daemon wakes on a schedule and must not log an error forever.
func TestTickIsIdempotent(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-ticks")
	clk.set(9 * time.Hour)

	for i := 0; i < 4; i++ {
		var err error
		rec, err = ctl.Transition(rec, TickEvent())
		if err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	if rec.State != record.StateExpired {
		t.Fatalf("State = %q, want %q", rec.State, record.StateExpired)
	}
}

// ---------------------------------------------------------------------------
// Version-bump watermarks
// ---------------------------------------------------------------------------

func TestPublicationIsNotPerFinding(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 10, Interval: time.Hour})
	rec := mustBegin(t, ctl, "audit-watermark-count")
	start := rec.Version

	for i := 0; i < 9; i++ {
		rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfDast, finding(fmt.Sprintf("r%d", i))))
	}
	if rec.Version != start {
		t.Fatalf("Version = %d after 9 of N=10 findings, want %d; per-finding publication is the named failure", rec.Version, start)
	}
	if rec.PendingDastFindings != 9 {
		t.Errorf("PendingDastFindings = %d, want 9", rec.PendingDastFindings)
	}

	before := rec
	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfDast, finding("r9")))
	if !VersionBumped(before, rec) {
		t.Fatalf("the 10th finding did not bump the version (was %d, is %d)", before.Version, rec.Version)
	}
	if rec.PendingDastFindings != 0 {
		t.Errorf("PendingDastFindings = %d after a publication, want 0", rec.PendingDastFindings)
	}
}

func TestSastFindingsDoNotBumpUntilTheHalfSeals(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 2})
	rec := mustBegin(t, ctl, "audit-watermark-sast")
	start := rec.Version

	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfSast, findings(50)...))
	if rec.Version != start {
		t.Fatalf("Version = %d, want %d: watermark (b) is scoped to DAST findings", rec.Version, start)
	}
	if rec.PendingDastFindings != 0 {
		t.Errorf("PendingDastFindings = %d; SAST findings must not feed the DAST counter", rec.PendingDastFindings)
	}

	before := rec
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))
	if !VersionBumped(before, rec) {
		t.Error("watermark (a): the SAST seal must publish")
	}
}

func TestTimeWatermarkPublishesUnpublishedDastFindings(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 1000, Interval: 15 * time.Minute})
	rec := mustBegin(t, ctl, "audit-watermark-time")

	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfDast, findings(3)...))
	before := rec

	// A tick before M elapses publishes nothing.
	clk.set(10 * time.Minute)
	rec = mustTransition(t, ctl, rec, TickEvent())
	if VersionBumped(before, rec) {
		t.Fatalf("published at t+10m with M=15m (version %d -> %d)", before.Version, rec.Version)
	}

	clk.set(15 * time.Minute)
	rec = mustTransition(t, ctl, rec, TickEvent())
	if !VersionBumped(before, rec) {
		t.Fatalf("no publication at t+15m with M=15m (version still %d)", rec.Version)
	}
	if !rec.PublishedAt.Equal(baseTime.Add(15 * time.Minute)) {
		t.Errorf("PublishedAt = %s, want %s", rec.PublishedAt, baseTime.Add(15*time.Minute))
	}

	// With nothing unpublished, the time arm does not fire again.
	before = rec
	clk.set(2 * time.Hour)
	rec = mustTransition(t, ctl, rec, TickEvent())
	if VersionBumped(before, rec) {
		t.Error("the time watermark fired with no unpublished DAST findings")
	}
}

func TestDastTerminalSealPublishes(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 1000})
	rec := mustBegin(t, ctl, "audit-watermark-dast-terminal")
	rec = mustTransition(t, ctl, rec, DastOutcomeEvent(bootedCleanOutcome()))
	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfDast, findings(3)...))

	before := rec
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfDast, record.HalfStatusSealed))
	if !VersionBumped(before, rec) {
		t.Error("watermark (c): the DAST terminal state must publish")
	}
	if rec.PendingDastFindings != 0 {
		t.Errorf("PendingDastFindings = %d after the terminal seal, want 0", rec.PendingDastFindings)
	}
}

func TestClockThreeSealPublishes(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-watermark-clock3")
	before := rec

	clk.set(4 * time.Hour)
	rec = mustTransition(t, ctl, rec, TickEvent())
	if !VersionBumped(before, rec) {
		t.Error("forcing the DAST half terminal on clock 3 must publish (watermark (c))")
	}
}

func TestConsumeDoesNotPublishAndIsReentrant(t *testing.T) {
	ctl, _ := newTestController(t, sastOnlyPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-consume")
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))

	before := rec
	rec = mustTransition(t, ctl, rec, ConsumeEvent())
	if VersionBumped(before, rec) {
		t.Error("consumption is not a publication watermark")
	}
	if rec.ConsumedAt == nil {
		t.Fatal("ConsumedAt not stamped; audit_record.consumed_at would be NULL")
	}
	firstTake := *rec.ConsumedAt

	// Re-entrant: consuming again is accepted, does not move consumed_at,
	// and leaves the sealed half readable.
	again := mustTransition(t, ctl, rec, ConsumeEvent())
	if again.ConsumedAt == nil || !again.ConsumedAt.Equal(firstTake) {
		t.Errorf("consumed_at moved on a second take: %v -> %v", firstTake, again.ConsumedAt)
	}
	if !ctl.Readable(again, record.HalfSast) {
		t.Error("taking the record once must not shut the gate (S1: a RE-ENTRANT consumer)")
	}
}

func TestVersionIsMonotonic(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 2, Interval: time.Minute})
	rec := mustBegin(t, ctl, "audit-monotonic")
	last := rec.Version

	steps := []Event{
		FindingsEvent(record.HalfDast, findings(2)...),
		DastOutcomeEvent(bootedCleanOutcome()),
		FindingsEvent(record.HalfSast, findings(3)...),
		SealHalfEvent(record.HalfSast, record.HalfStatusSealed),
		FindingsEvent(record.HalfDast, findings(1)...),
		TickEvent(),
		SealHalfEvent(record.HalfDast, record.HalfStatusSealed),
		ConsumeEvent(),
	}
	for i, ev := range steps {
		clk.set(time.Duration(i+1) * 10 * time.Minute)
		rec = mustTransition(t, ctl, rec, ev)
		if rec.Version < last {
			t.Fatalf("step %d (%s): version went backwards, %d -> %d", i, ev.Kind, last, rec.Version)
		}
		if rec.Version < 1 {
			t.Fatalf("step %d: version %d violates ck_audit_record_audit_version_positive", i, rec.Version)
		}
		last = rec.Version
	}
}

// ---------------------------------------------------------------------------
// The single durable write
// ---------------------------------------------------------------------------

func TestDurableWriteDueFiresExactlyOncePerAudit(t *testing.T) {
	tests := []struct {
		name   string
		policy DeadlinePolicy
		run    func(t *testing.T, ctl *Controller, clk *testClock, rec AuditRecord) []AuditRecord
	}{
		{
			name:   "seal then consume",
			policy: dastPolicy(),
			run: func(t *testing.T, ctl *Controller, clk *testClock, rec AuditRecord) []AuditRecord {
				out := []AuditRecord{rec}
				for _, ev := range []Event{
					FindingsEvent(record.HalfSast, finding("a")),
					DastOutcomeEvent(bootedCleanOutcome()),
					SealHalfEvent(record.HalfSast, record.HalfStatusSealed),
					SealHalfEvent(record.HalfDast, record.HalfStatusSealed),
					ConsumeEvent(),
				} {
					rec = mustTransition(t, ctl, rec, ev)
					out = append(out, rec)
				}
				return out
			},
		},
		{
			name:   "expire with only the SAST half sealed",
			policy: sastOnlyPolicy(),
			run: func(t *testing.T, ctl *Controller, clk *testClock, rec AuditRecord) []AuditRecord {
				out := []AuditRecord{rec}
				rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfSast, finding("a")))
				out = append(out, rec)
				clk.set(8 * time.Hour)
				rec = mustTransition(t, ctl, rec, TickEvent())
				out = append(out, rec)
				rec = mustTransition(t, ctl, rec, TickEvent())
				return append(out, rec)
			},
		},
		{
			name:   "seal, then expire without ever being consumed",
			policy: dastPolicy(),
			run: func(t *testing.T, ctl *Controller, clk *testClock, rec AuditRecord) []AuditRecord {
				out := []AuditRecord{rec}
				for _, ev := range []Event{
					DastOutcomeEvent(bootedCleanOutcome()),
					SealHalfEvent(record.HalfDast, record.HalfStatusSealed),
					SealHalfEvent(record.HalfSast, record.HalfStatusSealed),
				} {
					rec = mustTransition(t, ctl, rec, ev)
					out = append(out, rec)
				}
				clk.set(8 * time.Hour)
				rec = mustTransition(t, ctl, rec, TickEvent())
				return append(out, rec)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl, clk := newTestController(t, tt.policy, WatermarkPolicy{})
			seq := tt.run(t, ctl, clk, mustBegin(t, ctl, "audit-write-"+tt.name))

			writes := 0
			for i := 1; i < len(seq); i++ {
				if DurableWriteDue(seq[i-1], seq[i]) {
					writes++
				}
			}
			if writes != 1 {
				t.Fatalf("DurableWriteDue fired %d times across %d transitions; want exactly 1", writes, len(seq)-1)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The read gate — called, never re-derived
// ---------------------------------------------------------------------------

func TestFindingsAreGatedInEveryUnreadableShape(t *testing.T) {
	tests := []struct {
		name   string
		status record.HalfStatus
	}{
		{"running", record.HalfStatusRunning},
		{"failed", record.HalfStatusFailed},
		{"timed_out", record.HalfStatusTimedOut},
		{"skipped", record.HalfStatusSkipped},
	}
	for _, tt := range tests {
		t.Run("sast half is "+tt.name, func(t *testing.T) {
			ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
			rec := mustBegin(t, ctl, "audit-gate-"+tt.name)
			rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfSast, findings(2)...))
			if tt.status != record.HalfStatusRunning {
				rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, tt.status))
			}
			if rec.Sast.Status != tt.status {
				t.Fatalf("Sast.Status = %q, want %q", rec.Sast.Status, tt.status)
			}
			got, err := ctl.Findings(rec, record.HalfSast)
			if !errors.Is(err, record.ErrHalfNotSealed) {
				t.Fatalf("Findings error = %v, want record.ErrHalfNotSealed", err)
			}
			if got != nil {
				t.Errorf("a refused read returned %d findings; it must return nothing", len(got))
			}
			if ctl.Readable(rec, record.HalfSast) {
				t.Error("Readable disagreed with Findings; there is meant to be ONE gate")
			}
			// The count is deliberately ungated — it is metadata, not
			// results — so it still answers.
			if rec.Sast.FindingCount() != 2 {
				t.Errorf("FindingCount = %d, want 2", rec.Sast.FindingCount())
			}
		})
	}
}

// Findings and Readable must never disagree, in any state, for either half.
func TestReadableAgreesWithFindingsEverywhere(t *testing.T) {
	for _, s := range record.StateValues() {
		for _, half := range record.HalfValues() {
			ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
			rec, err := driveToState(t, ctl, clk, s)
			if err != nil {
				t.Fatalf("driving to %q: %v", s, err)
			}
			_, readErr := ctl.Findings(rec, half)
			if got, want := readErr == nil, ctl.Readable(rec, half); got != want {
				t.Errorf("state %q half %q: Findings ok=%v but Readable=%v", s, half, got, want)
			}
		}
	}
}

func TestFindingsOnAnUnknownHalf(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-unknown-half")
	_, err := ctl.Findings(rec, record.Half("host"))
	var ee *record.EnumError
	if !errors.As(err, &ee) || ee.Field != "anvil/half" {
		t.Fatalf("Findings(host) error = %v, want a *record.EnumError on anvil/half", err)
	}
	if ctl.Readable(rec, record.Half("host")) {
		t.Error("an unknown half must never be readable")
	}
}

// Findings returns a COPY: mutating the returned slice must not reach into the
// record a consumer will read again.
func TestFindingsReturnsACopy(t *testing.T) {
	ctl, _ := newTestController(t, sastOnlyPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-copy")
	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfSast, findings(2)...))
	rec = mustTransition(t, ctl, rec, SealHalfEvent(record.HalfSast, record.HalfStatusSealed))

	got, err := ctl.Findings(rec, record.HalfSast)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	got[0].RuleID = "tampered"

	again, err := ctl.Findings(rec, record.HalfSast)
	if err != nil {
		t.Fatalf("Findings (second read): %v", err)
	}
	if again[0].RuleID == "tampered" {
		t.Error("Findings handed out the backing array; a consumer can rewrite a sealed half")
	}
}

// ---------------------------------------------------------------------------
// Value semantics
// ---------------------------------------------------------------------------

func TestTransitionDoesNotMutateItsInput(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 1})
	before := mustBegin(t, ctl, "audit-immutable")
	before = mustTransition(t, ctl, before, FindingsEvent(record.HalfSast, finding("a")))

	snapshot := before
	after := mustTransition(t, ctl, before, FindingsEvent(record.HalfSast, finding("b")))

	if before.Version != snapshot.Version || before.State != snapshot.State {
		t.Errorf("Transition mutated the input's scalars: %+v vs %+v", before, snapshot)
	}
	if before.Sast.FindingCount() != 1 {
		t.Errorf("input Sast.FindingCount = %d, want 1; the input's findings were appended to", before.Sast.FindingCount())
	}
	if after.Sast.FindingCount() != 2 {
		t.Errorf("output Sast.FindingCount = %d, want 2", after.Sast.FindingCount())
	}
}

func TestCorrelationIsCopiedNotAliased(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-correlation")

	clusters := []record.Correlation{{ClusterID: "c1", Role: record.HalfSast}}
	rec = mustTransition(t, ctl, rec, CorrelateEvent(clusters...))
	clusters[0].ClusterID = "tampered"

	if len(rec.Correlation) != 1 || rec.Correlation[0].ClusterID != "c1" {
		t.Errorf("Correlation aliased the caller's slice: %+v", rec.Correlation)
	}
}

// ---------------------------------------------------------------------------
// acceptsWrites must not drift from the Sealer's own guard
// ---------------------------------------------------------------------------

func TestAcceptsWritesAgreesWithTheSealer(t *testing.T) {
	for _, s := range record.StateValues() {
		ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{})
		rec, err := driveToState(t, ctl, clk, s)
		if err != nil {
			t.Fatalf("driving to %q: %v", s, err)
		}
		if rec.State != s {
			t.Fatalf("expected state %q, got %q", s, rec.State)
		}

		// The Sealer's own guard: SealHalf refuses a consumed or expired
		// audit with record.ErrAuditTerminal before it looks at the half.
		sealErr := ctl.Sealer().SealHalf(rec.AuditID, record.HalfSast, record.HalfStatusSealed)
		sealerRefused := errors.Is(sealErr, record.ErrAuditTerminal)

		if got := acceptsWrites(s); got == sealerRefused {
			t.Errorf("state %q: acceptsWrites = %v but the Sealer's ErrAuditTerminal guard = %v; the mirror has drifted",
				s, got, sealerRefused)
		}
	}
}

func TestSettledIsTotalOverTheStateEnum(t *testing.T) {
	want := map[record.State]bool{
		record.StateCollecting: false,
		record.StateSastSealed: false,
		record.StateDastSealed: false,
		record.StateBothSealed: true,
		record.StateConsumed:   true,
		record.StateExpired:    true,
	}
	if len(want) != len(record.StateValues()) {
		t.Fatalf("this table covers %d states but the frozen enum has %d; R.1 changed under us",
			len(want), len(record.StateValues()))
	}
	for _, s := range record.StateValues() {
		if got := settled(s); got != want[s] {
			t.Errorf("settled(%q) = %v, want %v", s, got, want[s])
		}
	}
}

// ---------------------------------------------------------------------------
// WatermarkPolicy
// ---------------------------------------------------------------------------

func TestWatermarkPolicyResolve(t *testing.T) {
	fourHours := 4 * time.Hour

	t.Run("zero resolves to the derived defaults", func(t *testing.T) {
		got, err := WatermarkPolicy{}.Resolve(fourHours)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got.DastFindings != DefaultWatermarkDastFindings {
			t.Errorf("DastFindings = %d, want %d", got.DastFindings, DefaultWatermarkDastFindings)
		}
		if got.Interval != 15*time.Minute {
			t.Errorf("Interval = %s, want 15m (4h / %d)", got.Interval, WatermarkIntervalDivisor)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		once, err := WatermarkPolicy{}.Resolve(fourHours)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		twice, err := once.Resolve(fourHours)
		if err != nil {
			t.Fatalf("Resolve twice: %v", err)
		}
		if once != twice {
			t.Errorf("Resolve is not idempotent: %+v vs %+v", once, twice)
		}
	})

	t.Run("M scales with the budget rather than being written down", func(t *testing.T) {
		got, err := WatermarkPolicy{}.Resolve(32 * time.Minute)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got.Interval != 2*time.Minute {
			t.Errorf("Interval = %s, want 2m for a 32m budget", got.Interval)
		}
	})

	t.Run("a tiny budget still yields a positive M", func(t *testing.T) {
		if got := DefaultWatermarkInterval(time.Nanosecond); got != time.Second {
			t.Errorf("DefaultWatermarkInterval(1ns) = %s, want 1s", got)
		}
		if got := DefaultWatermarkInterval(0); got != time.Second {
			t.Errorf("DefaultWatermarkInterval(0) = %s, want 1s", got)
		}
	})

	t.Run("negatives are rejected", func(t *testing.T) {
		if _, err := (WatermarkPolicy{DastFindings: -1}).Resolve(fourHours); !errors.Is(err, ErrInvalidWatermarkPolicy) {
			t.Errorf("negative N error = %v, want ErrInvalidWatermarkPolicy", err)
		}
		if _, err := (WatermarkPolicy{Interval: -time.Second}).Resolve(fourHours); !errors.Is(err, ErrInvalidWatermarkPolicy) {
			t.Errorf("negative M error = %v, want ErrInvalidWatermarkPolicy", err)
		}
	})

	t.Run("NewController rejects an invalid watermark policy", func(t *testing.T) {
		if _, err := NewController(dastPolicy(), WatermarkPolicy{DastFindings: -5}); !errors.Is(err, ErrInvalidWatermarkPolicy) {
			t.Errorf("NewController error = %v, want ErrInvalidWatermarkPolicy", err)
		}
	})

	t.Run("NewController rejects an invalid deadline policy", func(t *testing.T) {
		if _, err := NewController(DeadlinePolicy{ClaimTimeoutSeconds: -1}, WatermarkPolicy{}); !errors.Is(err, ErrInvalidDeadlinePolicy) {
			t.Errorf("NewController error = %v, want ErrInvalidDeadlinePolicy", err)
		}
	})
}

// With no DAST half there is no DAST deadline, so M is derived from half the
// claim window — the same quantity DefaultDastDeadlineSeconds would produce.
// M must not jump when an operator installs `anvil-dast` and takes the default.
func TestWatermarkIntervalIsStableAcrossTheDastInstall(t *testing.T) {
	withDast, err := NewController(dastPolicy(), WatermarkPolicy{})
	if err != nil {
		t.Fatalf("NewController(dast): %v", err)
	}
	withoutDast, err := NewController(sastOnlyPolicy(), WatermarkPolicy{})
	if err != nil {
		t.Fatalf("NewController(sast-only): %v", err)
	}
	if a, b := withDast.Watermarks().Interval, withoutDast.Watermarks().Interval; a != b {
		t.Errorf("M jumped across the anvil-dast install: %s vs %s", a, b)
	}
	if got := withDast.Watermarks().Interval; got != 15*time.Minute {
		t.Errorf("Interval = %s, want 15m at the shipped defaults", got)
	}
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

func TestNextWakeWidensDeadlinesWithTheTimeWatermark(t *testing.T) {
	ctl, clk := newTestController(t, dastPolicy(), WatermarkPolicy{DastFindings: 1000, Interval: 15 * time.Minute})
	rec := mustBegin(t, ctl, "audit-nextwake")

	// With nothing pending, the next wake is clock 3 at t+4h.
	at, ok := ctl.NextWake(rec)
	if !ok || !at.Equal(baseTime.Add(4*time.Hour)) {
		t.Fatalf("NextWake = (%s, %v), want (%s, true)", at, ok, baseTime.Add(4*time.Hour))
	}

	// One unpublished DAST finding pulls the wake forward to the M boundary,
	// which Deadlines alone cannot know about.
	rec = mustTransition(t, ctl, rec, FindingsEvent(record.HalfDast, finding("a")))
	at, ok = ctl.NextWake(rec)
	if !ok || !at.Equal(baseTime.Add(15*time.Minute)) {
		t.Fatalf("NextWake with pending findings = (%s, %v), want (%s, true)", at, ok, baseTime.Add(15*time.Minute))
	}

	// Past both deadlines with nothing pending, there is nothing to wait for.
	clk.set(9 * time.Hour)
	rec = mustTransition(t, ctl, rec, TickEvent())
	if at, ok := ctl.NextWake(rec); ok {
		t.Errorf("NextWake = (%s, true) past both deadlines, want ok=false", at)
	}
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

// The event vocabulary must not collide with any of R.1's frozen enums. A
// collision is how "two areas meaning different things by the same field name"
// starts, and this package owns no vocabulary at all.
func TestEventKindsDoNotCollideWithFrozenEnums(t *testing.T) {
	frozen := map[string]string{}
	for _, v := range record.StateValues() {
		frozen[string(v)] = "anvil/state"
	}
	for _, v := range record.HalfStatusValues() {
		frozen[string(v)] = "anvil/status"
	}
	for _, v := range record.DastStatusValues() {
		frozen[string(v)] = "anvil/dastStatus"
	}
	for _, k := range EventKindValues() {
		if field, clash := frozen[string(k)]; clash {
			t.Errorf("EventKind %q collides with a %s literal", k, field)
		}
		if !k.Valid() {
			t.Errorf("EventKind %q is not reported valid by its own predicate", k)
		}
	}
	if EventKind("").Valid() {
		t.Error("the empty EventKind must not be valid")
	}
}

func TestTransitionErrorNamesTheCaller(t *testing.T) {
	ctl, _ := newTestController(t, dastPolicy(), WatermarkPolicy{})
	rec := mustBegin(t, ctl, "audit-error-message")

	_, err := ctl.Transition(rec, FindingsEvent(record.HalfSast))
	var te *TransitionError
	if !errors.As(err, &te) {
		t.Fatalf("error %v is not a *TransitionError", err)
	}
	if te.AuditID != "audit-error-message" || te.Kind != EventKindFindings ||
		te.Half != record.HalfSast || te.State != record.StateCollecting {
		t.Errorf("TransitionError does not identify the caller: %+v", te)
	}
	if te.Error() == "" {
		t.Error("empty error message")
	}
}
