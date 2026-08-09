package record

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// scanStart is a fixed scan_run.started_at for every test here, so that any
// movement in deadline_at is a bug and not clock jitter.
var scanStart = time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)

// fixedClock returns a clock function whose value the caller can advance.
func fixedClock(t *time.Time) func() time.Time {
	return func() time.Time { return *t }
}

// newTestSealer returns a Sealer on a controllable clock, plus a pointer the
// test moves to advance time.
func newTestSealer(t *testing.T) (*Sealer, *time.Time) {
	t.Helper()
	now := scanStart
	s := NewSealer()
	s.SetClock(fixedClock(&now))
	return s, &now
}

// beginSAST starts a DAST-DISABLED audit — plan/00-SPINE.md S9-AMENDED's
// common case, the core `anvil` artifact with no probing capability compiled
// in.
func beginSAST(t *testing.T, s *Sealer, id string) AuditSeal {
	t.Helper()
	seal, err := s.BeginAudit(AuditConfig{AuditID: id, StartedAt: scanStart})
	if err != nil {
		t.Fatalf("BeginAudit(%q): %v", id, err)
	}
	return seal
}

// beginDAST starts a DAST-ENABLED audit with a target that booted cleanly.
func beginDAST(t *testing.T, s *Sealer, id string) AuditSeal {
	t.Helper()
	dastDeadline := 1800
	seal, err := s.BeginAudit(AuditConfig{
		AuditID:             id,
		StartedAt:           scanStart,
		DastEnabled:         true,
		DastDeadlineSeconds: &dastDeadline,
	})
	if err != nil {
		t.Fatalf("BeginAudit(%q): %v", id, err)
	}
	if err := s.RecordDastOutcome(id, DastOutcome{Provenance: TargetProvenanceBootedClean}); err != nil {
		t.Fatalf("RecordDastOutcome(%q): %v", id, err)
	}
	return seal
}

// ---------------------------------------------------------------------------
// THE HARD READ GATE
// ---------------------------------------------------------------------------

// TestReadGateRefusesEveryNonSealedStatus is R.6's central obligation, stated
// directly: "no consumer may read a half's results before that half's status
// equals sealed."
//
// It walks EVERY HalfStatus other than HalfStatusSealed — including the three
// terminal ones, which advance `anvil/state` and are the easy ones to mistake
// for readable — and asserts the read is refused with a typed *ReadGateError
// carrying no seal data.
//
// plan/IMPLEMENTATION-PLAN.md §6 ruling G5 records why this test exists: area
// O keyed its transitions on `complete`, "which meant the gate never opens".
func TestReadGateRefusesEveryNonSealedStatus(t *testing.T) {
	for _, half := range HalfValues() {
		for _, status := range HalfStatusValues() {
			if status == HalfStatusSealed {
				continue // the one value that legitimately opens the gate
			}
			name := fmt.Sprintf("%s/%s", half, status)
			t.Run(name, func(t *testing.T) {
				s, _ := newTestSealer(t)
				id := "audit-" + name
				beginDAST(t, s, id)

				// HalfStatusRunning is the initial state; the rest are
				// reached by sealing.
				if status != HalfStatusRunning {
					if err := s.SealHalf(id, half, status); err != nil {
						t.Fatalf("SealHalf(%s, %s): %v", half, status, err)
					}
				}

				seal, err := s.ReadHalf(id, half)
				if err == nil {
					t.Fatalf("ReadHalf(%s) returned seal %+v with status %q; the gate must refuse everything but %q",
						half, seal, status, HalfStatusSealed)
				}
				if !errors.Is(err, ErrHalfNotSealed) {
					t.Errorf("ReadHalf error %v does not match ErrHalfNotSealed", err)
				}
				var gate *ReadGateError
				if !errors.As(err, &gate) {
					t.Fatalf("ReadHalf error %v is not a *ReadGateError; R.6 requires a TYPED refusal", err)
				}
				if gate.Half != half || gate.Status != status {
					t.Errorf("ReadGateError = {half:%q status:%q}, want {half:%q status:%q}",
						gate.Half, gate.Status, half, status)
				}
				if seal != (HalfSeal{}) {
					t.Errorf("refused read returned %+v; it must be the zero value, never a partial result", seal)
				}

				// And the same refusal is visible through the bool API.
				sastReady, dastReady := s.ReadyForConsumption(id)
				ready := sastReady
				if half == HalfDast {
					ready = dastReady
				}
				if ready {
					t.Errorf("ReadyForConsumption reports %s ready at status %q", half, status)
				}
			})
		}
	}
}

// TestReadGateOpensOnlyAtSealed is the positive half: the gate does open, and
// it stamps `anvil/sealedAt`.
func TestReadGateOpensOnlyAtSealed(t *testing.T) {
	s, now := newTestSealer(t)
	beginDAST(t, s, "a")

	*now = scanStart.Add(11 * time.Minute)
	if err := s.SealHalf("a", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}

	seal, err := s.ReadHalf("a", HalfSast)
	if err != nil {
		t.Fatalf("ReadHalf after seal: %v", err)
	}
	if seal.Status != HalfStatusSealed {
		t.Errorf("Status = %q, want %q", seal.Status, HalfStatusSealed)
	}
	if seal.SealedAt == nil {
		t.Fatal("SealedAt is nil on a sealed half; contract.go requires it once Status == sealed")
	}
	if got, want := seal.SealedAt.UTC(), scanStart.Add(11*time.Minute); !got.Equal(want) {
		t.Errorf("SealedAt = %v, want %v", got, want)
	}
	if !seal.Readable() {
		t.Error("HalfSeal.Readable() is false for a sealed half")
	}

	// The DAST half is still running, so it is still refused. The two halves
	// gate INDEPENDENTLY (plan/00-SPINE.md S1).
	if _, err := s.ReadHalf("a", HalfDast); !errors.Is(err, ErrHalfNotSealed) {
		t.Errorf("DAST read after a SAST-only seal: err = %v, want ErrHalfNotSealed", err)
	}
	sastReady, dastReady := s.ReadyForConsumption("a")
	if !sastReady || dastReady {
		t.Errorf("ReadyForConsumption = (%v, %v), want (true, false)", sastReady, dastReady)
	}
}

// TestSealedAtNilForEveryUnsealedTerminalStatus pins contract.go's rule that
// `anvil/sealedAt` is "required once Status == HalfStatusSealed, and is
// explicitly null otherwise". A failed half with a timestamp would read as a
// completion in `audit_record.sast_sealed_at`.
func TestSealedAtNilForEveryUnsealedTerminalStatus(t *testing.T) {
	for _, status := range []HalfStatus{HalfStatusFailed, HalfStatusTimedOut, HalfStatusSkipped} {
		t.Run(string(status), func(t *testing.T) {
			s, now := newTestSealer(t)
			id := "a-" + string(status)
			beginDAST(t, s, id)
			*now = scanStart.Add(time.Hour)

			if err := s.SealHalf(id, HalfSast, status); err != nil {
				t.Fatalf("SealHalf: %v", err)
			}
			snap, ok := s.Inspect(id)
			if !ok {
				t.Fatal("Inspect: audit not found")
			}
			if snap.Sast.SealedAt != nil {
				t.Errorf("sast_sealed_at = %v for status %q; must be NULL", *snap.Sast.SealedAt, status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DAST-DISABLED AUDITS REACH both_sealed
// ---------------------------------------------------------------------------

// TestDastDisabledAuditReachesBothSealed is the case
// plan/IMPLEMENTATION-PLAN.md §6 ruling G2 says area O's four-state machine
// could not express, and the reason area 40's six-value enum won.
//
// A core `anvil` install (plan/00-SPINE.md S9-AMENDED: no DAST artifact, so
// no DAST worker exists to seal anything) must still reach StateBothSealed on
// its SAST seal alone, with dast_status = 'not_run' — never NULL and never
// 'completed_clean'.
func TestDastDisabledAuditReachesBothSealed(t *testing.T) {
	s, _ := newTestSealer(t)
	seal := beginSAST(t, s, "sast-only")

	// Before any seal, the DAST half is ALREADY terminal, so the audit sits
	// in dast_sealed — a state area O's machine had no value for.
	if seal.State != StateDastSealed {
		t.Errorf("initial state = %q, want %q", seal.State, StateDastSealed)
	}
	if seal.Dast.Status != HalfStatusSkipped {
		t.Errorf("dast half status = %q, want %q", seal.Dast.Status, HalfStatusSkipped)
	}
	if seal.DastStatus != DastStatusNotRun {
		t.Errorf("dast_status = %q, want %q", seal.DastStatus, DastStatusNotRun)
	}

	if err := s.SealHalf("sast-only", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}

	snap, ok := s.Inspect("sast-only")
	if !ok {
		t.Fatal("Inspect: audit not found")
	}
	if snap.State != StateBothSealed {
		t.Fatalf("state = %q, want %q — a DAST-disabled audit that cannot reach both_sealed wedges the consumer forever",
			snap.State, StateBothSealed)
	}
	if snap.DastStatus != DastStatusNotRun {
		t.Errorf("dast_status = %q, want %q", snap.DastStatus, DastStatusNotRun)
	}
	if snap.DastStatus == "" {
		t.Error("dast_status is empty; audit_record.dast_status is NOT NULL")
	}
	if snap.Dast.SealedAt != nil {
		t.Errorf("dast_sealed_at = %v; a skipped half never cleanly sealed", *snap.Dast.SealedAt)
	}

	// both_sealed does NOT open the DAST read gate: there is nothing to read.
	sastReady, dastReady := s.ReadyForConsumption("sast-only")
	if !sastReady {
		t.Error("sastReady is false after the SAST half sealed")
	}
	if dastReady {
		t.Error("dastReady is true for a DAST-disabled audit; there are no DAST results to read")
	}
	if _, err := s.ReadHalf("sast-only", HalfDast); !errors.Is(err, ErrHalfNotSealed) {
		t.Errorf("ReadHalf(dast) on a DAST-disabled audit: err = %v, want ErrHalfNotSealed", err)
	}

	// And the audit is consumable, which is the whole point.
	if err := s.Consume("sast-only"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
}

// TestDastDisabledDistinguishableFromCleanDastScan is R.6's named validation
// item: "a test asserting a DAST-disabled scan's dast_status is
// distinguishable from a DAST-enabled scan that found nothing
// ('completed_clean')".
//
// research/23 Risk #1: "Anvil must never report '0 DAST findings' as 'no
// dynamic vulnerabilities'." Both audits below have zero DAST findings; only
// one of them was dynamically scanned.
func TestDastDisabledDistinguishableFromCleanDastScan(t *testing.T) {
	s, _ := newTestSealer(t)

	beginSAST(t, s, "disabled")
	if err := s.SealHalf("disabled", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf(disabled): %v", err)
	}

	beginDAST(t, s, "enabled-clean")
	if err := s.RecordDastOutcome("enabled-clean", DastOutcome{
		Provenance:   TargetProvenanceBootedClean,
		FindingCount: 0,
	}); err != nil {
		t.Fatalf("RecordDastOutcome: %v", err)
	}
	if err := s.SealHalf("enabled-clean", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf(enabled-clean, sast): %v", err)
	}
	if err := s.SealHalf("enabled-clean", HalfDast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf(enabled-clean, dast): %v", err)
	}

	disabled, _ := s.Inspect("disabled")
	clean, _ := s.Inspect("enabled-clean")

	if disabled.State != StateBothSealed || clean.State != StateBothSealed {
		t.Fatalf("states = (%q, %q); both audits must reach both_sealed", disabled.State, clean.State)
	}
	if disabled.DastStatus == clean.DastStatus {
		t.Fatalf("both audits report dast_status %q; a scan that never ran must not look like a clean scan",
			disabled.DastStatus)
	}
	if disabled.DastStatus != DastStatusNotRun {
		t.Errorf("DAST-disabled dast_status = %q, want %q", disabled.DastStatus, DastStatusNotRun)
	}
	if clean.DastStatus != DastStatusCompletedClean {
		t.Errorf("DAST-enabled clean dast_status = %q, want %q", clean.DastStatus, DastStatusCompletedClean)
	}

	// The semantic predicate contract.go provides for exactly this question.
	if disabled.DastStatus.MeansDynamicallyScannedClean() {
		t.Error("a DAST-disabled audit reports MeansDynamicallyScannedClean")
	}
	if !clean.DastStatus.MeansDynamicallyScannedClean() {
		t.Error("a clean DAST scan does not report MeansDynamicallyScannedClean")
	}

	// And the read gate distinguishes them too: only the scanned one is
	// readable.
	if _, dastReady := s.ReadyForConsumption("disabled"); dastReady {
		t.Error("DAST-disabled audit reports dastReady")
	}
	if _, dastReady := s.ReadyForConsumption("enabled-clean"); !dastReady {
		t.Error("cleanly scanned DAST half is not readable")
	}
}

// ---------------------------------------------------------------------------
// deadline_at is anchored to scan START
// ---------------------------------------------------------------------------

// TestDeadlineAnchoredToScanStart pins the formula.
func TestDeadlineAnchoredToScanStart(t *testing.T) {
	s, _ := newTestSealer(t)

	seal, err := s.BeginAudit(AuditConfig{
		AuditID: "d", StartedAt: scanStart, ClaimTimeoutSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if want := scanStart.Add(time.Hour); !seal.DeadlineAt.Equal(want) {
		t.Errorf("DeadlineAt = %v, want %v", seal.DeadlineAt, want)
	}
	if !seal.DeadlineAt.Equal(ComputeDeadline(scanStart, 3600)) {
		t.Error("DeadlineAt disagrees with ComputeDeadline")
	}

	// The documented default is 8 hours.
	def, err := s.BeginAudit(AuditConfig{AuditID: "d2", StartedAt: scanStart})
	if err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if want := scanStart.Add(DefaultClaimTimeoutSeconds * time.Second); !def.DeadlineAt.Equal(want) {
		t.Errorf("default DeadlineAt = %v, want %v", def.DeadlineAt, want)
	}
	if def.ClaimTimeoutSeconds != DefaultClaimTimeoutSeconds {
		t.Errorf("ClaimTimeoutSeconds = %d, want %d", def.ClaimTimeoutSeconds, DefaultClaimTimeoutSeconds)
	}
}

// TestDeadlineUnchangedByLateSeal is R.6's second named validation item: "a
// test asserting `deadline_at` is unchanged by a late write to either half".
//
// R.6's forbidden actions: "Do not compute `deadline_at` from any write
// timestamp". Anchoring the claim clock to the last write makes the timeout
// unbounded for a chatty scan, so the reaper never fires.
func TestDeadlineUnchangedByLateSeal(t *testing.T) {
	s, now := newTestSealer(t)
	initial := beginDAST(t, s, "late")
	want := initial.DeadlineAt

	// Every subsequent operation happens far past the deadline. None of them
	// may move it.
	steps := []struct {
		name    string
		advance time.Duration
		do      func() error
	}{
		{"record dast outcome", 3 * time.Hour, func() error {
			return s.RecordDastOutcome("late", DastOutcome{
				Provenance: TargetProvenanceBootedClean, FindingCount: 4,
			})
		}},
		{"seal sast", 9 * time.Hour, func() error {
			return s.SealHalf("late", HalfSast, HalfStatusSealed)
		}},
		{"seal dast", 40 * time.Hour, func() error {
			return s.SealHalf("late", HalfDast, HalfStatusSealed)
		}},
		{"read sast", 90 * time.Hour, func() error {
			_, err := s.ReadHalf("late", HalfSast)
			return err
		}},
		{"consume", 200 * time.Hour, func() error {
			return s.Consume("late")
		}},
	}
	for _, step := range steps {
		*now = scanStart.Add(step.advance)
		if err := step.do(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		snap, ok := s.Inspect("late")
		if !ok {
			t.Fatalf("%s: Inspect: audit not found", step.name)
		}
		if !snap.DeadlineAt.Equal(want) {
			t.Fatalf("after %s at %v: DeadlineAt = %v, want %v — deadline_at must never be recomputed from a write timestamp",
				step.name, *now, snap.DeadlineAt, want)
		}
		if !snap.StartedAt.Equal(scanStart) {
			t.Fatalf("after %s: StartedAt = %v, want %v", step.name, snap.StartedAt, scanStart)
		}
	}

	// And sealedAt DID move with the clock — proving the two are independent
	// clocks, not one clock read twice.
	snap, _ := s.Inspect("late")
	if snap.Sast.SealedAt == nil {
		t.Fatal("sast SealedAt is nil after a clean seal")
	}
	if snap.Sast.SealedAt.Equal(snap.DeadlineAt) {
		t.Error("sealedAt equals deadlineAt; R.6 forbids conflating the per-half seal with the claim clock")
	}
	if !snap.Sast.SealedAt.After(snap.DeadlineAt) {
		t.Errorf("sealedAt %v did not track the clock past deadlineAt %v", snap.Sast.SealedAt, snap.DeadlineAt)
	}
}

// TestSealHalfDoesNotResetOnIdempotentReseal proves a retried write cannot
// move `anvil/sealedAt` either.
func TestSealHalfDoesNotResetOnIdempotentReseal(t *testing.T) {
	s, now := newTestSealer(t)
	beginDAST(t, s, "retry")

	*now = scanStart.Add(time.Minute)
	if err := s.SealHalf("retry", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	first, _ := s.Inspect("retry")

	*now = scanStart.Add(5 * time.Hour)
	if err := s.SealHalf("retry", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("idempotent re-seal: %v", err)
	}
	second, _ := s.Inspect("retry")

	if !second.Sast.SealedAt.Equal(*first.Sast.SealedAt) {
		t.Errorf("SealedAt moved from %v to %v on a repeated seal",
			*first.Sast.SealedAt, *second.Sast.SealedAt)
	}
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

// TestDeriveStateCoversEveryCombination walks all 25 (sast, dast) status
// pairs and asserts the derived state, then asserts every one of the four
// derivable states is actually produced — including StateDastSealed, whose
// unreachability in area O's machine is what ruling G2 struck.
func TestDeriveStateCoversEveryCombination(t *testing.T) {
	seen := map[State]bool{}
	for _, sast := range HalfStatusValues() {
		for _, dast := range HalfStatusValues() {
			got := DeriveState(sast, dast)
			var want State
			switch {
			case IsTerminalHalfStatus(sast) && IsTerminalHalfStatus(dast):
				want = StateBothSealed
			case IsTerminalHalfStatus(sast):
				want = StateSastSealed
			case IsTerminalHalfStatus(dast):
				want = StateDastSealed
			default:
				want = StateCollecting
			}
			if got != want {
				t.Errorf("DeriveState(%q, %q) = %q, want %q", sast, dast, got, want)
			}
			if err := ValidateState(string(got)); err != nil {
				t.Errorf("DeriveState(%q, %q) produced an illegal literal: %v", sast, dast, err)
			}
			seen[got] = true
		}
	}
	for _, want := range []State{StateCollecting, StateSastSealed, StateDastSealed, StateBothSealed} {
		if !seen[want] {
			t.Errorf("state %q is unreachable from DeriveState", want)
		}
	}
}

// TestDastFirstSealReachesDastSealed is plan/00-SPINE.md S1's "two
// INDEPENDENTLY-sealed halves" in its awkward direction: the DAST half seals
// first while the SAST half is still running. Ruling G2: area O's machine
// "cannot express a DAST-first seal at all".
func TestDastFirstSealReachesDastSealed(t *testing.T) {
	s, _ := newTestSealer(t)
	beginDAST(t, s, "dast-first")

	if err := s.SealHalf("dast-first", HalfDast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf(dast): %v", err)
	}
	snap, _ := s.Inspect("dast-first")
	if snap.State != StateDastSealed {
		t.Fatalf("state = %q, want %q", snap.State, StateDastSealed)
	}
	if _, err := s.ReadHalf("dast-first", HalfDast); err != nil {
		t.Errorf("DAST half is sealed but unreadable: %v", err)
	}
	if _, err := s.ReadHalf("dast-first", HalfSast); !errors.Is(err, ErrHalfNotSealed) {
		t.Errorf("SAST read while running: err = %v, want ErrHalfNotSealed", err)
	}

	// The SAST half can still fail after a DAST seal, and the audit still
	// reaches both_sealed.
	if err := s.SealHalf("dast-first", HalfSast, HalfStatusFailed); err != nil {
		t.Fatalf("SealHalf(sast, failed): %v", err)
	}
	snap, _ = s.Inspect("dast-first")
	if snap.State != StateBothSealed {
		t.Errorf("state = %q, want %q", snap.State, StateBothSealed)
	}
	// ...but a failed half is not a readable half.
	if _, err := s.ReadHalf("dast-first", HalfSast); !errors.Is(err, ErrHalfNotSealed) {
		t.Errorf("failed SAST half is readable: err = %v", err)
	}
}

// TestSealHalfRejectsNonTerminalStatus: "still running" is not a seal.
func TestSealHalfRejectsNonTerminalStatus(t *testing.T) {
	s, _ := newTestSealer(t)
	beginDAST(t, s, "a")

	err := s.SealHalf("a", HalfSast, HalfStatusRunning)
	if !errors.Is(err, ErrNotSealable) {
		t.Fatalf("SealHalf(running) = %v, want ErrNotSealable", err)
	}
	var se *SealingError
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a *SealingError", err)
	}
	snap, _ := s.Inspect("a")
	if snap.State != StateCollecting {
		t.Errorf("state = %q after a refused seal, want %q", snap.State, StateCollecting)
	}
}

// TestSealHalfRejectsConflictingReseal: a half seals once.
func TestSealHalfRejectsConflictingReseal(t *testing.T) {
	s, _ := newTestSealer(t)
	beginDAST(t, s, "a")

	if err := s.SealHalf("a", HalfSast, HalfStatusFailed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	err := s.SealHalf("a", HalfSast, HalfStatusSealed)
	if !errors.Is(err, ErrHalfAlreadySealed) {
		t.Fatalf("re-seal failed->sealed = %v, want ErrHalfAlreadySealed", err)
	}
	snap, _ := s.Inspect("a")
	if snap.Sast.Status != HalfStatusFailed {
		t.Errorf("status = %q after a refused re-seal, want %q", snap.Sast.Status, HalfStatusFailed)
	}
	if _, rerr := s.ReadHalf("a", HalfSast); !errors.Is(rerr, ErrHalfNotSealed) {
		t.Errorf("a failed half became readable via a refused re-seal: %v", rerr)
	}
}

// TestDastDisabledHalfCannotBeSealedClean: the core artifact has no DAST
// capability, so nothing may later claim its DAST half sealed.
func TestDastDisabledHalfCannotBeSealedClean(t *testing.T) {
	s, _ := newTestSealer(t)
	beginSAST(t, s, "a")

	if err := s.SealHalf("a", HalfDast, HalfStatusSealed); !errors.Is(err, ErrHalfAlreadySealed) {
		t.Fatalf("sealing a DAST-disabled half = %v, want ErrHalfAlreadySealed", err)
	}
	snap, _ := s.Inspect("a")
	if snap.DastStatus != DastStatusNotRun {
		t.Errorf("dast_status = %q, want %q", snap.DastStatus, DastStatusNotRun)
	}
	// Repeating the skip it already has is a harmless no-op.
	if err := s.SealHalf("a", HalfDast, HalfStatusSkipped); err != nil {
		t.Errorf("idempotent skip: %v", err)
	}
}

// TestRecordDastOutcomeCannotClaimAnUninstalledTier: TierInstalled is taken
// from the audit, never from the caller.
func TestRecordDastOutcomeCannotClaimAnUninstalledTier(t *testing.T) {
	s, _ := newTestSealer(t)
	beginSAST(t, s, "a")

	err := s.RecordDastOutcome("a", DastOutcome{
		TierInstalled: true,
		Provenance:    TargetProvenanceBootedClean,
		FindingCount:  0,
	})
	// The DAST half is already terminally skipped, so the outcome is frozen.
	if !errors.Is(err, ErrHalfAlreadySealed) {
		t.Fatalf("RecordDastOutcome on a DAST-disabled audit = %v, want ErrHalfAlreadySealed", err)
	}
	snap, _ := s.Inspect("a")
	if snap.DastStatus != DastStatusNotRun {
		t.Errorf("dast_status = %q, want %q", snap.DastStatus, DastStatusNotRun)
	}
}

// ---------------------------------------------------------------------------
// Consumption and expiry
// ---------------------------------------------------------------------------

// TestConsumeRequiresBothSealed.
func TestConsumeRequiresBothSealed(t *testing.T) {
	s, _ := newTestSealer(t)
	beginDAST(t, s, "a")

	if err := s.Consume("a"); !errors.Is(err, ErrNotBothSealed) {
		t.Fatalf("Consume while collecting = %v, want ErrNotBothSealed", err)
	}
	if err := s.SealHalf("a", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	if err := s.Consume("a"); !errors.Is(err, ErrNotBothSealed) {
		t.Fatalf("Consume at sast_sealed = %v, want ErrNotBothSealed", err)
	}
	if err := s.SealHalf("a", HalfDast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	if err := s.Consume("a"); err != nil {
		t.Fatalf("Consume at both_sealed: %v", err)
	}
	snap, _ := s.Inspect("a")
	if snap.State != StateConsumed {
		t.Errorf("state = %q, want %q", snap.State, StateConsumed)
	}
}

// TestConsumerIsReEntrant: plan/00-SPINE.md S1 requires a RE-ENTRANT
// consumer, so consuming the record must not shut the gate behind it.
func TestConsumerIsReEntrant(t *testing.T) {
	s, _ := newTestSealer(t)
	beginDAST(t, s, "a")
	for _, half := range HalfValues() {
		if err := s.SealHalf("a", half, HalfStatusSealed); err != nil {
			t.Fatalf("SealHalf(%s): %v", half, err)
		}
	}
	if err := s.Consume("a"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := s.Consume("a"); err != nil {
		t.Fatalf("second Consume: %v — consumption must be idempotent", err)
	}
	for _, half := range HalfValues() {
		if _, err := s.ReadHalf("a", half); err != nil {
			t.Errorf("ReadHalf(%s) after consumption: %v — the consumer is re-entrant", half, err)
		}
	}
	sastReady, dastReady := s.ReadyForConsumption("a")
	if !sastReady || !dastReady {
		t.Errorf("ReadyForConsumption after consumption = (%v, %v), want (true, true)", sastReady, dastReady)
	}
}

// TestExpiryIsGovernedOnlyByDeadlineAt: nothing expires early, and an expired
// audit stops being readable because the reaper dropped its payload.
func TestExpiryIsGovernedOnlyByDeadlineAt(t *testing.T) {
	s, now := newTestSealer(t)
	seal, err := s.BeginAudit(AuditConfig{AuditID: "a", StartedAt: scanStart, ClaimTimeoutSeconds: 60})
	if err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := s.SealHalf("a", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}

	*now = seal.DeadlineAt.Add(-time.Nanosecond)
	if expired, err := s.ExpireIfDue("a"); err != nil || expired {
		t.Fatalf("ExpireIfDue one ns early = (%v, %v), want (false, nil)", expired, err)
	}
	if _, err := s.ReadHalf("a", HalfSast); err != nil {
		t.Fatalf("read before the deadline: %v", err)
	}

	*now = seal.DeadlineAt
	expired, err := s.ExpireIfDue("a")
	if err != nil || !expired {
		t.Fatalf("ExpireIfDue at the deadline = (%v, %v), want (true, nil)", expired, err)
	}
	snap, _ := s.Inspect("a")
	if snap.State != StateExpired {
		t.Errorf("state = %q, want %q", snap.State, StateExpired)
	}
	if _, err := s.ReadHalf("a", HalfSast); !errors.Is(err, ErrHalfNotSealed) {
		t.Errorf("read after expiry = %v, want ErrHalfNotSealed", err)
	}
	if sastReady, dastReady := s.ReadyForConsumption("a"); sastReady || dastReady {
		t.Errorf("ReadyForConsumption after expiry = (%v, %v), want (false, false)", sastReady, dastReady)
	}
	if err := s.SealHalf("a", HalfDast, HalfStatusSealed); !errors.Is(err, ErrAuditTerminal) {
		t.Errorf("seal after expiry = %v, want ErrAuditTerminal", err)
	}
}

// TestConsumedAuditIsNeverExpiredUnderItsConsumer.
func TestConsumedAuditIsNeverExpiredUnderItsConsumer(t *testing.T) {
	s, now := newTestSealer(t)
	seal, err := s.BeginAudit(AuditConfig{AuditID: "a", StartedAt: scanStart, ClaimTimeoutSeconds: 60})
	if err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := s.SealHalf("a", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	if err := s.Consume("a"); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	*now = seal.DeadlineAt.Add(time.Hour)
	if expired, err := s.ExpireIfDue("a"); err != nil || expired {
		t.Fatalf("ExpireIfDue on a consumed audit = (%v, %v), want (false, nil)", expired, err)
	}
	snap, _ := s.Inspect("a")
	if snap.State != StateConsumed {
		t.Errorf("state = %q, want %q", snap.State, StateConsumed)
	}
}

// ---------------------------------------------------------------------------
// DastStatus derivation
// ---------------------------------------------------------------------------

// TestDeriveDastStatusTable pins the whole mapping, value by value.
func TestDeriveDastStatusTable(t *testing.T) {
	clean := TargetProvenanceBootedClean
	cases := []struct {
		name    string
		status  HalfStatus
		outcome DastOutcome
		want    DastStatus
	}{
		{"tier absent", HalfStatusSkipped, DastOutcome{}, DastStatusNotRun},
		{"tier absent even when sealed", HalfStatusSealed, DastOutcome{}, DastStatusNotRun},
		{"running", HalfStatusRunning, DastOutcome{TierInstalled: true, Provenance: clean}, DastStatusRunning},
		{"boot failed", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: TargetProvenanceBootFailed}, DastStatusTargetBootFailed},
		{"build failed", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: TargetProvenanceBuildFailed}, DastStatusTargetBootFailed},
		{"unreachable", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: TargetProvenanceUnreachableAtScanTime}, DastStatusTargetUnreachable},
		{"no target declared", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: TargetProvenanceNoTargetDeclared}, DastStatusSkippedNoManifest},
		{"skipped with tier", HalfStatusSkipped, DastOutcome{TierInstalled: true, Provenance: clean}, DastStatusSkippedNoManifest},
		{"timed out", HalfStatusTimedOut, DastOutcome{TierInstalled: true, Provenance: clean}, DastStatusTimedOut},
		// A half that broke against a target that was up is a DAST-side
		// failure, not a coverage decision. Before the section 6 amendment
		// this derived completed_partial, which invited a reader to take
		// DastCoverage's numbers as a deliberate scope. CRITIQUE-02 F8/rule 8.
		{"failed mid-scan", HalfStatusFailed, DastOutcome{TierInstalled: true, Provenance: clean}, DastStatusCompletedFailed},
		{"sealed partial", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: clean, PartialCoverage: true}, DastStatusCompletedPartial},
		{"sealed partial outranks findings", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: clean, PartialCoverage: true, FindingCount: 3}, DastStatusCompletedPartial},
		{"sealed with findings", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: clean, FindingCount: 1}, DastStatusCompletedFindings},
		{"sealed clean", HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: clean}, DastStatusCompletedClean},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveDastStatus(tc.status, tc.outcome)
			if err != nil {
				t.Fatalf("DeriveDastStatus: %v", err)
			}
			if got != tc.want {
				t.Errorf("DeriveDastStatus(%q, %+v) = %q, want %q", tc.status, tc.outcome, got, tc.want)
			}
			if err := ValidateDastStatus(string(got)); err != nil {
				t.Errorf("derived an illegal anvil/dastStatus literal: %v", err)
			}
		})
	}
}

// TestCompletedCleanIsUnreachableWithoutAScannedTarget is S6's requirement
// stated as a negative: "a target that failed to boot must be
// distinguishable from 'scanned clean'". Zero findings plus a sealed half is
// NOT sufficient for DastStatusCompletedClean; the target must also have
// booted cleanly.
func TestCompletedCleanIsUnreachableWithoutAScannedTarget(t *testing.T) {
	for _, prov := range TargetProvenanceValues() {
		if prov == TargetProvenanceBootedClean {
			continue
		}
		for _, status := range HalfStatusValues() {
			got, err := DeriveDastStatus(status, DastOutcome{
				TierInstalled: true, Provenance: prov, FindingCount: 0,
			})
			if err != nil {
				t.Fatalf("DeriveDastStatus(%q, %q): %v", status, prov, err)
			}
			if got == DastStatusCompletedClean {
				t.Errorf("DeriveDastStatus(%q, provenance=%q) = %q; a target that never scanned cleanly must not report clean",
					status, prov, got)
			}
			if got.MeansDynamicallyScannedClean() {
				t.Errorf("provenance %q with status %q reports MeansDynamicallyScannedClean", prov, status)
			}
		}
	}
}

// TestDeriveDastStatusRejectsIllegalLiterals: the derivation validates its
// inputs against contract.go's frozen enums rather than trusting them.
func TestDeriveDastStatusRejectsIllegalLiterals(t *testing.T) {
	if _, err := DeriveDastStatus(HalfStatus("complete"), DastOutcome{TierInstalled: true, Provenance: TargetProvenanceBootedClean}); err == nil {
		t.Error(`DeriveDastStatus accepted area O's struck "complete" token`)
	} else {
		var ee *EnumError
		if !errors.As(err, &ee) {
			t.Errorf("error %v is not an *EnumError", err)
		}
	}
	if _, err := DeriveDastStatus(HalfStatusSealed, DastOutcome{TierInstalled: true, Provenance: TargetProvenance("ok")}); err == nil {
		t.Error("DeriveDastStatus accepted an illegal anvil/target.provenance")
	}
}

// ---------------------------------------------------------------------------
// Input validation and the package-level API
// ---------------------------------------------------------------------------

// TestBeginAuditRejectsUnusableConfigs.
func TestBeginAuditRejectsUnusableConfigs(t *testing.T) {
	negative := -1
	zero := 0
	cases := []struct {
		name string
		cfg  AuditConfig
	}{
		{"empty audit id", AuditConfig{StartedAt: scanStart}},
		{"zero start", AuditConfig{AuditID: "a"}},
		{"negative claim timeout", AuditConfig{AuditID: "a", StartedAt: scanStart, ClaimTimeoutSeconds: -1}},
		{"zero dast deadline", AuditConfig{AuditID: "a", StartedAt: scanStart, DastDeadlineSeconds: &zero}},
		{"negative dast deadline", AuditConfig{AuditID: "a", StartedAt: scanStart, DastDeadlineSeconds: &negative}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestSealer(t)
			if _, err := s.BeginAudit(tc.cfg); !errors.Is(err, ErrInvalidAuditConfig) {
				t.Fatalf("BeginAudit = %v, want ErrInvalidAuditConfig", err)
			}
		})
	}

	s, _ := newTestSealer(t)
	beginDAST(t, s, "dup")
	if _, err := s.BeginAudit(AuditConfig{AuditID: "dup", StartedAt: scanStart.Add(time.Hour)}); !errors.Is(err, ErrDuplicateAudit) {
		t.Errorf("re-BeginAudit = %v, want ErrDuplicateAudit — it would recompute deadline_at", err)
	}
	snap, _ := s.Inspect("dup")
	if !snap.StartedAt.Equal(scanStart) {
		t.Errorf("StartedAt = %v after a refused re-begin, want %v", snap.StartedAt, scanStart)
	}
}

// TestUnknownAuditIsAlwaysRefused: no operation silently invents an audit.
func TestUnknownAuditIsAlwaysRefused(t *testing.T) {
	s, _ := newTestSealer(t)

	if err := s.SealHalf("nope", HalfSast, HalfStatusSealed); !errors.Is(err, ErrUnknownAudit) {
		t.Errorf("SealHalf = %v, want ErrUnknownAudit", err)
	}
	if err := s.RecordDastOutcome("nope", DastOutcome{}); !errors.Is(err, ErrUnknownAudit) {
		t.Errorf("RecordDastOutcome = %v, want ErrUnknownAudit", err)
	}
	if err := s.Consume("nope"); !errors.Is(err, ErrUnknownAudit) {
		t.Errorf("Consume = %v, want ErrUnknownAudit", err)
	}
	if _, err := s.ExpireIfDue("nope"); !errors.Is(err, ErrUnknownAudit) {
		t.Errorf("ExpireIfDue = %v, want ErrUnknownAudit", err)
	}
	seal, err := s.ReadHalf("nope", HalfSast)
	if !errors.Is(err, ErrUnknownAudit) {
		t.Errorf("ReadHalf = %v, want ErrUnknownAudit", err)
	}
	if seal != (HalfSeal{}) {
		t.Errorf("ReadHalf on an unknown audit returned %+v", seal)
	}
	if sastReady, dastReady := s.ReadyForConsumption("nope"); sastReady || dastReady {
		t.Errorf("ReadyForConsumption on an unknown audit = (%v, %v), want (false, false)", sastReady, dastReady)
	}
	if _, ok := s.Inspect("nope"); ok {
		t.Error("Inspect reported an unknown audit as found")
	}
}

// TestSealHalfRejectsBareStringsOutsideTheFrozenEnums. The package-level
// SealHalf takes strings because it is a process boundary; it must reject
// anything that is not a contract.go literal, with an *EnumError naming the
// legal set. Area O's struck `complete` is the concrete regression this
// guards (plan/IMPLEMENTATION-PLAN.md §6 ruling G5).
func TestSealHalfRejectsBareStringsOutsideTheFrozenEnums(t *testing.T) {
	s, _ := newTestSealer(t)
	beginDAST(t, s, "a")

	if err := s.SealHalf("a", Half("both"), HalfStatusSealed); err == nil {
		t.Error(`SealHalf accepted half "both"`)
	} else {
		var ee *EnumError
		if !errors.As(err, &ee) {
			t.Errorf("half error %v is not an *EnumError", err)
		} else if ee.Field != "anvil/half" {
			t.Errorf("EnumError.Field = %q, want anvil/half", ee.Field)
		}
	}

	for _, bogus := range []string{"complete", "SEALED", "", "done"} {
		err := s.SealHalf("a", HalfSast, HalfStatus(bogus))
		if err == nil {
			t.Errorf("SealHalf accepted status %q", bogus)
			continue
		}
		var ee *EnumError
		if !errors.As(err, &ee) {
			t.Errorf("status error for %q is not an *EnumError: %v", bogus, err)
		}
	}
	snap, _ := s.Inspect("a")
	if snap.State != StateCollecting {
		t.Errorf("state = %q after refused seals, want %q", snap.State, StateCollecting)
	}
}

// TestPackageLevelAPIMatchesR6Signatures exercises the two functions R.6
// names by signature — SealHalf(auditID, half, status string) error and
// ReadyForConsumption(auditID string) (sastReady, dastReady bool) — on the
// default Sealer, threading contract.go's constants through rather than
// hand-typed literals.
func TestPackageLevelAPIMatchesR6Signatures(t *testing.T) {
	const id = "pkg-level-r6-audit"
	t.Cleanup(func() { DefaultSealer().Forget(id) })

	if _, err := BeginAudit(AuditConfig{AuditID: id, StartedAt: scanStart, DastEnabled: true}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := RecordDastOutcome(id, DastOutcome{Provenance: TargetProvenanceBootedClean, FindingCount: 2}); err != nil {
		t.Fatalf("RecordDastOutcome: %v", err)
	}

	if sastReady, dastReady := ReadyForConsumption(id); sastReady || dastReady {
		t.Fatalf("ReadyForConsumption before sealing = (%v, %v), want (false, false)", sastReady, dastReady)
	}
	if err := SealHalf(id, string(HalfSast), string(HalfStatusSealed)); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	if sastReady, dastReady := ReadyForConsumption(id); !sastReady || dastReady {
		t.Fatalf("ReadyForConsumption after the SAST seal = (%v, %v), want (true, false)", sastReady, dastReady)
	}
	if err := SealHalf(id, string(HalfDast), string(HalfStatusSealed)); err != nil {
		t.Fatalf("SealHalf(dast): %v", err)
	}
	if sastReady, dastReady := ReadyForConsumption(id); !sastReady || !dastReady {
		t.Fatalf("ReadyForConsumption after both seals = (%v, %v), want (true, true)", sastReady, dastReady)
	}
	if _, err := ReadHalf(id, HalfDast); err != nil {
		t.Fatalf("ReadHalf: %v", err)
	}
	snap, ok := Inspect(id)
	if !ok {
		t.Fatal("Inspect: audit not found")
	}
	if snap.State != StateBothSealed || snap.DastStatus != DastStatusCompletedFindings {
		t.Errorf("snapshot = {state:%q dast_status:%q}, want {%q %q}",
			snap.State, snap.DastStatus, StateBothSealed, DastStatusCompletedFindings)
	}
	if err := Consume(id); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if expired, err := ExpireIfDue(id); err != nil || expired {
		t.Errorf("ExpireIfDue on a consumed audit = (%v, %v), want (false, nil)", expired, err)
	}
}

// TestSnapshotDoesNotAliasSealerState: a caller mutating a snapshot must not
// reach back into the Sealer.
func TestSnapshotDoesNotAliasSealerState(t *testing.T) {
	s, _ := newTestSealer(t)
	beginDAST(t, s, "a")
	if err := s.SealHalf("a", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}

	snap, _ := s.Inspect("a")
	*snap.Sast.SealedAt = scanStart.Add(1000 * time.Hour)
	*snap.DastDeadlineSeconds = 999999

	fresh, _ := s.Inspect("a")
	if fresh.Sast.SealedAt.Equal(*snap.Sast.SealedAt) {
		t.Error("mutating a snapshot's SealedAt changed the Sealer's state")
	}
	if *fresh.DastDeadlineSeconds == *snap.DastDeadlineSeconds {
		t.Error("mutating a snapshot's DastDeadlineSeconds changed the Sealer's state")
	}
}

// TestConcurrentSealingAndReading exercises the mutex. The read gate is worth
// nothing if a consumer can observe a half mid-update; this fails loudly
// under `go test -race` in CI.
func TestConcurrentSealingAndReading(t *testing.T) {
	s, _ := newTestSealer(t)
	const audits = 16
	for i := 0; i < audits; i++ {
		beginDAST(t, s, fmt.Sprintf("a%d", i))
	}

	var wg sync.WaitGroup
	for i := 0; i < audits; i++ {
		id := fmt.Sprintf("a%d", i)
		for _, half := range HalfValues() {
			wg.Add(1)
			go func(half Half) {
				defer wg.Done()
				if err := s.SealHalf(id, half, HalfStatusSealed); err != nil {
					t.Errorf("SealHalf(%s, %s): %v", id, half, err)
				}
			}(half)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				seal, err := s.ReadHalf(id, HalfSast)
				if err != nil {
					if !errors.Is(err, ErrHalfNotSealed) {
						t.Errorf("ReadHalf(%s): unexpected error %v", id, err)
					}
					continue
				}
				// A successful read must be complete, never partial.
				if seal.Status != HalfStatusSealed || seal.SealedAt == nil {
					t.Errorf("ReadHalf(%s) returned a partial seal %+v", id, seal)
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.ReadyForConsumption(id)
			}
		}()
	}
	wg.Wait()

	for i := 0; i < audits; i++ {
		snap, _ := s.Inspect(fmt.Sprintf("a%d", i))
		if snap.State != StateBothSealed {
			t.Errorf("audit a%d state = %q, want %q", i, snap.State, StateBothSealed)
		}
	}
}

// TestHalfStatusClassificationMatchesContract keeps the terminal/readable
// split honest against contract.go's enum: every legal HalfStatus is
// classified, and exactly one is readable.
func TestHalfStatusClassificationMatchesContract(t *testing.T) {
	readable := 0
	for _, s := range HalfStatusValues() {
		if IsReadableHalfStatus(s) {
			readable++
			if !IsTerminalHalfStatus(s) {
				t.Errorf("%q is readable but not terminal", s)
			}
		}
		if s == HalfStatusRunning && IsTerminalHalfStatus(s) {
			t.Errorf("%q must not be terminal", s)
		}
		if s != HalfStatusRunning && !IsTerminalHalfStatus(s) {
			t.Errorf("%q must be terminal", s)
		}
	}
	if readable != 1 {
		t.Errorf("%d readable statuses, want exactly 1 (%q)", readable, HalfStatusSealed)
	}
	if len(TerminalHalfStatuses()) != len(HalfStatusValues())-1 {
		t.Errorf("TerminalHalfStatuses has %d values, want %d",
			len(TerminalHalfStatuses()), len(HalfStatusValues())-1)
	}
}

// ---------------------------------------------------------------------------
// Regression guards for CRITIQUE-02 (R.10 critic gate 2).
// ---------------------------------------------------------------------------

// TestDeriveDastStatusIsTotal is the amendment's real stop condition: after
// adding DastStatusCompletedFailed, EVERY (tier, provenance, half status) pair
// has exactly one image, and none of them is the empty string.
//
// `audit_record.dast_status` is NOT NULL and the enum carries no value meaning
// "unknown", so a pair with no image is not a cosmetic gap — it is a row the
// store cannot hold. Before the amendment the failed/booted_clean pair had no
// image of its own and was folded onto completed_partial; the test below
// asserts the mapping is total AND that the fold is gone.
func TestDeriveDastStatusIsTotal(t *testing.T) {
	seen := map[DastStatus]bool{}
	for _, tier := range []bool{false, true} {
		for _, prov := range TargetProvenanceValues() {
			for _, status := range HalfStatusValues() {
				for _, partial := range []bool{false, true} {
					for _, count := range []int{0, 3} {
						o := DastOutcome{
							TierInstalled:   tier,
							Provenance:      prov,
							PartialCoverage: partial,
							FindingCount:    count,
						}
						got, err := DeriveDastStatus(status, o)
						if err != nil {
							t.Fatalf("DeriveDastStatus(%q, %+v) errored: %v", status, o, err)
						}
						if got == "" {
							t.Fatalf("DeriveDastStatus(%q, %+v) produced the empty string; "+
								"audit_record.dast_status is NOT NULL and has no 'unknown' value", status, o)
						}
						if err := ValidateDastStatus(string(got)); err != nil {
							t.Fatalf("DeriveDastStatus(%q, %+v) = %q, not a legal literal: %v",
								status, o, got, err)
						}
						seen[got] = true
					}
				}
			}
		}
	}
	// Every value except `running` requires a non-running half; `running` is
	// reached above too, so the whole enum must be covered. A literal nothing
	// can derive is a literal the store can hold and no code can produce.
	for _, v := range DastStatusValues() {
		if !seen[v] {
			t.Errorf("no (tier, provenance, status) pair derives %q; it is unreachable", v)
		}
	}
}

// TestFailedHalfAgainstALiveTargetIsNotPartialCoverage is the F8/rule-8
// regression. A DAST half that CRASHED must not be reported as one that
// deliberately covered part of the surface, because DastCoverage's numbers
// mean different things in the two cases.
func TestFailedHalfAgainstALiveTargetIsNotPartialCoverage(t *testing.T) {
	got, err := DeriveDastStatus(HalfStatusFailed, DastOutcome{
		TierInstalled: true, Provenance: TargetProvenanceBootedClean,
	})
	if err != nil {
		t.Fatalf("DeriveDastStatus: %v", err)
	}
	if got == DastStatusCompletedPartial {
		t.Errorf("a failed DAST half against a booted_clean target derives %q; "+
			"a crash is not a coverage decision", got)
	}
	if got != DastStatusCompletedFailed {
		t.Errorf("DeriveDastStatus(failed, booted_clean) = %q, want %q", got, DastStatusCompletedFailed)
	}
	if got.MeansDynamicallyScannedClean() {
		t.Errorf("%q reports MeansDynamicallyScannedClean", got)
	}
	// completed_failed is reachable ONLY through a target that was actually up:
	// rules 3-5 outrank the half's own status.
	for _, prov := range TargetProvenanceValues() {
		if prov == TargetProvenanceBootedClean {
			continue
		}
		other, err := DeriveDastStatus(HalfStatusFailed, DastOutcome{TierInstalled: true, Provenance: prov})
		if err != nil {
			t.Fatalf("DeriveDastStatus(failed, %q): %v", prov, err)
		}
		if other == DastStatusCompletedFailed {
			t.Errorf("provenance %q derives %q; what happened to the TARGET outranks what happened to the half",
				prov, other)
		}
	}
}

// TestInspectHonoursTheExpiryArmOfTheReadGate reproduces CRITIQUE-02 F6
// directly: ReadHalf refuses an expired audit, and before the fix Inspect
// handed out the same HalfSeal with Readable() == true.
func TestInspectHonoursTheExpiryArmOfTheReadGate(t *testing.T) {
	s, now := newTestSealer(t)
	seal := beginSAST(t, s, "a")
	if err := s.SealHalf("a", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	// Readable before expiry, so the assertion after it is not vacuous.
	snap, ok := s.Inspect("a")
	if !ok || !snap.Sast.Readable() {
		t.Fatalf("a sealed SAST half is not readable before expiry: %+v", snap.Sast)
	}

	*now = seal.DeadlineAt.Add(time.Hour)
	if expired, err := s.ExpireIfDue("a"); err != nil || !expired {
		t.Fatalf("ExpireIfDue = (%v, %v), want (true, nil)", expired, err)
	}

	if _, err := s.ReadHalf("a", HalfSast); !errors.Is(err, ErrHalfNotSealed) {
		t.Fatalf("ReadHalf after expiry = %v, want a read-gate refusal", err)
	}
	snap, ok = s.Inspect("a")
	if !ok {
		t.Fatal("Inspect lost the audit")
	}
	if snap.Sast.Readable() {
		t.Errorf("Inspect reports the SAST half readable on an expired audit that ReadHalf refuses: %+v", snap.Sast)
	}
	// Inspect is a diagnostic and must still tell the truth about the status.
	if snap.Sast.Status != HalfStatusSealed {
		t.Errorf("Inspect hid the half's real status: %q", snap.Sast.Status)
	}
}

// TestInspectAgreesWithReadHalfOnEveryState is the structural half of the same
// fix: for every audit shape this package can produce, HalfSeal.Readable() and
// "ReadHalf returns without error" are the SAME predicate. Two exported
// readiness paths that can disagree make the gate advisory.
func TestInspectAgreesWithReadHalfOnEveryState(t *testing.T) {
	for _, half := range HalfValues() {
		for _, status := range HalfStatusValues() {
			for _, expire := range []bool{false, true} {
				for _, consume := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/expired=%v/consumed=%v", half, status, expire, consume)
					t.Run(name, func(t *testing.T) {
						s, now := newTestSealer(t)
						seal := beginDAST(t, s, "a")
						// Drive both halves to `status` where that is legal;
						// `running` simply leaves them alone.
						if IsTerminalHalfStatus(status) {
							for _, h := range HalfValues() {
								if err := s.SealHalf("a", h, status); err != nil {
									t.Fatalf("SealHalf(%s, %s): %v", h, status, err)
								}
							}
						}
						if consume {
							_ = s.Consume("a") // legal only from both_sealed
						}
						if expire {
							*now = seal.DeadlineAt.Add(time.Hour)
							if _, err := s.ExpireIfDue("a"); err != nil {
								t.Fatalf("ExpireIfDue: %v", err)
							}
						}

						snap, ok := s.Inspect("a")
						if !ok {
							t.Fatal("Inspect lost the audit")
						}
						inspected := snap.Sast
						if half == HalfDast {
							inspected = snap.Dast
						}
						_, readErr := s.ReadHalf("a", half)
						gateOpen := readErr == nil

						if inspected.Readable() != gateOpen {
							t.Errorf("Inspect(...).Readable() = %v but ReadHalf %s (state=%q status=%q); "+
								"the two exported readiness paths must not disagree",
								inspected.Readable(), map[bool]string{true: "succeeded", false: "refused"}[gateOpen],
								snap.State, inspected.Status)
						}
						// And the per-half accessor on the snapshot agrees too.
						if ready, _ := s.ReadyForConsumption("a"); half == HalfSast && ready != gateOpen {
							t.Errorf("ReadyForConsumption sast = %v, ReadHalf open = %v", ready, gateOpen)
						}
					})
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 B1/M1 — one gate, every spelling, every (state, status) pair
// ---------------------------------------------------------------------------

// TestEverySpellingOfTheReadGateAgrees drives the whole cross product of
// anvil/state and anvil/status through every exported way this package answers
// "may a consumer read this half's results?" and asserts they never disagree.
//
// The four historical bypasses (sealing.go's read-gate section) were all one
// shape: a second answer to a question that already had one. This test is what
// makes a second answer visible immediately, without waiting for a critic to
// find the consumer that acted on it.
func TestEverySpellingOfTheReadGateAgrees(t *testing.T) {
	for _, state := range StateValues() {
		for _, status := range HalfStatusValues() {
			seal := HalfSeal{Half: HalfSast, Status: status, AuditState: state}

			// (1) The bool spelling, which is what a caller branches on.
			readable := seal.Readable()

			// (2) The typed spelling, which is what a caller reports.
			err := HalfReadGate("audit-1", seal)
			if (err == nil) != readable {
				t.Errorf("state=%q status=%q: HalfReadGate says %v but Readable() says %t",
					state, status, err, readable)
			}
			if err != nil {
				if !errors.Is(err, ErrHalfNotSealed) {
					t.Errorf("state=%q status=%q: refusal does not match ErrHalfNotSealed: %v",
						state, status, err)
				}
				var rge *ReadGateError
				if !errors.As(err, &rge) {
					t.Errorf("state=%q status=%q: refusal is %T, want a *ReadGateError", state, status, err)
				} else {
					if rge.Status != status || rge.State != state || rge.Half != HalfSast {
						t.Errorf("state=%q status=%q: refusal reports half=%q status=%q state=%q",
							state, status, rge.Half, rge.Status, rge.State)
					}
					if rge.Reason == "" {
						t.Errorf("state=%q status=%q: refusal carries no reason", state, status)
					}
				}
			}

			// (3) The record-side spelling, built from a run and its envelope.
			// This is the projection readpath.go, taskcard.go and
			// sarif_github.go all go through, and the one CRITIQUE-03 found
			// two callers reaching around.
			l := &SARIFLog{
				Properties: AuditProperties{AuditID: "audit-1", State: state},
				Runs:       []Run{{Properties: RunProperties{Half: HalfSast, Status: status}}},
			}
			if got := halfSealOfRun(l, &l.Runs[0]).Readable(); got != readable {
				t.Errorf("state=%q status=%q: halfSealOfRun(...).Readable() = %t, want %t",
					state, status, got, readable)
			}

			// (4) The two arms are BOTH load-bearing, and neither alone is the
			// gate. This is the assertion that fails if someone "simplifies"
			// the gate back to one of its halves.
			statusArm := IsReadableHalfStatus(status)
			if statusArm && state == StateExpired && readable {
				t.Errorf("state=%q status=%q: the status arm alone opened the gate; "+
					"an expired audit's payload has been dropped", state, status)
			}
			if !statusArm && readable {
				t.Errorf("state=%q status=%q: the gate opened on a half that is not sealed",
					state, status)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// THE HALF-GATE DETECTOR — what the previous version of this test could not see
// ---------------------------------------------------------------------------
//
// The previous version counted function bodies that mentioned BOTH
// `StateExpired` AND `IsReadableHalfStatus`, and required exactly one such
// body (halfReadRefusal). It could not detect the defect it was written to
// detect. CRITIQUE-03 M1's original bug, character for character, was
//
//	if !IsReadableHalfStatus(run.Properties.Status) { continue }
//
// in readOrder — ONE arm. A body carrying one arm never matched the
// two-literal test, so the count stayed at 1 and the suite stayed green while
// an expired audit handed out nine task cards.
//
// The hazard is not a second COMPLETE gate. Nobody writes one of those; a
// complete gate is correct. The hazard is a HALF-gate: a site that decides
// readability from one arm and never learns about the other. So this test
// looks for the arms THEMSELVES, anywhere outside the one function that is
// allowed to combine them:
//
//	IsReadableHalfStatus(...)        the status arm, called
//	x == / != StateExpired           the expiry arm, hand-rolled
//	x == / != HalfStatusSealed       the status arm, hand-rolled (which is
//	                                 what IsReadableHalfStatus itself is)
//
// Finding any of them outside halfReadRefusal is the signal. Not every hit is
// a bug — the Sealer's lifecycle transitions legitimately ask "is this audit
// expired?" before accepting a seal, and contract.go's validator legitimately
// asks "is this half sealed?" before requiring a sealedAt — but every hit must
// have been LOOKED AT, and the allowlist below is that record. A site is
// keyed by file, function AND arm, so adding the missing arm to a function
// that was cleared for one of them still trips.

// gateArmSite is one place an arm of the read gate is spelled.
type gateArmSite struct {
	file string // base filename
	fn   string // "Func" or "Recv.Method"
	arm  string // the sentinel spelled there
}

func (s gateArmSite) key() string { return s.file + ":" + s.fn + ":" + s.arm }

// gateArmSentinels are the three spellings of half a gate. IsReadableHalfStatus
// is matched as a CALL; the other two as comparisons (`==`, `!=`, or a switch
// case), never as a bare mention, because `string(HalfStatusSealed)` inside an
// error message is prose about the gate and not a use of it.
var gateArmSentinels = map[string]bool{
	"IsReadableHalfStatus": true,
	"StateExpired":         true,
	"HalfStatusSealed":     true,
}

// gateArmAllowlist names the sites where an arm of the read gate is spelled
// outside halfReadRefusal for a reason that is not a readability decision.
//
// Each entry is file:function:arm. Every one of them has been read; the reason
// says what the site is deciding INSTEAD of readability. The test fails if an
// entry stops matching a real site, so the list cannot outlive the code it
// describes.
func gateArmAllowlist() map[string]string {
	return map[string]string{
		// ---- lifecycle: may this audit still accept writes? --------------
		"sealing.go:Sealer.RecordDastOutcome:StateExpired": "refuses an outcome update on a " +
			"terminal audit. It decides whether the SEALER accepts a WRITE, not whether a " +
			"consumer may read; the read direction is ReadHalf, which calls the gate.",
		"sealing.go:Sealer.SealHalf:StateExpired": "refuses a seal on a terminal audit — the " +
			"same write-side question as RecordDastOutcome.",
		"sealing.go:Sealer.Consume:StateExpired": "refuses consumption of an expired audit. " +
			"Consumption is a state transition on the audit, not a read of a half.",
		"sealing.go:Sealer.ExpireIfDue:StateExpired": "the expiry transition itself: already " +
			"expired means there is nothing to do. This is where StateExpired is PRODUCED.",

		// ---- lifecycle: stamping and deriving, not gating ----------------
		"sealing.go:Sealer.SealHalf:HalfStatusSealed": "stamps SealedAt only for a clean seal, " +
			"per contract.go's rule that sealedAt is null unless the status is sealed. It is " +
			"writing the field the gate later reads, not reading it.",
		"sealing.go:DeriveDastStatus:HalfStatusSealed": "derives the audit-level DastStatus " +
			"from the DAST half's outcome. It is a projection of the half's status onto a " +
			"different enum; DastStatus is not a readability answer, and R.6 keeps " +
			"'completed_clean' distinct from 'readable' on purpose.",

		// ---- the status arm's own definition ------------------------------
		"sealing.go:IsReadableHalfStatus:HalfStatusSealed": "IS the comparison, named. This is " +
			"the one site allowed to spell the status arm as a literal, and sealing.go's own " +
			"doc comment on it says in capitals that it is HALF OF THE GATE, NOT THE GATE. " +
			"Every other site asks HalfReadGate, which asks halfReadRefusal, which asks this.",

		// ---- the producer-side validator ---------------------------------
		"contract.go:SARIFLog.validateStateAgainstHalves:HalfStatusSealed": "derives which " +
			"anvil/state the halves imply, so the envelope and the runs cannot disagree. It " +
			"runs on the PRODUCER side, on records no half of which may be readable yet.",
		"contract.go:SARIFLog.validateStateAgainstHalves:StateExpired": "exempts the two " +
			"terminal states from that derivation, because consumed and expired are not " +
			"derivable from the halves. Same validator, same producer side.",
		"contract.go:Run.validate:HalfStatusSealed": "enforces contract.go's sealedAt " +
			"invariant — required when sealed, null otherwise — so that 'never cleanly " +
			"sealed' and 'we forgot to write it' cannot be the same observation. It is a " +
			"well-formedness check on one run, not a decision about a consumer.",
	}
}

// TestReadGateArmsAppearOnlyInsideTheGate reads the package as data and reports
// every site outside halfReadRefusal that spells an arm of the read gate. See
// the section above for why it looks for ARMS and not for whole gates.
//
// It is a source assertion of the same kind as TestPatentRiskIsFlaggedInSource,
// and it exists because the defect this package keeps re-acquiring is not a
// wrong answer but a SECOND, PARTIAL answer. A behavioural test cannot see one
// until some consumer calls it; this can.
func TestReadGateArmsAppearOnlyInsideTheGate(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package source: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("parsed no packages; this test asserts nothing unless it reads the source")
	}

	allow := gateArmAllowlist()
	matched := map[string]bool{}
	gateArms := map[string]bool{}
	sites := 0

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			base := filepath.Base(path)
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				name := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) == 1 {
					if recv := gateBaseTypeName(fn.Recv.List[0].Type); recv != "" {
						name = recv + "." + name
					}
				}
				isTheGate := base == "sealing.go" && name == "halfReadRefusal"

				for _, arm := range gateArmsIn(fn) {
					site := gateArmSite{file: base, fn: name, arm: arm}
					if isTheGate {
						gateArms[arm] = true
						continue
					}
					sites++
					if reason, ok := allow[site.key()]; ok {
						matched[site.key()] = true
						if strings.TrimSpace(reason) == "" {
							t.Errorf("%s is allowlisted with an empty reason", site.key())
						}
						continue
					}
					t.Errorf("%s spells %q outside the read gate.\n"+
						"    ONE ARM IS NOT THE GATE. Readability is\n"+
						"        IsReadableHalfStatus(status) AND the audit has not expired,\n"+
						"    and CRITIQUE-03 M1 was exactly this: readOrder asked the status arm\n"+
						"    alone, so an expired audit handed a coding agent nine task cards.\n"+
						"    Call HalfReadGate (or HalfSeal.Readable), or — if this site is\n"+
						"    deciding something OTHER than readability — add it to\n"+
						"    gateArmAllowlist with the reason.",
						site.key(), arm)
				}
			}
		}
	}

	// The gate must still BE the gate: both arms, in the one body.
	for _, arm := range []string{"IsReadableHalfStatus", "StateExpired"} {
		if !gateArms[arm] {
			t.Errorf("halfReadRefusal no longer spells %q. It is the ONE place both arms are "+
				"combined; if it has lost one, the gate is now half a gate and this test is "+
				"reporting on a function that no longer decides anything.", arm)
		}
	}

	// A stale exemption is how the next real one gets waved through.
	for key := range allow {
		if !matched[key] {
			t.Errorf("gateArmAllowlist names %q, which is not a site in the current source. "+
				"Delete the entry — an allowlist that outlives the code it describes is a "+
				"standing exemption nobody has read.", key)
		}
	}
	t.Logf("read-gate arms: %d sites outside halfReadRefusal, %d allowlisted", sites, len(matched))
}

// gateHalfGateProbeSource is the negative control for the detector above: two
// half-gates and one innocent function, as source text.
//
// readOrderStatusArmOnly is CRITIQUE-03 M1's original defect, character for
// character — the status arm alone, in readOrder, which the previous
// two-literal test could not see because one arm never matched a check that
// required both.
//
// expiryArmOnly is the mirror-image half-gate nobody has written yet.
//
// prosePloneNamesTheArms is the false-positive control: it TALKS about both
// arms in comments and puts one in an error string, and must not fire. The
// detector matching on the AST rather than on text is the whole reason it can
// tell those apart, and sealing.go's header would trip a text search on every
// run.
const gateHalfGateProbeSource = `package record

import "fmt"

func readOrderStatusArmOnly(l *SARIFLog) int {
	n := 0
	for ri := range l.Runs {
		if !IsReadableHalfStatus(l.Runs[ri].Properties.Status) {
			continue
		}
		n += len(l.Runs[ri].Results)
	}
	return n
}

func expiryArmOnly(l *SARIFLog) bool {
	if l.Properties.State == StateExpired {
		return false
	}
	return true
}

// prosePloneNamesTheArms explains that readability is IsReadableHalfStatus AND
// the audit is not StateExpired, and that HalfStatusSealed is the only readable
// status. It decides nothing.
func prosePloneNamesTheArms() error {
	return fmt.Errorf("anvil/status must be %q", string(HalfStatusSealed))
}
`

// TestTheHalfGateDetectorCatchesTheDefectItsPredecessorMissed is the negative
// control for TestReadGateArmsAppearOnlyInsideTheGate.
//
// It runs gateArmsIn — the same function the detector calls — over three
// synthetic functions and asserts the two half-gates are seen and the prose is
// not. Without it, this test would be another guard that has never been
// observed to fail, which is exactly how the previous one shipped: it counted
// bodies carrying BOTH arms, so the one-arm defect it was written for went
// through it twice.
func TestTheHalfGateDetectorCatchesTheDefectItsPredecessorMissed(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "zz_half_gate_probe.go", gateHalfGateProbeSource, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing the synthetic half-gate file: %v", err)
	}

	want := map[string][]string{
		"readOrderStatusArmOnly": {"IsReadableHalfStatus"},
		"expiryArmOnly":          {"StateExpired"},
		"prosePloneNamesTheArms": nil,
	}
	seen := map[string]bool{}
	allow := gateArmAllowlist()

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		exp, ok := want[fn.Name.Name]
		if !ok {
			t.Fatalf("the probe file grew a function %q the control does not check", fn.Name.Name)
		}
		seen[fn.Name.Name] = true
		got := gateArmsIn(fn)
		if strings.Join(got, ",") != strings.Join(exp, ",") {
			if len(exp) == 0 {
				t.Errorf("%s spells no arm of the gate but the detector reported %v; a comment "+
					"or an error message discussing the gate is not a decision about it",
					fn.Name.Name, got)
			} else {
				t.Errorf("%s is a half-gate spelling %v, but the detector reported %v. This is "+
					"the exact shape of CRITIQUE-03 M1, and a detector that cannot see it is "+
					"the detector this one replaced.", fn.Name.Name, exp, got)
			}
		}
		// And a hit must actually be REPORTED, not silently pre-cleared.
		for _, arm := range got {
			key := gateArmSite{file: "readpath.go", fn: fn.Name.Name, arm: arm}.key()
			if _, ok := allow[key]; ok {
				t.Errorf("%s is already in gateArmAllowlist, so the control proves nothing", key)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("the control never examined %q; the probe file did not parse as expected", name)
		}
	}
}

// gateArmsIn returns the arms of the read gate spelled in fn's body, sorted
// and deduplicated.
//
// Matching is on the AST, not on text, so a comment naming an arm is never a
// use of one — sealing.go's header discusses both arms at length, deliberately,
// and prose is not a decision. `IsReadableHalfStatus` counts as a CALL; the two
// enum literals count only in a comparison (`==`, `!=`) or a switch case, so
// `string(HalfStatusSealed)` inside an error message does not fire.
func gateArmsIn(fn *ast.FuncDecl) []string {
	found := map[string]bool{}

	note := func(e ast.Expr) {
		if id, ok := e.(*ast.Ident); ok && gateArmSentinels[id.Name] {
			found[id.Name] = true
		}
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "IsReadableHalfStatus" {
				found[id.Name] = true
			}
		case *ast.BinaryExpr:
			if e.Op == token.EQL || e.Op == token.NEQ {
				note(e.X)
				note(e.Y)
			}
		case *ast.CaseClause:
			for _, expr := range e.List {
				note(expr)
			}
		}
		return true
	})

	out := make([]string, 0, len(found))
	for arm := range found {
		out = append(out, arm)
	}
	sort.Strings(out)
	return out
}
