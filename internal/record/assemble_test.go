package record

import (
	"errors"
	"testing"
	"time"
)

func assembleSeal(t *testing.T, sast HalfStatus) AuditSeal {
	t.Helper()
	s := NewSealer()
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return start.Add(time.Minute) })
	if _, err := s.BeginAudit(AuditConfig{AuditID: "aud-assemble", StartedAt: start}); err != nil {
		t.Fatal(err)
	}
	if err := s.SealHalf("aud-assemble", HalfSast, sast); err != nil {
		t.Fatal(err)
	}
	seal, _ := s.Inspect("aud-assemble")
	return seal
}

// The assembler copies the sealer's answer; every terminal SAST status
// produces a record the contract accepts, in the state DeriveState gives it.
func TestAssembleAcceptsEveryTerminalSastHalf(t *testing.T) {
	for _, st := range []HalfStatus{HalfStatusSealed, HalfStatusFailed, HalfStatusTimedOut, HalfStatusSkipped} {
		seal := assembleSeal(t, st)
		l, err := Assemble(Assembly{
			Seal: seal, Version: 1,
			Target:   Target{Provenance: TargetProvenanceNoTargetDeclared},
			SastTool: ToolComponent{Name: "anvil"},
		})
		if err != nil {
			t.Errorf("%s: %v", st, err)
			continue
		}
		if l.Properties.State != StateBothSealed || l.Runs[0].Properties.Status != st {
			t.Errorf("%s: state=%q run status=%q", st, l.Properties.State, l.Runs[0].Properties.Status)
		}
		if l.Runs[0].Results == nil {
			t.Errorf("%s: results is null on the wire; an empty half is [], not absent", st)
		}
	}
}

// A failed half is terminal: an envelope still saying collecting disagrees
// with the halves, and Validate says so. Before plan node cli it said the
// opposite and refused the sealer's own output.
func TestValidateCountsTerminalNotReadableHalves(t *testing.T) {
	seal := assembleSeal(t, HalfStatusFailed)
	l, err := Assemble(Assembly{Seal: seal, Version: 1,
		Target: Target{Provenance: TargetProvenanceNoTargetDeclared}, SastTool: ToolComponent{Name: "anvil"}})
	if err != nil {
		t.Fatal(err)
	}
	l.Properties.State = StateCollecting
	if err := l.Validate(); err == nil {
		t.Fatal("a record whose SAST half failed validated as collecting")
	}
}

func TestAssembleRefusesADastHalfItCannotBuild(t *testing.T) {
	seal := assembleSeal(t, HalfStatusSealed)
	seal.DastStatus = DastStatusCompletedClean
	if _, err := Assemble(Assembly{Seal: seal, Version: 1}); !errors.Is(err, ErrAssembleDastHalf) {
		t.Fatalf("err = %v, want ErrAssembleDastHalf", err)
	}
}
