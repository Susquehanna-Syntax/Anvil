// Seal provenance — the runtime closure of adversary attack 14, and the tests
// that are the difference between closing it and saying it was closed.
//
// readpath_test.go's KNOWN LIMITS carried attack 14 as an OPEN hole for two
// rounds: call the read gate, check the error, obey it, and hand it a HalfSeal
// you built yourself. The static guard cannot see it, because which value
// flowed into which parameter is a dataflow question. The section proposed the
// fix that landed:
//
//	"an unexported provenance field on HalfSeal that only halfSealOfRun and
//	 the Sealer can set, with HalfReadGate refusing any seal without it"
//
// It was not a hypothetical. CRITIQUE O.4 found the shape occurring NATURALLY
// in internal/scanctl: AuditRecord.HalfSeal assembled a record.HalfSeal from
// caller-held fields, with no refresh path, and handed it to the gate. Nobody
// was attacking anything; it is simply the natural way to write it.
//
// TestGateRefusesAHandBuiltHalfSeal below rebuilds that exact shape and asserts
// the gate now refuses it. Every other test in this file covers one of the
// remaining provenance faults, and each has a POSITIVE CONTROL alongside it: a
// refusal that fires for every input is not a gate, it is an outage.

package record

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ATTACK 14 — the fabricated seal
// ---------------------------------------------------------------------------

// provFabricatedSeal builds a HalfSeal the way a caller OUTSIDE this package
// would: exported fields only, assembled from state the caller happens to
// hold. It is character for character the shape internal/scanctl's
// AuditRecord.HalfSeal produced —
//
//	record.HalfSeal{
//	        Half:       h.Half,
//	        Status:     h.Status,
//	        SealedAt:   copyTime(h.SealedAt),
//	        AuditState: r.State,
//	}
//
// — and it deliberately does NOT set prov, because no package outside
// internal/record can: an unexported field in a composite literal is a compile
// error, and that compile error is the whole mechanism.
func provFabricatedSeal(half Half, status HalfStatus, state State, sealedAt *time.Time) HalfSeal {
	return HalfSeal{
		Half:       half,
		Status:     status,
		SealedAt:   copyTime(sealedAt),
		AuditState: state,
	}
}

// TestGateRefusesAHandBuiltHalfSeal is the deliverable: the gate must refuse a
// seal no producer minted, EVEN WHEN every exported field on it says the half
// is cleanly sealed and the audit is live.
//
// The facts on this seal are not lies. They are exactly the facts a real seal
// would carry for a readable SAST half — the positive control below proves it
// by obtaining a real seal with the same facts and reading through it. The
// refusal is about the seal's ORIGIN, and about nothing else.
func TestGateRefusesAHandBuiltHalfSeal(t *testing.T) {
	sealedAt := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	fabricated := provFabricatedSeal(HalfSast, HalfStatusSealed, StateBothSealed, &sealedAt)

	err := HalfReadGate("audit-fabricated", fabricated)
	if err == nil {
		t.Fatal("ATTACK 14 REPRODUCED: HalfReadGate accepted a HalfSeal that no producer " +
			"minted. A caller can build a seal that says `sealed` and read any half it likes.")
	}
	if fabricated.Readable() {
		t.Error("ATTACK 14 REPRODUCED via the bool spelling: Readable() is true on a fabricated " +
			"seal. HalfReadGate and Readable() must never disagree.")
	}

	// The refusal is a read-gate refusal, so every caller written before
	// provenance existed still branches correctly...
	if !errors.Is(err, ErrHalfNotSealed) {
		t.Errorf("refusal does not match ErrHalfNotSealed: %v", err)
	}
	var rge *ReadGateError
	if !errors.As(err, &rge) {
		t.Fatalf("refusal is %T, want a *ReadGateError", err)
	}
	// ...and it is DISTINCT, so a caller that wants to know it was refused for
	// provenance rather than for an unsealed half can find out.
	if !errors.Is(err, ErrSealNotFromProducer) {
		t.Errorf("refusal does not match ErrSealNotFromProducer: %v", err)
	}
	if errors.Is(err, ErrSealStale) {
		t.Error("a seal nobody minted reported as STALE; absent provenance and stale " +
			"provenance are different faults about different objects")
	}
	var pe *SealProvenanceError
	if !errors.As(err, &pe) {
		t.Fatalf("refusal carries no *SealProvenanceError (Cause = %v)", rge.Cause)
	}
	if pe.Fault != SealProvenanceAbsent {
		t.Errorf("fault = %q, want %q", pe.Fault, SealProvenanceAbsent)
	}
	if pe.AuditID != "audit-fabricated" || pe.Half != HalfSast {
		t.Errorf("the provenance refusal names audit %q half %q; it must name the caller's",
			pe.AuditID, pe.Half)
	}

	// It must NAME THE TWO PRODUCERS. A caller that trips this is by
	// construction a caller that does not know a seal has an origin, so
	// "refused" without "here is where a real one comes from" sends it to
	// guess.
	for _, want := range []string{"halfSealOfRun", "Sealer"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q as a producer:\n%v", want, err)
		}
		if !strings.Contains(pe.Error(), want) {
			t.Errorf("the provenance error does not name %q as a producer:\n%v", want, pe)
		}
	}

	// POSITIVE CONTROL. The same facts, obtained from a producer, are
	// readable. Without this the test above would pass just as well against a
	// gate that had been broken shut.
	l := &SARIFLog{
		Properties: AuditProperties{AuditID: "audit-fabricated", State: StateBothSealed},
		Runs: []Run{{Properties: RunProperties{
			Half: HalfSast, Status: HalfStatusSealed, SealedAt: &sealedAt,
		}}},
	}
	real := halfSealOfRun(l, &l.Runs[0])
	if err := HalfReadGate("audit-fabricated", real); err != nil {
		t.Fatalf("POSITIVE CONTROL FAILED: a producer-minted seal with the same facts was "+
			"refused: %v. The gate is shut, not gated.", err)
	}
	if factsOfSeal(real) != factsOfSeal(fabricated) {
		t.Fatalf("the control seal does not carry the same facts as the fabricated one "+
			"(%v vs %v); the comparison above proves nothing",
			factsOfSeal(real), factsOfSeal(fabricated))
	}
}

// TestGateRefusesTheZeroHalfSeal covers the other end of the same rule: the
// zero value carries no provenance either, and every refusing path in this
// package returns exactly that value.
func TestGateRefusesTheZeroHalfSeal(t *testing.T) {
	if (HalfSeal{}).Readable() {
		t.Error("the zero HalfSeal is readable")
	}
	if err := HalfReadGate("", HalfSeal{}); !errors.Is(err, ErrSealNotFromProducer) {
		t.Errorf("the zero HalfSeal was refused as %v, want ErrSealNotFromProducer", err)
	}
	// And a seal a JSON round-trip produced is a fabricated seal: unexported
	// fields do not survive one. Modelled here as a copy of the exported
	// fields, which is what any decoder produces.
	l := &SARIFLog{
		Properties: AuditProperties{AuditID: "a", State: StateBothSealed},
		Runs:       []Run{{Properties: RunProperties{Half: HalfDast, Status: HalfStatusSealed}}},
	}
	real := halfSealOfRun(l, &l.Runs[0])
	decoded := HalfSeal{Half: real.Half, Status: real.Status, SealedAt: real.SealedAt, AuditState: real.AuditState}
	if decoded.Readable() {
		t.Error("a seal reassembled from exported fields is readable; provenance does not " +
			"survive serialisation and must not be re-acquirable by copying the fields out")
	}
}

// ---------------------------------------------------------------------------
// STALENESS — the fault that actually occurred
// ---------------------------------------------------------------------------

// TestGateRefusesASealHeldAcrossAStateChange is CRITIQUE O.4's defect in this
// package's own shape: a seal a legitimate producer minted, kept while the
// audit moved, and then used to read.
//
// It runs the Sealer arm (an in-flight audit) and asserts the refusal is
// STALE, not absent — the seal is genuine, and reporting it as forged would
// send an operator to look for a caller that does not exist.
func TestGateRefusesASealHeldAcrossAStateChange(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	s := NewSealer()
	s.SetClock(func() time.Time { return now })
	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "held", StartedAt: now, ClaimTimeoutSeconds: 3600, DastEnabled: false,
	}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := s.SealHalf("held", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}

	held, err := s.ReadHalf("held", HalfSast)
	if err != nil {
		t.Fatalf("ReadHalf: %v", err)
	}
	if !held.Readable() {
		t.Fatal("the seal ReadHalf just handed out is not readable; the gate is shut")
	}

	// The audit moves on. The consumer still holds the seal it got ten
	// minutes ago and never refreshed.
	if err := s.Consume("held"); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	if err := HalfReadGate("held", held); err == nil {
		t.Fatal("O.4 REPRODUCED: a seal minted before a state change still opens the gate. " +
			"The gate answered truthfully about a snapshot nobody refreshed.")
	} else {
		var pe *SealProvenanceError
		if !errors.As(err, &pe) {
			t.Fatalf("the refusal is %v, with no provenance detail", err)
		}
		if pe.Fault != SealProvenanceStale {
			t.Errorf("fault = %q, want %q; the seal is genuine and only its age is wrong",
				pe.Fault, SealProvenanceStale)
		}
		if !errors.Is(err, ErrSealStale) || !errors.Is(err, ErrHalfNotSealed) {
			t.Errorf("a stale refusal must match both ErrSealStale and ErrHalfNotSealed: %v", err)
		}
		if pe.LiveVersion <= pe.Version {
			t.Errorf("the refusal reports minted version %d and live version %d; the live "+
				"version must have advanced or the staleness check has no substrate",
				pe.Version, pe.LiveVersion)
		}
	}

	// POSITIVE CONTROL, and S1's re-entrancy: a FRESHLY obtained seal for the
	// same consumed audit is still readable. Staleness must not be a one-way
	// door that consumption closes.
	fresh, err := s.ReadHalf("held", HalfSast)
	if err != nil {
		t.Fatalf("POSITIVE CONTROL FAILED: ReadHalf refused a consumed audit: %v "+
			"(S1 requires a RE-ENTRANT consumer)", err)
	}
	if !fresh.Readable() {
		t.Error("POSITIVE CONTROL FAILED: a freshly minted seal is not readable")
	}
}

// TestReMintingAnUnchangedSealStaysCurrent is the anti-overshoot control for
// the test above. If any Sealer call bumped the version, every seal would be
// stale by the time it was used and the gate would be an outage.
func TestReMintingAnUnchangedSealStaysCurrent(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	s := NewSealer()
	s.SetClock(func() time.Time { return now })
	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "steady", StartedAt: now, ClaimTimeoutSeconds: 3600, DastEnabled: false,
	}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := s.SealHalf("steady", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	first, err := s.ReadHalf("steady", HalfSast)
	if err != nil {
		t.Fatalf("ReadHalf: %v", err)
	}

	// Reads, snapshots, a re-seal with the identical status (documented as a
	// no-op), and a not-yet-due expiry check must all leave the seal current.
	if _, ok := s.Inspect("steady"); !ok {
		t.Fatal("Inspect: audit missing")
	}
	if sast, _ := s.ReadyForConsumption("steady"); !sast {
		t.Fatal("ReadyForConsumption says the sealed SAST half is not ready")
	}
	if err := s.SealHalf("steady", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("idempotent re-seal: %v", err)
	}
	if expired, err := s.ExpireIfDue("steady"); err != nil || expired {
		t.Fatalf("ExpireIfDue before the deadline: (%v, %v)", expired, err)
	}
	if err := HalfReadGate("steady", first); err != nil {
		t.Errorf("a seal went stale although nothing about the audit changed: %v.\n"+
			"    A staleness check that fires on no-ops is an outage, not a gate.", err)
	}
}

// TestGateRefusesASealWhoseRecordMovedOn is the record-side arm of the same
// rule: halfSealOfRun's provenance holds the live (*SARIFLog, *Run), and the
// gate re-reads them.
//
// It runs the mutation in the direction that OPENS the gate — a running half
// that later seals — so the refusal cannot be mistaken for the status arm
// doing the work.
func TestGateRefusesASealWhoseRecordMovedOn(t *testing.T) {
	l := &SARIFLog{
		Properties: AuditProperties{AuditID: "moved", State: StateCollecting},
		Runs:       []Run{{Properties: RunProperties{Half: HalfSast, Status: HalfStatusRunning}}},
	}
	held := halfSealOfRun(l, &l.Runs[0])
	if held.Readable() {
		t.Fatal("a running half is readable; the status arm is gone")
	}

	// The record seals. The held seal still describes the running half.
	sealedAt := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	l.Properties.State = StateBothSealed
	l.Runs[0].Properties.Status = HalfStatusSealed
	l.Runs[0].Properties.SealedAt = &sealedAt

	err := HalfReadGate("moved", held)
	if err == nil {
		t.Fatal("the gate accepted a seal that no longer matches the record it came from")
	}
	var pe *SealProvenanceError
	if !errors.As(err, &pe) || pe.Fault != SealProvenanceStale {
		t.Fatalf("refusal = %v, want a stale-provenance refusal", err)
	}
	if !strings.Contains(pe.Minted, string(HalfStatusRunning)) ||
		!strings.Contains(pe.Live, string(HalfStatusSealed)) {
		t.Errorf("the refusal reports minted=%q live=%q; it must say what changed",
			pe.Minted, pe.Live)
	}

	// POSITIVE CONTROL: re-projecting the SAME record now opens the gate.
	if err := HalfReadGate("moved", halfSealOfRun(l, &l.Runs[0])); err != nil {
		t.Fatalf("POSITIVE CONTROL FAILED: a freshly projected seal over a sealed half was "+
			"refused: %v", err)
	}
}

// TestGateRefusesAnEditedSeal closes the near-miss of attack 14: obtain a
// genuine seal, then assign to its exported fields. Copying a HalfSeal is
// legal and happens everywhere; EDITING one turns a real seal into a
// fabricated one that still carries a producer's mark.
func TestGateRefusesAnEditedSeal(t *testing.T) {
	l := &SARIFLog{
		Properties: AuditProperties{AuditID: "edited", State: StateCollecting},
		Runs:       []Run{{Properties: RunProperties{Half: HalfDast, Status: HalfStatusRunning}}},
	}
	seal := halfSealOfRun(l, &l.Runs[0])

	edited := seal // a copy carries the provenance, as any pass-by-value does
	edited.Status = HalfStatusSealed
	edited.AuditState = StateBothSealed

	err := HalfReadGate("edited", edited)
	if err == nil {
		t.Fatal("ATTACK 14 VARIANT REPRODUCED: a real seal was edited to say `sealed` and " +
			"the gate honoured it. Provenance that survives editing is a rubber stamp.")
	}
	var pe *SealProvenanceError
	if !errors.As(err, &pe) || pe.Fault != SealProvenanceTampered {
		t.Fatalf("refusal = %v, want a tampered-provenance refusal", err)
	}

	// The half field is part of the facts too, which is what makes "obey the
	// gate for SAST, relabel the seal, read DAST" not work. It is NOT a fix
	// for attack 15 — see readpath_test.go's KNOWN LIMITS — because attack 15
	// never needs to relabel anything.
	relabelled := seal
	relabelled.Half = HalfSast
	if relabelled.Readable() {
		t.Error("a seal relabelled onto the other half is readable")
	}

	// POSITIVE CONTROL: the untouched original still answers for itself.
	if seal.Readable() {
		t.Error("the original seal is readable; it describes a RUNNING half")
	}
	if err := HalfReadGate("edited", seal); !errors.Is(err, ErrHalfNotSealed) ||
		errors.Is(err, ErrSealStale) || errors.Is(err, ErrSealNotFromProducer) {
		t.Errorf("the untouched seal was refused as %v; it must be refused by the STATUS arm, "+
			"not by provenance", err)
	}
}

// TestGateRefusesASealFromAForgottenAudit: once Sealer.Forget drops an audit,
// seals minted from it can no longer be checked against anything, and an
// unverifiable seal is refused like any other.
func TestGateRefusesASealFromAForgottenAudit(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	s := NewSealer()
	s.SetClock(func() time.Time { return now })
	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "gone", StartedAt: now, ClaimTimeoutSeconds: 3600, DastEnabled: false,
	}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := s.SealHalf("gone", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	seal, err := s.ReadHalf("gone", HalfSast)
	if err != nil {
		t.Fatalf("ReadHalf: %v", err)
	}
	if !seal.Readable() {
		t.Fatal("the seal ReadHalf handed out is not readable")
	}

	s.Forget("gone")

	if seal.Readable() {
		t.Error("a seal minted from a forgotten audit is still readable; there is nothing " +
			"left to check it against and it must not be believed")
	}
	var pe *SealProvenanceError
	if err := HalfReadGate("gone", seal); !errors.As(err, &pe) {
		t.Fatalf("refusal = %v, want a provenance refusal", err)
	} else if pe.Fault != SealProvenanceOriginGone {
		t.Errorf("fault = %q, want %q", pe.Fault, SealProvenanceOriginGone)
	}
}

// ---------------------------------------------------------------------------
// THE PRODUCER CENSUS — there are two, and a third must not appear quietly
// ---------------------------------------------------------------------------

// TestOnlyTwoProducersStampProvenance reads the package as data and fails if
// any function other than halfSealOfRun and audit.halfSeal writes the
// provenance field.
//
// The compiler stops OTHER PACKAGES from forging provenance; nothing stops
// this one. A third producer added here — an exported constructor, a
// "convenience" helper for a caller that finds the gate inconvenient — would
// reopen attack 14 with the package's own help, and would look entirely
// reasonable in review. This test is what makes that visible.
func TestOnlyTwoProducersStampProvenance(t *testing.T) {
	const provField = "prov"
	legitimate := map[string]bool{
		"halfSealOfRun":  true,
		"audit.halfSeal": true,
	}

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

	found := map[string]bool{}
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
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					var writes bool
					switch v := n.(type) {
					case *ast.KeyValueExpr:
						// HalfSeal{..., prov: ...}
						if id, ok := v.Key.(*ast.Ident); ok && id.Name == provField {
							writes = true
						}
					case *ast.AssignStmt:
						// seal.prov = ...
						for _, lhs := range v.Lhs {
							if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == provField {
								writes = true
							}
						}
					}
					if !writes {
						return true
					}
					found[name] = true
					if !legitimate[name] {
						t.Errorf("%s (%s) stamps seal provenance, and it is not one of the two "+
							"legitimate producers.\n"+
							"    THE UNEXPORTED FIELD IS THE WHOLE MECHANISM: the compiler stops\n"+
							"    other packages from forging it, and this list is what stops this\n"+
							"    one. A third producer is adversary attack 14 reopened from inside.\n"+
							"    If this really is a producer, say why here and add it to the list;\n"+
							"    if it is a convenience for a caller that found the gate awkward,\n"+
							"    the caller is the thing to fix.", name, base)
					}
					return true
				})
			}
		}
	}

	for want := range legitimate {
		if !found[want] {
			t.Errorf("%s no longer stamps provenance. It is one of the two producers the gate's "+
				"refusal message names; if it has stopped minting, either the mechanism is gone "+
				"or the message is now a lie.", want)
		}
	}
}

// ===========================================================================
// THE MUTATION FUNNEL — publish-on-every-mutation, and the proof it matters
// ===========================================================================
//
// Everything above tests the gate's REACTION to a stale seal. This section
// tests the thing that makes a seal stale in the first place: the audit
// publishes an atomic facts snapshot on every mutation, and a held seal is
// compared against it.
//
// The re-verification of R.6 found two mutations that could skip that publish —
// Sealer.SealHalf's DAST branch and Sealer.SealDastIfDeadlineDue, both of which
// assigned the half's fields and then returned a derivation error from between
// the assignment and the publish. It classified them LATENT, NOT REACHABLE
// TODAY, and it was right about reachability: DeriveDastStatus cannot fail on
// inputs the Sealer's own validators admit.
//
// It matters anyway, and TestASealHeldAcrossAnUnpublishedMutationReadsAsCurrent
// below is the demonstration rather than the assertion. An unpublished mutation
// does not weaken the staleness check; it INVERTS it. The gate reads its two
// arms off the seal's own fields, and the staleness check is the entire reason
// those fields may be believed. Take the publish away and a seal minted before
// an EXPIRY still says `sealed` / `both_sealed`, still matches the published
// facts, and the gate hands a consumer the results of an audit whose payload the
// reaper has already dropped. That is CRITIQUE-03 M1's harm arriving through the
// mechanism built to prevent it.

// provAudit reaches into the Sealer for the live *audit. Every test in this
// section needs it: the defect is a disagreement between an audit's FIELDS and
// its PUBLISHED facts, and nothing exported can show both.
func provAudit(t *testing.T, s *Sealer, auditID string) *audit {
	t.Helper()
	a, ok := s.audits[auditID]
	if !ok {
		t.Fatalf("audit %q is not registered with this Sealer", auditID)
	}
	return a
}

// provFactsDisagreement returns a description of how an audit's published facts
// differ from its fields, or "" when they agree.
//
// AGREEMENT IS THE INVARIANT. Everything the staleness gate does rests on it:
// `live` is the substrate a held seal is checked against, so the moment it lags
// the fields, a seal describing the OLD record compares equal to the CURRENT
// one.
func provFactsDisagreement(a *audit) string {
	live := a.live.Load()
	if live == nil {
		return "nothing has ever been published for this audit"
	}
	if want := a.factsFor(HalfSast); live.sast != want {
		return fmt.Sprintf("SAST half: published %v, but the fields say %v", live.sast, want)
	}
	if want := a.factsFor(HalfDast); live.dast != want {
		return fmt.Sprintf("DAST half: published %v, but the fields say %v", live.dast, want)
	}
	return ""
}

// provCorruptDastProvenance makes DeriveDastStatus FAIL for this audit.
//
// It is the only way to reach the two paths at all, and it is why they were
// classified latent: RecordDastOutcome validates the provenance token and
// BeginAudit supplies a legal default, so no caller outside this package can
// put an illegal one in place. This test file is inside the package and can, so
// the paths the re-verifier could only read are paths this file can EXECUTE.
func provCorruptDastProvenance(t *testing.T, s *Sealer, auditID string) *audit {
	t.Helper()
	a := provAudit(t, s, auditID)
	a.dastOutcome.TierInstalled = true
	a.dastOutcome.Provenance = TargetProvenance("gremlin-not-a-provenance")
	if _, err := DeriveDastStatus(HalfStatusSealed, a.dastOutcome); err == nil {
		t.Fatal("the probe did not actually break the derivation, so every assertion below " +
			"would pass against the unfixed code as well; it proves nothing")
	}
	return a
}

// TestASealHeldAcrossAnUnpublishedMutationReadsAsCurrent is the proof the
// re-verification asked for: construct the sequence that would have left a
// stale seal reading CURRENT, and assert the gate now refuses it.
//
// Two identical audits, one transition, two ways of making it:
//
//	A  "unpublished" — the audit's state field is assigned directly, the way an
//	   early return between an assignment and a publish leaves it. The gate is
//	   FOOLED: a seal minted before the transition still matches the published
//	   facts, so the staleness arm passes, and the gate then reads its two
//	   readability arms off that seal's own stale fields and OPENS on an EXPIRED
//	   audit.
//	B  "funnelled" — the same transition through Sealer.ExpireIfDue, which goes
//	   through audit.setLifecycleState, which publishes. The identical held seal
//	   is refused as SealProvenanceStale.
//
// A is not an assertion that the product is broken. It is the negative control
// that gives B its meaning: without it, B would pass just as well against a gate
// that refused everything.
func TestASealHeldAcrossAnUnpublishedMutationReadsAsCurrent(t *testing.T) {
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)

	// setup returns a Sealer whose audit has a cleanly sealed, READABLE SAST
	// half, plus a seal a consumer obtained and held.
	setup := func(id string) (*Sealer, *time.Time, HalfSeal) {
		now := start
		s := NewSealer()
		s.SetClock(func() time.Time { return now })
		if _, err := s.BeginAudit(AuditConfig{
			AuditID: id, StartedAt: start, ClaimTimeoutSeconds: 3600, DastEnabled: false,
		}); err != nil {
			t.Fatalf("BeginAudit: %v", err)
		}
		if err := s.SealHalf(id, HalfSast, HalfStatusSealed); err != nil {
			t.Fatalf("SealHalf: %v", err)
		}
		held, err := s.ReadHalf(id, HalfSast)
		if err != nil {
			t.Fatalf("ReadHalf: %v", err)
		}
		if !held.Readable() {
			t.Fatal("the seal ReadHalf handed out is not readable; the scenario never starts")
		}
		if held.AuditState != StateBothSealed || held.Status != HalfStatusSealed {
			t.Fatalf("the held seal reads %s/%s, want %s/%s",
				held.Status, held.AuditState, HalfStatusSealed, StateBothSealed)
		}
		return s, &now, held
	}

	// ---- A: the transition WITHOUT a publish -----------------------------
	sA, _, heldA := setup("unpublished")
	aA := provAudit(t, sA, "unpublished")
	aA.state = StateExpired // exactly what an early return before publish leaves

	if d := provFactsDisagreement(aA); d == "" {
		t.Fatal("the probe did not desynchronise the published facts from the fields, so the " +
			"control below demonstrates nothing")
	}
	if err := HalfReadGate("unpublished", heldA); err != nil {
		t.Fatalf("the unpublished-mutation control did not reproduce the inversion: %v.\n"+
			"    It is supposed to show the gate being FOOLED. If it no longer can, the\n"+
			"    mechanism has changed and the assertion below is measuring something else.", err)
	}
	if !heldA.Readable() {
		t.Fatal("the unpublished-mutation control did not reproduce the inversion via Readable()")
	}
	// Stated for the record, because this is the whole point: at this instant
	// the live audit is EXPIRED — the reaper has dropped its payload — and the
	// one gate that stands between a consumer and those results said yes.

	// ---- B: the same transition THROUGH the funnel ------------------------
	sB, nowB, heldB := setup("funnelled")
	if factsOfSeal(heldA) != factsOfSeal(heldB) {
		t.Fatalf("the two held seals do not carry the same facts (%v vs %v); A and B are not "+
			"the same scenario and comparing their outcomes proves nothing",
			factsOfSeal(heldA), factsOfSeal(heldB))
	}
	*nowB = start.Add(2 * time.Hour) // past deadline_at
	expired, err := sB.ExpireIfDue("funnelled")
	if err != nil || !expired {
		t.Fatalf("ExpireIfDue = (%v, %v); the scenario requires the audit to expire", expired, err)
	}
	if d := provFactsDisagreement(provAudit(t, sB, "funnelled")); d != "" {
		t.Fatalf("ExpireIfDue left the published facts behind the fields: %s.\n"+
			"    Every mutation must publish; that is the invariant the staleness gate rests on.", d)
	}

	err = HalfReadGate("funnelled", heldB)
	if err == nil {
		t.Fatal("RESIDUAL 2 REPRODUCED: a seal minted before an EXPIRY still opens the gate. " +
			"The staleness check is not degraded by an unpublished mutation, it is inverted: " +
			"the consumer reads a half whose payload the reaper has dropped.")
	}
	if heldB.Readable() {
		t.Error("RESIDUAL 2 REPRODUCED via the bool spelling: Readable() is true on a seal held " +
			"across an expiry")
	}
	var pe *SealProvenanceError
	if !errors.As(err, &pe) {
		t.Fatalf("the refusal is %v, with no provenance detail", err)
	}
	if pe.Fault != SealProvenanceStale {
		t.Errorf("fault = %q, want %q; the seal is genuine and only its age is wrong",
			pe.Fault, SealProvenanceStale)
	}
	if pe.LiveVersion <= pe.Version {
		t.Errorf("minted version %d, live version %d: the publish did not advance the revision, "+
			"so the staleness check has no substrate", pe.Version, pe.LiveVersion)
	}

	// POSITIVE CONTROL. Refusing everything is not a gate. A seal minted NOW,
	// from the same expired audit, is still refused — but by the EXPIRY arm,
	// which is the arm that should be deciding once the seal itself is current.
	fresh, freshErr := sB.ReadHalf("funnelled", HalfSast)
	if !errors.Is(freshErr, ErrHalfNotSealed) {
		t.Fatalf("ReadHalf on an expired audit = (%v, %v), want a read-gate refusal", fresh, freshErr)
	}
	if errors.Is(freshErr, ErrSealStale) {
		t.Error("a freshly minted seal was refused as STALE; the two arms have collapsed into " +
			"one and the staleness refusal above no longer distinguishes anything")
	}
}

// TestTheTwoLatentUnpublishedMutationPathsAreClosed executes the two paths the
// re-verification named, by making DeriveDastStatus fail the only way anything
// can make it fail.
//
// Both used to assign the DAST half's fields and THEN return the derivation's
// error, leaving the fields moved and the published facts behind. Both now
// derive first, so a failure leaves the audit completely untouched — which is a
// stronger property than "it publishes anyway": there is no half-moved state to
// publish.
func TestTheTwoLatentUnpublishedMutationPathsAreClosed(t *testing.T) {
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		// fire drives the path that must fail, and reports the error it gave.
		fire func(t *testing.T, s *Sealer, now *time.Time, id string) error
	}{
		{
			name: "SealHalf DAST branch",
			fire: func(t *testing.T, s *Sealer, _ *time.Time, id string) error {
				return s.SealHalf(id, HalfDast, HalfStatusSealed)
			},
		},
		{
			name: "SealDastIfDeadlineDue",
			fire: func(t *testing.T, s *Sealer, now *time.Time, id string) error {
				*now = start.Add(9 * time.Hour) // well past the DAST deadline
				fired, err := s.SealDastIfDeadlineDue(id)
				if fired {
					t.Error("the forced timeout reported success on a failed derivation")
				}
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := start
			s := NewSealer()
			s.SetClock(func() time.Time { return now })
			hour := 3600
			if _, err := s.BeginAudit(AuditConfig{
				AuditID: "latent", StartedAt: start, ClaimTimeoutSeconds: 24 * 3600,
				DastEnabled: true, DastDeadlineSeconds: &hour,
			}); err != nil {
				t.Fatalf("BeginAudit: %v", err)
			}
			// A consumer holds a seal describing the DAST half as it is now.
			held, ok := s.Inspect("latent")
			if !ok {
				t.Fatal("Inspect: audit missing")
			}
			if err := HalfReadGate("latent", held.Dast); !errors.Is(err, ErrHalfNotSealed) ||
				errors.Is(err, ErrSealStale) {
				t.Fatalf("the freshly held DAST seal is already stale or unrefused (%v); the "+
					"scenario never starts", err)
			}

			a := provCorruptDastProvenance(t, s, "latent")
			before := a.factsFor(HalfDast)

			err := tc.fire(t, s, &now, "latent")
			if err == nil {
				t.Fatal("the derivation did not fail, so this path was never entered")
			}

			// 1. ATOMICITY: the mutation did not happen at all.
			if got := a.factsFor(HalfDast); got != before {
				t.Errorf("a FAILED transition moved the DAST half from %v to %v.\n"+
					"    The fallible derivation must run BEFORE the fields are assigned, so a\n"+
					"    failure leaves nothing half-moved.", before, got)
			}

			// 2. THE INVARIANT: fields and published facts still agree, so no
			// held seal can be reading a record that has moved past it.
			if d := provFactsDisagreement(a); d != "" {
				t.Errorf("RESIDUAL 2 REPRODUCED on %s: %s.\n"+
					"    A mutation that does not publish leaves every seal minted before it\n"+
					"    reading as CURRENT. That is the staleness gate inverted, not degraded.",
					tc.name, d)
			}

			// 3. The consequence, in the gate's own terms: the held seal is
			// still current, because nothing changed, and is still refused by
			// the arm that was refusing it before.
			if err := HalfReadGate("latent", held.Dast); errors.Is(err, ErrSealStale) {
				t.Errorf("the held seal went STALE although the transition failed and nothing "+
					"moved: %v", err)
			}
		})
	}
}

// TestEveryMutatingEntryPointPublishes drives every entry point that can move
// an audit and asserts the fields and the published facts agree after each one.
//
// It is the behavioural companion to the AST guard below: the guard checks that
// mutations are written inside the funnel, this checks that the funnel actually
// keeps the substrate current for the sequences a caller really performs.
func TestEveryMutatingEntryPointPublishes(t *testing.T) {
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	now := start
	s := NewSealer()
	s.SetClock(func() time.Time { return now })

	hour := 3600
	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "walk", StartedAt: start, ClaimTimeoutSeconds: 24 * 3600,
		DastEnabled: true, DastDeadlineSeconds: &hour,
	}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	a := provAudit(t, s, "walk")

	check := func(step string) {
		t.Helper()
		if d := provFactsDisagreement(a); d != "" {
			t.Fatalf("after %s: %s", step, d)
		}
	}
	check("BeginAudit")

	if err := s.RecordDastOutcome("walk", DastOutcome{Provenance: TargetProvenanceBootedClean}); err != nil {
		t.Fatalf("RecordDastOutcome: %v", err)
	}
	check("RecordDastOutcome")

	if err := s.SealHalf("walk", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf(sast): %v", err)
	}
	check("SealHalf(sast, sealed)")

	now = start.Add(2 * time.Hour)
	if fired, err := s.SealDastIfDeadlineDue("walk"); err != nil || !fired {
		t.Fatalf("SealDastIfDeadlineDue = (%v, %v), want it to fire", fired, err)
	}
	check("SealDastIfDeadlineDue")

	if err := s.Consume("walk"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	check("Consume")

	// A separate audit for the expiry arm, since consumption blocks it.
	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "walk-expiry", StartedAt: start, ClaimTimeoutSeconds: 3600, DastEnabled: false,
	}); err != nil {
		t.Fatalf("BeginAudit(walk-expiry): %v", err)
	}
	b := provAudit(t, s, "walk-expiry")
	if d := provFactsDisagreement(b); d != "" {
		t.Fatalf("after BeginAudit(dast disabled): %s", d)
	}
	now = start.Add(48 * time.Hour)
	if expired, err := s.ExpireIfDue("walk-expiry"); err != nil || !expired {
		t.Fatalf("ExpireIfDue = (%v, %v), want it to fire", expired, err)
	}
	if d := provFactsDisagreement(b); d != "" {
		t.Fatalf("after ExpireIfDue: %s", d)
	}
}

// ---------------------------------------------------------------------------
// THE FUNNEL CENSUS — the class, not the two instances
// ---------------------------------------------------------------------------

// provFunnelMutators are the only functions permitted to assign a fact-bearing
// field of an *audit after construction. Each must end in a publish.
func provFunnelMutators() map[string]string {
	return map[string]string{
		"audit.setHalf": "assigns one half's status and sealedAt and re-derives anvil/state. " +
			"The fallible DastStatus derivation is a PARAMETER, so nothing inside can fail " +
			"between the assignment and the publish.",
		"audit.setLifecycleState": "assigns the two states DeriveState never produces, " +
			"StateConsumed and StateExpired, which are explicit transitions.",
		"audit.setDastOutcome": "stores the target-lifecycle facts anvil/dastStatus is derived " +
			"from, plus the already-derived value.",
	}
}

// provNonFactAuditFields are the fields of `audit` that are NOT fact-bearing,
// each with the reason it is safe to assign outside the funnel.
//
// The fact set is computed as "every field of `audit` MINUS this list", not as a
// hand-written list of fact-bearing names, and that direction is the point: a
// field added to `audit` tomorrow is fact-bearing BY DEFAULT and must either go
// through the funnel or be exempted here, in writing, by someone who thought
// about it. A hand-written positive list would silently omit it.
func provNonFactAuditFields() map[string]string {
	return map[string]string{
		"id":                  "the audit id, written once at construction and never again",
		"startedAt":           "scan_run.started_at, fixed at BeginAudit; R.6 forbids recomputing it",
		"deadlineAt":          "clock 2, computed once at BeginAudit and never recomputed",
		"claimTimeoutSeconds": "an AuditConfig input, fixed at BeginAudit",
		"dastDeadlineSeconds": "clock 3's input, fixed at BeginAudit",
		"dastEnabled":         "plan/00-SPINE.md S9-AMENDED's tier bit, fixed at BeginAudit",
		"live": "IS the published snapshot. publish() stores it and Forget() clears it, " +
			"both through atomic.Pointer methods rather than assignment; it is the thing the " +
			"funnel maintains, not a fact the funnel must maintain it for.",
	}
}

// provFunnelFinding is one violation the scanner reports.
type provFunnelFinding struct {
	kind string // "assign" (a fact-bearing write outside the funnel) | "publish"
	fn   string // "Func" or "Recv.Method"
	what string
}

func (f provFunnelFinding) String() string { return f.kind + ":" + f.fn + ":" + f.what }

// provScanFunnel walks parsed source and reports every fact-bearing assignment
// outside the funnel, plus every funnel mutator that does not end in a publish.
//
// It is a separate function from the test so the negative control can run the
// SAME detector over source that deliberately contains the defects. A guard that
// has never been observed to fail has not been tested, and this package has
// paid for that lesson three times.
func provScanFunnel(files map[string]*ast.File, factFields, mutators map[string]bool) (findings []provFunnelFinding, seenMutators map[string]bool) {
	seenMutators = map[string]bool{}

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths) // deterministic order; ranging a map to report is the old determinism bug

	for _, path := range paths {
		for _, decl := range files[path].Decls {
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

			if mutators[name] {
				seenMutators[name] = true
				findings = append(findings, provCheckMutatorPublishes(name, fn.Body)...)
				continue // assignments here are the point of the function
			}

			var hits []string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				var targets []ast.Expr
				switch v := n.(type) {
				case *ast.AssignStmt:
					targets = v.Lhs
				case *ast.IncDecStmt:
					targets = []ast.Expr{v.X}
				}
				for _, target := range targets {
					sel, ok := target.(*ast.SelectorExpr)
					if ok && factFields[sel.Sel.Name] && !slices.Contains(hits, sel.Sel.Name) {
						hits = append(hits, sel.Sel.Name)
					}
				}
				return true
			})
			slices.Sort(hits)
			for _, field := range hits {
				findings = append(findings, provFunnelFinding{kind: "assign", fn: name, what: field})
			}
		}
	}
	return findings, seenMutators
}

// provCheckMutatorPublishes enforces the shape that makes "publishes on every
// return path" checkable at all: the body's LAST statement is a call to
// publish, and the body contains no return.
//
// A straight-line body with the publish last has exactly one return path, so
// the two conditions together ARE "every return path publishes". That works
// only because the three mutators are three, four and three statements long. If
// one ever grows a branch this test will demand it be split rather than start
// reasoning about control flow — which is the right trade: a checkable shape
// beats a clever checker.
func provCheckMutatorPublishes(name string, body *ast.BlockStmt) []provFunnelFinding {
	var out []provFunnelFinding

	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			out = append(out, provFunnelFinding{kind: "publish", fn: name, what: "returns early"})
		}
		return true
	})

	last := ""
	if n := len(body.List); n > 0 {
		if stmt, ok := body.List[n-1].(*ast.ExprStmt); ok {
			if call, ok := stmt.X.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					last = sel.Sel.Name
				}
			}
		}
	}
	if last != "publish" {
		out = append(out, provFunnelFinding{kind: "publish", fn: name, what: "does not end in publish"})
	}
	return out
}

// provAuditFactFields computes the fact-bearing field set from the `audit`
// struct declaration itself, minus provNonFactAuditFields.
func provAuditFactFields(t *testing.T, files map[string]*ast.File) map[string]bool {
	t.Helper()

	var fields []string
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "audit" {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, f := range st.Fields.List {
				for _, id := range f.Names {
					fields = append(fields, id.Name)
				}
			}
			return false
		})
	}
	if len(fields) == 0 {
		t.Fatal("found no fields on the `audit` struct; this test asserts nothing unless it " +
			"reads the type it is about")
	}

	exempt := provNonFactAuditFields()
	out := map[string]bool{}
	for _, f := range fields {
		if reason, ok := exempt[f]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("audit.%s is exempted from the fact-bearing set with an empty reason", f)
			}
			continue
		}
		out[f] = true
	}
	for f := range exempt {
		if !slices.Contains(fields, f) {
			t.Errorf("provNonFactAuditFields exempts audit.%s, which is not a field of `audit` any "+
				"more. Delete the entry — an exemption that outlives its field is a standing "+
				"waiver nobody has read.", f)
		}
	}
	if len(out) == 0 {
		t.Fatal("every field of `audit` is exempted; the fact-bearing set is empty and this test " +
			"cannot fail")
	}
	return out
}

// TestEveryFactBearingAssignmentGoesThroughTheMutationFunnel is the CLASS fix
// for residual 2, in place of fixing two instances.
//
// It reads this package as data and fails when a fact-bearing field of an
// *audit is assigned anywhere outside the three funnel mutators, or when one of
// those mutators stops publishing on every return path.
//
// WHY A CENSUS AND NOT TWO FIXES. The re-verifier named one path and said there
// were two; there were. That is the fourth time this package has been handed a
// list of instances of a shape (four read-gate bypasses, three guard defeats),
// and the pattern — not any one instance — has been the defect every time. The
// two paths are fixed in sealing.go; this is what stops the third.
//
// ---------------------------------------------------------------------------
// KNOWN LIMITS — read these before trusting a green run
// ---------------------------------------------------------------------------
//
// This is a GUARD, not a proof. It is a syntactic walk, and the following are
// OPEN, deliberately and with the reasoning written down rather than implied.
//
//  1. IT MATCHES ON FIELD NAME, NOT ON TYPE. An assignment to `x.state` is
//     flagged whichever struct x is — a false POSITIVE, which is the safe
//     direction and has an obvious fix (rename, or exempt with a reason). What
//     it cannot do is know that some future `x.state` is a different field.
//     Closing this needs go/types, which this package's guards have so far
//     avoided for the sake of a test that runs anywhere.
//
//  2. IT CANNOT SEE A WRITE THROUGH A POINTER ALIAS. `p := &a.dastStatus;
//     *p = HalfStatusSealed` compiles, mutates, and is invisible here: the
//     assignment's left-hand side is a StarExpr, not a SelectorExpr. So is a
//     write through reflect, and so is `*a = audit{...}`, which replaces every
//     field at once. None of these is a shape anyone writes by accident, which
//     is exactly the limit: this catches the ACCIDENT, and the accident is what
//     happened twice.
//
//  3. CONSTRUCTION IS EXEMPT. `&audit{...}` composite literals are not
//     inspected, because BeginAudit fills one while it is still unreachable
//     from the Sealer and no seal can exist to be made stale. If an `audit`
//     value is ever REUSED — reset and handed back out — that exemption becomes
//     wrong and nothing here will notice.
//
//  4. "PUBLISHES ON EVERY RETURN PATH" IS CHECKED AS A SHAPE, not as control
//     flow: last statement is a publish, and there is no return anywhere. It is
//     equivalent for straight-line bodies and for nothing else. A mutator that
//     grows an `if` fails this test even when it is correct — on purpose, so the
//     answer is to split the function rather than to teach the checker.
//
//  5. IT DOES NOT CHECK THAT publish() PUBLISHES THE RIGHT THING. That is
//     behaviour, and TestEveryMutatingEntryPointPublishes above is what covers
//     it, by comparing the published facts against the fields after every
//     mutating entry point.
//
//  6. IT WALKS THIS PACKAGE ONLY. That happens to be complete for this field
//     set — every field of `audit` is unexported, so no other package can
//     assign one at all — and it is the one place this guard is stronger than a
//     convention. It would stop being complete the moment a fact-bearing field
//     were exported, which is a change nobody should make and nothing here
//     forbids.
func TestEveryFactBearingAssignmentGoesThroughTheMutationFunnel(t *testing.T) {
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

	files := map[string]*ast.File{}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			files[filepath.Base(path)] = file
		}
	}

	factFields := provAuditFactFields(t, files)
	mutatorReasons := provFunnelMutators()
	mutators := map[string]bool{}
	for name := range mutatorReasons {
		mutators[name] = true
	}

	findings, seen := provScanFunnel(files, factFields, mutators)
	for _, f := range findings {
		switch f.kind {
		case "assign":
			t.Errorf("%s assigns the fact-bearing field audit.%s outside the mutation funnel.\n"+
				"    EVERY MUTATION MUST PUBLISH. The staleness arm of the read gate compares a\n"+
				"    held seal against the audit's published facts; a mutation that does not\n"+
				"    publish leaves every seal minted before it reading as CURRENT. That is not\n"+
				"    a degraded check, it is the check inverted, and it fails OPEN.\n"+
				"    Route the write through one of %v, which publish by construction.",
				f.fn, f.what, slices.Sorted(maps.Keys(mutatorReasons)))
		case "publish":
			t.Errorf("the funnel mutator %s %s.\n"+
				"    Its whole reason to exist is that a fact-bearing write and its publish are\n"+
				"    ONE operation. A mutator with a return before its publish is the defect this\n"+
				"    funnel was built to make unwritable, relocated into the funnel itself.",
				f.fn, f.what)
		}
	}

	for name, reason := range mutatorReasons {
		if !seen[name] {
			t.Errorf("provFunnelMutators names %q, which is not a function in the current "+
				"source (reason on file: %s). Delete the entry — a funnel that names mutators "+
				"which no longer exist has stopped describing the code.", name, reason)
		}
	}
	t.Logf("mutation funnel: %d fact-bearing fields, %d mutators, %d findings",
		len(factFields), len(seen), len(findings))
}

// provFunnelProbeSource is the negative control: residual 2's two defects and
// one innocent function, as source text.
//
// sealHalfUnpublishedDast is Sealer.SealHalf's DAST branch as it stood, line for
// line — assign, derive, return the error from between the assignment and the
// publish.
//
// setHalf and setLifecycleState are the two ways a funnel mutator can stop
// being one: losing its publish, and growing a return in front of it.
//
// innocentReader is the false-positive control. It READS every fact-bearing
// field, compares them, and assigns a local variable — and must not fire, or
// the detector would flag half of sealing.go.
const provFunnelProbeSource = `package record

import "time"

func (s *Sealer) sealHalfUnpublishedDast(a *audit, status HalfStatus, sealedAt *time.Time) error {
	a.dastStatus = status
	a.dastSealedAt = sealedAt
	derived, derr := DeriveDastStatus(a.dastStatus, a.dastOutcome)
	if derr != nil {
		return derr
	}
	a.dastDerived = derived
	a.state = DeriveState(a.sastStatus, a.dastStatus)
	a.publish()
	return nil
}

func (a *audit) setHalf(half Half, status HalfStatus, sealedAt *time.Time, dastDerived DastStatus) {
	a.sastStatus = status
	a.sastSealedAt = sealedAt
	a.dastDerived = dastDerived
	a.state = DeriveState(a.sastStatus, a.dastStatus)
}

func (a *audit) setLifecycleState(state State) {
	a.state = state
	if state == StateConsumed {
		return
	}
	a.publish()
}

func (a *audit) setDastOutcome(o DastOutcome, dastDerived DastStatus) {
	a.dastOutcome = o
	a.dastDerived = dastDerived
	a.publish()
}

func innocentReader(a *audit) State {
	seen := a.state
	if a.dastStatus == a.sastStatus && a.dastSealedAt == a.sastSealedAt {
		seen = a.state
	}
	return seen
}
`

// TestTheFunnelDetectorCatchesTheDefectItWasWrittenFor runs the SAME scanner
// the census uses over source that deliberately contains residual 2's shape.
//
// Without it the census would be one more guard that has never been seen to
// fail. That is not a hypothetical failure mode in this package: the previous
// read-gate guard counted bodies carrying BOTH arms, so the one-arm defect it
// was written for went through it twice.
func TestTheFunnelDetectorCatchesTheDefectItWasWrittenFor(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "zz_funnel_probe.go", provFunnelProbeSource, 0)
	if err != nil {
		t.Fatalf("parsing the synthetic probe: %v", err)
	}

	factFields := map[string]bool{
		"state": true, "sastStatus": true, "sastSealedAt": true,
		"dastStatus": true, "dastSealedAt": true, "dastDerived": true, "dastOutcome": true,
	}
	mutators := map[string]bool{
		"audit.setHalf": true, "audit.setLifecycleState": true, "audit.setDastOutcome": true,
	}

	findings, seen := provScanFunnel(map[string]*ast.File{"zz_funnel_probe.go": file}, factFields, mutators)

	got := map[string]bool{}
	for _, f := range findings {
		got[f.String()] = true
	}
	want := []string{
		// residual 2's shape: four fact-bearing writes in a non-mutator whose
		// error return sits between the first of them and the publish.
		"assign:Sealer.sealHalfUnpublishedDast:dastDerived",
		"assign:Sealer.sealHalfUnpublishedDast:dastSealedAt",
		"assign:Sealer.sealHalfUnpublishedDast:dastStatus",
		"assign:Sealer.sealHalfUnpublishedDast:state",
		// a mutator that lost its publish, and one that returns in front of it.
		"publish:audit.setHalf:does not end in publish",
		"publish:audit.setLifecycleState:returns early",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("the detector missed %q. It is the shape the census exists to catch, so a "+
				"census that cannot see it here cannot see it in sealing.go either.\n"+
				"    reported: %v", w, slices.Sorted(maps.Keys(got)))
		}
		delete(got, w)
	}
	for extra := range got {
		t.Errorf("the detector reported %q, which the probe does not contain. innocentReader "+
			"only READS the fact-bearing fields and assigns a local; flagging a read would "+
			"flag half of sealing.go and the census would be unusable.", extra)
	}
	if !seen["audit.setDastOutcome"] {
		t.Error("the probe's well-formed mutator was not recognised as a mutator; the detector " +
			"would report the whole funnel as missing")
	}
	if len(seen) != len(mutators) {
		t.Errorf("the detector saw %d of %d mutators", len(seen), len(mutators))
	}
}

// ---------------------------------------------------------------------------
// CLOCK 3 — the DAST deadline now has an authoritative substrate
// ---------------------------------------------------------------------------

// TestClockThreeIsDueCheckedAgainstTheSealersOwnCopy is CRITIQUE O.4 blocker
// 2's probe P10, second half, moved to the owner: the due-check is against
// `startedAt + dastDeadlineSeconds` as BeginAudit fixed them, so nothing a
// caller holds can move it.
func TestClockThreeIsDueCheckedAgainstTheSealersOwnCopy(t *testing.T) {
	start := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	now := start
	s := NewSealer()
	s.SetClock(func() time.Time { return now })

	four := 4 * 3600
	seal, err := s.BeginAudit(AuditConfig{
		AuditID: "clock3", StartedAt: start, ClaimTimeoutSeconds: 24 * 3600,
		DastEnabled: true, DastDeadlineSeconds: &four,
	})
	if err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}

	due, ok := seal.DastDeadlineAt()
	if !ok {
		t.Fatal("AuditSeal.DastDeadlineAt reports no DAST deadline for an audit that has one")
	}
	if want := start.Add(4 * time.Hour); !due.Equal(want) {
		t.Errorf("clock 3 = %s, want %s (started_at + dast_deadline_seconds)", due, want)
	}

	// The target booted and the half is scanning. Without this the derivation
	// reports skipped_no_manifest — provenance outranks the half's status, by
	// design — and clock 3's own outcome would be invisible.
	if err := s.RecordDastOutcome("clock3", DastOutcome{Provenance: TargetProvenanceBootedClean}); err != nil {
		t.Fatalf("RecordDastOutcome: %v", err)
	}

	// Before the deadline: nothing happens, and it is not an error.
	now = start.Add(3 * time.Hour)
	if fired, err := s.SealDastIfDeadlineDue("clock3"); err != nil || fired {
		t.Fatalf("clock 3 fired %v (err %v) three hours into a four-hour deadline", fired, err)
	}

	// A caller re-deriving from its own snapshot cannot move it: there is no
	// deadline FIELD to assign to, only StartedAt and DastDeadlineSeconds,
	// both fixed at BeginAudit. Mutating the caller's copy of the snapshot
	// changes what that copy says and nothing about what fires.
	tampered, _ := s.Inspect("clock3")
	hundred := 100 * 3600
	tampered.DastDeadlineSeconds = &hundred
	tampered.StartedAt = start.Add(96 * time.Hour)
	if moved, _ := tampered.DastDeadlineAt(); moved.Equal(due) {
		t.Fatal("the probe did not actually move the caller's copy; it proves nothing")
	}
	now = start.Add(5 * time.Hour)
	fired, err := s.SealDastIfDeadlineDue("clock3")
	if err != nil {
		t.Fatalf("SealDastIfDeadlineDue: %v", err)
	}
	if !fired {
		t.Fatal("O4-B2 REPRODUCED: clock 3 did not fire an hour past the deadline after a " +
			"caller pushed its own copy of the deadline out. The Sealer must hold its own.")
	}

	live, _ := s.Inspect("clock3")
	if live.Dast.Status != HalfStatusTimedOut {
		t.Errorf("DAST half is %q after clock 3 fired, want %q", live.Dast.Status, HalfStatusTimedOut)
	}
	if live.Dast.SealedAt != nil {
		t.Error("a timed-out half carries a sealedAt; only a cleanly sealed half may")
	}
	if live.DastStatus != DastStatusTimedOut {
		t.Errorf("anvil/dastStatus = %q, want %q", live.DastStatus, DastStatusTimedOut)
	}
	if live.Dast.Readable() {
		t.Error("a timed-out DAST half is readable; terminal is not readable")
	}

	// Clock 3 firing does not move clock 2 by one nanosecond.
	if !live.DeadlineAt.Equal(seal.DeadlineAt) {
		t.Errorf("deadline_at moved from %s to %s when clock 3 fired; the clocks are independent",
			seal.DeadlineAt, live.DeadlineAt)
	}

	// Firing twice is a no-op: the half is already terminal.
	if again, err := s.SealDastIfDeadlineDue("clock3"); err != nil || again {
		t.Errorf("a second due-check re-fired (%v, %v); a half seals once", again, err)
	}
}

// TestClockThreeIsAbsentWhenNoDastDeadlineIsConfigured: the common
// core-`anvil` install has no DAST tier, no DAST deadline, and must not have
// its already-skipped half re-sealed by a tick.
func TestClockThreeIsAbsentWhenNoDastDeadlineIsConfigured(t *testing.T) {
	start := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	now := start
	s := NewSealer()
	s.SetClock(func() time.Time { return now })

	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "noclock3", StartedAt: start, ClaimTimeoutSeconds: 3600, DastEnabled: false,
	}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	snap, _ := s.Inspect("noclock3")
	if _, ok := snap.DastDeadlineAt(); ok {
		t.Error("a DAST-disabled audit reports a DAST deadline")
	}

	now = start.Add(10000 * time.Hour)
	if fired, err := s.SealDastIfDeadlineDue("noclock3"); err != nil || fired {
		t.Errorf("clock 3 fired (%v, %v) on an audit with no DAST deadline", fired, err)
	}
	after, _ := s.Inspect("noclock3")
	if after.Dast.Status != HalfStatusSkipped {
		t.Errorf("the skipped DAST half became %q", after.Dast.Status)
	}

	// And an unknown audit is an error, not a silent false: a tick against an
	// audit nobody began is a bug in the caller.
	if _, err := s.SealDastIfDeadlineDue("no-such-audit"); !errors.Is(err, ErrUnknownAudit) {
		t.Errorf("SealDastIfDeadlineDue on an unknown audit = %v, want ErrUnknownAudit", err)
	}
}

// TestComputeDastDeadlineIsTheOneFormula pins the formula itself, so a second
// spelling of clock 3 cannot appear without this failing.
func TestComputeDastDeadlineIsTheOneFormula(t *testing.T) {
	start := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	if _, ok := ComputeDastDeadline(start, nil); ok {
		t.Error("a nil dast_deadline_seconds produced a deadline")
	}
	zero, neg := 0, -1
	if _, ok := ComputeDastDeadline(start, &zero); ok {
		t.Error("a zero dast_deadline_seconds produced a deadline; the schema requires NULL or > 0")
	}
	if _, ok := ComputeDastDeadline(start, &neg); ok {
		t.Error("a negative dast_deadline_seconds produced a deadline")
	}
	n := 90
	got, ok := ComputeDastDeadline(start, &n)
	if !ok || !got.Equal(start.Add(90*time.Second)) {
		t.Errorf("ComputeDastDeadline = (%s, %v), want %s", got, ok, start.Add(90*time.Second))
	}
}
