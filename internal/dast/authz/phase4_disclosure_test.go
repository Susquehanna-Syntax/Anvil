package authz

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// FIXTURES
// ===========================================================================
//
// Every fixture below is a HAND-WRITTEN LITERAL: a 64-character hex string
// nobody hashed, a security.txt document typed out as bytes, a date written
// down. Nothing here is produced by the code under test, so no fixture can
// agree with a bug in it. The sealed constructors appear only where there is
// no other way in — OpenEmbargo, ClassifyOwnership and NewAuditKey have no
// alternative entry point, and that unforgeability is itself the property
// several of these tests are about.

const (
	// p4OtherHash is a hand-written 64-character lowercase hex string. It is
	// the SHA-256 of nothing, so no scope file hashes to it.
	p4OtherHash = "1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb"
	// p4PatchDigest is a hand-written digest for a patch nobody hashed.
	p4PatchDigest = "0f0f0f0f1e1e1e1e2d2d2d2d3c3c3c3c4b4b4b4b5a5a5a5a6969696978787878"

	// p4Finding is the finding every disclosure test is about.
	p4Finding FindingID = "anvil-2026-0001"
	// p4OtherFinding is a second one, for the mismatch tests.
	p4OtherFinding FindingID = "anvil-2026-0002"

	// p4VendorRepo is a repository the operator does NOT own.
	p4VendorRepo = "vendor/product"
	// p4OperatorRepo is one they do.
	p4OperatorRepo = "operator/anvil"

	// p4TargetAddr is a routable address in none of gate 10's reserved
	// ranges.
	p4TargetAddr = "93.184.216.34"
	// p4OtherAddr is a second routable address, for the cross-host redirect.
	p4OtherAddr = "93.184.216.35"
)

var (
	// p4FirstContact is the instant the vendor was first contacted, and
	// therefore the instant every embargo clock in this file starts from.
	p4FirstContact = time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	// p4AttIssued and p4AttExpires bound the attestation. The window is 28
	// days, inside gate 5's 30-day coded ceiling.
	p4AttIssued  = time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	p4AttExpires = time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
)

func p4Clock(t *testing.T, at time.Time) Clock {
	t.Helper()
	c, err := NewClock(at)
	if err != nil {
		t.Fatalf("NewClock(%s): %v", at, err)
	}
	return c
}

// p4Day returns a clock d days after first contact. Day 0 is first contact and
// day 45 is the default deadline.
func p4Day(t *testing.T, d int) Clock {
	t.Helper()
	return p4Clock(t, p4FirstContact.Add(time.Duration(d)*24*time.Hour))
}

// p4Run seals a RUN CLOCK at at. sealRunClock is unexported on purpose — see
// types.go's RunClock — so this helper is only spellable from inside the
// package, which is the property TestRunClockHasNoExportedConstructor pins.
func p4Run(t *testing.T, at time.Time) RunClock {
	t.Helper()
	r := sealRunClock(p4Clock(t, at))
	if !r.Valid() {
		t.Fatalf("sealRunClock(%s) produced an invalid RunClock", at)
	}
	return r
}

// p4RunDay returns THE RUN'S clock, d days after first contact.
func p4RunDay(t *testing.T, d int) RunClock {
	t.Helper()
	return p4Run(t, p4FirstContact.Add(time.Duration(d)*24*time.Hour))
}

// p4Sec returns a clock d seconds after first contact, for the health monitor's
// timeline.
func p4Sec(t *testing.T, d int) Clock {
	t.Helper()
	return p4Clock(t, p4FirstContact.Add(time.Duration(d)*time.Second))
}

// p4ScopeRaw is the scope file every disclosure test's scope is loaded from,
// and p4ScopeHash is what it hashes to. The hash is derived because a Scope's
// hash is now the SHA-256 of the bytes gate 4 parsed; a hand-written value
// would not be the hash of any file.
var (
	p4ScopeRaw = scopeFileJSON(ModeExternal,
		[]ScopeEntry{{Host: "target.example.com", Ports: []uint16{443}}}, nil)
	p4ScopeHash = ScopeHashOf(p4ScopeRaw)
)

func p4Scope(t *testing.T) Scope {
	t.Helper()
	decl, err := DeclareMode(ModeExternal)
	if err != nil {
		t.Fatalf("DeclareMode: %v", err)
	}
	s, err := NewScope(p4ScopeRaw, decl)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	return s
}

func p4Attestation(t *testing.T, hash ScopeHash) Attestation {
	t.Helper()
	a, err := NewAttestation(
		"attest-p4-001",
		"Vendor Liaison, operator of target.example.com",
		AuthorityOperator,
		hash,
		p4AttIssued,
		p4AttExpires,
		DefaultAttestationCeiling(),
	)
	if err != nil {
		t.Fatalf("NewAttestation: %v", err)
	}
	return a
}

func p4Key(t *testing.T) AuditKey {
	t.Helper()
	key, res := NewAuditKey(p4Attestation(t, p4ScopeHash), p4Scope(t))
	p4AssertPassed(t, res, Gate21ImmutableAudit)
	return key
}

// p4SecurityTxt is a hand-typed RFC 9116 document. It is bytes, not a
// constructed SecurityTxtResult, so the reporting channel in these tests goes
// through D.5's real parser.
const p4SecurityTxt = "Contact: mailto:security@vendor.example.com\n" +
	"Policy: https://vendor.example.com/vdp\n" +
	"Expires: 2027-06-01T00:00:00Z\n"

func p4Channel(t *testing.T) SecurityTxtResult {
	t.Helper()
	r := FetchSecurityTxt([]SecurityTxtDocument{{
		Location:  SecurityTxtWellKnown,
		Body:      []byte(p4SecurityTxt),
		Retrieved: true,
	}}, p4Day(t, 0))
	if r.Status() != SecurityTxtStatusResolved {
		t.Fatalf("the fixture security.txt resolved to %q; want %q",
			r.Status(), SecurityTxtStatusResolved)
	}
	return r
}

func p4Contact(t *testing.T) VendorContact {
	t.Helper()
	c, res := RecordVendorContact(p4Channel(t), p4Day(t, 0), p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)
	return c
}

func p4Owned(t *testing.T, repos ...string) OwnedRepositories {
	t.Helper()
	o, err := NewOwnedRepositories(repos...)
	if err != nil {
		t.Fatalf("NewOwnedRepositories(%v): %v", repos, err)
	}
	return o
}

// p4ThirdParty classifies a repository nobody declared, which is every
// repository in the world but the operator's.
func p4ThirdParty(t *testing.T) Ownership {
	t.Helper()
	own, res := ClassifyOwnership(p4VendorRepo, p4Owned(t, p4OperatorRepo))
	p4AssertPassed(t, res, Gate18Embargo)
	return own
}

func p4OperatorOwned(t *testing.T) Ownership {
	t.Helper()
	own, res := ClassifyOwnership(p4OperatorRepo, p4Owned(t, p4OperatorRepo))
	p4AssertPassed(t, res, Gate18Embargo)
	return own
}

func p4Embargo(t *testing.T) EmbargoState {
	t.Helper()
	e, res := OpenEmbargo(p4ThirdParty(t), p4Finding, p4Contact(t), p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)
	return e
}

func p4Patch(t *testing.T) PatchProposal {
	t.Helper()
	p, err := NewPatchProposal(p4PatchDigest, 812)
	if err != nil {
		t.Fatalf("NewPatchProposal: %v", err)
	}
	return p
}

func p4AssertRefused(t *testing.T, res GateResult, wantGate GateID, wantReason Reason) {
	t.Helper()
	if res.Passed() {
		t.Fatalf("the gate PASSED; it was required to refuse (%s / %s)", wantGate, wantReason)
	}
	if res.Gate() != wantGate {
		t.Fatalf("refusal attributed to %s; want %s (%v)", res.Gate(), wantGate, res.Err())
	}
	f := res.Failure()
	if f == nil {
		t.Fatalf("a refusal with no typed failure attached")
	}
	if f.Reason != wantReason {
		t.Fatalf("reason %q; want %q (%v)", string(f.Reason), string(wantReason), res.Err())
	}
	if !errors.Is(res.Err(), ErrRefused) {
		t.Fatalf("the failure does not unwrap to ErrRefused: %v", res.Err())
	}
}

func p4AssertPassed(t *testing.T, res GateResult, wantGate GateID) {
	t.Helper()
	if !res.Passed() {
		t.Fatalf("the gate REFUSED and was required to pass: %v", res.Err())
	}
	if res.Gate() != wantGate {
		t.Fatalf("pass attributed to %s; want %s", res.Gate(), wantGate)
	}
}

// p4Store is a DisclosureStore whose medium, sequence and error are all set by
// the test. It is the negative control for gate 19.
//
// It KEEPS ITS ROWS and answers DisclosureStateFor out of them, which is what
// makes it usable as the shared store the withheld-then-overwritten attack
// needs: a fake that forgot every write could not distinguish the defect from
// the fix.
type p4Store struct {
	medium  StorageMedium
	err     error
	readErr error
	silent  bool
	rows    []DisclosureRecord
	next    AuditSeq
}

func (s *p4Store) Medium() StorageMedium { return s.medium }

func (s *p4Store) PutDisclosureState(r DisclosureRecord) (AuditSeq, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.silent {
		return 0, nil
	}
	s.rows = append(s.rows, r)
	s.next++
	return s.next, nil
}

// DisclosureStateFor returns the MOST RECENT row's state for that finding, or
// DisclosureStateUnset if there is none.
func (s *p4Store) DisclosureStateFor(f FindingID) (DisclosureState, error) {
	if s.readErr != nil {
		return DisclosureStateUnset, s.readErr
	}
	state := DisclosureStateUnset
	for _, r := range s.rows {
		if r.Finding() == f {
			state = r.State()
		}
	}
	return state, nil
}

func p4RecordStore() *p4Store { return &p4Store{medium: MediumRecordStoreSQLite} }

// p4CommittedThenFailedStore is p4CommittedThenFailedSink's twin for gate 19:
// it returns a REAL, ADVANCING sequence number AND an error — the shape a store
// takes when it assigned a row id and then failed to commit.
//
// It exists because p4Store cannot reach persistDisclosureState's `err != nil`
// branch at all: p4Store returns (0, s.err), so the seq==0 branch fires first
// and masks it. Measured before this fake existed: replacing `case err != nil:`
// with `case false:` left the whole suite GREEN. Against this store the error
// branch is the only thing that can refuse.
type p4CommittedThenFailedStore struct {
	err  error
	next AuditSeq
	rows []DisclosureRecord
}

func (s *p4CommittedThenFailedStore) Medium() StorageMedium { return MediumRecordStoreSQLite }

func (s *p4CommittedThenFailedStore) PutDisclosureState(r DisclosureRecord) (AuditSeq, error) {
	s.rows = append(s.rows, r)
	s.next++
	return s.next, s.err
}

func (s *p4CommittedThenFailedStore) DisclosureStateFor(f FindingID) (DisclosureState, error) {
	state := DisclosureStateUnset
	for _, r := range s.rows {
		if r.Finding() == f {
			state = r.State()
		}
	}
	return state, nil
}

// p4FlippingStore answers MediumRecordStoreSQLite on its FIRST Medium() call
// and the tmpfs handoff buffer on every call after it.
//
// A store has no business changing its answer, and a real one will not. This
// one exists to prove that gate 19 asks ONCE: the medium that is checked and
// the medium that is stamped into the proof must be one value, not two answers
// to one question.
type p4FlippingStore struct {
	calls int
	next  AuditSeq
}

func (s *p4FlippingStore) Medium() StorageMedium {
	s.calls++
	if s.calls == 1 {
		return MediumRecordStoreSQLite
	}
	return MediumTmpfsHandoffBuffer
}

func (s *p4FlippingStore) PutDisclosureState(DisclosureRecord) (AuditSeq, error) {
	s.next++
	return s.next, nil
}

func (s *p4FlippingStore) DisclosureStateFor(FindingID) (DisclosureState, error) {
	return DisclosureStateUnset, nil
}

// p4RewindSink is an AuditSink that reports success and hands back THE SAME
// sequence number every time — a log that was rewound, or a row that was
// overwritten rather than appended.
type p4RewindSink struct {
	rows []GateRecord
}

func (s *p4RewindSink) WriteGateDecision(r GateRecord) (AuditSeq, error) {
	s.rows = append(s.rows, r)
	return 7, nil
}

// p4CommittedThenFailedSink returns a REAL, ADVANCING sequence number AND an
// error — the shape a store takes when it assigned a row id and then failed to
// commit.
//
// Both halves are load-bearing. A sink returning (0, err) is refused by
// Record's sequence-zero branch as well as its error branch, and a sink
// returning a CONSTANT sequence with an error is refused by the append-only
// branch from the second row onward. Against either of those, deleting the
// error branch stayed green — a mutation run showed both — so this sink
// advances, which leaves `werr != nil` as the only thing that can refuse it.
type p4CommittedThenFailedSink struct {
	err  error
	next AuditSeq
}

func (s *p4CommittedThenFailedSink) WriteGateDecision(GateRecord) (AuditSeq, error) {
	s.next++
	return s.next, s.err
}

// p4Audit binds a writer to a run clocked at first contact. Tests that need
// the writer's run to sit somewhere else on the timeline use p4AuditAt.
func p4Audit(t *testing.T, sink AuditSink) *GateAudit {
	t.Helper()
	return p4AuditAt(t, sink, p4RunDay(t, 0))
}

func p4AuditAt(t *testing.T, sink AuditSink, run RunClock) *GateAudit {
	t.Helper()
	a, res := NewGateAudit(sink, p4Key(t), run)
	p4AssertPassed(t, res, Gate21ImmutableAudit)
	return a
}

// p4Persisted runs the real gate 19 path INTO store and returns the proof gate
// 18 wants.
//
// The store is a parameter rather than a throwaway created here because gate
// 18 now READS it: a proof minted against a store that was then dropped on the
// floor is a proof of a row nobody can find, which is the condition gate 18
// refuses.
func p4Persisted(t *testing.T, store DisclosureStore, emb EmbargoState, state DisclosureState) PersistedDisclosure {
	t.Helper()
	rec, res := NewDisclosureRecord(emb, state, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	p, res := persistDisclosureState(store, rec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	return p
}

// p4PublishRequest is the well-formed third-party publication request every
// gate-18 test starts from and then breaks one field of, together with THE
// STORE its disclosure row was written to.
//
// The two are returned together because they cannot be separated any more:
// gate 18 asks the store what this finding's recorded state is, so a request
// handed a different store than the one its proof came from is a request whose
// state the store has never heard of.
func p4PublishRequest(t *testing.T, emb EmbargoState) (PublicationRequest, *p4Store) {
	t.Helper()
	store := p4RecordStore()
	return PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: p4Persisted(t, store, emb, DisclosureStateEmbargoed),
	}, store
}

// p4PushRequest is the well-formed third-party push request every gate-20 test
// starts from.
func p4PushRequest(t *testing.T) PushRequest {
	t.Helper()
	return PushRequest{
		Finding:     p4Finding,
		Destination: p4ThirdParty(t),
		Attestation: p4Attestation(t, p4ScopeHash),
		Scope:       p4Scope(t),
		Embargo:     p4Embargo(t),
		Patch:       p4Patch(t),
	}
}

// ===========================================================================
// GATE 18 — no auto-publication of third-party findings
// ===========================================================================

func TestGate18DeadlineIsFortyFiveDaysFromFirstContact(t *testing.T) {
	emb := p4Embargo(t)
	want := p4FirstContact.Add(DefaultEmbargo)
	if !emb.Deadline().Equal(want) {
		t.Fatalf("deadline %s; want %s", emb.Deadline(), want)
	}
	if DefaultEmbargo != 45*24*time.Hour {
		t.Fatalf("DefaultEmbargo is %s; research/20 gate 18 and CERT/CC say 45 days",
			DefaultEmbargo)
	}
	if !emb.FirstContact().Equal(p4FirstContact) {
		t.Fatalf("first contact %s; want %s", emb.FirstContact(), p4FirstContact)
	}
}

// TestGate18ThirdPartyFindingIsNotPublishedBeforeTheDeadline is D.7's first
// required validation: "a third-party finding cannot reach a 'published' state
// before 45 days without an explicit acceleration reason attached".
func TestGate18ThirdPartyFindingIsNotPublishedBeforeTheDeadline(t *testing.T) {
	emb := p4Embargo(t)

	for _, day := range []int{0, 1, 22, 44} {
		req, store := p4PublishRequest(t, emb)
		res := checkGate18Publication(req, p4RunDay(t, day), store)
		p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoRunning)
	}

	// Day 45 is the deadline itself, and the comparison is "not before", so
	// the deadline instant publishes.
	day45, store45 := p4PublishRequest(t, emb)
	res := checkGate18Publication(day45, p4RunDay(t, 45), store45)
	p4AssertPassed(t, res, Gate18Embargo)
}

func TestGate18AccelerationNeedsAnAllowlistedReason(t *testing.T) {
	emb := p4Embargo(t)
	for _, reason := range []EmbargoAccelerationReason{
		EmbargoAccelerationUnset,
		"active_exploitation", // near-miss of the real token
		"ACTIVE_EXPLOITATION_OBSERVED",
		"vendor_unresponsive",
		"operator_decision",
		"disable",
	} {
		_, res := emb.Accelerate(reason, "IDS caught it in the wild on 2026-08-12", p4RunDay(t, 5))
		p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoAccelerationUnsupported)
	}
}

func TestGate18AccelerationNeedsEvidence(t *testing.T) {
	emb := p4Embargo(t)
	for name, evidence := range map[string]string{
		"empty":        "",
		"whitespace":   "   \t  ",
		"control byte": "seen in the wild\x00",
		"newline":      "seen in the wild\nand again",
		"too long":     strings.Repeat("a", maxEmbargoEvidenceLen+1),
		"non ascii":    "seen in the wild é",
	} {
		t.Run(name, func(t *testing.T) {
			_, res := emb.Accelerate(EmbargoAccelerationActiveExploitation, evidence, p4RunDay(t, 5))
			p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoAccelerationUnevidenced)
		})
	}
}

// TestGate18AccelerationCannotZeroTheEmbargo is the forbidden action:
// "the 45-day CERT/CC embargo default must not be fully disablable by config".
// Acceleration is the only shortening path, and it is floored.
func TestGate18AccelerationCannotZeroTheEmbargo(t *testing.T) {
	emb := p4Embargo(t)

	// Accelerate on the very day of first contact. The request is honoured,
	// and the deadline lands on the floor rather than on "now".
	fast, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"exploitation observed in server logs", p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)

	// The expected floor is a HAND-WRITTEN INSTANT, not p4FirstContact plus
	// MinAcceleratedEmbargo. Computed from the constant, this assertion said
	// only that the code equals itself: measured, MinAcceleratedEmbargo could
	// be changed from 24h to 1s and this test stayed GREEN while acceleration
	// became the disable switch the gate table says does not exist.
	// p4FirstContact is 2026-08-10T12:00:00Z, so one day later is this.
	want := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	if !fast.Deadline().Equal(want) {
		t.Fatalf("accelerated deadline %s; want the coded floor %s", fast.Deadline(), want)
	}

	// Publication on the day of contact is still refused.
	day0, day0Store := p4PublishRequest(t, fast)
	res = checkGate18Publication(day0, p4RunDay(t, 0), day0Store)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoRunning)

	// And is permitted a day later, which is what "accelerated" means.
	day1, day1Store := p4PublishRequest(t, fast)
	res = checkGate18Publication(day1, p4RunDay(t, 1), day1Store)
	p4AssertPassed(t, res, Gate18Embargo)
}

func TestGate18AccelerationCannotLengthenTheEmbargo(t *testing.T) {
	emb := p4Embargo(t)
	_, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"observed on 2026-09-28", p4RunDay(t, 50))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoAccelerationNoEffect)
}

func TestGate18AccelerationRefusesAClockBeforeFirstContact(t *testing.T) {
	emb := p4Embargo(t)
	_, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"observed before we told anyone", p4RunDay(t, -3))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoClockWentBack)
}

func TestGate18ExtensionNeedsAnAllowlistedReasonAndEvidence(t *testing.T) {
	emb := p4Embargo(t)
	for _, reason := range []EmbargoExtensionReason{
		EmbargoExtensionUnset, "vendor_asked_nicely", "STANDARDS_PROCESS", "core_os",
	} {
		_, res := emb.Extend(reason, "IETF draft in last call", p4Day(t, 90), p4RunDay(t, 0))
		p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionUnsupported)
	}
	_, res := emb.Extend(EmbargoExtensionStandardsProcess, "", p4Day(t, 90), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionUnevidenced)
}

func TestGate18ExtensionOnlyLengthensAndIsBounded(t *testing.T) {
	emb := p4Embargo(t)

	_, res := emb.Extend(EmbargoExtensionCoreOSChange, "kernel patch queued", p4Day(t, 40), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionNotLonger)

	_, res = emb.Extend(EmbargoExtensionCoreOSChange, "kernel patch queued", p4Day(t, 400), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionExceedsBound)

	long, res := emb.Extend(EmbargoExtensionStandardsProcess, "IETF draft in last call",
		p4Day(t, 120), p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)
	if !long.Deadline().Equal(p4FirstContact.Add(120 * 24 * time.Hour)) {
		t.Fatalf("extended deadline %s; want day 120", long.Deadline())
	}
	// The extension is what the publication gate now measures against.
	longReq, longStore := p4PublishRequest(t, long)
	res = checkGate18Publication(longReq, p4RunDay(t, 46), longStore)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoRunning)
}

func TestGate18AdjustmentsAreRecordedWithBothDeadlines(t *testing.T) {
	emb := p4Embargo(t)
	fast, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"exploited in the wild", p4RunDay(t, 10))
	p4AssertPassed(t, res, Gate18Embargo)

	adj := fast.Adjustments()
	if len(adj) != 1 {
		t.Fatalf("%d adjustments recorded; want 1", len(adj))
	}
	if adj[0].Kind() != EmbargoAdjustmentAccelerate {
		t.Fatalf("kind %q; want %q", adj[0].Kind(), EmbargoAdjustmentAccelerate)
	}
	if adj[0].Reason() != string(EmbargoAccelerationActiveExploitation) {
		t.Fatalf("reason %q", adj[0].Reason())
	}
	if !adj[0].From().Equal(p4FirstContact.Add(DefaultEmbargo)) {
		t.Fatalf("from %s; want the 45-day deadline", adj[0].From())
	}
	if !adj[0].To().Equal(fast.Deadline()) {
		t.Fatalf("to %s; want the new deadline %s", adj[0].To(), fast.Deadline())
	}
	// The original is untouched: Accelerate returns a new state.
	if len(emb.Adjustments()) != 0 {
		t.Fatalf("Accelerate mutated the receiver's adjustments")
	}
	if !emb.Deadline().Equal(p4FirstContact.Add(DefaultEmbargo)) {
		t.Fatalf("Accelerate mutated the receiver's deadline")
	}
}

// TestEmbargoAdjustmentsCannotBeWrittenThrough is the test D.3's critic asked
// for against Scope: mutate what the accessor handed back and assert the value
// is unmoved.
func TestEmbargoAdjustmentsCannotBeWrittenThrough(t *testing.T) {
	emb := p4Embargo(t)
	fast, res := emb.Accelerate(EmbargoAccelerationActiveExploitation, "exploited", p4RunDay(t, 10))
	p4AssertPassed(t, res, Gate18Embargo)

	got := fast.Adjustments()
	got[0] = EmbargoAdjustment{kind: EmbargoAdjustmentExtend, reason: "forged"}
	got = append(got, EmbargoAdjustment{kind: EmbargoAdjustmentExtend})

	again := fast.Adjustments()
	if len(again) != 1 || again[0].Kind() != EmbargoAdjustmentAccelerate ||
		again[0].Reason() != string(EmbargoAccelerationActiveExploitation) {
		t.Fatalf("the adjustment list was writable through the accessor: %+v", again)
	}
}

// TestEmbargoAdjustmentHasNoReferenceFields is the guard behind the comment on
// EmbargoState.Adjustments. D.3's critic showed that copying a []ScopeEntry
// copies the structs but not their []uint16 backing arrays; a shallow copy is
// only sufficient while every field is a value type, so this fails the moment
// somebody adds a slice, map, pointer or interface field.
func TestEmbargoAdjustmentHasNoReferenceFields(t *testing.T) {
	typ := reflect.TypeOf(EmbargoAdjustment{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		switch f.Type.Kind() {
		case reflect.Slice, reflect.Map, reflect.Ptr, reflect.Interface,
			reflect.Chan, reflect.Func, reflect.UnsafePointer, reflect.Array:
			t.Fatalf("EmbargoAdjustment.%s is a %s. Adjustments() returns a shallow copy, "+
				"which no longer seals the value: deep-copy it or unexport the path",
				f.Name, f.Type.Kind())
		}
	}
}

func TestGate18RefusesAnUnclassifiedOwnership(t *testing.T) {
	emb := p4Embargo(t)
	req, store := p4PublishRequest(t, emb)
	req.Ownership = Ownership{}
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo,
		ReasonOwnershipUnclassified)
}

// TestGate18PublishesAnOperatorOwnedFindingWithoutAnEmbargo is the branch's
// legitimate half: the operator's own finding has no embargo and does not need
// one. It still needs gate 19's proof, which is what
// NewOwnFindingDisclosureRecord is for — see
// TestGate18OperatorOwnedClaimDeletesTheEmbargoAndNothingElse for the half
// that used to be a bypass.
func TestGate18PublishesAnOperatorOwnedFindingWithoutAnEmbargo(t *testing.T) {
	own := p4OperatorOwned(t)
	store := p4RecordStore()
	rec, res := NewOwnFindingDisclosureRecord(own, p4Finding, DisclosureStatePublished, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	pers, res := persistDisclosureState(store, rec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	res = checkGate18Publication(PublicationRequest{
		Finding:   p4Finding,
		Ownership: own,
		Persisted: pers,
	}, p4RunDay(t, 0), store)
	p4AssertPassed(t, res, Gate18Embargo)
}

func TestGate18RefusesAnEmbargoForAnotherFinding(t *testing.T) {
	other, res := OpenEmbargo(p4ThirdParty(t), p4OtherFinding, p4Contact(t), p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)

	req, store := p4PublishRequest(t, p4Embargo(t))
	req.Embargo = other
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo,
		ReasonEmbargoFindingMismatch)
}

// TestGate18RefusesWithoutGate19sProof is the wiring between the two gates:
// an embargo that exists only in memory does not publish, because tmpfs does
// not survive a reboot and neither does a local variable.
func TestGate18RefusesWithoutGate19sProof(t *testing.T) {
	emb := p4Embargo(t)
	req, store := p4PublishRequest(t, emb)
	req.Persisted = PersistedDisclosure{}
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo,
		ReasonPublicationStateNotPersisted)

	// A proof that names the RIGHT finding and is still not valid. These are
	// built here rather than through PersistDisclosureState because gate 18's
	// Valid() check is what stands between a publication and a proof whose
	// medium or sequence is wrong, and a proof with the wrong finding is
	// caught by a later branch — so without these two cases the Valid() check
	// could be deleted and the suite would stay green. A mutation run
	// confirmed exactly that before they were added.
	for name, forged := range map[string]PersistedDisclosure{
		"persisted to tmpfs": {
			finding: p4Finding, state: DisclosureStateEmbargoed,
			medium: MediumTmpfsHandoffBuffer, seq: 1, key: p4Key(t), sealed: true,
		},
		"no row sequence": {
			finding: p4Finding, state: DisclosureStateEmbargoed,
			medium: MediumRecordStoreSQLite, seq: 0, key: p4Key(t), sealed: true,
		},
		"unkeyed": {
			finding: p4Finding, state: DisclosureStateEmbargoed,
			medium: MediumRecordStoreSQLite, seq: 4, sealed: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad, badStore := p4PublishRequest(t, emb)
			bad.Persisted = forged
			p4AssertRefused(t, checkGate18Publication(bad, p4RunDay(t, 60), badStore),
				Gate18Embargo, ReasonPublicationStateNotPersisted)
		})
	}

	// A proof for a DIFFERENT finding is not a proof for this one.
	other, res := OpenEmbargo(p4ThirdParty(t), p4OtherFinding, p4Contact(t), p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)
	req, store = p4PublishRequest(t, emb)
	req.Persisted = p4Persisted(t, p4RecordStore(), other, DisclosureStateEmbargoed)
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo,
		ReasonPublicationStateNotPersisted)
}

func TestGate18RefusesAWithheldFinding(t *testing.T) {
	emb := p4Embargo(t)
	req, store := p4PublishRequest(t, emb)
	req.Persisted = p4Persisted(t, p4RecordStore(), emb, DisclosureStateWithheld)
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo,
		ReasonPublicationFindingWithheld)
}

// ===========================================================================
// A RECORDED `withheld` IS NOT OVERTURNED BY WRITING A SECOND ROW
// ===========================================================================

// TestWithheldSurvivesASecondRow is finding 2, run end to end against ONE
// SHARED STORE, which is what the previous tree never did.
//
// # What was measured against the previous tree
//
// Gate 18 read only the PersistedDisclosure its caller handed it, and
// persistDisclosureState imposed no ordering on the rows it wrote. Every value
// was sealed and both writes were audited, and this passed:
//
//	AuditedPersistDisclosure(store, rec{withheld})    passed=true
//	AuditedPersistDisclosure(store, rec{embargoed})   passed=true
//	AuditedPublication(req{Persisted: the SECOND proof})  passed=true
//
// The word "withheld" meant "withheld until somebody writes another row".
//
// # The two halves, because closing either alone leaves the other open
//
// (1) GATE 19 refuses the second write: leaving `withheld` requires an
//
//	allowlisted reason and evidence, the same treatment Accelerate and
//	Extend already require.
//
// (2) GATE 18 refuses the publication even when it is handed a perfectly
//
//	valid non-withheld proof, because it asks the STORE rather than the
//	caller. Half (2) is exercised below by persisting `embargoed` FIRST and
//	`withheld` second, so the caller legitimately holds a valid embargoed
//	proof and the store legitimately says withheld — which is exactly the
//	"a caller holding two proofs presents the convenient one" case that
//	half (1) alone does not reach.
func TestWithheldSurvivesASecondRow(t *testing.T) {
	emb := p4Embargo(t)

	// ---- Half 1: gate 19 refuses the overwrite. ----
	//
	// Driven through the ONLY EXPORTED ROUTE, GateAudit.AuditedPersistDisclosure,
	// because that is the route the measurement used and because a refusal
	// reachable only from inside the package refuses nobody.
	store := p4RecordStore()
	sink19 := &recordingSink{}
	audit19 := p4AuditAt(t, sink19, p4RunDay(t, 60))

	withheldRec, res := NewDisclosureRecord(emb, DisclosureStateWithheld, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	_, res = audit19.AuditedPersistDisclosure(store, withheldRec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	openRec, res := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	overturn, res := audit19.AuditedPersistDisclosure(store, openRec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureWithholdingHeld)
	if overturn.Valid() {
		t.Fatal("the refused overwrite handed back a publication proof anyway")
	}
	if n := len(store.rows); n != 1 {
		t.Fatalf("the store holds %d rows; the second write must not have landed", n)
	}
	if len(sink19.rows) != 2 || sink19.rows[1].Outcome != OutcomeDeny {
		t.Fatalf("the refused overwrite was not recorded as a deny row: %+v", sink19.rows)
	}

	// Re-AFFIRMING the withholding is not leaving it and needs no release.
	_, res = audit19.AuditedPersistDisclosure(store, withheldRec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	// ---- Half 2: gate 18 asks the store, not the caller. ----
	//
	// Order reversed on a fresh store so the caller ends up holding a VALID
	// embargoed proof while the store's latest row says withheld. Nothing here
	// is forged.
	second := p4RecordStore()
	goodProof := p4Persisted(t, second, emb, DisclosureStateEmbargoed)
	if !goodProof.Valid() {
		t.Fatal("the embargoed proof is not valid, so half 2 would prove nothing")
	}
	if goodProof.State() == DisclosureStateWithheld {
		t.Fatal("the proof already says withheld; gate 18's OLD check would catch this " +
			"and the store read would prove nothing")
	}
	_, res = persistDisclosureState(second, withheldRec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	req := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: goodProof,
	}
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), second), Gate18Embargo,
		ReasonPublicationFindingWithheld)

	// And through the only exported route, with the audit row down.
	sink := &recordingSink{}
	audit := p4AuditAt(t, sink, p4RunDay(t, 60))
	out := audit.AuditedPublication(second, req)
	p4AssertRefused(t, out, Gate18Embargo, ReasonPublicationFindingWithheld)
	if len(sink.rows) != 1 || sink.rows[0].Outcome != OutcomeDeny {
		t.Fatalf("the refusal was not recorded as a deny row: %+v", sink.rows)
	}
}

// TestWithholdingIsReleasedOnlyWithAnAllowlistedReasonAndEvidence is the other
// side of the state machine: `withheld` is REVERSIBLE, deliberately, and the
// cost of reversing it is the cost of shortening an embargo.
//
// A control that cannot be lifted at all is a control operators route around.
func TestWithholdingIsReleasedOnlyWithAnAllowlistedReasonAndEvidence(t *testing.T) {
	emb := p4Embargo(t)
	store := p4RecordStore()
	withheldRec, res := NewDisclosureRecord(emb, DisclosureStateWithheld, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	_, res = persistDisclosureState(store, withheldRec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	openRec, res := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	// No reason on the allowlist releases nothing, including the empty one a
	// caller that forgot the argument supplies.
	for _, reason := range []WithholdingReleaseReason{
		WithholdingReleaseUnset,
		"rescinded",
		"WITHHOLDING_DECISION_RESCINDED",
		"operator_changed_their_mind",
		"vendor_published",
	} {
		_, res := openRec.ReleaseWithholding(reason, "advisory GHSA-xxxx published 2026-09-01")
		p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureReleaseUnsupported)
	}

	// An allowlisted reason with nothing attached is an assertion.
	for name, evidence := range map[string]string{
		"empty":      "",
		"whitespace": "   \t  ",
		"non-ascii":  "advisory published \u00e9",
		"newline":    "advisory\npublished",
	} {
		t.Run("evidence "+name, func(t *testing.T) {
			_, res := openRec.ReleaseWithholding(WithholdingReleaseRescinded, evidence)
			p4AssertRefused(t, res, Gate19DisclosureStateInDB,
				ReasonDisclosureReleaseUnevidenced)
		})
	}

	// A release on a row that is ITSELF entering `withheld` releases nothing.
	_, res = withheldRec.ReleaseWithholding(WithholdingReleaseRescinded, "rescinded by the reporter")
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureReleaseNotApplicable)

	// A release on a record nobody constructed mints nothing.
	_, res = DisclosureRecord{}.ReleaseWithholding(WithholdingReleaseRescinded, "rescinded")
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureRecordUnconstructed)

	// THE LEGITIMATE PATH. Both allowlisted reasons work, and the row carries
	// the reason and the evidence into the store.
	released, res := openRec.ReleaseWithholding(WithholdingReleaseVendorPublished,
		"vendor advisory GHSA-0000-0000-0000 published 2026-09-01")
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	if released.ReleaseReason() != WithholdingReleaseVendorPublished {
		t.Fatalf("the released row carries reason %q", released.ReleaseReason())
	}
	if released.ReleaseEvidence() == "" {
		t.Fatal("the released row carries no evidence, so the record store would keep " +
			"a reversal nobody can review")
	}
	// The ORIGINAL row is unchanged, the same shape Accelerate and Extend use.
	if openRec.ReleaseReason() != WithholdingReleaseUnset {
		t.Fatal("ReleaseWithholding mutated its receiver, so a caller holding the old row " +
			"holds one that can now overturn a withholding")
	}

	proof, res := persistDisclosureState(store, released)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	if !proof.Valid() {
		t.Fatal("the released write produced no publication proof")
	}
	if got := store.rows[len(store.rows)-1].ReleaseEvidence(); got == "" {
		t.Fatal("the row that reached the store carries no release evidence")
	}

	// And now the store says `embargoed`, so gate 18 measures the clock again
	// rather than refusing on the withholding.
	req := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: proof,
	}
	p4AssertPassed(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo)
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 10), store), Gate18Embargo,
		ReasonEmbargoRunning)
}

// TestGate19RefusesAReleaseWithNothingToRelease keeps the reason token honest:
// a release recorded next to a transition that did not happen is a row a
// reviewer will believe.
func TestGate19RefusesAReleaseWithNothingToRelease(t *testing.T) {
	emb := p4Embargo(t)
	store := p4RecordStore()
	rec, res := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	released, res := rec.ReleaseWithholding(WithholdingReleaseRescinded,
		"rescinded by the reporter on 2026-09-01")
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	// Nothing is in the store, so nothing is withheld.
	_, res = persistDisclosureState(store, released)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureReleaseNotApplicable)

	// Nor when the recorded state is a real, non-withheld one.
	_, res = persistDisclosureState(store, rec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	_, res = persistDisclosureState(store, released)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureReleaseNotApplicable)
}

// TestBothGatesRefuseAStoreTheyCannotRead is the "a check that cannot see the
// damage is not a check" case: an unreadable state is not an absent one,
// because the row that could not be read is the row that says `withheld`.
func TestBothGatesRefuseAStoreTheyCannotRead(t *testing.T) {
	emb := p4Embargo(t)
	good := p4RecordStore()
	proof := p4Persisted(t, good, emb, DisclosureStateEmbargoed)

	blind := &p4Store{
		medium:  MediumRecordStoreSQLite,
		readErr: errors.New("disclosure table is locked"),
	}
	rec, res := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	_, res = persistDisclosureState(blind, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureReadFailed)
	if n := len(blind.rows); n != 0 {
		t.Fatalf("a write landed (%d rows) despite the prior state being unreadable", n)
	}

	req := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: proof,
	}
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), blind), Gate18Embargo,
		ReasonPublicationStoreUnreadable)
}

// TestGate18RefusesAStoreItCannotTrustOrDoesNotHave covers the three ways the
// store gate 18 was handed cannot be the authority on what was recorded.
func TestGate18RefusesAStoreItCannotTrustOrDoesNotHave(t *testing.T) {
	emb := p4Embargo(t)
	held := p4RecordStore()
	req := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: p4Persisted(t, held, emb, DisclosureStateEmbargoed),
	}

	// No store at all: gate 18 would be deciding from the proof the caller
	// chose to hand over.
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), nil), Gate18Embargo,
		ReasonPublicationStoreMissing)

	// A store that is not the record store. "Nothing is withheld" read out of
	// the tmpfs handoff buffer is not an answer: the buffer does not survive a
	// reboot, so a withholding decision cannot be kept there.
	for _, medium := range []StorageMedium{
		MediumTmpfsHandoffBuffer, MediumProcessMemory, MediumUnset, "something_new",
	} {
		p4AssertRefused(t,
			checkGate18Publication(req, p4RunDay(t, 60), &p4Store{medium: medium}),
			Gate18Embargo, ReasonPublicationStoreWrongMedium)
	}

	// The right kind of store, which has simply never heard of this finding.
	// The proof says one thing and the authority says nothing; the authority
	// wins.
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), p4RecordStore()),
		Gate18Embargo, ReasonPublicationStateNotPersisted)

	// The control for all four: the store that actually holds the row permits.
	p4AssertPassed(t, checkGate18Publication(req, p4RunDay(t, 60), held), Gate18Embargo)
}

func TestGate18ZeroRequestRefuses(t *testing.T) {
	p4AssertRefused(t, checkGate18Publication(PublicationRequest{}, p4RunDay(t, 60), p4RecordStore()),
		Gate18Embargo, ReasonFindingUnidentified)

	// A ZERO RunClock is not a clock. It is what a caller reaching gate 18
	// from outside an initiated run has, and it must refuse rather than read
	// as 1970 — which is before every deadline and would therefore report
	// every embargo as still running, or after every deadline for a
	// comparison written the other way round.
	req := PublicationRequest{Finding: p4Finding}
	p4AssertRefused(t, checkGate18Publication(req, RunClock{}, p4RecordStore()),
		Gate18Embargo, ReasonEmbargoClockUnconstructed)

	// And an unclassified ownership refuses under a valid run clock.
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), p4RecordStore()),
		Gate18Embargo, ReasonOwnershipUnclassified)
}

func TestGate18RefusesAnUnconstructedEmbargoForAThirdParty(t *testing.T) {
	// With gate 19's proof present, so that the refusal below is the embargo
	// branch rather than the persistence branch above it.
	store := p4RecordStore()
	res := checkGate18Publication(PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Persisted: p4Persisted(t, store, p4Embargo(t), DisclosureStateEmbargoed),
	}, p4RunDay(t, 400), store)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoUnconstructed)
}

func TestOpenEmbargoNeedsAResolvedReportingChannel(t *testing.T) {
	// No document at all.
	absent := FetchSecurityTxt(nil, p4Day(t, 0))
	_, res := RecordVendorContact(absent, p4Day(t, 0), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)

	// A document with no Contact field is malformed under RFC 9116.
	noContact := FetchSecurityTxt([]SecurityTxtDocument{{
		Location:  SecurityTxtWellKnown,
		Body:      []byte("Policy: https://vendor.example.com/vdp\nExpires: 2027-06-01T00:00:00Z\n"),
		Retrieved: true,
	}}, p4Day(t, 0))
	_, res = RecordVendorContact(noContact, p4Day(t, 0), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)

	// A stale document resolves no channel.
	expired := FetchSecurityTxt([]SecurityTxtDocument{{
		Location: SecurityTxtWellKnown,
		Body: []byte("Contact: mailto:security@vendor.example.com\n" +
			"Expires: 2026-01-01T00:00:00Z\n"),
		Retrieved: true,
	}}, p4Day(t, 0))
	_, res = RecordVendorContact(expired, p4Day(t, 0), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)

	// And the zero value, which is what a caller that never fetched has.
	_, res = RecordVendorContact(SecurityTxtResult{}, p4Day(t, 0), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)
}

func TestOpenEmbargoRefusesWithoutAVendorContact(t *testing.T) {
	_, res := OpenEmbargo(p4ThirdParty(t), p4Finding, VendorContact{}, p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoVendorContact)
}

func TestOpenEmbargoRefusesAnOperatorOwnedFinding(t *testing.T) {
	_, res := OpenEmbargo(p4OperatorOwned(t), p4Finding, p4Contact(t), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoOperatorOwned)
}

func TestOpenEmbargoRefusesAnUnclassifiedOwnershipAndABadFinding(t *testing.T) {
	_, res := OpenEmbargo(Ownership{}, p4Finding, p4Contact(t), p4RunDay(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonOwnershipUnclassified)

	for _, bad := range []FindingID{"", "anvil 2026", "anvil/2026", FindingID(strings.Repeat("a", 129))} {
		_, res := OpenEmbargo(p4ThirdParty(t), bad, p4Contact(t), p4RunDay(t, 0))
		p4AssertRefused(t, res, Gate18Embargo, ReasonFindingUnidentified)
	}
}

func TestClassifyOwnershipTreatsAnUndeclaredRepositoryAsThirdParty(t *testing.T) {
	owned := p4Owned(t, p4OperatorRepo)
	for _, repo := range []string{p4VendorRepo, "someone/else", "operator/other-repo"} {
		own, res := ClassifyOwnership(repo, owned)
		p4AssertPassed(t, res, Gate18Embargo)
		if own.OperatorOwned() {
			t.Fatalf("%q classified as operator-owned; it is not on the declared list", repo)
		}
		if !own.ThirdParty() {
			t.Fatalf("%q is neither operator-owned nor third-party", repo)
		}
		if own.Owner() != FindingOwnershipThirdParty {
			t.Fatalf("%q classified as %q", repo, own.Owner())
		}
	}
}

func TestClassifyOwnershipRefusesAMalformedRepository(t *testing.T) {
	owned := p4Owned(t, p4OperatorRepo)
	for _, repo := range []string{"", "no-slash", "/name", "owner/", "owner/na me", "a/b/c"} {
		_, res := ClassifyOwnership(repo, owned)
		p4AssertRefused(t, res, Gate18Embargo, ReasonOwnershipRepositoryMalformed)
	}
}

func TestOwnedRepositoriesZeroValueOwnsNothing(t *testing.T) {
	var zero OwnedRepositories
	if zero.Constructed() {
		t.Fatalf("a zero OwnedRepositories reports Constructed()")
	}
	for _, repo := range []string{p4OperatorRepo, p4VendorRepo, ""} {
		if zero.Owns(repo) {
			t.Fatalf("a zero OwnedRepositories claims to own %q", repo)
		}
	}
	own, res := ClassifyOwnership(p4OperatorRepo, zero)
	p4AssertPassed(t, res, Gate18Embargo)
	if own.OperatorOwned() {
		t.Fatalf("a zero declaration made %q operator-owned", p4OperatorRepo)
	}

	// An empty declaration is legal and owns nothing either.
	empty := p4Owned(t)
	if empty.Owns(p4OperatorRepo) || empty.Count() != 0 {
		t.Fatalf("an empty declaration owns something")
	}
}

func TestOwnershipZeroValueIsThirdParty(t *testing.T) {
	var zero Ownership
	if zero.Classified() {
		t.Fatalf("a zero Ownership reports Classified()")
	}
	if zero.OperatorOwned() {
		t.Fatalf("a zero Ownership reports OperatorOwned(); the zero value must not publish")
	}
	if !zero.ThirdParty() {
		t.Fatalf("a zero Ownership is not third-party; an unclassified repo is not ours")
	}
	if zero.Owner() != FindingOwnershipUnset {
		t.Fatalf("a zero Ownership names owner %q", zero.Owner())
	}
}

// ===========================================================================
// GATE 19 — disclosure state lives in the record store, not the buffer
// ===========================================================================

// TestGate19RefusesTheTmpfsHandoffBuffer is the packet's data-location rule:
// tmpfs does not survive a reboot and an embargo that forgets itself is an
// embargo that publishes.
func TestGate19RefusesTheTmpfsHandoffBuffer(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	buffer := &p4Store{medium: MediumTmpfsHandoffBuffer}
	p4AssertRefused(t, checkGate19DisclosureStore(buffer),
		Gate19DisclosureStateInDB, ReasonDisclosureStoreWrongMedium)

	_, res = persistDisclosureState(buffer, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStoreWrongMedium)
	if len(buffer.rows) != 0 {
		t.Fatalf("gate 19 refused and the buffer still received %d rows", len(buffer.rows))
	}
	if !strings.Contains(res.Err().Error(), "tmpfs") {
		t.Fatalf("the refusal does not name the tmpfs buffer: %v", res.Err())
	}
}

func TestGate19RefusesEveryMediumButTheRecordStore(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	for _, medium := range []StorageMedium{
		MediumUnset,
		MediumTmpfsHandoffBuffer,
		MediumProcessMemory,
		"sqlite",
		"RECORD_STORE_SQLITE",
		"record_store",
	} {
		store := &p4Store{medium: medium}
		_, res := persistDisclosureState(store, rec)
		p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStoreWrongMedium)
	}
}

func TestGate19RefusesANilStore(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	p4AssertRefused(t, checkGate19DisclosureStore(nil),
		Gate19DisclosureStateInDB, ReasonDisclosureStoreMissing)
	_, res = persistDisclosureState(nil, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStoreMissing)
}

func TestGate19RefusesAFailedOrSilentWrite(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	failing := &p4Store{medium: MediumRecordStoreSQLite, err: errors.New("disk is full")}
	p, res := persistDisclosureState(failing, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureWriteFailed)
	if p.Valid() {
		t.Fatalf("a failed write produced a valid PersistedDisclosure")
	}

	silent := &p4Store{medium: MediumRecordStoreSQLite, silent: true}
	p, res = persistDisclosureState(silent, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureWriteFailed)
	if p.Valid() {
		t.Fatalf("a sequence-zero write produced a valid PersistedDisclosure")
	}
}

func TestGate19RefusesAnUnconstructedRecord(t *testing.T) {
	_, res := persistDisclosureState(p4RecordStore(), DisclosureRecord{})
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureRecordUnconstructed)
}

func TestNewDisclosureRecordRefusesBadInputs(t *testing.T) {
	emb := p4Embargo(t)
	key := p4Key(t)

	_, res := NewDisclosureRecord(EmbargoState{}, DisclosureStateEmbargoed, key)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonEmbargoUnconstructed)

	for _, state := range []DisclosureState{DisclosureStateUnset, "publish", "EMBARGOED", "open"} {
		_, res := NewDisclosureRecord(emb, state, key)
		p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStateUnknown)
	}

	_, res = NewDisclosureRecord(emb, DisclosureStateEmbargoed, AuditKey{})
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureKeyIncomplete)
}

func TestGate19PersistsToTheRecordStoreAndKeysTheRow(t *testing.T) {
	emb := p4Embargo(t)
	store := p4RecordStore()
	rec, res := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	p, res := persistDisclosureState(store, rec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	if !p.Valid() {
		t.Fatalf("a successful write produced no valid proof")
	}
	if p.Finding() != p4Finding || p.State() != DisclosureStateEmbargoed {
		t.Fatalf("proof names finding %q state %q", p.Finding(), p.State())
	}
	if p.Medium() != MediumRecordStoreSQLite || p.Seq() == 0 {
		t.Fatalf("proof medium %q seq %d", p.Medium(), p.Seq())
	}
	if len(store.rows) != 1 {
		t.Fatalf("%d rows written; want 1", len(store.rows))
	}
	row := store.rows[0]
	if row.AttestationID() != "attest-p4-001" || row.ScopeHash() != p4ScopeHash {
		t.Fatalf("row keyed to %q/%q", row.AttestationID(), row.ScopeHash())
	}
	if !row.Deadline().Equal(emb.Deadline()) || !row.FirstContact().Equal(emb.FirstContact()) {
		t.Fatalf("the row's clock disagrees with the embargo it describes")
	}
	if row.Ownership() != FindingOwnershipThirdParty || row.Repository() != p4VendorRepo {
		t.Fatalf("row ownership %q repo %q", row.Ownership(), row.Repository())
	}
}

// TestDisclosureRecordSerialisesToNothing is the structural half of gate 19.
// The tmpfs handoff packet is built by marshalling values; a DisclosureRecord
// with no exported fields marshals to `{}`, so a packet builder that embeds
// one carries no disclosure state off the durable store.
func TestDisclosureRecordSerialisesToNothing(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal(DisclosureRecord): %v", err)
	}
	if string(raw) != "{}" {
		t.Fatalf("a DisclosureRecord serialised to %s. Every field must stay unexported so "+
			"that a handoff packet embedding one carries no disclosure state into tmpfs",
			raw)
	}

	typ := reflect.TypeOf(DisclosureRecord{})
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.IsExported() {
			t.Fatalf("DisclosureRecord.%s is exported; gate 19 relies on the whole struct "+
				"being unreachable to encoding/json", f.Name)
		}
	}

	// Round-tripping through JSON produces a record that is not constructed,
	// which is the fail-closed direction: a disclosure state that arrived
	// through a serialised packet proves nothing.
	var back DisclosureRecord
	if err := json.Unmarshal([]byte(`{"finding":"anvil-2026-0001","state":"published"}`), &back); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if back.Constructed() || back.State() != DisclosureStateUnset {
		t.Fatalf("a DisclosureRecord decoded from JSON reports itself constructed")
	}
}

func TestPersistedDisclosureZeroValueProvesNothing(t *testing.T) {
	var zero PersistedDisclosure
	if zero.Valid() {
		t.Fatalf("a zero PersistedDisclosure reports Valid()")
	}
	if zero.Seq() != 0 || zero.Medium() != MediumUnset || zero.State() != DisclosureStateUnset {
		t.Fatalf("a zero PersistedDisclosure carries data")
	}
}

// ===========================================================================
// GATE 20 — no unsolicited fixes pushed to third parties
// ===========================================================================

// TestPushGateRefusesABenignPatchWithoutAnAttestation is D.7's third required
// validation: PushGate refuses without a valid attestation even when the patch
// content itself is benign. Gate 20 never sees patch content at all, which is
// what makes "but the patch is harmless" unexpressible rather than merely
// unpersuasive.
func TestPushGateRefusesABenignPatchWithoutAnAttestation(t *testing.T) {
	req := p4PushRequest(t)
	req.Attestation = Attestation{}
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes, ReasonPushWithoutAttestation)

	// The patch is a well-formed, identified, small proposal — and it makes no
	// difference.
	if !req.Patch.Constructed() || req.Patch.Bytes() != 812 {
		t.Fatalf("the fixture patch is not the benign identified patch this test needs")
	}
}

func TestPushGateRefusesAnAttestationBoundToAnotherScope(t *testing.T) {
	req := p4PushRequest(t)
	req.Attestation = p4Attestation(t, p4OtherHash)
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes,
		ReasonPushAttestationScopeUnbound)
}

func TestPushGateRefusesAnExpiredAttestation(t *testing.T) {
	req := p4PushRequest(t)
	// The fixture attestation expires on day 19; day 40 is well past it.
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 40)), Gate20NoUnsolicitedFixes,
		ReasonPushAttestationNotLive)

	// And a run before it was issued is equally not live.
	p4AssertRefused(t, pushGate(req, p4Run(t, p4AttIssued.Add(-24*time.Hour))),
		Gate20NoUnsolicitedFixes, ReasonPushAttestationNotLive)
}

func TestPushGateRefusesWithoutAnEmbargoAndThereforeWithoutAVendorContact(t *testing.T) {
	req := p4PushRequest(t)
	req.Embargo = EmbargoState{}
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes, ReasonPushNoEmbargoOpened)
}

func TestPushGateRefusesAnEmbargoForAnotherFinding(t *testing.T) {
	other, res := OpenEmbargo(p4ThirdParty(t), p4OtherFinding, p4Contact(t), p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)

	req := p4PushRequest(t)
	req.Embargo = other
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes, ReasonPushFindingMismatch)
}

func TestPushGateRefusesAnUnidentifiedPatchAndAnUnclassifiedDestination(t *testing.T) {
	req := p4PushRequest(t)
	req.Patch = PatchProposal{}
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes, ReasonPushPatchUnidentified)

	req = p4PushRequest(t)
	req.Destination = Ownership{}
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes, ReasonPushOwnershipUnclassified)

	req = p4PushRequest(t)
	p4AssertRefused(t, pushGate(req, RunClock{}), Gate20NoUnsolicitedFixes,
		ReasonPushClockUnconstructed)

	req = p4PushRequest(t)
	req.Scope = Scope{}
	p4AssertRefused(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes, ReasonPushScopeUnconstructed)
}

func TestPushGateZeroRequestRefuses(t *testing.T) {
	p4AssertRefused(t, pushGate(PushRequest{}, p4RunDay(t, 0)),
		Gate20NoUnsolicitedFixes, ReasonPushPatchUnidentified)
}

// TestPushGatePermitsDeliveryToTheOperatorsOwnRepository pins what the
// operator-owned branch may skip: the EMBARGO and the vendor contact, which
// are meaningless for your own repository.
func TestPushGatePermitsDeliveryToTheOperatorsOwnRepository(t *testing.T) {
	res := pushGate(PushRequest{
		Finding:     p4Finding,
		Destination: p4OperatorOwned(t),
		Attestation: p4Attestation(t, p4ScopeHash),
		Scope:       p4Scope(t),
		Patch:       p4Patch(t),
		// No Embargo. Gate 20 is about repositories the operator does NOT
		// control, and there is no vendor to have contacted about your own.
	}, p4RunDay(t, 0))
	p4AssertPassed(t, res, Gate20NoUnsolicitedFixes)
}

// TestPushGateOwnershipIsAClaimAndCannotAlsoDeleteTheAttestation is the guard
// on the bypass that the operator-owned branch used to be.
//
// Ownership is a SELF-ASSERTION: NewOwnedRepositories takes "owner/name"
// strings from the caller and nothing in this package checks them against a
// forge. While the branch sat above the scope and attestation checks, naming
// the VICTIM's repository as one's own was enough to push a patch to it with a
// zero Attestation, a zero Scope and a zero EmbargoState — gate 20 bypassed by
// asserting that the third party is you.
//
// The literal probe that produced the finding is the first block below.
func TestPushGateOwnershipIsAClaimAndCannotAlsoDeleteTheAttestation(t *testing.T) {
	// Claim the vendor's repository. ClassifyOwnership believes it, because
	// believing the operator's declaration is the whole of its job.
	claimed, res := ClassifyOwnership(p4VendorRepo, p4Owned(t, p4VendorRepo))
	p4AssertPassed(t, res, Gate18Embargo)
	if !claimed.OperatorOwned() {
		t.Fatalf("the claim did not take; this test would prove nothing")
	}

	// The exact bypass: zero Attestation, zero Scope, zero EmbargoState.
	bypass := PushRequest{
		Finding:     p4Finding,
		Destination: claimed,
		Patch:       p4Patch(t),
	}
	p4AssertRefused(t, pushGate(bypass, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes,
		ReasonPushScopeUnconstructed)

	// With a scope but still no attestation, it is the attestation that
	// refuses — so the scope check above is not the only thing standing here.
	bypass.Scope = p4Scope(t)
	p4AssertRefused(t, pushGate(bypass, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes,
		ReasonPushWithoutAttestation)

	// An attestation for some other engagement does not authorise it either.
	bypass.Attestation = p4Attestation(t, p4OtherHash)
	p4AssertRefused(t, pushGate(bypass, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes,
		ReasonPushAttestationScopeUnbound)

	// And an expired one is not an authorisation.
	bypass.Attestation = p4Attestation(t, p4ScopeHash)
	p4AssertRefused(t, pushGate(bypass, p4RunDay(t, 40)), Gate20NoUnsolicitedFixes,
		ReasonPushAttestationNotLive)

	// What the claim IS still worth: a live attestation and no embargo is
	// enough for a destination the operator says is theirs, and is not enough
	// for one they do not.
	p4AssertPassed(t, pushGate(bypass, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes)

	disclaimed := bypass
	disclaimed.Destination = p4ThirdParty(t)
	p4AssertRefused(t, pushGate(disclaimed, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes,
		ReasonPushNoEmbargoOpened)
}

func TestPushGatePermitsAnAttestedThirdPartyDelivery(t *testing.T) {
	p4AssertPassed(t, pushGate(p4PushRequest(t), p4RunDay(t, 0)), Gate20NoUnsolicitedFixes)
}

// TestPushGateDoesNotRequireTheEmbargoToHaveElapsed records the deliberate
// choice in PushGate's doc comment: delivering the fix to the vendor is the
// coordinated half of coordinated disclosure, and requiring the clock to run
// out first would forbid the thing the clock exists to make room for.
func TestPushGateDoesNotRequireTheEmbargoToHaveElapsed(t *testing.T) {
	req := p4PushRequest(t)
	if req.Embargo.Elapsed(p4RunDay(t, 0).Now()) {
		t.Fatalf("the fixture embargo has already elapsed; this test proves nothing")
	}
	p4AssertPassed(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes)
}

func TestNewPatchProposalRefusesABadDigestOrSize(t *testing.T) {
	for name, digest := range map[string]string{
		"empty":     "",
		"short":     "0f0f",
		"uppercase": strings.ToUpper(p4PatchDigest),
		"non hex":   strings.Repeat("g", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPatchProposal(digest, 812); err == nil {
				t.Fatalf("NewPatchProposal accepted digest %q", digest)
			} else if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not unwrap to ErrRefused: %v", err)
			}
		})
	}
	for _, size := range []int{0, -1} {
		if _, err := NewPatchProposal(p4PatchDigest, size); err == nil {
			t.Fatalf("NewPatchProposal accepted a patch of %d bytes", size)
		}
	}
	var zero PatchProposal
	if zero.Constructed() {
		t.Fatalf("a zero PatchProposal reports Constructed()")
	}
}

// ===========================================================================
// GATE 21 — the immutable audit of every gate decision
// ===========================================================================

func TestNewAuditKeyRefusesAnAttestationNotBoundToTheScope(t *testing.T) {
	_, res := NewAuditKey(p4Attestation(t, p4OtherHash), p4Scope(t))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonScopeAttestationMismatch)
}

func TestNewAuditKeyRefusesZeroValues(t *testing.T) {
	_, res := NewAuditKey(Attestation{}, p4Scope(t))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAttestationUnconstructed)

	_, res = NewAuditKey(p4Attestation(t, p4ScopeHash), Scope{})
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonScopeUnconstructed)

	var zero AuditKey
	if zero.Valid() {
		t.Fatalf("a zero AuditKey reports Valid()")
	}
	if _, res := NewGateAudit(&recordingSink{}, zero, p4RunDay(t, 0)); res.Passed() {
		t.Fatalf("NewGateAudit accepted a zero AuditKey")
	}
}

func TestGateAuditKeysEveryRowToTheAttestationAndScopeHash(t *testing.T) {
	sink := &recordingSink{}
	audit := p4Audit(t, sink)

	target := p4Target(t)
	for _, res := range []GateResult{
		gatePassed(Gate16CircuitBreaker),
		gateFailed(Gate13RevalidateEveryRequest, ReasonCrossHostRedirect, "cross-host hop"),
	} {
		if _, out := audit.Record(res, SubjectTarget(target), p4Day(t, 0)); out.Passed() != res.Passed() {
			t.Fatalf("Record changed the outcome of a decision whose write succeeded")
		}
	}
	if len(sink.rows) != 2 {
		t.Fatalf("%d rows written; want 2", len(sink.rows))
	}
	for i, row := range sink.rows {
		if row.AttestationID != "attest-p4-001" {
			t.Fatalf("row %d keyed to attestation %q", i, row.AttestationID)
		}
		if row.ScopeHash != p4ScopeHash {
			t.Fatalf("row %d keyed to scope hash %q", i, row.ScopeHash)
		}
		if row.Mode != ModeExternal {
			t.Fatalf("row %d carries mode %q", i, row.Mode)
		}
		if row.Target != target.String() {
			t.Fatalf("row %d names target %q", i, row.Target)
		}
		if err := row.Validate(); err != nil {
			t.Fatalf("row %d is not a well-formed audit row: %v", i, err)
		}
	}
	if sink.rows[0].Outcome != OutcomeAllow || sink.rows[1].Outcome != OutcomeDeny {
		t.Fatalf("the allow and the deny were not recorded as such")
	}
	if audit.Rows() != 2 || audit.LastSeq() != 2 {
		t.Fatalf("writer reports %d rows, last seq %d", audit.Rows(), audit.LastSeq())
	}
}

// TestGateAuditRefusesWhenThePairedWriteFails is gate 21 as a sentence: "a
// gate decision is not 'allowed' if its paired audit write fails."
func TestGateAuditRefusesWhenThePairedWriteFails(t *testing.T) {
	for name, sink := range map[string]AuditSink{
		"write error":           failingSink{err: errors.New("the disk went away")},
		"silent stub":           silentSink{},
		"rewound log":           &p4RewindSink{},
		"no advance":            &p4RewindSink{},
		"nothing wrote":         failingSink{err: errors.New("no such table")},
		"row id then no commit": &p4CommittedThenFailedSink{err: errors.New("commit failed")},
	} {
		t.Run(name, func(t *testing.T) {
			audit := p4Audit(t, sink)
			allow := gatePassed(Gate14HardCaps)

			// The first write on the rewind sink succeeds; the second does
			// not advance. Write twice so both sink shapes reach a refusal.
			_, first := audit.Record(allow, SubjectTarget(p4Target(t)), p4Day(t, 0))
			_, second := audit.Record(allow, SubjectTarget(p4Target(t)), p4Day(t, 0))

			if first.Passed() && second.Passed() {
				t.Fatalf("a passing gate decision survived a sink that never durably "+
					"advanced (%s)", name)
			}
			worst := first
			if worst.Passed() {
				worst = second
			}
			if worst.Gate() != Gate21ImmutableAudit {
				t.Fatalf("the refusal is attributed to %s; want gate 21", worst.Gate())
			}
			if !errors.Is(worst.Err(), ErrRefused) {
				t.Fatalf("the refusal does not unwrap to ErrRefused: %v", worst.Err())
			}
		})
	}
}

func TestGateAuditRefusesASequenceThatDoesNotAdvance(t *testing.T) {
	sink := &p4RewindSink{}
	audit := p4Audit(t, sink)

	_, first := audit.Record(gatePassed(Gate14HardCaps), SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertPassed(t, first, Gate14HardCaps)

	_, second := audit.Record(gatePassed(Gate14HardCaps), SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, second, Gate21ImmutableAudit, ReasonAuditNotAppendOnly)

	if audit.Rows() != 1 {
		t.Fatalf("the writer counted %d durable rows; the second write did not advance",
			audit.Rows())
	}
}

func TestGateAuditRefusesAnUnattributableDecision(t *testing.T) {
	audit := p4Audit(t, &recordingSink{})

	// Gate 10 has TWO pass tokens with different meanings, so it is
	// deliberately absent from the pass-token maps. A passing gate 10
	// GateResult is refused rather than recorded under a token that would say
	// something false.
	_, res := audit.Record(gatePassed(Gate10ReservedRanges), SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditRowUnattributable)

	// A GateResult nobody minted has no gate and no failure.
	_, res = audit.Record(GateResult{}, SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditRowUnattributable)
}

func TestGateAuditRefusesAnUnsetClockAndAnEmptySubject(t *testing.T) {
	audit := p4Audit(t, &recordingSink{})

	_, res := audit.Record(gatePassed(Gate14HardCaps), SubjectTarget(p4Target(t)), Clock{})
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditClockUnconstructed)

	_, res = audit.Record(gatePassed(Gate14HardCaps), AuditSubject{}, p4Day(t, 0))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditKeyIncomplete)
}

func TestGateAuditZeroValueRecordsNothing(t *testing.T) {
	var zero *GateAudit
	if zero.Constructed() {
		t.Fatalf("a nil GateAudit reports Constructed()")
	}
	_, res := zero.Record(gatePassed(Gate14HardCaps), SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditSinkMissing)

	res = zero.RecordTrace([]GateResult{gatePassed(Gate14HardCaps)},
		SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditSinkMissing)

	if _, res := NewGateAudit(nil, p4Key(t), p4RunDay(t, 0)); res.Passed() {
		t.Fatalf("NewGateAudit accepted a nil sink")
	} else {
		p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditSinkMissing)
	}

	// A writer with no RUN behind it is refused before either of those. Gates
	// 18 and 20 read their "now" from this field, so a zero RunClock here
	// would put every Phase 4 comparison in 1970.
	if _, res := NewGateAudit(&recordingSink{}, p4Key(t), RunClock{}); res.Passed() {
		t.Fatalf("NewGateAudit accepted a zero RunClock")
	} else {
		p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditClockUnconstructed)
	}
}

func TestRecordTraceWritesOneRowPerGateAndRefusesAnEmptyTrace(t *testing.T) {
	sink := &recordingSink{}
	audit := p4Audit(t, sink)

	trace := []GateResult{
		gatePassed(Gate16CircuitBreaker),
		gatePassed(Gate17RetryAfter),
		gatePassed(Gate13RevalidateEveryRequest),
		gateFailed(Gate15DestructiveTechniques, ReasonTechniqueDestructive, "denylisted"),
	}
	res := audit.RecordTrace(trace, SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, res, Gate15DestructiveTechniques, ReasonTechniqueDestructive)

	if len(sink.rows) != 4 {
		t.Fatalf("%d rows written for a 4-gate trace; gate 21 wants one per gate decision, "+
			"not one per adjudication", len(sink.rows))
	}
	want := []GateID{Gate16CircuitBreaker, Gate17RetryAfter,
		Gate13RevalidateEveryRequest, Gate15DestructiveTechniques}
	for i, g := range want {
		if sink.rows[i].Gate != g {
			t.Fatalf("row %d names %s; want %s", i, sink.rows[i].Gate, g)
		}
	}

	p4AssertRefused(t, audit.RecordTrace(nil, SubjectTarget(p4Target(t)), p4Day(t, 0)),
		Gate21ImmutableAudit, ReasonAuditTraceEmpty)
}

// ---------------------------------------------------------------------------
// The per-request coupling
// ---------------------------------------------------------------------------

func p4Target(t *testing.T) Target {
	t.Helper()
	return p3Target(t, SchemeHTTPS, "target.example.com", 443, p4TargetAddr)
}

func p4Governor(t *testing.T) *Governor {
	t.Helper()
	allow, err := NewEndpointAllowance()
	if err != nil {
		t.Fatalf("NewEndpointAllowance: %v", err)
	}
	target := p4Target(t)
	g, res := NewGovernor(GovernorConfig{
		Target:      target,
		Scope:       p4Scope(t),
		Attestation: p4Attestation(t, p4ScopeHash),
		Caps:        CodedCaps(),
		Thresholds:  CodedHealthThresholds(),
		Robots:      RobotsNotFound(target.Canonical(), target.Port()),
		Allowance:   allow,
		Start:       p4Sec(t, 0),
	})
	p4AssertPassed(t, res, Gate13RevalidateEveryRequest)
	return g
}

func p4Intent(t *testing.T, origin RequestOrigin, next Target, hop int) RequestIntent {
	t.Helper()
	i, err := NewRequestIntent(RequestFacts{
		Origin:   origin,
		Admitted: p4Target(t),
		Next:     next,
		Method:   MethodGet,
		Path:     "/",
		Hop:      hop,
	})
	if err != nil {
		t.Fatalf("NewRequestIntent: %v", err)
	}
	return i
}

func TestAuditedAdmitWritesARowForEveryGateInTheTrace(t *testing.T) {
	sink := &recordingSink{}
	audit := p4Audit(t, sink)
	gov := p4Governor(t)

	lease, res := audit.AuditedAdmit(gov, p4Intent(t, OriginInitial, p4Target(t), 0),
		TechniqueVersionFingerprint, p4Sec(t, 1))
	if !res.Passed() {
		t.Fatalf("the request was refused: %v", res.Err())
	}
	if !lease.Held() {
		t.Fatalf("an admitted request holds no lease")
	}
	lease.Release()

	if len(sink.rows) != len(GovernorGateOrder()) {
		t.Fatalf("%d rows for %d gates; gate 21 wants one per gate decision",
			len(sink.rows), len(GovernorGateOrder()))
	}
	for i, g := range GovernorGateOrder() {
		if sink.rows[i].Gate != g {
			t.Fatalf("row %d names %s; want %s", i, sink.rows[i].Gate, g)
		}
		if sink.rows[i].Outcome != OutcomeAllow {
			t.Fatalf("row %d for an admitted request is %q", i, sink.rows[i].Outcome)
		}
	}
}

// TestAuditedAdmitReleasesTheLeaseWhenTheWriteFails is the load-bearing test
// for D.7's second required validation: an audit-log write failure causes the
// paired gate decision to fail closed, not silently allow.
func TestAuditedAdmitReleasesTheLeaseWhenTheWriteFails(t *testing.T) {
	// Both failure shapes, because they exercise DIFFERENT branches of
	// Record: a (0, err) sink is refused by the error branch and by the
	// sequence-zero branch alike, while a (9, err) sink can only be refused by
	// the error branch. Testing one alone leaves the other deletable, which a
	// mutation run demonstrated.
	for name, sink := range map[string]AuditSink{
		"no row at all":         failingSink{err: errors.New("the audit table is gone")},
		"row id then no commit": &p4CommittedThenFailedSink{err: errors.New("commit failed")},
		"silent stub":           silentSink{},
	} {
		t.Run(name, func(t *testing.T) {
			audit := p4Audit(t, sink)
			gov := p4Governor(t)

			lease, res := audit.AuditedAdmit(gov, p4Intent(t, OriginInitial, p4Target(t), 0),
				TechniqueVersionFingerprint, p4Sec(t, 1))

			if res.Passed() {
				t.Fatalf("the request was ADMITTED with no audit row behind it")
			}
			if res.Gate() != Gate21ImmutableAudit {
				t.Fatalf("the refusal is attributed to %s; want gate 21", res.Gate())
			}
			if lease.Held() {
				t.Fatalf("the caller holds a concurrency lease for a request that was " +
					"not audited; it will issue the request")
			}
			if n := gov.Limiter().InFlight(); n != 0 {
				t.Fatalf("%d slots still in flight after a refused admission; the "+
					"semaphore drifts", n)
			}
			if !errors.Is(res.Err(), ErrRefused) {
				t.Fatalf("the refusal does not unwrap to ErrRefused: %v", res.Err())
			}
		})
	}
}

func TestAuditedAdmitRecordsARedirectRefusal(t *testing.T) {
	sink := &recordingSink{}
	audit := p4Audit(t, sink)
	gov := p4Governor(t)

	elsewhere := p3Target(t, SchemeHTTPS, "evil.example.net", 443, p4OtherAddr)
	lease, res := audit.AuditedAdmit(gov, p4Intent(t, OriginRedirect, elsewhere, 1),
		TechniqueVersionFingerprint, p4Sec(t, 1))

	if res.Passed() {
		t.Fatalf("a cross-host redirect was admitted")
	}
	if lease.Held() {
		t.Fatalf("a refused redirect holds a lease")
	}
	if res.Gate() != Gate13RevalidateEveryRequest {
		t.Fatalf("the refusal is attributed to %s; want gate 13", res.Gate())
	}

	var found bool
	for _, row := range sink.rows {
		if row.Gate == Gate13RevalidateEveryRequest && row.Outcome == OutcomeDeny {
			found = true
			if row.AttestationID == "" || row.ScopeHash == "" {
				t.Fatalf("the redirect refusal was recorded unkeyed")
			}
		}
	}
	if !found {
		t.Fatalf("gate 21 requires every redirect refusal to be logged; %d rows written and "+
			"none is a gate 13 denial", len(sink.rows))
	}
}

func TestAuditedObservationRecordsACircuitBreakerTrip(t *testing.T) {
	sink := &recordingSink{}
	audit := p4Audit(t, sink)
	gov := p4Governor(t)

	var trip GateResult
	for i := 0; i < 40; i++ {
		res := gov.Health().ObserveResponse(500, 50*time.Millisecond, p4Sec(t, i+1))
		if !res.Passed() {
			trip = res
			break
		}
	}
	if trip.Passed() || trip.Gate() != Gate16CircuitBreaker {
		t.Fatalf("the breaker never tripped on 40 consecutive 500s; this test proves nothing")
	}

	out := audit.AuditedObservation(trip, p4Target(t), p4Sec(t, 60))
	if out.Passed() {
		t.Fatalf("a recorded breaker trip came back as an allow")
	}
	if len(sink.rows) != 1 || sink.rows[0].Gate != Gate16CircuitBreaker ||
		sink.rows[0].Outcome != OutcomeDeny {
		t.Fatalf("gate 21 requires every circuit-breaker trip to be logged; rows: %+v",
			sink.rows)
	}
	if sink.rows[0].AttestationID != "attest-p4-001" || sink.rows[0].ScopeHash != p4ScopeHash {
		t.Fatalf("the trip was recorded unkeyed")
	}
}

// ---------------------------------------------------------------------------
// The Phase 4 couplings
// ---------------------------------------------------------------------------

func TestAuditedPublicationRefusesWhenTheAuditWriteFails(t *testing.T) {
	emb := p4Embargo(t)
	req, store := p4PublishRequest(t, emb)

	// The gate itself permits: the clock has run out and the state is
	// persisted.
	p4AssertPassed(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo)

	audit := p4AuditAt(t, failingSink{err: errors.New("audit table is read-only")},
		p4RunDay(t, 60))
	out := audit.AuditedPublication(store, req)
	if out.Passed() {
		t.Fatalf("a finding was cleared for publication with no audit row behind it")
	}
	if out.Gate() != Gate21ImmutableAudit {
		t.Fatalf("the refusal is attributed to %s; want gate 21", out.Gate())
	}

	// And with a working sink it permits, and the row names the finding.
	sink := &recordingSink{}
	audit = p4AuditAt(t, sink, p4RunDay(t, 60))
	out = audit.AuditedPublication(store, req)
	p4AssertPassed(t, out, Gate18Embargo)
	if len(sink.rows) != 1 || sink.rows[0].Target != "finding "+string(p4Finding) {
		t.Fatalf("the publication row does not name the finding: %+v", sink.rows)
	}
	if sink.rows[0].Reason != ReasonPublicationPermitted {
		t.Fatalf("the allow row carries reason %q", sink.rows[0].Reason)
	}
}

func TestAuditedPushRefusesWhenTheAuditWriteFails(t *testing.T) {
	req := p4PushRequest(t)
	p4AssertPassed(t, pushGate(req, p4RunDay(t, 0)), Gate20NoUnsolicitedFixes)

	audit := p4Audit(t, failingSink{err: errors.New("audit table is read-only")})
	out := audit.AuditedPush(req)
	if out.Passed() {
		t.Fatalf("a patch was cleared for delivery with no audit row behind it")
	}
	if out.Gate() != Gate21ImmutableAudit {
		t.Fatalf("the refusal is attributed to %s; want gate 21", out.Gate())
	}

	sink := &recordingSink{}
	audit = p4Audit(t, sink)
	p4AssertPassed(t, audit.AuditedPush(req), Gate20NoUnsolicitedFixes)
	if len(sink.rows) != 1 || sink.rows[0].Target != "repository "+p4VendorRepo {
		t.Fatalf("the push row does not name the destination: %+v", sink.rows)
	}
}

func TestAuditedPersistDisclosureWithholdsTheProofWhenTheAuditWriteFails(t *testing.T) {
	emb := p4Embargo(t)
	rec, res := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	store := p4RecordStore()
	audit := p4Audit(t, failingSink{err: errors.New("audit table is read-only")})

	p, out := audit.AuditedPersistDisclosure(store, rec)
	if out.Passed() {
		t.Fatalf("the persist was reported as allowed with no audit row behind it")
	}
	if p.Valid() {
		t.Fatalf("an unaudited persist handed back gate 18's publication proof")
	}

	// The proof is what gate 18 requires, so an unaudited persist cannot
	// publish.
	req := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: p,
	}
	p4AssertRefused(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo,
		ReasonPublicationStateNotPersisted)

	// With a working audit sink the proof is minted and publication clears.
	audit = p4Audit(t, &recordingSink{})
	p, out = audit.AuditedPersistDisclosure(store, rec)
	p4AssertPassed(t, out, Gate19DisclosureStateInDB)
	req.Persisted = p
	p4AssertPassed(t, checkGate18Publication(req, p4RunDay(t, 60), store), Gate18Embargo)
}

// ---------------------------------------------------------------------------
// Structural guards
// ---------------------------------------------------------------------------

// TestPhase4GatesCannotBeRegisteredIntoAChain locks D.2's refusal in place. If
// somebody adds `register(Gate18Embargo, ...)` to phase4_disclosure.go, the
// package panics at init in every test binary that links it — but only because
// registerInto still refuses Phase 4, and this is what fails if that refusal is
// ever relaxed.
func TestPhase4GatesCannotBeRegisteredIntoAChain(t *testing.T) {
	noop := func(Target, Scope, Attestation, Clock) Ruling {
		return permit(Gate18Embargo, ReasonPublicationPermitted, "")
	}
	for _, g := range []GateID{
		Gate18Embargo, Gate19DisclosureStateInDB,
		Gate20NoUnsolicitedFixes, Gate21ImmutableAudit,
	} {
		m := map[GateID]gateFunc{}
		err := registerInto(m, g, noop)
		if err == nil {
			t.Fatalf("%s was accepted as a per-target gate implementation", g)
		}
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: the refusal does not unwrap to ErrRefused: %v", g, err)
		}
		if len(m) != 0 {
			t.Fatalf("%s: the registry was mutated by a refused registration", g)
		}
	}
	// The compiled-in chains must not name a Phase 4 gate either.
	for _, ch := range [][]GateID{admissionChain, revalidationChain} {
		for _, g := range ch {
			if g.Phase() == 4 {
				t.Fatalf("%s is a Phase 4 gate and appears in a per-target chain", g)
			}
		}
	}
}

// TestPhase4PassTokensAreValidAndNameTheirOwnGate is the guard against a pass
// token that would make GateRecord.Validate refuse every allow row for a gate.
func TestPhase4PassTokensAreValidAndNameTheirOwnGate(t *testing.T) {
	for _, m := range []map[GateID]Reason{phase4PassReasons, phase1PassReasons} {
		for gate, reason := range m {
			named, err := reason.Gate()
			if err != nil {
				t.Fatalf("%s: pass token %q is not a valid reason: %v", gate, reason, err)
			}
			if named != gate {
				t.Fatalf("%s: pass token %q names %s", gate, reason, named)
			}
		}
	}
	// Every Phase 4 gate has one, because every Phase 4 gate can permit.
	for _, g := range []GateID{
		Gate18Embargo, Gate19DisclosureStateInDB,
		Gate20NoUnsolicitedFixes, Gate21ImmutableAudit,
	} {
		if _, ok := phase4PassReasons[g]; !ok {
			t.Fatalf("%s can permit and has no audit pass token, so its allow rows cannot "+
				"be written", g)
		}
	}
}

// TestPhase4ZeroValuesRefuse is the file-wide survey of the one rule
// types.go states: the zero value of every type here means refuse.
func TestPhase4ZeroValuesRefuse(t *testing.T) {
	checks := map[string]func() bool{
		"Ownership{}.Classified":            func() bool { return Ownership{}.Classified() },
		"Ownership{}.OperatorOwned":         func() bool { return Ownership{}.OperatorOwned() },
		"OwnedRepositories{}.Constructed":   func() bool { return OwnedRepositories{}.Constructed() },
		"VendorContact{}.Recorded":          func() bool { return VendorContact{}.Recorded() },
		"EmbargoState{}.Constructed":        func() bool { return EmbargoState{}.Constructed() },
		"EmbargoState{}.Elapsed":            func() bool { return EmbargoState{}.Elapsed(p4Day(t, 999)) },
		"DisclosureRecord{}.Constructed":    func() bool { return DisclosureRecord{}.Constructed() },
		"PersistedDisclosure{}.Valid":       func() bool { return PersistedDisclosure{}.Valid() },
		"PatchProposal{}.Constructed":       func() bool { return PatchProposal{}.Constructed() },
		"AuditKey{}.Valid":                  func() bool { return AuditKey{}.Valid() },
		"AuditSubject{}.Constructed":        func() bool { return AuditSubject{}.Constructed() },
		"FindingOwnershipUnset.Valid":       func() bool { return FindingOwnershipUnset.Valid() },
		"DisclosureStateUnset.Valid":        func() bool { return DisclosureStateUnset.Valid() },
		"EmbargoAccelerationUnset.Valid":    func() bool { return EmbargoAccelerationUnset.Valid() },
		"EmbargoExtensionUnset.Valid":       func() bool { return EmbargoExtensionUnset.Valid() },
		"FindingID(\"\").Validate() == nil": func() bool { return FindingID("").Validate() == nil },
	}
	for name, fn := range checks {
		if fn() {
			t.Errorf("%s reported true; the zero value of every type in this file must refuse",
				name)
		}
	}
}

// TestAuditSubjectCarriesNoFreeText asserts that every constructor builds its
// text from already-validated components, so no bytes from a scanned target
// can reach GateRecord.Target through this path.
func TestAuditSubjectCarriesNoFreeText(t *testing.T) {
	for _, bad := range []FindingID{"", "finding with spaces", "a\nb", "../../etc/passwd"} {
		if _, err := SubjectFinding(bad); err == nil {
			t.Fatalf("SubjectFinding accepted %q", bad)
		}
	}
	for _, bad := range []string{"", "no-slash", "owner/na me", "owner/name\nInjected: yes"} {
		if _, err := SubjectRepository(bad); err == nil {
			t.Fatalf("SubjectRepository accepted %q", bad)
		}
	}
	s, err := SubjectFinding(p4Finding)
	if err != nil {
		t.Fatalf("SubjectFinding(%q): %v", p4Finding, err)
	}
	if s.String() != "finding "+string(p4Finding) {
		t.Fatalf("subject renders as %q", s.String())
	}
	// An unconstructed Target still produces a nameable, Anvil-authored row.
	if got := SubjectTarget(Target{}).String(); !strings.Contains(got, "unconstructed") {
		t.Fatalf("an unconstructed target renders as %q", got)
	}
}

func TestBoundedEvidenceIsAnAllowlist(t *testing.T) {
	ok, err := boundedEvidence("  seen in the wild, ref CVE-2026-0001 (vendor ticket 44)  ")
	if err != nil {
		t.Fatalf("boundedEvidence refused printable ASCII: %v", err)
	}
	if strings.HasPrefix(ok, " ") || strings.HasSuffix(ok, " ") {
		t.Fatalf("boundedEvidence did not trim: %q", ok)
	}
	for _, bad := range []string{"", "   ", "a\tb", "a\nb", "a\x1bb", "café",
		strings.Repeat("x", maxEmbargoEvidenceLen+1)} {
		if _, err := boundedEvidence(bad); err == nil {
			t.Fatalf("boundedEvidence accepted %q", bad)
		}
	}
}

func TestValidateSHA256HexIsStrict(t *testing.T) {
	if err := validateSHA256Hex(p4PatchDigest, "patch digest"); err != nil {
		t.Fatalf("a well-formed digest was refused: %v", err)
	}
	for _, bad := range []string{"", "0f", strings.ToUpper(p4PatchDigest),
		p4PatchDigest + "0", strings.Repeat("z", 64)} {
		if err := validateSHA256Hex(bad, "patch digest"); err == nil {
			t.Fatalf("validateSHA256Hex accepted %q", bad)
		}
	}
}

// TestGate19RefusalNamesTheMediumItWasOffered keeps the operator-facing
// message honest: a refusal that says only "not the record store" leaves the
// reader guessing what they passed.
func TestGate19RefusalNamesTheMediumItWasOffered(t *testing.T) {
	for medium, want := range map[StorageMedium]string{
		MediumTmpfsHandoffBuffer: "tmpfs",
		MediumProcessMemory:      "only for this process",
		MediumUnset:              "declared no medium",
	} {
		res := checkGate19DisclosureStore(&p4Store{medium: medium})
		p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStoreWrongMedium)
		if !strings.Contains(res.Err().Error(), want) {
			t.Fatalf("the refusal for %q does not mention %q: %v", medium, want, res.Err())
		}
	}
}

// TestGateRecordsFromPhase4AreWellFormed drives one row of every Phase 4 gate
// through GateRecord.Validate, which is what the SQLite writer will do.
func TestGateRecordsFromPhase4AreWellFormed(t *testing.T) {
	sink := &recordingSink{}
	audit := p4Audit(t, sink)
	emb := p4Embargo(t)

	pub, pubStore := p4PublishRequest(t, emb)
	audit.AuditedPublication(pubStore, pub)
	audit.AuditedPush(p4PushRequest(t))
	rec, _ := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	audit.AuditedPersistDisclosure(p4RecordStore(), rec)

	if len(sink.rows) != 3 {
		t.Fatalf("%d rows; want one per Phase 4 decision", len(sink.rows))
	}
	seen := map[GateID]bool{}
	for i, row := range sink.rows {
		if err := row.Validate(); err != nil {
			t.Fatalf("row %d is not writable: %v", i, err)
		}
		seen[row.Gate] = true
		if row.Detail == "" {
			t.Fatalf("row %d carries no detail", i)
		}
	}
	for _, g := range []GateID{Gate18Embargo, Gate20NoUnsolicitedFixes, Gate19DisclosureStateInDB} {
		if !seen[g] {
			t.Fatalf("no row for %s", g)
		}
	}
}

// TestPhase4DecisionInputsCarryNoResponseBytes is a small shape guard: nothing
// in this file takes an http.Header, an io.Reader or any other extension
// point through which a scanned response body could arrive at a disclosure
// decision.
//
// This comment used to open "TestHTTPHeaderTypeIsNotReachableFromPhase4",
// which is not the name of anything in the tree — a grep for it returns only
// the comment itself. A reviewer looking for the named control does not find
// it and concludes the control is missing.
func TestPhase4DecisionInputsCarryNoResponseBytes(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(PublicationRequest{}),
		reflect.TypeOf(PushRequest{}),
		reflect.TypeOf(DisclosureRecord{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			switch f.Type.Kind() {
			case reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer:
				t.Fatalf("%s.%s is a %s, which is an extension point a response body could "+
					"arrive through", typ.Name(), f.Name, f.Type.Kind())
			}
			if f.Type == reflect.TypeOf(http.Header{}) {
				t.Fatalf("%s.%s is an http.Header", typ.Name(), f.Name)
			}
			if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
				t.Fatalf("%s.%s is a byte slice", typ.Name(), f.Name)
			}
		}
	}
	// A sanity check that the survey above is looking at real types rather
	// than passing because it walked nothing.
	if reflect.TypeOf(PushRequest{}).NumField() < 5 {
		t.Fatalf("PushRequest has fewer fields than expected; the survey may be vacuous")
	}
}

// ===========================================================================
// THE CLOCK-ORIGIN BOUNDS — gate 18's other embargo knob
// ===========================================================================

// TestGate18TheEmbargoCannotBeDrivenToZeroByBackDating runs the exact sequence
// that defeated gate 18 before RecordVendorContact and OpenEmbargo read the
// RUN'S clock rather than accepting one.
//
// The defence this file used to state — "there is NO FUNCTION IN THIS FILE
// THAT TAKES AN EMBARGO DURATION" — was true and beside the point. Accelerate
// is genuinely airtight: allowlisted to one reason, evidence-bounded, floored.
// The deadline was moved instead through the ORIGIN OF THE CLOCK, which was
// simply whatever the caller passed, and the result was an elapsed embargo
// with ZERO recorded adjustments.
//
// Every instant below is hand-written. Nothing here is derived from a constant
// in the implementation, so the assertions cannot agree with a bug in it.
func TestGate18TheEmbargoCannotBeDrivenToZeroByBackDating(t *testing.T) {
	january := p4Clock(t, time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC))
	august := p4Clock(t, time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC))
	januaryRun := p4Run(t, january.Instant())
	augustRun := p4Run(t, august.Instant())

	// (1) The reported attack. A run in August records first contact as
	// January, which would make the 45-day deadline 15 February and therefore
	// already elapsed. The contact never forms.
	_, res := RecordVendorContact(p4Channel(t), january, augustRun)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoContactBackdated)

	// (2) The same lie told consistently, WITHIN one run: a January contact
	// recorded against a January run clock is a legitimate VendorContact, and
	// the embargo opens — with a February deadline that has not passed yet at
	// the January clock. What the run cannot then do is publish, because a run
	// has one clock and it is still January. See
	// TestGate18TheConsistentClockLieIsRefusedInBothDirections.
	contact, res := RecordVendorContact(p4Channel(t), january, januaryRun)
	p4AssertPassed(t, res, Gate18Embargo)

	// (3) Opening that January embargo from an AUGUST run fails, because the
	// deadline it would carry is already in the past. An embargo that was over
	// before anybody opened it is not one.
	emb, res := OpenEmbargo(p4ThirdParty(t), p4Finding, contact, augustRun)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoElapsedBeforeItOpened)
	if emb.Constructed() {
		t.Fatalf("a refused OpenEmbargo handed back a constructed EmbargoState")
	}

	// (4) And so the chain the finding demonstrated end to end — back-dated
	// contact, elapsed deadline, publication permitted in August with no
	// adjustments — cannot be assembled. There is no embargo to carry into it.
	pubStore := p4RecordStore()
	pub := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: p4Persisted(t, pubStore, p4Embargo(t), DisclosureStateEmbargoed),
	}
	p4AssertRefused(t, checkGate18Publication(pub, augustRun, pubStore), Gate18Embargo,
		ReasonEmbargoUnconstructed)

	// (5) A contact dated after the run recording it is refused too. The
	// mirror image: a contact that has not happened starts no clock.
	_, res = RecordVendorContact(p4Channel(t), august, januaryRun)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoContactInTheFuture)

	// (6) Unset clocks on either side refuse rather than defaulting.
	_, res = RecordVendorContact(p4Channel(t), august, RunClock{})
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoClockUnconstructed)
	_, res = RecordVendorContact(p4Channel(t), Clock{}, augustRun)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoClockUnconstructed)
	_, res = OpenEmbargo(p4ThirdParty(t), p4Finding, p4Contact(t), RunClock{})
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoClockUnconstructed)
}

// TestGate18TheConsistentClockLieIsRefusedInBothDirections is the regression
// for the variant the back-date bound did NOT catch.
//
// # What was measured against the previous shape
//
// Run verbatim through the only exported route, no permitAll, no in-package
// shortcuts:
//
//	RecordVendorContact(channel, at=2026-01-03T09:00Z, now=2026-01-03T09:00Z)
//	  -> passed=true      (the back-date is ZERO, so the bound never engages)
//	OpenEmbargo(..., now=2026-01-03T09:00Z)
//	  -> passed=true, deadline=2026-02-17T09:00Z
//	GateAudit.AuditedPublication(..., Now=2026-08-22T12:00Z)
//	  -> passed=true, rows=2
//
// Forty-five days of embargo, zero days of vendor notice, every gate green and
// an audit row saying so. Bounding one caller-supplied instant against another
// catches the lie told with one clock and misses the lie told with two.
//
// # What this test holds
//
// A RUN HAS EXACTLY ONE CLOCK — chosen once by the caller at initiation, and
// not re-suppliable per decision. The sequence above is no longer spellable,
// because there is no second instant to supply: PublicationRequest has no
// clock field and the GateAudit carries the run's. Both directions are run
// here, because a fix that closed only one of them would leave the other open:
//
//	January run: contact is honest, publication is REFUSED (embargo running)
//	August  run: publication would clear, contact is REFUSED (back-dated)
//
// Every instant is hand-written, so nothing here can agree with a bug in the
// implementation's constants.
func TestGate18TheConsistentClockLieIsRefusedInBothDirections(t *testing.T) {
	januaryContact := p4Clock(t, time.Date(2026, time.January, 3, 9, 0, 0, 0, time.UTC))
	januaryRun := p4Run(t, time.Date(2026, time.January, 3, 9, 0, 0, 0, time.UTC))
	augustRun := p4Run(t, time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC))

	// ---- Direction 1: tell the lie consistently at the January clock. ----
	channel := FetchSecurityTxt([]SecurityTxtDocument{{
		Location:  SecurityTxtWellKnown,
		Body:      []byte(p4SecurityTxt),
		Retrieved: true,
	}}, januaryContact)
	contact, res := RecordVendorContact(channel, januaryContact, januaryRun)
	p4AssertPassed(t, res, Gate18Embargo)

	own := p4ThirdParty(t)
	emb, res := OpenEmbargo(own, p4Finding, contact, januaryRun)
	p4AssertPassed(t, res, Gate18Embargo)
	wantDeadline := time.Date(2026, time.February, 17, 9, 0, 0, 0, time.UTC)
	if !emb.Deadline().Equal(wantDeadline) {
		t.Fatalf("deadline %s; want %s", emb.Deadline(), wantDeadline)
	}

	sink := &recordingSink{}
	audit := p4AuditAt(t, sink, januaryRun)
	rec, res := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	store := p4RecordStore()
	pers, res := audit.AuditedPersistDisclosure(store, rec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	out := audit.AuditedPublication(store, PublicationRequest{
		Finding:   p4Finding,
		Ownership: own,
		Embargo:   emb,
		Persisted: pers,
	})
	p4AssertRefused(t, out, Gate18Embargo, ReasonEmbargoRunning)

	// ---- Direction 2: move the run to August so publication WOULD clear. ----
	// The contact cannot be recorded at all: it is back-dated seven months past
	// MaxVendorContactBackdate.
	_, res = RecordVendorContact(channel, januaryContact, augustRun)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoContactBackdated)

	// And there is no third instant to reach for. PublicationRequest has no
	// clock field, so a writer publishes against ITS run — which is the only
	// way to get a passing publication here, and it needs a contact that run
	// cannot record.
	if _, ok := reflect.TypeOf(PublicationRequest{}).FieldByName("Now"); ok {
		t.Fatalf("PublicationRequest has a Now field again. Gate 18's now must be the " +
			"run's, or the January/August lie is spellable again")
	}
	if _, ok := reflect.TypeOf(PushRequest{}).FieldByName("Now"); ok {
		t.Fatalf("PushRequest has a Now field again")
	}
}

// TestGate18OperatorOwnedClaimDeletesTheEmbargoAndNothingElse is the guard on
// the bypass gate 18 kept for a round after gate 20's was closed.
//
// # What was measured against the previous shape
//
// Through the only exported route, no permitAll:
//
//	NewOwnedRepositories("victim/product") -> ClassifyOwnership
//	  -> OperatorOwned()==true
//	GateAudit.AuditedPublication{Finding, Ownership, zero Embargo,
//	                             zero Persisted, Now}
//	  -> passed=true, rows=1
//
// Zero embargo, no gate-19 proof, and an audit row recording the allow.
// checkGate18Publication returned a bare pass on OperatorOwned() before it
// consulted anything below.
//
// Ownership is a SELF-ASSERTION: OwnedRepositories is a list of "owner/name"
// strings the caller supplied and nothing here can check it against a forge.
// An unverified caller assertion may delete only the part of a control the
// assertion is ABOUT. It is about the EMBARGO. It is not about whether the
// disclosure state was persisted, nor about a recorded decision to withhold.
func TestGate18OperatorOwnedClaimDeletesTheEmbargoAndNothingElse(t *testing.T) {
	// Claim the victim's repository. ClassifyOwnership believes it, because
	// believing the operator's declaration is the whole of its job.
	claimed, res := ClassifyOwnership(p4VendorRepo, p4Owned(t, p4VendorRepo))
	p4AssertPassed(t, res, Gate18Embargo)
	if !claimed.OperatorOwned() {
		t.Fatalf("the claim did not take; this test would prove nothing")
	}

	// THE EXACT BYPASS, through the only exported route.
	sink := &recordingSink{}
	audit := p4AuditAt(t, sink, p4RunDay(t, 60))
	out := audit.AuditedPublication(p4RecordStore(), PublicationRequest{
		Finding:   p4Finding,
		Ownership: claimed,
	})
	p4AssertRefused(t, out, Gate18Embargo, ReasonPublicationStateNotPersisted)
	if len(sink.rows) != 1 || sink.rows[0].Outcome != OutcomeDeny {
		t.Fatalf("the refusal was not recorded as a deny row: %+v", sink.rows)
	}

	// A persisted state for a DIFFERENT finding is not this finding's proof,
	// claim or no claim.
	otherStore := p4RecordStore()
	pers := p4Persisted(t, otherStore, p4Embargo(t), DisclosureStateEmbargoed)
	other := PublicationRequest{
		Finding:   p4OtherFinding,
		Ownership: claimed,
		Persisted: pers,
	}
	p4AssertRefused(t, checkGate18Publication(other, p4RunDay(t, 60), otherStore),
		Gate18Embargo, ReasonPublicationStateNotPersisted)

	// A WITHHELD decision is not overturned by claiming to own the repository
	// either. This is the branch that used to be unreachable for an
	// operator-owned finding.
	withheldRec, res := NewOwnFindingDisclosureRecord(claimed, p4Finding,
		DisclosureStateWithheld, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	withheldStore := p4RecordStore()
	withheld, res := persistDisclosureState(withheldStore, withheldRec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	p4AssertRefused(t, checkGate18Publication(PublicationRequest{
		Finding:   p4Finding,
		Ownership: claimed,
		Persisted: withheld,
	}, p4RunDay(t, 60), withheldStore), Gate18Embargo, ReasonPublicationFindingWithheld)

	// A zero RUN CLOCK refuses before the claim is even read.
	p4AssertRefused(t, checkGate18Publication(PublicationRequest{
		Finding:   p4Finding,
		Ownership: claimed,
		Persisted: withheld,
	}, RunClock{}, withheldStore), Gate18Embargo, ReasonEmbargoClockUnconstructed)

	// What the claim IS still worth: with gate 19's proof present, an
	// operator-owned finding publishes with no embargo. That is the branch's
	// legitimate half and it still works.
	okRec, res := NewOwnFindingDisclosureRecord(claimed, p4Finding,
		DisclosureStatePublished, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	okStore := p4RecordStore()
	okPers, res := persistDisclosureState(okStore, okRec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	p4AssertPassed(t, checkGate18Publication(PublicationRequest{
		Finding:   p4Finding,
		Ownership: claimed,
		Persisted: okPers,
	}, p4RunDay(t, 60), okStore), Gate18Embargo)
}

// TestOwnFindingDisclosureRecordRefusesAThirdPartyFinding closes the door the
// new constructor could otherwise be: a third-party finding routed through it
// would get gate 19's proof with no first contact and no deadline, which is
// exactly the shape gate 18 requires the proof in order to prevent.
func TestOwnFindingDisclosureRecordRefusesAThirdPartyFinding(t *testing.T) {
	_, res := NewOwnFindingDisclosureRecord(p4ThirdParty(t), p4Finding,
		DisclosureStatePublished, p4Key(t))
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonEmbargoUnconstructed)

	_, res = NewOwnFindingDisclosureRecord(Ownership{}, p4Finding,
		DisclosureStatePublished, p4Key(t))
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonOwnershipUnclassified)

	own := p4OperatorOwned(t)
	_, res = NewOwnFindingDisclosureRecord(own, "", DisclosureStatePublished, p4Key(t))
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonFindingUnidentified)

	_, res = NewOwnFindingDisclosureRecord(own, p4Finding, DisclosureStateUnset, p4Key(t))
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStateUnknown)

	_, res = NewOwnFindingDisclosureRecord(own, p4Finding, DisclosureStatePublished, AuditKey{})
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureKeyIncomplete)
}

// TestGate18TheBackdateBoundIsABoundAndNotABan walks the boundary with
// hand-written instants, so the coded value is pinned by behaviour rather than
// by an assertion that reads the constant back.
func TestGate18TheBackdateBoundIsABoundAndNotABan(t *testing.T) {
	contact := p4Clock(t, time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC))

	// Exactly one HOUR later: accepted. The bound is inclusive.
	onTheBound := p4Run(t, time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC))
	v, res := RecordVendorContact(p4Channel(t), contact, onTheBound)
	p4AssertPassed(t, res, Gate18Embargo)
	if !v.At().Equal(contact.Instant()) {
		t.Fatalf("the recorded contact instant is %s; want %s", v.At(), contact.Instant())
	}

	// One second past it: refused.
	pastTheBound := p4Run(t, time.Date(2026, time.August, 10, 13, 0, 1, 0, time.UTC))
	_, res = RecordVendorContact(p4Channel(t), contact, pastTheBound)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoContactBackdated)

	// A WHOLE DAY back: refused. This instant was ACCEPTED while the bound was
	// 24h, and it is the instant finding 1's attack used to cancel the
	// acceleration floor.
	aDayBack := p4Run(t, time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC))
	_, res = RecordVendorContact(p4Channel(t), contact, aDayBack)
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoContactBackdated)

	// A contact back-dated to the bound still buys 45 days from the contact
	// instant, which is 24 September — so the shortest embargo reachable this
	// way is 45 days less an hour, not zero, and the only route below that is
	// Accelerate.
	emb, res := OpenEmbargo(p4ThirdParty(t), p4Finding, v, onTheBound)
	p4AssertPassed(t, res, Gate18Embargo)
	wantDeadline := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	if !emb.Deadline().Equal(wantDeadline) {
		t.Fatalf("deadline %s; want %s", emb.Deadline(), wantDeadline)
	}
	if n := len(emb.Adjustments()); n != 0 {
		t.Fatalf("opening an embargo recorded %d adjustments", n)
	}

	// One day before that deadline it is still running.
	dayBefore := p4Clock(t, time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC))
	if emb.Elapsed(dayBefore) {
		t.Fatalf("the embargo reported itself elapsed on %s", dayBefore.Instant())
	}
	if !emb.Elapsed(p4Clock(t, wantDeadline)) {
		t.Fatalf("the embargo did not elapse on its own deadline")
	}
}

// TestGate18BackdatingToTheBoundCannotCancelTheAccelerationFloor is the
// BEHAVIOURAL half of finding 1, run end to end through the exported routes
// with hand-written instants and no reference to either constant.
//
// # What was measured against the previous tree
//
// MaxVendorContactBackdate and MinAcceleratedEmbargo were both 24h. Each was
// individually defensible, their RELATION was never asserted, and one
// cancelled the other exactly:
//
//	run clock                                     2026-08-11T12:00:00Z
//	RecordVendorContact(at=2026-08-10T12:00:00Z)  passed (back-date == the bound)
//	OpenEmbargo                                   passed (deadline 2026-09-24)
//	Accelerate(active_exploitation, evidence)     passed -> deadline == the run
//	publication, SAME RUN                         PASSED
//
// Zero seconds of embargo served, in the run that recorded first contact, with
// the one allowlisted acceleration reason. Both doc comments claiming a
// guaranteed one-day window were false.
//
// # What this holds
//
// In TWO PARTS, because neither alone is enough.
//
// PART 1 uses HAND-WRITTEN instants and mentions no constant at all: a one-hour
// back-date, an accelerated deadline written out as 2026-08-11T12:00:00Z, and
// publication refused until that instant. An expectation computed as
// firstContact.Add(MinAcceleratedEmbargo) would agree with ANY pair of
// constants — including the pair that cancelled — which is exactly how the
// defect survived a constants test that pinned both values.
//
// PART 2 drives the attack AT THE BOUND, and for that it must ask what the
// bound is; what it asserts is not computed from any constant. The property is
// "a third-party finding is not published in the run that recorded first
// contact, no matter how far back the contact is dated", and that sentence is
// true or false independently of what the two durations are. Part 1 pins
// today's numbers; part 2 is what goes red if MaxVendorContactBackdate is
// restored to 24h, because at 24h the worst-case floor lands exactly on the
// run clock and the same-run publication PASSES.
func TestGate18BackdatingToTheBoundCannotCancelTheAccelerationFloor(t *testing.T) {
	// The run is 2026-08-10T13:00:00Z and the contact is back-dated to exactly
	// the permitted bound, which is the attacker's best move: any further back
	// and RecordVendorContact refuses.
	run := p4Run(t, time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC))
	contact := p4Clock(t, time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC))

	v, res := RecordVendorContact(p4Channel(t), contact, run)
	p4AssertPassed(t, res, Gate18Embargo)

	emb, res := OpenEmbargo(p4ThirdParty(t), p4Finding, v, run)
	p4AssertPassed(t, res, Gate18Embargo)

	fast, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"exploited in the wild, IDS capture 2026-08-10", run)
	p4AssertPassed(t, res, Gate18Embargo)

	// 12:00 plus the floor is 2026-08-11T12:00:00Z. The run is 13:00, so the
	// vendor gets 23 hours it did not get before.
	wantFloor := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	if !fast.Deadline().Equal(wantFloor) {
		t.Fatalf("the accelerated deadline is %s; want the coded floor %s. If it equals "+
			"the run clock, back-dating has cancelled the acceleration floor and a "+
			"third-party finding publishes in the run that recorded first contact",
			fast.Deadline(), wantFloor)
	}
	if served := fast.Deadline().Sub(run.Instant()); served <= 0 {
		t.Fatalf("the accelerated embargo serves %s measured forward from the run that "+
			"accelerated it. An embargo that is already over when it is shortened is "+
			"not an embargo", served)
	}

	// THE ATTACK ITSELF: publish in the same run.
	store := p4RecordStore()
	pers := p4Persisted(t, store, fast, DisclosureStateEmbargoed)
	pub := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   fast,
		Persisted: pers,
	}
	p4AssertRefused(t, checkGate18Publication(pub, run, store), Gate18Embargo,
		ReasonEmbargoRunning)

	// One second before the floor: still refused.
	p4AssertRefused(t, checkGate18Publication(pub, p4Run(t, wantFloor.Add(-time.Second)), store),
		Gate18Embargo, ReasonEmbargoRunning)

	// At the floor it publishes, which is what makes this a bound and not a ban.
	p4AssertPassed(t, checkGate18Publication(pub, p4Run(t, wantFloor), store), Gate18Embargo)

	// ---- PART 2: the same attack driven AT THE BOUND, whatever it is. ----
	//
	// The attacker's best move is to back-date by exactly MaxVendorContactBackdate,
	// so that is what this does. Nothing asserted below is computed from a
	// duration constant: the claim is that the run which RECORDS first contact
	// cannot also PUBLISH, and that claim is true or false on its own terms.
	worstRun := p4Run(t, time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC))
	worstContact := p4Clock(t, worstRun.Instant().Add(-MaxVendorContactBackdate))

	wv, res := RecordVendorContact(p4Channel(t), worstContact, worstRun)
	p4AssertPassed(t, res, Gate18Embargo)

	wemb, res := OpenEmbargo(p4ThirdParty(t), p4Finding, wv, worstRun)
	p4AssertPassed(t, res, Gate18Embargo)

	wfast, res := wemb.Accelerate(EmbargoAccelerationActiveExploitation,
		"exploited in the wild, IDS capture 2026-08-10", worstRun)
	p4AssertPassed(t, res, Gate18Embargo)

	if !wfast.Deadline().After(worstRun.Instant()) {
		t.Fatalf("with the contact back-dated by the full permitted bound, the accelerated "+
			"deadline is %s and the run is %s. The deadline is not in the run's future, "+
			"so the acceleration floor has been cancelled by the back-date bound and a "+
			"third-party finding publishes in the run that recorded first contact with "+
			"no embargo served at all.",
			wfast.Deadline().UTC().Format(time.RFC3339),
			worstRun.Instant().UTC().Format(time.RFC3339))
	}

	worstStore := p4RecordStore()
	worstPub := PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   wfast,
		Persisted: p4Persisted(t, worstStore, wfast, DisclosureStateEmbargoed),
	}
	p4AssertRefused(t, checkGate18Publication(worstPub, worstRun, worstStore), Gate18Embargo,
		ReasonEmbargoRunning)

	// And through the only exported route, so the refusal is the one an
	// operator would actually hit.
	audit := p4AuditAt(t, &recordingSink{}, worstRun)
	p4AssertRefused(t, audit.AuditedPublication(worstStore, worstPub), Gate18Embargo,
		ReasonEmbargoRunning)
}

// TestPhase4EmbargoConstantsArePinnedToTheirLiteralValues pins the four coded
// durations to values written a DIFFERENT way than the declarations write
// them: nanoseconds as integers, plus the string Duration renders.
//
// Writing "nothing may raise this" in a comment pins nothing. Measured before
// this test existed: MinAcceleratedEmbargo could be changed from 24h to 1s —
// turning acceleration into the disable switch plan/50-dast.md says is not
// configurable — and the whole suite stayed GREEN, because the one test that
// looked at the floor computed its expectation as p4FirstContact.Add(
// MinAcceleratedEmbargo) and so asserted that the code equals itself.
func TestPhase4EmbargoConstantsArePinnedToTheirLiteralValues(t *testing.T) {
	for _, c := range []struct {
		name    string
		got     time.Duration
		wantNs  int64
		wantStr string
	}{
		{"DefaultEmbargo", DefaultEmbargo, 3_888_000_000_000_000, "1080h0m0s"},
		{"MinAcceleratedEmbargo", MinAcceleratedEmbargo, 86_400_000_000_000, "24h0m0s"},
		{"MaxEmbargo", MaxEmbargo, 31_536_000_000_000_000, "8760h0m0s"},
		{"MaxVendorContactBackdate", MaxVendorContactBackdate, 3_600_000_000_000, "1h0m0s"},
	} {
		if int64(c.got) != c.wantNs {
			t.Errorf("%s is %d ns (%s); it is pinned at %d ns (%s). Changing it changes "+
				"what an embargo is, so it changes here first and in review.",
				c.name, int64(c.got), c.got, c.wantNs, time.Duration(c.wantNs))
		}
		if c.got.String() != c.wantStr {
			t.Errorf("%s renders as %q; want %q", c.name, c.got.String(), c.wantStr)
		}
	}
}

// TestPhase4EmbargoConstantsPinTheRelationsNotOnlyTheValues is the half the
// test above cannot be.
//
// # Why it is a separate test with its own name
//
// Because finding 1 was not a wrong constant. MaxVendorContactBackdate was 24h
// and MinAcceleratedEmbargo was 24h and BOTH WERE INDIVIDUALLY DEFENSIBLE; the
// test above pinned both literals and passed. What was never asserted was the
// RELATION, and the two happened to be equal, so one cancelled the other and a
// third-party finding published in the run that recorded first contact with 0s
// of embargo served.
//
// Three relations were pinned here before and a fourth — the load-bearing one
// — was not. That is the shape this test now exists to prevent, so each
// relation says what it buys and what breaks without it.
func TestPhase4EmbargoConstantsPinTheRelationsNotOnlyTheValues(t *testing.T) {
	// R1. Acceleration must be able to shorten something. Without this,
	// "accelerate" would be a no-op or a lengthening.
	if MinAcceleratedEmbargo >= DefaultEmbargo {
		t.Errorf("the acceleration floor (%s) is not below the default embargo (%s)",
			MinAcceleratedEmbargo, DefaultEmbargo)
	}
	// R2. Extension must be able to lengthen something.
	if MaxEmbargo <= DefaultEmbargo {
		t.Errorf("the extension ceiling (%s) is not above the default embargo (%s)",
			MaxEmbargo, DefaultEmbargo)
	}
	// R3. Back-dating ALONE must not reach below what Accelerate reaches.
	// Otherwise the allowlist and the evidence requirement are optional: you
	// get the same deadline by lying about the date instead.
	if MaxVendorContactBackdate >= DefaultEmbargo-MinAcceleratedEmbargo {
		t.Errorf("back-dating (%s) can reach further than Accelerate can (%s), which makes "+
			"the acceleration allowlist optional",
			MaxVendorContactBackdate, DefaultEmbargo-MinAcceleratedEmbargo)
	}
	// R4. THE ONE THAT WAS MISSING. The acceleration floor is measured from
	// FIRST CONTACT, and first contact can be moved back by up to
	// MaxVendorContactBackdate, so the window a vendor actually gets —
	// measured forward from the run that accelerates — is the DIFFERENCE.
	// While the two were equal that difference was zero and the floor was not
	// a floor. STRICTLY less, not less-or-equal: equality is the defect.
	if MaxVendorContactBackdate >= MinAcceleratedEmbargo {
		t.Errorf("MaxVendorContactBackdate (%s) is not STRICTLY LESS THAN "+
			"MinAcceleratedEmbargo (%s). The floor is measured from first contact and "+
			"back-dating moves first contact, so a contact dated to the bound puts the "+
			"floor %s from the run that accelerates. At zero, one allowlisted "+
			"acceleration publishes a third-party finding in the run that recorded "+
			"first contact.",
			MaxVendorContactBackdate, MinAcceleratedEmbargo,
			MinAcceleratedEmbargo-MaxVendorContactBackdate)
	}
	// And the number that relation guarantees, written out rather than
	// described, because "a one-day window" is what the doc comments used to
	// claim and it was not true.
	if got, want := MinAcceleratedEmbargo-MaxVendorContactBackdate, 23*time.Hour; got != want {
		t.Errorf("the shortest embargo any sequence in this file can produce, measured "+
			"forward from the run that accelerates, is %s; the file's prose says %s. "+
			"Change the prose in the same commit or change it back.", got, want)
	}

	// ---- The pairs that were audited and are FINE, recorded so the next
	// reader does not have to re-derive them. ----
	//
	// (a) MaxVendorContactBackdate vs MaxEmbargo. The extension ceiling is
	//     firstContact+MaxEmbargo, so back-dating moves the ceiling EARLIER.
	//     The interaction is in the safe direction: back-dating cannot buy a
	//     longer extension, it costs one. Asserted anyway, because "safe
	//     direction" is a claim.
	if bound := MaxEmbargo - MaxVendorContactBackdate; bound >= MaxEmbargo {
		t.Errorf("back-dating does not tighten the extension ceiling; check Extend's bound")
	}
	// (b) MinAcceleratedEmbargo vs MaxEmbargo. Implied by R1 and R2
	//     (Min < Default < Max) rather than independent, and asserted so that
	//     dropping either of those does not silently drop this too.
	if MinAcceleratedEmbargo >= MaxEmbargo {
		t.Errorf("the acceleration floor is not below the extension ceiling")
	}
	// (c) DefaultEmbargo vs MaxEmbargo, for Extend specifically: Extend
	//     requires a deadline strictly later than the current one and no later
	//     than firstContact+MaxEmbargo, so there must be room between the
	//     default deadline and the ceiling or Extend could never succeed.
	if MaxEmbargo-DefaultEmbargo <= 0 {
		t.Errorf("there is no room between the default deadline and the extension " +
			"ceiling, so no extension can ever succeed")
	}
	// (d) DefaultEmbargo (45d) against gate 5's attestation ceiling (30d) is
	//     NOT a constant-interaction defect and is deliberately not asserted
	//     here: an embargo outliving the attestation that authorised the scan
	//     is expected, and it is what makes the two-run divergent-clock
	//     residual visible in the audit log at all. See SKIPPED-CONTROLS
	//     G18-2.
}

// ===========================================================================
// GATE 21's COUPLING IS NOT OPT-IN
// ===========================================================================

// TestPhase4HasNoUnauditedExportedDecisionPath is the structural half of gate
// 21's coupling.
//
// The Audited* wrappers enforce the coupling correctly against every failing
// sink shape in this file. That was not enough while CheckGate18Publication,
// PushGate and PersistDisclosureState were EXPORTED, because all three
// returned an allow — and PersistDisclosureState a valid PersistedDisclosure —
// with zero audit rows written. The measured probe output was
// "bare CheckGate18Publication passed=true", "bare PushGate passed=true" and
// "PersistedDisclosure.Valid()=true with 0 audit rows written". A rule that
// applies only when the caller chooses the wrapper is not a rule.
//
// So the three are unexported and only GateAudit's methods reach them. This
// test parses the file and holds that shape with an ALLOWLIST: an exported
// package-level function may return a GateResult only if it is named here, and
// every name here mints a sealed VALUE rather than permitting an ACTION. A
// newly exported gate entry point fails this test until somebody adds it to
// the list, which is a line a reviewer sees.
func TestPhase4HasNoUnauditedExportedDecisionPath(t *testing.T) {
	const file = "phase4_disclosure.go"
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	// The allowlist. Each entry mints a sealed value and decides nothing about
	// an action, so none of them is a decision an audit row must be paired
	// with.
	allowed := map[string]string{
		"ClassifyOwnership":             "mints an Ownership from the operator's declaration",
		"RecordVendorContact":           "mints a VendorContact",
		"OpenEmbargo":                   "mints an EmbargoState",
		"NewDisclosureRecord":           "mints a DisclosureRecord",
		"NewOwnFindingDisclosureRecord": "mints a DisclosureRecord for an operator-owned finding; it writes nothing and persistDisclosureState is still the only writer",
		"NewAuditKey":                   "mints an AuditKey",
		"NewGateAudit":                  "mints the audit writer itself",
	}
	// The three that must never be exported again, and the fourth that
	// granted nothing but still returned a bare allow.
	mustBeUnexported := []string{
		"checkGate18Publication",
		"pushGate",
		"persistDisclosureState",
		"checkGate19DisclosureStore",
	}

	coupled := map[string]bool{
		"GateResult":          true,
		"PersistedDisclosure": true,
	}
	seen := map[string]bool{}
	declared := map[string]bool{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		declared[fn.Name.Name] = true
		if fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
			continue
		}
		returnsDecision := false
		for _, r := range fn.Type.Results.List {
			if id, ok := r.Type.(*ast.Ident); ok && coupled[id.Name] {
				returnsDecision = true
			}
		}
		if !returnsDecision {
			continue
		}
		if _, ok := allowed[fn.Name.Name]; !ok {
			t.Fatalf("%s is an EXPORTED package-level function returning a gate decision. "+
				"Gate 21 says a decision is not allowed if its paired audit write "+
				"fails; an exported function that returns an allow having written "+
				"nothing makes that optional. Reach it through a GateAudit method, or "+
				"add it to this test's allowlist and say why it grants nothing.",
				fn.Name.Name)
		}
		seen[fn.Name.Name] = true
	}
	for name := range allowed {
		if !seen[name] {
			t.Fatalf("the allowlist names %s, which this walk did not find as an exported "+
				"function returning a gate decision. The survey is stale or vacuous.",
				name)
		}
	}
	for _, name := range mustBeUnexported {
		if !declared[name] {
			t.Fatalf("%s is not declared in %s. It was unexported so that the only route "+
				"to the gate is the audited one; if it has been renamed or re-exported, "+
				"the coupling is opt-in again.", name, file)
		}
	}
}

// TestRunClockHasNoExportedConstructor is what makes "a run has exactly one
// clock, and no decision in the run may be handed a different one" a property
// of the package rather than a convention.
//
// The wording here used to be "and it is not a parameter", which was wrong:
// RunRequest.Clock is an exported, settable field and InitiateRun copies it
// verbatim into the seal, so the run's instant IS chosen by the caller. What
// this test holds is the half that is true and load-bearing.
//
// A RunClock is only worth more than a Clock if a caller outside this package
// cannot mint one. sealRunClock is unexported, RunClock's fields are
// unexported, and the single exported route is RunInitiation.RunClock — a
// METHOD on a value that exists only after gates 6, 4, 5 and 7 and EnableDAST
// have all passed.
//
// This walks every .go file in the package and fails if any EXPORTED
// package-level function returns a RunClock, which is the shape a second door
// would take. It also fails if the one method it expects is not found, so it
// cannot pass by walking nothing.
func TestRunClockHasNoExportedConstructor(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) < 10 {
		t.Fatalf("the walk found %d files in the package; the survey is not looking at "+
			"the package", len(files))
	}

	mintsRunClock := func(fn *ast.FuncDecl) bool {
		if fn.Type.Results == nil {
			return false
		}
		for _, r := range fn.Type.Results.List {
			if id, ok := r.Type.(*ast.Ident); ok && id.Name == "RunClock" {
				return true
			}
		}
		return false
	}

	foundTheMethod := false
	foundTheSeal := false
	for _, file := range files {
		parsed, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !mintsRunClock(fn) {
				continue
			}
			if fn.Name.Name == "sealRunClock" {
				foundTheSeal = true
				if fn.Name.IsExported() {
					t.Fatalf("sealRunClock is exported")
				}
				continue
			}
			if fn.Recv != nil {
				recv := ""
				if len(fn.Recv.List) == 1 {
					typ := fn.Recv.List[0].Type
					if star, ok := typ.(*ast.StarExpr); ok {
						typ = star.X
					}
					if id, ok := typ.(*ast.Ident); ok {
						recv = id.Name
					}
				}
				if recv == "" {
					t.Fatalf("%s declares a method returning a RunClock whose receiver "+
						"type this walk could not read, so the survey below is blind "+
						"to it", file)
				}
				switch {
				case recv == "RunInitiation" && fn.Name.Name == "RunClock":
					foundTheMethod = true
				case recv == "GateAudit" || recv == "RunClock":
					// A method that hands back a RunClock it was already given
					// mints nothing.
				default:
					if fn.Name.IsExported() {
						t.Fatalf("%s.%s in %s returns a RunClock. The only exported route "+
							"to one is RunInitiation.RunClock; a second door makes the "+
							"run's clock a parameter again, and the consistently-told "+
							"January/August embargo lie spellable again.",
							recv, fn.Name.Name, file)
					}
				}
				continue
			}
			if fn.Name.IsExported() {
				t.Fatalf("%s in %s is an EXPORTED package-level function returning a "+
					"RunClock. sealRunClock is unexported precisely so that a caller "+
					"cannot mint the run's clock; this is that door, reopened.",
					fn.Name.Name, file)
			}
		}
	}
	if !foundTheSeal {
		t.Fatal("sealRunClock was not found in the package, so this survey is stale and " +
			anchorNoteSeal)
	}
	if !foundTheMethod {
		t.Fatal("RunInitiation.RunClock was not found, so this survey is stale and " +
			anchorNoteMethod)
	}

	// And the zero value is not a clock, whatever route it arrived by.
	var zero RunClock
	if zero.Valid() {
		t.Fatal("the zero RunClock reports Valid()")
	}
	if !zero.Instant().IsZero() {
		t.Fatal("the zero RunClock hands back a non-zero instant")
	}
	if zero.Now().Valid() {
		t.Fatal("the zero RunClock laundered itself into a valid Clock through Now()")
	}
	// An invalid Clock cannot be sealed into a valid RunClock either.
	if sealRunClock(Clock{}).Valid() {
		t.Fatal("sealRunClock sealed a Clock that NewClock never built")
	}
}

const (
	anchorNoteSeal   = "passes by finding nothing"
	anchorNoteMethod = "passes by finding nothing"
)

// TestRunClockComesFromAnInitiatedRunOnly walks the exported route end to end:
// a RunInitiation that Phase 1 minted hands back a RunClock carrying the run's
// instant, and a zero RunInitiation hands back an error and a clock that
// refuses.
func TestRunClockComesFromAnInitiatedRunOnly(t *testing.T) {
	var never RunInitiation
	if _, err := never.RunClock(); err == nil {
		t.Fatal("a RunInitiation nobody initiated handed back a run clock")
	}
	clock, _ := never.RunClock()
	if clock.Valid() {
		t.Fatal("the run clock from an uninitiated run reports Valid()")
	}

	run, res := InitiateRun(p1GoodRequest(t))
	if !res.Passed() {
		t.Fatalf("InitiateRun refused the good request: %v", res.Err())
	}
	got, err := run.RunClock()
	if err != nil {
		t.Fatalf("an initiated run has no clock: %v", err)
	}
	if !got.Valid() {
		t.Fatal("the run clock of an initiated run reports Valid()==false")
	}
	if !got.Instant().Equal(p1GoodRequest(t).Clock.Instant()) {
		t.Fatalf("the run clock is %s; want the instant the run was initiated at, %s",
			got.Instant(), p1GoodRequest(t).Clock.Instant())
	}
	if !got.Now().Instant().Equal(got.Instant()) {
		t.Fatalf("RunClock.Now() and RunClock.Instant() disagree")
	}
}

// ===========================================================================
// THE LAYERS THAT COULD NOT FAIL
// ===========================================================================

// TestGate19RefusesAStoreThatCommittedARowThenFailed reaches
// persistDisclosureState's `err != nil` branch, which p4Store cannot: it
// returns (0, s.err), so the seq==0 branch fires first and masks it. Measured
// before this test existed: replacing `case err != nil:` with `case false:`
// left the suite GREEN.
func TestGate19RefusesAStoreThatCommittedARowThenFailed(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	store := &p4CommittedThenFailedStore{err: errors.New("commit failed after INSERT")}
	p, res := persistDisclosureState(store, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureWriteFailed)
	if p.Valid() {
		t.Fatalf("a store that failed to commit produced gate 18's publication proof")
	}
	if store.next == 0 {
		t.Fatalf("the fake did not advance its sequence, so the seq==0 branch could have " +
			"been what refused and this test proves nothing")
	}
	if !strings.Contains(res.Err().Error(), "commit failed after INSERT") {
		t.Fatalf("the refusal does not carry the store's error: %v", res.Err())
	}
}

// TestGate19ReadsTheStoresMediumExactlyOnce holds the read-once rule.
//
// persistDisclosureState used to call store.Medium() twice — once for the
// location check and once to stamp the proof — and returned gatePassed
// regardless. A store answering `record_store_sqlite` and then
// `tmpfs_handoff_buffer` therefore produced passed=true alongside a
// PersistedDisclosure whose Valid() is false: the gate said yes and the proof
// said no, and a caller checks one of them.
func TestGate19ReadsTheStoresMediumExactlyOnce(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	store := &p4FlippingStore{}
	p, res := persistDisclosureState(store, rec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	if store.calls != 1 {
		t.Fatalf("gate 19 asked the store for its medium %d times; it must ask once, so "+
			"that the value checked and the value stamped into the proof are one value",
			store.calls)
	}
	if !p.Valid() {
		t.Fatalf("gate 19 passed and handed back a proof that is not valid")
	}
	if p.Medium() != MediumRecordStoreSQLite {
		t.Fatalf("the proof was stamped %q", p.Medium())
	}
}

// TestRecordTraceStopsAtTheFirstRefusal puts the refusal in the SECOND of four
// positions.
//
// Every other trace in this file has its refusal LAST, so the final value
// carries the refusal whether or not the early return exists — measured,
// deleting the early return left the suite GREEN. With the refusal in the
// middle, deleting it writes four rows instead of two AND returns the fourth
// gate's ALLOW.
func TestRecordTraceStopsAtTheFirstRefusal(t *testing.T) {
	sink := &recordingSink{}
	audit := p4Audit(t, sink)

	trace := []GateResult{
		gatePassed(Gate16CircuitBreaker),
		gateFailed(Gate15DestructiveTechniques, ReasonTechniqueDestructive, "denylisted"),
		gatePassed(Gate17RetryAfter),
		gatePassed(Gate13RevalidateEveryRequest),
	}
	res := audit.RecordTrace(trace, SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, res, Gate15DestructiveTechniques, ReasonTechniqueDestructive)

	if len(sink.rows) != 2 {
		t.Fatalf("%d rows written; the trace was decided at the second gate and the two "+
			"gates after it were never consulted, so recording them would put "+
			"decisions in the log that nothing made", len(sink.rows))
	}
	for i, g := range []GateID{Gate16CircuitBreaker, Gate15DestructiveTechniques} {
		if sink.rows[i].Gate != g {
			t.Fatalf("row %d names %s; want %s", i, sink.rows[i].Gate, g)
		}
	}
	if audit.Rows() != 2 {
		t.Fatalf("the writer counted %d durable rows; want 2", audit.Rows())
	}
}

// TestAuditedObservationRefusesWhenTheAuditWriteFails closes the one audited
// path in this file that had no such test — and it is the path gate 21's
// "every circuit-breaker trip" arrives through.
func TestAuditedObservationRefusesWhenTheAuditWriteFails(t *testing.T) {
	gov := p4Governor(t)

	// A HEALTHY observation. This is the load-bearing case: a refusal comes
	// back as a refusal either way, so only an allow can show the coupling.
	healthy := gov.Health().ObserveResponse(200, 10*time.Millisecond, p4Sec(t, 1))
	if !healthy.Passed() || healthy.Gate() != Gate16CircuitBreaker {
		t.Fatalf("a single 200 did not produce a passing gate 16 observation: %v",
			healthy.Err())
	}

	// The sink assigns a row id and then fails to commit, so the write-error
	// branch is the only thing that can refuse it.
	failing := &p4CommittedThenFailedSink{err: errors.New("commit failed")}
	audit := p4Audit(t, failing)
	out := audit.AuditedObservation(healthy, p4Target(t), p4Sec(t, 2))
	if out.Passed() {
		t.Fatalf("a healthy observation survived a failed audit write; gate 21 says a " +
			"decision is not allowed if its paired audit write fails")
	}
	if out.Gate() != Gate21ImmutableAudit {
		t.Fatalf("the refusal is attributed to %s; want gate 21", out.Gate())
	}
	if audit.Rows() != 0 {
		t.Fatalf("the writer counted %d durable rows after a failed commit", audit.Rows())
	}

	// And with a working sink the observation passes and is recorded.
	sink := &recordingSink{}
	audit = p4Audit(t, sink)
	p4AssertPassed(t, audit.AuditedObservation(healthy, p4Target(t), p4Sec(t, 2)),
		Gate16CircuitBreaker)
	if len(sink.rows) != 1 || sink.rows[0].Gate != Gate16CircuitBreaker ||
		sink.rows[0].Outcome != OutcomeAllow {
		t.Fatalf("the healthy observation was not recorded as an allow: %+v", sink.rows)
	}
}

// TestGateAuditNamesASilentWriteAsAFailedWriteNotARewind separates Record's
// two sequence branches.
//
// On the FIRST row lastSeq is still 0, so a sink returning (0, nil) satisfies
// both `seq == 0` and `seq <= a.lastSeq`. The switch takes the first, and the
// two carry DIFFERENT tokens — an operator greps for one of them. Measured
// before this test existed: deleting the seq==0 branch left the suite GREEN,
// because the only test covering a silent sink asserted the gate and
// ErrRefused but never the reason.
func TestGateAuditNamesASilentWriteAsAFailedWriteNotARewind(t *testing.T) {
	audit := p4Audit(t, silentSink{})
	if audit.LastSeq() != 0 {
		t.Fatalf("the writer started at sequence %d; this test needs the first row, where "+
			"the two branches overlap", audit.LastSeq())
	}

	seq, res := audit.Record(gatePassed(Gate14HardCaps), SubjectTarget(p4Target(t)), p4Day(t, 0))
	p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditWriteFailed)
	if seq != 0 {
		t.Fatalf("a refused write returned sequence %d", seq)
	}
	if audit.Rows() != 0 {
		t.Fatalf("the writer counted %d durable rows for a sink that wrote none",
			audit.Rows())
	}
}
