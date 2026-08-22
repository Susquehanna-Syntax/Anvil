package authz

import (
	"encoding/json"
	"errors"
	"net/http"
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
	c, res := RecordVendorContact(p4Channel(t), p4Day(t, 0))
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
	e, res := OpenEmbargo(p4ThirdParty(t), p4Finding, p4Contact(t))
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
type p4Store struct {
	medium StorageMedium
	err    error
	silent bool
	rows   []DisclosureRecord
	next   AuditSeq
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

func p4RecordStore() *p4Store { return &p4Store{medium: MediumRecordStoreSQLite} }

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

func p4Audit(t *testing.T, sink AuditSink) *GateAudit {
	t.Helper()
	a, res := NewGateAudit(sink, p4Key(t))
	p4AssertPassed(t, res, Gate21ImmutableAudit)
	return a
}

// p4Persisted runs the real gate 19 path and returns the proof gate 18 wants.
func p4Persisted(t *testing.T, emb EmbargoState, state DisclosureState) PersistedDisclosure {
	t.Helper()
	rec, res := NewDisclosureRecord(emb, state, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	p, res := PersistDisclosureState(p4RecordStore(), rec)
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)
	return p
}

// p4PublishRequest is the well-formed third-party publication request every
// gate-18 test starts from and then breaks one field of.
func p4PublishRequest(t *testing.T, emb EmbargoState, now Clock) PublicationRequest {
	t.Helper()
	return PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Embargo:   emb,
		Persisted: p4Persisted(t, emb, DisclosureStateEmbargoed),
		Now:       now,
	}
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
		Now:         p4Day(t, 0),
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
		req := p4PublishRequest(t, emb, p4Day(t, day))
		res := CheckGate18Publication(req)
		p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoRunning)
	}

	// Day 45 is the deadline itself, and the comparison is "not before", so
	// the deadline instant publishes.
	res := CheckGate18Publication(p4PublishRequest(t, emb, p4Day(t, 45)))
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
		_, res := emb.Accelerate(reason, "IDS caught it in the wild on 2026-08-12", p4Day(t, 5))
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
			_, res := emb.Accelerate(EmbargoAccelerationActiveExploitation, evidence, p4Day(t, 5))
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
		"exploitation observed in server logs", p4Day(t, 0))
	p4AssertPassed(t, res, Gate18Embargo)

	want := p4FirstContact.Add(MinAcceleratedEmbargo)
	if !fast.Deadline().Equal(want) {
		t.Fatalf("accelerated deadline %s; want the coded floor %s", fast.Deadline(), want)
	}

	// Publication on the day of contact is still refused.
	res = CheckGate18Publication(p4PublishRequest(t, fast, p4Day(t, 0)))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoRunning)

	// And is permitted a day later, which is what "accelerated" means.
	res = CheckGate18Publication(p4PublishRequest(t, fast, p4Day(t, 1)))
	p4AssertPassed(t, res, Gate18Embargo)
}

func TestGate18AccelerationCannotLengthenTheEmbargo(t *testing.T) {
	emb := p4Embargo(t)
	_, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"observed on 2026-09-28", p4Day(t, 50))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoAccelerationNoEffect)
}

func TestGate18AccelerationRefusesAClockBeforeFirstContact(t *testing.T) {
	emb := p4Embargo(t)
	_, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"observed before we told anyone", p4Day(t, -3))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoClockWentBack)
}

func TestGate18ExtensionNeedsAnAllowlistedReasonAndEvidence(t *testing.T) {
	emb := p4Embargo(t)
	for _, reason := range []EmbargoExtensionReason{
		EmbargoExtensionUnset, "vendor_asked_nicely", "STANDARDS_PROCESS", "core_os",
	} {
		_, res := emb.Extend(reason, "IETF draft in last call", p4Day(t, 90))
		p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionUnsupported)
	}
	_, res := emb.Extend(EmbargoExtensionStandardsProcess, "", p4Day(t, 90))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionUnevidenced)
}

func TestGate18ExtensionOnlyLengthensAndIsBounded(t *testing.T) {
	emb := p4Embargo(t)

	_, res := emb.Extend(EmbargoExtensionCoreOSChange, "kernel patch queued", p4Day(t, 40))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionNotLonger)

	_, res = emb.Extend(EmbargoExtensionCoreOSChange, "kernel patch queued", p4Day(t, 400))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoExtensionExceedsBound)

	long, res := emb.Extend(EmbargoExtensionStandardsProcess, "IETF draft in last call",
		p4Day(t, 120))
	p4AssertPassed(t, res, Gate18Embargo)
	if !long.Deadline().Equal(p4FirstContact.Add(120 * 24 * time.Hour)) {
		t.Fatalf("extended deadline %s; want day 120", long.Deadline())
	}
	// The extension is what the publication gate now measures against.
	res = CheckGate18Publication(p4PublishRequest(t, long, p4Day(t, 46)))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoRunning)
}

func TestGate18AdjustmentsAreRecordedWithBothDeadlines(t *testing.T) {
	emb := p4Embargo(t)
	fast, res := emb.Accelerate(EmbargoAccelerationActiveExploitation,
		"exploited in the wild", p4Day(t, 10))
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
	fast, res := emb.Accelerate(EmbargoAccelerationActiveExploitation, "exploited", p4Day(t, 10))
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
	req := p4PublishRequest(t, emb, p4Day(t, 60))
	req.Ownership = Ownership{}
	p4AssertRefused(t, CheckGate18Publication(req), Gate18Embargo, ReasonOwnershipUnclassified)
}

func TestGate18PublishesAnOperatorOwnedFindingWithoutAnEmbargo(t *testing.T) {
	res := CheckGate18Publication(PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4OperatorOwned(t),
		Now:       p4Day(t, 0),
	})
	p4AssertPassed(t, res, Gate18Embargo)
}

func TestGate18RefusesAnEmbargoForAnotherFinding(t *testing.T) {
	other, res := OpenEmbargo(p4ThirdParty(t), p4OtherFinding, p4Contact(t))
	p4AssertPassed(t, res, Gate18Embargo)

	req := p4PublishRequest(t, p4Embargo(t), p4Day(t, 60))
	req.Embargo = other
	p4AssertRefused(t, CheckGate18Publication(req), Gate18Embargo, ReasonEmbargoFindingMismatch)
}

// TestGate18RefusesWithoutGate19sProof is the wiring between the two gates:
// an embargo that exists only in memory does not publish, because tmpfs does
// not survive a reboot and neither does a local variable.
func TestGate18RefusesWithoutGate19sProof(t *testing.T) {
	emb := p4Embargo(t)
	req := p4PublishRequest(t, emb, p4Day(t, 60))
	req.Persisted = PersistedDisclosure{}
	p4AssertRefused(t, CheckGate18Publication(req), Gate18Embargo,
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
			bad := p4PublishRequest(t, emb, p4Day(t, 60))
			bad.Persisted = forged
			p4AssertRefused(t, CheckGate18Publication(bad), Gate18Embargo,
				ReasonPublicationStateNotPersisted)
		})
	}

	// A proof for a DIFFERENT finding is not a proof for this one.
	other, res := OpenEmbargo(p4ThirdParty(t), p4OtherFinding, p4Contact(t))
	p4AssertPassed(t, res, Gate18Embargo)
	req = p4PublishRequest(t, emb, p4Day(t, 60))
	req.Persisted = p4Persisted(t, other, DisclosureStateEmbargoed)
	p4AssertRefused(t, CheckGate18Publication(req), Gate18Embargo,
		ReasonPublicationStateNotPersisted)
}

func TestGate18RefusesAWithheldFinding(t *testing.T) {
	emb := p4Embargo(t)
	req := p4PublishRequest(t, emb, p4Day(t, 60))
	req.Persisted = p4Persisted(t, emb, DisclosureStateWithheld)
	p4AssertRefused(t, CheckGate18Publication(req), Gate18Embargo,
		ReasonPublicationFindingWithheld)
}

func TestGate18ZeroRequestRefuses(t *testing.T) {
	p4AssertRefused(t, CheckGate18Publication(PublicationRequest{}),
		Gate18Embargo, ReasonFindingUnidentified)

	req := PublicationRequest{Finding: p4Finding}
	p4AssertRefused(t, CheckGate18Publication(req),
		Gate18Embargo, ReasonEmbargoClockUnconstructed)
}

func TestGate18RefusesAnUnconstructedEmbargoForAThirdParty(t *testing.T) {
	res := CheckGate18Publication(PublicationRequest{
		Finding:   p4Finding,
		Ownership: p4ThirdParty(t),
		Now:       p4Day(t, 400),
	})
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoUnconstructed)
}

func TestOpenEmbargoNeedsAResolvedReportingChannel(t *testing.T) {
	// No document at all.
	absent := FetchSecurityTxt(nil, p4Day(t, 0))
	_, res := RecordVendorContact(absent, p4Day(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)

	// A document with no Contact field is malformed under RFC 9116.
	noContact := FetchSecurityTxt([]SecurityTxtDocument{{
		Location:  SecurityTxtWellKnown,
		Body:      []byte("Policy: https://vendor.example.com/vdp\nExpires: 2027-06-01T00:00:00Z\n"),
		Retrieved: true,
	}}, p4Day(t, 0))
	_, res = RecordVendorContact(noContact, p4Day(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)

	// A stale document resolves no channel.
	expired := FetchSecurityTxt([]SecurityTxtDocument{{
		Location: SecurityTxtWellKnown,
		Body: []byte("Contact: mailto:security@vendor.example.com\n" +
			"Expires: 2026-01-01T00:00:00Z\n"),
		Retrieved: true,
	}}, p4Day(t, 0))
	_, res = RecordVendorContact(expired, p4Day(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)

	// And the zero value, which is what a caller that never fetched has.
	_, res = RecordVendorContact(SecurityTxtResult{}, p4Day(t, 0))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoReportingChannel)
}

func TestOpenEmbargoRefusesWithoutAVendorContact(t *testing.T) {
	_, res := OpenEmbargo(p4ThirdParty(t), p4Finding, VendorContact{})
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoNoVendorContact)
}

func TestOpenEmbargoRefusesAnOperatorOwnedFinding(t *testing.T) {
	_, res := OpenEmbargo(p4OperatorOwned(t), p4Finding, p4Contact(t))
	p4AssertRefused(t, res, Gate18Embargo, ReasonEmbargoOperatorOwned)
}

func TestOpenEmbargoRefusesAnUnclassifiedOwnershipAndABadFinding(t *testing.T) {
	_, res := OpenEmbargo(Ownership{}, p4Finding, p4Contact(t))
	p4AssertRefused(t, res, Gate18Embargo, ReasonOwnershipUnclassified)

	for _, bad := range []FindingID{"", "anvil 2026", "anvil/2026", FindingID(strings.Repeat("a", 129))} {
		_, res := OpenEmbargo(p4ThirdParty(t), bad, p4Contact(t))
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
	p4AssertRefused(t, CheckGate19DisclosureStore(buffer),
		Gate19DisclosureStateInDB, ReasonDisclosureStoreWrongMedium)

	_, res = PersistDisclosureState(buffer, rec)
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
		_, res := PersistDisclosureState(store, rec)
		p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStoreWrongMedium)
	}
}

func TestGate19RefusesANilStore(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	p4AssertRefused(t, CheckGate19DisclosureStore(nil),
		Gate19DisclosureStateInDB, ReasonDisclosureStoreMissing)
	_, res = PersistDisclosureState(nil, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureStoreMissing)
}

func TestGate19RefusesAFailedOrSilentWrite(t *testing.T) {
	rec, res := NewDisclosureRecord(p4Embargo(t), DisclosureStateEmbargoed, p4Key(t))
	p4AssertPassed(t, res, Gate19DisclosureStateInDB)

	failing := &p4Store{medium: MediumRecordStoreSQLite, err: errors.New("disk is full")}
	p, res := PersistDisclosureState(failing, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureWriteFailed)
	if p.Valid() {
		t.Fatalf("a failed write produced a valid PersistedDisclosure")
	}

	silent := &p4Store{medium: MediumRecordStoreSQLite, silent: true}
	p, res = PersistDisclosureState(silent, rec)
	p4AssertRefused(t, res, Gate19DisclosureStateInDB, ReasonDisclosureWriteFailed)
	if p.Valid() {
		t.Fatalf("a sequence-zero write produced a valid PersistedDisclosure")
	}
}

func TestGate19RefusesAnUnconstructedRecord(t *testing.T) {
	_, res := PersistDisclosureState(p4RecordStore(), DisclosureRecord{})
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

	p, res := PersistDisclosureState(store, rec)
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
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushWithoutAttestation)

	// The patch is a well-formed, identified, small proposal — and it makes no
	// difference.
	if !req.Patch.Constructed() || req.Patch.Bytes() != 812 {
		t.Fatalf("the fixture patch is not the benign identified patch this test needs")
	}
}

func TestPushGateRefusesAnAttestationBoundToAnotherScope(t *testing.T) {
	req := p4PushRequest(t)
	req.Attestation = p4Attestation(t, p4OtherHash)
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes,
		ReasonPushAttestationScopeUnbound)
}

func TestPushGateRefusesAnExpiredAttestation(t *testing.T) {
	req := p4PushRequest(t)
	// The fixture attestation expires on day 19; day 40 is well past it.
	req.Now = p4Day(t, 40)
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushAttestationNotLive)

	// And a run before it was issued is equally not live.
	req.Now = p4Clock(t, p4AttIssued.Add(-24*time.Hour))
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushAttestationNotLive)
}

func TestPushGateRefusesWithoutAnEmbargoAndThereforeWithoutAVendorContact(t *testing.T) {
	req := p4PushRequest(t)
	req.Embargo = EmbargoState{}
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushNoEmbargoOpened)
}

func TestPushGateRefusesAnEmbargoForAnotherFinding(t *testing.T) {
	other, res := OpenEmbargo(p4ThirdParty(t), p4OtherFinding, p4Contact(t))
	p4AssertPassed(t, res, Gate18Embargo)

	req := p4PushRequest(t)
	req.Embargo = other
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushFindingMismatch)
}

func TestPushGateRefusesAnUnidentifiedPatchAndAnUnclassifiedDestination(t *testing.T) {
	req := p4PushRequest(t)
	req.Patch = PatchProposal{}
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushPatchUnidentified)

	req = p4PushRequest(t)
	req.Destination = Ownership{}
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushOwnershipUnclassified)

	req = p4PushRequest(t)
	req.Now = Clock{}
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushClockUnconstructed)

	req = p4PushRequest(t)
	req.Scope = Scope{}
	p4AssertRefused(t, PushGate(req), Gate20NoUnsolicitedFixes, ReasonPushScopeUnconstructed)
}

func TestPushGateZeroRequestRefuses(t *testing.T) {
	p4AssertRefused(t, PushGate(PushRequest{}),
		Gate20NoUnsolicitedFixes, ReasonPushPatchUnidentified)
}

func TestPushGatePermitsDeliveryToTheOperatorsOwnRepository(t *testing.T) {
	// No attestation, no scope, no embargo — and permitted, because gate 20 is
	// about repositories the operator does NOT control.
	res := PushGate(PushRequest{
		Finding:     p4Finding,
		Destination: p4OperatorOwned(t),
		Patch:       p4Patch(t),
		Now:         p4Day(t, 0),
	})
	p4AssertPassed(t, res, Gate20NoUnsolicitedFixes)
}

func TestPushGatePermitsAnAttestedThirdPartyDelivery(t *testing.T) {
	p4AssertPassed(t, PushGate(p4PushRequest(t)), Gate20NoUnsolicitedFixes)
}

// TestPushGateDoesNotRequireTheEmbargoToHaveElapsed records the deliberate
// choice in PushGate's doc comment: delivering the fix to the vendor is the
// coordinated half of coordinated disclosure, and requiring the clock to run
// out first would forbid the thing the clock exists to make room for.
func TestPushGateDoesNotRequireTheEmbargoToHaveElapsed(t *testing.T) {
	req := p4PushRequest(t)
	if req.Embargo.Elapsed(req.Now) {
		t.Fatalf("the fixture embargo has already elapsed; this test proves nothing")
	}
	p4AssertPassed(t, PushGate(req), Gate20NoUnsolicitedFixes)
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
	if _, res := NewGateAudit(&recordingSink{}, zero); res.Passed() {
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

	if _, res := NewGateAudit(nil, p4Key(t)); res.Passed() {
		t.Fatalf("NewGateAudit accepted a nil sink")
	} else {
		p4AssertRefused(t, res, Gate21ImmutableAudit, ReasonAuditSinkMissing)
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
	req := p4PublishRequest(t, emb, p4Day(t, 60))

	// The gate itself permits: the clock has run out and the state is
	// persisted.
	p4AssertPassed(t, CheckGate18Publication(req), Gate18Embargo)

	audit := p4Audit(t, failingSink{err: errors.New("audit table is read-only")})
	out := audit.AuditedPublication(req)
	if out.Passed() {
		t.Fatalf("a finding was cleared for publication with no audit row behind it")
	}
	if out.Gate() != Gate21ImmutableAudit {
		t.Fatalf("the refusal is attributed to %s; want gate 21", out.Gate())
	}

	// And with a working sink it permits, and the row names the finding.
	sink := &recordingSink{}
	audit = p4Audit(t, sink)
	out = audit.AuditedPublication(req)
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
	p4AssertPassed(t, PushGate(req), Gate20NoUnsolicitedFixes)

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

	p, out := audit.AuditedPersistDisclosure(store, rec, p4Day(t, 0))
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
		Now:       p4Day(t, 60),
	}
	p4AssertRefused(t, CheckGate18Publication(req), Gate18Embargo,
		ReasonPublicationStateNotPersisted)

	// With a working audit sink the proof is minted and publication clears.
	audit = p4Audit(t, &recordingSink{})
	p, out = audit.AuditedPersistDisclosure(store, rec, p4Day(t, 0))
	p4AssertPassed(t, out, Gate19DisclosureStateInDB)
	req.Persisted = p
	p4AssertPassed(t, CheckGate18Publication(req), Gate18Embargo)
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
		res := CheckGate19DisclosureStore(&p4Store{medium: medium})
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

	audit.AuditedPublication(p4PublishRequest(t, emb, p4Day(t, 60)))
	audit.AuditedPush(p4PushRequest(t))
	rec, _ := NewDisclosureRecord(emb, DisclosureStateEmbargoed, p4Key(t))
	audit.AuditedPersistDisclosure(p4RecordStore(), rec, p4Day(t, 0))

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

// TestHTTPHeaderTypeIsNotReachableFromPhase4 is a small shape guard: nothing
// in this file takes an http.Header, an io.Reader or any other extension
// point through which a scanned response body could arrive at a disclosure
// decision.
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
