// confirm_gate_test.go is D.27's evidence.
//
// Two of these tests are named in plan/50-dast.md as the packet's stop
// condition and neither is a formality:
//
//	TestPhantomSQLiClusterIsDemotedAndTheRealOnesSurvive
//	    "A fixture reproducing something shaped like the 88-phantom-SQLi ZAP
//	    scenario (an engine emits N candidate SQLi findings against a target
//	    known not to have them) and asserting the confirmation gate
//	    demotes/drops the false positives rather than passing them through".
//	    It carries a positive control: a gate that rejected everything would
//	    pass the negative half and is caught by the two real findings.
//
//	TestFindingTypeClosureHasNoRawBodyPath
//	TestNoFindingReachableStringExceedsTheSpanLimit
//	    "a reflection-based test confirming no Finding-reachable field can
//	    hold a value longer than the regex-extracted-span length limit
//	    (proving raw-body inlining is structurally impossible, not just
//	    avoided by convention)". The first is the type half, the second the
//	    value half, and each is itself checked against a fixture that
//	    violates it — a walker that cannot report a violation would pass on
//	    Finding for the wrong reason.
package record

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	rec "github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// sqliMarker is the string a real SQL-injection probe makes the target emit.
const sqliMarker = "You have an error in your SQL syntax near 'anvil-probe-4f2a'"

// sqliPattern is the oracle. It is a literal, so a body that does not contain
// it does not match, which is the entire mechanism by which 88 phantom
// findings die.
const sqliPattern = `You have an error in your SQL syntax near '[a-z0-9-]{1,32}'`

// spanBoundaryPattern is a probe-marker PAIR: an oracle narrow enough that no
// generated benign body matches it, and greedy enough to swallow everything
// between its two markers.
//
// IT HAS BEEN REWRITTEN TWICE AND BOTH REWRITES ARE THE CHECK GETTING
// STRICTER, not the fixture getting weaker:
//
//	`(?s)A.*B`                     refused by the BACKSTOP: generated prose
//	                               capitalises sentence openings, so a body
//	                               with an 'A' before a 'B' is an ordinary
//	                               body.
//	`(?s)ANVIL-...BEGIN.*...END`   refused by the CONTROL, rule R2: `.` under
//	                               (?s) is an open position, and a signature
//	                               may not match through bytes extractSpan
//	                               drops.
//
// What is left declares the shape of what it will quote: `[0-9A-Za-z]` is
// printable ASCII (R2) and carries no separator, so it is not content-bearing
// and R3 lets it repeat without a ceiling. THAT IS THE RESIDUAL THIS FIXTURE
// EMBODIES — an unbounded token-shaped class can still swallow a whole body,
// which is exactly why the span bound is still needed and why this fixture
// still has a job.
const spanBoundaryPattern = `ANVIL-SPAN-BEGIN[0-9A-Za-z]*ANVIL-SPAN-END`

// scriptedReprober is the re-probe seam under test control.
//
// It can produce EVERY input the gate is supposed to handle differently:
// a matching body, a non-matching body, a body that matches on some attempts
// and not others, a hostile 512 KiB body, an error, and "nothing was issued".
// A generator that could not produce one of those would make the
// corresponding assertion vacuous.
type scriptedReprober struct {
	body      func(c RawFinding, attempt int) []byte
	status    int
	err       error
	notIssued bool

	// statusFn overrides status per attempt. It is what lets a fixture
	// produce a target whose rate limiter trips PART WAY THROUGH the
	// confirmation pass, which is the input the mixed-run assertion needs
	// and which a single `status` field cannot express.
	statusFn func(c RawFinding, attempt int) int
	// errFn overrides err per attempt, for the connection-reset case where
	// one attempt fails and the others do not.
	errFn func(c RawFinding, attempt int) error

	calls    int
	perPath  map[string]int
	lastAtt  int
	observed []string
}

func (r *scriptedReprober) Reprobe(ctx context.Context, c RawFinding, attempt int) (Observation, error) {
	r.calls++
	r.lastAtt = attempt
	if r.perPath == nil {
		r.perPath = map[string]int{}
	}
	r.perPath[c.Path]++
	r.observed = append(r.observed, fmt.Sprintf("%s %s #%d", c.Method, c.Path, attempt))
	if r.errFn != nil {
		if err := r.errFn(c, attempt); err != nil {
			return Observation{}, err
		}
	}
	if r.err != nil {
		return Observation{}, r.err
	}
	if r.notIssued {
		return Observation{Issued: false}, nil
	}
	// statusFn's value is used VERBATIM, 0 included: "the re-probe reported
	// no HTTP status" is one of the inputs the gate must handle differently
	// and a fixture that silently rewrote 0 to 200 could not produce it.
	status := r.status
	switch {
	case r.statusFn != nil:
		status = r.statusFn(c, attempt)
	case status == 0:
		status = 200
	}
	var b []byte
	if r.body != nil {
		b = r.body(c, attempt)
	}
	return Observation{Issued: true, Status: status, Body: b}, nil
}

func mustSignature(t *testing.T, pattern string) Signature {
	t.Helper()
	s, err := NewSignature(pattern)
	if err != nil {
		t.Fatalf("NewSignature(%q): %v", pattern, err)
	}
	return s
}

// sqliCandidate is one phantom-shaped candidate.
func sqliCandidate(t *testing.T, path string) RawFinding {
	t.Helper()
	return RawFinding{
		Engine:          "zap",
		Target:          "http://127.0.0.1:8080 [127.0.0.1:8080]",
		Method:          "GET",
		Path:            path,
		Class:           ClassInjection,
		DetectionMethod: DetectionMethodTemplate,
		TemplateID:      "zap-40018-sqli",
		TemplateDigest:  strings.Repeat("a", 64),
		Signature:       mustSignature(t, sqliPattern),
	}
}

func mustGate(t *testing.T, cfg GateConfig) *Gate {
	t.Helper()
	g, err := NewGate(cfg)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g
}

// ---------------------------------------------------------------------------
// THE STOP CONDITION, HALF 1 — the 88 phantom SQL-injection findings
// ---------------------------------------------------------------------------

// TestPhantomSQLiClusterIsDemotedAndTheRealOnesSurvive is the fixture
// research/15-dast-tooling-landscape.md's ZAP entry describes: an engine
// emits a cluster of SQL-injection candidates against a target that has none.
//
// THE POSITIVE CONTROL IS THE POINT. A gate that rejected every candidate
// would satisfy "the phantoms are dropped" perfectly and be useless, so two
// candidates in this batch are real — the re-probe target emits the SQL error
// for them — and the test asserts BOTH counts. Asserting only that the
// phantom count fell to zero is the len(x)>0 mistake in the other direction.
func TestPhantomSQLiClusterIsDemotedAndTheRealOnesSurvive(t *testing.T) {
	const phantoms = 88

	// The target: /search?q= is genuinely injectable; nothing else is. The
	// engine reported all 90 as SQL injection.
	rp := &scriptedReprober{
		body: func(c RawFinding, attempt int) []byte {
			if strings.HasPrefix(c.Path, "/search") {
				return []byte(`{"error":"` + sqliMarker + `"}`)
			}
			return []byte(`{"ok":true,"items":[]}`)
		},
	}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})

	var candidates []RawFinding
	for i := 0; i < phantoms; i++ {
		candidates = append(candidates, sqliCandidate(t, fmt.Sprintf("/api/v1/item/%d", i)))
	}
	candidates = append(candidates,
		sqliCandidate(t, "/search"),
		sqliCandidate(t, "/search/advanced"),
	)

	l, err := g.ConfirmAll(context.Background(), candidates)
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}

	// ASSERT THE COUNT, NOT MERELY THAT ROWS EXIST.
	if got, want := l.CandidateCount(), phantoms+2; got != want {
		t.Fatalf("candidate count = %d, want %d; %s", got, want, l)
	}
	if got, want := l.RejectedCount(), phantoms; got != want {
		t.Errorf("rejected = %d, want %d (the phantom cluster). %s", got, want, l)
	}
	if got, want := l.ConfirmedCount(), 2; got != want {
		t.Errorf("confirmed = %d, want %d. A gate that drops the phantoms AND the real "+
			"findings has not confirmed anything, it has stopped reporting. %s", got, want, l)
	}
	if got := l.UnconfirmedCount(); got != 0 {
		t.Errorf("unconfirmed = %d, want 0: an oracle-bearing class with a decisive "+
			"re-probe has no route to unconfirmed. %s", got, l)
	}
	if got := l.RefusedCount(); got != 0 {
		t.Errorf("refused = %d, want 0; every candidate was well-formed. %v", got, l.Refusals())
	}

	// The number that reaches the record.
	if got, want := l.FindingCountForStatus(), 2; got != want {
		t.Errorf("FindingCountForStatus = %d, want %d: only confirmed findings count", got, want)
	}

	// Every request that left the process. 90 candidates times 3 attempts.
	if got, want := rp.calls, (phantoms+2)*3; got != want {
		t.Errorf("re-probes issued = %d, want %d; a candidate confirmed without being "+
			"re-probed the full number of attempts is a candidate that was not confirmed",
			got, want)
	}

	// Per-finding shape, both halves.
	var confirmedPaths, rejectedPaths []string
	for _, f := range l.Findings() {
		switch f.Outcome() {
		case OutcomeConfirmed:
			confirmedPaths = append(confirmedPaths, f.Path())
			if f.Reason() != ReasonReproduced {
				t.Errorf("%s: confirmed with reason %q", f.Path(), f.Reason())
			}
			if c, ok := f.Confidence(); !ok || c != 1.0 {
				t.Errorf("%s: confidence = (%v,%v), want (1,true) for 3/3 reproduction",
					f.Path(), c, ok)
			}
			if got := f.Evidence().ExtractedSpan(); !strings.Contains(got, "SQL syntax") {
				t.Errorf("%s: confirmed finding's span is %q; it must be the regex match "+
					"from the body that reproduced", f.Path(), got)
			}
		case OutcomeRejected:
			rejectedPaths = append(rejectedPaths, f.Path())
			if f.Reason() != ReasonDidNotReproduce {
				t.Errorf("%s: rejected with reason %q", f.Path(), f.Reason())
			}
			if f.CountsAsFinding() {
				t.Errorf("%s: a rejected finding counts toward dast_status findings", f.Path())
			}
			if got := f.Evidence().ExtractedSpan(); got != "" {
				t.Errorf("%s: rejected finding carries a span %q; nothing matched, so there "+
					"is nothing to inline", f.Path(), got)
			}
			if f.Evidence().BodyHash() == "" {
				t.Errorf("%s: rejected finding carries no body hash. The hash is the proof "+
					"Anvil looked; without it a rejection is indistinguishable from a "+
					"candidate that was never probed", f.Path())
			}
		default:
			t.Errorf("%s: unexpected outcome %q", f.Path(), f.Outcome())
		}
	}
	if len(confirmedPaths) != 2 || len(rejectedPaths) != phantoms {
		t.Fatalf("confirmed %v, rejected %d paths", confirmedPaths, len(rejectedPaths))
	}

	// This ledger has confirmed findings, so it is not silently clean.
	if err := l.AssertNotSilentlyClean(); err != nil {
		t.Errorf("AssertNotSilentlyClean on a ledger with 2 confirmed findings: %v", err)
	}
}

// TestEightyEightPhantomsAloneProduceCompletedCleanAndThatIsHonest is the
// other half of the same scenario, and it is the one that decides what the
// record says.
//
// With ONLY the phantoms in the batch, the confirmed count is zero and
// record.DeriveDastStatus produces DastStatusCompletedClean. That is not the
// gate hiding findings: 88 candidates were re-probed three times each and
// none reproduced. AssertNotSilentlyClean therefore returns nil here — the
// clean verdict is earned — and the same call fires when the zero comes from
// candidates nobody could decide about. Both directions are asserted.
func TestEightyEightPhantomsAloneProduceCompletedCleanAndThatIsHonest(t *testing.T) {
	const phantoms = 88
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return []byte(`{"ok":true}`) }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})

	var candidates []RawFinding
	for i := 0; i < phantoms; i++ {
		candidates = append(candidates, sqliCandidate(t, fmt.Sprintf("/api/v1/item/%d", i)))
	}
	l, err := g.ConfirmAll(context.Background(), candidates)
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	if got, want := l.RejectedCount(), phantoms; got != want {
		t.Fatalf("rejected = %d, want %d", got, want)
	}
	if got := l.FindingCountForStatus(); got != 0 {
		t.Fatalf("FindingCountForStatus = %d, want 0", got)
	}
	if err := l.AssertNotSilentlyClean(); err != nil {
		t.Errorf("AssertNotSilentlyClean fired on a ledger whose zero was earned by "+
			"disproving every candidate: %v", err)
	}

	status, err := rec.DeriveDastStatus(rec.HalfStatusSealed, rec.DastOutcome{
		TierInstalled: true,
		Provenance:    rec.TargetProvenanceBootedClean,
		FindingCount:  l.FindingCountForStatus(),
	})
	if err != nil {
		t.Fatalf("DeriveDastStatus: %v", err)
	}
	if status != rec.DastStatusCompletedClean {
		t.Errorf("dast_status = %q, want %q. 88 disproved candidates must not reach "+
			"completed_findings", status, rec.DastStatusCompletedClean)
	}

	// The positive control on the same mapping: one confirmed finding moves
	// it. Without this, the assertion above would pass for a
	// FindingCountForStatus that was hard-wired to zero.
	moved, err := rec.DeriveDastStatus(rec.HalfStatusSealed, rec.DastOutcome{
		TierInstalled: true,
		Provenance:    rec.TargetProvenanceBootedClean,
		FindingCount:  1,
	})
	if err != nil {
		t.Fatalf("DeriveDastStatus: %v", err)
	}
	if moved != rec.DastStatusCompletedFindings {
		t.Fatalf("a finding count of 1 produced %q, so the assertion above proves nothing",
			moved)
	}
}

// TestOnlyConfirmedFindingsReachDastStatusFindings is the numerator claim, and
// it exists because the two tests above did not prove it.
//
// FOUND BY BREAKING THE GUARD. FindingCountForStatus was mutated to
// `ConfirmedCount() + UnconfirmedCount()` — the exact defect the D.27
// forbidden-actions clause describes — and both phantom fixtures STAYED GREEN,
// because neither of them ever puts an unconfirmed finding in the same ledger
// as the status assertion. Zero plus zero is zero. The assertion was true and
// vacuous.
//
// This ledger holds all three outcomes at once, which is the only shape in
// which the sum and the confirmed count differ.
func TestOnlyConfirmedFindingsReachDastStatusFindings(t *testing.T) {
	const phantoms = 88
	const undecidable = 3

	rp := &scriptedReprober{body: func(c RawFinding, _ int) []byte {
		if strings.HasPrefix(c.Path, "/search") || strings.HasPrefix(c.Path, "/admin") {
			return []byte(`{"error":"` + sqliMarker + `"}`)
		}
		return []byte(`{"ok":true}`)
	}}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})

	var candidates []RawFinding
	for i := 0; i < phantoms; i++ {
		candidates = append(candidates, sqliCandidate(t, fmt.Sprintf("/api/v1/item/%d", i)))
	}
	for i, class := range []Class{ClassAuthorization, ClassIDOR, ClassBusinessLogic} {
		c := sqliCandidate(t, fmt.Sprintf("/admin/%d", i))
		c.Class = class
		candidates = append(candidates, c)
	}

	l, err := g.ConfirmAll(context.Background(), candidates)
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	if got, want := l.RejectedCount(), phantoms; got != want {
		t.Fatalf("rejected = %d, want %d", got, want)
	}
	if got, want := l.UnconfirmedCount(), undecidable; got != want {
		t.Fatalf("unconfirmed = %d, want %d; without unconfirmed findings in this ledger "+
			"the assertion below cannot distinguish ConfirmedCount() from "+
			"ConfirmedCount()+UnconfirmedCount()", got, want)
	}
	if got := l.ConfirmedCount(); got != 0 {
		t.Fatalf("confirmed = %d, want 0", got)
	}

	// THE CLAIM. 91 candidates decided, 3 of them undecidable, and the
	// number that reaches the record is zero.
	if got := l.FindingCountForStatus(); got != 0 {
		t.Errorf("FindingCountForStatus = %d, want 0. plan/50-dast.md D.27: \"No finding "+
			"reaches dast_status: findings without having passed a re-probe confirmation "+
			"step.\" An unconfirmed finding is by definition one that did not pass it", got)
	}
	status, derr := rec.DeriveDastStatus(rec.HalfStatusSealed, rec.DastOutcome{
		TierInstalled: true,
		Provenance:    rec.TargetProvenanceBootedClean,
		FindingCount:  l.FindingCountForStatus(),
	})
	if derr != nil {
		t.Fatalf("DeriveDastStatus: %v", derr)
	}
	if status != rec.DastStatusCompletedClean {
		t.Errorf("dast_status = %q, want %q", status, rec.DastStatusCompletedClean)
	}

	// ...and this is exactly the case where completed_clean would be a lie
	// if it were shipped unqualified, so the ledger says so.
	if aerr := l.AssertNotSilentlyClean(); !errors.Is(aerr, ErrSilentlyClean) {
		t.Errorf("AssertNotSilentlyClean = %v, want ErrSilentlyClean: 3 findings nothing "+
			"could decide sit in this ledger and the derived status says the target was "+
			"scanned clean", aerr)
	}

	// The positive control: adding one genuinely confirmed finding moves
	// both the count and the status.
	withReal := append(append([]RawFinding(nil), candidates...), sqliCandidate(t, "/search"))
	l2, err := g.ConfirmAll(context.Background(), withReal)
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	if got, want := l2.ConfirmedCount(), 1; got != want {
		t.Fatalf("confirmed = %d, want %d", got, want)
	}
	if got, want := l2.FindingCountForStatus(), 1; got != want {
		t.Errorf("FindingCountForStatus = %d, want %d", got, want)
	}
	if got, want := l2.UnconfirmedCount(), undecidable; got != want {
		t.Fatalf("unconfirmed = %d, want %d", got, want)
	}
	status2, derr := rec.DeriveDastStatus(rec.HalfStatusSealed, rec.DastOutcome{
		TierInstalled: true,
		Provenance:    rec.TargetProvenanceBootedClean,
		FindingCount:  l2.FindingCountForStatus(),
	})
	if derr != nil {
		t.Fatalf("DeriveDastStatus: %v", derr)
	}
	if status2 != rec.DastStatusCompletedFindings {
		t.Errorf("dast_status = %q, want %q", status2, rec.DastStatusCompletedFindings)
	}
}

// ---------------------------------------------------------------------------
// THE STOP CONDITION, HALF 2 — no raw-body path out of Finding
// ---------------------------------------------------------------------------

// closureViolations walks the transitive field-type closure of typ and
// returns one string per kind of field a response body could travel through.
//
// The allowlist is the point. Finding is strings, named string enums,
// integers, a float and bools, nested in structs. Anything else — a []byte, a
// pointer, a slice, a map, an interface, a func, a channel — is either a body
// carrier or a route to one, and it fails here rather than being argued about
// in review.
//
// Types outside this module are not exempt: their KIND is still checked, so
// an io.Reader field or a *bytes.Buffer field fails exactly as a local one
// would.
//
// ===========================================================================
// THE SUBJECT IS A ROUTE, NOT A TYPE, AND THE DEDUP KEY USED TO SAY OTHERWISE
// ===========================================================================
//
// This walk used to mark seen[reflect.Type] on entry and return early on a
// repeat. That answers "have I visited this TYPE" when the question this test
// asks is "have I visited this ROUTE", and deduplicating by type merges two
// distinct routes into one report. MEASURED against the previous shape:
//
//	struct{ Left, Right zzCarrier }, zzCarrier{ Payload []byte }
//	  TWO routes to a raw body, ONE reported — the second is skipped
//	  because zzCarrier was already marked.
//	struct{ Head string; Body, Raw []byte }
//	  TWO byte-sequence fields, ONE reported. Adding `Raw []byte` after
//	  `Body` on Observation left the whole package GREEN.
//
// A guard that exists to stop a raw body reaching a consumer must not be
// defeatable by putting the field second. There is no dedup here now.
//
// NOTHING IS LOST BY DROPPING IT, because the dedup was never what made this
// terminate. GO'S OWN TYPE RULES DO: a struct may not contain itself, directly
// or through arrays, so the part of the closure this walk DESCENDS INTO is
// finite and acyclic by construction — and every kind that could reintroduce a
// cycle (pointer, slice, map, interface, func, chan) is REPORTED and returned
// from rather than followed. TestFindingTypeClosureHasNoRawBodyPath drives a
// self-referential fixture to keep that from being a claim about today's
// compiler.
//
// closureWalkNodeBudget bounds the one thing those rules leave open: struct
// nesting that SHARES sub-types can have a route count exponential in its
// depth, and without a dedup key nothing collapses those routes. EXHAUSTING
// THE BUDGET IS ITSELF A REPORTED VIOLATION, so it is not room an attacker can
// step outside — a type too large for this walk is a type this test refuses to
// vouch for, which is the fail-closed direction.
const closureWalkNodeBudget = 1 << 16

func closureViolations(typ reflect.Type) []string {
	var out []string
	budget := closureWalkNodeBudget
	var walk func(path string, t reflect.Type)
	walk = func(path string, t reflect.Type) {
		if t == nil {
			return
		}
		budget--
		if budget < 0 {
			if budget == -1 {
				out = append(out, fmt.Sprintf("the walk of %s exhausted its %d-node "+
					"budget at %s: this type's field-type closure is too large to "+
					"vouch for, and an unfinished walk is not a clean one",
					typ, closureWalkNodeBudget, path))
			}
			return
		}
		switch t.Kind() {
		case reflect.String, reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			return
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				walk(path+"."+f.Name, f.Type)
			}
			return
		case reflect.Slice, reflect.Array:
			if t.Elem().Kind() == reflect.Uint8 {
				out = append(out, fmt.Sprintf("%s is %s: a byte sequence is a raw response "+
					"body, and plan/00-SPINE.md S7 forbids inlining one", path, t))
				return
			}
			out = append(out, fmt.Sprintf("%s is %s: a sequence field makes the total string "+
				"a Finding can hold unbounded, so the span limit stops meaning anything",
				path, t))
			return
		case reflect.Pointer, reflect.Map, reflect.Interface, reflect.Func,
			reflect.Chan, reflect.UnsafePointer:
			out = append(out, fmt.Sprintf("%s is a %s (%s): it is a reference through which a "+
				"body can be reached, and it also makes a Finding copy shallow", path,
				t.Kind(), t))
			return
		default:
			out = append(out, fmt.Sprintf("%s is an unhandled kind %s (%s)", path, t.Kind(), t))
			return
		}
	}
	walk(typ.Name(), typ)
	return out
}

// bodyCarrier is the fixture that proves closureViolations can SEE a
// violation. A walker that reported clean on everything would pass on Finding
// for entirely the wrong reason.
type bodyCarrier struct {
	Hash string
	Body []byte
	Next *bodyCarrier
	Sink func([]byte)
	Bag  map[string]string
	Any  any
}

func TestFindingTypeClosureHasNoRawBodyPath(t *testing.T) {
	// The generator first: the walker must be able to produce the breaking
	// input, or its silence on Finding is worthless.
	got := closureViolations(reflect.TypeOf(bodyCarrier{}))
	wantSubstrings := []string{".Body", ".Next", ".Sink", ".Bag", ".Any"}
	if len(got) != len(wantSubstrings) {
		t.Fatalf("closureViolations found %d violations in the fixture, want %d: %v",
			len(got), len(wantSubstrings), got)
	}
	joined := strings.Join(got, "\n")
	for _, w := range wantSubstrings {
		if !strings.Contains(joined, w) {
			t.Fatalf("closureViolations missed %s in the fixture; it cannot see the damage "+
				"and therefore proves nothing about Finding:\n%s", w, joined)
		}
	}

	// The claim.
	if v := closureViolations(reflect.TypeOf(Finding{})); len(v) != 0 {
		t.Errorf("Finding's field-type closure has %d route(s) a raw response body could "+
			"travel through. plan/50-dast.md D.27: \"This gate's output type must make "+
			"'the model reads the raw body' a type error, not a discipline problem\":\n%s",
			len(v), strings.Join(v, "\n"))
	}

	// The same claim for what a Ledger hands out, since that is what a
	// consumer actually holds.
	if v := closureViolations(reflect.TypeOf(EvidenceRef{})); len(v) != 0 {
		t.Errorf("EvidenceRef's closure has %d body route(s):\n%s", len(v), strings.Join(v, "\n"))
	}

	// And the negative control on the OTHER side of the boundary:
	// Observation is the one type that IS allowed to carry a body, and if it
	// stopped doing so the gate would be extracting evidence from nothing.
	if v := closureViolations(reflect.TypeOf(Observation{})); len(v) == 0 {
		t.Error("Observation's closure carries no byte sequence. It is the re-probe seam's " +
			"return value and it is supposed to hold the body; a clean walk here means " +
			"the body arrives some other way and this whole test is watching the wrong type")
	}

	// =====================================================================
	// EVERY ROUTE, NOT EVERY TYPE. See closureViolations' header.
	// =====================================================================
	//
	// The walk used to mark seen[reflect.Type] on entry, which silently
	// skipped the SECOND route to a raw body anywhere in a closure. These
	// two fixtures are the two spellings of that, and each reported ONE
	// violation before the key changed.
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		want []string
		why  string
	}{
		{
			name: "a shared struct type on two routes",
			typ:  reflect.TypeOf(twoRouteCarrier{}),
			want: []string{".Left.Payload", ".Right.Payload"},
			why: "one TYPE, two ROUTES. Keying the walk by type answers the wrong " +
				"question and reports only the route it happened to reach first",
		},
		{
			name: "a second byte sequence beside the first",
			typ:  reflect.TypeOf(twoBodyFields{}),
			want: []string{".Body", ".Raw"},
			why: "MEASURED: adding `Raw []byte` after `Body` on Observation left the " +
				"whole package green. A guard against raw bodies that can be beaten " +
				"by putting the field second is not a guard",
		},
	} {
		got := closureViolations(tc.typ)
		if len(got) != len(tc.want) {
			t.Errorf("closureViolations(%s) found %d violation(s), want %d — %s:\n%s",
				tc.name, len(got), len(tc.want), tc.why, strings.Join(got, "\n"))
			continue
		}
		joined := strings.Join(got, "\n")
		for _, w := range tc.want {
			if !strings.Contains(joined, w) {
				t.Errorf("closureViolations(%s) missed %s — %s:\n%s",
					tc.name, w, tc.why, joined)
			}
		}
	}

	// THE MUTATION, RUN AGAINST EVERY TYPE THIS TEST VOUCHES FOR rather than
	// against one of them. Each is doubled and given two byte sequences; a
	// route-keyed walk must report twice whatever the clean type reports,
	// plus both new routes. A type-keyed one reports the clean count plus
	// one, whatever it is handed.
	rawBytes := reflect.TypeOf([]byte(nil))
	for _, base := range []reflect.Type{
		reflect.TypeOf(Finding{}),
		reflect.TypeOf(EvidenceRef{}),
		reflect.TypeOf(Observation{}),
		reflect.TypeOf(bodyCarrier{}),
	} {
		clean := len(closureViolations(base))
		doubled := reflect.StructOf([]reflect.StructField{
			{Name: "First", Type: base},
			{Name: "Second", Type: base},
			{Name: "Raw", Type: rawBytes},
			{Name: "Also", Type: rawBytes},
		})
		got, want := len(closureViolations(doubled)), 2*clean+2
		if got != want {
			t.Errorf("a struct holding %s TWICE plus two []byte fields reports %d "+
				"violation(s), want %d (2 x %d clean, plus both raw fields). Every "+
				"route to a body has to be reported, not every distinct type",
				base, got, want, clean)
		}
	}

	// TERMINATION WITHOUT A DEDUP KEY, since dropping the key is what makes
	// the two fixtures above work and "it still terminates" is the thing
	// that claim rests on. bodyCarrier is self-referential through
	// `Next *bodyCarrier`; the walk reports the pointer and does not follow
	// it, which is why reaching here at all is the assertion.
	if !strings.Contains(strings.Join(closureViolations(reflect.TypeOf(bodyCarrier{})), "\n"),
		"bodyCarrier.Next is a ptr") {
		t.Error("the self-referential field is not reported as a pointer. The walk " +
			"terminates because every kind that could close a cycle is reported and " +
			"NOT descended into; if that stops being true, removing the dedup key " +
			"stops being safe")
	}

	// AND THE BUDGET FAILS CLOSED. Struct nesting that shares sub-types has
	// a route count exponential in its depth, so the walk is bounded — and
	// the bound has to REPORT rather than return quietly, or it is exactly
	// the kind of ceiling an attacker steps outside.
	wide := reflect.TypeOf(false)
	for i := 0; i < 17; i++ {
		wide = reflect.StructOf([]reflect.StructField{
			{Name: "A", Type: wide},
			{Name: "B", Type: wide},
		})
	}
	over := closureViolations(wide)
	if len(over) != 1 || !strings.Contains(over[0], "exhausted its") {
		t.Errorf("a %d-route type with no forbidden kind in it reported %v; the node "+
			"budget is supposed to report a violation when it runs out, because an "+
			"unfinished walk is not a clean one", 1<<17, over)
	}
}

// twoRouteCarrier and twoBodyFields are the two spellings of the dedup defect
// closureViolations used to have. Each reported ONE violation while the walk
// was keyed by reflect.Type; each has TWO routes to a raw response body.
type payloadCarrier struct{ Payload []byte }

type twoRouteCarrier struct {
	Left  payloadCarrier
	Right payloadCarrier
}

type twoBodyFields struct {
	Head string
	Body []byte
	Raw  []byte
}

// oversizedStrings walks a VALUE and returns every reachable string longer
// than limit, unexported fields included.
//
// reflect.Value.String() reads an unexported string field without panicking,
// which is what lets this see the fields the type deliberately does not
// export. Interface() would panic, so it is never called.
func oversizedStrings(path string, v reflect.Value, limit int) []string {
	var out []string
	switch v.Kind() {
	case reflect.String:
		if s := v.String(); len(s) > limit {
			out = append(out, fmt.Sprintf("%s holds %d bytes (limit %d)", path, len(s), limit))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			out = append(out, oversizedStrings(path+"."+v.Type().Field(i).Name, v.Field(i), limit)...)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			out = append(out, oversizedStrings(fmt.Sprintf("%s[%d]", path, i), v.Index(i), limit)...)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			out = append(out, oversizedStrings(path+"*", v.Elem(), limit)...)
		}
	}
	return out
}

func TestNoFindingReachableStringExceedsTheSpanLimit(t *testing.T) {
	// The generator, again first: a 512 KiB body whose regex match is the
	// WHOLE body. `(?s).*` is the breaking input for the span bound, and a
	// gate that only truncated short matches would pass a test that never
	// produced one.
	const bodyBytes = 512 * 1024
	// sqliMarker sits OUTSIDE the marker pair: spanBoundaryPattern's middle
	// is a token-shaped class now (see there), and the marker's spaces and
	// quotes would end the run rather than be swallowed by it.
	hostile := []byte(sqliMarker + "ANVIL-SPAN-BEGIN" + strings.Repeat("A", bodyBytes/2) +
		strings.Repeat("B", bodyBytes/2) + "ANVIL-SPAN-END")

	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return hostile }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 2})

	c := sqliCandidate(t, "/search")
	// matches essentially the entire body; see spanBoundaryPattern for why it
	// is a marker pair and not `(?s)A.*B`.
	c.Signature = mustSignature(t, spanBoundaryPattern)

	f, err := g.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	if f.Outcome() != OutcomeConfirmed {
		t.Fatalf("outcome = %q; the fixture is supposed to reproduce so that a CONFIRMED "+
			"finding is the thing being walked", f.Outcome())
	}
	if f.Evidence().SpanOverBroadBytes() < bodyBytes {
		t.Fatalf("SpanOverBroadBytes = %d; the match was supposed to be ~%d bytes, so this "+
			"fixture is not exercising the bound", f.Evidence().SpanOverBroadBytes(), bodyBytes)
	}
	// AND THE SPAN IS EMPTY, not 512 bytes of the body.
	//
	// This assertion is the fix for what the previous shape of this field
	// hid. `spanTruncatedFrom` recorded that a 512 KiB match had been cut
	// down to MaxSpanBytes — and the 512 bytes that survived were a
	// VERBATIM PREFIX OF THE RESPONSE, arriving through the one channel
	// spine S7 sanctions. Every assertion in this test passed while that
	// was happening, because every assertion was about LENGTH.
	if got := f.Evidence().ExtractedSpan(); got != "" {
		t.Errorf("an over-broad match produced a %d-byte span %q. A prefix of an arbitrary "+
			"response body is not evidence at any length; there is no span here",
			len(got), printable(got, 64))
	}

	// The claim, over every string reachable from the value a consumer
	// holds — unexported fields included.
	if v := oversizedStrings("Finding", reflect.ValueOf(*f), MaxSpanBytes); len(v) != 0 {
		t.Errorf("a Finding built from a %d-byte response body holds string(s) longer than "+
			"MaxSpanBytes=%d:\n%s", bodyBytes, MaxSpanBytes, strings.Join(v, "\n"))
	}

	// The walker must be able to see the damage.
	bad := Finding{engine: strings.Repeat("x", MaxSpanBytes+1)}
	if v := oversizedStrings("Finding", reflect.ValueOf(bad), MaxSpanBytes); len(v) != 1 {
		t.Fatalf("oversizedStrings found %d violations in a Finding with a deliberately "+
			"over-long unexported field, want 1; it cannot read unexported strings and "+
			"proves nothing: %v", len(v), v)
	}

	// And the whole body must not be anywhere in the finding's rendering
	// either: String() is a log line, and a log line is a prompt often
	// enough.
	if len(f.String()) > 4096 {
		t.Errorf("Finding.String() is %d bytes", len(f.String()))
	}
	if strings.Contains(f.String(), strings.Repeat("A", 64)) {
		t.Error("Finding.String() quotes the response body")
	}
}

// TestExtractedSpanIsBoundedPrintableAndDropsRatherThanSubstitutes covers the
// three properties extractSpan documents, each with an input that breaks it.
//
// IT COMPILES ITS FIXTURE DIRECTLY, BYPASSING NewSignature, and that is
// deliberate rather than convenient. `(?s)<v>.*</v>` is refused by the control
// now — `.` is an open position under R2 — and extractSpan is the SECOND line:
// its job is to hold for whatever *regexp.Regexp it is handed, including one
// no Signature could carry. A version of this test that could only feed it
// vetted patterns would stop exercising the properties extractSpan documents.
// The refusal is asserted below so the bypass stays visible.
func TestExtractedSpanIsBoundedPrintableAndDropsRatherThanSubstitutes(t *testing.T) {
	const allPattern = `(?s)<v>.*</v>`
	if _, err := NewSignature(allPattern); !errors.Is(err, ErrSignatureMatchesEverything) {
		t.Fatalf("NewSignature(%q) = %v; this fixture is compiled raw BECAUSE the control "+
			"refuses it, and if it no longer does, the bypass below has become an "+
			"unexplained shortcut", allPattern, err)
	}
	// spelled is set to MaxSpanBytes so that extractSpan's COMPOSITION rule
	// (property 1b, "no more unspelled bytes than spelled ones") can never
	// fire here. This test is about the LENGTH bound and the charset, one
	// property at a time; the composition rule has its own sweep in
	// TestASpanMayNotCarryMoreOfTheBodyThanThePatternSpells, and a fixture
	// that tripped both at once could not tell a reader which one it was
	// measuring.
	all := Signature{re: regexp.MustCompile(allPattern), src: allPattern,
		spelled: MaxSpanBytes, sealed: true}

	// An over-broad match produces NO SPAN, and the boundary is exact.
	//
	// The three sizes are chosen so that an off-by-one in either direction
	// is visible: at the budget the span survives whole, one byte over it
	// disappears entirely, and far over it disappears the same way. A test
	// that only fed it 10x the budget would pass against `>= MaxSpanBytes`,
	// against `> MaxSpanBytes`, and against a truncating implementation.
	t.Run("over_broad_match_yields_no_span", func(t *testing.T) {
		const wrap = len("<v></v>")
		for _, tc := range []struct {
			name     string
			fill     int
			wantSpan bool
		}{
			{"exactly the budget", MaxSpanBytes - wrap, true},
			{"one byte over", MaxSpanBytes - wrap + 1, false},
			{"ten times over", 10 * MaxSpanBytes, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				body := []byte("<v>" + strings.Repeat("q", tc.fill) + "</v>")
				span, dropped, overBroad, matched := extractSpan(body, all)
				if !matched {
					t.Fatal("the fixture did not match; nothing is being bounded. " +
						"THE ORACLE STILL FIRED: an over-broad match is a match whose " +
						"text cannot be shown, not a non-match")
				}
				if dropped != 0 {
					t.Errorf("dropped = %d over printable input, want 0", dropped)
				}
				if tc.wantSpan {
					if len(span) != len(body) {
						t.Errorf("span is %d bytes, want the whole %d-byte match",
							len(span), len(body))
					}
					if overBroad != 0 {
						t.Errorf("overBroad = %d for a match inside the budget", overBroad)
					}
					return
				}
				if span != "" {
					t.Errorf("a %d-byte match produced a %d-byte span. Truncating an "+
						"over-broad match to the budget inlines a verbatim prefix of "+
						"the response, which is the thing plan/00-SPINE.md S7 forbids",
						len(body), len(span))
				}
				if overBroad != len(body) {
					t.Errorf("overBroad = %d, want %d (the whole match)", overBroad, len(body))
				}
			})
		}
	})

	t.Run("printable_ascii_only", func(t *testing.T) {
		// One representative of every class engines.scrub removes one at a
		// time, plus a malformed UTF-8 byte. The allowlist removes all of
		// them without enumerating any of them, which is the argument for
		// an allowlist.
		classes := []struct {
			name string
			s    string
		}{
			{"C0 control", "\x01"},
			{"DEL", "\x7f"},
			{"C1 control", "\u0085"},
			{"bidi override", "\u202e"},
			{"bidi isolate", "\u2066"},
			{"zero width", "\u200b"},
			{"word joiner", "\u2060"},
			{"BOM", "\ufeff"},
			{"soft hyphen", "\u00ad"},
			{"unicode tag", "\U000e0041"},
			{"newline", "\n"},
			{"tab", "\t"},
		}
		for _, cl := range classes {
			body := []byte("<v>ok" + cl.s + "ok</v>")
			// A malformed UTF-8 byte cannot be written as a Go string
			// literal, so it is appended separately below.
			span, dropped, _, matched := extractSpan(body, all)
			if !matched {
				t.Fatalf("%s: no match", cl.name)
			}
			if !isPrintableASCII(span) {
				t.Errorf("%s: span %q is not printable ASCII", cl.name, span)
			}
			if dropped == 0 {
				t.Errorf("%s: dropped = 0, so the character survived or was never counted",
					cl.name)
			}
			if strings.Contains(span, "\ufffd") {
				t.Errorf("%s: span contains U+FFFD; extraction must DROP, not substitute — "+
					"a replacement character is a byte Anvil invented inside prose "+
					"attributed to the target", cl.name)
			}
			if !strings.Contains(span, "okok") {
				t.Errorf("%s: span = %q, want the surviving printable bytes joined",
					cl.name, span)
			}
		}

		malformed := append([]byte("<v>ok"), 0xff, 0xfe)
		malformed = append(malformed, []byte("ok</v>")...)
		span, dropped, _, matched := extractSpan(malformed, all)
		if !matched || dropped != 2 || !isPrintableASCII(span) || !strings.Contains(span, "okok") {
			t.Errorf("malformed UTF-8: span=%q dropped=%d matched=%v", span, dropped, matched)
		}
	})

	t.Run("no_match_no_span", func(t *testing.T) {
		span, dropped, overBroad, matched := extractSpan([]byte("nothing here"), all)
		if matched || span != "" || dropped != 0 || overBroad != 0 {
			t.Errorf("extractSpan on a non-matching body returned (%q,%d,%d,%v)",
				span, dropped, overBroad, matched)
		}
	})
}

// TestBodyHashIsOfTheWholeBodyNotOfTheSpan is what makes "hash-and-reference"
// mean anything: a hash of the 512-byte span would not identify the response.
func TestBodyHashIsOfTheWholeBodyNotOfTheSpan(t *testing.T) {
	body := []byte(strings.Repeat("z", 4096) + sqliMarker)
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return body }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: MinAttempts})

	f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	sum := sha256.Sum256(body)
	if got, want := f.Evidence().BodyHash(), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("body hash = %s, want the SHA-256 of the whole %d-byte body (%s)",
			got, len(body), want)
	}
	spanSum := sha256.Sum256([]byte(f.Evidence().ExtractedSpan()))
	if f.Evidence().BodyHash() == hex.EncodeToString(spanSum[:]) {
		t.Error("the body hash equals the hash of the extracted span, so it references the " +
			"span rather than the response and cannot be used to identify the response")
	}
}

// ---------------------------------------------------------------------------
// UNCONFIRMED IS A THIRD OUTCOME
// ---------------------------------------------------------------------------

// TestOracleLessClassesAreTaggedUnconfirmedNotAssertedAndNotDropped covers the
// contract sentence verbatim: "oracle-less classes (authorization, IDOR,
// business logic) are tagged unconfirmed rather than asserted or dropped."
//
// It runs each of the three named classes through BOTH a re-probe that
// matches every time and one that never matches, because "rather than
// asserted" and "rather than dropped" are two different failures and only one
// input exposes each.
func TestOracleLessClassesAreTaggedUnconfirmedNotAssertedAndNotDropped(t *testing.T) {
	named := []Class{ClassAuthorization, ClassIDOR, ClassBusinessLogic}
	for _, class := range named {
		for _, matching := range []bool{true, false} {
			name := fmt.Sprintf("%s/matches=%v", class, matching)
			t.Run(name, func(t *testing.T) {
				rp := &scriptedReprober{body: func(RawFinding, int) []byte {
					if matching {
						return []byte(`{"role":"admin","users":[]}`)
					}
					return []byte(`{"error":"forbidden"}`)
				}}
				g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})

				c := sqliCandidate(t, "/admin/users")
				c.Class = class
				c.Signature = mustSignature(t, `"role":"admin"`)

				f, err := g.ConfirmFinding(context.Background(), c)
				if err != nil {
					t.Fatalf("ConfirmFinding: %v", err)
				}
				if f.Outcome() != OutcomeUnconfirmed {
					t.Fatalf("outcome = %q, want %q", f.Outcome(), OutcomeUnconfirmed)
				}
				if f.Reason() != ReasonNoOracleForClass {
					t.Errorf("reason = %q, want %q", f.Reason(), ReasonNoOracleForClass)
				}
				if f.CountsAsFinding() {
					t.Error("an unconfirmed finding counts toward dast_status findings; " +
						"D.27: no finding reaches it without passing confirmation")
				}
				// NOT ASSERTED: no confidence number at all.
				if c, ok := f.Confidence(); ok {
					t.Errorf("confidence = (%v,true); an oracle-less class has no "+
						"reproduction ratio, and 0.0 or 1.0 would both be a claim "+
						"this gate cannot support", c)
				}
				// NOT DROPPED: it is in the ledger, with its evidence.
				if f.Evidence().BodyHash() == "" {
					t.Error("no body hash: the finding was tagged but nothing was recorded " +
						"about what was observed")
				}
				if matching && f.Evidence().ExtractedSpan() == "" {
					t.Error("the signature matched and no span was extracted; a human " +
						"triaging an unconfirmed finding has nothing to look at")
				}
				// The raw measurement is still reported, under its own name.
				wantMatches := 0
				if matching {
					wantMatches = 3
				}
				if f.SignatureMatches() != wantMatches || f.Attempts() != 3 {
					t.Errorf("matches/attempts = %d/%d, want %d/3",
						f.SignatureMatches(), f.Attempts(), wantMatches)
				}
			})
		}
	}
}

// TestUnconfirmedIsStructurallyDistinctFromBothOthers is the "not a low
// confidence score" half. A consumer must be able to separate the three
// without arithmetic on a float.
func TestUnconfirmedIsStructurallyDistinctFromBothOthers(t *testing.T) {
	seen := map[Outcome]bool{}
	for _, o := range OutcomeValues() {
		if seen[o] {
			t.Fatalf("%q appears twice in OutcomeValues", o)
		}
		seen[o] = true
		if o == OutcomeUnset || !o.Valid() {
			t.Fatalf("%q is not a valid terminal outcome", o)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("OutcomeValues has %d entries, want exactly 3", len(seen))
	}
	if OutcomeUnset.Valid() {
		t.Error("the zero Outcome validates; a Finding nobody filled in would look terminal")
	}
	for _, o := range OutcomeValues() {
		if got, want := o.CountsAsFinding(), o == OutcomeConfirmed; got != want {
			t.Errorf("%q.CountsAsFinding() = %v, want %v", o, got, want)
		}
	}
	if OutcomeUnset.CountsAsFinding() {
		t.Error("the zero Outcome counts as a finding: a Go zero value means permitted")
	}

	// A confirmed finding with a genuinely low ratio is impossible by
	// construction (confirmed requires matches == attempts), so there is no
	// confidence value at which confirmed and unconfirmed overlap. Proved by
	// running every reason through the mapping.
	for _, r := range ReasonValues() {
		o, err := outcomeForReason(r)
		if err != nil {
			t.Fatalf("outcomeForReason(%q): %v", r, err)
		}
		if !o.Valid() {
			t.Fatalf("outcomeForReason(%q) = %q", r, o)
		}
	}
	if _, err := outcomeForReason(ReasonUnset); !errors.Is(err, ErrRefused) {
		t.Errorf("outcomeForReason(ReasonUnset) = %v, want a refusal", err)
	}
	if _, err := outcomeForReason(Reason("something_new")); !errors.Is(err, ErrRefused) {
		t.Error("outcomeForReason admitted a reason this gate does not mint")
	}
}

// TestDecideTablePrecedenceIsAsDocumented enumerates the reason table across
// every class, every detection method and every reproduction ratio.
//
// It is a total enumeration rather than five hand-picked cases because the
// precedence between rules is the thing that is easy to get wrong, and a
// hand-picked case set silently loses coverage the day a class is added.
func TestDecideTablePrecedenceIsAsDocumented(t *testing.T) {
	const attempts = 3
	for _, class := range ClassValues() {
		for _, dm := range DetectionMethodValues() {
			for matches := 0; matches <= attempts; matches++ {
				c := RawFinding{Class: class, DetectionMethod: dm}
				got := decide(c, matches, 0 /* indecisive */, attempts)

				var want Reason
				switch {
				case class.OracleLess():
					want = ReasonNoOracleForClass
				case matches == 0:
					want = ReasonDidNotReproduce
				case dm == DetectionMethodModelInference:
					want = ReasonModelInferenceIsNotObservation
				case matches < attempts:
					want = ReasonReproducedIntermittently
				default:
					want = ReasonReproduced
				}
				if got != want {
					t.Errorf("decide(%s, %s, %d/%d) = %q, want %q",
						class, dm, matches, attempts, got, want)
				}
				o, err := outcomeForReason(got)
				if err != nil {
					t.Fatalf("outcomeForReason(%q): %v", got, err)
				}
				if o == OutcomeConfirmed {
					if class.OracleLess() || !dm.CanConfirm() || matches != attempts {
						t.Errorf("decide(%s, %s, %d/%d) reached OutcomeConfirmed",
							class, dm, matches, attempts)
					}
				}
			}
		}
	}
}

// TestModelInferenceIsNeverConfirmed is the rule pulled out of the table and
// driven end to end, because it is the one a future reader is most likely to
// think is an oversight.
func TestModelInferenceIsNeverConfirmed(t *testing.T) {
	rp := &scriptedReprober{body: func(RawFinding, int) []byte {
		return []byte(`{"error":"` + sqliMarker + `"}`)
	}}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})

	c := sqliCandidate(t, "/search")
	c.DetectionMethod = DetectionMethodModelInference

	f, err := g.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	if f.Outcome() != OutcomeUnconfirmed {
		t.Fatalf("outcome = %q, want unconfirmed even on 3/3 reproduction", f.Outcome())
	}
	if f.Reason() != ReasonModelInferenceIsNotObservation {
		t.Errorf("reason = %q", f.Reason())
	}
	// AND IT CARRIES NO CONFIDENCE.
	//
	// This assertion is inverted from what it used to say, and the old
	// version was the defect. It read (1.0, true) and defended it in a
	// comment: "the ratio is still a real measurement and is still
	// reported". The result was a single record stating, at once, that the
	// candidate is unconfirmed BECAUSE a model inference is not an
	// observation, and that Anvil's confidence in it is 1.000. A consumer
	// that sorts by confidence puts it at the top of the list the reason
	// field exists to keep it off.
	//
	// The measurement is not lost and that is what makes the split honest:
	// SignatureMatches()/Attempts() still report 3 of 3 below. What is
	// withheld is the CLAIM. Confidence is defined in this file as the
	// oracle's reproduction ratio standing behind the finding, and a
	// reproduced signature does not stand behind an inference about what
	// the signature means.
	if conf, ok := f.Confidence(); ok {
		t.Errorf("confidence = (%v,%v), want (_,false): a finding whose reason is %q "+
			"cannot simultaneously report a confidence, and %v is the number that "+
			"contradicts it hardest", conf, ok, ReasonModelInferenceIsNotObservation, conf)
	}
	if got, want := f.SignatureMatches(), 3; got != want {
		t.Errorf("SignatureMatches = %d, want %d. Withholding the CLAIM must not delete "+
			"the MEASUREMENT, or an operator loses the only evidence that the model was "+
			"looking at something stable", got, want)
	}
	if got, want := f.Attempts(), 3; got != want {
		t.Errorf("Attempts = %d, want %d", got, want)
	}

	// The positive control on the same fixture: the identical candidate
	// detected by a template IS confirmed. Without it, this test would pass
	// against a gate that confirms nothing.
	c.DetectionMethod = DetectionMethodTemplate
	f2, err := g.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	if f2.Outcome() != OutcomeConfirmed {
		t.Fatalf("the same candidate detected by template gave %q; the fixture cannot "+
			"produce a confirmation and the assertion above is vacuous", f2.Outcome())
	}
}

// TestIntermittentReproductionIsUnconfirmed covers the third route to
// unconfirmed, and the confidence arithmetic behind it.
func TestIntermittentReproductionIsUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		matchOn    map[int]bool
		attempts   int
		wantReason Reason
		wantConf   float64
	}{
		{"one of three", map[int]bool{2: true}, 3, ReasonReproducedIntermittently, 1.0 / 3.0},
		{"two of three", map[int]bool{1: true, 3: true}, 3, ReasonReproducedIntermittently, 2.0 / 3.0},
		{"three of three", map[int]bool{1: true, 2: true, 3: true}, 3, ReasonReproduced, 1.0},
		{"zero of three", map[int]bool{}, 3, ReasonDidNotReproduce, 0.0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := &scriptedReprober{body: func(_ RawFinding, attempt int) []byte {
				if tc.matchOn[attempt] {
					return []byte(`{"error":"` + sqliMarker + `"}`)
				}
				return []byte(`{"ok":true}`)
			}}
			g := mustGate(t, GateConfig{Reprober: rp, Attempts: tc.attempts})
			f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
			if err != nil {
				t.Fatalf("ConfirmFinding: %v", err)
			}
			if f.Reason() != tc.wantReason {
				t.Errorf("reason = %q, want %q", f.Reason(), tc.wantReason)
			}
			conf, ok := f.Confidence()
			if !ok {
				t.Fatal("confidence unknown for a class that has an oracle")
			}
			if diff := conf - tc.wantConf; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("confidence = %v, want %v (matches/attempts)", conf, tc.wantConf)
			}
			if conf < 0 || conf > 1 {
				t.Errorf("confidence = %v is outside [0,1]", conf)
			}
			// Evidence must come from an attempt that MATCHED when one did.
			if len(tc.matchOn) > 0 && f.Evidence().ExtractedSpan() == "" {
				t.Error("the signature matched on some attempt and the recorded evidence " +
					"carries no span, so evidence was taken from an attempt that missed")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detection_method is part of the truth
// ---------------------------------------------------------------------------

func TestDetectionMethodIsNeverDefaulted(t *testing.T) {
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return []byte("{}") }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: MinAttempts})

	for _, bad := range []DetectionMethod{DetectionMethodUnset, "manual", "TEMPLATE", "regex"} {
		c := sqliCandidate(t, "/search")
		c.DetectionMethod = bad
		reason, verr := c.Validate()
		if verr == nil {
			t.Errorf("detection_method %q validated", bad)
			continue
		}
		if reason != RefuseUnrecognisedDetectionMethod {
			t.Errorf("detection_method %q refused as %q", bad, reason)
		}
		if _, err := g.ConfirmFinding(context.Background(), c); !errors.Is(err, ErrRefused) {
			t.Errorf("ConfirmFinding with detection_method %q: %v", bad, err)
		}
	}
	if rp.calls != 0 {
		t.Errorf("%d re-probes were issued for candidates that never validated. Validation "+
			"must run before egress: a candidate that cannot produce an interpretable "+
			"finding must not spend requests against a live target", rp.calls)
	}

	// The three legal literals are exactly the contract's three, and the
	// confirm-eligibility split is asserted rather than assumed.
	if got, want := len(DetectionMethodValues()), 3; got != want {
		t.Fatalf("DetectionMethodValues has %d entries, want %d", got, want)
	}
	for _, m := range DetectionMethodValues() {
		if !m.Valid() {
			t.Errorf("%q does not validate", m)
		}
		if got, want := m.CanConfirm(), m != DetectionMethodModelInference; got != want {
			t.Errorf("%q.CanConfirm() = %v, want %v", m, got, want)
		}
	}
	if DetectionMethodUnset.Valid() || DetectionMethodUnset.CanConfirm() {
		t.Error("the zero DetectionMethod is valid or can confirm; a Go zero value means " +
			"permitted, which is the failure this enum exists to prevent")
	}

	// The finding carries it through unchanged, so a consumer can tell the
	// acts apart without reading the finding text.
	for _, m := range []DetectionMethod{DetectionMethodTemplate, DetectionMethodDifferential} {
		c := sqliCandidate(t, "/search")
		c.DetectionMethod = m
		f, err := g.ConfirmFinding(context.Background(), c)
		if err != nil {
			t.Fatalf("ConfirmFinding: %v", err)
		}
		if f.DetectionMethod() != m {
			t.Errorf("detection_method = %q, want %q", f.DetectionMethod(), m)
		}
	}
}

// TestClassOracleTableCoversEveryDeclaredClass catches the failure mode a
// positional allowlist has: a class constant that exists but is in neither
// list, and therefore routes by accident.
func TestClassOracleTableCoversEveryDeclaredClass(t *testing.T) {
	declared := []Class{
		ClassInjection, ClassXSS, ClassPathTraversal, ClassSSRF,
		ClassMisconfiguration, ClassExposedSecret, ClassOutdatedComponent,
		ClassAuthorization, ClassIDOR, ClassBusinessLogic,
	}
	if got, want := len(ClassValues()), len(declared); got != want {
		t.Fatalf("ClassValues has %d entries and %d classes are declared in this test; one "+
			"of the two lists has drifted and a class is routing by accident", got, want)
	}
	for _, c := range declared {
		if !c.Recognised() {
			t.Errorf("%q is a declared Class constant and classOracles does not key it, so "+
				"it falls through to OracleLess()==true by accident rather than by "+
				"decision", c)
		}
	}
	// The three the contract names, by name.
	for _, c := range []Class{ClassAuthorization, ClassIDOR, ClassBusinessLogic} {
		if !c.OracleLess() {
			t.Errorf("%q has an oracle. The Coverage Reporting Contract names authorization, "+
				"IDOR and business logic as the oracle-less classes", c)
		}
	}
	// And at least one that does, or the gate confirms nothing.
	if ClassInjection.OracleLess() {
		t.Error("injection is oracle-less, so no candidate can ever be confirmed")
	}
	// Fail closed on the unknown.
	if !Class("something_new").OracleLess() || !ClassUnset.OracleLess() {
		t.Error("an unrecognised or zero Class reports that it has an oracle; the unknown " +
			"must never take the route that ends in `confirmed`")
	}
	if Class("something_new").Recognised() || ClassUnset.Recognised() {
		t.Error("an unrecognised or zero Class is Recognised()")
	}
}

// ---------------------------------------------------------------------------
// The re-probe is required, and the tool-absent path refuses loudly
// ---------------------------------------------------------------------------

func TestAReprobeThatDidNotHappenIsNotAConfirmationAndIsNotARejection(t *testing.T) {
	cases := []struct {
		name string
		cfg  GateConfig
	}{
		{"no reprober wired", GateConfig{Reprober: nil, Attempts: 3}},
		{"reprober errored", GateConfig{Reprober: &scriptedReprober{
			err: errors.New("dial refused by the kernel")}, Attempts: 3}},
		{"nothing was issued", GateConfig{Reprober: &scriptedReprober{
			notIssued: true}, Attempts: 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := mustGate(t, tc.cfg)
			f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
			if f != nil {
				t.Errorf("a Finding was produced for a candidate that was not re-probed: %s", f)
			}
			if !errors.Is(err, ErrNotReprobed) {
				t.Fatalf("err = %v, want ErrNotReprobed. A candidate nobody probed is not a "+
					"candidate that failed to reproduce", err)
			}

			// And in a batch: refused, not silently absent.
			l, aerr := g.ConfirmAll(context.Background(),
				[]RawFinding{sqliCandidate(t, "/search"), sqliCandidate(t, "/a")})
			if aerr != nil {
				t.Fatalf("ConfirmAll: %v", aerr)
			}
			if got, want := l.RefusedCount(), 2; got != want {
				t.Errorf("refused = %d, want %d", got, want)
			}
			if l.ConfirmedCount() != 0 || l.RejectedCount() != 0 || l.UnconfirmedCount() != 0 {
				t.Errorf("a candidate that was not probed produced a decided finding: %s", l)
			}
			for _, r := range l.Refusals() {
				if r.Reason != RefuseNotReprobed {
					t.Errorf("refusal reason = %q, want %q", r.Reason, RefuseNotReprobed)
				}
				if !errors.Is(r.Err, ErrNotReprobed) {
					t.Errorf("refusal error = %v", r.Err)
				}
			}
			// THE POINT: zero confirmed here must not read as a clean scan.
			if err := l.AssertNotSilentlyClean(); !errors.Is(err, ErrSilentlyClean) {
				t.Errorf("AssertNotSilentlyClean = %v; a ledger of 2 candidates that were "+
					"never re-probed has a zero confirmed count for a reason that is "+
					"nothing like `we looked and found nothing`", err)
			}
		})
	}
}

func TestReproberWiredReportsTheToolAbsentPath(t *testing.T) {
	if mustGate(t, GateConfig{}).ReproberWired() {
		t.Error("a Gate with no Reprober reports one wired")
	}
	if !mustGate(t, GateConfig{Reprober: &scriptedReprober{}}).ReproberWired() {
		t.Error("a Gate with a Reprober reports none wired")
	}
	if (*Gate)(nil).ReproberWired() || (*Gate)(nil).Constructed() {
		t.Error("a nil *Gate reports itself constructed or wired")
	}
	if got := (*Gate)(nil).Attempts(); got != 0 {
		t.Errorf("a nil *Gate reports %d attempts", got)
	}
	var zero Gate
	if _, err := zero.ConfirmFinding(context.Background(), RawFinding{}); !errors.Is(err, ErrUnconstructed) {
		t.Errorf("a zero Gate confirmed: %v", err)
	}
	if _, err := zero.ConfirmAll(context.Background(), nil); !errors.Is(err, ErrUnconstructed) {
		t.Errorf("a zero Gate ran a batch: %v", err)
	}
}

func TestEveryAttemptIsIssuedAndOneAttemptCannotStandForThree(t *testing.T) {
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return []byte("{}") }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 4})
	if _, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search")); err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	if rp.calls != 4 {
		t.Errorf("%d re-probes issued, want 4", rp.calls)
	}
	if rp.lastAtt != 4 {
		t.Errorf("last attempt number = %d, want 4: an implementation that varies a nonce "+
			"per attempt needs the counter to advance", rp.lastAtt)
	}
	want := []string{"GET /search #1", "GET /search #2", "GET /search #3", "GET /search #4"}
	if len(rp.observed) != len(want) {
		t.Fatalf("observed %v", rp.observed)
	}
	for i := range want {
		if rp.observed[i] != want[i] {
			t.Errorf("observed[%d] = %q, want %q", i, rp.observed[i], want[i])
		}
	}
}

func TestAttemptCountIsBounded(t *testing.T) {
	if g, err := NewGate(GateConfig{}); err != nil || g.Attempts() != DefaultAttempts {
		t.Errorf("zero Attempts gave (%v, %v), want DefaultAttempts=%d", g, err, DefaultAttempts)
	}
	for _, n := range []int{-1, MaxAttempts + 1, 1 << 20} {
		if _, err := NewGate(GateConfig{Attempts: n}); !errors.Is(err, ErrRefused) {
			t.Errorf("NewGate with Attempts=%d: %v", n, err)
		}
	}
	if _, err := NewGate(GateConfig{Attempts: MaxAttempts}); err != nil {
		t.Errorf("NewGate with Attempts=%d: %v", MaxAttempts, err)
	}
}

func TestCancellationStopsTheBatchLoudly(t *testing.T) {
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return []byte("{}") }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: MinAttempts})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l, err := g.ConfirmAll(ctx, []RawFinding{sqliCandidate(t, "/a")})
	if !errors.Is(err, ErrNotReprobed) {
		t.Fatalf("ConfirmAll on a cancelled context = %v, want ErrNotReprobed", err)
	}
	if l.Constructed() {
		t.Error("a cancelled batch returned a constructed Ledger, which a caller could " +
			"read counts off as though the pass had completed")
	}
	if rp.calls != 0 {
		t.Errorf("%d re-probes issued after cancellation", rp.calls)
	}
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

func TestSignatureRefusesAnOracleThatWouldConfirmEverything(t *testing.T) {
	for _, p := range []string{`.*`, `(?s).*`, `a?`, `^`, `(foo)?`, `x{0,3}`} {
		if _, err := NewSignature(p); !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%q) = %v, want ErrSignatureMatchesEverything: a pattern "+
				"that matches the empty string reproduces against any body, including an "+
				"empty one, and turns this gate into a pass-through that still reports "+
				"`confirmed`", p, err)
		}
	}
	for _, p := range []string{"", strings.Repeat("a", MaxPatternBytes+1), `[`, `(?P<`} {
		if _, err := NewSignature(p); !errors.Is(err, ErrRefused) {
			t.Errorf("NewSignature(%q) = %v, want a refusal", printable(p, 32), err)
		}
	}
	s := mustSignature(t, sqliPattern)
	if !s.Constructed() || s.Pattern() != sqliPattern {
		t.Errorf("Constructed=%v Pattern=%q", s.Constructed(), s.Pattern())
	}
	if (Signature{}).Constructed() {
		t.Error("the zero Signature reports itself constructed")
	}

	// A candidate with no signature never reaches egress.
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return []byte("{}") }}
	g := mustGate(t, GateConfig{Reprober: rp})
	c := sqliCandidate(t, "/search")
	c.Signature = Signature{}
	if _, err := g.ConfirmFinding(context.Background(), c); !errors.Is(err, ErrRefused) {
		t.Errorf("a candidate with no Signature was probed: %v", err)
	}
	if rp.calls != 0 {
		t.Errorf("%d re-probes issued for a candidate with no oracle", rp.calls)
	}
}

// ---------------------------------------------------------------------------
// Validation, bounds and refusals
// ---------------------------------------------------------------------------

func TestOversizedIdentityFieldsAreRefusedAndNotTruncated(t *testing.T) {
	long := strings.Repeat("/x", MaxFieldBytes)
	cases := []struct {
		name  string
		mut   func(*RawFinding)
		want  RefuseReason
		probe bool
	}{
		{"path", func(c *RawFinding) { c.Path = long }, RefuseOversizedField, false},
		{"target", func(c *RawFinding) { c.Target = long }, RefuseOversizedField, false},
		{"engine", func(c *RawFinding) { c.Engine = long }, RefuseOversizedField, false},
		{"template id", func(c *RawFinding) { c.TemplateID = long }, RefuseOversizedField, false},
		{"empty engine", func(c *RawFinding) { c.Engine = "" }, RefuseMalformedField, false},
		{"empty target", func(c *RawFinding) { c.Target = "" }, RefuseMalformedField, false},
		{"relative path", func(c *RawFinding) { c.Path = "search" }, RefuseMalformedField, false},
		{"lowercase method", func(c *RawFinding) { c.Method = "get" }, RefuseMalformedField, false},
		{"bidi in path", func(c *RawFinding) { c.Path = "/a\u202eb" }, RefuseMalformedField, false},
		{"nul in target", func(c *RawFinding) { c.Target = "http://x\x00" }, RefuseMalformedField, false},
	}
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return []byte("{}") }}
	g := mustGate(t, GateConfig{Reprober: rp})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := sqliCandidate(t, "/search")
			tc.mut(&c)
			reason, err := c.Validate()
			if err == nil {
				t.Fatalf("%s validated", tc.name)
			}
			if reason != tc.want {
				t.Errorf("reason = %q, want %q", reason, tc.want)
			}
			if _, cerr := g.ConfirmFinding(context.Background(), c); !errors.Is(cerr, ErrRefused) {
				t.Errorf("ConfirmFinding = %v, want a refusal", cerr)
			}
		})
	}
	if rp.calls != 0 {
		t.Errorf("%d re-probes issued for candidates that never validated", rp.calls)
	}

	// A path at exactly the bound is accepted, so the bound is a bound and
	// not an off-by-one that refuses everything.
	c := sqliCandidate(t, "/"+strings.Repeat("y", MaxFieldBytes-1))
	if _, err := c.Validate(); err != nil {
		t.Errorf("a path of exactly MaxFieldBytes=%d was refused: %v", MaxFieldBytes, err)
	}
}

func TestConfirmAllDoesNotStopAtTheFirstRefusal(t *testing.T) {
	rp := &scriptedReprober{body: func(c RawFinding, _ int) []byte {
		if c.Path == "/search" {
			return []byte(`{"error":"` + sqliMarker + `"}`)
		}
		return []byte(`{"ok":true}`)
	}}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 2})

	bad := sqliCandidate(t, "/search")
	bad.Class = Class("not_a_class")

	l, err := g.ConfirmAll(context.Background(), []RawFinding{
		bad,
		sqliCandidate(t, "/search"),
		sqliCandidate(t, "/nope"),
	})
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	if got := l.CandidateCount(); got != 3 {
		t.Errorf("candidate count = %d, want 3; a refused candidate must still be counted", got)
	}
	if l.RefusedCount() != 1 || l.ConfirmedCount() != 1 || l.RejectedCount() != 1 {
		t.Errorf("refused/confirmed/rejected = %d/%d/%d, want 1/1/1. %s",
			l.RefusedCount(), l.ConfirmedCount(), l.RejectedCount(), l)
	}
	r := l.Refusals()[0]
	if r.Index != 0 || r.Reason != RefuseUnrecognisedClass {
		t.Errorf("refusal = %+v, want index 0 / %q", r, RefuseUnrecognisedClass)
	}
	if !strings.Contains(r.Detail, "/search") || !isPrintableASCII(r.Detail) ||
		len(r.Detail) > MaxFieldBytes {
		t.Errorf("refusal detail = %q; it must locate the candidate, stay printable ASCII "+
			"and stay bounded", r.Detail)
	}
	// A zero confirmed count is not at issue here, but the mixed ledger must
	// still be honest about the refusal.
	if err := l.AssertNotSilentlyClean(); err != nil {
		t.Errorf("AssertNotSilentlyClean on a ledger with a confirmed finding: %v", err)
	}
}

// TestAssertNotSilentlyCleanFiresOnEveryWayOfReachingZeroDishonestly
// enumerates the reasons a confirmed count can be zero and asserts which of
// them are clean.
func TestAssertNotSilentlyCleanFiresOnEveryWayOfReachingZeroDishonestly(t *testing.T) {
	body := func(match bool) func(RawFinding, int) []byte {
		return func(RawFinding, int) []byte {
			if match {
				return []byte(`{"error":"` + sqliMarker + `"}`)
			}
			return []byte(`{"ok":true}`)
		}
	}
	oracleLess := func(t *testing.T) RawFinding {
		c := sqliCandidate(t, "/admin")
		c.Class = ClassAuthorization
		return c
	}
	malformed := func(t *testing.T) RawFinding {
		c := sqliCandidate(t, "/search")
		c.Class = ClassUnset
		return c
	}

	for _, tc := range []struct {
		name      string
		cfg       GateConfig
		mk        func(*testing.T) RawFinding
		wantClean bool
	}{
		{"nothing to find", GateConfig{Reprober: &scriptedReprober{body: body(false)}},
			func(t *testing.T) RawFinding { return sqliCandidate(t, "/a") }, true},
		{"undecidable", GateConfig{Reprober: &scriptedReprober{body: body(true)}},
			oracleLess, false},
		{"never probed", GateConfig{Reprober: nil},
			func(t *testing.T) RawFinding { return sqliCandidate(t, "/a") }, false},
		{"malformed", GateConfig{Reprober: &scriptedReprober{body: body(false)}},
			malformed, false},
		{"empty batch", GateConfig{Reprober: &scriptedReprober{body: body(false)}}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := mustGate(t, tc.cfg)
			var in []RawFinding
			if tc.mk != nil {
				in = []RawFinding{tc.mk(t)}
			}
			l, err := g.ConfirmAll(context.Background(), in)
			if err != nil {
				t.Fatalf("ConfirmAll: %v", err)
			}
			if l.ConfirmedCount() != 0 {
				t.Fatalf("fixture confirmed something (%s); it is not exercising the zero case", l)
			}
			gotClean := l.AssertNotSilentlyClean() == nil
			if gotClean != tc.wantClean {
				t.Errorf("AssertNotSilentlyClean clean=%v, want %v. %s (%v)",
					gotClean, tc.wantClean, l, l.AssertNotSilentlyClean())
			}
		})
	}

	var zero Ledger
	if err := zero.AssertNotSilentlyClean(); !errors.Is(err, ErrUnconstructed) {
		t.Errorf("an unconstructed Ledger reported clean: %v", err)
	}
	if zero.Constructed() {
		t.Error("the zero Ledger reports itself constructed")
	}
}

// ---------------------------------------------------------------------------
// The copy is real
// ---------------------------------------------------------------------------

// TestFindingsIsARealCopyAcrossEveryField mutates EVERY field of the returned
// value, not only the one where a shallow copy happens to be a real copy.
//
// That failure has been found three times in this build. Here the type has no
// reference-typed field at all — TestFindingTypeClosureHasNoRawBodyPath is
// what keeps that true — so the interesting assertion is the slice header
// itself plus a full field-by-field comparison after mutation.
func TestFindingsIsARealCopyAcrossEveryField(t *testing.T) {
	rp := &scriptedReprober{body: func(RawFinding, int) []byte {
		return []byte(`{"error":"` + sqliMarker + `"}`)
	}}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 2})
	l, err := g.ConfirmAll(context.Background(), []RawFinding{sqliCandidate(t, "/search")})
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	before := l.Findings()
	if len(before) != 1 {
		t.Fatalf("got %d findings", len(before))
	}

	// Mutate every field of the caller's copy, including the nested struct.
	got := l.Findings()
	got[0] = Finding{
		engine: "tampered", target: "tampered", method: "TAMPER", path: "/tampered",
		templateID: "t", templateDigest: "d",
		class: ClassIDOR, detection: DetectionMethodModelInference,
		outcome: OutcomeRejected, reason: ReasonDidNotReproduce,
		evidence: EvidenceRef{bodyHash: "0", span: "s", spanDroppedBytes: 9,
			spanOverBroadBytes: 9, sealed: true},
		status: 500, attempts: 99, matches: 0, indecisive: 7,
		confidence: 0, confidenceKnown: false,
		sealed: false,
	}
	got = append(got, Finding{})

	after := l.Findings()
	if len(after) != 1 {
		t.Fatalf("appending to the caller's slice changed the ledger's length to %d", len(after))
	}
	if !reflect.DeepEqual(before[0], after[0]) {
		t.Errorf("mutating the returned slice changed the ledger's finding:\nbefore %+v\nafter  %+v",
			before[0], after[0])
	}

	// Same for Refusals.
	g2 := mustGate(t, GateConfig{})
	l2, err := g2.ConfirmAll(context.Background(), []RawFinding{sqliCandidate(t, "/search")})
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	r := l2.Refusals()
	r[0] = Refusal{Index: 42, Reason: RefuseMalformedField, Detail: "x", Err: RefusalError{}}
	if l2.Refusals()[0].Index != 0 || l2.Refusals()[0].Reason != RefuseNotReprobed {
		t.Errorf("mutating the returned refusals changed the ledger: %+v", l2.Refusals()[0])
	}
}

// ---------------------------------------------------------------------------
// Renderings quote no body
// ---------------------------------------------------------------------------

func TestRenderingsCarryTheArithmeticAndNotTheProse(t *testing.T) {
	secret := "TOTALLY-DISTINCTIVE-BODY-TEXT"
	rp := &scriptedReprober{body: func(RawFinding, int) []byte {
		return []byte(secret + ` {"error":"` + sqliMarker + `"} ` + secret)
	}}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 2})
	l, err := g.ConfirmAll(context.Background(), []RawFinding{sqliCandidate(t, "/search")})
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	f := l.Findings()[0]
	for name, s := range map[string]string{"Finding.String": f.String(), "Ledger.String": l.String()} {
		if strings.Contains(s, secret) {
			t.Errorf("%s quotes text from the response body: %q", name, s)
		}
		if !isPrintableASCII(s) {
			t.Errorf("%s is not printable ASCII: %q", name, s)
		}
	}
	for _, want := range []string{"outcome=confirmed", "matches=2/2", "confidence=1.000", "body_hash="} {
		if !strings.Contains(f.String(), want) {
			t.Errorf("Finding.String() = %q, missing %q", f.String(), want)
		}
	}
	if got := (Finding{}).String(); got != "finding(unconstructed)" {
		t.Errorf("zero Finding.String() = %q", got)
	}
	if got := (Ledger{}).String(); got != "ledger(unconstructed)" {
		t.Errorf("zero Ledger.String() = %q", got)
	}
	if !strings.Contains(l.String(), "confirmed=1") {
		t.Errorf("Ledger.String() = %q", l.String())
	}
}

// TestAssembledFindingBoundIsEnforcedInProductionAndNotOnlyInTests drives the
// runtime assertion directly, because it is the half of the bound that runs
// outside the test binary.
func TestAssembledFindingBoundIsEnforcedInProductionAndNotOnlyInTests(t *testing.T) {
	ok := Finding{engine: "zap", target: "t", method: "GET", path: "/a",
		class: ClassInjection, detection: DetectionMethodTemplate,
		outcome: OutcomeConfirmed, reason: ReasonReproduced,
		evidence: EvidenceRef{bodyHash: strings.Repeat("0", 64), sealed: true}, sealed: true}
	if err := assertFindingStringsBounded(ok); err != nil {
		t.Fatalf("a well-formed Finding was refused: %v", err)
	}
	// Every string field, one at a time. A check that only looks at the span
	// is a check that cannot see the damage.
	mutators := map[string]func(*Finding){
		"engine":          func(f *Finding) { f.engine = strings.Repeat("x", MaxSpanBytes+1) },
		"target":          func(f *Finding) { f.target = strings.Repeat("x", MaxSpanBytes+1) },
		"method":          func(f *Finding) { f.method = strings.Repeat("X", MaxSpanBytes+1) },
		"path":            func(f *Finding) { f.path = strings.Repeat("x", MaxSpanBytes+1) },
		"template_id":     func(f *Finding) { f.templateID = strings.Repeat("x", MaxSpanBytes+1) },
		"template_digest": func(f *Finding) { f.templateDigest = strings.Repeat("x", MaxSpanBytes+1) },
		"class":           func(f *Finding) { f.class = Class(strings.Repeat("x", MaxSpanBytes+1)) },
		"detection":       func(f *Finding) { f.detection = DetectionMethod(strings.Repeat("x", MaxSpanBytes+1)) },
		"outcome":         func(f *Finding) { f.outcome = Outcome(strings.Repeat("x", MaxSpanBytes+1)) },
		"reason":          func(f *Finding) { f.reason = Reason(strings.Repeat("x", MaxSpanBytes+1)) },
		"body_hash":       func(f *Finding) { f.evidence.bodyHash = strings.Repeat("x", MaxSpanBytes+1) },
		"span":            func(f *Finding) { f.evidence.span = strings.Repeat("x", MaxSpanBytes+1) },
	}
	// The mutator set must cover every string reachable from Finding, or a
	// field could grow unwatched.
	if got, want := len(mutators), len(oversizedStrings("f", reflect.ValueOf(allStringsLong()), 0)); got != want {
		t.Fatalf("assertFindingStringsBounded is checked against %d fields and Finding has "+
			"%d reachable strings; a field is unwatched", got, want)
	}
	for name, mut := range mutators {
		f := ok
		mut(&f)
		err := assertFindingStringsBounded(f)
		if err == nil {
			t.Errorf("%s over the bound was accepted", name)
			continue
		}
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v, want a refusal naming the field", name, err)
		}
	}
}

// allStringsLong returns a Finding with every reachable string non-empty, so
// oversizedStrings with a limit of 0 counts them.
func allStringsLong() Finding {
	return Finding{
		engine: "a", target: "a", method: "a", path: "a",
		templateID: "a", templateDigest: "a",
		class: "a", detection: "a", outcome: "a", reason: "a",
		evidence: EvidenceRef{bodyHash: "a", span: "a"},
	}
}

// TestEvidenceRefZeroValueAssertsNothing keeps the fail-closed direction on
// the type the contract names.
func TestEvidenceRefZeroValueAssertsNothing(t *testing.T) {
	var e EvidenceRef
	if e.Constructed() {
		t.Error("the zero EvidenceRef reports itself constructed")
	}
	if e.BodyHash() != "" || e.ExtractedSpan() != "" ||
		e.SpanDroppedBytes() != 0 || e.SpanOverBroadBytes() != 0 {
		t.Errorf("the zero EvidenceRef is not zero: %+v", e)
	}
	if got := hashBody(nil); got != hex.EncodeToString(func() []byte {
		s := sha256.Sum256(nil)
		return s[:]
	}()) {
		t.Errorf("hashBody(nil) = %q; a body-less observation must still produce a hash, or "+
			"EvidenceRef.Constructed() stops meaning anything", got)
	}
}

// TestConfirmationTakesTheTimeItTakes is a guard against a future "cache the
// first attempt" optimisation: the same candidate re-probed twice must issue
// twice as many requests.
func TestConfirmationTakesTheTimeItTakes(t *testing.T) {
	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return []byte("{}") }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})
	c := sqliCandidate(t, "/search")
	for i := 0; i < 2; i++ {
		if _, err := g.ConfirmFinding(context.Background(), c); err != nil {
			t.Fatalf("ConfirmFinding: %v", err)
		}
	}
	if rp.calls != 6 {
		t.Errorf("%d re-probes for two confirmations of the same candidate, want 6", rp.calls)
	}
	if rp.perPath["/search"] != 6 {
		t.Errorf("per-path count = %d, want 6", rp.perPath["/search"])
	}

}

// ===========================================================================
// D.29 CRITICAL 1 — the raw body escaped through the error return
// ===========================================================================

// hostileReprober is a Reprober that does THE ORDINARY THING an
// implementation does with a response it cannot parse: it quotes it.
//
// It is not adversarial. Every Go HTTP client wrapper ever written has an
// error path that reads "unexpected response: <the response>", and the
// Reprober is implemented on the far side of the gate-3 boundary, in code
// this packet does not own and cannot review. That is the point: the leak
// this fixture reproduces cannot be closed by asking implementers to behave.
type hostileReprober struct {
	body []byte
}

func (h *hostileReprober) Reprobe(context.Context, RawFinding, int) (Observation, error) {
	return Observation{}, fmt.Errorf("unexpected response from target: %q", string(h.body))
}

// TestNoErrorCrossingTheBoundaryCarriesTheResponseBody is CRITICAL 1.
//
// FOUND BY POINTING AN EXISTING GUARD AT THE RIGHT TYPES.
// TestFindingTypeClosureHasNoRawBodyPath walked Finding, EvidenceRef and
// Observation and never walked Refusal — and Refusal.Err was a bare `error`
// that ConfirmFinding filled with `%w` of the Reprober's error, UNBOUNDED.
// The type-closure guarantee on Finding was real and complete and the body
// went round it through the field next door.
func TestNoErrorCrossingTheBoundaryCarriesTheResponseBody(t *testing.T) {
	// The generator first. A 4301-byte body with a distinctive marker and a
	// representative of every non-printable class, so that a guard which
	// only checked LENGTH, or only checked the marker, is visibly
	// insufficient.
	const marker = "MARKER-9d4c-RAW-RESPONSE-BODY"
	nonPrintable := "\x00\x01\x1b\x7f\u202e\u200b\ufeff"
	body := []byte(marker + nonPrintable + strings.Repeat("Z", 4301-len(marker)-len(nonPrintable)))
	if len(body) != 4301 {
		t.Fatalf("fixture body is %d bytes, want 4301", len(body))
	}

	rp := &hostileReprober{body: body}

	// The control on the fixture: the Reprober's own error DOES carry the
	// body. Without this, everything below could pass because the fixture
	// never produced the damage.
	_, rawErr := rp.Reprobe(context.Background(), RawFinding{}, 1)
	if !strings.Contains(rawErr.Error(), marker) {
		t.Fatal("the hostile Reprober's error does not quote the body, so this test " +
			"proves nothing about what the gate does with one")
	}
	if len(rawErr.Error()) < 4301 {
		t.Fatalf("the hostile Reprober's error is %d bytes; the fixture is not producing "+
			"an unbounded one", len(rawErr.Error()))
	}

	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})

	// Route 1: the error ConfirmFinding returns directly.
	_, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
	if err == nil {
		t.Fatal("ConfirmFinding succeeded against a Reprober that always errors")
	}
	assertErrorIsClean(t, "ConfirmFinding's returned error", err, marker)
	if !errors.Is(err, ErrNotReprobed) {
		t.Errorf("ConfirmFinding = %v, want ErrNotReprobed: a Reprober that errored did "+
			"not observe an absence", err)
	}

	// Route 2: Ledger.Refusals()[i].Err, which is the one an operator reads.
	l, cerr := g.ConfirmAll(context.Background(), []RawFinding{sqliCandidate(t, "/search")})
	if cerr != nil {
		t.Fatalf("ConfirmAll: %v", cerr)
	}
	rs := l.Refusals()
	if len(rs) != 1 {
		t.Fatalf("got %d refusals, want 1", len(rs))
	}
	assertErrorIsClean(t, "Ledger.Refusals()[0].Err", rs[0].Err, marker)

	// Identity survives even though the text does not.
	if !errors.Is(rs[0].Err, ErrNotReprobed) {
		t.Errorf("errors.Is(refusal.Err, ErrNotReprobed) = false; quarantining the text "+
			"must not cost the caller the ability to classify the failure: %v", rs[0].Err)
	}
	if errors.Is(rs[0].Err, ErrRefused) {
		t.Error("a not-reprobed refusal also matches ErrRefused; the sentinels stop " +
			"distinguishing 'Anvil did not look' from 'the candidate was malformed'")
	}

	// AND THE CHAIN STOPS. An Unwrap that handed back the foreign error
	// would put the body one errors.Unwrap call away from a %v.
	if u := errors.Unwrap(rs[0].Err); u != nil {
		t.Errorf("errors.Unwrap(refusal.Err) = %v (type %T); the chain must stop at "+
			"RefusalError, or the quarantined text is reachable by unwrapping",
			printable(u.Error(), 96), u)
	}

	// The type-level half: Refusal's closure is as closed as Finding's.
	if v := closureViolations(reflect.TypeOf(Refusal{})); len(v) != 0 {
		t.Errorf("Refusal's field-type closure has %d route(s) a raw response body could "+
			"travel through:\n%s", len(v), strings.Join(v, "\n"))
	}
	if v := closureViolations(reflect.TypeOf(RefusalError{})); len(v) != 0 {
		t.Errorf("RefusalError's closure has %d body route(s):\n%s", len(v), strings.Join(v, "\n"))
	}

	// The zero value asserts nothing, the same way every other zero value in
	// this file does.
	var zero RefusalError
	if zero.Constructed() || errors.Is(zero, ErrRefused) || errors.Is(zero, ErrNotReprobed) {
		t.Errorf("the zero RefusalError matches a sentinel: %v", zero)
	}
}

// assertErrorIsClean is the claim, applied to one error value.
//
// Three separate properties, because a guard that checked only one of them
// would have passed on the defect: the marker (a body that is short and
// printable still must not appear), the bound (a body that avoids the marker
// still must not be unbounded), and the charset (this string is prompt-bound
// and a bidi override inside it is a rendering attack whatever its length).
func assertErrorIsClean(t *testing.T, what string, err error, marker string) {
	t.Helper()
	msg := err.Error()
	if strings.Contains(msg, marker) {
		t.Errorf("%s quotes the response body. plan/00-SPINE.md S7: the DAST response "+
			"body is the highest-risk injection channel, and an error message is read "+
			"by a human and increasingly by an agent", what)
	}
	if strings.Contains(msg, strings.Repeat("Z", 64)) {
		t.Errorf("%s carries a run of the response body's filler", what)
	}
	if len(msg) > MaxRefusalMessageBytes {
		t.Errorf("%s is %d bytes and the bound is %d", what, len(msg), MaxRefusalMessageBytes)
	}
	if !isPrintableASCII(msg) {
		t.Errorf("%s carries bytes outside printable ASCII", what)
	}
}

// ---------------------------------------------------------------------------
// The meta-guard: every type this package hands back is walked
// ---------------------------------------------------------------------------

// boundaryVerdict is the claim made about one type a consumer can hold.
//
// There are three and they are ordered by strength. A type is registered with
// the STRONGEST claim that is true of it, and the test enforces that: a
// verdictBounded type whose closure is actually clean is a downgrade, and a
// downgrade is how a guarantee gets lost without a diff that looks like
// anything.
type boundaryVerdict string

const (
	// verdictClosed: closureViolations is empty. No pointer, no slice, no
	// map, no interface anywhere in the closure — the value IS a complete
	// copy and there is nowhere a response body could sit.
	verdictClosed boundaryVerdict = "closed"

	// verdictBounded: the type holds sequences or maps BY DESIGN, so
	// closureViolations flags it for exactly the property it is supposed to
	// have. The weaker claim is asserted instead: no []byte, no interface,
	// no func, no channel, and no pointer to anything but a scalar, anywhere
	// in the closure. There is still no route to a raw body; there is simply
	// aliasing, which the accessors handle by cloning.
	verdictBounded boundaryVerdict = "bounded"

	// verdictInbound: NOT closed, deliberately. These travel INTO the gate
	// or ARE the gate. The claim is inverted — closureViolations must be
	// NON-empty — so that a type quietly losing its capability (a Signature
	// that stopped carrying a compiled regexp, an Observation that stopped
	// carrying a body) fails here instead of passing.
	//
	// ===================================================================
	// IT USED TO BE A TOTAL EXEMPTION, AND A TOTAL EXEMPTION IS A
	// JUDGEMENT LIST WITH ONE ENTRY
	// ===================================================================
	//
	// "closureViolations must be non-empty" is satisfied BY THE VIOLATION
	// ITSELF. MEASURED: adding `Raw []byte` to Summary and changing its
	// registration from bounded to inbound — one word — left the whole
	// package GREEN. Finding is defended against that by
	// TestFindingTypeClosureHasNoRawBodyPath, which asserts its closure
	// outside this registry; Summary had nothing.
	//
	// So the exemption is now bounded twice over, and both bounds are
	// derived rather than listed:
	//
	//	WHO MAY CLAIM IT. Only a type the package's OWN SOURCE shows
	//	crossing inward — a parameter of an exported function, anything
	//	in an exported interface's method signatures, or a field of one
	//	of those — or a type holding a CAPABILITY (an interface, a func
	//	or a channel), which is the one shape no other verdict can
	//	express. Summary is neither, so the flip above is now refused
	//	before its routes are even looked at. See inboundEligibleTypes.
	//
	//	WHAT IT COVERS. Exactly the routes named in boundaryType.carries,
	//	compared as a SET against what closureViolations reports. A new
	//	body route on an inbound type fails like a new one anywhere
	//	else; declaring it is an explicit line of registry, not a
	//	one-word verdict change.
	verdictInbound boundaryVerdict = "inbound"
)

// boundaryType is one registered type: what it is, what is claimed about it,
// and why.
type boundaryType struct {
	name    string
	typ     reflect.Type
	verdict boundaryVerdict
	why     string
	// carries is the EXACT set of field paths closureViolations may report
	// for a verdictInbound type — the capability or the raw input this type
	// exists to hold, named one path at a time.
	//
	// It must be empty for every other verdict, and for an inbound type it
	// must match what the walker actually finds, set-for-set. That is what
	// stops "inbound" meaning "stop looking".
	carries []string
}

// violationPaths reduces walker output to the field paths it named, so a
// registry entry can state WHICH routes a type carries without pinning the
// wording of the walker's explanation. The path is everything before the
// first " is ", which is how both walkers format their messages.
func violationPaths(violations []string) []string {
	out := make([]string, 0, len(violations))
	for _, v := range violations {
		out = append(out, strings.SplitN(v, " is ", 2)[0])
	}
	sort.Strings(out)
	return out
}

// boundaryTypes is the registry. IT IS NOT THE MEMBERSHIP RULE — the rule is
// derived from the package's own source in exportedResultTypeNames, and this
// registry is checked against it. A type that starts being handed back and is
// not registered here fails; a name registered here that no longer exists
// fails too.
func boundaryTypes() []boundaryType {
	return []boundaryType{
		// --- confirm_gate.go: the values a consumer holds after the gate ---
		{"Finding", reflect.TypeOf(Finding{}), verdictClosed,
			"the gate's output type; D.27 requires that a raw body be a type error here", nil},
		{"EvidenceRef", reflect.TypeOf(EvidenceRef{}), verdictClosed,
			"{body_hash, extracted_span} and nothing else", nil},
		{"Refusal", reflect.TypeOf(Refusal{}), verdictClosed,
			"the error channel is part of the output; Refusal.Err is the field that " +
				"proved it", nil},
		{"RefusalError", reflect.TypeOf(RefusalError{}), verdictClosed,
			"a value with no Unwrap, so no foreign Error() can print a body through it", nil},
		{"Class", reflect.TypeOf(ClassUnset), verdictClosed, "a named string", nil},
		{"DetectionMethod", reflect.TypeOf(DetectionMethodUnset), verdictClosed,
			"a named string", nil},
		{"Outcome", reflect.TypeOf(OutcomeUnset), verdictClosed, "a named string", nil},
		{"Reason", reflect.TypeOf(ReasonUnset), verdictClosed, "a named string", nil},
		{"RefuseReason", reflect.TypeOf(RefuseNotReprobed), verdictClosed, "a named string", nil},

		// --- coverage.go: the OTHER consumer-held output types ----------
		//
		// Summary and ProvenanceRow were MISSING from this test. It exists
		// so "the next field like Refusal.Err" cannot be added to a type
		// nobody walks, and it omitted the package's two other output
		// types — a membership rule that did not enumerate its own members,
		// which is the defect it was written to prevent one level up. That
		// is why the list is now derived rather than written.
		{"Summary", reflect.TypeOf(Summary{}), verdictBounded,
			"holds the qualifier, row and tier slices, the provenance maps and a " +
				"NULL-able server-line float; every accessor clones", nil},
		{"ProvenanceRow", reflect.TypeOf(ProvenanceRow{}), verdictBounded,
			"Operations is a []string by design: many GraphQL operations share one " +
				"address", nil},
		{"Qualifier", reflect.TypeOf(Qualifier{}), verdictClosed, "a reason, a count, a note", nil},
		{"TierContribution", reflect.TypeOf(TierContribution{}), verdictClosed,
			"a tier name and three integers", nil},
		{"ScanMode", reflect.TypeOf(ScanMode("")), verdictClosed, "a named string", nil},
		{"Determinacy", reflect.TypeOf(Determinacy("")), verdictClosed, "a named string", nil},
		{"Direction", reflect.TypeOf(Direction("")), verdictClosed, "a named string", nil},
		{"QualifierReason", reflect.TypeOf(QualifierReason("")), verdictClosed,
			"a named string", nil},
		{"TierName", reflect.TypeOf(TierName("")), verdictClosed, "a named string", nil},

		// --- containers -------------------------------------------------
		{"Ledger", reflect.TypeOf(Ledger{}), verdictBounded,
			"a container of closed record types; the slices are the point", nil},

		// --- inbound, and NOT closed on purpose -------------------------
		{"Signature", reflect.TypeOf(Signature{}), verdictInbound,
			"holds the caller's own *regexp.Regexp travelling INTO the gate; a clean " +
				"closure here would mean the oracle is gone",
			[]string{"Signature.re"}},
		{"Observation", reflect.TypeOf(Observation{}), verdictInbound,
			"carries the response body — that is its job, and it is the only type in " +
				"the package that does",
			[]string{"Observation.Body"}},
		{"RawFinding", reflect.TypeOf(RawFinding{}), verdictInbound,
			"the untrusted candidate, carrying a Signature",
			[]string{"RawFinding.Signature.re"}},
		{"Gate", reflect.TypeOf(Gate{}), verdictInbound,
			"the engine, not an output: it holds the Reprober interface by design",
			[]string{"Gate.reprober", "Gate.defence.re"}},

		// --- the three the RESULT-POSITION derivation could not see -----
		//
		// None of these is ever returned by anything, so the old rule
		// reached none of them and none was registered. All three are
		// types a consumer BUILDS AND HOLDS, and a body field added to
		// any of them is a body field that used to be walked by nothing.
		{"GateConfig", reflect.TypeOf(GateConfig{}), verdictInbound,
			"the caller's configuration travelling INTO NewGate: it holds the Reprober " +
				"interface and the caller's DefenceSignature, so a clean closure here " +
				"would mean the seam or the defence pattern is gone",
			[]string{"GateConfig.Reprober", "GateConfig.DefenceSignature.re"}},
		{"Reprober", reflect.TypeOf((*Reprober)(nil)).Elem(), verdictInbound,
			"the re-probe seam itself. It IS an interface, which is the capability gate 3 " +
				"pushes to the far side of this package, and a version of it that " +
				"walked clean would not be a seam",
			[]string{"Reprober"}},
		{"Inputs", reflect.TypeOf(Inputs{}), verdictInbound,
			"coverage.go's INPUT struct: it holds pointers to the inventory tiers' own " +
				"results, which is how the merge is checked, and it is never handed back",
			[]string{"Inputs.Union", "Inputs.Tier0", "Inputs.Tier1", "Inputs.Tier2Go",
				"Inputs.Tier2Other", "Inputs.ServerLineCoverage"}},
	}
}

// inboundEligibleTypes is the DIRECTION half of the verdictInbound bound: the
// set of registered types that may claim the exemption at all.
//
// ===========================================================================
// WHY THIS EXISTS AT ALL
// ===========================================================================
//
// verdictInbound's only check used to be "closureViolations is non-empty",
// which the violation itself satisfies. MEASURED: adding `Raw []byte` to
// Summary and changing one word — bounded to inbound — left the package green.
// The type had no business claiming the exemption in the first place, and
// nothing was asking whether it did.
//
// A type is eligible on either of two grounds, and both are derived:
//
//	IT CROSSES INWARD. The package's own source shows the caller producing
//	it: a parameter of an exported function or method, anything in an
//	exported interface's method signatures, or a FIELD of one of those.
//	Signature is a field of RawFinding and of GateConfig; Observation is
//	Reprober.Reprobe's result and Reprober is the caller's to implement.
//
//	IT HOLDS A CAPABILITY. Its field closure contains an interface, a func
//	or a channel. That is not a loophole, it is the residue: a type holding
//	one CANNOT be verdictClosed and CANNOT be verdictBounded, because both
//	walkers refuse those kinds outright, so inbound is the only verdict that
//	can be true of it. Gate reaches eligibility this way — it is returned by
//	NewGate and passed to nothing, but it holds the Reprober seam.
//
// A []byte is deliberately NOT a capability. It is DATA, and raw data on a
// consumer-held type is precisely what the output verdicts exist to forbid, so
// admitting it here would hand back the exemption this function takes away.
// That is the difference between Summary+Raw (ineligible) and Gate (eligible).
//
// THE RESIDUAL, STATED: eligibility is NECESSARY, not sufficient.
// ProvenanceRow is a parameter of SortRows, so it crosses inward and is
// eligible — the thing that stops it being flipped is the other half of the
// bound, boundaryType.carries, which would have to name
// "ProvenanceRow.Operations" in the same diff.
func inboundEligibleTypes(registry map[string]boundaryType, callerSupplied map[string]bool) map[string]bool {
	byType := map[reflect.Type]string{}
	for name, bt := range registry {
		byType[bt.typ] = name
	}

	eligible := map[string]bool{}
	// GROUND 1: the source shows it crossing inward, plus the field closure
	// of everything that does — a type reachable from a parameter is a type
	// the caller had to build.
	seen := map[reflect.Type]bool{}
	var reach func(t reflect.Type)
	reach = func(t reflect.Type) {
		if t == nil || seen[t] {
			return
		}
		seen[t] = true
		if name, ok := byType[t]; ok {
			eligible[name] = true
		}
		switch t.Kind() {
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				reach(t.Field(i).Type)
			}
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
			reach(t.Elem())
		case reflect.Map:
			reach(t.Key())
			reach(t.Elem())
		}
	}
	for name := range callerSupplied {
		bt, ok := registry[name]
		if !ok {
			continue
		}
		eligible[name] = true
		reach(bt.typ)
	}

	// GROUND 2: it holds a capability, so no other verdict can be true of
	// it.
	for name, bt := range registry {
		if holdsACapability(bt.typ) {
			eligible[name] = true
		}
	}
	return eligible
}

// holdsACapability reports whether typ's field closure contains an interface,
// a func or a channel — code or a rendezvous the caller supplies, as opposed
// to DATA the type carries.
//
// The distinction is the whole of ground 2 in inboundEligibleTypes: a []byte
// is data and must never make a type eligible, or the exemption reopens for
// exactly the field it was closed against.
func holdsACapability(typ reflect.Type) bool {
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type) bool
	walk = func(t reflect.Type) bool {
		if t == nil || seen[t] {
			return false
		}
		seen[t] = true
		switch t.Kind() {
		case reflect.Interface, reflect.Func, reflect.Chan:
			return true
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				if walk(t.Field(i).Type) {
					return true
				}
			}
		case reflect.Pointer, reflect.Slice, reflect.Array:
			return walk(t.Elem())
		case reflect.Map:
			return walk(t.Key()) || walk(t.Elem())
		}
		return false
	}
	return walk(typ)
}

// verdictViolations is the per-type verdict check, factored out for the same
// reason unregisteredBoundaryTypes is: a rule that has only ever run against
// the real registry is a rule whose failure nobody has watched.
// TestTheMetaGuardFailsWhenAVerdictIsFlipped runs it against every wrong
// verdict for every registered type.
func verdictViolations(bt boundaryType, eligible map[string]bool) []string {
	closed := closureViolations(bt.typ)
	bounded := outputViolations(bt.typ)
	var out []string

	if bt.verdict != verdictInbound && len(bt.carries) != 0 {
		out = append(out, fmt.Sprintf("%s is registered %s and names carried routes (%s). "+
			"Only an inbound type carries anything: on any other verdict the claim is "+
			"that there is nothing to name", bt.name, bt.verdict,
			strings.Join(bt.carries, ", ")))
	}

	switch bt.verdict {
	case verdictClosed:
		if len(closed) != 0 {
			out = append(out, fmt.Sprintf("%s is registered closed (%s) but its field-type "+
				"closure has %d body route(s):\n%s", bt.name, bt.why, len(closed),
				strings.Join(closed, "\n")))
		}
	case verdictBounded:
		if len(bounded) != 0 {
			out = append(out, fmt.Sprintf("%s is registered bounded (%s) but its closure "+
				"has %d route(s) a raw response body could travel through:\n%s",
				bt.name, bt.why, len(bounded), strings.Join(bounded, "\n")))
		}
		if len(closed) == 0 {
			out = append(out, fmt.Sprintf("%s is registered bounded but its closure is "+
				"CLEAN, so the stronger verdict is true of it. Registering the weaker "+
				"one loses a guarantee in a diff that looks like nothing", bt.name))
		}
	case verdictInbound:
		if !eligible[bt.name] {
			out = append(out, fmt.Sprintf("%s is registered inbound and NOTHING IN THE "+
				"PACKAGE'S OWN SOURCE says it travels inward: it is not a parameter of "+
				"an exported function, not in an exported interface's signatures, not a "+
				"field of anything that is, and it holds no interface, func or channel. "+
				"verdictInbound is not a way to stop the walkers looking — MEASURED, a "+
				"one-word flip from bounded to inbound hid a `Raw []byte` on Summary. "+
				"Register the true verdict, or explain why the type is inbound in the "+
				"API rather than in this table", bt.name))
		}
		if len(closed) == 0 {
			out = append(out, fmt.Sprintf("%s is registered inbound (%s) but its closure "+
				"is clean, which means it stopped carrying the thing it exists to carry",
				bt.name, bt.why))
		}
		got := violationPaths(closed)
		want := append([]string(nil), bt.carries...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			out = append(out, fmt.Sprintf("%s is registered inbound carrying {%s} and its "+
				"closure actually holds {%s}. An inbound verdict covers EXACTLY the "+
				"routes it names: a new one is a new body route and has to be declared "+
				"in the same diff that adds it, and a stale one is a claim about a "+
				"field that is gone", bt.name, strings.Join(want, ", "),
				strings.Join(got, ", ")))
		}
	default:
		out = append(out, fmt.Sprintf("%s carries verdict %q, which is not one this test "+
			"knows", bt.name, bt.verdict))
	}
	return out
}

// outputViolations is the verdictBounded walk: no route to a raw body, and no
// reference a consumer could be surprised by, but sequences and maps of closed
// types are permitted.
//
// It is strictly weaker than closureViolations — anything the latter passes,
// this passes — which is what makes "register the strongest true verdict" a
// meaningful rule rather than a preference.
func outputViolations(typ reflect.Type) []string {
	var out []string
	seen := map[reflect.Type]bool{}
	basic := func(k reflect.Kind) bool {
		switch k {
		case reflect.String, reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			return true
		}
		return false
	}
	var walk func(path string, t reflect.Type)
	walk = func(path string, t reflect.Type) {
		if t == nil || seen[t] {
			return
		}
		seen[t] = true
		switch {
		case basic(t.Kind()):
			return
		case t.Kind() == reflect.Uint8:
			// A lone byte is a scalar. A SEQUENCE of them is a body, and
			// that is caught below.
			return
		case t.Kind() == reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				walk(path+"."+f.Name, f.Type)
			}
		case t.Kind() == reflect.Slice || t.Kind() == reflect.Array:
			if t.Elem().Kind() == reflect.Uint8 {
				out = append(out, fmt.Sprintf("%s is %s: a byte sequence is a raw "+
					"response body, and plan/00-SPINE.md S7 forbids inlining one", path, t))
				return
			}
			walk(path+"[]", t.Elem())
		case t.Kind() == reflect.Map:
			walk(path+"{key}", t.Key())
			walk(path+"{}", t.Elem())
		case t.Kind() == reflect.Pointer:
			if basic(t.Elem().Kind()) {
				// A pointer to a scalar is a NULL-able number, which is
				// this package's whole shape for "nothing was measured".
				// See Summary.serverLine and coverage.go, ScanMode.
				return
			}
			out = append(out, fmt.Sprintf("%s is a pointer to %s: a pointer to anything "+
				"but a scalar is a reference a body can be reached through", path, t.Elem()))
		default:
			out = append(out, fmt.Sprintf("%s is a %s (%s): a consumer-held output type "+
				"may not carry one", path, t.Kind(), t))
		}
	}
	walk(typ.Name(), typ)
	return out
}

// exportedResultTypeNames derives three sets from this package's own source
// and returns all three, because the meta-guard needs one for MEMBERSHIP, one
// for NON-VACUITY and one for DIRECTION, and conflating them is what let two
// types go unwalked and then let a verdict be flipped on a third.
//
//	declared        every exported type declared in this package's non-test
//	                files. THIS IS THE MEMBERSHIP RULE. A type that exists
//	                and is not registered fails, whatever it is and wherever
//	                it appears.
//	handedBack      the subset that appears in a RESULT position of an
//	                exported function, an exported method, or an exported
//	                interface's method.
//	callerSupplied  the subset the package's API requires the CALLER to
//	                produce: a parameter of an exported function or method,
//	                anything in an exported interface's method signatures
//	                (the caller implements it, so its results travel inward
//	                too), or the exported interface type itself.
//
// THE THIRD SET IS THE DIRECTION HALF OF verdictInbound, and it is derived
// here rather than judged in the registry because "this type travels inward"
// was exactly the claim a one-word edit could make about anything.
//
// ===========================================================================
// WHY MEMBERSHIP IS "DECLARED" AND NOT "HANDED BACK"
// ===========================================================================
//
// It was "handed back", and MEASURED: that derivation reached 21 of this
// package's 26 exported types, and deleting RawFinding and RefusalError from
// boundaryTypes left the meta-guard GREEN. That is the Summary/ProvenanceRow
// defect — a membership rule that does not enumerate its own members — still
// live in the fix written to close it, one level further down. RawFinding
// travels IN and is never returned, so no result position mentions it; it is
// still a type a consumer builds and holds, and a body field added to it is
// still a body field nobody would have walked.
//
// So the rule is now the widest thing the source can state: EVERY EXPORTED
// TYPE. It has no exclusion list, deliberately, for the same reason
// applicationResponseStatuses has no deny side — an exclusion list is a second
// list to keep current, and forgetting to add to it is invisible. A type that
// genuinely cannot be walked is registered with the verdict that says so and a
// reason; registering is the human act, forgetting is not an option.
//
// It reads the source rather than using reflection because Go cannot enumerate
// a package's declarations at runtime. The parse is of the NON-TEST files
// only: a type declared in a test is not API.
func exportedResultTypeNames(t *testing.T) (declaredOut, handedBack, callerSupplied map[string]bool) {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parsing %s: %v", n, perr)
		}
		files = append(files, f)
	}
	if len(files) < 2 {
		t.Fatalf("parsed %d non-test source files; the derivation is reading the wrong "+
			"directory and would report an empty rule", len(files))
	}

	declared := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.IsExported() {
				declared[ts.Name.Name] = true
			}
			return true
		})
	}

	out := map[string]bool{}
	var collect func(e ast.Expr)
	collect = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.Ident:
			if declared[v.Name] {
				out[v.Name] = true
			}
		case *ast.StarExpr:
			collect(v.X)
		case *ast.ParenExpr:
			collect(v.X)
		case *ast.ArrayType:
			collect(v.Elt)
		case *ast.Ellipsis:
			collect(v.Elt)
		case *ast.ChanType:
			collect(v.Value)
		case *ast.MapType:
			collect(v.Key)
			collect(v.Value)
		}
		// A SelectorExpr is a type from another package and is that
		// package's problem; a FuncType, StructType or InterfaceType in a
		// result position is anonymous and has no name to register.
	}
	inward := map[string]bool{}
	var collectInward func(e ast.Expr)
	collectInward = func(e ast.Expr) {
		saved := out
		out = inward
		collect(e)
		out = saved
	}
	results := func(ft *ast.FuncType) {
		if ft == nil || ft.Results == nil {
			return
		}
		for _, f := range ft.Results.List {
			collect(f.Type)
		}
	}
	params := func(ft *ast.FuncType) {
		if ft == nil || ft.Params == nil {
			return
		}
		for _, f := range ft.Params.List {
			collectInward(f.Type)
		}
	}

	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				if !v.Name.IsExported() {
					return true
				}
				if v.Recv != nil && len(v.Recv.List) == 1 {
					// A method on an unexported type is not reachable.
					var recv ast.Expr = v.Recv.List[0].Type
					if star, ok := recv.(*ast.StarExpr); ok {
						recv = star.X
					}
					if id, ok := recv.(*ast.Ident); ok && !id.IsExported() {
						return true
					}
				}
				results(v.Type)
				params(v.Type)
			case *ast.TypeSpec:
				it, ok := v.Type.(*ast.InterfaceType)
				if !ok || !v.Name.IsExported() || it.Methods == nil {
					return true
				}
				// AN EXPORTED INTERFACE IS IMPLEMENTED BY THE CALLER, so
				// everything in its method signatures crosses inward —
				// its RESULTS included. Observation is only ever produced
				// by Reprober.Reprobe, which is the caller's code.
				inward[v.Name.Name] = true
				for _, m := range it.Methods.List {
					if ft, ok := m.Type.(*ast.FuncType); ok {
						results(ft)
						params(ft)
						if ft.Results != nil {
							for _, r := range ft.Results.List {
								collectInward(r.Type)
							}
						}
					}
				}
			}
			return true
		})
	}
	return declared, out, inward
}

// unregisteredBoundaryTypes is the membership rule, factored out so a test can
// run it against a registry with something DELETED. A rule that only ever sees
// the real registry is a rule whose failure nobody has watched.
func unregisteredBoundaryTypes(declared map[string]bool, registry map[string]boundaryType) []string {
	var missing []string
	for name := range declared {
		if _, ok := registry[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// TestTheMetaGuardFailsWhenARegistrationIsDeleted is the mutation the previous
// derivation could not survive.
//
// MEASURED against the result-position rule: deleting RawFinding and
// RefusalError from boundaryTypes left TestEveryExportedTypeThatCrossesTheBoundaryIsWalked
// GREEN, because neither type appears in any result position. Both are still
// types a consumer builds and holds. This test deletes each registration in
// turn and asserts the membership rule reports it — so the guard's failure is
// something this suite has watched happen, for every entry, rather than
// something a reader is asked to believe.
func TestTheMetaGuardFailsWhenARegistrationIsDeleted(t *testing.T) {
	declared, _, _ := exportedResultTypeNames(t)
	full := map[string]boundaryType{}
	for _, bt := range boundaryTypes() {
		full[bt.name] = bt
	}
	if got := unregisteredBoundaryTypes(declared, full); len(got) != 0 {
		t.Fatalf("the intact registry already reports %v missing; the mutation below "+
			"cannot be distinguished from the baseline", got)
	}

	for _, bt := range boundaryTypes() {
		t.Run(bt.name, func(t *testing.T) {
			mutated := map[string]boundaryType{}
			for name, v := range full {
				if name == bt.name {
					continue
				}
				mutated[name] = v
			}
			got := unregisteredBoundaryTypes(declared, mutated)
			if len(got) != 1 || got[0] != bt.name {
				t.Errorf("with %s deleted from the registry, the membership rule reports "+
					"%v. Forgetting this type is invisible, which is exactly the state "+
					"RawFinding and RefusalError were in", bt.name, got)
			}
		})
	}

	// THE TWO MEASURED TYPES BY NAME, because a reader coming from the
	// finding will look for them.
	for _, name := range []string{"RawFinding", "RefusalError"} {
		if !declared[name] {
			t.Errorf("%s is not in the derived membership set. It was the type the "+
				"result-position derivation could not see, and if the derivation has "+
				"narrowed back, this whole guard has too", name)
		}
	}
}

// TestTheMetaGuardFailsWhenAVerdictIsFlipped is the mutation the VERDICT half
// could not survive, and it is the exact counterpart of
// TestTheMetaGuardFailsWhenARegistrationIsDeleted for the other half of the
// registry.
//
// ===========================================================================
// THE MEASURED DEFECT
// ===========================================================================
//
// The membership half was derived and mutation-tested; the verdict half was a
// human claim with one non-vacuity check each, and verdictInbound's check —
// "closureViolations must be non-empty" — IS SATISFIED BY THE VIOLATION
// ITSELF. Adding `Raw []byte` to Summary and changing one word, bounded to
// inbound, left the whole package GREEN. Finding was defended against that by
// TestFindingTypeClosureHasNoRawBodyPath, which asserts its closure outside
// this registry; Summary had nothing, and neither did Ledger, ProvenanceRow or
// any other output type.
//
// So this test flips EVERY registration to EVERY other verdict and requires
// the check to report it. That is the same standard the deletion mutation
// holds membership to: the guard's failure is something this suite has watched
// happen, for every entry, rather than something a reader is asked to believe.
//
// It flips the verdict AND NOTHING ELSE, which is the point: the mutation
// under test is the one-word edit. A flip to inbound keeps the entry's own
// carries (empty, for every type that is not already inbound), so the routes
// half refuses it; and eligibility refuses it before that wherever the type
// has no claim on the exemption at all.
func TestTheMetaGuardFailsWhenAVerdictIsFlipped(t *testing.T) {
	registry := map[string]boundaryType{}
	for _, bt := range boundaryTypes() {
		registry[bt.name] = bt
	}
	_, _, callerSupplied := exportedResultTypeNames(t)
	eligible := inboundEligibleTypes(registry, callerSupplied)

	// The baseline: the intact registry must be clean, or a mutation below
	// cannot be told from the state it started in.
	for _, bt := range boundaryTypes() {
		if v := verdictViolations(bt, eligible); len(v) != 0 {
			t.Fatalf("the intact registry already reports %s: %s. Every mutation below "+
				"would pass for that reason instead of its own",
				bt.name, strings.Join(v, "\n"))
		}
	}

	all := []boundaryVerdict{verdictClosed, verdictBounded, verdictInbound}
	flips := 0
	for _, bt := range boundaryTypes() {
		for _, v := range all {
			if v == bt.verdict {
				continue
			}
			mutated := bt
			mutated.verdict = v
			t.Run(bt.name+"_as_"+string(v), func(t *testing.T) {
				if got := verdictViolations(mutated, eligible); len(got) == 0 {
					t.Errorf("%s registered %s instead of %s is reported by NOTHING. A "+
						"verdict nobody checks is a verdict anybody can edit, and the "+
						"measured version of this edit hid a raw body field on an "+
						"output type", bt.name, v, bt.verdict)
				}
			})
			flips++
		}
	}
	if flips != 2*len(boundaryTypes()) {
		t.Errorf("the sweep tried %d flips over %d registrations, want %d; it is not "+
			"covering every wrong verdict for every type",
			flips, len(boundaryTypes()), 2*len(boundaryTypes()))
	}

	// AND THE MEASURED EDIT ITSELF, END TO END, on a stand-in with Summary's
	// shape plus the field that was added to it. A registration claiming
	// this is inbound must be refused on BOTH grounds — it is not eligible,
	// and it names none of the routes it holds — because either one alone is
	// a bound somebody can argue their way past.
	type summaryWithRawBody struct {
		Qualifiers []Qualifier
		Rows       []ProvenanceRow
		ServerLine *float64
		Raw        []byte
	}
	forged := boundaryType{
		name:    "summaryWithRawBody",
		typ:     reflect.TypeOf(summaryWithRawBody{}),
		verdict: verdictInbound,
		why:     "the measured one-word flip, as a fixture",
	}
	got := verdictViolations(forged, eligible)
	if len(got) < 2 {
		t.Errorf("a Summary-shaped type carrying `Raw []byte`, registered inbound, is "+
			"reported by %d check(s): %s. It must be refused twice — once for claiming "+
			"an exemption it has no source-derived claim to, and once for not naming "+
			"the routes it carries", len(got), strings.Join(got, "\n"))
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{"NOTHING IN THE PACKAGE'S OWN SOURCE", ".Raw"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the refusal of the forged inbound registration does not mention "+
				"%q:\n%s", want, joined)
		}
	}

	// THE NEGATIVE CONTROL ON THE FIXTURE: the same type WITHOUT the raw
	// body must still be refused (it is still not eligible), and a genuinely
	// inbound type must still be accepted, or the check above is just
	// refusing everything.
	if v := verdictViolations(registry["Observation"], eligible); len(v) != 0 {
		t.Errorf("Observation, which carries the response body by design and is the "+
			"result of the caller-implemented Reprober, is refused: %s. The bound has "+
			"become a ban and the seam cannot be expressed", strings.Join(v, "\n"))
	}
}

// TestEveryExportedTypeThatCrossesTheBoundaryIsWalked is the meta-guard: it is
// what stops the next field like Refusal.Err from being added to a type nobody
// points the walker at.
//
// ===========================================================================
// IT WAS THE DEFECT IT WAS WRITTEN TO PREVENT, ONE LEVEL UP
// ===========================================================================
//
// The list used to be written out by name, with a stated rule beside it, and
// the justification was that Go cannot enumerate a package's types at runtime.
// It named four record types plus Ledger — and OMITTED Summary and
// ProvenanceRow, the package's other two consumer-held output types, both of
// which satisfy the rule the comment stated. A MEMBERSHIP RULE THAT DOES NOT
// ENUMERATE ITS OWN MEMBERS is exactly the failure the walker exists to catch,
// moved up a level where nothing was watching.
//
// So the list is DERIVED, and this round the derivation got WIDER. It used to
// be "every type in a result position", which reached 21 of 26 exported types
// and left RawFinding and RefusalError registered by nothing — deleting both
// from boundaryTypes left this test green, which is the same defect again, one
// level down. The rule is now EVERY EXPORTED TYPE DECLARED IN THIS PACKAGE.
// Registering a verdict for each is still a human act — the verdicts are
// claims, and a claim needs a reason — but FORGETTING one is not possible,
// because the derivation fails the test rather than shrinking silently.
//
// TestTheMetaGuardFailsWhenARegistrationIsDeleted is the mutation: it removes
// a registration and checks that the membership rule reports it.
func TestEveryExportedTypeThatCrossesTheBoundaryIsWalked(t *testing.T) {
	registry := map[string]boundaryType{}
	for _, bt := range boundaryTypes() {
		if _, dup := registry[bt.name]; dup {
			t.Fatalf("%s is registered twice", bt.name)
		}
		if bt.why == "" {
			t.Errorf("%s is registered with no reason; a verdict without an argument is "+
				"the next author's blank cheque", bt.name)
		}
		registry[bt.name] = bt
	}

	// THE DERIVATION IS THE RULE, and the registry is measured against it.
	declared, handedBack, callerSupplied := exportedResultTypeNames(t)
	if len(declared) < 20 {
		t.Fatalf("the derivation found %d exported types declared in this package; it is "+
			"not working and every assertion below is vacuous", len(declared))
	}
	if len(handedBack) < 10 {
		t.Fatalf("the derivation found %d handed-back types; the result-position half has "+
			"stopped working and the non-vacuity checks below are worthless",
			len(handedBack))
	}
	// The two must not have become the same query. If they had, the widening
	// this round exists for would be undone and nothing would say so.
	if len(handedBack) >= len(declared) {
		t.Errorf("the derivation reports %d declared and %d handed back. Membership is "+
			"supposed to be the WIDER of the two: it was 'handed back' before, that "+
			"reached 21 of 26, and RawFinding and RefusalError could be deleted from "+
			"the registry with a green build", len(declared), len(handedBack))
	}

	missing := unregisteredBoundaryTypes(declared, registry)
	if len(missing) != 0 {
		t.Errorf("%d exported type(s) are declared by this package and walked by nothing: "+
			"%s. Add each to boundaryTypes with a verdict and a reason. There is no "+
			"exclusion list on purpose: a type nobody can walk is registered with the "+
			"verdict that says so, because an exclusion is a second list to keep "+
			"current and forgetting to add to it is invisible",
			len(missing), strings.Join(missing, ", "))
	}

	// AND THE OTHER DIRECTION: a registered name that is no longer declared
	// here is a stale entry, and a stale entry is a walk that proves nothing
	// about the current code. This is derived too — the four names it used
	// to check were themselves a hand-written list.
	var stale []string
	for name := range registry {
		if !declared[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) != 0 {
		t.Errorf("%d registered name(s) are no longer declared in this package: %s. A "+
			"stale registration walks a type the package does not have",
			len(stale), strings.Join(stale, ", "))
	}

	// The named output types, still checked against the RESULT-position half,
	// because "Summary is handed back" is the fact their verdicts rest on and
	// membership no longer asserts it.
	for _, out := range []string{"Summary", "ProvenanceRow", "Ledger", "Finding"} {
		if !handedBack[out] {
			t.Errorf("%s is registered but the derivation does not see it handed back; "+
				"either it stopped being output or the derivation stopped working", out)
		}
	}

	// THE DIRECTION HALF OF verdictInbound, derived before the walk so the
	// exemption can be refused to a type that has no claim on it.
	eligible := inboundEligibleTypes(registry, callerSupplied)
	if len(eligible) == 0 {
		t.Fatal("no registered type is eligible for the inbound verdict; the derivation " +
			"is not working and every inbound registration below would fail for the " +
			"wrong reason")
	}
	if len(eligible) >= len(registry) {
		t.Errorf("%d of %d registered types are eligible for the inbound exemption. It is "+
			"supposed to be the minority that genuinely crosses inward or holds a "+
			"capability; an eligibility rule that admits everything is the total "+
			"exemption again under a longer name", len(eligible), len(registry))
	}
	// THE MEASURED FLIP, BY NAME. Summary is the type the one-word edit was
	// measured on, so it is asserted here rather than left to the sweep.
	if eligible["Summary"] {
		t.Error("Summary is eligible for the inbound exemption. MEASURED: adding " +
			"`Raw []byte` to Summary and changing bounded to inbound left this package " +
			"GREEN, and this is the check that is supposed to refuse the claim before " +
			"its routes are looked at")
	}

	// THE WALK ITSELF, one verdict at a time.
	for _, bt := range boundaryTypes() {
		t.Run(bt.name, func(t *testing.T) {
			for _, v := range verdictViolations(bt, eligible) {
				t.Error(v)
			}
		})
	}

	// THE NEGATIVE CONTROLS ON BOTH WALKERS. A walker that reported clean on
	// everything would pass every assertion above.
	if v := outputViolations(reflect.TypeOf(bodyCarrier{})); len(v) == 0 {
		t.Error("outputViolations reports the body-carrying fixture clean; it cannot see " +
			"a violation and every bounded verdict above is worthless")
	}
	if v := outputViolations(reflect.TypeOf(struct {
		Names  []string
		Counts map[string]int
		Ratio  *float64
	}{})); len(v) != 0 {
		t.Errorf("outputViolations refuses a struct of a string slice, a scalar map and a "+
			"NULL-able float: %s. Those are the shapes Summary is made of, and a walker "+
			"that refuses them cannot express the bounded verdict at all",
			strings.Join(v, "\n"))
	}
	if v := closureViolations(reflect.TypeOf(struct{ Names []string }{})); len(v) == 0 {
		t.Error("closureViolations reports a struct holding a []string clean; the two " +
			"walkers are no longer ordered by strength and the bounded/closed " +
			"distinction means nothing")
	}
}

// TestEveryTestNamedInASourceCommentExists closes the class of defect that
// produced two false claims in this round alone.
//
// This package's production files cite tests by name, dozens of times, because
// "the claim is driven over there" is how a reader checks a comment rather
// than believing it. A CITATION TO A TEST THAT DOES NOT EXIST IS A CLAIM THAT
// CANNOT BE CHECKED, and it reads as evidence anyway — which is worse than no
// citation, because a reader who cannot find the test assumes they searched
// badly. MEASURED IN THIS FILE: confirm_gate.go and confirm_gate_test.go both
// pointed at an "...AloneAreACleanScan" spelling of the phantom-cluster test,
// which has never existed; the test they meant is
// TestEightyEightPhantomsAloneProduceCompletedCleanAndThatIsHonest. The dead
// name is not written out here, because this guard would flag its own
// narration -- which is the first thing it did.
//
// The check is derived, not enumerated: every `Test<Something>` token in any
// comment in this package's source is resolved against the test functions
// actually declared in the repository. A rename that leaves a citation behind
// fails here, in the same commit as the rename.
func TestEveryTestNamedInASourceCommentExists(t *testing.T) {
	// The universe: every test function declared anywhere in the module.
	// Repo-wide rather than package-local because a comment may legitimately
	// cite the kernel's own guards — this file's header cites
	// TestAdmissionInputClosureIsClosed, which lives in internal/dast/authz.
	declared := map[string]bool{}
	root := filepath.Join("..", "..", "..")
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			declared[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module for test declarations: %v", err)
	}
	if len(declared) < 100 {
		t.Fatalf("found %d test functions in the module; the walk is not working and "+
			"every citation below would pass for the wrong reason", len(declared))
	}
	// The positive control on the walk itself: it must be able to see a test
	// it is standing inside.
	if !declared["TestEveryTestNamedInASourceCommentExists"] {
		t.Fatal("the walk cannot see this very test; it is reading the wrong tree")
	}

	// The citations: every Test<Name> token appearing in a COMMENT in this
	// package's source, test files included.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	cite := regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]{3,}`)
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, perr := parser.ParseFile(fset, e.Name(), nil, parser.ParseComments|parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parsing %s: %v", e.Name(), perr)
		}
		for _, group := range f.Comments {
			for _, c := range group.List {
				for _, name := range cite.FindAllString(c.Text, -1) {
					checked++
					if declared[name] {
						continue
					}
					t.Errorf("%s:%d cites %s, and no test by that name is declared "+
						"anywhere in the module. A citation a reader cannot follow is "+
						"read as evidence and is not any",
						e.Name(), fset.Position(c.Pos()).Line, name)
				}
			}
		}
	}
	if checked < 10 {
		t.Errorf("only %d test citations were checked; this package's comments cite tests "+
			"far more often than that and the scan is missing them", checked)
	}
}

// ===========================================================================
// D.29 CRITICAL 2 — a target that defends itself is not a target with nothing
// ===========================================================================

// TestARateLimitedReprobeIsNotADisproof is the failure this project exists to
// avoid, driven end to end.
//
// MEASURED BEFORE THE FIX: Observation.Status was captured at the re-probe,
// stamped onto the Finding, and read by nothing. decide() never saw it. A
// genuinely vulnerable target whose rate limiter trips during the
// confirmation pass answered 429 on all three attempts; the signature matched
// none of them because the application never ran; and the candidate came out
// outcome=rejected, reason=did_not_reproduce_on_any_attempt, confidence
// 0.000 — byte-for-byte indistinguishable from one of the 88 phantoms. The
// ledger then reported FindingCountForStatus()==0 and derived
// completed_clean over a live vulnerability.
//
// The neighbours are here for the reason the encodings lesson is in this
// file's header: 429 is one spelling of "the target did not answer as the
// application" and a guard that recognised only 429 would be a denylist of
// one. It was subsequently a denylist of FOUR, which 403 walked over; the
// exhaustive version of this test is
// TestEveryStatusOutsideTheApplicationAllowlistIsIndecisive and these cases
// remain because they are the named scenarios a reader comes here looking
// for.
func TestARateLimitedReprobeIsNotADisproof(t *testing.T) {
	// The body the target WOULD have returned. It reproduces the oracle
	// every time, so every rejection below would be a rejection of
	// something real — which is what makes the assertions mean anything.
	vulnerable := []byte(`{"error":"` + sqliMarker + `"}`)
	// The WAF's block page. Status 200, no marker: the case a status-code
	// check alone cannot see.
	blockPage := []byte(`<html><head><title>Request Blocked</title></head>` +
		`<body>Your request was blocked by policy reference 8812-AA.</body></html>`)
	blockSig := mustSignature(t, `blocked by policy reference [0-9]{4}-[A-Z]{2}`)

	for _, tc := range []struct {
		name string
		cfg  func(Reprober) GateConfig
		rp   *scriptedReprober
		// wantErr means the candidate never became a Finding at all.
		wantErr        bool
		wantReason     Reason
		wantOutcome    Outcome
		wantIndecisive int
		wantMatches    int
	}{
		{
			name: "429 on every attempt",
			rp: &scriptedReprober{
				body:     func(RawFinding, int) []byte { return []byte(`{"error":"too many requests"}`) },
				statusFn: func(RawFinding, int) int { return 429 },
			},
			wantReason: ReasonReprobeIndecisive, wantOutcome: OutcomeUnconfirmed,
			wantIndecisive: 3, wantMatches: 0,
		},
		{
			name: "503 on every attempt",
			rp: &scriptedReprober{
				body:     func(RawFinding, int) []byte { return []byte(`upstream unavailable`) },
				statusFn: func(RawFinding, int) int { return 503 },
			},
			wantReason: ReasonReprobeIndecisive, wantOutcome: OutcomeUnconfirmed,
			wantIndecisive: 3, wantMatches: 0,
		},
		{
			name: "no status reported at all",
			rp: &scriptedReprober{
				body:     func(RawFinding, int) []byte { return []byte(`{}`) },
				statusFn: func(RawFinding, int) int { return 0 },
			},
			wantReason: ReasonReprobeIndecisive, wantOutcome: OutcomeUnconfirmed,
			wantIndecisive: 3, wantMatches: 0,
		},
		{
			name: "a WAF block page returning 200",
			cfg: func(rp Reprober) GateConfig {
				return GateConfig{Reprober: rp, Attempts: 3, DefenceSignature: blockSig}
			},
			rp: &scriptedReprober{
				body:     func(RawFinding, int) []byte { return blockPage },
				statusFn: func(RawFinding, int) int { return 200 },
			},
			wantReason: ReasonReprobeIndecisive, wantOutcome: OutcomeUnconfirmed,
			wantIndecisive: 3, wantMatches: 0,
		},
		{
			name: "a connection reset on one attempt",
			rp: &scriptedReprober{
				body: func(RawFinding, int) []byte { return vulnerable },
				errFn: func(_ RawFinding, attempt int) error {
					if attempt == 2 {
						return errors.New("read tcp 127.0.0.1:54321->127.0.0.1:8080: " +
							"connection reset by peer")
					}
					return nil
				},
			},
			wantErr: true,
		},
		{
			name: "a mixed run: the limiter trips part way through",
			rp: &scriptedReprober{
				body: func(_ RawFinding, attempt int) []byte {
					if attempt == 1 {
						return vulnerable
					}
					return []byte(`{"error":"too many requests"}`)
				},
				statusFn: func(_ RawFinding, attempt int) int {
					if attempt == 1 {
						return 200
					}
					return 429
				},
			},
			wantReason: ReasonReproducedIntermittently, wantOutcome: OutcomeUnconfirmed,
			wantIndecisive: 2, wantMatches: 1,
		},
		{
			// THE POSITIVE CONTROL. The identical candidate against a
			// target that answers is CONFIRMED. Without it every assertion
			// above would pass against a gate that confirms nothing.
			name: "the target answers and the oracle reproduces",
			rp: &scriptedReprober{
				body:     func(RawFinding, int) []byte { return vulnerable },
				statusFn: func(RawFinding, int) int { return 200 },
			},
			wantReason: ReasonReproduced, wantOutcome: OutcomeConfirmed,
			wantIndecisive: 0, wantMatches: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := GateConfig{Reprober: tc.rp, Attempts: 3}
			if tc.cfg != nil {
				cfg = tc.cfg(tc.rp)
			}
			g := mustGate(t, cfg)
			f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))

			if tc.wantErr {
				// A transport failure is a REFUSAL, not a rejection: the
				// re-probe did not complete, so nothing was disproved.
				if !errors.Is(err, ErrNotReprobed) {
					t.Fatalf("ConfirmFinding = (%v, %v), want ErrNotReprobed. A candidate "+
						"whose re-probe died mid-pass must not come back rejected", f, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ConfirmFinding: %v", err)
			}

			if f.Outcome() == OutcomeRejected {
				t.Errorf("outcome = rejected. THIS IS THE FAILURE: a re-probe the target "+
					"never answered has disproved nothing, and a rejection here is a "+
					"real vulnerability reported as a phantom. %s", f)
			}
			if got := f.Outcome(); got != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q. %s", got, tc.wantOutcome, f)
			}
			if got := f.Reason(); got != tc.wantReason {
				t.Errorf("reason = %q, want %q. %s", got, tc.wantReason, f)
			}
			if got := f.IndecisiveAttempts(); got != tc.wantIndecisive {
				t.Errorf("IndecisiveAttempts = %d, want %d. %s", got, tc.wantIndecisive, f)
			}
			if got := f.SignatureMatches(); got != tc.wantMatches {
				t.Errorf("SignatureMatches = %d, want %d. %s", got, tc.wantMatches, f)
			}

			// AN INDECISIVE RUN REPORTS NO CONFIDENCE. matches/attempts over
			// a run the application never answered counts questions that
			// were never asked, and 0.000 reads as "certainly not a
			// vulnerability".
			conf, ok := f.Confidence()
			if tc.wantIndecisive > 0 && ok {
				t.Errorf("confidence = (%v,true) over a run with %d indecisive attempt(s); "+
					"that ratio's denominator counts questions nobody asked",
					conf, tc.wantIndecisive)
			}
			if tc.wantIndecisive == 0 && !ok {
				t.Error("confidence unknown for a fully answered run of an oracle-bearing " +
					"class detected by template")
			}

			// AN INDECISIVE ATTEMPT'S BODY IS NEVER EXTRACTED FROM. A block
			// page that happened to contain the marker would otherwise be
			// quoted as evidence attributed to the application.
			if tc.wantIndecisive == 3 && f.Evidence().ExtractedSpan() != "" {
				t.Errorf("a wholly indecisive run carries evidence span %q",
					printable(f.Evidence().ExtractedSpan(), 64))
			}
			if f.Evidence().BodyHash() == "" {
				t.Error("an indecisive run carries no body hash; the hash is the proof " +
					"Anvil looked, and without it an unanswered re-probe is " +
					"indistinguishable from a probe that never ran")
			}
		})
	}
}

// TestADefendedLedgerIsNeverReadAsCompletedClean is the other half of
// CRITICAL 2: the arithmetic, all the way to dast_status.
func TestADefendedLedgerIsNeverReadAsCompletedClean(t *testing.T) {
	const n = 12
	rp := &scriptedReprober{
		body:     func(RawFinding, int) []byte { return []byte(`{"error":"too many requests"}`) },
		statusFn: func(RawFinding, int) int { return 429 },
	}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})

	var candidates []RawFinding
	for i := 0; i < n; i++ {
		candidates = append(candidates, sqliCandidate(t, fmt.Sprintf("/api/v1/item/%d", i)))
	}
	l, err := g.ConfirmAll(context.Background(), candidates)
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}

	// ASSERT THE COUNT, NOT MERELY THAT ROWS EXIST.
	if got := l.RejectedCount(); got != 0 {
		t.Errorf("rejected = %d, want 0. Every one of these %d candidates was answered "+
			"with a rate limit and none of them was disproved. %s", got, n, l)
	}
	if got, want := l.UnconfirmedCount(), n; got != want {
		t.Fatalf("unconfirmed = %d, want %d. %s", got, want, l)
	}
	if got := l.FindingCountForStatus(); got != 0 {
		t.Fatalf("FindingCountForStatus = %d; an unconfirmed finding did not pass the "+
			"re-probe step and must not reach dast_status: findings", got)
	}

	// AND THE LEDGER SAYS SO. This is the call that used to return nil.
	if aerr := l.AssertNotSilentlyClean(); !errors.Is(aerr, ErrSilentlyClean) {
		t.Errorf("AssertNotSilentlyClean = %v, want ErrSilentlyClean. %d candidates the "+
			"target refused to answer produce a zero confirmed count, and reporting "+
			"completed_clean from that ledger tells a coding agent Anvil looked and "+
			"found nothing", aerr, n)
	}
}

// TestAssertNotSilentlyCleanSeesUnconfirmedAndRefusedAndNotOnlyOne closes the
// half of CRITICAL 2 that is about the assertion itself.
//
// AssertNotSilentlyClean consulted UnconfirmedCount alone, so a ledger of
// nothing but refusals read as an earned clean. It also grew a third term —
// IndecisiveRejectionCount, "rejections that could not have disproved
// anything" — which was MEASURED unreachable from every production path and
// has been deleted along with the claim that it was a second line of defence.
// See assertRejectionIsDecisive for what replaced it and
// TestARejectionThatCouldNotHaveDisprovedAnythingIsRefused for the proof that
// the replacement can fire.
//
// A REJECTION IS NOT A REASON TO WITHHOLD `clean`. That is the gate's whole
// purpose and TestEightyEightPhantomsAloneProduceCompletedCleanAndThatIsHonest is the case.
func TestAssertNotSilentlyCleanSeesUnconfirmedAndRefusedAndNotOnlyOne(t *testing.T) {
	rejected := Finding{
		engine: "zap", target: "t", method: "GET", path: "/x",
		class: ClassInjection, detection: DetectionMethodTemplate,
		outcome: OutcomeRejected, reason: ReasonDidNotReproduce,
		evidence: EvidenceRef{bodyHash: strings.Repeat("0", 64), sealed: true},
		status:   200, attempts: 3, matches: 0, indecisive: 0,
		sealed: true,
	}
	unconfirmed := rejected
	unconfirmed.outcome, unconfirmed.reason = OutcomeUnconfirmed, ReasonReprobeIndecisive
	confirmed := rejected
	confirmed.outcome, confirmed.reason = OutcomeConfirmed, ReasonReproduced

	refusal := Refusal{Index: 0, Reason: RefuseNotReprobed, Detail: "GET /x",
		Err: newRefusalError(ErrNotReprobed)}

	for _, tc := range []struct {
		name      string
		findings  []Finding
		refusals  []Refusal
		wantClean bool
	}{
		{"an honest disproof", []Finding{rejected}, nil, true},
		{"nothing at all", nil, nil, true},
		{"one undecidable finding", []Finding{unconfirmed}, nil, false},
		{"one refused candidate", nil, []Refusal{refusal}, false},
		{"a rejection beside an undecidable one", []Finding{rejected, unconfirmed}, nil, false},
		{"a rejection beside a refusal", []Finding{rejected}, []Refusal{refusal}, false},
		// A confirmed finding short-circuits: the caller is not about to
		// read this ledger as clean, so there is nothing to refuse.
		{"a confirmed finding beside an undecidable one",
			[]Finding{confirmed, unconfirmed}, []Refusal{refusal}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := Ledger{findings: tc.findings, refusals: tc.refusals, sealed: true}
			err := l.AssertNotSilentlyClean()
			if gotClean := err == nil; gotClean != tc.wantClean {
				t.Errorf("AssertNotSilentlyClean clean=%v, want %v. %s (%v)",
					gotClean, tc.wantClean, l, err)
			}
			if err != nil && !errors.Is(err, ErrSilentlyClean) {
				t.Errorf("error = %v, want ErrSilentlyClean", err)
			}
		})
	}
}

// TestARejectionThatCouldNotHaveDisprovedAnythingIsRefused is the control that
// replaced Ledger.IndecisiveRejectionCount.
//
// The count was unreachable: MEASURED by sweeping ConfirmAll over 26 statuses
// crossed with {the signature matches, the signature does not match} — 52 runs
// — it returned non-zero zero times, because decide()'s rule 2 routes every
// indecisive run to ReasonReprobeIndecisive before ReasonDidNotReproduce can
// be reached. The report that called it "the second line of
// AssertNotSilentlyClean" was describing a control that cannot fire.
//
// assertRejectionIsDecisive states the same invariant where it CAN fire: it
// runs on every Finding ConfirmFinding assembles, and it turns a violation
// into a REFUSAL rather than into a rejection nobody counts. This test builds
// the values decide()'s precedence is supposed to make impossible — possible
// here because the test is in the package that owns the type — and watches the
// assertion refuse each one.
func TestARejectionThatCouldNotHaveDisprovedAnythingIsRefused(t *testing.T) {
	base := Finding{
		engine: "zap", target: "t", method: "GET", path: "/x",
		class: ClassInjection, detection: DetectionMethodTemplate,
		outcome: OutcomeRejected, reason: ReasonDidNotReproduce,
		evidence: EvidenceRef{bodyHash: strings.Repeat("0", 64), sealed: true},
		status:   200, attempts: 3, matches: 0, indecisive: 0,
		sealed: true,
	}
	with := func(mutate func(*Finding)) Finding {
		f := base
		mutate(&f)
		return f
	}

	for _, tc := range []struct {
		name    string
		finding Finding
		wantErr bool
	}{
		{"an honest disproof", base, false},
		{"one attempt the application never answered",
			with(func(f *Finding) { f.indecisive = 1 }), true},
		{"every attempt indecisive",
			with(func(f *Finding) { f.indecisive = 3 }), true},
		{"no status observed",
			with(func(f *Finding) { f.status = 0 }), true},
		{"a status outside the application allowlist",
			with(func(f *Finding) { f.status = 403 }), true},
		{"a rate limit",
			with(func(f *Finding) { f.status = 429 }), true},
		// The verdict is scoped to REJECTED. An unconfirmed finding is
		// allowed to carry indecisive attempts — that is what it means.
		{"an unconfirmed finding over an indecisive run",
			with(func(f *Finding) {
				f.outcome, f.reason = OutcomeUnconfirmed, ReasonReprobeIndecisive
				f.indecisive, f.status = 3, 429
			}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := assertRejectionIsDecisive(tc.finding)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("assertRejectionIsDecisive = %v, want error=%v. %s",
					err, tc.wantErr, tc.finding)
			}
			if tc.wantErr && !errors.Is(err, ErrRefused) {
				t.Errorf("error = %v, want ErrRefused", err)
			}
		})
	}
}

// TestEveryStatusOutsideTheApplicationAllowlistIsIndecisive is the sweep.
//
// ===========================================================================
// THE MEASUREMENT THIS TEST EXISTS TO REPRODUCE
// ===========================================================================
//
// Defence detection used to be a four-entry status list, {429, 502, 503, 504},
// with everything else falling through to "the application answered". A
// Reprober answering 403 with a WAF page on all three attempts therefore
// produced outcome=rejected, reason=did_not_reproduce_on_any_attempt over
// genuinely vulnerable candidates, and the ledger read completed_clean —
// the original defect, one layer down, from a list one entry short.
//
// So this does not test 403. It sweeps EVERY status a target can answer with,
// crossed with both signature outcomes, and asserts the rule rather than the
// examples: a re-probe may only end in `rejected` when the status is one
// IsApplicationResponseStatus accepts. Every other status — including ones
// nobody enumerated — must land unconfirmed.
func TestEveryStatusOutsideTheApplicationAllowlistIsIndecisive(t *testing.T) {
	vulnerable := []byte(`{"error":"` + sqliMarker + `"}`)
	ordinary := []byte(`{"ok":true,"items":[]}`)

	statuses := []int{0}
	for s := 100; s <= 599; s++ {
		statuses = append(statuses, s)
	}
	// Off the end of the real space on purpose: a status this gate has
	// never seen must take the safe route, and "never seen" is the whole
	// point of an allowlist.
	statuses = append(statuses, 600, 999, 1000, -1)

	sawRejected, sawConfirmed, sawIndecisive := 0, 0, 0
	for _, status := range statuses {
		for _, matching := range []bool{false, true} {
			body := ordinary
			if matching {
				body = vulnerable
			}
			rp := &scriptedReprober{
				body:     func(RawFinding, int) []byte { return body },
				statusFn: func(RawFinding, int) int { return status },
			}
			g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})
			f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
			if err != nil {
				t.Fatalf("status=%d matching=%v: ConfirmFinding: %v", status, matching, err)
			}

			answered := IsApplicationResponseStatus(status)
			switch {
			case !answered:
				sawIndecisive++
				if f.Outcome() == OutcomeRejected {
					t.Errorf("status=%d matching=%v gave outcome=rejected. THIS IS THE "+
						"FAILURE: the target did not answer as the application, so "+
						"nothing was disproved, and a rejection here is a live finding "+
						"reported as a phantom. %s", status, matching, f)
				}
				if f.Reason() != ReasonReprobeIndecisive {
					t.Errorf("status=%d matching=%v gave reason=%q, want %q. %s",
						status, matching, f.Reason(), ReasonReprobeIndecisive, f)
				}
				if _, ok := f.Confidence(); ok {
					t.Errorf("status=%d reports a confidence over a run the application "+
						"never answered. %s", status, f)
				}
				if got := f.IndecisiveAttempts(); got != 3 {
					t.Errorf("status=%d IndecisiveAttempts = %d, want 3", status, got)
				}
			case matching:
				sawConfirmed++
				if f.Outcome() != OutcomeConfirmed {
					t.Errorf("status=%d with the oracle reproducing gave outcome=%q, want "+
						"confirmed. An allowlisted status that cannot confirm makes the "+
						"whole sweep vacuous. %s", status, f.Outcome(), f)
				}
			default:
				sawRejected++
				if f.Outcome() != OutcomeRejected {
					t.Errorf("status=%d with the oracle silent gave outcome=%q, want "+
						"rejected. An application answer that cannot disprove anything "+
						"turns the gate into a machine that never decides. %s",
						status, f.Outcome(), f)
				}
			}
		}
	}

	// THE POSITIVE CONTROLS ON THE SWEEP ITSELF. A run in which nothing was
	// ever rejected, or nothing was ever confirmed, would satisfy every
	// assertion above and prove nothing.
	if sawRejected != len(applicationResponseStatuses()) {
		t.Errorf("the sweep reached `rejected` %d time(s) and the allowlist has %d "+
			"entries", sawRejected, len(applicationResponseStatuses()))
	}
	if sawConfirmed != len(applicationResponseStatuses()) {
		t.Errorf("the sweep reached `confirmed` %d time(s) and the allowlist has %d "+
			"entries", sawConfirmed, len(applicationResponseStatuses()))
	}
	wantIndecisiveRuns := 2 * (len(statuses) - len(applicationResponseStatuses()))
	if sawIndecisive != wantIndecisiveRuns {
		t.Errorf("the sweep reached `indecisive` %d time(s) over %d statuses, want %d; it "+
			"is not exercising the safe side it claims to",
			sawIndecisive, len(statuses), wantIndecisiveRuns)
	}

	// AND THE MEASURED CASES BY NAME, so a reader can find them.
	if IsApplicationResponseStatus(403) {
		t.Error("403 is accepted as the application answering. That is the status a WAF " +
			"block page arrives with, and accepting it reproduces the defect this " +
			"whole inversion exists to close")
	}
	if IsApplicationResponseStatus(404) {
		t.Error("404 is accepted as the application answering. MEASURED: a CDN edge node " +
			"answering 404 on all three attempts yields outcome=rejected — a finding " +
			"disproven by a machine that never reached the application")
	}
	for _, s := range []int{401, 403, 407, 451, 429, 502, 503, 504, 0, 302, 400} {
		if IsApplicationResponseStatus(s) {
			t.Errorf("status %d is accepted as the application answering", s)
		}
	}
	for _, s := range []int{200} {
		if !IsApplicationResponseStatus(s) {
			t.Errorf("status %d is not accepted as the application answering; without it "+
				"an ordinary disproof is impossible and the gate never decides", s)
		}
	}
}

// statusForbidsABody is conjunct (a) of the allowlist's membership rule: RFC
// 9110 section 6.4.1 and section 15.3.5 — a 1xx, a 204 and a 304 response is
// terminated by the first empty line after the header fields and cannot
// contain a message body; a 205 must have a zero-length one.
//
// These predicates live in the TEST rather than beside the map on purpose.
// They are the rule the map is measured AGAINST, and a rule that ships in the
// same function as the thing it judges is a rule that can be edited to fit.
func statusForbidsABody(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return true
	case status == 204, status == 205, status == 304:
		return true
	}
	return false
}

// statusBodyIsAFragment is conjunct (b): a 206 body is a byte range chosen by
// whoever answered, so a signature's silence over it is silence about part of
// a representation and not about the representation.
func statusBodyIsAFragment(status int) bool { return status == 206 }

// statusReportsTheRequestWasCarriedOut is conjunct (c): the status reports
// that THE ORIGIN CARRIED THE REQUEST OUT, so the body is that act's own
// representation.
//
// ===========================================================================
// IT USED TO BE `status >= 200 && status <= 299`. THAT IS A SHAPE, NOT A RULE.
// ===========================================================================
//
// Conjuncts (a) and (b) were made to assert the rule last round and this one
// was left as the range, which is why nobody could see that 202 sat on the
// allowlist under a derivation ITS OWN RFC SEMANTICS CONTRADICT. The header
// beside the map derived 202 as "accepting the request into processing is the
// origin's act" — but the conjunct does not say "the origin acted", it says
// THE REQUEST WAS CARRIED OUT, and RFC 9110 §15.3.3 says of a 202 that
// "the request has been accepted for processing, but the processing has not
// been completed" and that the response is "intentionally noncommittal". The
// derivation swapped the conjunct for a weaker one in the space of a line.
//
// TWO STATUSES IN THE 200-299 RANGE FAIL THIS CONJUNCT, and the range could
// see neither:
//
//	202 accepted    the request was NOT carried out. Its body describes a
//	                status monitor, not the outcome, so a signature's
//	                silence over it is silence about work that has not
//	                happened yet. This is the one the range hid.
//	203 non-        RFC 9110 §15.3.4: the payload "has been modified ... by
//	    authoritative a transforming proxy". The status exists precisely to
//	                say the bytes are NOT the origin's, which is the half of
//	                this conjunct the range never tested at all.
//
// AND EVERY UNASSIGNED 2xx FAILS IT, for the reason shapeOf's default arm
// refuses an operator it has not heard of: the rule is that THE STATUS ITSELF
// establishes the fact, and a number with no registered semantics establishes
// nothing. 299 used to satisfy this conjunct.
//
// So this is a table over the REGISTERED success statuses, each derived, with
// no deny side to keep current — the same shape as the allowlist it judges.
func statusReportsTheRequestWasCarriedOut(status int) bool {
	switch status {
	case 200, // RFC 9110 §15.3.1: the request succeeded.
		201, // §15.3.2: one or more resources were created. The origin's act.
		204, // §15.3.5: succeeded, no further content. Fails (a), not (c).
		205, // §15.3.6: succeeded, reset the document view. Fails (a), not (c).
		206, // §15.3.7: succeeded over a range. Fails (b), not (c).
		207, // RFC 4918 §13: multi-status; each member status is the origin's.
		208, // RFC 5842 §7.1: already enumerated in this response's own scope.
		226: // RFC 3229 §10.4.1: the origin applied instance manipulations.
		return true
	}
	return false
}

// statusSatisfiesTheMembershipRule is the rule itself, as one predicate: A
// STATUS IS ON THE ALLOWLIST WHEN THE STATUS ITSELF ESTABLISHES THAT THE BODY
// IS A REPRESENTATION THE ORIGIN APPLICATION PRODUCED.
//
// It is NECESSARY and not sufficient — see the test — because a status also
// has to have a meaning before it can have this one.
func statusSatisfiesTheMembershipRule(status int) bool {
	return statusReportsTheRequestWasCarriedOut(status) &&
		!statusForbidsABody(status) &&
		!statusBodyIsAFragment(status)
}

// TestTheApplicationAllowlistMatchesTheRuleItsCommentStates is the check that
// was missing when 404, 405, 410, 422 and 500 sat on this list under a comment
// that did not cover them — and that was still missing, in a smaller way, when
// 204 and 206 did.
//
// ===========================================================================
// IT USED TO ENCODE "2xx". THE RULE IS NOT "2xx".
// ===========================================================================
//
// The predicate here was `status >= 200 && status <= 299`, and the comment
// beside it said that was the rule. It is one THIRD of the rule — conjunct (c)
// — and the two conjuncts it dropped are exactly the two that decide the two
// entries nobody had checked:
//
//	204  MEASURED: a 204 re-probe over a vulnerable candidate yielded
//	     outcome=rejected at confidence 0.000 marked KNOWN. A 204 cannot
//	     carry a body at all, so that is a finding disproven by bytes that
//	     could not have held the marker. 205 — the neighbouring
//	     mandated-empty status — was never on the list, so the list
//	     disagreed with itself about the same body semantics.
//	206  the body is a byte range somebody else chose, so a non-match is
//	     silence about the part that came back and nothing about the rest.
//
// So this test asserts the RULE, in all three conjuncts, over every member and
// over the whole status space. Adding an entry the rule does not admit fails
// here, and so does removing a conjunct: each one has a control below proving
// it rejects something, so a conjunct edited into a tautology fails too.
func TestTheApplicationAllowlistMatchesTheRuleItsCommentStates(t *testing.T) {
	// THE CONJUNCTS ARE NOT VACUOUS. A predicate that returned false for
	// every status would make the rule trivially satisfied by the whole
	// list, which is precisely the failure being repaired.
	for _, c := range []struct {
		name    string
		pred    func(int) bool
		holds   []int
		refutes []int
	}{
		{"forbids a body", statusForbidsABody,
			[]int{100, 101, 199, 204, 205, 304}, []int{200, 201, 202, 203, 206, 404}},
		{"body is a fragment", statusBodyIsAFragment,
			[]int{206}, []int{200, 204, 205, 207}},
		{"reports the request was carried out", statusReportsTheRequestWasCarriedOut,
			[]int{200, 201, 204, 205, 206, 207, 208, 226},
			// 202 and 203 are the two the old `2xx` range could not see:
			// a 202's processing has not been completed, and a 203's
			// payload was modified by a transforming proxy. 209 and 299
			// are unassigned, and an unregistered number establishes
			// nothing about anything.
			[]int{100, 199, 202, 203, 209, 299, 300, 302, 400, 403, 500}},
	} {
		for _, s := range c.holds {
			if !c.pred(s) {
				t.Errorf("conjunct %q says status %d does not hold it; the conjunct has "+
					"been narrowed and the rule below is weaker than it reads", c.name, s)
			}
		}
		for _, s := range c.refutes {
			if c.pred(s) {
				t.Errorf("conjunct %q holds for status %d; the conjunct has been widened "+
					"into something that decides nothing", c.name, s)
			}
		}
	}

	// THE RULE, OVER THE WHOLE SPACE. Every member must satisfy every
	// conjunct, and the failure message says WHICH one it broke, because
	// "not 2xx" was the message that could not describe 204 or 206.
	admitted := 0
	for status := -1; status <= 1000; status++ {
		on := IsApplicationResponseStatus(status)
		if statusSatisfiesTheMembershipRule(status) {
			admitted++
		}
		if !on {
			continue
		}
		switch {
		case !statusReportsTheRequestWasCarriedOut(status):
			t.Errorf("status %d is on the application allowlist and does not report that "+
				"the ORIGIN CARRIED THE REQUEST OUT (conjunct c). Three ways to fail "+
				"it: an error status is something a CDN, a proxy, a gateway or a WAF "+
				"emits without reaching the application; a 202 says the processing has "+
				"NOT been completed, so its body is a queue receipt rather than the "+
				"outcome; a 203 says the payload was modified by a transforming proxy. "+
				"Either the entry goes or the comment does", status)
		case statusForbidsABody(status):
			t.Errorf("status %d is on the application allowlist and CANNOT CARRY A BODY "+
				"(conjunct a, RFC 9110). A signature's silence over a body the protocol "+
				"forbids is not the application declining to emit a marker, and a "+
				"rejection built on it is a finding disproven by bytes that never "+
				"existed", status)
		case statusBodyIsAFragment(status):
			t.Errorf("status %d is on the application allowlist and its body is a byte "+
				"RANGE somebody else chose (conjunct b). A signature that did not match "+
				"a fragment has shown nothing about the representation the fragment "+
				"came from", status)
		}
	}
	if admitted < 2 {
		t.Fatalf("the rule admits %d status(es) over the whole space; it has collapsed "+
			"and every assertion above passes for the wrong reason", admitted)
	}

	// The rule alone would permit every 2xx that carries a whole body; the
	// list is narrower, because a status has to have a MEANING before it can
	// have this one. That is a judgement and it is stated as one, so the
	// assertion is only that the list is a subset of the rule and non-empty
	// — not that it is all of it.
	if len(applicationResponseStatuses()) == 0 {
		t.Fatal("the allowlist is empty; the gate can never decide anything")
	}
	if len(applicationResponseStatuses()) >= admitted {
		t.Errorf("the allowlist has %d entries and the rule admits %d; the list is "+
			"supposed to be a strict subset, and one that is not has stopped being a "+
			"judgement about meaning", len(applicationResponseStatuses()), admitted)
	}

	// AND THE REMOVALS BY NAME, each with the reason, so re-adding one is a
	// deliberate act against a written argument rather than a one-line diff
	// nobody reads.
	for _, tc := range []struct {
		status int
		why    string
	}{
		{404, "a CDN edge node, nginx try_files and an object store all answer 404 " +
			"without consulting the application; MEASURED as a rejection"},
		{405, "nginx limit_except answers 405 in the proxy"},
		{410, "a CDN purge rule answers 410 at the edge"},
		{422, "an API gateway's request validation, and any WAF with a configurable " +
			"block status, answer 422 with no origin round trip"},
		{500, "a reverse proxy emits 500 for its own internal failures"},
		{204, "a 204 cannot carry a message body at all, so there is nothing for the " +
			"oracle to be silent about; MEASURED as outcome=rejected at confidence " +
			"0.000 marked KNOWN"},
		{206, "a 206 body is a byte range chosen by whoever answered, so a non-match " +
			"says nothing about the rest of the representation"},
		{202, "RFC 9110 §15.3.3: a 202's processing HAS NOT BEEN COMPLETED and the " +
			"response is intentionally noncommittal, so its body describes a status " +
			"monitor rather than the outcome of the request. It sat here for a round " +
			"under the derivation \"accepting the request into processing is the " +
			"origin's act\", which is not conjunct (c) — conjunct (c) is that the " +
			"request was CARRIED OUT — and the test could not see the difference " +
			"while (c) was literally `2xx`"},
		{203, "RFC 9110 §15.3.4: a 203 says the payload was modified by a TRANSFORMING " +
			"PROXY, which is the exact negation of \"only the origin can have " +
			"produced it\""},
	} {
		if IsApplicationResponseStatus(tc.status) {
			t.Errorf("status %d is back on the application allowlist. It was removed "+
				"because %s, and nothing about that has changed by adding it again",
				tc.status, tc.why)
		}
	}

	// THE CONSISTENCY THE LIST DID NOT HAVE: 204 and 205 are the two
	// statuses whose bodies the protocol mandates empty, and a list that
	// decides them differently is a list following something other than its
	// stated rule.
	if IsApplicationResponseStatus(204) != IsApplicationResponseStatus(205) {
		t.Errorf("204 is %v on the allowlist and 205 is %v. Both are mandated-empty by "+
			"RFC 9110 and the rule cannot see any difference between them; deciding "+
			"them differently is the list disagreeing with itself",
			IsApplicationResponseStatus(204), IsApplicationResponseStatus(205))
	}
}

// TestRemoving500FromTheAllowlistCostsAConfirmationAndSaysSo prices the
// removal instead of asserting it was free.
//
// An error-based injection whose reproduction is a 500 carrying a stack trace
// used to come out CONFIRMED. It now comes out unconfirmed/reprobe_indecisive,
// because the attempt is counted indecisive BEFORE the signature is run. That
// is a loss of true positives, it is the price of not letting a proxy's 500
// count as the application, and it is asserted here so it is a known cost
// rather than a surprise in the field.
func TestRemoving500FromTheAllowlistCostsAConfirmationAndSaysSo(t *testing.T) {
	stackTrace := []byte(`<h1>500</h1><pre>` + sqliMarker + `</pre>`)
	rp := &scriptedReprober{
		body:   func(RawFinding, int) []byte { return stackTrace },
		status: 500,
	}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})
	f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	if f.Outcome() == OutcomeConfirmed {
		t.Fatalf("a 500 carrying the marker was CONFIRMED. 500 is off the allowlist "+
			"precisely because a proxy can emit one, so this path must not reach a "+
			"claim. %s", f)
	}
	if f.Outcome() == OutcomeRejected {
		t.Fatalf("a 500 carrying the marker was REJECTED, which is worse than either "+
			"honest answer: nothing was disproved. %s", f)
	}
	if f.Reason() != ReasonReprobeIndecisive {
		t.Errorf("reason = %q, want %q", f.Reason(), ReasonReprobeIndecisive)
	}
	// The finding is NOT dropped, and the body hash is still there. That is
	// the half that makes the cost acceptable.
	if !f.Evidence().Constructed() || f.Evidence().BodyHash() == "" {
		t.Error("the indecisive finding carries no body hash; the operator has been left " +
			"with an undecided row and nothing to look at")
	}
	// And the signature was NOT run, which is why there is no span: a body
	// the target may have produced instead of running the application must
	// not be handed to the oracle at all.
	if got := f.SignatureMatches(); got != 0 {
		t.Errorf("SignatureMatches = %d over attempts that were never handed to the "+
			"oracle; the application-answered test has stopped running first", got)
	}
}

// TestTheApplicationAnsweredTestFailsClosedOnEveryRouteButOne states the
// control-flow property the inversion buys: attemptAnsweredAsApplication has
// exactly one path that returns true.
func TestTheApplicationAnsweredTestFailsClosedOnEveryRouteButOne(t *testing.T) {
	blockPage := []byte(`<html><body>Your request was blocked by policy reference 8812-AA.</body></html>`)
	blockSig := mustSignature(t, `blocked by policy reference [0-9]{4}-[A-Z]{2}`)
	plain := mustGate(t, GateConfig{Reprober: &scriptedReprober{}, Attempts: 3})
	guarded := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{}, Attempts: 3, DefenceSignature: blockSig,
	})

	for _, tc := range []struct {
		name string
		gate *Gate
		obs  Observation
		want bool
	}{
		{"the zero Observation", plain, Observation{}, false},
		{"issued but no status", plain, Observation{Issued: true}, false},
		{"not issued, with a perfectly good status", plain,
			Observation{Status: 200, Body: []byte("{}")}, false},
		{"a status nobody enumerated", plain, Observation{Issued: true, Status: 418}, false},
		{"a WAF block page at 200, with no defence signature wired", plain,
			Observation{Issued: true, Status: 200, Body: blockPage}, true},
		{"a WAF block page at 200, with one wired", guarded,
			Observation{Issued: true, Status: 200, Body: blockPage}, false},
		{"an ordinary 200", plain,
			Observation{Issued: true, Status: 200, Body: []byte(`{"ok":true}`)}, true},
		{"an ordinary 200, with a defence signature that does not match", guarded,
			Observation{Issued: true, Status: 200, Body: []byte(`{"ok":true}`)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, why := tc.gate.attemptAnsweredAsApplication(tc.obs)
			if got != tc.want {
				t.Fatalf("attemptAnsweredAsApplication = (%v, %q), want %v", got, why, tc.want)
			}
			if why == "" {
				t.Error("the reason string is empty; a decision nobody can explain is a " +
					"decision nobody can audit")
			}
		})
	}

	// The residual, stated in the doc and asserted here so it cannot quietly
	// stop being true: WITH NO DefenceSignature WIRED A 200 BLOCK PAGE IS
	// INDISTINGUISHABLE FROM AN APPLICATION RESPONSE. The fifth case above
	// is that sentence; this is it said out loud.
	if ok, _ := plain.attemptAnsweredAsApplication(
		Observation{Issued: true, Status: 200, Body: blockPage}); !ok {
		t.Error("an unconfigured gate distinguished a 200 block page from an application " +
			"response. If that has become possible the DefenceSignature doc is wrong")
	}
}

// TestAnOracleLessClassIsUnaffectedByTheInversion falsifies the claim the old
// comment made for keeping 403 on the application side.
//
// It said that treating a 403 as a non-answer "would make the oracle-less
// classes undecidable for a second, wrong reason and would hide real
// behaviour". decide()'s rule 1 routes an oracle-less class to
// ReasonNoOracleForClass BEFORE indecisiveness is consulted, so the claim was
// false. It is deleted from the source rather than qualified, and this is what
// stands behind the deletion.
func TestAnOracleLessClassIsUnaffectedByTheInversion(t *testing.T) {
	for _, class := range []Class{ClassAuthorization, ClassIDOR, ClassBusinessLogic} {
		for _, status := range []int{200, 403, 401, 429, 0} {
			rp := &scriptedReprober{
				body:     func(RawFinding, int) []byte { return []byte(`{"role":"admin"}`) },
				statusFn: func(RawFinding, int) int { return status },
			}
			g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})
			c := sqliCandidate(t, "/admin/users")
			c.Class = class
			f, err := g.ConfirmFinding(context.Background(), c)
			if err != nil {
				t.Fatalf("class=%s status=%d: %v", class, status, err)
			}
			if f.Reason() != ReasonNoOracleForClass {
				t.Errorf("class=%s status=%d gave reason=%q, want %q. The inversion is "+
					"reaching a class rule 1 is supposed to have already decided",
					class, status, f.Reason(), ReasonNoOracleForClass)
			}
			if f.Outcome() != OutcomeUnconfirmed {
				t.Errorf("class=%s status=%d gave outcome=%q", class, status, f.Outcome())
			}
			if _, ok := f.Confidence(); ok {
				t.Errorf("class=%s status=%d reports a confidence", class, status)
			}
		}
	}
}

// ===========================================================================
// D.29 HIGH 3 — an oracle that fires on a benign page
// ===========================================================================

// TestSignatureRefusesAnOracleThatFiresOnAGeneratedBenignBody is HIGH 3, end
// to end through NewSignature.
//
// ===========================================================================
// WHAT WAS MEASURED, THREE TIMES
// ===========================================================================
//
// Round one: the predicate was re.MatchString("") alone, and ".",
// "(?s).{1,512}", `[\s\S]`, ".*." and "(?s)^" all passed it — five oracles
// that confirm a benign page at confidence 1.000.
//
// Round two: the predicate became seventeen hand-written probes totalling 720
// bytes, and `(?s)[\s\S]{721}` passed — one byte past the longest thing the
// check could produce.
//
// Round three: the probes became a seeded generator over five hand-written
// vocabulary slices, and `(?s)<h1[\s\S]{0,400}` passed, because `h1` is not
// one of the thirteen tag names the generator was given. A GENERATOR OVER A
// WRITTEN-DOWN ALPHABET IS A CORPUS, and a corpus's size is the attacker's
// budget however it is produced.
//
// WHICH CHECK REFUSES WHAT IS ASSERTED SOMEWHERE ELSE ON PURPOSE. This test
// goes through NewSignature and only asks that each pattern be refused; the
// division of labour between the structural control and the corpus backstop is
// driven by TestTheControlDecidesOnTheStructureAndNotOnASampleOfBodies and
// TestTheBackstopRefusesWhatTheControlAccepts. Keeping them apart is what
// stops this test quietly becoming a test of whichever check happens to fire
// first.
func TestSignatureRefusesAnOracleThatFiresOnAGeneratedBenignBody(t *testing.T) {
	// The two measured families, together, because the sentinel does not
	// distinguish them and neither should a reader.
	for _, p := range []string{
		".", `(?s).{1,512}`, `[\s\S]`, `.*.`, `(?s)^`, // round one
		`.*`, `(?s).*`, `a?`, `^`, `(foo)?`, `x{0,3}`,
		`(?s).+`, `[\s\S]{1,10}`, `(?s)(.|\n)*`, `[^\x00]`,
	} {
		if _, err := NewSignature(p); !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%q) = %v, want ErrSignatureMatchesEverything. Measured "+
				"against a benign homepage, a pattern like this confirms it at "+
				"confidence 1.000 AND inlines a verbatim body prefix as its evidence "+
				"span — two failures from one accepted regex", p, err)
		}
	}

	// THE LENGTH FAMILY. `(?s)[\s\S]{N}` is "any body of at least N bytes",
	// which is not an oracle at any N. The seventeen-probe corpus refused it
	// up to 720 and accepted it at 721. A corpus twice the size would accept
	// it at 1441 — which is why the answer is not a bigger list of lengths
	// but the bound asserted in
	// TestTheLengthThresholdFamilyIsClosedAndNotMerelyOutrun.
	//
	// What is driven here is that the mechanism works at every length a
	// pattern can actually reach it at, INCLUDING lengths built by
	// concatenation rather than by one repeat count.
	for _, n := range []int{1, 2, 512, 719, 720, 721, 1000} {
		p := fmt.Sprintf(`(?s)[\s\S]{%d}`, n)
		if _, err := NewSignature(p); !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%q) = %v, want ErrSignatureMatchesEverything. "+
				"\"the response is at least %d bytes long\" is not an oracle, and a "+
				"corpus that accepts it has a ceiling the next author will step over",
				p, err, n)
		}
	}
	for _, k := range []int{1, 2, 3, 5, 8, 13} {
		p := "(?s)" + strings.Repeat(`.{1000}`, k)
		if _, err := NewSignature(p); !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%d concatenated .{1000}, minimum match %d bytes) = %v, "+
				"want ErrSignatureMatchesEverything. Go caps ONE repeat at 1000, so "+
				"concatenation is how a length threshold gets past that cap, and a "+
				"corpus that only sampled short bodies would accept every one of these",
				k, k*1000, err)
		}
	}

	// THE POSITIVE CONTROL, and it is the half that decides whether this
	// check is usable at all. A corpus-based refusal that also refused real
	// oracles would be a gate nobody could configure, so every signature
	// this suite and the plan actually use must still compile.
	for _, p := range []string{
		sqliPattern,
		`"role":"admin"`,
		spanBoundaryPattern,
		`You have an error in your SQL syntax`,
		`root:[x*]:0:0:`,
		`AKIA[0-9A-Z]{16}`,
		`Server: nginx/1\.[0-9]+\.[0-9]+`,
		`<script>alert\(1\)</script>`,
		`java\.lang\.NullPointerException`,
		`blocked by policy reference [0-9]{4}-[A-Z]{2}`,
		// The two shapes the structural rules could most plausibly have
		// broken, and did not: a case-insensitive class, which the parser
		// expands to include U+017F and U+212A, and a narrow class with
		// no repeat ceiling.
		`(?i)PHP Fatal error:  Uncaught [A-Za-z]{1,40}`,
		`X-Debug-Token: [0-9a-f]+`,
	} {
		if _, err := NewSignature(p); err != nil {
			t.Errorf("NewSignature(%q) = %v; a real oracle is being refused and the check "+
				"is unusable", p, err)
		}
	}

	// THE COST, ASSERTED RATHER THAN CLAIMED, and it grew this round. Two
	// patterns that used to be positive controls in this very test are now
	// refused, each for a stated reason, and each is written down here so
	// nobody reads it as a regression:
	//
	//	`(?s)A.*B`       by the BACKSTOP first (prose capitalises sentence
	//	                 openings, so a body with an A before a B is an
	//	                 ordinary body) and by the CONTROL now (`.` is an
	//	                 open position under R2).
	//	`(?s)<v>.*</v>`  by the CONTROL, same rule. A delimiter pair may
	//	                 still be written; it must declare what it will
	//	                 quote, which is what spanBoundaryPattern now does.
	for _, tc := range []struct{ pattern, why string }{
		{`(?s)A.*B`, "a delimiter pair over an open class"},
		{`(?s)<v>.*</v>`, "a tag pair over an open class"},
	} {
		if _, err := NewSignature(tc.pattern); !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%q) = %v; %s used to be refused and no longer is, so a "+
				"whole family of delimiter-pair patterns has stopped being caught",
				tc.pattern, err, tc.why)
		}
	}
}

// TestTheBenignCorpusIsGeneratedAndReachesTheKernelsCodedBodyCap is the claim
// the corpus rests on, checked against its two sources.
//
// FIRST: the ceiling is not a number chosen here. It is gate 14's coded body
// cap, and the whole "the length race is closed rather than outrun" argument
// in confirm_gate.go depends on the two being equal. If authz lowers or raises
// CodedMaxBodyBytes, this goes red and the argument gets re-made rather than
// silently becoming false.
//
// SECOND: the corpus must actually SPAN a space rather than restate a list.
func TestTheBenignCorpusIsGeneratedAndReachesTheKernelsCodedBodyCap(t *testing.T) {
	if got, want := int64(maxBenignBodyBytes), authz.CodedMaxBodyBytes; got != want {
		t.Fatalf("maxBenignBodyBytes = %d and gate 14's CodedMaxBodyBytes = %d. The "+
			"corpus closes the length race only while the longest generated body is "+
			"at least as long as the longest body an Observation can carry", got, want)
	}

	longest, total, distinct := 0, 0, map[string]bool{}
	for _, b := range benignCorpus {
		if len(b) > longest {
			longest = len(b)
		}
		total += len(b)
		distinct[b] = true
	}
	if longest != maxBenignBodyBytes {
		t.Errorf("the longest generated body is %d bytes, want %d", longest, maxBenignBodyBytes)
	}
	if total <= 720 {
		t.Errorf("the corpus totals %d bytes; the corpus it replaced was 720 and its size "+
			"was the defect", total)
	}
	if len(distinct) < len(benignCorpus)-4 {
		t.Errorf("%d of %d generated bodies are duplicates; the generator is sampling a "+
			"much smaller space than its length axis suggests",
			len(benignCorpus)-len(distinct), len(benignCorpus))
	}

	// EVERY BODY IS LOAD-BEARING in the only sense that can be checked
	// mechanically: the broadest pattern there is has to match it. `(?s).`
	// and not `.` — "." does not match a newline, which is why the corpus
	// contains newlines and why this assertion can be made at all.
	anyByte := regexp.MustCompile(`(?s).`)
	nonEmpty := 0
	for i, b := range benignCorpus {
		if b == "" {
			continue
		}
		nonEmpty++
		if !anyByte.MatchString(b) {
			t.Errorf("generated body %d (%d bytes) is not matched by `(?s).`; it cannot "+
				"catch the broadest pattern there is", i, len(b))
		}
	}
	if nonEmpty < 8 {
		t.Errorf("the corpus has %d non-empty bodies; one or two is a coincidence filter, "+
			"not a corpus", nonEmpty)
	}

	// THE GENERATOR IS DETERMINISTIC. A corpus that differs run to run turns
	// "your signature was refused" into a report about the weather, and a
	// refusal nobody can reproduce is a refusal nobody will believe.
	again := buildBenignCorpus()
	if len(again) != len(benignCorpus) {
		t.Fatalf("rebuilding the corpus produced %d bodies, want %d", len(again), len(benignCorpus))
	}
	for i := range again {
		if again[i] != benignCorpus[i] {
			t.Fatalf("body %d differs between two builds from seed %#x; the corpus is not "+
				"reproducible and neither is any refusal it decides", i, benignCorpusSeed)
		}
	}

	// AND THE SHAPES ARE ACTUALLY PRESENT. A generator that emitted a
	// megabyte of one character would satisfy every count above.
	whole := strings.Join(benignCorpus, "\n")
	for _, marker := range []string{"<div ", "<!doctype html>", "<script src=", "{}", "[]",
		"null", "\"count\":", "HTTP/1.1 200 OK", ". ", "\t"} {
		if !strings.Contains(whole, marker) {
			t.Errorf("no generated body contains %q; a shape the corpus is documented as "+
				"covering is missing and the patterns it catches are not caught", marker)
		}
	}
}

// TestTheLengthThresholdFamilyIsClosedAndNotMerelyOutrun is the arithmetic the
// corpus's ceiling rests on.
//
// A bigger corpus does not close a length race, it moves the finish line. What
// closes it is that THE LENGTH A PATTERN CAN DEMAND IS ITSELF BOUNDED:
//
//	Go's regexp caps the total expansion of a repeat at 1000. `{1001}` does
//	not compile, and neither does `(X{1000}){2}` — the product is checked,
//	not each factor. So one repeat construct demands at most 1000 bytes.
//
//	A repeat construct costs at least one byte of pattern, and a pattern is
//	bounded at MaxPatternBytes.
//
//	Therefore no pattern this gate can compile demands more than
//	MaxPatternBytes * 1000 bytes, and maxBenignBodyBytes is larger than that.
//
// Every length threshold that can be written down meets a generated body at
// least that long. The family is CLOSED. If any of the three facts stops being
// true this goes red, and the paragraph in confirm_gate.go gets re-argued
// instead of quietly becoming decoration.
func TestTheLengthThresholdFamilyIsClosedAndNotMerelyOutrun(t *testing.T) {
	if _, err := regexp.Compile(`[\s\S]{1001}`); err == nil {
		t.Error("Go compiled a repeat count of 1001; the 1000-per-repeat cap this bound " +
			"rests on is gone and the length family is open again")
	}
	if _, err := regexp.Compile(`([\s\S]{1000}){2}`); err == nil {
		t.Error("Go compiled a NESTED repeat whose product is 2000; the cap is per-repeat " +
			"rather than on the product, and a 20-byte pattern can now demand more " +
			"bytes than this bound allows for")
	}
	const goMaxRepeat = 1000
	if got, want := MaxPatternBytes*goMaxRepeat, maxBenignBodyBytes; got > want {
		t.Errorf("a pattern of %d bytes can demand up to %d bytes and the longest "+
			"generated body is %d. There is a length threshold the corpus cannot "+
			"refuse, and its exact value is the next author's budget",
			MaxPatternBytes, got, want)
	}

	// THE CONTROL ON THE ARITHMETIC: the longest threshold actually
	// expressible under MaxPatternBytes is refused. It is not run here —
	// matching an 85,000-instruction program against the whole corpus takes
	// roughly fifteen seconds — but its size is asserted, so the claim
	// "expressible lengths stay under the ceiling" is checked against the
	// real construction and not only against the inequality.
	unit := `[\s\S]{1000}`
	worst := "(?s)" + strings.Repeat(unit, (MaxPatternBytes-len("(?s)"))/len(unit))
	if len(worst) > MaxPatternBytes {
		t.Fatalf("the worst-case pattern is %d bytes, over the %d bound; the construction "+
			"is wrong and proves nothing", len(worst), MaxPatternBytes)
	}
	if _, err := regexp.Compile(worst); err != nil {
		t.Fatalf("the worst-case pattern does not compile (%v), so it is not the worst "+
			"case", err)
	}
	demanded := ((MaxPatternBytes - len("(?s)")) / len(unit)) * goMaxRepeat
	if demanded >= maxBenignBodyBytes {
		t.Errorf("the longest expressible threshold demands %d bytes and the ceiling is "+
			"%d", demanded, maxBenignBodyBytes)
	}
}

// TestTheBoundedPrefixFamilyIsRefusedByTheControlOnItsStructure is the
// measured CRITICAL of this round, closed and then attacked from both sides.
//
// ===========================================================================
// THE MEASUREMENT
// ===========================================================================
//
// `(?s)<h1[\s\S]{0,400}` passed NewSignature, and it did two things at once:
// it confirmed any page carrying an h1 at confidence 1.000, and it INLINED 403
// verbatim body bytes into ExtractedSpan. MaxSpanBytes could not see the
// second, because that bound only refuses matches LONGER than 512. The corpus
// could not see the first, because `h1` was not one of the thirteen tag names
// the generator was given — 17 of 20 bounded-prefix HTML anchors passed.
//
// So the family is decided on the PATTERN now, and this test attacks that
// decision the way the last four rounds were attacked: by varying the thing
// the previous fix depended on.
func TestTheBoundedPrefixFamilyIsRefusedByTheControlOnItsStructure(t *testing.T) {
	// THE TAG NAME IS NOT LOAD-BEARING ANY MORE, and this is the sweep that
	// says so. The corpus knew thirteen tags; the control knows none. Every
	// anchor here is refused for the same structural reason, including the
	// ones no vocabulary contains.
	for _, tag := range []string{
		"h1", "h2", "h6", "div", "span", "form", "main", "figure", "dialog",
		"marquee", "blink", "anvil-widget", "x", "custom-element-nobody-wrote",
	} {
		p := `(?s)<` + tag + `[\s\S]{0,400}`
		_, err := refuseOverBroadPattern(p)
		if err == nil {
			t.Errorf("refuseOverBroadPattern(%q) accepted it. The whole point of deciding "+
				"on the pattern is that <%s> is no more special than <div>: a corpus "+
				"knows the tags it was given and a structural rule knows none",
				p, tag)
		}
		if _, nerr := NewSignature(p); !errors.Is(nerr, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%q) = %v, want ErrSignatureMatchesEverything", p, nerr)
		}
	}

	// AND THE OBVIOUS EVASION: narrow the class until R2 stops objecting.
	// `[[:print:]]`, `[ -~]` and `[!-~]` are all confined to printable
	// ASCII, so R2 passes them — and R3 refuses every one, because 400
	// quoted positions against three spelled bytes is the pattern quoting
	// the response rather than identifying it.
	for _, class := range []string{`[[:print:]]`, `[ -~]`, `[!-~]`, `[a-z ]`, `[\x20-\x7e]`} {
		p := `<h1` + class + `{0,400}`
		if _, err := refuseOverBroadPattern(p); err == nil {
			t.Errorf("refuseOverBroadPattern(%q) accepted it: R2 is satisfied by a narrowed "+
				"class and R3 did not catch the quotation, so the bounded-prefix family "+
				"is open again one character away from where it was closed", p)
		}
	}

	// THE THIRD SIDE: the same shape with a footing large enough to pay for
	// what it quotes IS accepted, and that is the rule being a rule rather
	// than a ban on a syntax. It is not a hole — the pattern had to spell
	// 400 bytes the target must emit to get 400 bytes of quotation.
	paid := `ANVIL-CANARY-1F4B-ANVIL-CANARY-1F4B[[:print:]]{0,35}`
	if _, err := refuseOverBroadPattern(paid); err != nil {
		t.Errorf("refuseOverBroadPattern(%q) = %v; 35 quoted positions against 35 spelled "+
			"bytes satisfies R3 by construction, and a rule that refuses it is a ban on "+
			"context rather than a bound on quotation", paid, err)
	}
}

// generatorVocabularySize counts the entries of the first []string literal
// declared inside the named generator function in confirm_gate.go.
//
// The corpus's budget IS those lists, and the control's header now names their
// sizes. Reading them out of the source is what stops the disclosure and the
// code drifting apart: the lists are local variables inside the generators, so
// there is nothing to call, and a number written into a comment beside code
// nobody re-checks is how the last disclosure got narrower than the truth.
func generatorVocabularySize(t *testing.T, fn, varName string) int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "confirm_gate.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing confirm_gate.go: %v", err)
	}
	n := -1
	ast.Inspect(f, func(node ast.Node) bool {
		fd, ok := node.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			return true
		}
		ast.Inspect(fd, func(inner ast.Node) bool {
			as, ok := inner.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok || id.Name != varName {
				return true
			}
			if cl, ok := as.Rhs[0].(*ast.CompositeLit); ok && n < 0 {
				n = len(cl.Elts)
			}
			return true
		})
		return false
	})
	if n < 0 {
		t.Fatalf("no []string literal named %q found in %s; the corpus generators have "+
			"been restructured and this measurement is of nothing", varName, fn)
	}
	return n
}

// TestTheCorpusResidualIsAsWideAsItsVocabularies drives the backstop's
// disclosed budget, because THE DISCLOSURE WAS NARROWER THAN THE RESIDUAL.
//
// ===========================================================================
// ONE FACE WAS NAMED. THEN FIVE. THERE ARE NINE, AND THE WIDEST WAS MISSING.
// ===========================================================================
//
// The header said the residual was "a pattern that spells ordinary text the
// generator's vocabulary happens not to emit" and gave
// `(?i)(error|warning|expired)` as the example — a gap in ONE list, the prose
// word list. The round after that disclosed five lists. Five was still
// narrower than what a probe finds, and the list it left out is the biggest:
// THE LIST OF FORMATS THE CORPUS CAN GENERATE AT ALL. buildBenignCorpus
// crosses its length axis with four shape functions, so an ordinary XML
// document, an ordinary PEM block and an ordinary multipart part are not
// missing a token — they are absent as documents.
//
// MEASURED, with the structural control silent on every probe below so it is
// the CORPUS that decides:
//
//	list                     inside (refused)          outside (accepted)
//	shapes (4)               —                         `<\?xml `,
//	                                                   `-----BEGIN `,
//	                                                   `Content-Disposition: `
//	benignWords (33)         `invoice`                 `expired`
//	benignProse enders (6)   `\. `, `; `               `! `
//	benignHTML tags (13)     `<div`, `<h2`             `<h1>`, `<table`,
//	                                                   `<button`, `<form `
//	benignHTML classes (9)   `class="row"`             `class="banner"`
//	benignHTML head literals `class="`, `<title>`      `id="`, `href="https`,
//	                         `href="/static`           `/assets/`, `&amp;`
//	benignJSON keys (14)     `"status":`               `"error_code":`,
//	                                                   `"user_id":`
//	benignJSON values (6)    `:null`, `\[\]`           `1\.0`, `0\.0`, `\[\{`
//	benignStructural (45)    `Content-Type: ...`       `X-Powered-By: `,
//	                                                   `Set-Cookie: `,
//	                                                   `text/html`,
//	                                                   `HTTP/1\.1 404`
//
// TWO OF THESE ARE WORTH READING TWICE, because they are not "a word the list
// happens to lack" but whole classes of ordinary content the generator cannot
// produce: NO HTML ENTITY IS EVER EMITTED (`&amp;` on a benign page is
// invisible), and NO NUMBER EVER CARRIES A DECIMAL POINT, because every one is
// printed with %d.
//
// A BACKSTOP IS ALLOWED A BUDGET; what it is not allowed is a budget stated
// smaller than it is, because the next person sizes their trust to the
// statement. This test fails when the statement stops being true in either
// direction — a list that grows past its disclosed size, or an "outside" probe
// the corpus starts catching.
func TestTheCorpusResidualIsAsWideAsItsVocabularies(t *testing.T) {
	// sizeNotASliceLiteral marks a vocabulary that is real and probed but
	// is not a []string the AST helper can count — the HTML head is six
	// literal WriteString lines. The probes are the disclosure for those;
	// no number is claimed, because a number nothing checks is the kind of
	// claim this file deletes rather than qualifies.
	const sizeNotASliceLiteral = -1
	for _, v := range []struct {
		what      string
		size      int
		disclosed int
		inside    []string
		outside   []string
	}{
		// THE WIDEST LIST FIRST. It is the set of formats that can be
		// generated at all, and a response in any other format is
		// something this corpus has never seen one byte of.
		{"the corpus SHAPE list", generatorVocabularySize(t, "buildBenignCorpus", "shapes"), 4,
			// One format marker per generated shape, to show the row is
			// about which FORMATS exist rather than about tokens.
			[]string{`<!doctype html>`, `HTTP/1\.1 `},
			[]string{`<\?xml `, `-----BEGIN `, `Content-Disposition: `}},
		{"benignWords (prose vocabulary)", len(benignWords()), 33,
			[]string{`invoice`, `warehouse`},
			[]string{`expired`, `warning`, `(?i)(error|warning|expired)`}},
		{"benignProse sentence enders", generatorVocabularySize(t, "benignProse", "enders"), 6,
			[]string{`\. `, `\.\n`, `; `},
			// `!` is only ever written as `!\n` and `?` only as `? `.
			[]string{`! `}},
		{"benignHTML tag names", generatorVocabularySize(t, "benignHTML", "tags"), 13,
			[]string{`<div`, `<h2`},
			[]string{`<h1>`, `<table`, `<button`, `<form `, `<input `, `<br>`}},
		{"benignHTML class values", generatorVocabularySize(t, "benignHTML", "classes"), 9,
			[]string{`class="row"`, `class="card"`},
			[]string{`class="banner"`, `class="checkout-total"`}},
		{"benignHTML fixed head literals", sizeNotASliceLiteral, sizeNotASliceLiteral,
			[]string{`class="`, `href="/static`, `<title>`, `charset="utf-8"`},
			// No other attribute, no other path, and NO ENTITY AT ALL.
			[]string{`id="`, `data-testid="`, `href="https`, `/assets/`, `&amp;`, `&nbsp;`}},
		{"benignJSON key names", generatorVocabularySize(t, "benignJSON", "keys"), 14,
			[]string{`"status":`, `"created_at":`},
			[]string{`"error_code":`, `"user_id":`}},
		{"benignJSON value kinds", sizeNotASliceLiteral, sizeNotASliceLiteral,
			[]string{`:null`, `\[\]`, `:true`},
			// %d for every number, and arrays of integers only.
			[]string{`1\.0`, `0\.0`, `\[\{`}},
		{"benignStructural tokens", generatorVocabularySize(t, "benignStructural", "toks"), 45,
			[]string{`Content-Type: application/json`, `Cache-Control: no-store`,
				`HTTP/1\.1 200 OK`},
			[]string{`X-Powered-By: `, `Set-Cookie: `, `text/html`, `HTTP/1\.1 404`}},
	} {
		if v.size != v.disclosed {
			t.Errorf("%s has %d entries and the corpus header discloses %d. The size of "+
				"each list IS the backstop's budget, and a reader sizes their trust to "+
				"the number in the comment; move the comment in the same diff that "+
				"moves the list", v.what, v.size, v.disclosed)
		}
		for _, p := range v.inside {
			if _, err := refuseOverBroadPattern(p); err != nil {
				t.Errorf("%s: the control refuses %q (%v), so this probe says nothing "+
					"about the corpus", v.what, p, err)
				continue
			}
			if _, err := NewSignature(p); err == nil {
				t.Errorf("%s: %q is INSIDE the vocabulary and the corpus accepted it. "+
					"The corpus cannot see the shape at all, so the paired 'outside' "+
					"probe below proves nothing about a vocabulary gap", v.what, p)
			}
		}
		for _, p := range v.outside {
			if _, err := refuseOverBroadPattern(p); err != nil {
				t.Errorf("%s: the control refuses %q (%v); it is no longer a measurement "+
					"of the corpus's budget", v.what, p, err)
				continue
			}
			if _, err := NewSignature(p); err != nil {
				t.Errorf("%s: %q is now REFUSED (%v). That is a good change and the "+
					"disclosure in the corpus header is now wider than the truth — "+
					"narrow it, rather than leaving a residual described that no "+
					"longer exists", v.what, p, err)
			}
		}
	}

	// THE ORIGINALLY-DISCLOSED FACE, BY NAME, with its consequence rather
	// than just its acceptance: it is not "a pattern the corpus misses", it
	// is a SQL-injection candidate confirmed at confidence 1.000 by an
	// ordinary page carrying the word "expired".
	sig, err := NewSignature(`(?i)(error|warning|expired)`)
	if err != nil {
		t.Fatalf("the measured word-vocabulary residual no longer compiles: %v. Widen or "+
			"narrow the disclosure to match", err)
	}
	ordinary := []byte(`<!doctype html><html><body><p>Your session has expired.</p></body></html>`)
	if !sig.re.Match(ordinary) {
		t.Fatal("the measured residual pattern does not fire on the ordinary page it was " +
			"measured against; the fixture has drifted")
	}
}

// TestTheQuotationRuleBoundsWhatAnInlinedSpanCanCarry drives the arithmetic
// the control's header states, over real matches rather than on paper.
//
// The claim is: for any match extractSpan actually inlines, the quoted
// (content-bearing, unspelled) bytes are at most half of it, so at most 256.
// The way to break that claim is to find a pattern NewSignature accepts whose
// inlined span is mostly body, so the sweep below tries to build one at every
// footing length from 1 to 64.
func TestTheQuotationRuleBoundsWhatAnInlinedSpanCanCarry(t *testing.T) {
	const filler = "ANVIL-CANARY-1F4B"
	worst := 0
	for footing := 1; footing <= 64; footing++ {
		// The longest quotation this footing can buy, plus one, which must
		// be refused.
		lit := strings.Repeat("Z", footing)
		for _, tc := range []struct {
			quoted int
			accept bool
		}{{footing, true}, {footing + 1, false}} {
			p := fmt.Sprintf(`%s[[:print:]]{0,%d}`, lit, tc.quoted)
			s, err := NewSignature(p)
			if tc.accept != (err == nil) {
				t.Fatalf("NewSignature(%q): err=%v, want accepted=%v. R3 is 1:1 against "+
					"the literal footing and the boundary must be exactly there",
					p, err, tc.accept)
			}
			if !tc.accept {
				continue
			}
			// The greediest body this signature can be handed.
			body := []byte(lit + strings.Repeat("q", 4096))
			span, _, overBroad, matched := extractSpan(body, s)
			if !matched {
				t.Fatalf("%q did not match its own greediest fixture", p)
			}
			if overBroad != 0 {
				continue // no span at all; the bound already refused it
			}
			quoted := len(span) - footing
			if quoted > footing {
				t.Errorf("%q inlined a %d-byte span carrying %d quoted byte(s) against %d "+
					"spelled: the header's q <= s is false", p, len(span), quoted, footing)
			}
			if 2*quoted > len(span) {
				t.Errorf("%q inlined a span that is more than half body: %d of %d bytes",
					p, quoted, len(span))
			}
			if quoted > worst {
				worst = quoted
			}
		}
	}
	if worst == 0 {
		t.Fatal("the sweep never produced an inlined span with a quoted byte in it; every " +
			"assertion above is vacuous")
	}
	if worst > MaxSpanBytes/2 {
		t.Errorf("the sweep inlined %d quoted bytes and the arithmetic bound is %d",
			worst, MaxSpanBytes/2)
	}
	t.Logf("greediest inlined quotation over the sweep: %d bytes (bound %d)",
		worst, MaxSpanBytes/2)
}

// TestTheQuotationRuleIsTakenOverTheUnionOfWhatAPositionConsumes is R3's
// aggregation rule, and it exists because the per-branch reading of it was
// EVADED BY SPELLING.
//
// MEASURED against the previous shape of shapeOf:
//
//	ZZZZZZZZ(?:([0-9A-Za-z])|([[:punct:]])|( ))*
//	  ACCEPTED, quoted=0, and then matched ALL 634 bytes of an ordinary
//	  634-byte single-line HTML document.
//
// Every branch is a class R3 is silent about on its own — alnum carries no
// separator, punct carries no letter, a single space is a spelled literal —
// and the three capture groups are what stop regexp/syntax folding them into
// the one class that WOULD have been content-bearing. Taking a MAX over
// branches asks which branch quotes most; the question at a position a match
// can enter by any branch is what the position can consume AT ALL, which is
// the union.
//
// The three parts below are the three things that have to be true at once: the
// evasions are refused BY R3 rather than by the corpus behind it, the patterns
// the carve-out exists for still compile, and the residual the rule does NOT
// decide is measured at its ceiling instead of being described.
func TestTheQuotationRuleIsTakenOverTheUnionOfWhatAPositionConsumes(t *testing.T) {
	// PART 1: the evasion family, refused, and refused by the CONTROL.
	// refuseOverBroadPattern is called directly rather than through
	// NewSignature so that a pass cannot be credited to the benign corpus:
	// the corpus is a backstop and a backstop catching this would leave the
	// rule just as broken.
	for _, tc := range []struct {
		pattern string
		why     string
	}{
		{`ZZZZZZZZ(?:([0-9A-Za-z])|([[:punct:]])|( ))*`,
			"THE MEASURED ONE: capture groups block the parser's class merge, so no " +
				"single branch is content-bearing and the union is"},
		{`ZZZZZZZZ(?:[0-9A-Za-z]|[[:punct:]]| )*`,
			"the same alternation with the merge left intact; it must not be the " +
				"parser's folding that decides this"},
		{`ZZZZZZZZ(?:([0-9A-Za-z])|([[:punct:]])|( )){0,400}`,
			"the same union under a CEILING: 400 positions against 8 spelled bytes"},
		{`ZZZZZZZZ(?:([a-z])|([[:punct:]]))+`,
			"two branches rather than three, and a plus rather than a star"},
		{`ZZZZZZZZ(?:[a-z][[:punct:]])*`,
			"the same defect through CONCATENATION inside a repeat: the repeat makes " +
				"one region of the response out of both classes"},
		{`ZZZZZZZZ(?:[a-z][[:punct:]]){200}`,
			"the concatenated unit under a ceiling"},
		{`ZZZZZZZZ(?:([0-9])|([a-z])|([[:punct:]]))*`,
			"three narrow branches, none content-bearing, union content-bearing"},

		// THE SPELLING FAMILY. Every one of these is the SAME position
		// with the SAME alphabet, written so that fewer and fewer of its
		// branches are classes. They are here because the union used to
		// be taken over classes ONLY — "a literal is not a class" — so
		// respelling the punctuation as captured single-rune literals
		// restored the evasion whole while the rule's words stayed the
		// same. The last one contains no class at all.
		{`anvil-probe-4f2a(?:([0-9A-Za-z])|( )|(<)|(>)|(/)|(")|(=)|(-)|(:)|(;)|(,)|(\.)|(!)|(@))*`,
			"THE MEASURED ONE: ACCEPTED with quoted=0, matching 252 of the 321 bytes " +
				"of an ordinary HTML document. Its non-capturing spelling was refused " +
				"only because regexp/syntax MERGES the branches, so the guard's real " +
				"dependency was a parser optimisation and not the stated rule"},
		{`anvil-probe-4f2a(?:[0-9A-Za-z]| |<|>|/|"|=|-|:|;|,|\.|!|@)*`,
			"the merged spelling of the same thing; it must not be the parser that " +
				"decides this"},
		{`anvil-probe-4f2a(?:([0-9A-Za-z])|[ <>/"=:;,.!@-])*`,
			"half spelled and half a class: the union has to cross the two"},
		{`anvil-probe-4f2a(?:([a-z])|( ))*`,
			"the SMALLEST member of the family — one class, one spelled space. If a " +
				"spelled rune is outside the union then lowercase prose is quotable " +
				"without limit against sixteen bytes of footing"},
		{`anvil-probe-4f2a(?:([a-z])|([ ]))*`,
			"the space written as a one-rune CLASS. classShape reads `[ ]` as a " +
				"literal, which is right — and is exactly why the literal has to be " +
				"in the union too"},
		{`anvil-probe-4f2a(?:(a)|(b)|(c)|(d)|(e)|(f)|(g)|(h)|(i)|(j)|(k)|(l)|(m)|` +
			`(n)|(o)|(p)|(q)|(r)|(s)|(t)|(u)|(v)|(w)|(x)|(y)|(z)|( )|(,)|(\.))*`,
			"NOT ONE CLASS ANYWHERE. Twenty-nine captured single-rune literals " +
				"spelling the alphabet of English prose. Putting the literals into " +
				"the union is not enough on its own here — every branch reports " +
				"declared=0, so an aggregation that only promotes DECLARED positions " +
				"has nothing to promote. An alternation is a position the pattern did " +
				"not decide, whatever its branches are made of"},
		{`anvil-probe-4f2a(?:(a)|(b)|(c)|(d)|(e)|(f)|(g)|(h)|(i)|(j)|(k)|(l)|(m)|` +
			`(n)|(o)|(p)|(q)|(r)|(s)|(t)|(u)|(v)|(w)|(x)|(y)|(z)|( )|(,)|(\.)){0,400}`,
			"the all-literal alternation under a CEILING: 400 undecided positions " +
				"against sixteen bytes of footing, because the thinnest branch of a " +
				"mixed alternation is what sets the footing"},
		{`Z(?:err|, )*`,
			"THE DISCLOSED PRICE of the two lines above, named in the control's " +
				"header so it is not read as a regression. Every byte this can match " +
				"is spelled, and it is refused anyway: a repeat of an undecided " +
				"position over an alphabet that crosses letters into punctuation is " +
				"an alphabet DECLARATION, not evidence about a response. If this ever " +
				"starts compiling, the header's disclosure has to change with it"},
	} {
		_, err := refuseOverBroadPattern(tc.pattern)
		if err == nil {
			t.Errorf("refuseOverBroadPattern(%q) ACCEPTED it. %s. R3 is aggregating over "+
				"branches instead of over the union, which is the reading that let a "+
				"pattern quoting zero positions match a whole document",
				tc.pattern, tc.why)
			continue
		}
		if !strings.Contains(err.Error(), "rule R3") {
			t.Errorf("refuseOverBroadPattern(%q) refused it for %q, not R3. It has to be "+
				"the quotation rule that decides this: if some other rule happens to "+
				"catch it, R3 is still evaded and the next spelling gets through",
				tc.pattern, err)
		}
	}

	// PART 2: NON-VACUITY. A union rule that swallowed the carve-out would
	// refuse the patterns the carve-out exists for, and a control that
	// refuses everything is not a control.
	for _, tc := range []struct {
		pattern string
		why     string
	}{
		{`AKIA[0-9A-Z]{16}`, "an AWS key id: one token-shaped class, repeated"},
		{`Server: nginx/1\.[0-9]+\.[0-9]+`,
			"two digit classes and literals; the union is digits and stays token-shaped"},
		{`(?:[0-9]{1,3}\.){3}[0-9]{1,3} ZZZZ`,
			"a dotted quad: a repeat whose unit mixes a digit class with a SPELLED " +
				"dot. The dot IS in the union — ruling 12 put it there — and the " +
				"union is still not content-bearing, because digits and a dot carry " +
				"no letter to run from one token into the next. This is the case that " +
				"separates 'the union holds the literals' from 'the union bans " +
				"literals'"},
		{`<h1[0-9A-Za-z]{0,400}`,
			"the disclosed alnum residual; it is closed at extraction by property 1b " +
				"and must not start being closed here, or the disclosure is wrong"},
		{`<h1[[:print:]]{0,3}`, "three quoted against three spelled: R3 satisfied 1:1"},
		{`Server: nginx/[0-9]+\.[0-9]+ \(Ubuntu[[:print:]]{0,2}\)`,
			"a content-bearing class CONCATENATED with a digit class. A union taken " +
				"at the concatenation would poison the digit run and refuse this"},
		{`(?i)(error|warning|expired)`,
			"an alternation of LITERALS whose union is LETTERS ONLY. Ruling 12 puts " +
				"those letters in the union and marks the position undecided; " +
				"contentBearingClass is still what decides, and a letters-only " +
				"alphabet cannot run out of the token it declared. This is the " +
				"disclosed word-list residual and it must stay open here, or the " +
				"disclosure in the control's header is wrong"},
		{`(?:GET|POST|PUT) /admin/[a-z]{1,20} ZZZZ`,
			"an UNREPEATED alternation whose union crosses letters and a slash. " +
				"Ruling 12 makes that one undecided position, and one undecided " +
				"position against twelve spelled bytes is what R3 exists to allow"},
		{`(?:(a)|(b)|(,))ZZZZZZZZ`,
			"an all-literal alternation that is NOT repeated: one undecided position " +
				"against eight bytes of footing. The bump is to ONE, not to the " +
				"length of the longest branch, and a rule that refused this would be " +
				"a ban on alternation rather than a quotation rule"},
		{`ZZZZ(?:(a)|(b)|(,)){0,4}`,
			"the same alternation under a SMALL ceiling: four undecided positions " +
				"against four spelled bytes, R3 satisfied 1:1. The ceiling is the " +
				"remedy R3's own message tells the author to reach for, so it has to " +
				"work"},
	} {
		if _, err := refuseOverBroadPattern(tc.pattern); err != nil {
			t.Errorf("refuseOverBroadPattern(%q) = %v. %s. The union is taken over what a "+
				"position can CONSUME FROM A CLASS, and widening it past that turns R3 "+
				"into a ban on repeats", tc.pattern, err, tc.why)
		}
	}

	// PART 3: THE RESIDUAL, MEASURED AT ITS CEILING RATHER THAN DESCRIBED.
	//
	// A CONCATENATION is a sequence of positions, each with one alphabet, so
	// R3 does not promote its union — and that is a deliberate line, not an
	// oversight, because promoting at a concatenation is what would refuse
	// the nginx pattern in part 2. What it costs is bounded by arithmetic:
	// every such position must be SPELLED OUT, the cheapest two-rune class
	// is four bytes, and MaxPatternBytes is 1024.
	const worstPairs = 127
	worst := "Z" + strings.Repeat("[ab][,;]", worstPairs)
	if len(worst) > MaxPatternBytes {
		t.Fatalf("the residual fixture is %d bytes and MaxPatternBytes is %d; the ceiling "+
			"moved and this measurement is of nothing", len(worst), MaxPatternBytes)
	}
	if over := "Z" + strings.Repeat("[ab][,;]", worstPairs+1); len(over) <= MaxPatternBytes {
		t.Errorf("%d pairs is %d bytes and still fits under MaxPatternBytes=%d, so %d is "+
			"not the ceiling and the disclosed number is too small",
			worstPairs+1, len(over), MaxPatternBytes, worstPairs)
	}
	sig, err := NewSignature(worst)
	if err != nil {
		t.Fatalf("the residual fixture no longer compiles: %v. That is a WIDENING of R3 "+
			"and the disclosure in the control's header now overstates the residual — "+
			"which is the same defect as understating it", err)
	}
	body := []byte("Z" + strings.Repeat("a,b;", worstPairs))
	span, _, overBroad, matched := extractSpan(body, sig)
	if !matched {
		t.Fatalf("the residual fixture did not match its own body; the measurement below " +
			"is vacuous")
	}
	if len(span) != 0 {
		t.Errorf("extractSpan INLINED %d byte(s) of the residual match. The whole reason "+
			"this residual is disclosed rather than closed is that property 1b refuses "+
			"to inline it: %q", len(span), span)
	}
	if overBroad != 2*worstPairs+1 {
		t.Errorf("extractSpan reported %d over-broad byte(s), want %d. The residual is a "+
			"CONFIRMATION residual of a known size, and if the size has changed the "+
			"disclosure has to change with it", overBroad, 2*worstPairs+1)
	}
	if sig.spelled != 1 {
		t.Errorf("the residual fixture spells %d byte(s), want 1; it is supposed to be the "+
			"worst ratio the pattern budget can buy", sig.spelled)
	}

	// PART 4: THE MEASUREMENT THE SPELLING FAMILY RESTS ON, KEPT LIVE.
	//
	// A refusal is only worth something if the thing refused really would
	// have swallowed a document, and "matching 252 of 321 bytes" is the kind
	// of number that ages into folklore. So the two headline evasions are
	// compiled with regexp DIRECTLY — NewSignature refuses them now, which
	// is the point — and run against an ordinary body here, so the figures
	// quoted in this file and in the control's header are checked on every
	// run rather than remembered.
	const ordinaryHTML = `<!doctype html><html><head><title>Acme Store</title></head>` +
		`<body><h1>anvil-probe-4f2a</h1><p>Welcome to the store, friend. Everything ` +
		`is fine here; nothing is wrong.</p><ul><li>one</li><li>two</li><li>three</li>` +
		`</ul><footer>copyright 2026 acme, inc. all rights reserved. contact: ` +
		`sales@acme.example</footer></body></html>`
	for _, tc := range []struct {
		pattern   string
		wantBody  int
		wantMatch int
		what      string
	}{
		{`anvil-probe-4f2a(?:([0-9A-Za-z])|( )|(<)|(>)|(/)|(")|(=)|(-)|(:)|(;)|(,)|` +
			`(\.)|(!)|(@))*`, 321, 252,
			"the capture-group respelling, which was ACCEPTED with quoted=0"},
		{`anvil-probe-4f2a(?:[0-9A-Za-z]| |<|>|/|"|=|-|:|;|,|\.|!|@)*`, 321, 252,
			"the merged spelling: identical behaviour, and it was refused only " +
				"because regexp/syntax folds the branches into one class"},
	} {
		if len(ordinaryHTML) != tc.wantBody {
			t.Fatalf("the ordinary-document fixture is %d bytes and the measurements "+
				"quoted throughout this file assume %d", len(ordinaryHTML), tc.wantBody)
		}
		if _, err := refuseOverBroadPattern(tc.pattern); err == nil {
			t.Errorf("refuseOverBroadPattern still accepts %q; part 1 above is the "+
				"assertion, and this part only measures what acceptance would cost",
				tc.pattern)
		}
		m := regexp.MustCompile(tc.pattern).FindStringIndex(ordinaryHTML)
		if m == nil {
			t.Errorf("%s does not match the ordinary document at all; the measurement "+
				"behind the refusal has drifted and the refusal is now unmotivated",
				tc.what)
			continue
		}
		if got := m[1] - m[0]; got != tc.wantMatch {
			t.Errorf("%s matches %d of the %d bytes of an ordinary document, and this "+
				"file says %d. Move the number in the same diff that moves the fixture",
				tc.what, got, len(ordinaryHTML), tc.wantMatch)
		}
	}
}

// TestASpanMayNotCarryMoreOfTheBodyThanThePatternSpells is extractSpan's
// property 1b, and it exists because RERUNNING THIS ROUND'S OWN ATTACK ONE
// CLASS TO THE LEFT FOUND THE DEFECT ALIVE.
//
// MEASURED, after R1/R2/R3 were in place and all twenty `[\s\S]` anchors were
// refused:
//
//	<h1[0-9A-Za-z]{0,400}   ACCEPTED, match=true span=403 overBroad=0
//
// An alphanumeric class carries no separator, so R3 does not count it as
// quotation — and that reasoning is load-bearing, because it is the same
// reasoning that lets AKIA[0-9A-Z]{16} and `nginx/1\.[0-9]+` compile. So the
// answer was not to widen R3 until it caught this too; it was to enforce the
// same inequality a second time, at extraction, over the actual match, where
// no class definition is involved at all.
func TestASpanMayNotCarryMoreOfTheBodyThanThePatternSpells(t *testing.T) {
	// THE MEASURED CASE, by name and with the same fixture.
	attack := `<h1[0-9A-Za-z]{0,400}`
	s := mustSignature(t, attack)
	body := []byte("<h1" + strings.Repeat("a", 600))
	span, _, overBroad, matched := extractSpan(body, s)
	if !matched {
		t.Fatalf("%q did not match its own fixture", attack)
	}
	if span != "" {
		t.Errorf("%q inlined a %d-byte span from three spelled bytes: %q. That is the "+
			"403-byte inlining this round was supposed to close, one character class "+
			"to the left of where it was closed",
			attack, len(span), printable(span, 48))
	}
	if overBroad != len(body) && overBroad == 0 {
		t.Errorf("the withheld span was not recorded: overBroad = %d. A span that "+
			"vanishes without a number beside it is a match a reader cannot account "+
			"for", overBroad)
	}

	// THE SWEEP. For every footing from 1 to 48, the longest match that
	// satisfies L-s <= s keeps its span and the next byte loses it. The
	// boundary is asserted on BOTH sides, because a rule that only ever
	// refuses, or only ever allows, is not a boundary.
	for footing := 1; footing <= 48; footing++ {
		lit := strings.Repeat("Z", footing)
		sig := mustSignature(t, lit+`[0-9A-Za-z]*`)
		for _, tc := range []struct {
			extra    int
			wantSpan bool
		}{{footing, true}, {footing + 1, false}} {
			b := []byte(lit + strings.Repeat("a", tc.extra))
			span, _, over, ok := extractSpan(b, sig)
			if !ok {
				t.Fatalf("footing %d: the fixture did not match", footing)
			}
			if (span != "") != tc.wantSpan {
				t.Errorf("footing=%d match=%d bytes (%d unspelled): span=%q over=%d, "+
					"want span=%v. The rule is L-s <= s and the boundary must be "+
					"exactly there", footing, len(b), tc.extra, printable(span, 32),
					over, tc.wantSpan)
			}
			if tc.wantSpan && len(span) != len(b) {
				t.Errorf("footing=%d: a span inside the budget was %d bytes, want the "+
					"whole %d-byte match", footing, len(span), len(b))
			}
		}
	}

	// THE COST, ASSERTED SO IT IS KNOWN RATHER THAN DISCOVERED. A signature
	// whose whole job is to quote a token loses its span. It does NOT lose
	// its verdict or its body hash, which is what makes the trade payable.
	akia := mustSignature(t, `AKIA[0-9A-Z]{16}`)
	span, _, over, ok := extractSpan([]byte("... AKIA1234567890ABCDEF ..."), akia)
	if !ok {
		t.Fatal("the AKIA fixture did not match")
	}
	if span != "" {
		t.Errorf("AKIA[0-9A-Z]{16} inlined %q. Four spelled bytes do not buy sixteen "+
			"unspelled ones, and a 16-character AWS key id is a credential", span)
	}
	if over != 20 {
		t.Errorf("SpanOverBroadBytes = %d, want 20: the match length must be recorded "+
			"even when the span is withheld", over)
	}

	// AND THE OTHER DIRECTION, so this is a rule and not a ban on classes:
	// a signature that spells enough keeps its span.
	nginx := mustSignature(t, `Server: nginx/1\.[0-9]+\.[0-9]+`)
	span, _, _, ok = extractSpan([]byte("Server: nginx/1.24.0\r\n"), nginx)
	if !ok || span != "Server: nginx/1.24.0" {
		t.Errorf("the nginx banner span = %q (matched=%v); 17 spelled bytes comfortably "+
			"pay for three unspelled ones, and a rule that refuses this is a ban on "+
			"variable content rather than a bound on quotation", span, ok)
	}
}

// withEmptyBenignCorpus runs f with the backstop switched off.
//
// It is the only way to tell the two checks apart from outside NewSignature,
// and telling them apart is the whole subject of this round: for three rounds
// the corpus was DESCRIBED as the control, and no test could have noticed the
// difference. With the corpus emptied, every refusal NewSignature still
// produces is the control's, and every refusal that disappears was the
// backstop's.
//
// No test in this package calls t.Parallel(), so the swap is safe; the restore
// is deferred so a failing assertion inside f cannot leave the package with no
// backstop for the tests that follow.
func withEmptyBenignCorpus(t *testing.T, f func()) {
	t.Helper()
	saved := benignCorpus
	benignCorpus = nil
	defer func() { benignCorpus = saved }()
	f()
}

// TestTheControlDecidesOnTheStructureAndNotOnASampleOfBodies is the claim
// ruling 9 asks for, made falsifiable.
//
// A check that samples inputs has a budget: the attacker needs one input
// outside the sample, and four rounds of this file have produced one each
// time. The control's claim is that it samples nothing — its verdict is a
// function of the pattern alone. THIS TEST EMPTIES THE CORPUS AND CHECKS THAT
// THE VERDICT DOES NOT MOVE. If any of these refusals came from a body, it
// would vanish when the bodies do.
func TestTheControlDecidesOnTheStructureAndNotOnASampleOfBodies(t *testing.T) {
	// One representative per rule, plus the two families measured in
	// rounds two and three.
	refused := []struct{ pattern, rule string }{
		{`(?s)[\s\S]{721}`, "R1: spells nothing"},
		{`.`, "R1: spells nothing"},
		{`x{0,3}`, "R1: a path that spells nothing"},
		{`(?s)<h1[\s\S]{0,400}`, "R2: an open position"},
		{`(?s)<div[\s\S]{0,500}`, "R2: an open position"},
		{`ANVIL-CANARY-1F4B\s{0,9}`, "R2: whitespace is not printable ASCII"},
		{`<h1[[:print:]]{0,400}`, "R3: quotes 400 against 3"},
		{`ANVIL-CANARY-1F4B[[:print:]]*`, "R3: quotes without a ceiling"},
	}
	withEmptyBenignCorpus(t, func() {
		if len(benignCorpus) != 0 {
			t.Fatal("the corpus was not emptied; this test is about to prove nothing")
		}
		for _, tc := range refused {
			if _, err := NewSignature(tc.pattern); !errors.Is(err, ErrSignatureMatchesEverything) {
				t.Errorf("with NO benign bodies at all, NewSignature(%q) = %v. This "+
					"refusal was supposed to be structural (%s); it came from a "+
					"sample, and a sample has a budget", tc.pattern, err, tc.rule)
			}
		}
	})
	// And the same verdicts with the corpus back, so the swap itself is not
	// what produced them.
	for _, tc := range refused {
		if _, err := NewSignature(tc.pattern); !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%q) = %v with the corpus restored", tc.pattern, err)
		}
	}

	// EACH RULE IS LOAD-BEARING, shown by a pattern only that rule refuses.
	// A rule the others already cover is a rule that could be deleted with
	// a green build, which is how a guard becomes decoration.
	for _, tc := range []struct {
		name    string
		pattern string
		// what shapeOf must say, so the arm being exercised is named
		// rather than inferred from the refusal text.
		wantOpen     bool
		wantNoLit    bool
		wantOverQuot bool
	}{
		{"R1 alone", `[\s\S]{0,4}`, true, true, false},
		{"R1 without R2", `(?:AB)?`, false, true, false},
		{"R2 without R1", `ANVIL-CANARY-1F4B[\s\S]{1,4}`, true, false, false},
		{"R3 without R1 or R2", `<h1[[:print:]]{0,400}`, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := syntax.Parse(tc.pattern, syntax.Perl)
			if err != nil {
				t.Fatalf("parsing %q: %v", tc.pattern, err)
			}
			s := shapeOf(parsed)
			if s.open != tc.wantOpen {
				t.Errorf("shapeOf(%q).open = %v, want %v", tc.pattern, s.open, tc.wantOpen)
			}
			if (s.minLiteral == 0) != tc.wantNoLit {
				t.Errorf("shapeOf(%q).minLiteral = %d, want zero=%v",
					tc.pattern, s.minLiteral, tc.wantNoLit)
			}
			overQuoted := s.quoted == shapeUnbounded || s.quoted > s.minLiteral
			if overQuoted != tc.wantOverQuot {
				t.Errorf("shapeOf(%q) quoted=%d minLiteral=%d, want over-quoted=%v",
					tc.pattern, s.quoted, s.minLiteral, tc.wantOverQuot)
			}
			if _, err := refuseOverBroadPattern(tc.pattern); err == nil {
				t.Errorf("refuseOverBroadPattern(%q) accepted it", tc.pattern)
			}
		})
	}

	// THE R1 BOUNDARY IS EXACTLY ZERO, not a length somebody picked. One
	// spelled byte is enough, and it must be, or the rule would be a
	// minimum-length threshold wearing a structural argument.
	if _, err := refuseOverBroadPattern(`Z[0-9]{0,0}`); err != nil {
		t.Errorf("refuseOverBroadPattern(`Z[0-9]{0,0}`) = %v; one spelled byte satisfies "+
			"R1 by construction and anything stricter is a threshold", err)
	}

	// AN OPERATOR THIS WALKER HAS NEVER HEARD OF FAILS CLOSED. The default
	// arm is the reason "a future regexp/syntax operator" is not on anyone's
	// list of things to remember.
	if s := shapeOf(&syntax.Regexp{Op: syntax.Op(200)}); !s.open {
		t.Error("shapeOf reported a regexp operator it does not know as safe. The " +
			"failure mode of not knowing must be a refused signature, or this walker " +
			"is a denylist of the operators somebody thought of")
	}
	// AND A MALFORMED TREE DOES NOT PANIC. syntax.Parse cannot produce a
	// childless Star, so these are unreachable from NewSignature — but a
	// panic inside a production admission check is a crash, and the guard is
	// cheaper than the claim that it can never happen.
	if s := shapeOf(nil); !s.open {
		t.Error("shapeOf(nil) reported a safe shape")
	}
	for _, op := range []syntax.Op{syntax.OpCapture, syntax.OpQuest, syntax.OpStar,
		syntax.OpPlus, syntax.OpRepeat} {
		if s := shapeOf(&syntax.Regexp{Op: op}); !s.open {
			t.Errorf("shapeOf(childless %v) reported a safe shape", op)
		}
	}
}

// TestTheOpenPositionRuleUsesTheSpanExtractorsOwnCharset checks R2's premise
// by RUNNING the extractor rather than by reading its constants.
//
// R2's argument is "a signature may not match through bytes its own evidence
// extractor throws away". That argument is only worth anything if the two
// charsets are the same set, and a second spelling of 0x20-0x7e in this file
// would be a second thing to keep current. So the agreement is measured over
// all 256 byte values, in both directions.
func TestTheOpenPositionRuleUsesTheSpanExtractorsOwnCharset(t *testing.T) {
	// A raw fixture, because a Signature that could match every byte is
	// exactly what the rule under test forbids; spelled is large so the
	// composition rule cannot fire on these three-byte matches.
	all := Signature{re: regexp.MustCompile(`(?s)Z[\s\S]*Z`), src: "fixture",
		spelled: MaxSpanBytes, sealed: true}
	agreed, kept := 0, 0
	for b := 0; b < 256; b++ {
		span, dropped, _, matched := extractSpan([]byte{'Z', byte(b), 'Z'}, all)
		if !matched {
			t.Fatalf("byte 0x%02x: the fixture did not match, so nothing is measured", b)
		}
		extractorKeeps := dropped == 0 && len(span) == 3
		if extractorKeeps {
			kept++
		}

		// The same byte as a two-rune class, which is what the rule sees.
		class := []rune{rune(b), rune(b), 'a', 'a'}
		if rune(b) > 'a' {
			class = []rune{'a', 'a', rune(b), rune(b)}
		}
		ruleOpen := openClass(class)
		if ruleOpen == extractorKeeps {
			t.Errorf("byte 0x%02x: extractSpan keeps it = %v, and openClass calls the "+
				"class open = %v. R2's whole argument is that those are the same "+
				"question, and they have stopped being", b, extractorKeeps, ruleOpen)
			continue
		}
		agreed++
	}
	if agreed != 256 {
		t.Errorf("the rule and the extractor agreed on %d of 256 bytes", agreed)
	}
	// The positive control on the sweep: if the extractor kept everything,
	// or nothing, every agreement above would be an accident.
	if kept != printableASCIIHi-printableASCIILo+1 {
		t.Errorf("the extractor kept %d of 256 bytes, want %d; the sweep is not "+
			"exercising both sides", kept, printableASCIIHi-printableASCIILo+1)
	}
}

// TestTheBackstopRefusesWhatTheControlAccepts is what makes "backstop" a
// demonstrated word.
//
// A backstop that never catches anything the control misses is not a backstop,
// it is a second copy of the control paying a megabyte of scan per signature.
// So: patterns the structural rules ACCEPT, that the corpus refuses, and the
// same patterns accepted again once the corpus is taken away.
//
// Every fixture here is markup benignHTML emits UNCONDITIONALLY — the doctype,
// the stylesheet link, the script tag — rather than a tag-and-class
// combination the generator only reaches by chance. A backstop test that
// depended on the RNG landing somewhere would be a flake, and a flake in a
// guard is a guard that gets deleted.
func TestTheBackstopRefusesWhatTheControlAccepts(t *testing.T) {
	furniture := []string{
		`<!doctype html>`,
		`<link rel="stylesheet" href="/static/site\.css">`,
		`<script src="/static/app\.js"></script>`,
		`<meta charset="utf-8">`,
	}
	for _, p := range furniture {
		if _, err := refuseOverBroadPattern(p); err != nil {
			t.Errorf("refuseOverBroadPattern(%q) = %v; this fixture is supposed to be one "+
				"the CONTROL accepts, so it no longer demonstrates anything about the "+
				"backstop", p, err)
			continue
		}
		if _, err := NewSignature(p); !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("NewSignature(%q) = %v; the backstop is not catching ordinary "+
				"document furniture, which is the one job the structural rules cannot "+
				"do — %q is seven or more spelled bytes either way, and only a body "+
				"can say whether an ordinary page contains it", p, err, p)
		}
	}

	// AND THE OTHER DIRECTION, which is what proves the refusals above came
	// from the corpus rather than from a rule that happens to catch them:
	// with no bodies, every one of them compiles.
	withEmptyBenignCorpus(t, func() {
		for _, p := range furniture {
			if _, err := NewSignature(p); err != nil {
				t.Errorf("with the corpus emptied, NewSignature(%q) = %v. The refusal "+
					"was not the backstop's after all, and this test is measuring "+
					"something other than what it claims", p, err)
			}
		}
	})
}

// BenchmarkBenignCorpusBuild measures what package initialisation costs.
//
// It exists because the corpus section's cost paragraph used to state a figure
// nothing had measured. Run it, and the number in that paragraph is checkable:
//
//	go test -run XXX -bench 'BenignCorpus|NewSignature' -benchtime 10x ./internal/dast/record/
func BenchmarkBenignCorpusBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if got := len(buildBenignCorpus()); got == 0 {
			b.Fatal("the corpus built empty")
		}
	}
}

// BenchmarkNewSignature measures the per-signature cost of the two checks
// together, over a pattern that reaches the END of the corpus — an ordinary
// oracle, refused by nothing, which is the case that pays for the whole scan.
func BenchmarkNewSignature(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := NewSignature(sqliPattern); err != nil {
			b.Fatalf("NewSignature: %v", err)
		}
	}
}

// BenchmarkRefuseOverBroadPattern measures the CONTROL alone, which is what
// decides whether putting it first is a saving or a tax.
func BenchmarkRefuseOverBroadPattern(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := refuseOverBroadPattern(sqliPattern); err != nil {
			b.Fatalf("refuseOverBroadPattern: %v", err)
		}
	}
}

// TestAnOverBroadMatchOnAHostileBodyProducesNoSpanEvenWhenTheSignatureIsNarrow
// is the second line HIGH 3 needs.
//
// NewSignature refuses patterns that are broad against benignCorpus. A
// pattern can pass that and still swallow a hostile body whole:
// spanBoundaryPattern is specific enough that no generated benign body matches
// it, and against a body that opens with its start marker and closes with its
// end marker it matches the lot. The span bound is what catches that, and it
// catches it by producing NOTHING rather than by producing a shorter prefix.
func TestAnOverBroadMatchOnAHostileBodyProducesNoSpanEvenWhenTheSignatureIsNarrow(t *testing.T) {
	// Alphanumeric because spanBoundaryPattern's middle is a token-shaped
	// class; a hyphen would end the run instead of being swallowed by it.
	const secret = "SENSITIVEPREFIXOFTHERESPONSE"
	hostile := []byte("ANVIL-SPAN-BEGIN" + secret + strings.Repeat("q", 4096) + "ANVIL-SPAN-END")

	rp := &scriptedReprober{body: func(RawFinding, int) []byte { return hostile }}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: 3})
	c := sqliCandidate(t, "/search")
	c.Signature = mustSignature(t, spanBoundaryPattern)

	f, err := g.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	// The oracle fired. That is a separate fact from whether its match can
	// be shown, and conflating the two would silently turn every over-broad
	// match into a non-reproduction.
	if f.Outcome() != OutcomeConfirmed {
		t.Fatalf("outcome = %q; the signature matched every attempt and withholding the "+
			"SPAN must not change the VERDICT", f.Outcome())
	}
	if got := f.Evidence().ExtractedSpan(); got != "" {
		t.Errorf("span = %q (%d bytes)", printable(got, 64), len(got))
	}
	if strings.Contains(f.Evidence().ExtractedSpan(), secret) {
		t.Error("the evidence span carries a verbatim prefix of the response body")
	}
	if got, want := f.Evidence().SpanOverBroadBytes(), len(hostile); got != want {
		t.Errorf("SpanOverBroadBytes = %d, want %d", got, want)
	}
	if strings.Contains(f.String(), secret) {
		t.Error("Finding.String() quotes the response body")
	}
}

// ===========================================================================
// D.29 MEDIUM 5 — the attempt count had a ceiling and no floor
// ===========================================================================

// TestAttemptCountHasAFloorAndNotOnlyACeiling.
//
// Attempts=1 was legal and produced reason="reproduced_on_every_attempt"
// from a single observation — the flake detection DefaultAttempts=3 exists
// for, removed, with the reason string still claiming it ran. D.31 wiring
// under a time budget is exactly the caller that would set it.
func TestAttemptCountHasAFloorAndNotOnlyACeiling(t *testing.T) {
	for _, n := range []int{1, -1, -1000, MaxAttempts + 1, 1 << 20} {
		if _, err := NewGate(GateConfig{Attempts: n}); !errors.Is(err, ErrRefused) {
			t.Errorf("NewGate with Attempts=%d = %v, want a refusal", n, err)
		}
	}
	for _, n := range []int{MinAttempts, DefaultAttempts, MaxAttempts} {
		g, err := NewGate(GateConfig{Attempts: n})
		if err != nil {
			t.Fatalf("NewGate with Attempts=%d: %v", n, err)
		}
		if g.Attempts() != n {
			t.Errorf("Attempts() = %d, want %d", g.Attempts(), n)
		}
	}
	if MinAttempts < 2 {
		t.Fatalf("MinAttempts = %d; below two there is no ratio and "+
			"ReasonReproducedIntermittently is unreachable", MinAttempts)
	}
	if DefaultAttempts < MinAttempts || DefaultAttempts > MaxAttempts {
		t.Fatalf("DefaultAttempts=%d is outside [%d,%d]",
			DefaultAttempts, MinAttempts, MaxAttempts)
	}

	// THE CLAIM, driven: at the floor a flake is still visible as a flake.
	rp := &scriptedReprober{body: func(_ RawFinding, attempt int) []byte {
		if attempt == 1 {
			return []byte(`{"error":"` + sqliMarker + `"}`)
		}
		return []byte(`{"ok":true}`)
	}}
	g := mustGate(t, GateConfig{Reprober: rp, Attempts: MinAttempts})
	f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	if f.Reason() != ReasonReproducedIntermittently {
		t.Errorf("reason = %q at Attempts=%d over a 1-of-%d reproduction, want %q. If the "+
			"floor cannot tell a flake from a finding it is not a floor",
			f.Reason(), MinAttempts, MinAttempts, ReasonReproducedIntermittently)
	}
	if f.Outcome() == OutcomeConfirmed {
		t.Error("a one-in-two reproduction was confirmed")
	}
}

// ===========================================================================
// D.29 MEDIUM 6 — an unconfirmed finding carrying full confidence
// ===========================================================================

// TestNoUnconfirmedFindingCarriesFullConfidence is the record-consistency
// claim, driven over every route to unconfirmed there is.
//
// The defect was narrow and the guard is not: the confidence gate keyed on
// Class.OracleLess() alone and ignored DetectionMethod.CanConfirm(), so a
// model_inference candidate matching 3 of 3 landed unconfirmed with reason
// "model_inference_is_not_an_observation" AND confidence 1.000. Two
// statements contradicting each other inside one record.
func TestNoUnconfirmedFindingCarriesFullConfidence(t *testing.T) {
	vulnerable := []byte(`{"error":"` + sqliMarker + `"}`)

	cases := []struct {
		name     string
		mutate   func(*RawFinding)
		reprober *scriptedReprober
	}{
		{
			name:     "oracle-less class, reproducing every time",
			mutate:   func(c *RawFinding) { c.Class = ClassAuthorization },
			reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return vulnerable }},
		},
		{
			name:     "IDOR, reproducing every time",
			mutate:   func(c *RawFinding) { c.Class = ClassIDOR },
			reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return vulnerable }},
		},
		{
			name:     "business logic, reproducing every time",
			mutate:   func(c *RawFinding) { c.Class = ClassBusinessLogic },
			reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return vulnerable }},
		},
		{
			name:     "model inference, reproducing every time",
			mutate:   func(c *RawFinding) { c.DetectionMethod = DetectionMethodModelInference },
			reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return vulnerable }},
		},
		{
			name:   "intermittent",
			mutate: func(*RawFinding) {},
			reprober: &scriptedReprober{body: func(_ RawFinding, attempt int) []byte {
				if attempt == 1 {
					return vulnerable
				}
				return []byte(`{"ok":true}`)
			}},
		},
		{
			name:   "indecisive on every attempt",
			mutate: func(*RawFinding) {},
			reprober: &scriptedReprober{
				body:     func(RawFinding, int) []byte { return vulnerable },
				statusFn: func(RawFinding, int) int { return 429 },
			},
		},
	}

	sawUnconfirmed := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := mustGate(t, GateConfig{Reprober: tc.reprober, Attempts: 3})
			c := sqliCandidate(t, "/admin/users")
			tc.mutate(&c)
			f, err := g.ConfirmFinding(context.Background(), c)
			if err != nil {
				t.Fatalf("ConfirmFinding: %v", err)
			}
			if f.Outcome() != OutcomeUnconfirmed {
				t.Fatalf("outcome = %q, want unconfirmed; this case is not exercising "+
					"the invariant. %s", f.Outcome(), f)
			}
			sawUnconfirmed++

			conf, ok := f.Confidence()
			if ok && conf >= 1.0 {
				t.Errorf("an UNCONFIRMED finding reports confidence %.3f with "+
					"confidenceKnown=true. reason=%q and confidence=1.000 are two "+
					"statements contradicting each other in one record, and a consumer "+
					"sorting by confidence puts this at the top of the list the reason "+
					"exists to keep it off", conf, f.Reason())
			}
			// The stronger half for the three routes where the CLAIM is
			// withheld entirely rather than merely reduced.
			switch f.Reason() {
			case ReasonNoOracleForClass, ReasonModelInferenceIsNotObservation,
				ReasonReprobeIndecisive:
				if ok {
					t.Errorf("reason=%q reports a confidence of %.3f; there is no "+
						"reproduction ratio standing behind this finding at all, and 0.0 "+
						"or 1.0 both read as claims Anvil cannot make", f.Reason(), conf)
				}
			case ReasonReproducedIntermittently:
				if !ok {
					t.Error("an intermittent reproduction of an oracle-bearing class " +
						"detected by template has a real ratio and must report it")
				}
			}
			// The MEASUREMENT survives in every case.
			if f.Attempts() != 3 {
				t.Errorf("Attempts = %d, want 3", f.Attempts())
			}
		})
	}
	if sawUnconfirmed != len(cases) {
		t.Fatalf("%d of %d cases reached unconfirmed", sawUnconfirmed, len(cases))
	}

	// THE POSITIVE CONTROL on the whole invariant: confidence 1.000 with
	// confidenceKnown=true is reachable, and only from a CONFIRMED finding.
	// Without this, a gate that returned (0,false) unconditionally would
	// pass every assertion above.
	g := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return vulnerable }},
		Attempts: 3,
	})
	f, err := g.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	if conf, ok := f.Confidence(); !ok || conf != 1.0 || f.Outcome() != OutcomeConfirmed {
		t.Fatalf("the control case gave outcome=%q confidence=(%v,%v); full confidence is "+
			"unreachable and every assertion above is vacuous", f.Outcome(), conf, ok)
	}
}
