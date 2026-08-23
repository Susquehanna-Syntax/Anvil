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
	// THIS FIXTURE NO LONGER CONFIRMS, AND THAT IS RULING 14 RATHER THAN
	// DRIFT. It used to assert OutcomeConfirmed here, on the reasoning that
	// the walk is only worth doing on the value a consumer forwards. The
	// match is 512 KiB against 16 spelled bytes, so it now lands unconfirmed
	// with reason signature_match_quoted_more_than_it_spells.
	//
	// The premise stays honoured rather than dropped: a SECOND finding is
	// built below from a narrow signature against a body of the same size,
	// it IS confirmed, it carries a real span, and the walk runs over both.
	// Deleting the confirmed half would have quietly narrowed the
	// type-closure claim to unconfirmed findings only.
	if got, want := f.Outcome(), OutcomeUnconfirmed; got != want {
		t.Fatalf("outcome = %q, want %q", got, want)
	}
	if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
		t.Fatalf("reason = %q, want %q", got, want)
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

	// THE CONFIRMED HALF. A narrow oracle against a body of the same size:
	// sqliMarker is 60 spelled bytes and the match is exactly the marker, so
	// the composition rule is satisfied and this one really is the value a
	// consumer forwards.
	confirmedBody := []byte(strings.Repeat("q", bodyBytes/2) + sqliMarker +
		strings.Repeat("q", bodyBytes/2))
	cg := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return confirmedBody }},
		Attempts: 2,
	})
	confirmedHalf, err := cg.ConfirmFinding(context.Background(), sqliCandidate(t, "/search"))
	if err != nil {
		t.Fatalf("ConfirmFinding (confirmed half): %v", err)
	}
	if got, want := confirmedHalf.Outcome(), OutcomeConfirmed; got != want {
		t.Fatalf("the confirmed half came out %q, want %q; without it this test walks no "+
			"confirmed value and the type-closure claim is narrower than it reads",
			got, want)
	}
	if confirmedHalf.Evidence().ExtractedSpan() == "" {
		t.Fatal("the confirmed half carries an EMPTY span, so the walk below would not " +
			"see a span at all and the assertion would be vacuous")
	}

	// The claim, over every string reachable from the value a consumer
	// holds — unexported fields included — for BOTH outcomes.
	for _, walked := range []*Finding{f, confirmedHalf} {
		if v := oversizedStrings("Finding", reflect.ValueOf(*walked), MaxSpanBytes); len(v) != 0 {
			t.Errorf("a Finding built from a %d-byte response body holds string(s) longer "+
				"than MaxSpanBytes=%d:\n%s", bodyBytes, MaxSpanBytes, strings.Join(v, "\n"))
		}
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
				span, dropped, overBroad, _, matched := extractSpan(body, all)
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
			span, dropped, _, _, matched := extractSpan(body, all)
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
		span, dropped, _, _, matched := extractSpan(malformed, all)
		if !matched || dropped != 2 || !isPrintableASCII(span) || !strings.Contains(span, "okok") {
			t.Errorf("malformed UTF-8: span=%q dropped=%d matched=%v", span, dropped, matched)
		}
	})

	t.Run("no_match_no_span", func(t *testing.T) {
		span, dropped, overBroad, _, matched := extractSpan([]byte("nothing here"), all)
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
	// construction (confirmed requires matches == attempts: anything less is
	// ReasonReproducedIntermittently, which outcomeForReason maps to
	// unconfirmed), so there is no confidence value at which confirmed and
	// unconfirmed overlap. Proved by running every reason through the
	// mapping; the arithmetic itself is ENFORCED BY ConfirmFinding,
	// MEASURED BY TestIntermittentReproductionIsUnconfirmed on the
	// matches < attempts side, and ENFORCED BY Confidence,
	// MEASURED BY TestNoUnconfirmedFindingCarriesFullConfidence on the
	// confidence side.
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
				got := decide(c, matches, 0 /* indecisive */, 0 /* overQuoted */, attempts)

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
// completed_clean over a live vulnerability. ENFORCED BY ConfirmFinding,
// MEASURED BY TestARateLimitedReprobeIsNotADisproof.
//
// THAT CITATION USED TO NAME decide AND IT WAS SELF-CERTIFYING. A citation
// standing in a test's own doc comment, measured by that same test, passed
// the aptness check on the strength of the words "decide()" in the paragraph
// above it — the claim was certifying itself. Under ruling 17 the check reads
// the cited test's SYNTAX TREE, where a comment leaves no trace, so the
// citation now has to name something this test's code names: ConfirmFinding,
// which every case below drives, and which reaches decide.
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
// — it returned non-zero zero times.
//
// THE REASON THIS PARAGRAPH USED TO GIVE FOR THAT WAS FALSE IN BOTH HALVES,
// AND IT WAS THE SECOND COPY OF A SENTENCE CORRECTED IN confirm_gate.go WHILE
// THIS ONE STOOD. The withdrawn wording is quoted and
// refuted once, at assertRejectionIsDecisive, and it is entry 1 of
// withdrawnPhrasings so that neither copy can be corrected without the other:
// TestNoWithdrawnPhrasingSurvivesAsLiveProse fails on the wording itself, in
// any file of this package, at any line wrapping.
//
// The route that DOES make the count unreachable: ReasonDidNotReproduce is
// the only reason outcomeForReason maps to OutcomeRejected, and no indecisive
// run arrives at it. Rule 3 takes an indecisive run with no match to
// ReasonReprobeIndecisive, and an indecisive run that also carries an
// over-broad match is taken earlier still, by rule 2, to
// ReasonMatchQuotedTheResponse. Either way ConfirmFinding cannot produce the
// value that method counted. The report that called it "the second line of
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
			span, _, overBroad, _, matched := extractSpan(body, s)
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
			"the space written as a one-rune CLASS. classShape never sees one: " +
				"regexp/syntax rewrites `[ ]` into the LITERAL space before this " +
				"walk starts, which is exactly why the literal has to be in the " +
				"union too. See TestAOneRuneClassNeverReachesTheWalk"},
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
	// the nginx pattern in part 2.
	//
	// WHAT IT COSTS IS NOT BOUNDED BY MaxPatternBytes, and the sentence that
	// used to sit here said it was: "What it costs is bounded by arithmetic:
	// every such position must be SPELLED OUT, the cheapest two-rune class
	// is four bytes, and MaxPatternBytes is 1024". MaxPatternBytes bounds
	// the number of ELEMENTS in a concatenation; an element may be an
	// unbounded repeat, which is how the 12,500,141-byte attack exists at
	// 891 pattern bytes. What follows is the ceiling OF THIS SHAPE —
	// fixed-width two-rune classes — and of nothing wider.
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
	span, _, overBroad, matchLen, matched := extractSpan(body, sig)
	if !matched {
		t.Fatalf("the residual fixture did not match its own body; the measurement below " +
			"is vacuous")
	}
	if sig.spelled != 1 {
		t.Errorf("the residual fixture spells %d byte(s), want 1; it is supposed to be the "+
			"worst ratio the pattern budget can buy", sig.spelled)
	}
	if matchLen != 2*worstPairs+1 {
		t.Errorf("the residual match is %d bytes, want %d; the measurement is of a "+
			"different fixture than the one disclosed", matchLen, 2*worstPairs+1)
	}

	// RULING 15 REVERSED THE DIRECTION OF THIS MEASUREMENT AND THE OLD ONE
	// IS QUOTED SO THE REVERSAL IS LEGIBLE. It asserted `len(span) == 0` and
	// `overBroad == 255`, on the reasoning that "the whole reason this
	// residual is disclosed rather than closed is that property 1b refuses
	// to inline it". Property 1b now has a floor: 254 of these 255 bytes are
	// unspelled, 254 is inside MaxUnspelledBytes, so the match is INLINED
	// and the finding CONFIRMS.
	//
	// THE RESIDUAL DID NOT CLOSE, IT CHANGED SHAPE, and this is the shape.
	// It is asserted at full size — one spelled byte, 254 of the target's —
	// because that is the number the disclosure at MaxUnspelledBytes names,
	// and a residual whose measurement is left in the old direction reads to
	// the next reader as a residual that was fixed.
	if len(span) != matchLen || overBroad != 0 {
		t.Errorf("the residual match inlined %d of %d bytes (over=%d); ruling 15's floor "+
			"admits it whole and the disclosure says so. If this is withheld again "+
			"the floor has moved and MaxUnspelledBytes has to move with it",
			len(span), matchLen, overBroad)
	}
	if q := matchLen - sig.spelled; q > MaxUnspelledBytes {
		t.Errorf("the residual carries %d unspelled bytes and the published ceiling is "+
			"%d; an inlined span may never exceed it", q, MaxUnspelledBytes)
	}
	rf, _ := overBroadCandidate(t, worst, body, 3)
	if got, want := rf.Outcome(), OutcomeConfirmed; got != want {
		t.Errorf("the residual came out %q, want %q. It is a CONFIRMING residual now, "+
			"and pretending otherwise here would leave the honest sentence in the "+
			"control's header contradicted by its own test", got, want)
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
//
// RULING 15 PUT A FLOOR UNDER THAT INEQUALITY AND THIS TEST MEASURES WHAT THE
// FLOOR ADMITS, IN BOTH DIRECTIONS. The 400-wide h1 spelling is still refused.
// The SAME FAMILY RESPELT AT THE FLOOR — `<h1[0-9A-Za-z]{0,256}` — is
// ADMITTED, inlines 256 verbatim body bytes and confirms, and that is asserted
// below rather than left for a reader to find. The residual is not closed by
// the floor; its magnitude is now the floor.
func TestASpanMayNotCarryMoreOfTheBodyThanThePatternSpells(t *testing.T) {
	// THE MEASURED CASE, by name and with the same fixture.
	attack := `<h1[0-9A-Za-z]{0,400}`
	s := mustSignature(t, attack)
	body := []byte("<h1" + strings.Repeat("a", 600))
	span, _, overBroad, _, matched := extractSpan(body, s)
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

	// THE SAME FAMILY AT THE FLOOR, WHICH THE FLOOR ADMITS. Disclosed at
	// MaxUnspelledBytes and measured here so the disclosure cannot rot into
	// "the h1 residual was closed". An attacker who wanted the 403-byte
	// inlining and cannot have it can still have 256 of it, plus the
	// confirmation the 400-wide spelling never got.
	respelt := fmt.Sprintf(`<h1[0-9A-Za-z]{0,%d}`, MaxUnspelledBytes)
	rs := mustSignature(t, respelt)
	rspan, _, rover, rlen, rmatched := extractSpan(body, rs)
	if !rmatched {
		t.Fatalf("%q did not match the h1 fixture", respelt)
	}
	if len(rspan) != MaxUnspelledBytes+3 || rover != 0 || rlen != MaxUnspelledBytes+3 {
		t.Errorf("%q: span=%d bytes over=%d matchLen=%d, want a %d-byte inlined span. "+
			"The floor admits this and the disclosure at MaxUnspelledBytes says so; "+
			"if it no longer does, the disclosure is now wrong in the direction that "+
			"overstates the residual", respelt, len(rspan), rover, rlen,
			MaxUnspelledBytes+3)
	}
	if rf, _ := overBroadCandidate(t, respelt, body, 3); rf.Outcome() != OutcomeConfirmed {
		t.Errorf("%q came out %q; the disclosed residual is that it CONFIRMS, and a "+
			"disclosure that overstates the damage ages exactly as badly as one that "+
			"understates it", respelt, rf.Outcome())
	}

	// THE SWEEP, AND RULING 15 MOVED WHERE ITS BOUNDARY SITS. It used to
	// step the footing from 1 to 48 and assert that `extra == footing` kept
	// its span while `extra == footing+1` lost it — the bare ratio. Under
	// the floor that is the wrong boundary for every footing under
	// MaxUnspelledBytes, and asserting it is what made `AKIA[0-9A-Z]{16}`
	// yield nothing.
	//
	// THE BOUNDARY FOR A SPAN IS NOW EXACTLY MaxUnspelledBytes, WHATEVER THE
	// FOOTING, and that is a derived fact rather than a second rule. Above
	// the floor the ratio arm needs unspelled <= spelled, so the match is at
	// least 2*unspelled > 2*MaxUnspelledBytes = MaxSpanBytes bytes long and
	// property 1 has already refused it. So at EXTRACTION the ratio arm is
	// unreachable, and the floor is the whole visible boundary. The ratio
	// arm is observable at the OUTCOME, where matchLen has no ceiling:
	// ENFORCED BY matchQuotesMoreThanItSpells,
	// MEASURED BY TestTheConfirmationBoundaryIsPinnedOnBothArms.
	for footing := 1; footing <= 48; footing++ {
		lit := strings.Repeat("Z", footing)
		sig := mustSignature(t, lit+`[0-9A-Za-z]*`)
		for _, tc := range []struct {
			extra    int
			wantSpan bool
		}{
			{footing, true},
			{footing + 1, true}, // over the old ratio, under the floor
			{MaxUnspelledBytes, true},
			{MaxUnspelledBytes + 1, false},
		} {
			b := []byte(lit + strings.Repeat("a", tc.extra))
			span, _, over, _, ok := extractSpan(b, sig)
			if !ok {
				t.Fatalf("footing %d: the fixture did not match", footing)
			}
			if (span != "") != tc.wantSpan {
				t.Errorf("footing=%d match=%d bytes (%d unspelled): span=%q over=%d, "+
					"want span=%v. The rule is `unspelled <= MaxUnspelledBytes=%d or "+
					"unspelled <= spelled`, and the boundary must be exactly there",
					footing, len(b), tc.extra, printable(span, 32), over, tc.wantSpan,
					MaxUnspelledBytes)
			}
			if tc.wantSpan && len(span) != len(b) {
				t.Errorf("footing=%d: a span inside the budget was %d bytes, want the "+
					"whole %d-byte match", footing, len(span), len(b))
			}
			// THE CEILING THE FLOOR DOES NOT RAISE. Whatever this sweep
			// inlines, it never carries more than MaxUnspelledBytes of
			// body — the claim matchQuotesMoreThanItSpells proves and
			// this loop is entitled to falsify.
			if q := len(span) - footing; span != "" && q > MaxUnspelledBytes {
				t.Errorf("footing=%d inlined a span carrying %d unspelled bytes, and the "+
					"published ceiling is %d", footing, q, MaxUnspelledBytes)
			}
		}
	}

	// THE COST OF THE FLOOR, ASSERTED AT ITS WORST CASE. One byte of
	// footing buys MaxUnspelledBytes bytes of response, inlined, and a
	// confirmation on top of it. This is the residual disclosed at
	// MaxUnspelledBytes, measured rather than described, and it is here so
	// that shrinking or growing the floor cannot happen quietly.
	cheap := mustSignature(t, `Z[0-9A-Za-z]*`)
	worstBody := []byte("Z" + strings.Repeat("a", MaxUnspelledBytes))
	worstSpan, _, worstOver, _, ok := extractSpan(worstBody, cheap)
	if !ok {
		t.Fatal("the worst-case floor fixture did not match")
	}
	if len(worstSpan) != MaxUnspelledBytes+1 || worstOver != 0 {
		t.Errorf("the worst case the floor admits inlined %d bytes (over=%d); the "+
			"disclosure says the whole %d-byte match, of which %d bytes are the "+
			"target's", len(worstSpan), worstOver, MaxUnspelledBytes+1, MaxUnspelledBytes)
	}

	// THE COST THE OLD PARAGRAPH CLAIMED, INVERTED, because it was false in
	// the direction that mattered. The old sentence said the AKIA span was
	// withheld and "the finding is still CONFIRMED"; the finding was NOT
	// confirmed, and a reproduced AWS key exposure never reached
	// dast_status. Under the floor the span comes back and so does the
	// verdict. See TestEveryRealOracleConfirmsAGenuineHit for the rest of
	// the suite's oracles.
	akia := mustSignature(t, `AKIA[0-9A-Z]{16}`)
	span, _, over, matchLen, ok := extractSpan([]byte("... AKIA1234567890ABCDEF ..."), akia)
	if !ok {
		t.Fatal("the AKIA fixture did not match")
	}
	if span != "AKIA1234567890ABCDEF" {
		t.Errorf("AKIA[0-9A-Z]{16} inlined %q, want the whole 20-byte match. Sixteen "+
			"unspelled bytes are inside MaxUnspelledBytes=%d, and an AWS access key "+
			"ID is the identifier an operator revokes by", span, MaxUnspelledBytes)
	}
	if over != 0 || matchLen != 20 {
		t.Errorf("AKIA: over=%d matchLen=%d, want over=0 matchLen=20", over, matchLen)
	}
	if matchQuotesMoreThanItSpells(matchLen, akia.spelled) {
		t.Errorf("matchQuotesMoreThanItSpells(%d, %d) = true; the oracle this gate exists "+
			"to report would not confirm", matchLen, akia.spelled)
	}

	// AND THE OTHER DIRECTION, so this is a rule and not a ban on classes:
	// a signature that spells enough keeps its span.
	nginx := mustSignature(t, `Server: nginx/1\.[0-9]+\.[0-9]+`)
	span, _, _, _, ok = extractSpan([]byte("Server: nginx/1.24.0\r\n"), nginx)
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
		span, dropped, _, _, matched := extractSpan([]byte{'Z', byte(b), 'Z'}, all)
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
//
// RULING 14 ADDED THE HALF THIS TEST WAS MISSING. It asserted the span was
// withheld and then asserted the finding was CONFIRMED, which is the shape of
// the whole defect: the quote was withheld and the claim was granted. The same
// comparison that withholds the span now decides the outcome, so this test
// checks both halves of one rule. See matchQuotesMoreThanItSpells.
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
	// THE SENTENCE THAT USED TO BE HERE WAS THE DEFECT, and it is kept as a
	// quotation because deleting it would hide what ruling 14 corrected:
	// "The oracle fired. That is a separate fact from whether its match can
	// be shown, and conflating the two would silently turn every over-broad
	// match into a non-reproduction." The first half is true and is asserted
	// below — matches stays 3. The conclusion drawn from it was wrong. The
	// alternative to CONFIRMED is not "non-reproduction"; this gate has a
	// third state, and an over-broad match is exactly what it is for.
	//
	// A confirmation is the claim "the oracle fired ON THIS RESPONSE". When
	// the match runs past its own footing the thing it fired on IS the
	// response, so there is no claim left to make — and there is no
	// disproof either, which is why this is unconfirmed and not rejected.
	if got, want := f.Outcome(), OutcomeUnconfirmed; got != want {
		t.Fatalf("outcome = %q, want %q: the match was %d bytes against %d spelled, so it "+
			"quoted more of the response than the signature spells",
			got, want, len(hostile), c.Signature.spelled)
	}
	if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
		t.Errorf("reason = %q, want %q. An operator reading any other reason goes hunting "+
			"for a flaky target instead of fixing the signature", got, want)
	}
	// THE ORACLE-FIRED FACT IS NOT LOST, only the claim built on it.
	if got, want := f.SignatureMatches(), 3; got != want {
		t.Errorf("SignatureMatches() = %d, want %d: the signature DID match every attempt "+
			"and that measurement must survive the verdict", got, want)
	}
	if got, want := f.OverQuotedMatches(), 3; got != want {
		t.Errorf("OverQuotedMatches() = %d, want %d", got, want)
	}
	// AND THERE IS NO CONFIDENCE. 3/3 printed beside "the signature quoted
	// the page" is the strongest number this gate can print next to a reason
	// saying it could not see.
	if conf, known := f.Confidence(); known {
		t.Errorf("Confidence() = (%.3f, true); a reproduction ratio whose numerator counts "+
			"matches that were the response rather than evidence about it is not a "+
			"reproduction ratio", conf)
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

// ---------------------------------------------------------------------------
// RULING 13 — one language, one verdict, however it is spelled
// ---------------------------------------------------------------------------

// TestEverySpellingOfOneLanguageGetsTheSameVerdict is the test seven rounds of
// operator enumeration could not give this control, and it is the reason
// `decided` is computed from a node's DENOTED LANGUAGE instead of from its
// operator tag.
//
// THE SEQUENCE IT ENDS. Each earlier round closed one spelling of one evasion
// and left the next spelling open: a status list, an entity-name bound, a
// benign corpus, a generator's alphabet, a union that existed only at depth 0,
// a class-union that excluded literals, and an alternation check keyed on the
// AST NODE. The last of those was MEASURED, and the three lines are kept as a
// fixture below:
//
//	Z(?:[a,]?)*      REFUSED (rule R3)
//	Z(?:(?:a|,)?)*   REFUSED (rule R3)
//	Z(?:a?,?)*       ACCEPTED, spelled=1, quoted=0
//
// Three spellings of ONE LANGUAGE — all of `{a, ','}*` after a marker — two
// refused and one accepted, because `x?` denotes `(?:|x)` and a concatenation
// of optionals denotes the alternation over their powerset, so nothing in the
// third pattern's tree is an OpAlternate for an operator test to find.
//
// WHAT THIS TEST ASSERTS IS A PROPERTY AND NOT A LIST. For each alphabet it
// generates spellings MECHANICALLY — optional against alternation-with-empty,
// bounded repeat against optional, nested groups, capturing against
// non-capturing, a class against a one-branch alternation, a hex escape
// against a spelled rune — then:
//
//  1. PROVES they denote the same language, by enumerating every string
//     over the alphabet up to a length and requiring identical membership.
//     A mis-transcribed spelling fails there rather than silently weakening
//     the property below.
//  2. Requires the CONTROL to return the same verdict for every one of
//     them, and the same RULE when it refuses.
//
// Nobody has to enumerate operators for this to catch the next round: a new
// spelling of an old language is a new entry in the list of spellings, and it
// gets held to the verdict its language already has.
//
// THE NON-VACUITY HALF IS THE SECOND AND THIRD ALPHABET. A control that
// refused every repeat would pass part 2 trivially, so two of the three
// alphabets are ones R3 deliberately allows — letters only, and digits with a
// dot — and every spelling of those has to be ACCEPTED.
func TestEverySpellingOfOneLanguageGetsTheSameVerdict(t *testing.T) {
	// marker is the literal footing. Without it R1 refuses every pattern
	// here for having no literal content, and R3 — the rule under test —
	// would never be reached at all.
	const marker = "Z"

	for _, family := range []struct {
		name       string
		alphabet   []rune
		wantRefuse bool
		why        string
	}{
		{"letters and punctuation", []rune{'a', ','}, true,
			"the union crosses a letter into punctuation, so a position drawing " +
				"from it can run out of the token the pattern declared and into " +
				"the next one. This is the evasion family"},
		{"letters only", []rune{'a', 'b'}, false,
			"a letters-only alphabet cannot leave the token it declared, and this " +
				"is the disclosed word-list residual. If these start being refused, " +
				"R3 has become a ban on repeats"},
		{"digits and a dot", []rune{'0', '.'}, false,
			"digits and a dot carry no letter, so the dotted-quad and version-banner " +
				"shapes stay legal. This is the case that separates 'the union holds " +
				"the literals' from 'the union bans literals'"},
	} {
		spellings := unboundedRunSpellings(family.alphabet)
		if len(spellings) < 20 {
			t.Fatalf("%s: the generator produced %d spellings; a property over a "+
				"handful of spellings is a list with extra steps",
				family.name, len(spellings))
		}

		// PART 1: they really are one language. Membership is measured,
		// not asserted in a comment.
		ref := spellings[0]
		refRE := regexp.MustCompile(`^(?:` + ref.frag + `)$`)
		words := stringsOverAlphabetUpTo(family.alphabet, 8)
		// Strings using a rune OUTSIDE the alphabet must be excluded by
		// every spelling too, or "same language" is only being checked on
		// the inside of the language.
		words = append(words, "z", "a;b", "!", string(family.alphabet)+"\x01")
		if len(words) < 400 {
			t.Fatalf("%s: the equivalence witness is %d strings; that is too small a "+
				"sample to distinguish two spellings that differ", family.name, len(words))
		}
		for _, sp := range spellings[1:] {
			re := regexp.MustCompile(`^(?:` + sp.frag + `)$`)
			for _, w := range words {
				if got, want := re.MatchString(w), refRE.MatchString(w); got != want {
					t.Fatalf("%s: spelling %s (%q) and reference %s (%q) disagree on "+
						"%q: %v vs %v. They are not the same language, so holding "+
						"them to one verdict would be asserting something false",
						family.name, sp.name, sp.frag, ref.name, ref.frag, w, got, want)
				}
			}
		}

		// PART 2: one language, one verdict — and one rule.
		for _, sp := range spellings {
			pattern := marker + sp.frag
			spelled, err := refuseOverBroadPattern(pattern)
			switch {
			case family.wantRefuse && err == nil:
				t.Errorf("%s: spelling %s — refuseOverBroadPattern(%q) ACCEPTED it with "+
					"spelled=%d, and the same language spelled %s is refused. %s. A "+
					"verdict that depends on the spelling is a verdict about the AST "+
					"and not about what the pattern can match",
					family.name, sp.name, pattern, spelled, ref.name, family.why)
			case family.wantRefuse && !strings.Contains(err.Error(), "rule R3"):
				t.Errorf("%s: spelling %s — refuseOverBroadPattern(%q) refused it for "+
					"%q, not rule R3. Refusing one spelling by a different rule means "+
					"the rule under test is still evaded and only the sample widened",
					family.name, sp.name, pattern, err)
			case !family.wantRefuse && err != nil:
				t.Errorf("%s: spelling %s — refuseOverBroadPattern(%q) = %v. %s",
					family.name, sp.name, pattern, err, family.why)
			}
		}
	}

	// THE MEASURED FIXTURE, kept verbatim so the three lines in this test's
	// header are checked on every run rather than remembered. All three must
	// be refused, and refused THE SAME WAY: same sentinel, same rule, same
	// message once the pattern text is taken out.
	msgs := make([]string, 0, 3)
	for _, p := range []string{`Z(?:[a,]?)*`, `Z(?:(?:a|,)?)*`, `Z(?:a?,?)*`} {
		_, err := refuseOverBroadPattern(p)
		if err == nil {
			t.Fatalf("refuseOverBroadPattern(%q) ACCEPTED it. This is ruling 13's "+
				"measured case: `x?` is an alternation with the empty string and a "+
				"concat of optionals is the alternation over their powerset, so an "+
				"operator test finds no OpAlternate here and promotes nothing", p)
		}
		if !errors.Is(err, ErrSignatureMatchesEverything) {
			t.Errorf("refuseOverBroadPattern(%q) refused with %v, which is not "+
				"ErrSignatureMatchesEverything; a caller matching on the sentinel "+
				"would not see this refusal", p, err)
		}
		msgs = append(msgs, strings.Replace(err.Error(), fmt.Sprintf("%q", p), "<pattern>", 1))
	}
	for i, m := range msgs[1:] {
		if m != msgs[0] {
			t.Errorf("the three spellings are refused with DIFFERENT messages:\n  %q\n  %q\n"+
				"They are one language and one defect, and reporting them differently "+
				"tells an operator to go on hunting for the spelling that works",
				msgs[0], msgs[i+1])
		}
	}

	// THE ALPHABET-SCALED FORM, which is what the accepted spelling was
	// worth. It is the concat-of-optionals spelling over the WHOLE printable
	// alphabet: 225 bytes, and before ruling 13 it compiled with spelled=16
	// and quoted=0 and then matched every byte of a marker followed by an
	// ordinary HTML page.
	scaled := "anvil-probe-4f2a(?:"
	for r := rune(printableASCIILo); r <= printableASCIIHi; r++ {
		scaled += regexp.QuoteMeta(string(r)) + "?"
	}
	scaled += ")*"
	if len(scaled) != 225 {
		t.Errorf("the scaled fixture is %d bytes and this test says 225; move the number "+
			"in the same diff that moves the fixture", len(scaled))
	}
	if _, err := refuseOverBroadPattern(scaled); err == nil {
		t.Errorf("refuseOverBroadPattern accepted the whole printable alphabet spelled as "+
			"a run of optionals: %q", scaled)
	}
	// The measurement the refusal is worth, kept live: compiled with regexp
	// DIRECTLY, because NewSignature refuses it now and that is the point.
	const ordinaryHTML = `<!doctype html><html><head><title>Acme Store</title></head>` +
		`<body><h1>anvil-probe-4f2a</h1><p>Welcome to the store, friend. Everything ` +
		`is fine here; nothing is wrong.</p><ul><li>one</li><li>two</li><li>three</li>` +
		`</ul><footer>copyright 2026 acme, inc. all rights reserved. contact: ` +
		`sales@acme.example</footer></body></html>`
	body := "anvil-probe-4f2a" + ordinaryHTML
	if len(body) != 337 {
		t.Fatalf("the scaled fixture's body is %d bytes and the measurement below assumes "+
			"337", len(body))
	}
	m := regexp.MustCompile(scaled).FindStringIndex(body)
	if m == nil || m[1]-m[0] != len(body) {
		t.Errorf("the scaled evasion matches %v of the %d bytes of a marker plus an "+
			"ordinary document; this file says all of them, and if it has drifted the "+
			"refusal above is unmotivated", m, len(body))
	}
}

// spelling is one way of writing a language, with a name a failure can print.
type spelling struct {
	name string
	frag string
}

// unboundedRunSpellings writes "any string over this alphabet, unbounded" every
// way this package can think of.
//
// IT IS MECHANICAL ON PURPOSE. A hand-written list of patterns is the thing
// seven rounds of this defect kept escaping; a generator parameterised by the
// alphabet turns "which operators did somebody remember" into "which rewrites
// of one language exist", and the rewrites below are the ones regexp/syntax
// gives an author for free: optionality, alternation with an empty branch,
// bounded repeats, grouping, capture, class membership, and hex escaping.
//
// EVERY ENTRY IS CHECKED TO DENOTE THE SAME LANGUAGE by its only caller before
// any verdict is compared, so a wrong entry here is a loud failure and not a
// quietly weaker property.
//
// THE SHAPE COVERAGE IS PART OF THE MECHANISM, not a detail of the list. The
// first seventeen entries all put the language under ONE OUTER REPEAT, so the
// verdict compared was always read off a repeat node and a defect in the
// concatenation arm was invisible to all of them at once — one shape wearing
// seventeen spellings. The last six are rooted on a CONCATENATION. Any future
// entry should ask which node the verdict is read off, not only which
// operators appear.
func unboundedRunSpellings(alphabet []rune) []spelling {
	atoms := make([]string, len(alphabet)) // outside a class
	hexes := make([]string, len(alphabet)) // inside or outside, escape-free
	for i, r := range alphabet {
		atoms[i] = regexp.QuoteMeta(string(r))
		hexes[i] = fmt.Sprintf(`\x%02x`, r)
	}
	class := "[" + strings.Join(hexes, "") + "]"
	alt := strings.Join(atoms, "|")
	captured := "(" + strings.Join(atoms, ")|(") + ")"

	concatOf := func(suffix string) string {
		var b strings.Builder
		for _, a := range atoms {
			b.WriteString(a)
			b.WriteString(suffix)
		}
		return b.String()
	}
	reversedConcatOf := func(suffix string) string {
		var b strings.Builder
		for i := len(atoms) - 1; i >= 0; i-- {
			b.WriteString(atoms[i])
			b.WriteString(suffix)
		}
		return b.String()
	}

	return []spelling{
		{"a class under a star", class + "*"},
		{"the class inside a non-capturing group", "(?:" + class + ")*"},
		{"the class inside two nested groups", "(?:(?:" + class + "))*"},
		{"an alternation of literals", "(?:" + alt + ")*"},
		{"the same alternation CAPTURED", "(?:" + captured + ")*"},
		{"an alternation with an explicit EMPTY branch", "(?:" + alt + "|)*"},
		{"an OPTIONAL class inside a star", "(?:" + class + "?)*"},
		{"an optional ALTERNATION inside a star", "(?:(?:" + alt + ")?)*"},
		{"a CONCAT OF OPTIONALS — no alternation node anywhere", "(?:" + concatOf("?") + ")*"},
		{"the same concat of optionals REVERSED", "(?:" + reversedConcatOf("?") + ")*"},
		{"a concat of optionals written as BOUNDED REPEATS", "(?:" + concatOf("{0,1}") + ")*"},
		{"a concat of STARS", "(?:" + concatOf("*") + ")*"},
		{"the class under a bounded repeat inside a star", "(?:" + class + "{0,2})*"},
		{"the class under a {0,1} inside a star", "(?:" + class + "{0,1})*"},
		{"a class and an optional class", "(?:" + class + class + "?)*"},
		{"a PLUS made optional", "(?:" + class + "+)?"},
		{"the class spelled with HEX ESCAPES outside a class",
			"(?:" + strings.Join(hexes, "|") + ")*"},

		// NOT REPEAT-ROOTED. Every spelling above puts the whole language
		// under one outer repeat, so the property they proved was closed
		// over ONE SHAPE rather than over the grammar: a defect living in
		// shapeWalk's OpConcat arm could not be seen by any of them,
		// because no verdict here was ever read off a concatenation node.
		// That was measured — see
		// TestTheStaticLayerMaySplitAndTheGuaranteeStillHolds, where a
		// concatenation of unbounded runs is accepted and the repeat
		// spelling of the SAME language is refused.
		//
		// These six put the root of the tree on an OpConcat. The language
		// is unchanged — `L* L*` is `L*` — and part 1 of the caller
		// proves that rather than trusting this sentence.
		{"a BARE CONCATENATION of two unbounded runs, no outer repeat", class + "*" + class + "*"},
		{"three unbounded runs concatenated", class + "*" + class + "*" + class + "*"},
		{"a run concatenated with an optional PLUS", class + "*(?:" + class + "+)?"},
		{"an alternation run concatenated with a class run", "(?:" + alt + ")*" + class + "*"},
		{"two CAPTURED runs concatenated", "(" + class + "*)(" + class + "*)"},
		{"an optional plus concatenated with an alternation run",
			"(?:" + class + "+)?(?:" + alt + ")*"},
	}
}

// stringsOverAlphabetUpTo enumerates every string over an alphabet up to a
// length, shortest first. It is the equivalence witness: two spellings that
// denote different languages differ on one of these.
func stringsOverAlphabetUpTo(alphabet []rune, maxLen int) []string {
	out := []string{""}
	frontier := []string{""}
	for n := 1; n <= maxLen; n++ {
		next := make([]string, 0, len(frontier)*len(alphabet))
		for _, w := range frontier {
			for _, r := range alphabet {
				next = append(next, w+string(r))
			}
		}
		out = append(out, next...)
		frontier = next
	}
	return out
}

// TestAOneRuneClassNeverReachesTheWalk deletes a claim rather than qualifying
// it.
//
// classShape used to carry an arm reading a one-rune class as a spelled
// literal, justified by "reading it as anything else would let `[<][h][1]`
// evade R1" — and that arm was UNREACHABLE from NewSignature, so the
// justification could not be demonstrated. regexp/syntax's parser rewrites a
// one-rune OpCharClass into an OpLiteral before any of this package sees it,
// which is why `[<][h][1]` arrives as the literal `<h1` with three bytes of
// footing and R1 was never in danger.
//
// THIS TEST IS WHAT MAKES THE DELETION SAFE. It runs the parser over every
// spelling that could plausibly produce a one-rune class — brackets round a
// letter, round punctuation, round a hex escape, a one-rune RANGE, a
// case-folded class, a negated class that leaves one rune — and asserts none
// of them does. If a future Go release stops folding them, this goes red and
// the general arm of classShape takes over: declared=1, decided=false,
// minLiteral=0, which fails toward refusal rather than away from it.
func TestAOneRuneClassNeverReachesTheWalk(t *testing.T) {
	var find func(re *syntax.Regexp, hits *[]string)
	find = func(re *syntax.Regexp, hits *[]string) {
		if re == nil {
			return
		}
		if re.Op == syntax.OpCharClass && len(re.Rune) == 2 && re.Rune[0] == re.Rune[1] {
			*hits = append(*hits, re.String())
		}
		for _, sub := range re.Sub {
			find(sub, hits)
		}
	}

	for _, p := range []string{
		`[a]`, `[ ]`, `[,]`, `[.]`, `[$]`, `[\]]`, `[\-]`, `[<][h][1]`,
		`[a-a]`, `[0-0]`, `[\x61]`, `[\x{212A}]`, `[\x7f]`,
		`(?i)[a]`, `(?i)[ ]`, `(?i)[a-a]`,
		`[^\x00-\x{10FFFE}]`, `x[ ]y`, `(?:[ ])`, `([ ])`, `[ ]*`, `[ ]{2}`,
		`[ab]`, `[a-z]`, `[[:punct:]]`,
	} {
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Errorf("syntax.Parse(%q) = %v; the probe cannot say anything about a "+
				"pattern it could not parse", p, err)
			continue
		}
		var hits []string
		find(re, &hits)
		if len(hits) != 0 {
			t.Errorf("syntax.Parse(%q) produced one-rune char class(es) %v. The arm that "+
				"read those as spelled literals has been DELETED, so this pattern now "+
				"reaches classShape's general arm and is judged as an undecided "+
				"position with zero literal footing. Either restore the arm with this "+
				"spelling as its witness, or accept the refusal", p, hits)
		}
	}

	// THE POSITIVE CONTROL ON THE PROBE. A walker that could not see a
	// one-rune class would pass the loop above for the wrong reason.
	synthetic := &syntax.Regexp{Op: syntax.OpCharClass, Rune: []rune{' ', ' '}}
	var hits []string
	find(synthetic, &hits)
	if len(hits) != 1 {
		t.Fatalf("the probe found %d one-rune class(es) in a regexp that IS one; every "+
			"assertion above is vacuous", len(hits))
	}

	// AND THE FAIL-CLOSED DIRECTION, asserted rather than described: if the
	// parser ever does hand one over, the general arm counts it as an
	// undecided position that spells nothing.
	s := classShape(synthetic.Rune)
	if s.minLiteral != 0 || s.declared != 1 || s.decided {
		t.Errorf("classShape([' ',' ']) = %+v; without the deleted arm a one-rune class "+
			"must fail CLOSED — no literal footing, one declared position, undecided — "+
			"so that an unreachable case becoming reachable costs a refusal and never "+
			"a confirmation", s)
	}
}

// TestCaseFoldingCannotMoveAPositionAcrossTheContentBoundary is the claim
// shapeWalk's OpLiteral arm rests on, checked by RUNNING the fold rather than
// by reading a Unicode table.
//
// A literal position is DECIDED under ruling 13 even under (?i), on the
// argument that a fold orbit is a set of spellings of one character the pattern
// itself wrote down — and that argument is only sound while folding cannot
// carry a position across the letter / non-letter partition contentBearingClass
// is built on. If `(?i)a` could fold to a semicolon, a case-insensitive literal
// would be a way to declare punctuation while spelling a letter, and the whole
// of R3 would go with it.
//
// So: for every printable-ASCII rune, the alphabet spelledRunes derives for it
// UNDER FOLD must not be content-bearing.
func TestCaseFoldingCannotMoveAPositionAcrossTheContentBoundary(t *testing.T) {
	widened := 0
	for r := rune(printableASCIILo); r <= printableASCIIHi; r++ {
		folded := spelledRunes([]rune{r}, true)
		if contentBearingClass(folded) {
			t.Errorf("the fold orbit of %q is %v, which IS content-bearing. A literal "+
				"position is treated as decided under (?i) precisely because folding "+
				"cannot cross the letter / non-letter partition; it can, so "+
				"shapeWalk's OpLiteral arm is now unsound and a folded literal is a "+
				"way to declare an alphabet while spelling a rune", r, folded)
		}
		if alphabetIsAmbiguous(folded) {
			widened++
		}
	}
	// NON-VACUITY: if folding widened nothing, the loop above asserted
	// nothing about folding at all.
	if widened != 52 {
		t.Errorf("case folding widened %d of the printable-ASCII runes' alphabets, want 52 "+
			"(the letters). If it widened none, this test is checking that a no-op is "+
			"harmless", widened)
	}
}

// TestARepeatedUnitOfVaryingWidthIsAnUndecidedPositionAtTheSeam is the half of
// ruling 13 that lives in the ORDER of the walk rather than in what it computes.
//
// A unit made of a fixed literal and a TRAILING optional is decided on its own:
// `a,?` puts 'a' at position 0 and ',' at position 1 and nothing anywhere twice.
// Repeat it and that stops being true — `(?:a,?)*` matches "aa" and "a,", so
// the seam between traversals is a position holding 'a' on one reading and ','
// on another, and the unit's alphabet really is that position's alphabet.
//
// MEASURED, with the width test present but applied to the REPEAT's own shape
// instead of to the unit's before its quotation was read:
//
//	Z(?:a,?)*   ACCEPTED, spelled=1, quoted=0
//
// The promotion landed on the star node, and by then `quoted` had already been
// read off the un-promoted unit; the star's parent is a concatenation, and a
// concatenation does not take quotation over a union, so the number nobody read
// was the number that mattered. See repeatedUnit.
//
// THE NON-VACUITY HALF IS THE SECOND TABLE. Repetition does not make everything
// undecided: a fixed-width unit has no seam, an alphabet with no letter cannot
// leave its token however the seam lands, and a repeat that runs at most once is
// not a repetition at all.
func TestARepeatedUnitOfVaryingWidthIsAnUndecidedPositionAtTheSeam(t *testing.T) {
	for _, tc := range []struct{ pattern, why string }{
		{`Z(?:a,?)*`,
			"THE MEASURED ONE: a fixed literal and a trailing optional, decided as a " +
				"unit and undecided at the seam"},
		{`Z(?:,a?)*`, "the same unit with the two runes swapped"},
		{`Z(?:a;?)*`, "the same shape over a different punctuation mark"},
		{`Z(?:a,?)+`, "a plus rather than a star; one traversal is guaranteed and the " +
			"seam is still there"},
		{`Z(?:a,?){0,400}`, "the same unit under a CEILING: 400 seams against one " +
			"spelled byte"},
		{`Z(?:err, ?)*`, "a longer fixed prefix; the seam does not care how much of " +
			"the unit is spelled"},
	} {
		_, err := refuseOverBroadPattern(tc.pattern)
		if err == nil {
			t.Errorf("refuseOverBroadPattern(%q) ACCEPTED it. %s. The unit's shape has to "+
				"be corrected for the seam BEFORE its quotation is read, or the "+
				"promotion lands on a node whose parent never looks at it",
				tc.pattern, tc.why)
			continue
		}
		if !strings.Contains(err.Error(), "rule R3") {
			t.Errorf("refuseOverBroadPattern(%q) refused it for %q, not R3. %s",
				tc.pattern, err, tc.why)
		}
	}

	for _, tc := range []struct{ pattern, why string }{
		{`Z(?:abc)*`, "a FIXED-WIDTH unit has no seam to be ambiguous at, and every " +
			"byte it matches is spelled"},
		{`Z(?:abc, )*`, "the same, over an alphabet that DOES cross letters into " +
			"punctuation. Width is what decides here, not the alphabet"},
		{`Z(?:ab?)*`, "a varying-width unit over LETTERS ONLY: the seam is undecided " +
			"and its alphabet still cannot leave the token it declared"},
		{`Z(?:0\.?)*`, "a varying-width unit over a digit and a dot, which is the " +
			"dotted-quad shape and carries no letter"},
		{`Z(?:[0-9]\.?)*`, "the same with the digit as a class"},
		{`Z(?:a,?){0,1}`, "a repeat that runs its unit AT MOST ONCE. Nothing is laid " +
			"end to end with anything, so there is no seam and the unit's own " +
			"verdict has to carry — a rule that refused this would be refusing " +
			"optionality rather than repetition"},
		{`(?:[0-9]{1,3}\.){3}[0-9]{1,3} ZZZZ`,
			"the dotted quad, whose unit is a varying-width digit class and a spelled " +
				"dot. It is the control that separates 'the seam is undecided' from " +
				"'the seam is quotation'"},
	} {
		if _, err := refuseOverBroadPattern(tc.pattern); err != nil {
			t.Errorf("refuseOverBroadPattern(%q) = %v. %s. A seam rule that refused this "+
				"would be a ban on repeats wearing ruling 13's clothes",
				tc.pattern, err, tc.why)
		}
	}
}

// TestAnUndecidedPositionIsCountedWithoutARepetitionToCarryIt is what makes
// `decided` a statement about the LANGUAGE rather than a flag that happens to
// be read in one place.
//
// After the seam correction landed, every refusal in this file could be
// credited to repeatedUnit: a repeat is where quotation is taken over a union,
// so a promotion at any other node had no reader. That is a fine reason for a
// rule to be right and a terrible reason to believe it — the next round's
// spelling will be the one that reaches `declared` by a path repeatedUnit is
// not on. So this test reaches it by one: a bounded repeat that runs its unit
// AT MOST ONCE is not a repetition, repeatedUnit deliberately leaves it alone,
// and quotationOverUnion still reads the unit's `declared`. Two of them
// concatenated against one byte of footing is R3's inequality with no
// repetition anywhere in the pattern.
//
//	Z(?:a?,?){0,1}(?:a?,?){0,1}         the concatenation-of-optionals rule
//	Z(?:(a)|(,)){0,1}(?:(a)|(,)){0,1}   the alternation rule
//
// Each of the two lines in shapeWalk that marks its node undecided is the only
// thing standing between one of those and acceptance, MEASURED by deleting it:
// with the concatenation's width test removed the first compiles with
// spelled=1, and with the alternation's the second does.
func TestAnUndecidedPositionIsCountedWithoutARepetitionToCarryIt(t *testing.T) {
	for _, tc := range []struct{ pattern, why string }{
		{`Z(?:a?,?){0,1}(?:a?,?){0,1}`,
			"a CONCATENATION OF OPTIONALS, twice, with no repetition to carry it. " +
				"The concatenation is undecided because a variable-width element " +
				"slides everything after it into the position it did not fill"},
		{`Z(?:(a)|(,)){0,1}(?:(a)|(,)){0,1}`,
			"an ALTERNATION, twice, with no repetition to carry it. A match can leave " +
				"by any branch, so no branch's structure decides the node's positions"},
	} {
		_, err := refuseOverBroadPattern(tc.pattern)
		if err == nil {
			t.Errorf("refuseOverBroadPattern(%q) ACCEPTED it. %s. Two undecided positions "+
				"over an alphabet that crosses letters into punctuation, against one "+
				"byte of literal footing, is exactly the inequality R3 states",
				tc.pattern, tc.why)
			continue
		}
		if !strings.Contains(err.Error(), "rule R3") {
			t.Errorf("refuseOverBroadPattern(%q) refused it for %q, not R3. %s",
				tc.pattern, err, tc.why)
		}
	}

	// NON-VACUITY, three ways: the same shape with the footing R3 asks for,
	// the same shape over an alphabet R3 allows, and a unit that is decided.
	// A rule that refused these would be counting positions instead of
	// counting undecided ones.
	for _, tc := range []struct{ pattern, why string }{
		{`ZZ(?:a?,?){0,1}(?:a?,?){0,1}`,
			"two undecided positions against TWO spelled bytes: R3 satisfied 1:1, " +
				"which is the remedy its own message tells an author to reach for"},
		{`Z(?:a?b?){0,1}(?:a?b?){0,1}`,
			"the same structure over a letters-only union, which cannot leave the " +
				"token it declared"},
		{`Z(?:ab){0,1}(?:ab){0,1}`,
			"a DECIDED unit: fixed width, every byte spelled, nothing undecided to " +
				"count"},
	} {
		if _, err := refuseOverBroadPattern(tc.pattern); err != nil {
			t.Errorf("refuseOverBroadPattern(%q) = %v. %s", tc.pattern, err, tc.why)
		}
	}
}

// ===========================================================================
// RULING 14 — the guarantee moves onto the match
// ===========================================================================

// overBroadCandidate builds and confirms a candidate whose signature and body
// the caller supplies, wired for the ordinary CONFIRMING path in every other
// respect: an oracle-bearing class, a mechanical detection method, and a
// target that answers 200 on every attempt.
//
// Everything about it is arranged to confirm. That is what makes the
// assertions below worth making: the only thing standing between these
// fixtures and outcome=confirmed at confidence 1.000 is the match check.
func overBroadCandidate(t *testing.T, pattern string, body []byte, attempts int) (*Finding, RawFinding) {
	t.Helper()
	sig, err := NewSignature(pattern)
	if err != nil {
		t.Fatalf("NewSignature(%q) refused it: %v. This fixture needs an ACCEPTED "+
			"signature; a refused one tests the early layer instead", pattern, err)
	}
	c := sqliCandidate(t, "/search")
	c.Signature = sig
	g := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return body }},
		Attempts: attempts,
	})
	f, err := g.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	return f, c
}

// scaledConcatPattern is the 891-byte attack: a marker followed by 125
// concatenated copies of an unbounded lowercase run. Every element is
// letters-only after a spelled space, so no element is content-bearing on its
// own and shapeWalk's OpConcat arm adds 125 zeroes.
func scaledConcatPattern() string {
	return "anvil-probe-4f2a" + strings.Repeat(" [a-z]*", 125)
}

// scaledConcatBody is the body it swallows: the marker, then 125 repetitions
// of a space followed by 100,000 lowercase letters. 16 + 125*100001 =
// 12,500,141.
func scaledConcatBody() []byte {
	return []byte("anvil-probe-4f2a" +
		strings.Repeat(" "+strings.Repeat("a", 100000), 125))
}

// TestAConcatenationOfUnboundedRunsIsNotBoundedByMaxPatternBytes is the MEDIUM
// the OpConcat arm's justification carried, measured in both directions.
//
// The sentence that used to sit on that arm read: "What a concatenation of
// narrow-but-differing classes can do is bounded by how many of them the
// pattern spells out, and MaxPatternBytes bounds that." MaxPatternBytes bounds
// the number of ELEMENTS. It bounds nothing about the bytes an element
// consumes, and an element may be an unbounded repeat.
//
// BOTH HALVES ARE ASSERTED, because asserting only the false one would leave a
// reader unable to tell which part of the old sentence was right. Fixed-width
// elements really are bounded, and the disclosed 255 is that measurement
// rather than a bound on the family.
func TestAConcatenationOfUnboundedRunsIsNotBoundedByMaxPatternBytes(t *testing.T) {
	// THE FIXED-WIDTH HALF, where the old bound holds.
	fixed := "Z" + strings.Repeat("[ab][,;]", 127)
	if len(fixed) != 1017 {
		t.Fatalf("the fixed-width fixture is %d bytes and this test says 1017", len(fixed))
	}
	if _, err := refuseOverBroadPattern(fixed); err != nil {
		t.Fatalf("refuseOverBroadPattern(fixed-width, 1017 bytes) = %v; the disclosure "+
			"says it is ACCEPTED and the measurement below depends on that", err)
	}
	fixedBody := "Z" + strings.Repeat("a,", 200)
	loc := regexp.MustCompile(fixed).FindStringIndex(fixedBody)
	if loc == nil || loc[1]-loc[0] != 255 {
		t.Errorf("the fixed-width pattern matched %v of %d bytes; the disclosure says "+
			"EXACTLY 255, and a drifted number makes the contrast below unreadable",
			loc, len(fixedBody))
	}
	// 128 copies is 1025 bytes. The refusal is MaxPatternBytes' and belongs
	// to NewSignature, so it is asserted there rather than on the structural
	// walk, which never looks at a pattern's length.
	if _, err := NewSignature("Z" + strings.Repeat("[ab][,;]", 128)); err == nil {
		t.Error("128 copies is 1025 bytes and must not compile at all; if it does, " +
			"MaxPatternBytes is not where this test thinks it is")
	}

	// THE UNBOUNDED HALF, where it does not. This is ruling 14's scaled
	// acceptance case, measured on the pattern rather than through the gate.
	scaled := scaledConcatPattern()
	if len(scaled) != 891 {
		t.Fatalf("the scaled fixture is %d bytes and this test says 891", len(scaled))
	}
	spelled, err := refuseOverBroadPattern(scaled)
	if err != nil {
		t.Fatalf("refuseOverBroadPattern(scaled) = %v. THIS TEST EXPECTS IT TO BE "+
			"ACCEPTED: ruling 14 forbids tuning R1/R2/R3 to close this, and if the "+
			"static layer has been tuned anyway, the match-layer assertions in "+
			"TestAnOverBroadMatchDoesNotConfirmHoweverItIsSpelled stop being "+
			"exercised by this shape", err)
	}
	if spelled != 141 {
		t.Errorf("spelled = %d, want 141", spelled)
	}
	body := scaledConcatBody()
	if len(body) != 12500141 {
		t.Fatalf("the scaled body is %d bytes and this test says 12,500,141", len(body))
	}
	loc = regexp.MustCompile(scaled).FindIndex(body)
	if loc == nil || loc[1]-loc[0] != len(body) {
		t.Fatalf("the scaled pattern matched %v of %d bytes; it is supposed to swallow "+
			"the lot, and if it no longer does this fixture is not the attack",
			loc, len(body))
	}
	// 891 pattern bytes bought 12,500,141 matched bytes. The old sentence
	// says that cannot happen.
	if len(body) <= len(scaled)*1000 {
		t.Errorf("the match is %d bytes against a %d-byte pattern, which is inside "+
			"MaxPatternBytes*1000; the fixture no longer demonstrates that bounding "+
			"the element count bounds nothing", len(body), len(scaled))
	}
}

// TestAnOverBroadMatchDoesNotConfirmHoweverItIsSpelled is ruling 14's SCALED
// acceptance case, driven end to end through the gate.
//
// MEASURED ON THE TREE AS IT WAS: this pattern is ACCEPTED at spelled=141, it
// matched 12,500,141 bytes of an ordinary page, extractSpan inlined NOTHING
// and reported all 12,500,141 as SpanOverBroadBytes — and the finding came out
//
//	outcome=confirmed reason=reproduced_on_every_attempt confidence=1.000
//
// The quote was withheld and the claim was granted. That is the defect, and it
// is the worse half of the two: the span was never the assertion, the outcome
// is.
func TestAnOverBroadMatchDoesNotConfirmHoweverItIsSpelled(t *testing.T) {
	body := scaledConcatBody()
	f, c := overBroadCandidate(t, scaledConcatPattern(), body, 3)

	if got, want := f.Outcome(), OutcomeUnconfirmed; got != want {
		t.Fatalf("outcome = %q, want %q", got, want)
	}

	// THE OUTCOME VALUE IS RULING 14'S THIRD PARAGRAPH, asserted rather than
	// commented. REJECTED would be wrong for a reason that costs something:
	// Ledger.AssertNotSilentlyClean deliberately does NOT count rejections,
	// because a ledger of nothing but rejections is an earned clean. Filing
	// "the signature cannot see" as "the target is fine" is the silent clean
	// arriving through a new door.
	if f.Outcome() == OutcomeRejected {
		t.Error("outcome = rejected. An over-broad match says nothing about whether the " +
			"target is vulnerable, and rejections do not reach AssertNotSilentlyClean")
	}
	if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
		t.Errorf("reason = %q, want %q; the reason must say what actually happened, "+
			"which is that the match ran past its own footing", got, want)
	}

	// THE ARITHMETIC IS STILL REPORTED. Suppressing the measurement along
	// with the claim would make an over-broad signature indistinguishable
	// from a non-reproduction.
	if got, want := f.SignatureMatches(), 3; got != want {
		t.Errorf("SignatureMatches() = %d, want %d", got, want)
	}
	if got, want := f.OverQuotedMatches(), 3; got != want {
		t.Errorf("OverQuotedMatches() = %d, want %d", got, want)
	}
	if got, want := f.Evidence().SpanOverBroadBytes(), len(body); got != want {
		t.Errorf("SpanOverBroadBytes() = %d, want %d", got, want)
	}

	// AND THERE IS NO CONFIDENCE. 1.000 beside "the signature quoted the
	// page" is the contradiction this gate already refuses for a model
	// inference, reached by a different cause.
	if conf, known := f.Confidence(); known {
		t.Errorf("Confidence() = (%.3f, true); matches/attempts is a REPRODUCTION ratio "+
			"and none of these matches reproduced anything", conf)
	}
	if got := f.Evidence().ExtractedSpan(); got != "" {
		t.Errorf("span = %q (%d bytes)", printable(got, 64), len(got))
	}

	// THE INVARIANT IS ARITHMETIC AND THE FIXTURE MEETS IT. Stated on the
	// numbers so a reader can check the verdict without running anything.
	if !matchQuotesMoreThanItSpells(len(body), c.Signature.spelled) {
		t.Fatalf("matchQuotesMoreThanItSpells(%d, %d) = false; the fixture no longer "+
			"exercises the rule it is named for", len(body), c.Signature.spelled)
	}

	// NOT SILENTLY CLEAN. A finding that vanishes into an outcome nobody
	// counts is the same failure in a new place, so this is asserted through
	// the ledger a caller actually reads.
	g := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return body }},
		Attempts: 3,
	})
	l, err := g.ConfirmAll(context.Background(), []RawFinding{c})
	if err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	if got, want := l.UnconfirmedCount(), 1; got != want {
		t.Errorf("UnconfirmedCount() = %d, want %d", got, want)
	}
	if l.FindingCountForStatus() != 0 {
		t.Errorf("FindingCountForStatus() = %d; an over-broad match must not drive "+
			"dast_status: findings", l.FindingCountForStatus())
	}
	if err := l.AssertNotSilentlyClean(); err == nil {
		t.Error("AssertNotSilentlyClean() = nil over a ledger holding one over-broad " +
			"candidate. Zero confirmed findings would then route to completed_clean, " +
			"and the operator would be told Anvil looked and found nothing")
	} else if !errors.Is(err, ErrSilentlyClean) {
		t.Errorf("AssertNotSilentlyClean() = %v, which is not ErrSilentlyClean", err)
	}
}

// TestTheStaticLayerMaySplitAndTheGuaranteeStillHolds is ruling 14's MINIMAL
// acceptance case, and it states the new division of labour as a measurement
// instead of as a paragraph.
//
// TWO SPELLINGS OF ONE LANGUAGE. `X [a-z]*` and `X(?: [a-z]*){1}` denote
// exactly the same set of strings — a repeat with min=max=1 runs its unit
// once. The early layer treats them differently and STILL DOES after ruling
// 14:
//
//	X [a-z]*          ACCEPTED, spelled=2, quoted=0
//	X(?: [a-z]*){1}   REFUSED (rule R3)
//
// THAT SPLIT IS REPORTED HERE RATHER THAN FIXED, and reporting it is the
// point. Closing it would mean another arm in shapeWalk, which is the tenth
// round of a game whose ninth round is in this file's history. R1/R2/R3 are a
// best-effort early refusal now, and an incomplete refusal is allowed to
// split.
//
// WHERE THE TWO MUST AGREE IS ON THE GUARANTEE, and they do. The refused
// spelling never compiles, so it can confirm nothing. The accepted spelling
// compiles, matches an ordinary page whole — and does not confirm, because the
// check that decides reads the match. One language, one guarantee, arrived at
// through two different layers.
//
// IF THIS TEST EVER FAILS AT ITS FIRST ACCEPTANCE, the early layer has been
// tuned and the acceptance case it was measured on is gone. That is not a win:
// read ruling 14's "WHAT YOU MUST NOT DO" before deciding it is.
func TestTheStaticLayerMaySplitAndTheGuaranteeStillHolds(t *testing.T) {
	const concatSpelling = `X [a-z]*`
	const repeatSpelling = `X(?: [a-z]*){1}`

	// PART 1: they are one language. Measured over every string up to a
	// length rather than asserted, the same way ruling 13's property does
	// it, so a mis-transcribed fixture fails loudly here.
	a := regexp.MustCompile(`^(?:` + concatSpelling + `)$`)
	b := regexp.MustCompile(`^(?:` + repeatSpelling + `)$`)
	words := stringsOverAlphabetUpTo([]rune{'X', ' ', 'a', 'z'}, 5)
	words = append(words, "X abc", "X ", "X", "Xa", "X A", "X a;b")
	if len(words) < 1000 {
		t.Fatalf("the equivalence witness is %d strings, which is too small a sample to "+
			"distinguish two spellings that differ", len(words))
	}
	for _, w := range words {
		if got, want := a.MatchString(w), b.MatchString(w); got != want {
			t.Fatalf("the two spellings disagree on %q: %v vs %v. They are not one "+
				"language, so this test would be asserting something false", w, got, want)
		}
	}

	// PART 2: the early layer splits, and the split is measured rather than
	// remembered.
	spelled, err := refuseOverBroadPattern(concatSpelling)
	if err != nil {
		t.Fatalf("refuseOverBroadPattern(%q) = %v. THIS TEST EXPECTS AN ACCEPTANCE: it "+
			"is the case the match layer is here to catch, and closing it in the "+
			"static layer is what ruling 14 forbids", concatSpelling, err)
	}
	if spelled != 2 {
		t.Errorf("spelled = %d, want 2", spelled)
	}
	if _, err := refuseOverBroadPattern(repeatSpelling); err == nil {
		t.Errorf("refuseOverBroadPattern(%q) ACCEPTED it; the disclosed split says it is "+
			"refused, and a disclosure that has stopped being true is worse than no "+
			"disclosure", repeatSpelling)
	} else if !strings.Contains(err.Error(), "rule R3") {
		t.Errorf("refuseOverBroadPattern(%q) refused it for %q, not rule R3; the split "+
			"this test discloses is an R3 split", repeatSpelling, err)
	}

	// PART 3: THE GUARANTEE, where the two spellings agree. An ordinary
	// response carrying one long lowercase token — a session id, a slug, a
	// base32 blob — hands this two-byte signature a 302-byte match.
	page := "prefix X " + strings.Repeat("abcdefghij", 30) + " and the rest of the page"
	loc := regexp.MustCompile(concatSpelling).FindStringIndex(page)
	if loc == nil || loc[1]-loc[0] != 302 {
		t.Fatalf("the accepted spelling matched %v of the page; this test says 302 bytes, "+
			"and a short match would make the assertions below vacuous", loc)
	}
	f, c := overBroadCandidate(t, concatSpelling, []byte(page), 3)
	if got, want := f.Outcome(), OutcomeUnconfirmed; got != want {
		t.Errorf("outcome = %q, want %q: the match ran to %d bytes against %d spelled",
			got, want, loc[1]-loc[0], c.Signature.spelled)
	}
	if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if conf, known := f.Confidence(); known {
		t.Errorf("Confidence() = (%.3f, true)", conf)
	}

	// NON-VACUITY. The same two-byte-footing signature against a body whose
	// match STAYS INSIDE its footing confirms normally, so part 3 is not
	// measuring a gate that refuses everything.
	narrow, _ := overBroadCandidate(t, concatSpelling, []byte("...X ab..."), 3)
	if got, want := narrow.Outcome(), OutcomeConfirmed; got != want {
		t.Errorf("a match of `X ab` — 4 bytes against 2 spelled — came out %q, want %q. "+
			"The rule is L-s <= s, not a ban on matching", got, want)
	}
	if got, want := narrow.Evidence().ExtractedSpan(), "X ab"; got != want {
		t.Errorf("span = %q, want %q", got, want)
	}
}

// TestAnOverBroadMatchOnOneAttemptTakesTheWholeCandidate is the interaction
// ruling 14 asked to be decided, documented and tested: the gate runs several
// attempts, and one of them can be over-broad while another is clean.
//
// THE DECISION IS FAIL-CLOSED: ANY over-broad match on ANY attempt takes the
// candidate, however clean the others were.
//
// WHY, and the reasoning is worth more than the rule. A confirmation is the
// claim that the oracle fired on EVERY attempt. An attempt whose "firing" was
// the pattern swallowing the page produced no evidence, so the run cannot
// support that claim — confirming on the strength of the other two is exactly
// the arithmetic this gate exists to refuse. Nor is the mixed run merely
// INTERMITTENT: intermittent says the target's behaviour varied, and what
// varied here is whether the signature could see at all. Reporting a signature
// defect as target flakiness sends an operator to re-run the scan instead of
// to fix the pattern.
func TestAnOverBroadMatchOnOneAttemptTakesTheWholeCandidate(t *testing.T) {
	const pattern = `X [a-z]*`
	narrow := []byte("...X ab...")
	wide := []byte("prefix X " + strings.Repeat("abcdefghij", 30) + " and the rest")

	sig, err := NewSignature(pattern)
	if err != nil {
		t.Fatalf("NewSignature(%q): %v", pattern, err)
	}
	c := sqliCandidate(t, "/search")
	c.Signature = sig

	for _, tc := range []struct {
		name   string
		overOn int // the attempt number that gets the wide body
	}{
		{"over-broad on the FIRST attempt, clean after", 1},
		{"clean first, over-broad in the MIDDLE", 2},
		{"clean first, over-broad on the LAST attempt", 3},
	} {
		g := mustGate(t, GateConfig{
			Reprober: &scriptedReprober{body: func(_ RawFinding, attempt int) []byte {
				if attempt == tc.overOn {
					return wide
				}
				return narrow
			}},
			Attempts: 3,
		})
		f, err := g.ConfirmFinding(context.Background(), c)
		if err != nil {
			t.Fatalf("%s: ConfirmFinding: %v", tc.name, err)
		}
		if got, want := f.Outcome(), OutcomeUnconfirmed; got != want {
			t.Errorf("%s: outcome = %q, want %q. Two clean attempts do not rehabilitate "+
				"a run in which the signature quoted the page once", tc.name, got, want)
		}
		if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
			t.Errorf("%s: reason = %q, want %q. reproduced_intermittently would send an "+
				"operator to re-run the scan instead of to fix the signature",
				tc.name, got, want)
		}
		if got, want := f.SignatureMatches(), 3; got != want {
			t.Errorf("%s: SignatureMatches() = %d, want %d: the oracle fired on all three "+
				"and that measurement must survive the verdict", tc.name, got, want)
		}
		if got, want := f.OverQuotedMatches(), 1; got != want {
			t.Errorf("%s: OverQuotedMatches() = %d, want %d", tc.name, got, want)
		}
		if conf, known := f.Confidence(); known {
			t.Errorf("%s: Confidence() = (%.3f, true); 3/3 printed beside a reason saying "+
				"the signature could not see is the contradiction condition 4 exists "+
				"to prevent", tc.name, conf)
		}
	}

	// THE INTERACTION WITH THE INDECISIVE RULE, decided the same way and for
	// the same reason: an over-broad match is something Anvil DID observe,
	// and a rate limiter tripping on another attempt does not make it
	// unobserved. Rule 2 outranks rule 3.
	g := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{
			body: func(RawFinding, int) []byte { return wide },
			statusFn: func(_ RawFinding, attempt int) int {
				if attempt == 1 {
					return 429
				}
				return 200
			},
		},
		Attempts: 3,
	})
	f, err := g.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding (mixed indecisive): %v", err)
	}
	if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if got, want := f.IndecisiveAttempts(), 1; got != want {
		t.Errorf("IndecisiveAttempts() = %d, want %d: the fact stays reported even when "+
			"another rule owns the reason", got, want)
	}
	if got, want := f.OverQuotedMatches(), 2; got != want {
		t.Errorf("OverQuotedMatches() = %d, want %d", got, want)
	}

	// AND THE NON-VACUOUS DIRECTION. Three clean attempts confirm, so none
	// of the above is a gate that refuses everything.
	clean := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return narrow }},
		Attempts: 3,
	})
	cf, err := clean.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding (all clean): %v", err)
	}
	if got, want := cf.Outcome(), OutcomeConfirmed; got != want {
		t.Fatalf("three clean attempts came out %q, want %q", got, want)
	}
	if conf, known := cf.Confidence(); !known || conf != 1.0 {
		t.Errorf("Confidence() = (%.3f, %v), want (1.000, true)", conf, known)
	}
}

// TestTheDisclosedFixedWidthUnitSplitHasAWitness is the LOW from repeatedUnit's
// disclosure, given the measurement it was missing.
//
// The section header discloses a REFUSAL-DIRECTION split: a repeat whose unit's
// alphabet crosses letters into punctuation is refused when the unit's width
// varies, and accepted when it does not.
//
//	Z(?:a,?)*     REFUSED — the unit's width varies, so the join between
//	              traversals is a position two runes can reach
//	Z(?:abc, )*   ACCEPTED — a fixed-width spelled unit has no seam to be
//	              ambiguous at, and refusing it would make R3 a ban on repeats
//
// THE DISCLOSURE WAS TRUE AND UNWITNESSED. What it did not say is what the
// accepted side is worth against a real body: `Z(?:abc, )*` spells ONE byte of
// footing and matches 5001 bytes of a body made of its own unit. That is the
// same residual the concatenation case has, reached by a different route.
//
// IT IS CLOSED WHERE ALL OF THEM ARE CLOSED NOW. The match runs past its
// footing, so it does not confirm. The witness is the point: a disclosed
// residual with a live measurement beside it can be checked, and one without
// ages quietly.
func TestTheDisclosedFixedWidthUnitSplitHasAWitness(t *testing.T) {
	const varying = `Z(?:a,?)*`
	const fixedWidth = `Z(?:abc, )*`

	if _, err := refuseOverBroadPattern(varying); err == nil {
		t.Errorf("refuseOverBroadPattern(%q) ACCEPTED it; the disclosed split says the "+
			"varying-width unit is refused", varying)
	} else if !strings.Contains(err.Error(), "rule R3") {
		t.Errorf("refuseOverBroadPattern(%q) refused it for %q, not rule R3", varying, err)
	}
	spelled, err := refuseOverBroadPattern(fixedWidth)
	if err != nil {
		t.Fatalf("refuseOverBroadPattern(%q) = %v; the disclosure says the fixed-width "+
			"spelled unit is ACCEPTED, and if that has changed R3 has become a ban on "+
			"repeats", fixedWidth, err)
	}
	if spelled != 1 {
		t.Errorf("spelled = %d, want 1", spelled)
	}

	// THE WITNESS. One byte of footing, 5001 bytes of match.
	body := []byte("Z" + strings.Repeat("abc, ", 1000))
	loc := regexp.MustCompile(fixedWidth).FindIndex(body)
	if loc == nil || loc[1]-loc[0] != 5001 {
		t.Fatalf("the fixed-width unit matched %v of %d bytes; this test says 5001, and "+
			"a drifted number leaves the disclosure unwitnessed again", loc, len(body))
	}
	if !matchQuotesMoreThanItSpells(5001, spelled) {
		t.Fatalf("matchQuotesMoreThanItSpells(5001, %d) = false", spelled)
	}

	f, _ := overBroadCandidate(t, fixedWidth, body, 3)
	if got, want := f.Outcome(), OutcomeUnconfirmed; got != want {
		t.Errorf("outcome = %q, want %q", got, want)
	}
	if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if got := f.Evidence().ExtractedSpan(); got != "" {
		t.Errorf("span = %q", printable(got, 64))
	}
}

// ===========================================================================
// RULING 15 — the floor, and the direction the ratio alone was wrong in
// ===========================================================================

// TestEveryRealOracleConfirmsAGenuineHit is ruling 15's ACCEPTANCE half, and
// it is the half the previous round did not have.
//
// A gate that refuses everything passes every over-broadness test in this
// file. Nine rounds tightened the refusal and none of them asked the opposite
// question, so the tightening ran past the oracles: MEASURED on the tree as it
// was, with `matchLen - spelled > spelled` as the whole rule,
//
//	AKIA[0-9A-Z]{16}                 spelled=4  matchLen=20  UNCONFIRMED
//	Server: nginx/1\.[0-9]+\.[0-9]+  spelled=17 matchLen=20  confirmed
//	X-Debug-Token: [0-9a-f]+         spelled=15 matchLen=31  UNCONFIRMED
//
// A REPRODUCED AWS KEY EXPOSURE LANDED UNCONFIRMED and never reached
// dast_status findings. spelled counts LITERAL footing, and a credential
// oracle's evidence is by construction a character class — the literal is the
// sigil, the class is the secret — so the ratio is structurally hostile to
// exactly the signatures the suite is made of.
//
// THIS TEST IS THE ACCEPTANCE LIST, NAMED — eighteen oracles. The twelve the
// package's own positive control calls "every signature this suite and the
// plan actually use", the three real shapes the union rule's non-vacuity list
// names, and the credential shapes an external verifier used (AWS is one of
// the twelve already; GitHub, Stripe and PHPSESSID are the three that are
// not). Each has a genuine hit, and each is asserted on the outcome AND on the
// two integers the rule reads. The numbers are written down rather than
// derived in the assertion, so a change to either layer has to move a number
// here in the same diff.
//
// A WHOLE FAMILY IS NOT ON THIS LIST AND IS NAMED SO ITS ABSENCE IS NOT READ
// AS COVERAGE. This paragraph used to name ONE member — the JWT pair — and
// read as if that were the whole gap. It is not; see
// TestTheContentBearingEvidenceClassFamilyIsRefusedByR3, which measures the
// family and is the disclosure this comment now only summarises. In short:
// every oracle whose evidence class admits a LETTER alongside a printable rune
// that is neither letter nor digit, repeated more times than the pattern
// spells, is refused at NewSignature by R3, upstream of the floor. Base64url
// is the face of that an operator meets first; it is not the boundary. That is
// a real coverage gap in a security scanner rather than one awkward pattern.
func TestEveryRealOracleConfirmsAGenuineHit(t *testing.T) {
	for _, tc := range []struct {
		pattern     string
		body        string
		wantSpelled int
		wantMatch   int
		what        string
	}{
		// THE TWELVE FROM THE PACKAGE'S OWN POSITIVE CONTROL.
		{sqliPattern, "<pre>" + sqliMarker + "</pre>", 44, 60,
			"the packet's stop-condition oracle"},
		{`"role":"admin"`, `{"user":"x","role":"admin"}`, 14, 14,
			"a pure literal: the ratio was never a problem here and it must stay that way"},
		{spanBoundaryPattern, "ANVIL-SPAN-BEGIN4f2aANVIL-SPAN-END", 30, 34,
			"the probe-marker pair against a SHORT payload, which is the case the " +
				"hostile-body test never covered"},
		{`You have an error in your SQL syntax`, "x" + sqliMarker, 36, 36,
			"the same oracle with no class at all"},
		{`root:[x*]:0:0:`, "root:x:0:0:root:/root:/bin/bash", 10, 11,
			"an /etc/passwd disclosure: one one-rune-choice class inside a literal"},
		{`AKIA[0-9A-Z]{16}`, "... AKIA1234567890ABCDEF ...", 4, 20,
			"THE NAMED CASE: an AWS key id, four spelled bytes and sixteen of class"},
		{`Server: nginx/1\.[0-9]+\.[0-9]+`, "Server: nginx/1.24.0\r\n", 17, 20,
			"a version banner; it confirmed before the floor too, and it is here as " +
				"the control that the floor changed nothing above it"},
		{`<script>alert\(1\)</script>`, "<p><script>alert(1)</script></p>", 25, 25,
			"a reflected-XSS marker: literal throughout"},
		{`java\.lang\.NullPointerException`, "at java.lang.NullPointerException\n", 30, 30,
			"a stack-trace leak"},
		{`blocked by policy reference [0-9]{4}-[A-Z]{2}`, "blocked by policy reference 4021-AC",
			29, 35, "the WAF marker the containment tests use"},
		{`(?i)PHP Fatal error:  Uncaught [A-Za-z]{1,40}`, "PHP Fatal error:  Uncaught TypeError",
			27, 36, "a case-insensitive class, which the parser expands past ASCII"},
		{`X-Debug-Token: [0-9a-f]+`, "X-Debug-Token: 9f2c1a4b8e7d6053\r\n", 15, 31,
			"a narrow class with NO repeat ceiling: the shape the ratio punishes hardest"},

		// THE THREE THE UNION RULE'S NON-VACUITY LIST NAMES AS REAL SHAPES.
		{`(?:[0-9]{1,3}\.){3}[0-9]{1,3} ZZZZ`, "leaked 10.20.30.41 ZZZZ", 8, 16,
			"a dotted quad: the internal-address leak ruling 15's message names"},
		{`(?i)(error|warning|expired)`, "session expired at 12:00", 5, 7,
			"the disclosed word-list residual, as an oracle"},
		{`(?:GET|POST|PUT) /admin/[a-z]{1,20} ZZZZ`, "POST /admin/users ZZZZ", 16, 22,
			"an unrepeated alternation over a method list"},

		// THE FOUR CREDENTIAL SHAPES THE EXTERNAL VERIFIER USED.
		{`ghp_[0-9A-Za-z]{36}`, "token ghp_" + strings.Repeat("A", 36) + " end", 4, 40,
			"a GitHub personal access token"},
		{`sk_live_[0-9a-zA-Z]{24}`, "key sk_live_" + strings.Repeat("b", 24), 8, 32,
			"a Stripe live secret key"},
		{`PHPSESSID=[0-9a-f]{26,32}`, "Set-Cookie: PHPSESSID=" + strings.Repeat("a", 32), 10, 42,
			"a session id in a Set-Cookie header"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			sig, err := NewSignature(tc.pattern)
			if err != nil {
				t.Fatalf("NewSignature(%q) = %v. %s. A real oracle the early layer "+
					"refuses is a gate nobody can configure", tc.pattern, err, tc.what)
			}
			if sig.spelled != tc.wantSpelled {
				t.Errorf("spelled = %d, want %d", sig.spelled, tc.wantSpelled)
			}
			span, _, over, matchLen, matched := extractSpan([]byte(tc.body), sig)
			if !matched {
				t.Fatalf("%q did not match its own genuine hit %q. %s",
					tc.pattern, printable(tc.body, 64), tc.what)
			}
			if matchLen != tc.wantMatch {
				t.Errorf("matchLen = %d, want %d", matchLen, tc.wantMatch)
			}
			if matchQuotesMoreThanItSpells(matchLen, sig.spelled) {
				t.Errorf("matchQuotesMoreThanItSpells(%d, %d) = true. %s. This is a "+
					"GENUINE HIT and the gate is calling it the response",
					matchLen, sig.spelled, tc.what)
			}
			if over != 0 || span == "" {
				t.Errorf("over=%d span=%q: a genuine hit must be inlined; %s",
					over, printable(span, 64), tc.what)
			}

			// THE OUTCOME, END TO END, WHICH IS WHAT RULING 15 IS ABOUT.
			// The span mattering less than the verdict is the lesson of
			// the round before this one.
			f, _ := overBroadCandidate(t, tc.pattern, []byte(tc.body), 3)
			if got, want := f.Outcome(), OutcomeConfirmed; got != want {
				t.Fatalf("outcome = %q, want %q (reason=%q). %s: spelled=%d matchLen=%d",
					got, want, f.Reason(), tc.what, sig.spelled, matchLen)
			}
			if conf, known := f.Confidence(); !known || conf != 1.0 {
				t.Errorf("Confidence() = (%.3f, %v), want (1.000, true)", conf, known)
			}
			t.Logf("spelled=%d matchLen=%d unspelled=%d outcome=%s span=%q",
				sig.spelled, matchLen, matchLen-sig.spelled, f.Outcome(),
				printable(span, 48))
		})
	}
}

// TestTheContentBearingEvidenceClassFamilyIsRefusedByR3 is a DISCLOSED
// COVERAGE GAP, measured, named as the family it is.
//
// ===========================================================================
// WHAT THE FAMILY IS — THE PREDICATE, NOT A LIST OF SIX
// ===========================================================================
//
// THIS TEST USED TO BE NAMED FOR BASE64URL AND THAT NAME WAS NARROWER THAN
// WHAT R3 REFUSES. Every member it listed was accurate and measured;
// base64url is one FACE of the family, picked because it is the alphabet
// operators reach for. The dead name is not written out here, because
// TestEveryTestNamedInASourceCommentExists would flag its own narration — as
// it did, in this diff. The boundary is wider, it is mechanical, and it is
// this:
//
//	R3's counting arm refuses a signature whose repeat draws from a class
//	that admits a LETTER and at least one printable-ASCII rune that is
//	NEITHER LETTER NOR DIGIT, whenever the repeat's ceiling exceeds the
//	pattern's literal footing.
//
// `-` and `_` satisfy that. So do `+` and `/`, `.`, `:`, a SPACE, and every
// punctuation mark. THE PREDICATE IS SWEPT RATHER THAN ILLUSTRATED below:
// adding each of the 33 printable non-alphanumeric runes in turn to an
// accepted alphanumeric class flips the verdict to an R3 refusal, all 33 of
// them, and dropping either half of the conjunction — the letter, or the
// non-alphanumeric rune — brings the pattern back.
//
// WHY R3 REFUSES IT, and it is R3 working correctly rather than a bug.
// contentBearingClass partitions printable ASCII: a class admitting a LETTER
// and something that is NEITHER LETTER NOR DIGIT can run from one token into
// the next, so a repeat of it can carry the response's own prose, markup or
// JSON. `[0-9A-Za-z_-]{20,60}` is therefore 60 QUOTED positions, and R3's
// relation is 1:1 against the pattern's literal footing — `eyJ` is three
// bytes. The class is not token-shaped in R3's sense even though a token is
// what an operator means by it, because R3 cannot see intent, only the
// alphabet.
//
// THE GAP IS THAT THIS IS ALSO THE ALPHABET OF NEARLY EVERY MODERN BEARER
// CREDENTIAL, AND OF SEVERAL THINGS THAT ARE NOT CREDENTIALS AT ALL. JWTs,
// Google OAuth access tokens, OpenAI keys, GitLab PATs, Slack tokens and raw
// `Authorization: Bearer` headers live in the base64url face. The wider family
// also takes a PEM `-----BEGIN ... PRIVATE KEY-----` header (its class admits
// a space), a `Set-Cookie` value spanning dots and colons, a URL in an
// `href`, a `\w` token, and a password charset carrying punctuation — all
// measured below. A scanner that cannot express an oracle for them cannot
// report them, and an operator needs to know the SHAPE of that hole rather
// than one example of it.
//
// ===========================================================================
// WHAT AN OPERATOR SHOULD DO INSTEAD, AND WHAT IT COSTS
// ===========================================================================
//
// DROP `_` AND `-` FROM THE CLASS. `eyJ[0-9A-Za-z]{20,60}` compiles, because
// `[0-9A-Za-z]` is not content-bearing, and it confirms on a genuine hit
// inlining the token's leading alphanumeric run. The remedy is measured below
// rather than asserted, because the last version of this disclosure asserted
// none.
//
// ITS COST IS A MISS RATE, NOT A TRUNCATION, and that is the part worth
// reading. The repeat's MINIMUM still has to be met by alphanumerics alone, so
// a token whose first 20 base64url characters contain one `_` or `-` is not
// matched short — it is not matched AT ALL. MEASURED over 2,000 seeded random
// 40-character base64url tokens: `eyJ[0-9A-Za-z]{20,60}` hit 1,036 of them,
// missing 964 — roughly a 48% miss, and (62/64)^20 = 0.53 says that is the
// rate rather than the draw. Lowering the minimum to `{8,60}` does
// match the truncated prefix, at the price of a shorter and less specific
// literal-to-evidence ratio. Neither is the pattern the operator wanted; both
// are what this gate will compile. That trade is the disclosure.
//
// TWO MEMBERS FAIL A DIFFERENT WAY AND ARE NOT COUNTED IN EITHER LIST. A
// ceiling-less base64url repeat (`{10,}`) meets R3's UNBOUNDED arm rather than
// its counting arm, and a bare `[A-Za-z0-9+/]{40,}={0,2}` with no sigil at all
// is refused by R1 for spelling nothing. Both are refusals an operator would
// expect; the members below are the ones that look like ordinary oracles and
// are refused anyway.
func TestTheContentBearingEvidenceClassFamilyIsRefusedByR3(t *testing.T) {
	// THE SIX MEASURED BASE64URL MEMBERS — one face of the family, kept by
	// name because they are the shapes an operator writes first. quoted and
	// spelled are the two numbers R3's message reports, written out here so a
	// change to either layer has to move a number in this file in the same
	// diff.
	for _, tc := range []struct {
		pattern     string
		what        string
		wantQuoted  int
		wantSpelled int
	}{
		{`eyJ[0-9A-Za-z_-]{20,60}\.eyJ[0-9A-Za-z_-]{20,60}`, "a JWT header.payload pair", 120, 7},
		{`ya29\.[0-9A-Za-z_-]{20,120}`, "a Google OAuth2 access token", 120, 5},
		{`sk-[A-Za-z0-9_-]{32,64}`, "an OpenAI-style secret key", 64, 3},
		{`glpat-[0-9A-Za-z_-]{20}`, "a GitLab personal access token", 20, 6},
		{`xoxb-[0-9A-Za-z-]{20,60}`, "a Slack bot token", 60, 5},
		{`Bearer [A-Za-z0-9\-_.]{40,200}`, "a raw Authorization bearer header", 200, 7},
	} {
		t.Run(tc.what, func(t *testing.T) {
			assertRefusedByR3Counting(t, tc.pattern, tc.what, tc.wantQuoted, tc.wantSpelled)
		})
	}

	// THE REST OF THE FAMILY, WHICH THE OLD NAME DID NOT COVER. Not one of
	// these is base64url; every one of them satisfies the predicate above,
	// and each carries a rune from a different corner of the partition so
	// the list cannot be read as six spellings of `_` and `-`.
	t.Run("the_family_is_wider_than_base64url", func(t *testing.T) {
		for _, tc := range []struct {
			pattern     string
			what        string
			wantQuoted  int
			wantSpelled int
		}{
			{`session=[A-Za-z0-9+/]{40,64}`,
				"standard base64, on + and /", 64, 8},
			{`token=\w{20,40}`,
				"a \\w token: _ is neither letter nor digit", 40, 6},
			{`Set-Cookie: sid=[A-Za-z0-9.:]{20,40}`,
				"a cookie value spanning dots and colons", 40, 16},
			{`href="[A-Za-z0-9:/.]{20,80}"`,
				"a URL in an href", 80, 7},
			{`-----BEGIN [A-Z ]{4,40} PRIVATE KEY-----`,
				"a PEM private-key header, on a SPACE", 40, 28},
			{`db_password: [A-Za-z0-9!@#$%^&*]{12,32}`,
				"a password charset carrying punctuation", 32, 13},
		} {
			t.Run(tc.what, func(t *testing.T) {
				assertRefusedByR3Counting(t, tc.pattern, tc.what, tc.wantQuoted, tc.wantSpelled)
			})
		}
	})

	// THE PREDICATE ITSELF, SWEPT. This is the part that makes the family a
	// CLASS rather than a list somebody remembered to write down: take a
	// pattern R3 accepts, add one printable non-alphanumeric rune to its
	// class, and it is refused — for every such rune there is.
	//
	// The rune is written as `\x{hh}` so that `]`, `\`, `^` and `-` need no
	// special-casing inside the class and the sweep has no holes where an
	// escaping bug would look like an acceptance.
	t.Run("every_printable_non_alphanumeric_rune_flips_the_verdict", func(t *testing.T) {
		const base = `eyJ[0-9A-Za-z%s]{20,60}`
		if _, err := NewSignature(fmt.Sprintf(base, "")); err != nil {
			t.Fatalf("the alphanumeric baseline %q is itself refused: %v. Every "+
				"assertion below would then pass for the wrong reason",
				fmt.Sprintf(base, ""), err)
		}
		swept := 0
		for r := 0x20; r <= 0x7e; r++ {
			c := rune(r)
			if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				continue
			}
			swept++
			p := fmt.Sprintf(base, fmt.Sprintf(`\x{%02x}`, r))
			_, err := NewSignature(p)
			if err == nil {
				t.Errorf("NewSignature(%q) was ACCEPTED. 0x%02x (%q) is neither letter "+
					"nor digit, so contentBearingClass should make this class quote "+
					"60 positions against 3 spelled bytes. The predicate this test "+
					"states is not the predicate the code runs", p, r, c)
				continue
			}
			if !strings.Contains(err.Error(), "(rule R3)") {
				t.Errorf("NewSignature(%q) was refused, but not by R3: %v. The family "+
					"is defined by R3's counting arm; a refusal from R1, R2 or the "+
					"corpus is a different fact", p, err)
			}
		}
		if swept != 33 {
			t.Fatalf("swept %d runes, want 33 — printable ASCII is 0x20-0x7e, which is "+
				"95 runes, of which 62 are alphanumeric", swept)
		}
		// BOTH HALVES OF THE CONJUNCTION ARE LOAD-BEARING, so the predicate
		// is not "a class with punctuation in it" and not "a class with a
		// letter in it". Dropping either half brings the pattern back.
		for _, tc := range []struct{ pattern, why string }{
			{`eyJ[0-9\x{2d}]{20,60}`, "a hyphen with NO letter in the class"},
			{`eyJ[0-9_]{20,60}`, "an underscore with NO letter in the class"},
			{`eyJ[0-9 ]{20,60}`, "a space with NO letter in the class"},
			{`eyJ[0-9A-Za-z]{20,60}`, "letters and digits and nothing else"},
		} {
			if _, err := NewSignature(tc.pattern); err != nil {
				t.Errorf("NewSignature(%q) was REFUSED: %v. %s, so it is outside the "+
					"predicate and R3's counting arm must not reach it — otherwise "+
					"the family is wider than this test says and the disclosure is "+
					"still too narrow", tc.pattern, err, tc.why)
			}
		}
	})

	// THE REMEDY, MEASURED. Same oracles with `_` and `-` out of the class:
	// accepted, matched, inlined, confirmed.
	t.Run("the_remedy_compiles_and_confirms", func(t *testing.T) {
		for _, tc := range []struct{ pattern, body, wantSpan string }{
			{`eyJ[0-9A-Za-z]{20,60}`,
				`{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0"}`,
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`},
			{`glpat-[0-9A-Za-z]{20}`,
				`PRIVATE-TOKEN: glpat-NOTAREALTOKEN0000000`,
				`glpat-NOTAREALTOKEN0000000`},
			{`ya29\.[0-9A-Za-z]{20,120}`,
				`Authorization: Bearer ya29.a0ARrdaM9xKfQwErTyUiOpAsDfGhJkL`,
				`ya29.a0ARrdaM9xKfQwErTyUiOpAsDfGhJkL`},
		} {
			sig := mustSignature(t, tc.pattern)
			span, _, over, matchLen, ok := extractSpan([]byte(tc.body), sig)
			if !ok || over != 0 || span != tc.wantSpan {
				t.Errorf("extractSpan(%q) = (%q, over=%d, match=%d, ok=%v), want span %q "+
					"with no over-broad bytes", tc.pattern, printable(span, 96), over,
					matchLen, ok, tc.wantSpan)
				continue
			}
			f, _ := overBroadCandidate(t, tc.pattern, []byte(tc.body), 3)
			if got := f.Outcome(); got != OutcomeConfirmed {
				t.Errorf("%q: outcome = %q (reason %q), want %q — the remedy this "+
					"disclosure recommends has to actually confirm",
					tc.pattern, got, f.Reason(), OutcomeConfirmed)
			}
		}
	})

	// THE COST, MEASURED, so the miss rate in the comment above cannot
	// quietly become false. A seeded generator, so a failure reproduces.
	t.Run("the_remedy_misses_tokens_carrying_an_underscore_or_hyphen_early", func(t *testing.T) {
		const base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		const trials = 2000
		sig := mustSignature(t, `eyJ[0-9A-Za-z]{20,60}`)
		// A three-line xorshift rather than math/rand: this package's
		// import set is an allowlist and a disclosure does not earn a new
		// entry in it. Seeded, so a failure reproduces byte-for-byte.
		state := uint64(0x9E3779B97F4A7C15)
		next := func() uint64 {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			return state
		}
		hits := 0
		for i := 0; i < trials; i++ {
			token := []byte("eyJ")
			for j := 0; j < 40; j++ {
				token = append(token, base64URL[next()%uint64(len(base64URL))])
			}
			if _, _, _, _, ok := extractSpan(token, sig); ok {
				hits++
			}
		}
		// The window is wide because the number that matters is the
		// ORDER — "about half" — not the exact draw. A remedy that
		// suddenly hit everything, or nothing, would mean the class
		// semantics moved and the disclosure needs rewriting.
		if hits < 900 || hits > 1300 {
			t.Fatalf("the remedy hit %d/%d seeded random base64url tokens; the "+
				"disclosure above says 1036, roughly a 48%% miss. A number far "+
				"outside that means the class rule moved and the operator "+
				"guidance needs remeasuring", hits, trials)
		}
		t.Logf("remedy `eyJ[0-9A-Za-z]{20,60}` hit %d/%d seeded random base64url "+
			"tokens: %d missed entirely", hits, trials, trials-hits)
	})
}

// TestTheUnspelledFloorIsTheLiteralTwoFiftySix pins the floor's VALUE, and it
// names no other constant in this package on purpose.
//
// WHY A TEST THAT LOOKS LIKE A TAUTOLOGY EXISTS. It is not one, and the reason
// is measured rather than argued: replacing
//
//	const MaxUnspelledBytes = MaxSpanBytes / 2
//
// with the bare literal
//
//	const MaxUnspelledBytes = 299
//
// — carrying no derivation and no relation to any coded constant — left the
// ENTIRE PACKAGE GREEN, `go test -count=1 ./internal/dast/record/` and all.
// The green window was 255 through 300. Every fixture in this file either
// over-quotes by orders of magnitude or, in the one test written to pin the
// boundary, took its own edge FROM MaxUnspelledBytes, so the boundary moved
// with the constant and nothing could see it move. That is the standing-sweep
// item "a pin computing its expectation from the constant it pins",
// reproduced inside the pin.
//
// SO THE TWO FACTS ARE PINNED SEPARATELY AND NEITHER IS COMPUTED FROM THE
// OTHER. This test carries the LITERAL and mentions MaxSpanBytes nowhere;
// TestTheUnspelledFloorIsExactlyHalfTheSpanBound carries the RELATION and
// mentions no literal. A bare-literal rewrite of the declaration fails this
// one whatever number it picks outside 256. Changing MaxSpanBytes and leaving
// a hard-coded floor behind fails the other.
//
// 256 IS NOT ARBITRARY AND THE FILE SAYS WHERE IT COMES FROM in two places —
// MaxUnspelledBytes's own derivation, and the R-rules section's surviving
// "q <= 256" ceiling on inlined quotation. This test does not restate the
// derivation; it asserts the number the derivation lands on, which is the one
// thing the derivation cannot assert about itself.
func TestTheUnspelledFloorIsTheLiteralTwoFiftySix(t *testing.T) {
	const theFloorThisPackagePublishes = 256
	if MaxUnspelledBytes != theFloorThisPackagePublishes {
		t.Fatalf("MaxUnspelledBytes = %d, want %d.\n"+
			"This is the published ceiling on how many bytes of a target's response "+
			"a confirmed finding may inline without the pattern spelling them, and "+
			"it is the magnitude of the residual MaxUnspelledBytes discloses. "+
			"Moving it moves what this scanner will confirm and what it will quote; "+
			"if that is intended, change this number IN THE SAME DIFF and restate "+
			"the residual's magnitude at MaxUnspelledBytes and at "+
			"matchQuotesMoreThanItSpells.",
			MaxUnspelledBytes, theFloorThisPackagePublishes)
	}
}

// TestTheUnspelledFloorIsExactlyHalfTheSpanBound pins the floor's RELATION to
// MaxSpanBytes, and it writes down no literal on purpose.
//
// The floor is DERIVED — `MaxSpanBytes / 2` — and the derivation is what makes
// 256 the right number rather than a number: an inlined span's match fits in
// MaxSpanBytes, and above the floor the ratio arm forces the unspelled half to
// be the smaller one, so 2q <= L <= MaxSpanBytes. If MaxSpanBytes moves and
// the floor does not move with it, that argument is silently false and the
// package goes on printing the old ceiling in its comments.
// ENFORCED BY MaxUnspelledBytes,
// MEASURED BY TestTheUnspelledFloorIsExactlyHalfTheSpanBound.
//
// A LITERAL PIN CANNOT SEE THAT. TestTheUnspelledFloorIsTheLiteralTwoFiftySix
// asserts 256 and would keep passing with MaxSpanBytes at 1024 and the floor
// hard-coded at 256 — a floor that is a quarter of the span bound while every
// comment in the file says half. This test is the other half of the pair and
// fails exactly there.
func TestTheUnspelledFloorIsExactlyHalfTheSpanBound(t *testing.T) {
	if 2*MaxUnspelledBytes != MaxSpanBytes {
		t.Fatalf("2*MaxUnspelledBytes = %d, MaxSpanBytes = %d: the floor is no longer "+
			"half the span bound.\n"+
			"MaxUnspelledBytes is documented as DERIVED FROM MaxSpanBytes rather than "+
			"chosen, and matchQuotesMoreThanItSpells proves the floor does not raise "+
			"the package's published quotation ceiling by using exactly that relation "+
			"(q > MaxUnspelledBytes implies L >= 2q > MaxSpanBytes, so no span). "+
			"Either restore the derivation or rewrite both proofs.",
			2*MaxUnspelledBytes, MaxSpanBytes)
	}
}

// TestTheConfirmationBoundaryIsPinnedOnBothArms is the boundary no
// confirmation-layer test pinned.
//
// Every ruling-14 fixture over-quotes by orders of magnitude — 12,500,141
// bytes against 141, 5001 against 1, 302 against 2 — so changing the relation
// from 2x to 4x, or moving the floor by a factor of two, left all of them
// green. A guard whose tests only ever feed it values far from its boundary is
// a guard whose boundary is not under test.
//
// SO BOTH ARMS ARE PINNED HERE, one under, exact, one over:
//
//	THE FLOOR ARM   spelled=1, unspelled 255 / 256 / 257 against
//	                MaxUnspelledBytes=256
//	THE RATIO ARM   spelled=300, unspelled 299 / 300 / 301 — a footing over
//	                the floor, which is the only place the ratio still decides
//
// The ratio arm needs spelled > MaxUnspelledBytes to be reachable at all, and
// that is not an inconvenience of the fixture, it is the shape of the rule: a
// match whose unspelled part is inside the floor never reaches the ratio.
// ENFORCED BY matchQuotesMoreThanItSpells,
// MEASURED BY TestTheConfirmationBoundaryIsPinnedOnBothArms.
func TestTheConfirmationBoundaryIsPinnedOnBothArms(t *testing.T) {
	for _, arm := range []struct {
		name     string
		pattern  string
		spelled  int
		wantSpan bool
	}{
		{"floor", `Z[0-9A-Za-z]*`, 1, true},
		{"ratio", strings.Repeat("Z", 300) + `[0-9A-Za-z]*`, 300, false},
	} {
		sig := mustSignature(t, arm.pattern)
		if sig.spelled != arm.spelled {
			t.Fatalf("%s arm: spelled = %d, want %d; the fixture is not sitting where "+
				"this test says it is", arm.name, sig.spelled, arm.spelled)
		}
		// The boundary value each arm is pinned against.
		//
		// THE FLOOR ARM'S EDGE IS WRITTEN OUT AND NOT READ FROM
		// MaxUnspelledBytes, and that is the whole point of the number
		// being here. This test used to say `edge := MaxUnspelledBytes`,
		// so the boundary moved with the constant and the test could not
		// see it move: MaxUnspelledBytes could be replaced by a bare
		// literal 299 and the entire package stayed green. MEASURED. A
		// pin that computes its expectation from the constant it pins is
		// not a pin. The value here is 256 because that is where the
		// boundary IS, and TestTheUnspelledFloorIsTheLiteralTwoFiftySix
		// asserts separately that the constant agrees.
		edge := 256
		if arm.name == "ratio" {
			edge = arm.spelled
		}
		for _, tc := range []struct {
			label       string
			unspelled   int
			wantOutcome Outcome
		}{
			{"one_under", edge - 1, OutcomeConfirmed},
			{"exactly_at_the_boundary", edge, OutcomeConfirmed},
			{"one_over", edge + 1, OutcomeUnconfirmed},
		} {
			t.Run(arm.name+"/"+tc.label, func(t *testing.T) {
				body := []byte(strings.Repeat("Z", arm.spelled) +
					strings.Repeat("a", tc.unspelled))
				matchLen := arm.spelled + tc.unspelled

				// THE PREDICATE ITSELF, so a failure names the two
				// integers rather than only the verdict.
				wantOver := tc.wantOutcome == OutcomeUnconfirmed
				if got := matchQuotesMoreThanItSpells(matchLen, arm.spelled); got != wantOver {
					t.Errorf("matchQuotesMoreThanItSpells(%d, %d) = %v, want %v "+
						"(unspelled=%d, floor=%d, spelled=%d)",
						matchLen, arm.spelled, got, wantOver, tc.unspelled,
						MaxUnspelledBytes, arm.spelled)
				}

				f, _ := overBroadCandidate(t, arm.pattern, body, 3)
				if got := f.Outcome(); got != tc.wantOutcome {
					t.Fatalf("outcome = %q, want %q: %d unspelled bytes against %d "+
						"spelled, with the floor at %d. The boundary must be "+
						"EXACTLY here — a rule at twice or half this number passes "+
						"every other fixture in this file",
						got, tc.wantOutcome, tc.unspelled, arm.spelled,
						MaxUnspelledBytes)
				}
				if tc.wantOutcome == OutcomeUnconfirmed {
					if got, want := f.Reason(), ReasonMatchQuotedTheResponse; got != want {
						t.Errorf("reason = %q, want %q", got, want)
					}
					if got := f.Evidence().ExtractedSpan(); got != "" {
						t.Errorf("span = %q", printable(got, 32))
					}
					return
				}
				// A CONFIRMED VERDICT DOES NOT IMPLY A SPAN, and the
				// ratio arm is where the two come apart: its matches run
				// past MaxSpanBytes, so property 1 withholds the span
				// while the outcome stands. That is pre-existing rule-1
				// behaviour, asserted here so this test cannot be read
				// as promising a span with every confirmation.
				gotSpan := f.Evidence().ExtractedSpan() != ""
				if gotSpan != arm.wantSpan {
					t.Errorf("span present = %v, want %v (matchLen=%d, MaxSpanBytes=%d)",
						gotSpan, arm.wantSpan, matchLen, MaxSpanBytes)
				}
				if arm.wantSpan {
					q := len(f.Evidence().ExtractedSpan()) - arm.spelled
					if q > MaxUnspelledBytes {
						t.Errorf("the inlined span carries %d unspelled bytes and the "+
							"published ceiling is %d", q, MaxUnspelledBytes)
					}
				}
			})
		}
	}
}

// TestAnUnvettedSignatureGetsNoFloor is the fail-closed arm of
// matchQuotesMoreThanItSpells, and it exists because BREAKING THE ARM DID NOT
// TURN ANYTHING RED.
//
// The arm was written, the whole package was run with it deleted, and every
// test still passed. A guard nothing can falsify is a guard that is not there,
// and this file's standard is that such a claim is deleted rather than
// qualified — so it is either demonstrated here or it comes out.
//
// WHAT IT PROTECTS. spelled is Signature.spelled, which refuseOverBroadPattern
// fills in and R1 guarantees is at least 1. A Signature assembled by hand
// carries spelled=0, and with q = matchLen - spelled = matchLen the floor
// would hand that unvetted pattern MaxUnspelledBytes free bytes of any
// response — an inlined span from a pattern no rule ever looked at. The arm
// refuses every non-empty match instead.
//
// ConfirmFinding cannot be the vehicle: an unsealed Signature is refused by
// validation long before a body is read, which is the OUTER half of the same
// fail-closed posture and is asserted here too. So the arm is driven where it
// is reachable — extractSpan, and the predicate itself.
func TestAnUnvettedSignatureGetsNoFloor(t *testing.T) {
	// A pattern that would sail through the floor if it had one: three
	// unspelled bytes, far under MaxUnspelledBytes.
	raw := Signature{re: regexp.MustCompile(`Z[0-9A-Za-z]*`), src: `Z[0-9A-Za-z]*`, sealed: true}
	if raw.spelled != 0 {
		t.Fatalf("the fixture spells %d; it is supposed to be the hand-assembled zero",
			raw.spelled)
	}
	body := []byte("Zabc")
	span, _, over, matchLen, matched := extractSpan(body, raw)
	if !matched {
		t.Fatal("the fixture did not match its own body")
	}
	if matchLen != 4 {
		t.Fatalf("matchLen = %d, want 4", matchLen)
	}
	if !matchQuotesMoreThanItSpells(matchLen, raw.spelled) {
		t.Errorf("matchQuotesMoreThanItSpells(%d, 0) = false. Four unspelled bytes are "+
			"inside MaxUnspelledBytes=%d, so the floor has been applied to a signature "+
			"NewSignature never vetted", matchLen, MaxUnspelledBytes)
	}
	if span != "" || over != matchLen {
		t.Errorf("span=%q over=%d: an unvetted signature must inline nothing, whatever "+
			"the floor would otherwise allow", printable(span, 32), over)
	}

	// EVERY LENGTH, not just one, because "no floor" is the claim and one
	// sample under the floor cannot distinguish it from a smaller floor.
	for _, n := range []int{1, 2, MaxUnspelledBytes - 1, MaxUnspelledBytes, MaxUnspelledBytes + 1} {
		if !matchQuotesMoreThanItSpells(n, 0) {
			t.Errorf("matchQuotesMoreThanItSpells(%d, 0) = false; every non-empty match "+
				"against zero footing is over-broad", n)
		}
	}
	// AND THE ZERO-LENGTH MATCH IS NOT, so this is a rule and not a constant
	// true. A zero-byte match quotes nothing.
	if matchQuotesMoreThanItSpells(0, 0) {
		t.Error("matchQuotesMoreThanItSpells(0, 0) = true; an empty match quotes nothing " +
			"and the arm has become an unconditional refusal")
	}

	// THE OUTER HALF. The gate never sees an unsealed Signature at all, and
	// that is asserted rather than assumed, because if it ever did the arm
	// above would be the only thing standing between an unvetted pattern and
	// a confirmed finding.
	c := sqliCandidate(t, "/search")
	c.Signature = Signature{re: regexp.MustCompile(`Z[0-9A-Za-z]*`), src: `Z[0-9A-Za-z]*`}
	g := mustGate(t, GateConfig{
		Reprober: &scriptedReprober{body: func(RawFinding, int) []byte { return body }},
		Attempts: 3,
	})
	if _, err := g.ConfirmFinding(context.Background(), c); err == nil {
		t.Error("ConfirmFinding accepted a Signature NewSignature did not build")
	}
}

// TestScalingTheSpelledFootingDoesNotBuyAnOrdinaryPage re-runs the attack that
// asks the obvious question about a ratio: if confirmation turns on
// `unspelled <= spelled`, can an attacker simply make spelled enormous?
//
// THEY CAN MAKE IT ENORMOUS. MaxPatternBytes bounds the pattern, not the
// footing: a counted repeat spells 1000 bytes in seven, so 144 of them inside
// a 1020-byte pattern spell 144,000. MEASURED below rather than argued.
//
// IT BUYS NOTHING, AND THE REASON IS THE ONE THING A RATIO OVER A REAL MATCH
// CANNOT BE TALKED OUT OF: to match at all, the response must actually contain
// those 144,000 literal bytes. A page that does is not an ordinary page — it
// is a page that echoed the signature's own marker 144,000 times. The attack
// fails at the MATCH, before any predicate is consulted, and this test asserts
// that on an ordinary document.
//
// THE RATIO'S SHAPE AT THAT SCALE IS DISCLOSED RATHER THAN LEFT IMPLICIT, and
// it is PRE-EXISTING — ruling 15's floor neither created nor widened it. A
// 288,000-byte match against 144,000 spelled bytes is inside the ratio and
// would confirm; 288,001 is not. No span is inlined either way, because both
// run past MaxSpanBytes, so no byte of the response reaches a prompt-bound
// field in either case. The arithmetic is asserted on integers rather than by
// running a 288 KB regex match, which costs a minute and a half and measures
// RE2 rather than this rule.
func TestScalingTheSpelledFootingDoesNotBuyAnOrdinaryPage(t *testing.T) {
	const copies = 144
	pattern := strings.Repeat(`Z{1000}`, copies) + `[0-9A-Za-z]*`
	if len(pattern) > MaxPatternBytes {
		t.Fatalf("the fixture is %d bytes and MaxPatternBytes is %d; it is supposed to sit "+
			"just under the ceiling", len(pattern), MaxPatternBytes)
	}
	if over := strings.Repeat(`Z{1000}`, copies+1) + `[0-9A-Za-z]*`; len(over) <= MaxPatternBytes {
		t.Errorf("%d copies is %d bytes and still fits under MaxPatternBytes=%d, so this "+
			"is not the ceiling and the footing below is understated",
			copies+1, len(over), MaxPatternBytes)
	}
	sig := mustSignature(t, pattern)
	if got, want := sig.spelled, copies*1000; got != want {
		t.Fatalf("spelled = %d, want %d. The point of this fixture is that a 1020-byte "+
			"pattern can spell %d bytes; if it no longer can, the attack it re-runs has "+
			"stopped existing and this test measures nothing", got, want, want)
	}

	// THE ATTACK: an ordinary document. It does not match, so there is no
	// verdict to argue about.
	const ordinary = `<!doctype html><html><head><title>Acme Store</title></head><body>` +
		`<h1>Welcome</h1><p>Everything is fine here; nothing is wrong.</p></body></html>`
	if _, _, _, _, matched := extractSpan([]byte(ordinary), sig); matched {
		t.Error("the scaled-footing signature MATCHED an ordinary document. A pattern " +
			"requiring 144,000 literal bytes cannot, and if it can the footing count " +
			"is not a lower bound on what a match requires")
	}
	f, _ := overBroadCandidate(t, pattern, []byte(ordinary), 3)
	if got := f.Outcome(); got == OutcomeConfirmed {
		t.Fatalf("outcome = %q against an ordinary page", got)
	}
	if got, want := f.Reason(), ReasonDidNotReproduce; got != want {
		t.Errorf("reason = %q, want %q: the oracle RAN and never fired, which is a "+
			"different fact from a match the gate would not credit", got, want)
	}

	// THE ARITHMETIC AT SCALE, ON INTEGERS. Both sides of the ratio's
	// boundary, so scaling the footing cannot be read as scaling the
	// allowance past what the footing actually paid for.
	for _, tc := range []struct {
		matchLen int
		want     bool
		why      string
	}{
		{2 * copies * 1000, false, "unspelled exactly equals spelled: inside the ratio"},
		{2*copies*1000 + 1, true, "one byte past it"},
		{12500141, true, "the scaled concatenation's match length, against this footing"},
	} {
		if got := matchQuotesMoreThanItSpells(tc.matchLen, sig.spelled); got != tc.want {
			t.Errorf("matchQuotesMoreThanItSpells(%d, %d) = %v, want %v: %s",
				tc.matchLen, sig.spelled, got, tc.want, tc.why)
		}
	}
}

// ===========================================================================
// D.30 — WHAT AN EMPTY SPAN MEANS, AND WHERE EVIDENCE COMES FROM
// ===========================================================================

// TestAnEmptySpanHasFourCausesAndOneFieldSeparatesOne is the measurement
// behind EvidenceRef.ExtractedSpan's doc comment, and it exists because that
// doc comment said "TWO different situations and SpanOverBroadBytes is what
// tells them apart" while there were four.
//
// A CONSUMER BRANCHING ON SpanOverBroadBytes IS THE READER THIS PROTECTS. The
// field is exported, its accessor is the first thing a consumer reads, and the
// sentence told them a zero meant "the signature matched nothing". Three of
// the four causes below carry a zero, and one of those three is a CONFIRMED
// finding whose oracle fired on every attempt.
//
// The four are asserted on all three fields at once — span, dropped,
// over-broad — because the claim being pinned is not "each case happens", it
// is "these are the values a consumer would have to tell them apart by".
func TestAnEmptySpanHasFourCausesAndOneFieldSeparatesOne(t *testing.T) {
	vulnerable := []byte(`{"error":"` + sqliMarker + `"}`)

	// CAUSE 1 — the signature ran against an application response and matched
	// nothing. This is the 88 phantoms.
	t.Run("matched_nothing", func(t *testing.T) {
		f := confirmAgainst(t, sqliCandidate(t, "/search"),
			&scriptedReprober{body: func(RawFinding, int) []byte { return []byte(`ordinary page`) }})
		assertEvidence(t, f, evidenceWant{
			span: "", dropped: 0, overBroad: 0,
			reason: ReasonDidNotReproduce, outcome: OutcomeRejected,
		})
	})

	// CAUSE 2 — no attempt reached the application, so the signature was
	// NEVER RUN. The body carried the marker on every attempt; the gate
	// refused to hand a 429 to the oracle at all.
	t.Run("the_signature_was_never_run", func(t *testing.T) {
		f := confirmAgainst(t, sqliCandidate(t, "/search"), &scriptedReprober{
			status: 429,
			body:   func(RawFinding, int) []byte { return vulnerable },
		})
		assertEvidence(t, f, evidenceWant{
			span: "", dropped: 0, overBroad: 0,
			reason: ReasonReprobeIndecisive, outcome: OutcomeUnconfirmed,
		})
	})

	// CAUSE 3 — the match was inlinable and every byte of it was dropped as
	// non-printable. SpanDroppedBytes is the only field that can say so.
	//
	// The pattern SPELLS eight non-printable bytes, which is why R2 lets it
	// compile: R2 refuses a class that can match outside printable ASCII
	// without spelling the rune, and this spells all eight.
	t.Run("every_matched_byte_was_dropped", func(t *testing.T) {
		const control = "\x01\x02\x03\x04\x05\x06\x07\x08"
		c := sqliCandidate(t, "/search")
		c.Signature = mustSignature(t, control)
		f := confirmAgainst(t, c, &scriptedReprober{
			body: func(RawFinding, int) []byte { return []byte("prefix" + control + "suffix") },
		})
		assertEvidence(t, f, evidenceWant{
			span: "", dropped: 8, overBroad: 0,
			reason: ReasonReproduced, outcome: OutcomeConfirmed,
		})
		// THE POINT OF THIS CASE, SAID OUT LOUD: a CONFIRMED finding, an
		// oracle that fired three times out of three, and an empty span
		// beside SpanOverBroadBytes = 0 — the exact pair the old doc
		// comment told a consumer meant "the signature matched nothing".
		if conf, known := f.Confidence(); !known || conf != 1.0 {
			t.Errorf("Confidence() = (%.3f, %v), want (1.000, true)", conf, known)
		}
	})

	// CAUSE 4 — the match could not be inlined at all. The ONLY cause
	// SpanOverBroadBytes names.
	t.Run("the_match_could_not_be_inlined", func(t *testing.T) {
		f, _ := overBroadCandidate(t, `anvil-probe-4f2a[0-9A-Za-z]*`,
			[]byte("anvil-probe-4f2a"+strings.Repeat("a", 5000)), 3)
		assertEvidence(t, f, evidenceWant{
			span: "", dropped: 0, overBroad: 5016,
			reason: ReasonMatchQuotedTheResponse, outcome: OutcomeUnconfirmed,
		})
	})

	// THE BICONDITIONAL THE FILE HEADER USED TO STATE, IN BOTH OF THE SENSES
	// ITS WITHDRAWAL USED TO EQUIVOCATE BETWEEN. It read "evidence exists
	// exactly when something matched", and `evidence` can mean the RECORD or
	// the SPAN. The header now fixes it to the span, where the failure is one
	// direction; these two subtests hold the measurements under both readings
	// so the fixing is a choice about wording and not about facts.
	t.Run("evidence_exists_when_nothing_matched", func(t *testing.T) {
		for _, tc := range []struct {
			what string
			r    *scriptedReprober
		}{
			{"the oracle ran and never fired", &scriptedReprober{
				body: func(RawFinding, int) []byte { return []byte(`ordinary page`) }}},
			{"the oracle was never run", &scriptedReprober{status: 429,
				body: func(RawFinding, int) []byte { return vulnerable }}},
		} {
			f := confirmAgainst(t, sqliCandidate(t, "/search"), tc.r)
			ev := f.Evidence()
			if !ev.Constructed() || len(ev.BodyHash()) != 64 {
				t.Errorf("%s: Constructed()=%v BodyHash()=%d chars, want a constructed "+
					"EvidenceRef carrying a SHA-256. Evidence exists here and nothing "+
					"matched, so the biconditional is false in this direction",
					tc.what, ev.Constructed(), len(ev.BodyHash()))
			}
		}
	})
	t.Run("something_matched_and_there_is_no_span", func(t *testing.T) {
		for _, tc := range []struct{ what, pattern, body string }{
			{"the match was all non-printable", "\x01\x02\x03\x04\x05\x06\x07\x08",
				"prefix\x01\x02\x03\x04\x05\x06\x07\x08suffix"},
			{"the match was over-broad", `anvil-probe-4f2a[0-9A-Za-z]*`,
				"anvil-probe-4f2a" + strings.Repeat("a", 5000)},
		} {
			sig := mustSignature(t, tc.pattern)
			span, _, _, _, matched := extractSpan([]byte(tc.body), sig)
			if !matched || span != "" {
				t.Errorf("%s: extractSpan matched=%v span=%q, want a match and no span. "+
					"Evidence does not exist whenever something matched",
					tc.what, matched, printable(span, 48))
			}
		}
	})
}

// evidenceWant is the verdict TestAnEmptySpanHasFourCausesAndOneFieldSeparatesOne
// asserts. Every field is stated on every case on purpose: a case asserting
// only the field it is about would pass while a neighbouring field silently
// took the same value, which is the confusion the test exists to rule out.
type evidenceWant struct {
	span      string
	dropped   int
	overBroad int
	reason    Reason
	outcome   Outcome
}

func assertEvidence(t *testing.T, f *Finding, want evidenceWant) {
	t.Helper()
	ev := f.Evidence()
	if got := ev.ExtractedSpan(); got != want.span {
		t.Errorf("ExtractedSpan() = %q, want %q", printable(got, 64), want.span)
	}
	if got := ev.SpanDroppedBytes(); got != want.dropped {
		t.Errorf("SpanDroppedBytes() = %d, want %d", got, want.dropped)
	}
	if got := ev.SpanOverBroadBytes(); got != want.overBroad {
		t.Errorf("SpanOverBroadBytes() = %d, want %d", got, want.overBroad)
	}
	if got := f.Reason(); got != want.reason {
		t.Errorf("Reason() = %q, want %q", got, want.reason)
	}
	if got := f.Outcome(); got != want.outcome {
		t.Errorf("Outcome() = %q, want %q", got, want.outcome)
	}
	if !ev.Constructed() || len(ev.BodyHash()) != 64 {
		t.Errorf("Constructed()=%v BodyHash()=%d chars, want a constructed EvidenceRef "+
			"carrying a SHA-256 whatever the span says", ev.Constructed(), len(ev.BodyHash()))
	}
}

// confirmAgainst runs one candidate through a three-attempt gate wired to the
// supplied reprober and refuses to swallow an error.
func confirmAgainst(t *testing.T, c RawFinding, r *scriptedReprober) *Finding {
	t.Helper()
	g := mustGate(t, GateConfig{Reprober: r, Attempts: 3})
	f, err := g.ConfirmFinding(context.Background(), c)
	if err != nil {
		t.Fatalf("ConfirmFinding: %v", err)
	}
	return f
}

// TestEvidenceComesFromTheFirstApplicationAnsweredAttemptNotFromAttemptOne is
// ConfirmFinding's step 4, and it is here because step 4's doc comment said
// "or from attempt 1 if none did" and attempt 1 is not where it comes from.
//
// THE DIFFERENCE IS A BLOCK PAGE'S HASH ON A FINDING. With attempt 1 answering
// 429 and attempt 2 answering 200, "attempt 1" would put the defence page's
// SHA-256 in the record as the body the finding is about. The rule the code
// actually runs is: the first attempt whose SIGNATURE MATCHED, failing that
// the first attempt the APPLICATION ANSWERED, failing that attempt 1 — and
// only the last of those three is attempt 1.
//
// The hashes are compared rather than the bodies, because the hash is the only
// thing about the body that crosses this boundary at all.
func TestEvidenceComesFromTheFirstApplicationAnsweredAttemptNotFromAttemptOne(t *testing.T) {
	vulnerable := []byte(`{"error":"` + sqliMarker + `"}`)
	block := []byte(`<html><body>Request blocked by the WAF.</body></html>`)
	ordinary := []byte(`ordinary page, no marker here`)
	blockedFirst := func(_ RawFinding, a int) int {
		if a == 1 {
			return 429
		}
		return 200
	}

	for _, tc := range []struct {
		what   string
		status func(RawFinding, int) int
		body   func(RawFinding, int) []byte
		want   []byte
		reason Reason
	}{
		{
			what:   "attempt 1 is a block page and attempt 2 answers with the marker",
			status: blockedFirst,
			body: func(_ RawFinding, a int) []byte {
				if a == 1 {
					return block
				}
				return vulnerable
			},
			want:   vulnerable,
			reason: ReasonReproducedIntermittently,
		},
		{
			what:   "attempt 1 is a block page and no later attempt matches",
			status: blockedFirst,
			body: func(_ RawFinding, a int) []byte {
				if a == 1 {
					return block
				}
				return ordinary
			},
			want:   ordinary,
			reason: ReasonReprobeIndecisive,
		},
		{
			what:   "attempt 1 answers and attempt 3 is the one that matches",
			status: func(RawFinding, int) int { return 200 },
			body: func(_ RawFinding, a int) []byte {
				if a == 3 {
					return vulnerable
				}
				return ordinary
			},
			want:   vulnerable,
			reason: ReasonReproducedIntermittently,
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			f := confirmAgainst(t, sqliCandidate(t, "/search"),
				&scriptedReprober{statusFn: tc.status, body: tc.body})
			if got, want := f.Evidence().BodyHash(), hashBody(tc.want); got != want {
				t.Errorf("BodyHash() = %s, want the hash of %q. Step 4's rule is "+
					"first-match, then first-answered, then attempt 1",
					got, printable(string(tc.want), 48))
			}
			if got := f.Reason(); got != tc.reason {
				t.Errorf("Reason() = %q, want %q; the fixture is not producing the "+
					"run this case is about", got, tc.reason)
			}
		})
	}

	// THE THIRD ARM, which IS attempt 1: every attempt indecisive, so there
	// is no answered attempt to prefer and attempt 1's hash is what is left.
	t.Run("every_attempt_indecisive_falls_back_to_attempt_1", func(t *testing.T) {
		f := confirmAgainst(t, sqliCandidate(t, "/search"), &scriptedReprober{
			status: 429,
			body: func(_ RawFinding, a int) []byte {
				return []byte(fmt.Sprintf("blocked, attempt %d", a))
			},
		})
		if got, want := f.Evidence().BodyHash(), hashBody([]byte("blocked, attempt 1")); got != want {
			t.Errorf("BodyHash() = %s, want attempt 1's. With nothing answered there "+
				"is no better attempt to take, and taking the LAST one would make the "+
				"record depend on the attempt count", got)
		}
	})
}

// assertRefusedByR3Counting is one member of the content-bearing-class family,
// checked against R3's COUNTING arm and against the two integers its message
// reports.
//
// The numbers are passed in rather than derived from the pattern, so a change
// to either layer has to move a number in this file in the same diff. The
// refusing RULE is asserted too: a member that starts being refused by R1, by
// R2 or by the benign corpus is no longer evidence about the family this test
// names, and would otherwise keep the test green while the disclosure went
// stale.
func assertRefusedByR3Counting(t *testing.T, pattern, what string, wantQuoted, wantSpelled int) {
	t.Helper()
	_, err := NewSignature(pattern)
	if err == nil {
		t.Fatalf("NewSignature(%q) was ACCEPTED. %s now compiles, which is a "+
			"REAL IMPROVEMENT and not a failure — but this test is the "+
			"disclosure of a gap, so close the gap in the comment above "+
			"before deleting the case", pattern, what)
	}
	if !errors.Is(err, ErrSignatureMatchesEverything) {
		t.Fatalf("NewSignature(%q): err = %v, want an ErrSignatureMatchesEverything",
			pattern, err)
	}
	if got := err.Error(); !strings.Contains(got, "(rule R3)") {
		t.Fatalf("NewSignature(%q) was refused, but not by R3: %v\n"+
			"The disclosure above is specifically about R3 counting a "+
			"content-bearing class as quotation", pattern, err)
	}
	for _, want := range []string{
		fmt.Sprintf("quotes up to %d position(s)", wantQuoted),
		fmt.Sprintf("against %d byte(s) of literal footing", wantSpelled),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("R3's refusal of %q does not report %q:\n%v", pattern, want, err)
		}
	}
}

// ===========================================================================
// D.30 — THE ARITHMETIC-CLAIM GUARD
// ===========================================================================

// TestEveryArithmeticClaimInACommentCitesAnEnforcerAndAMeasurement is the
// mechanical half of the round that produced it, and it exists because the
// human half keeps failing in the same shape.
//
// FOUR CONSECUTIVE ROUNDS WERE EACH ASKED TO SWEEP THIS FILE FOR FALSE
// CLAIMS. Each corrected the sentence it was pointed at and left another
// behind: one corrected a field comment twelve lines above a defect and an
// accessor six lines below it, and stepped over the exported method between
// them. A HUMAN SWEEP OF PROSE IS A DENYLIST OF SENTENCES SOMEBODY REMEMBERED
// TO READ, which is the shape this repository has spent fifteen rulings
// learning to distrust.
//
// ===========================================================================
// RULING 16: A CITATION IS A FORM, NOT A WORD
// ===========================================================================
//
// THE FIRST VERSION OF THIS GUARD HAD THE DEFECT IT WAS BUILT TO END. It asked
// a claim to NAME something — any token in the paragraph that resolved to a
// declared identifier and carried an upper-case letter counted as the enforcer
// — and its own doc asserted that requiring a case boundary "is what separates
// a NAME from an English word without keeping a denylist of English words".
// MEASURED FALSE, and the measurement is not quoted here from a commit
// message: the_shape_this_replaced_is_still_measurably_vacuous re-runs it on
// every invocation. It reported 435 of this package's 757 declared identifiers
// admitted as enforcer citations on the tree that shipped this, and among them
// the ordinary English nouns this file's prose leans on. A verifier appended a
// paragraph to confirm_gate.go asserting a ceiling of 4096 and a span running
// to twice the published limit, citing nothing its author intended — that
// subtest names the two tokens the old shape read out of it, `Evidence` and
// `Finding` — AND THE GUARD PASSED IT. That paragraph is case 7 of the table
// below and it is now caught.
//
// Requiring a NAME cannot work, because names are words. So this asks for a
// FORM instead, which is the answer this project has reached three times in
// other places: enumerate the shape the thing must take, and anything outside
// the shape fails by default.
//
// ===========================================================================
// THE TEMPLATE
// ===========================================================================
//
// A comment PARAGRAPH stating a relation must carry, somewhere in it:
//
//	ENFORCED BY <identifier>, MEASURED BY <Test...>
//
// and three things are then checked, weakest last:
//
//	THE FORM      the paragraph matches citationForm at all. Prose naming the
//	              same two identifiers in English does NOT satisfy this, and
//	              that is the entire point: prose accidentally matches a word,
//	              it does not accidentally match a template.
//	THE NAMES     <identifier> resolves against every name this package
//	              declares; <Test...> resolves against every Test function in
//	              this module. A rename that breaks either one turns this red
//	              in the same commit.
//	THE APTNESS   <identifier> is among the identifiers the declaration of
//	              <Test...> REFERENCES — the ast.Ident nodes of its code. This
//	              is the part that makes it more than a spell-check: a
//	              citation cannot name a real rule and a real test that never
//	              touches it.
//
// ===========================================================================
// RULING 17: A REFERENCE IS RESOLVED THROUGH THE SYNTAX TREE
// ===========================================================================
//
// THE APTNESS ARM SHIPPED WITH THE DEFECT RULING 16 HAD JUST REMOVED FROM THE
// LAYER ABOVE IT. It asked whether the cited test's SOURCE mentioned the
// enforcer, and it asked by text search — so an enforcer spelled like an
// English word was mentioned by any test whose prose used the word. A
// citation naming decide and a test in internal/match about advisory return
// order passed. NAMES ARE WORDS, and a text search over source cannot
// separate a reference from a sentence any more than a case boundary could
// separate a name from a noun.
//
// So the question is put to the TREE. A comment contributes no ast.Ident, so
// prose is not in the reference set and the check is decidable rather than
// approximate. The withdrawn rule is still compiled — it is `mentions` — and
// the_text_search_this_replaced_still_admits_the_attack drives it at that
// exact citation on every run, beside the shipped rule refusing it.
//
// DIRECT REFERENCES ONLY. Ruling 17 allows one hop through same-package
// helpers instead; that rule was built and counted and it is the LOOSEST of
// the three, admitting more pairs than the text search it would replace, as
// well as turning case 6 green. Both facts are asserted by
// the_one_hop_rule_this_rejected_is_measurably_looser, and what direct-only
// costs is asserted by cases 22 and 23. The reasoning is at
// declaredTestsInModule.
//
// EVERY CITATION IN THE TWO OWNED FILES IS RESOLVED, whether or not the
// paragraph holding it states a relation; the arithmetic scan alone reached
// only the ones inside claim paragraphs, and two of the citations outside
// them were inapt. See every_citation_in_an_owned_file_resolves_and_is_apt.
//
// ===========================================================================
// EXACTLY WHAT IT CAN SEE, AND EXACTLY WHAT IT CANNOT
// ===========================================================================
//
// A GUARD THAT SILENTLY COVERS LESS THAN IT APPEARS TO IS THE DEFECT THIS
// WHOLE FILE HAS BEEN FIGHTING, so its window is written out here and every
// edge of it is asserted below rather than described.
//
// IT SEES a comparison operator — `<=`, `>=`, `==`, `!=`, or a space-delimited
// `<` or `>` — surviving in a comment paragraph of confirm_gate.go or
// confirm_gate_test.go AFTER commentProse has been applied to every line of
// it. Paragraphs are split on blank comment lines, and a godoc display block
// (every line tab-indented) is folded into the prose paragraph that introduces
// it, because a bare indented equation cannot carry a citation of its own.
//
// "SURVIVING" AND "AFTER" ARE THE WHOLE OF IT, AND THIS SENTENCE USED TO SAY
// NEITHER. It read that the scanner sees an operator "in a `//` comment in
// confirm_gate.go or confirm_gate_test.go", which overstates the window in
// two directions and MEASURING IT IS THE ONLY WAY TO KNOW BY HOW MUCH:
//
//	184 of the two files' 6,211 comment NODES carry a comparison operator in
//	their RAW text. The scanner counts 40 of them, inside 20 claim
//	paragraphs. The other 144 are not seen, and NONE of them is unexplained:
//	126 are banner rules, where a line of equals signs is literally a row of
//	`==` and commentProse blanks it, and 18 are operators inside backticks or
//	double quotes, which commentProse removes. There is no third cause.
//	The counts are produced, not remembered, by
//	the_window_is_exactly_what_commentProse_leaves.
//
// THE UNIT IS THE ast.Comment NODE, AND THIS PARAGRAPH USED TO CALL IT A LINE
// WHILE PRINTING THE NODE COUNT. The two are not the same number. Every `//`
// comment is one node on one line, so for almost all of these two files they
// agree — but the two block comments in confirm_gate_test.go share a SINGLE
// line, so the nodes run one ahead of the physical lines they sit on: 6,211
// against 6,210. A count reported under the wrong unit is the same defect this
// whole section was built to catch, one unit further down, so both figures are
// now measured and both are pinned.
//
// A BLANKED LINE ALSO SPLITS A PARAGRAPH, which is why the banner arm is
// worth stating rather than waving at: a rule of equals signs between a claim
// and its citation puts them in different paragraphs, and the claim is then
// reported uncited. That direction fails loudly and is safe. The unsafe
// direction is the one the corrected sentence names — an operator that does
// not survive commentProse is an operator this guard never had.
//
// IT ALSO READS BLOCK COMMENTS, not only `//` ones. There are exactly 2 of
// them in the two files and they occupy ONE line between them: the two inline
// argument labels in the call decide's precedence table is driven through. An
// older sentence excluded block comments in prose while the code read them,
// and the sentence that corrected it called them "2 such lines" — the same
// node-for-line substitution, on the smallest population in the file, where it
// is off by a factor of two.
//
// IT DOES NOT SEE, and each of these is a real hole:
//
//	A FALSE CLAIM THAT FILLS THE TEMPLATE IN CORRECTLY. THIS IS THE CEILING
//	    ON THE WHOLE IDEA AND IT IS MEASURED, not conceded: case 19 of the
//	    table below is a paragraph asserting a ceiling of 4096 and a floor of
//	    1024 — both false — over a citation naming a real enforcer and a real
//	    test that really does drive it, and the scanner reports it clean. What
//	    the form buys is that the false sentence and the code that refutes it
//	    are now named in the same paragraph. It does not read either one.
//	RELATIONS WRITTEN IN ENGLISH. "more of the response than the pattern
//	    spells", "half the span bound", "twice the floor", "at most", "bounded
//	    by" — no operator, no detection. EVERY DEFECT THE ROUND THAT BUILT
//	    THIS GUARD WAS SENT TO FIX WAS OF EXACTLY THAT SHAPE, including the
//	    one about decide()'s rule 2 that four rounds walked past and this
//	    round finally fixed: it names a rule by number and states a routing,
//	    and there is not an operator in it. This guard would still not catch
//	    it. What it does is stop the NEXT author adding an uncited one in the
//	    form it can read, and force a citation onto the paragraphs around the
//	    prose, which is where a reader checking a sentence would start.
//	ANYTHING IN BACKTICKS OR DOUBLE QUOTES. `re.Op == OpAlternate` is a
//	    specimen and "q <= L/2 <= 256" is a quoted withdrawal, not a live
//	    claim. Deliberate, and asserted as a decision below.
//	A TIGHT `<` OR `>`. `<h1[0-9A-Za-z]{0,400}` is an HTML tag and `len(x)>0`
//	    is a code fragment. Requiring spaces is what keeps those out, and it
//	    is also how an author could hide a claim from this guard.
//	A SECOND RELATION IN A PARAGRAPH THAT ALREADY CARRIES A CITATION. Every
//	    CITATION is checked, so a resolving one cannot launder a broken one
//	    beside it — case 11. THE CONVERSE IS FALSE and it is where most of
//	    this file already sits: the unit checked is the PARAGRAPH, so one
//	    citation covers however many relations are written under it. MEASURED
//	    by one_citation_still_covers_every_relation_in_its_paragraph: 12 of
//	    the 20 claim paragraphs state more than one, and the widest states
//	    seven. Splitting the unit at the sentence was not attempted; the
//	    counts are here so nobody has to guess what that would be worth.
//	A COINCIDENTAL SPELLING IN ANOTHER PACKAGE. Aptness resolves names, not
//	    symbols, so a test in a package that has never heard of this one
//	    satisfies a citation by binding a variable with the same spelling.
//	    Case 24 asserts it against a real one. Locally bound names inside the
//	    cited test count as references for the same reason.
//	coverage.go AND coverage_test.go, which are in this package and outside
//	    D.27's write scope. Widening the window is one entry in `owned` below;
//	    the reason it has not been widened is scope, not difficulty. What that
//	    costs is measured, not guessed, by the window_excludes_the_two
//	    _unowned_files_in_this_package case below.
//	STRINGS, plan/*.md, AND EVERY OTHER PACKAGE. Comments only, here only.
func TestEveryArithmeticClaimInACommentCitesAnEnforcerAndAMeasurement(t *testing.T) {
	// The files this packet owns. See the window disclosure above.
	owned := map[string]bool{"confirm_gate.go": true, "confirm_gate_test.go": true}

	tests, callees := declaredTestsInModule(t)
	fset := token.NewFileSet()
	idents, files := declaredIdentsInPackage(t, fset)

	claims, uncited := 0, 0
	for name, f := range files {
		if !owned[name] {
			continue
		}
		n, bad := scanArithmeticClaims(fset, f, idents, tests)
		claims += n
		for _, v := range bad {
			uncited++
			t.Errorf("%s:%d states a relation and %s.\n"+
				"    %s\n"+
				"An arithmetic claim a reader cannot follow to the code that enforces "+
				"it and the test that measures it is read as evidence and is not any. "+
				"Put `ENFORCED BY <identifier>, MEASURED BY <Test...>` in this "+
				"paragraph, or stop asserting the relation.",
				name, v.line, v.defect, v.first)
		}
	}
	if claims < 12 {
		t.Fatalf("only %d arithmetic claims were found across %d owned files; these two "+
			"files argue in inequalities on nearly every page and a scan finding this "+
			"few is not reading them", claims, len(owned))
	}
	t.Logf("resolved %d arithmetic claims; %d uncited", claims, uncited)

	// ===================================================================
	// EVERY CITATION, NOT ONLY THE ONES STANDING IN A CLAIM. The scan
	// above only opens a paragraph that carries a comparison operator, so
	// a citation in a paragraph arguing in English was never resolved at
	// all — MEASURED: the two owned files carry 31 citations and the
	// arithmetic scan checks 25 of them. Six sat outside the window, and
	// TWO OF THE SIX WERE INAPT, including the self-certifying one case 21
	// is about. A citation is a promise to the reader wherever it is
	// written, so all of them are resolved here.
	// ===================================================================
	t.Run("every_citation_in_an_owned_file_resolves_and_is_apt", func(t *testing.T) {
		checked, inClaims := 0, 0
		for name, f := range files {
			if !owned[name] {
				continue
			}
			for _, g := range f.Comments {
				for _, p := range paragraphsOf(fset, g) {
					text := strings.Join(p.lines, "\n")
					cites := citationForm.FindAllStringSubmatch(text, -1)
					if relationOp.MatchString(text) {
						inClaims += len(cites)
					}
					for _, c := range cites {
						checked++
						if d := citationDefect(idents, tests, c[1], c[2]); d != "" {
							t.Errorf("%s:%d %s.\n    %s", name, p.line, d,
								strings.TrimSpace(p.lines[0]))
						}
					}
				}
			}
		}
		t.Logf("resolved %d citations across the owned files; %d of them stand in a "+
			"paragraph the arithmetic scan opens", checked, inClaims)
		for _, tc := range []struct {
			what      string
			got, want int
		}{
			{"citations in the owned files", checked, 31},
			{"of those, ones the arithmetic scan reaches", inClaims, 25},
		} {
			if tc.got != tc.want {
				t.Errorf("%s: %d, and the disclosure above says %d. Move the sentence "+
					"in this diff", tc.what, tc.got, tc.want)
			}
		}
		if checked <= inClaims {
			t.Fatal("this arm no longer reaches any citation the arithmetic scan " +
				"misses, so it is duplicating work; delete it and the paragraph above " +
				"it rather than keeping a green tautology")
		}
	})

	// ===================================================================
	// THE ANTI-LAUNDERING PROPERTY, IN BOTH DIRECTIONS. The disclosure
	// above says a resolving citation cannot launder a broken one beside
	// it. TRUE, and case 11 drives it. THE CONVERSE IS FALSE and it was
	// stated nowhere: the unit checked is the PARAGRAPH, so one citation
	// covers every relation written in it, however many there are. The
	// count is produced here rather than described.
	// ===================================================================
	t.Run("one_citation_still_covers_every_relation_in_its_paragraph", func(t *testing.T) {
		multi, single := 0, 0
		worst := 0
		for name, f := range files {
			if !owned[name] {
				continue
			}
			for _, g := range f.Comments {
				for _, p := range paragraphsOf(fset, g) {
					text := strings.Join(p.lines, "\n")
					n := len(relationOp.FindAllString(text, -1))
					if n == 0 {
						continue
					}
					if n > 1 {
						multi++
					} else {
						single++
					}
					if n > worst {
						worst = n
					}
				}
			}
		}
		t.Logf("%d of %d claim paragraphs state more than one relation; the most "+
			"any single paragraph states is %d, and one citation covers all of it",
			multi, multi+single, worst)
		if multi == 0 {
			t.Fatal("no owned paragraph states more than one relation any more. That " +
				"would make the citation-per-claim ratio one, and the concession this " +
				"subtest exists to measure would be gone — delete it and the sentence " +
				"it measures rather than keeping a green zero")
		}
		for _, tc := range []struct {
			what      string
			got, want int
		}{
			{"claim paragraphs stating more than one relation", multi, 12},
			{"claim paragraphs in the owned files", multi + single, 20},
			{"relations in the widest single paragraph", worst, 7},
		} {
			if tc.got != tc.want {
				t.Errorf("%s: %d, and the hole disclosed above says %d. Move the "+
					"sentence in this diff", tc.what, tc.got, tc.want)
			}
		}
	})

	// ===================================================================
	// THE WINDOW, ASSERTED. Every line of the disclosure above is a claim
	// about this scanner, so each one is driven against a synthetic source
	// rather than trusted. A guard whose own boundary is undescribed is the
	// thing it exists to prevent.
	// ===================================================================
	// `defect` IS NOT DECORATION AND IT WAS ADDED BECAUSE THE COUNT ALONE
	// MEASURED NOTHING. Disabling BOTH resolution arms — the enforcer's and
	// the measurement's — and re-running this table left it entirely GREEN:
	// an undeclared enforcer is also an enforcer the cited test does not
	// mention, and an undeclared test carries an empty declaration that
	// mentions nothing either, so the aptness arm was silently answering for
	// all three. Asserting WHICH arm fired is what separates them.
	for _, tc := range []struct {
		name   string
		src    string
		want   int
		defect string
		why    string
	}{
		{
			name:   "1_a_relation_with_no_citation_at_all",
			defect: "carries no citation in the form",
			src: "package p\n" +
				"// The unspelled part is at most 256, because q <= 256 always.\n" +
				"func f() {}\n",
			want: 1,
			why:  "this is the case the whole guard exists for",
		},
		{
			name: "2_a_relation_carrying_the_template",
			src: "package p\n" +
				"// q <= 256 always. ENFORCED BY matchQuotesMoreThanItSpells,\n" +
				"// MEASURED BY TestTheConfirmationBoundaryIsPinnedOnBothArms.\n" +
				"func f() {}\n",
			want: 0,
			why:  "a fully cited claim is what the guard is asking for",
		},
		{
			name:   "3_the_same_two_names_in_english_prose",
			defect: "carries no citation in the form",
			src: "package p\n" +
				"// q <= 256 always: matchQuotesMoreThanItSpells is the rule and\n" +
				"// TestTheConfirmationBoundaryIsPinnedOnBothArms pins both arms of it.\n" +
				"func f() {}\n",
			want: 1,
			why: "RULING 16. This paragraph PASSED the previous guard and it names " +
				"exactly the right pair — but a citation is a form, and reading names " +
				"out of prose is what let the English nouns counted by the_shape_this" +
				"_replaced_is_still_measurably_vacuous serve as enforcers",
		},
		{
			name:   "4_a_citation_to_a_test_that_does_not_exist",
			defect: "as its measurement, and this module declares no such test",
			src: "package p\n" +
				"// q <= 256 always. ENFORCED BY matchQuotesMoreThanItSpells,\n" +
				"// MEASURED BY TestThisNameHasNeverBeenDeclaredAnywhereInThisModule.\n" +
				"func f() {}\n",
			want: 1,
			why:  "the citation is RESOLVED; an invented test name is worse than none",
		},
		{
			name:   "5_a_citation_to_an_identifier_this_package_does_not_declare",
			defect: "as its enforcer, and this package declares no such identifier",
			src: "package p\n" +
				"// q <= 256 always. ENFORCED BY enforceTheCeilingSomewhereElse,\n" +
				"// MEASURED BY TestTheConfirmationBoundaryIsPinnedOnBothArms.\n" +
				"func f() {}\n",
			want: 1,
			why:  "an enforcer nobody declared cannot be read",
		},
		{
			name:   "6_a_real_enforcer_and_a_real_test_that_never_touches_it",
			defect: "references that enforcer",
			src: "package p\n" +
				"// q <= 256 always. ENFORCED BY matchQuotesMoreThanItSpells,\n" +
				"// MEASURED BY TestModelInferenceIsNeverConfirmed.\n" +
				"func f() {}\n",
			want: 1,
			why: "THE APTNESS CHECK, and the reason this is more than a spell-check. " +
				"Both names resolve. The test is real and green. Its code has nothing " +
				"to do with the over-broadness rule, so the citation is a dead end. " +
				"IT IS ALSO THE CASE THAT DISQUALIFIED ONE-HOP: that test drives " +
				"ConfirmFinding, ConfirmFinding consults this enforcer, and a rule " +
				"following the production call graph would report this paragraph clean",
		},
		{
			name:   "7_the_verifiers_attack_citing_only_english_nouns",
			defect: "carries no citation in the form",
			src: "package p\n" +
				"// The Evidence a Finding carries is capped at 4096, so len(span) <= 4096\n" +
				"// holds for every Finding, and a span may run to 1024 bytes.\n" +
				"func f() {}\n",
			want: 1,
			why: "THE REGRESSION. Both figures are false, the paragraph cites nothing " +
				"its author intended, and `Evidence` and `Finding` are declared types " +
				"with a case boundary — which is all the previous guard asked for",
		},
		{
			name: "8_an_all_lower_case_declared_identifier",
			src: "package p\n" +
				"// Rule 4 is reached only after rules 2 and 3, so matches == 0 alone\n" +
				"// does not decide it. ENFORCED BY decide,\n" +
				"// MEASURED BY TestDecideTablePrecedenceIsAsDocumented.\n" +
				"func f() {}\n",
			want: 0,
			why: "THE PRICE THE PREVIOUS SHAPE CHARGED, NOW REFUNDED. `decide` has no " +
				"case boundary and could not carry a citation under enforcerShape; " +
				"under a template the spelling of the name stops mattering",
		},
		{
			name:   "9_the_doc_comment_of_a_test_function",
			defect: "carries no citation in the form",
			src: "package p\n" +
				"// TestSomething drives matchQuotesMoreThanItSpells at q <= 256.\n" +
				"func TestSomething() {}\n",
			want: 1,
			why: "THE EXEMPTION IS WITHDRAWN. The previous guard treated a Test's own " +
				"doc comment as self-measuring, which made the whole enforcer half " +
				"optional across the file's largest body of prose",
		},
		{
			name:   "10_an_in_body_comment_inside_a_test_function",
			defect: "carries no citation in the form",
			src: "package p\n" +
				"// TestSomething drives matchQuotesMoreThanItSpells.\n" +
				"func TestSomething() {\n" +
				"\t// A second relation, q <= 128 this time, with nothing named.\n" +
				"}\n",
			want: 1,
			why: "a claim buried in a test body is not measured by the enclosing test " +
				"merely by being there",
		},
		{
			name:   "11_two_citations_one_of_them_broken",
			defect: "as its enforcer, and this package declares no such identifier",
			src: "package p\n" +
				"// q <= 256 always. ENFORCED BY matchQuotesMoreThanItSpells,\n" +
				"// MEASURED BY TestTheConfirmationBoundaryIsPinnedOnBothArms, and\n" +
				"// ENFORCED BY noSuchIdentifierIsDeclared,\n" +
				"// MEASURED BY TestTheConfirmationBoundaryIsPinnedOnBothArms.\n" +
				"func f() {}\n",
			want: 1,
			why: "every citation is checked. A resolving one standing beside a broken " +
				"one would otherwise launder it",
		},
		{
			name: "12_a_relation_inside_backticks",
			src: "package p\n" +
				"// The promotion used to ask `re.Op == OpAlternate`, which is a specimen.\n" +
				"func f() {}\n",
			want: 0,
			why:  "a quoted code fragment is not an assertion — DELIBERATE, and a hole",
		},
		{
			name: "13_a_relation_inside_double_quotes",
			src: "package p\n" +
				"// The withdrawn sentence read \"q <= L/2 <= 256\" and is kept as a quotation.\n" +
				"func f() {}\n",
			want: 0,
			why:  "a quoted withdrawal is history, not a live claim — DELIBERATE, and a hole",
		},
		{
			name: "14_a_relation_stated_in_english_with_no_operator",
			src: "package p\n" +
				"// At most half of any inlined span is body the pattern did not spell,\n" +
				"// and never more than twice the floor.\n" +
				"func f() {}\n",
			want: 0,
			why: "THE HOLE THAT MATTERS. Every defect the round that built this guard " +
				"was sent to fix was of this shape, and so was the rule-2 routing claim " +
				"this round fixed. It is asserted here so the limit is measured rather " +
				"than described",
		},
		{
			name: "15_a_tag_like_angle_bracket_and_a_tight_comparison",
			src: "package p\n" +
				"// `<h1[0-9A-Za-z]{0,400}` was accepted, and asserting len(x)>0 is the\n" +
				"// mistake in the other direction.\n" +
				"func f() {}\n",
			want: 0,
			why:  "requiring spaces around a bare < or > is what keeps markup out",
		},
		{
			name:   "16_an_indented_display_equation_under_an_uncited_paragraph",
			defect: "carries no citation in the form",
			src: "package p\n" +
				"// The derivation runs like this and names nothing:\n" +
				"//\n" +
				"//\tq <= L/2 <= 256.\n" +
				"func f() {}\n",
			want: 1,
			why: "a display block is folded into the prose that introduces it, so the " +
				"citation belongs there and cannot be evaded by indenting the equation",
		},
		{
			name: "17_an_indented_display_equation_under_a_cited_paragraph",
			src: "package p\n" +
				"// ENFORCED BY matchQuotesMoreThanItSpells,\n" +
				"// MEASURED BY TestTheConfirmationBoundaryIsPinnedOnBothArms:\n" +
				"//\n" +
				"//\tq <= L/2 <= 256.\n" +
				"func f() {}\n",
			want: 0,
			why:  "the fold has to work in the passing direction too, or it is just noise",
		},
		{
			name: "18_a_banner_rule",
			src: "package p\n" +
				"// ===========================================================\n" +
				"// A SECTION HEADING\n" +
				"// ===========================================================\n" +
				"func f() {}\n",
			want: 0,
			why:  "a rule of equals signs is not a claim about anything",
		},
		{
			name: "19_a_false_claim_that_fills_the_template_in_correctly",
			src: "package p\n" +
				"// The span ceiling is 4096 and no span shorter than 1024 is ever\n" +
				"// inlined, so 1024 <= len(span) <= 4096 for every span this gate\n" +
				"// emits. ENFORCED BY MaxSpanBytes,\n" +
				"// MEASURED BY TestNoFindingReachableStringExceedsTheSpanLimit.\n" +
				"func f() {}\n",
			want: 0,
			why: "THE MEASURED CEILING ON THIS ENTIRE IDEA. Every figure in that " +
				"paragraph is false — the real bound is MaxSpanBytes and there is no " +
				"floor on a span at all — and the citation resolves in all three " +
				"directions, so the scanner reports it clean. THIS IS WHAT THE GUARD " +
				"DOES NOT DO, asserted rather than conceded in prose",
		},
		{
			name:   "20_a_test_that_mentions_the_enforcer_only_in_its_doc_comment",
			defect: "references that enforcer",
			src: "package p\n" +
				"// The floor is not MaxSpanBytes, so q <= 256 rather than 512.\n" +
				"// ENFORCED BY shapeWalk,\n" +
				"// MEASURED BY TestTheStaticLayerMaySplitAndTheGuaranteeStillHolds.\n" +
				"func f() {}\n",
			want: 1,
			why: "THE CONCESSION THIS CASE USED TO ASSERT IS WITHDRAWN. It shipped as " +
				"want:0 — the citation was ACCEPTED because that test's doc comment " +
				"names shapeWalk while no line of its code does. Under ruling 17 the " +
				"check reads the syntax tree, where a comment leaves nothing, so " +
				"prose no longer certifies anything",
		},
		{
			name:   "21_a_claim_paragraph_that_is_the_cited_tests_own_doc_comment",
			defect: "references that enforcer",
			src: "package p\n" +
				"// TestTheStaticLayerMaySplitAndTheGuaranteeStillHolds drives shapeWalk\n" +
				"// at q <= 256. ENFORCED BY shapeWalk,\n" +
				"// MEASURED BY TestTheStaticLayerMaySplitAndTheGuaranteeStillHolds.\n" +
				"func f() {}\n",
			want: 1,
			why: "SELF-CERTIFICATION, KILLED BY CONSTRUCTION. One of the citations this " +
				"file shipped had exactly this shape — a claim in a test's own doc " +
				"comment, measured by that same test, apt because the paragraph making " +
				"the claim mentioned the enforcer. The claim was certifying itself. " +
				"The AST cannot see the paragraph, so the shape stops working without " +
				"a rule against it",
		},
		{
			name:   "22_an_enforcer_the_cited_test_reaches_through_a_helper",
			defect: "references that enforcer",
			src: "package p\n" +
				"// The first answered attempt is taken, so matches == 0 does not\n" +
				"// mean attempt 1. ENFORCED BY ConfirmFinding,\n" +
				"// MEASURED BY TestEvidenceComesFromTheFirstApplicationAnsweredAttemptNotFromAttemptOne.\n" +
				"func f() {}\n",
			want: 1,
			why: "THE PRICE OF DIRECT-ONLY, ASSERTED. That test is entirely about " +
				"ConfirmFinding's step 4 and it is the right measurement — but it " +
				"drives the gate through confirmAgainst and its code never names " +
				"ConfirmFinding, so this citation is refused",
		},
		{
			name: "23_the_same_citation_naming_the_helper_the_test_calls",
			src: "package p\n" +
				"// The first answered attempt is taken, so matches == 0 does not\n" +
				"// mean attempt 1. ENFORCED BY confirmAgainst,\n" +
				"// MEASURED BY TestEvidenceComesFromTheFirstApplicationAnsweredAttemptNotFromAttemptOne.\n" +
				"func f() {}\n",
			want: 0,
			why: "AND THE REMEDY, ASSERTED BESIDE IT. Ruling 17's answer to a hop is " +
				"that the citation names the helper; confirmAgainst is four lines whose " +
				"middle one is g.ConfirmFinding. This is the form ConfirmFinding's own " +
				"doc comment now uses",
		},
		{
			name: "24_a_test_in_another_package_that_uses_the_same_word_in_its_code",
			src: "package p\n" +
				"// Rule 4 is reached after 2 and 3, so matches == 0 does not decide it.\n" +
				"// ENFORCED BY Error,\n" +
				"// MEASURED BY TestOutputDoesNotDependOnAdvisoryReturnOrder.\n" +
				"func f() {}\n",
			want: 0,
			why: "THE RESIDUAL HOLE, ASSERTED. Names resolve by SPELLING and the cited " +
				"test lives in internal/match, which knows nothing about this package. " +
				"Error is a method this package declares and it is also what that test " +
				"calls on its own error value, and the coincidence is enough. The tree " +
				"closed the prose hole; it did not make identifiers unique across a " +
				"module. THE SAME TEST IS WHAT THE WITHDRAWN RULE FAILED ON, and the " +
				"difference is the size of the opening: prose admitted decide, " +
				"findings and finding as well, which are the names a claim in this " +
				"file would actually want to cite",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sfset := token.NewFileSet()
			f, err := parser.ParseFile(sfset, "synthetic.go", tc.src,
				parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parsing the synthetic source: %v", err)
			}
			_, bad := scanArithmeticClaims(sfset, f, idents, tests)
			if len(bad) != tc.want {
				t.Fatalf("the scanner reported %d uncited claims, want %d. %s.\n"+
					"source:\n%s\nreported: %v", len(bad), tc.want, tc.why, tc.src, bad)
			}
			if (tc.defect != "") != (tc.want != 0) {
				t.Fatalf("this case wants %d defect(s) and names %q as the one it is "+
					"about; a rejecting case with no named defect measures only that "+
					"SOMETHING fired", tc.want, tc.defect)
			}
			if tc.want != 0 && !strings.Contains(bad[0].defect, tc.defect) {
				t.Errorf("the scanner rejected this for the wrong reason.\n"+
					" got: %s\nwant it to contain: %s\n%s\nsource:\n%s",
					bad[0].defect, tc.defect, tc.why, tc.src)
			}
		})
	}

	// ===================================================================
	// WHAT THE WINDOW COSTS, MEASURED. The disclosure above says two files
	// in this package are outside `owned`. A report of this guard once put
	// figures on that exclusion which did not reproduce against the
	// shipped scanner, which is the same defect as a false comment. So the
	// figures live here, produced by the scanner itself, and a change to
	// either file has to move a number in this diff.
	// ===================================================================
	// ===================================================================
	// WHY THE SHAPE THIS REPLACED HAD TO GO, RE-MEASURED HERE RATHER THAN
	// REMEMBERED. The previous guard accepted, as the enforcer citation,
	// any token in the paragraph that resolved to a declared identifier
	// and carried an upper-case letter. That rule is restated below and
	// run — against the population it admits, and against the verifier's
	// attack paragraph, which it accepts. A number quoted in a commit
	// message goes stale the day after; this one is recomputed on every
	// run, and the exact value is logged so a reader never has to trust
	// the floor.
	// ===================================================================
	t.Run("the_shape_this_replaced_is_still_measurably_vacuous", func(t *testing.T) {
		oldEnforcerShape := regexp.MustCompile(`[A-Z]`)
		oldCiteToken := regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]{2,}\b`)
		admits := 0
		for id := range idents {
			if !strings.HasPrefix(id, "Test") && oldEnforcerShape.MatchString(id) &&
				oldCiteToken.MatchString(id) {
				admits++
			}
		}
		t.Logf("the case-boundary shape admits %d of this package's %d declared "+
			"identifiers as enforcer citations", admits, len(idents))
		if admits < 400 {
			t.Errorf("the case-boundary shape admits only %d identifiers. The whole "+
				"argument for ruling 16 is that this population is large enough to "+
				"contain the English nouns this file's prose uses; if it has "+
				"collapsed, re-derive the argument rather than keeping the sentence",
				admits)
		}

		// THE ATTACK, VERBATIM, AGAINST THE OLD RULE. It states two false
		// figures and names nothing its author intended.
		const attack = "The Evidence a Finding carries is capped at 4096, so " +
			"len(span) <= 4096 holds for every Finding, and a span may run to " +
			"1024 bytes."
		accepted := false
		for _, id := range oldCiteToken.FindAllString(attack, -1) {
			if idents[id] && !strings.HasPrefix(id, "Test") &&
				oldEnforcerShape.MatchString(id) {
				accepted = true
				t.Logf("the case-boundary shape reads %q out of the attack paragraph "+
					"as its enforcer citation", id)
			}
		}
		if !accepted {
			t.Error("the attack paragraph no longer satisfies the shape this guard " +
				"replaced. That is not a pass — it means the story told above about " +
				"why the form replaced the name no longer reproduces, and the doc " +
				"has to be rewritten around what does")
		}
		// And the shape that shipped refuses it. Case 7 asserts this over the
		// scanner; here it stands beside the old rule so the two are read
		// together.
		if citationForm.MatchString(attack) {
			t.Error("the attack paragraph matches citationForm, which would make " +
				"case 7 pass for a reason it does not name")
		}
	})

	// ===================================================================
	// RULING 17, RE-MEASURED THE SAME WAY. The aptness arm used to ask
	// whether the cited test's SOURCE mentioned the enforcer. That rule is
	// still compiled — it is `mentions` — and it is run here against the
	// citation it accepts and the shipped rule refuses, so the argument
	// for reading the tree is reproduced on every invocation instead of
	// being quoted from the round that made it.
	// ===================================================================
	t.Run("the_text_search_this_replaced_still_admits_the_attack", func(t *testing.T) {
		// The demonstration, verbatim: an enforcer spelled like an
		// English word, and a test in another package whose prose uses
		// the word while its code has never heard of the rule.
		const enforcer, measurement = "decide", "TestOutputDoesNotDependOnAdvisoryReturnOrder"
		d, ok := tests[measurement]
		if !ok {
			t.Fatalf("%s is not declared in this module any more. The attack this "+
				"guard was rebuilt around cannot be re-run, so re-derive the argument "+
				"against the text search rather than keeping the sentence", measurement)
		}
		if !idents[enforcer] {
			t.Fatalf("this package no longer declares %s, so the attack citation would "+
				"now fail at the resolution arm and would measure nothing about "+
				"aptness", enforcer)
		}
		if !mentions(d.src, enforcer) {
			t.Errorf("%s no longer mentions %s in its source, so the withdrawn rule "+
				"would refuse this citation and the story above no longer reproduces. "+
				"That is not a pass — find the attack that does, or delete the claim",
				measurement, enforcer)
		}
		if d.refs[enforcer] {
			t.Errorf("%s references %s in its code, which would make this citation "+
				"genuinely apt and this subtest a measurement of nothing",
				measurement, enforcer)
		}
		if got := citationDefect(idents, tests, enforcer, measurement); got == "" {
			t.Errorf("the shipped rule ACCEPTS the citation naming %s and %s. Ruling "+
				"17's whole claim is that it does not", enforcer, measurement)
		}

		// AND THE SIZE OF THE OPENING, over one real test rather than in
		// the abstract: how many of this package's declared names that
		// one citation could have named under each rule.
		byText, byTree := 0, 0
		var prose []string
		for id := range idents {
			if strings.HasPrefix(id, "Test") {
				continue
			}
			m, r := mentions(d.src, id), d.refs[id]
			if m {
				byText++
				if !r && len(prose) < 12 {
					prose = append(prose, id)
				}
			}
			if r {
				byTree++
			}
		}
		t.Logf("citing %s: the text search admits %d of this package's %d declared "+
			"names as its enforcer, the syntax tree admits %d. Admitted by prose "+
			"alone: %v", measurement, byText, len(idents), byTree, prose)
		if byText <= byTree {
			t.Errorf("the text search admits %d names and the tree admits %d. The "+
				"argument for ruling 17 is that the first number is the larger one; "+
				"if it is not, this doc is describing a change that did nothing",
				byText, byTree)
		}
	})

	// ===================================================================
	// THE RULE THAT WAS REJECTED, RUN. Ruling 17 offered a hop through
	// same-package helpers as an alternative to direct references.
	// declaredTestsInModule's doc says it was measured and refused; the
	// measurement is here, and the figures are literals in an assertion
	// rather than sentences in a comment, so a change to either layer has
	// to move a number in the same diff.
	// ===================================================================
	t.Run("the_one_hop_rule_this_rejected_is_measurably_looser", func(t *testing.T) {
		// THE DISQUALIFYING FACT FIRST. Case 6 of the table above is the
		// aptness check's reason to exist, and one hop reports it clean.
		const enforcer, measurement = "matchQuotesMoreThanItSpells",
			"TestModelInferenceIsNeverConfirmed"
		six, ok := tests[measurement]
		if !ok {
			t.Fatalf("%s is not declared in this module any more; case 6 is citing a "+
				"test that does not exist and this argument cannot be run", measurement)
		}
		if six.refs[enforcer] {
			t.Fatalf("%s now references %s directly, so case 6 is no longer the "+
				"citation this argument is about", measurement, enforcer)
		}
		if !callees.reach(six)[enforcer] {
			t.Error("one hop no longer reaches " + enforcer + " from " + measurement +
				". That was the fact that disqualified the hop, and if it has stopped " +
				"being true the choice has to be re-argued rather than restated")
		}

		// THE POPULATIONS. Every (declared name, module test) pair the
		// citation form can name, counted under all three rules.
		var ids []string
		for id := range idents {
			if !strings.HasPrefix(id, "Test") {
				ids = append(ids, id)
			}
		}
		words := map[string]map[string]bool{}
		hop := map[string]map[string]bool{}
		for name, d := range tests {
			w := map[string]bool{}
			for _, tok := range citeToken.FindAllString(d.src, -1) {
				w[tok] = true
			}
			words[name] = w
			hop[name] = callees.reach(d)
		}
		// Where "this package" is, taken from a test declared in this very
		// file rather than spelled out, so a move does not silently turn
		// the second row of the measurement into a count of nothing.
		self := "TestEveryArithmeticClaimInACommentCitesAnEnforcerAndAMeasurement"
		here := filepath.Clean(tests[self].pkg)
		if here == "" || here == "." {
			t.Fatalf("cannot locate this package from %s's declaration", self)
		}
		count := func(sameOnly bool) (pairs, text, direct, oneHop int) {
			for _, id := range ids {
				for name, d := range tests {
					if sameOnly && filepath.Clean(d.pkg) != here {
						continue
					}
					pairs++
					if words[name][id] {
						text++
					}
					if d.refs[id] {
						direct++
						oneHop++
						continue
					}
					if hop[name][id] {
						oneHop++
					}
				}
			}
			return pairs, text, direct, oneHop
		}
		pairs, text, direct, oneHop := count(false)
		t.Logf("over %d (declared name, module test) pairs: text %d, direct %d, "+
			"one hop %d", pairs, text, direct, oneHop)
		_, hText, hDirect, hHop := count(true)
		t.Logf("restricted to this package's own tests: text %d, direct %d, "+
			"one hop %d", hText, hDirect, hHop)

		// THE FINDING, ASSERTED RATHER THAN LOGGED, and it is not the one
		// the round expected: one hop is the LOOSEST of the three. It
		// admits more pairs than the text search it was supposed to
		// replace, because a callee carries its whole reference set into
		// every test that names it.
		if !(direct < text && text < oneHop) {
			t.Errorf("the three rules no longer order direct, text, one hop: %d, %d, "+
				"%d. declaredTestsInModule's doc says one hop is the loosest of the "+
				"three, which is why it was refused; if that has stopped being true "+
				"the choice has to be re-argued", direct, text, oneHop)
		}
		if !(hDirect < hText && hText < hHop) {
			t.Errorf("within this package direct admits %d pairs, text %d and one hop "+
				"%d. The same ordering has to hold where this file's citations actually "+
				"point, or the doc is arguing from the module and deciding for the "+
				"package", hDirect, hText, hHop)
		}
	})

	// ===================================================================
	// THE WINDOW, COUNTED RATHER THAN DESCRIBED. The disclosure above used
	// to say the scanner sees an operator "in a // comment in either owned
	// file". It sees an operator that SURVIVES commentProse, which is a
	// much smaller thing, and a disclosure that overstates the window is
	// how a claim ends up written where the guard cannot read it. Every
	// figure in the corrected sentence is produced here.
	//
	// THE THIRD BUCKET IS AN ACCOUNTING IDENTITY, NOT A GUARD, and saying
	// so is the point of writing it down. Given the scanner as it stands
	// the three causes are exhaustive by construction — a line either
	// blanks under commentProse, or loses its operator to a quoted span,
	// or keeps it and therefore lands in a paragraph the scan opens — so
	// the third bucket CANNOT be driven red without editing commentProse
	// or paragraphsOf. It is here to notice exactly that edit. The
	// assertions that carry weight are the pinned counts: they fail the
	// moment the window moves, which is what makes the sentence above
	// checkable rather than decorative.
	// ===================================================================
	t.Run("the_window_is_exactly_what_commentProse_leaves", func(t *testing.T) {
		const (
			banners = "a banner rule or a line of dashes, blanked by commentProse"
			quoted  = "the operator is inside backticks or double quotes"
			unknown = "NO CAUSE THIS TEST KNOWS ABOUT"
		)
		// NODES AND LINES ARE DIFFERENT UNITS AND THIS TEST USED TO
		// REPORT ONE UNDER THE OTHER'S NAME. Every `//` comment is one
		// ast.Comment on one line, so for nearly all of this package the
		// two agree — but a block comment is ONE node however many lines
		// it spans, and two of them can share a line, which is exactly
		// what confirm_gate_test.go does with the two inline argument
		// labels in decide's precedence table. So both are counted, and
		// both are pinned.
		var nodes, block, rawOps, seen int
		physical, blockPhysical := map[string]bool{}, map[string]bool{}
		cause := map[string]int{}
		for name, f := range files {
			if !owned[name] {
				continue
			}
			scanned := map[int]bool{}
			for _, g := range f.Comments {
				for _, p := range paragraphsOf(fset, g) {
					if !relationOp.MatchString(strings.Join(p.lines, "\n")) {
						continue
					}
					for _, n := range p.nums {
						scanned[n] = true
					}
				}
			}
			for _, g := range f.Comments {
				for _, c := range g.List {
					nodes++
					lo := fset.Position(c.Pos()).Line
					hi := fset.Position(c.End()).Line
					isBlock := !strings.HasPrefix(c.Text, "//")
					if isBlock {
						block++
					}
					for n := lo; n <= hi; n++ {
						key := fmt.Sprintf("%s:%d", name, n)
						physical[key] = true
						if isBlock {
							blockPhysical[key] = true
						}
					}
					raw := strings.TrimPrefix(strings.TrimSpace(c.Text), "//")
					if !relationOp.MatchString(raw) {
						continue
					}
					rawOps++
					if scanned[fset.Position(c.Pos()).Line] {
						seen++
						continue
					}
					switch pr := commentProse(c.Text); {
					case strings.TrimSpace(pr) == "":
						cause[banners]++
					case !relationOp.MatchString(pr):
						cause[quoted]++
					default:
						cause[unknown]++
						t.Errorf("%s:%d carries an operator that survives commentProse "+
							"and sits in no paragraph the scan opened. That is a fourth "+
							"cause and the window disclosure names three.\n    %s",
							name, fset.Position(c.Pos()).Line, strings.TrimSpace(raw))
					}
				}
			}
		}
		t.Logf("%d comment nodes on %d physical lines (%d block-comment nodes "+
			"on %d line(s)); %d nodes carry an operator in raw text; "+
			"%d are scanned; unseen by cause: %v",
			nodes, len(physical), block, len(blockPhysical), rawOps, seen, cause)
		for _, tc := range []struct {
			what string
			got  int
			want int
		}{
			{"comment NODES in the two owned files", nodes, 6211},
			{"physical LINES those nodes occupy", len(physical), 6210},
			{"block-comment NODES among them", block, 2},
			{"physical lines those block comments occupy", len(blockPhysical), 1},
			{"comment NODES whose RAW text carries an operator", rawOps, 184},
			{"of those, lines the scan opens", seen, 40},
			{"unseen because " + banners, cause[banners], 126},
			{"unseen because " + quoted, cause[quoted], 18},
			{"unseen for any other reason", cause[unknown], 0},
		} {
			if tc.got != tc.want {
				t.Errorf("%s: %d, and the window disclosure above says %d. Re-measure "+
					"and move the sentence in this diff; a figure a reader cannot "+
					"reproduce is the defect this guard is for", tc.what, tc.got, tc.want)
			}
		}
	})

	t.Run("window_excludes_the_two_unowned_files_in_this_package", func(t *testing.T) {
		for _, tc := range []struct {
			file            string
			claims, uncited int
		}{
			{"coverage.go", 2, 2},
			{"coverage_test.go", 4, 4},
		} {
			f, ok := files[tc.file]
			if !ok {
				t.Fatalf("%s is not in this package any more; the exclusion "+
					"disclosed above is describing a file that does not exist", tc.file)
			}
			if owned[tc.file] {
				t.Fatalf("%s is now owned; delete this case and the disclosure "+
					"it measures", tc.file)
			}
			n, bad := scanArithmeticClaims(fset, f, idents, tests)
			if n != tc.claims || len(bad) != tc.uncited {
				t.Errorf("%s holds %d relation-stating paragraph(s), %d of them "+
					"uncited; the disclosure says %d and %d.\nreported: %v",
					tc.file, n, len(bad), tc.claims, tc.uncited, bad)
			}
		}
	})
}

// claimSite is one comment paragraph that states a relation, together with
// what is wrong with the way it cites itself.
type claimSite struct {
	line   int
	first  string
	defect string
}

var (
	// relationOp is the FORM a claim has to take to be visible here. A bare
	// `<` or `>` must be space-delimited: `<h1` is markup and `len(x)>0` is
	// a code fragment, and neither is an assertion about arithmetic.
	relationOp = regexp.MustCompile(`(<=|>=|==|!=| < | > )`)
	// quotedSpan is what a comment quotes rather than claims: a backticked
	// specimen, a double-quoted sentence, or an arrow.
	quotedSpan = regexp.MustCompile("(`[^`]*`|\"[^\"]*\"|->|<-|=>|<[A-Za-z][A-Za-z0-9_]*>)")
	// citationForm IS THE TEMPLATE, and it is the whole of ruling 16.
	//
	// THE SHAPE THIS REPLACED ASKED FOR A NAME AND THAT IS UNSATISFIABLE,
	// MEASURED: the previous guard accepted any token in the paragraph that
	// resolved to a declared identifier and carried an upper-case letter,
	// on the theory that a case boundary separates a NAME from an English
	// word. That shape admits 435 of this package's 757 declared
	// identifiers, ordinary English nouns among them, and a verifier's
	// paragraph asserting a ceiling of 4096 (real: MaxSpanBytes) passed it
	// on the strength of the words Evidence and Finding. Both figures are
	// recomputed on every run by
	// the_shape_this_replaced_is_still_measurably_vacuous rather than
	// quoted here.
	//
	// NAMES ARE WORDS, so no rule about spelling can tell one from the
	// other. A FORM is not a word: ordinary prose does not accidentally
	// write `ENFORCED BY x, MEASURED BY TestY`, and anything outside the
	// form fails by default, which is the shape this project has landed on
	// three times elsewhere. `\s+` rather than a literal space because the
	// two names together are wider than a comment line and the citation has
	// to be allowed to wrap.
	citationForm = regexp.MustCompile(
		`ENFORCED\s+BY\s+([A-Za-z_][A-Za-z0-9_]*),\s+MEASURED\s+BY\s+(Test[A-Za-z0-9_]+)`)
	// testDeclLine finds a test function declaration in a source file.
	testDeclLine = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	// citeToken is how the WITHDRAWN aptness rule read a declaration: as a
	// bag of words. It is used only by the two subtests that re-run the
	// rules this guard replaced, so their arguments are measured rather
	// than remembered.
	citeToken = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

// mentions reports whether name occurs in src as a whole word.
//
// IT IS THE WITHDRAWN APTNESS RULE AND NOTHING SHIPPED CALLS IT. It was the
// aptness half of the citation check until ruling 17, and it is kept for the
// same reason the previous ruling's rule is kept: so the argument against it
// is RE-RUN rather than remembered. Its one caller is
// the_text_search_this_replaced_still_admits_the_attack, which drives it at
// the citation the shipped rule refuses.
//
// A TEXT SEARCH OVER SOURCE CANNOT TELL A REFERENCE FROM A SENTENCE, for
// exactly the reason a case boundary could not tell a name from a noun: names
// are words, and a test's doc comment is source too.
func mentions(src, name string) bool {
	for i := 0; ; {
		j := strings.Index(src[i:], name)
		if j < 0 {
			return false
		}
		s := i + j
		e := s + len(name)
		beforeOK := s == 0 || !isIdentByte(src[s-1])
		afterOK := e == len(src) || !isIdentByte(src[e])
		if beforeOK && afterOK {
			return true
		}
		i = s + 1
	}
}

func isIdentByte(b byte) bool {
	return b == '_' || ('0' <= b && b <= '9') ||
		('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

// commentProse strips a comment line down to what it ASSERTS: the marker goes,
// quoted spans go, and a rule of equals or dashes becomes empty.
func commentProse(text string) string {
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "//")
	s = quotedSpan.ReplaceAllString(s, " ")
	if strings.Trim(strings.TrimSpace(s), "=-") == "" {
		return ""
	}
	return s
}

// scanArithmeticClaims reports how many comment paragraphs in f state a
// relation, and which of those do not carry a resolving citation in the
// template form.
//
// THREE THINGS HAVE TO HOLD and they are checked in this order, because each
// is a weaker guarantee than the one before it dressed as the same sentence:
// the paragraph carries the FORM at all; the two names in it RESOLVE — the
// enforcer against this package's declarations, the measurement against the
// module's test declarations; and the cited test REFERENCES the cited
// enforcer, which is what stops a citation naming a real rule and a real test
// that have nothing to do with each other.
//
// RULING 17 IS THE THIRD ONE. It reads the cited test's REFERENCE SET — the
// ast.Ident nodes of its declaration — and not its source, so prose in the
// test's doc comment cannot satisfy a citation. See referencedIdents and
// declaredTestsInModule for what that set contains and what choosing it cost.
//
// Every citation in the paragraph is checked, not the first one that passes.
// A paragraph is allowed to cite two rules, and a good citation standing
// beside a broken one would otherwise launder it. A CITATION IS NOT LAUNDERED
// BY ANOTHER CITATION; A CLAIM IS STILL LAUNDERED BY ANOTHER CLAIM, because
// the unit checked here is the PARAGRAPH and a paragraph may state several
// relations under one citation. That asymmetry is measured, not conceded, by
// one_citation_still_covers_every_relation_in_its_paragraph.
func scanArithmeticClaims(fset *token.FileSet, f *ast.File,
	idents map[string]bool, tests map[string]testDecl) (claims int, uncited []claimSite) {
	for _, g := range f.Comments {
		for _, p := range paragraphsOf(fset, g) {
			text := strings.Join(p.lines, "\n")
			if !relationOp.MatchString(text) {
				continue
			}
			claims++
			site := func(defect string) {
				uncited = append(uncited, claimSite{
					line: p.line, first: strings.TrimSpace(p.lines[0]), defect: defect,
				})
			}
			cites := citationForm.FindAllStringSubmatch(text, -1)
			if len(cites) == 0 {
				site("carries no citation in the form " +
					"`ENFORCED BY <identifier>, MEASURED BY <Test...>`")
				continue
			}
			for _, c := range cites {
				if d := citationDefect(idents, tests, c[1], c[2]); d != "" {
					site(d)
				}
			}
		}
	}
	return claims, uncited
}

// citationDefect reports what is wrong with one citation, or the empty string
// if the two names resolve and the measurement is apt.
//
// It is a function of its own rather than a switch inside the scan because
// every_citation_in_an_owned_file_resolves_and_is_apt applies the same three
// checks to the citations that sit in paragraphs stating no relation, which
// the arithmetic scan never looks at.
func citationDefect(idents map[string]bool, tests map[string]testDecl,
	enforcer, measurement string) string {
	d, declared := tests[measurement]
	switch {
	case !idents[enforcer]:
		return fmt.Sprintf("names %s as its enforcer, and this package "+
			"declares no such identifier", enforcer)
	case !declared:
		return fmt.Sprintf("names %s as its measurement, and this module "+
			"declares no such test", measurement)
	case !d.refs[enforcer]:
		return fmt.Sprintf("cites %s and %s, and nothing in that test's code "+
			"references that enforcer — the citation points at an unrelated "+
			"measurement. Naming it in the test's PROSE does not count: a "+
			"comment leaves no node in the syntax tree this is read from",
			enforcer, measurement)
	}
	return ""
}

// commentParagraph is a run of comment lines with no blank line in it.
type commentParagraph struct {
	line  int
	lines []string
	// nums is the source line of each entry in lines. A folded display
	// block makes the two non-contiguous, which is why the numbers are
	// carried rather than derived from line. Only
	// the_window_is_exactly_what_commentProse_leaves reads them, to work
	// out which comment lines the scan actually looked at.
	nums []int
}

// paragraphsOf splits a comment group on blank comment lines and folds a godoc
// display block — a paragraph whose every line is tab-indented — into the
// prose that introduces it. An equation on its own indented line has nowhere
// to put a citation, and the paragraph above it is where a reader looks.
func paragraphsOf(fset *token.FileSet, g *ast.CommentGroup) []commentParagraph {
	var split []commentParagraph
	cur := commentParagraph{line: -1}
	for _, c := range g.List {
		s := commentProse(c.Text)
		if strings.TrimSpace(s) == "" {
			if len(cur.lines) > 0 {
				split = append(split, cur)
			}
			cur = commentParagraph{line: -1}
			continue
		}
		if cur.line < 0 {
			cur.line = fset.Position(c.Pos()).Line
		}
		cur.lines = append(cur.lines, s)
		cur.nums = append(cur.nums, fset.Position(c.Pos()).Line)
	}
	if len(cur.lines) > 0 {
		split = append(split, cur)
	}

	var folded []commentParagraph
	for _, p := range split {
		indented := true
		for _, l := range p.lines {
			if len(l) > 0 && l[0] != '\t' {
				indented = false
				break
			}
		}
		if indented && len(folded) > 0 {
			folded[len(folded)-1].lines = append(folded[len(folded)-1].lines, p.lines...)
			folded[len(folded)-1].nums = append(folded[len(folded)-1].nums, p.nums...)
			continue
		}
		folded = append(folded, p)
	}
	return folded
}

// testDecl is one Test function's declaration, reduced to the two things a
// citation is checked against.
type testDecl struct {
	// refs is every identifier the declaration REFERENCES: the ast.Ident
	// nodes of its parameters, its body and the types it names. It is what
	// the aptness arm reads, and the property that matters is what is NOT
	// in it — a doc comment contributes no ast.Ident, so prose cannot
	// satisfy a citation.
	refs map[string]bool
	// src is the declaration's source, doc comment included. It is kept for
	// ONE purpose: the_text_search_this_replaced_still_admits_the_attack
	// re-runs the withdrawn rule against it on every invocation, so the
	// argument for ruling 17 is measured here rather than quoted from a
	// commit message. Nothing in the shipped check reads it.
	src string
	// pkg is the directory the declaration was parsed from, which is what
	// a one-hop rule would have to resolve callees against. Nothing in the
	// shipped check reads it either.
	pkg string
}

// declaredTestsInModule is every Test function declared anywhere in this
// module, mapped to its declaration, which is the universe a measurement
// citation resolves against. Repo-wide rather than package-local for the
// reason TestEveryTestNamedInASourceCommentExists gives: a comment here may
// legitimately cite one of the kernel's own guards.
//
// ===========================================================================
// RULING 17: A REFERENCE IS RESOLVED THROUGH THE SYNTAX TREE
// ===========================================================================
//
// THIS FUNCTION USED TO RETURN SOURCE TEXT AND THE APTNESS ARM USED TO GREP
// IT, and that arm had, one layer down, the exact defect ruling 16 had just
// removed from the layer above. NAMES ARE WORDS: a text search cannot tell a
// reference from a sentence, so an enforcer spelled like an English word was
// "mentioned" by any test whose prose used the word. The demonstration is not
// described here, it is RE-RUN on every invocation by
// the_text_search_this_replaced_still_admits_the_attack: a citation naming
// decide and a test in internal/match about advisory return order passes the
// withdrawn rule and fails the shipped one.
//
// The tree is the answer, and it is decidable rather than approximate. A
// comment contributes no ast.Ident, so the reference set is exactly what the
// test's CODE names.
//
// DIRECT REFERENCES ONLY, AND THE ALTERNATIVE WAS BUILT BEFORE IT WAS
// REJECTED. Ruling 17 offers a hop through same-package helpers for the case
// where a test reaches its enforcer through something it calls. Both rules
// were run over every (declared identifier, module test) pair the citation
// form can name, and the counts are asserted as literals by
// the_one_hop_rule_this_rejected_is_measurably_looser rather than written
// out here, because a figure in a comment goes stale and a figure in an
// assertion cannot. Two findings decided it:
//
//	ONE HOP IS NOT A NARROWING AT ALL. It admits MORE pairs than the text
//	search it was supposed to replace — module-wide and again when the
//	count is restricted to this package's own tests, which is where this
//	file's citations point. A callee carries its entire reference set into
//	every test that names it, and a test naming three helpers inherits
//	three transitive sets, so the population grows rather than shrinks.
//	That result was not the one this round expected, which is the reason
//	it is asserted from a live count instead of reasoned about.
//
//	IT TURNS CASE 6 OF THE TABLE ABOVE GREEN, which is disqualifying rather
//	than merely loose. Case 6 is a real enforcer cited against a real test
//	that has nothing to do with it — the aptness check's entire reason for
//	existing — and it survives only under direct references.
//
// THE PRICE OF DIRECT-ONLY IS ONE CITATION AND IT IS PAID IN THE OPEN.
// ConfirmFinding's step 4 is measured by a test that drives it through
// confirmAgainst, so that citation names confirmAgainst — ruling 17's own
// remedy — with ConfirmFinding named in the prose beside it. Cases 22 and 23
// below assert both halves.
//
// WHAT DIRECT-ONLY STILL CANNOT SEE is that the reference set is every
// ast.Ident in the declaration, locally bound names included, and that names
// are resolved by SPELLING, so a test in another package that happens to use
// the same word satisfies a citation. Case 24 asserts the second one against
// a real coincidence.
func declaredTestsInModule(t *testing.T) (map[string]testDecl, calleeIndex) {
	t.Helper()
	declared := map[string]testDecl{}
	callees := calleeIndex{}
	root := filepath.Join("..", "..", "..")
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
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := string(b)
		tfset := token.NewFileSet()
		f, perr := parser.ParseFile(tfset, path, src,
			parser.ParseComments|parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parsing %s for its test declarations: %w", path, perr)
		}
		dir := filepath.Dir(path)
		isTest := strings.HasSuffix(d.Name(), "_test.go")
		for _, dec := range f.Decls {
			fd, ok := dec.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if !isTest || !strings.HasPrefix(fd.Name.Name, "Test") {
				if callees[dir] == nil {
					callees[dir] = map[string]map[string]bool{}
				}
				callees[dir][fd.Name.Name] = referencedIdents(fd)
				continue
			}
			start := fd.Pos()
			if fd.Doc != nil {
				start = fd.Doc.Pos()
			}
			lo := tfset.Position(start).Offset
			hi := tfset.Position(fd.Body.Rbrace).Offset
			if lo < 0 || hi <= lo || hi >= len(src) {
				return fmt.Errorf("%s: %s has an unreadable declaration span",
					path, fd.Name.Name)
			}
			declared[fd.Name.Name] = testDecl{
				refs: referencedIdents(fd),
				src:  src[lo : hi+1],
				pkg:  dir,
			}
		}
		if !isTest {
			return nil
		}
		// The regex walk is kept as a CROSS-CHECK on the parse: a test the
		// AST did not reach is a test a measurement citation would fail to
		// resolve, silently, which is this guard's own failure mode.
		for _, m := range testDeclLine.FindAllStringSubmatch(src, -1) {
			if _, ok := declared[m[1]]; !ok {
				return fmt.Errorf("%s declares %s and the AST walk did not see it",
					path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module for test declarations: %v", err)
	}
	if len(declared) < 100 {
		t.Fatalf("found %d test functions in the module; the walk is not working and "+
			"every measurement citation would resolve for the wrong reason", len(declared))
	}
	// The positive control on the REFERENCE half of the walk. Resolving the
	// name alone proved the test existed; this proves the tree under it was
	// read, and without it an empty reference set would refuse every
	// citation for a reason no message would name.
	if !declared["TestDecideTablePrecedenceIsAsDocumented"].refs["decide"] {
		t.Fatal("the walk cannot see that TestDecideTablePrecedenceIsAsDocumented " +
			"references decide, which it does on its own line. The reference sets " +
			"are not being built and every aptness check would fail for the wrong " +
			"reason")
	}
	return declared, callees
}

// calleeIndex is directory -> function name -> reference set, for every
// non-Test function in the module.
//
// NOTHING IN THE SHIPPED CHECK READS IT. It exists so that
// the_one_hop_rule_this_rejected_is_measurably_looser can RUN the alternative
// ruling 17 offered rather than describe it, and so the table in
// declaredTestsInModule's doc is recomputed on every invocation instead of
// being remembered from the round that wrote it.
type calleeIndex map[string]map[string]map[string]bool

// reach is the reference set ONE HOP out: every identifier referenced by any
// same-package function this declaration names.
func (c calleeIndex) reach(d testDecl) map[string]bool {
	out := map[string]bool{}
	for callee := range d.refs {
		for id := range c[d.pkg][callee] {
			out[id] = true
		}
	}
	return out
}

// referencedIdents is every identifier the declaration REFERENCES: every
// ast.Ident under it, less its own name.
//
// THE POINT IS WHAT IS ABSENT. Comments are not ast.Ident nodes, so a doc
// comment naming the enforcer contributes nothing here, and that single fact
// is what turns the aptness check from a text search into a decision. A
// selector's field or method name IS included — `f.Evidence()` references
// Evidence — because this package's citations legitimately name methods and
// struct fields.
//
// LOCALLY BOUND NAMES ARE INCLUDED TOO, and that is a hole rather than a
// decision: a test declaring a variable spelled like a package identifier
// satisfies a citation to it. Excluding them was built and measured, and it
// changed the verdict on none of the citations this file carries, so the
// simpler set is the one that ships.
func referencedIdents(fd *ast.FuncDecl) map[string]bool {
	refs := map[string]bool{}
	ast.Inspect(fd, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			refs[id.Name] = true
		}
		return true
	})
	delete(refs, fd.Name.Name)
	return refs
}

// declaredIdentsInPackage is every name this package declares — functions,
// methods, constants, variables, types and struct fields — which is the
// universe an enforcer citation resolves against. Fields are included because
// a claim about spanOverBroadBytes or minLiteral names a field, and a guard
// that could not see one would push authors towards vaguer citations.
func declaredIdentsInPackage(t *testing.T, fset *token.FileSet) (map[string]bool, map[string]*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	idents := map[string]bool{}
	files := map[string]*ast.File{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, perr := parser.ParseFile(fset, e.Name(), nil,
			parser.ParseComments|parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parsing %s: %v", e.Name(), perr)
		}
		files[e.Name()] = f
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				idents[v.Name.Name] = true
			case *ast.ValueSpec:
				for _, id := range v.Names {
					idents[id.Name] = true
				}
			case *ast.TypeSpec:
				idents[v.Name.Name] = true
			case *ast.Field:
				for _, id := range v.Names {
					idents[id.Name] = true
				}
			}
			return true
		})
	}
	// The positive control on the walk: it must see the two names every
	// arithmetic paragraph in this file leans on.
	for _, must := range []string{"matchQuotesMoreThanItSpells", "MaxUnspelledBytes"} {
		if !idents[must] {
			t.Fatalf("the package walk cannot see %s; it is reading the wrong tree and "+
				"every enforcer citation would fail for the wrong reason", must)
		}
	}
	return idents, files
}

// ===========================================================================
// D.31 — THE WITHDRAWN-PHRASING REGISTRY
// ===========================================================================

// withdrawnPhrasing is one sentence this package has RETRACTED as false,
// together with how many times it is still allowed to appear as a QUOTATION.
//
// THE REGISTRY EXISTS BECAUSE OF A COUNTED FAILURE, not a worry. Five
// consecutive rounds were each sent to correct a false sentence and each left
// exactly one behind, and the fifth left THE SAME ONE: the wording in entry 1
// below was corrected at length in confirm_gate.go and stood verbatim, at a
// different line wrapping, in confirm_gate_test.go. A false sentence that
// exists in two files was being half-corrected, and a human sweep cannot stop
// that, because the second copy is only findable by somebody who already knows
// about the first.
//
// THIS PARAGRAPH USED TO PUT THE TWO COPIES "1,331 lines away" FROM EACH
// OTHER, and so did the paragraph on
// TestARejectionThatCouldNotHaveDisprovedAnythingIsRefused. It was not a
// measurement of anything: the copies are in DIFFERENT FILES, and a line count
// between two files does not reproduce, so neither figure could be checked by
// the reader it was written for. What does reproduce is the part that mattered
// — the two copies were wrapped differently — and cases 1 and 2 below are the
// two wrappings, run on every invocation.
//
// The registry turns that into a mechanical fact: once a wording is entered
// here it cannot be asserted anywhere in this package again, so correcting
// one copy and leaving the other is a RED TEST rather than a missed line.
type withdrawnPhrasing struct {
	// text is the withdrawn wording. Line wrapping does not matter — it is
	// collapsed before matching, which is what makes the two differently
	// wrapped copies of entry 1 the same string.
	text string
	// wantQuoted is how many times this package still QUOTES the wording in
	// order to refute it. Pinned rather than merely permitted: an entry
	// whose quotation has been deleted is an entry nobody can check any
	// more, and it would go silently vacuous.
	wantQuoted int
	why        string
}

var withdrawnPhrasings = []withdrawnPhrasing{
	{
		text: "decide()'s rule 2 routes every indecisive run to " +
			"ReasonReprobeIndecisive before ReasonDidNotReproduce can be reached",
		wantQuoted: 1,
		why: "FALSE IN BOTH HALVES. Rule 2 is the over-quoted rule and it routes " +
			"to ReasonMatchQuotedTheResponse, so it is not what takes an " +
			"indecisive run anywhere near ReasonReprobeIndecisive; and " +
			"ReasonDidNotReproduce is not a reason an indecisive run could reach " +
			"in the first place, so there is no ordering between the two to " +
			"state. The surviving quotation is in assertRejectionIsDecisive's " +
			"doc comment in confirm_gate.go, where it is quoted and then refuted",
	},
	{
		text: "With no exported field and no exported constructor outside this " +
			"file, the only EvidenceRef that exists is one newEvidenceRef built, " +
			"and newEvidenceRef bounds its span",
		wantQuoted: 1,
		why: "IT CREDITED A FUNCTION THAT HAS NEVER EXISTED. There is no " +
			"newEvidenceRef in this package, so the sentence attributed a real " +
			"invariant to a mechanism a reader could not go and read — which is " +
			"worse than saying nothing, because it stops them looking. What " +
			"actually holds the invariant up is listed on EvidenceRef itself, " +
			"where the quotation now sits",
	},
}

// TestNoWithdrawnPhrasingSurvivesAsLiveProse is the streak-breaker.
//
// ===========================================================================
// WHAT IT DOES
// ===========================================================================
//
// For every entry in withdrawnPhrasings it reads every .go file in this
// package and sorts the occurrences of that wording into three piles:
//
//	LIVE      the wording appears in a comment, outside any quotation. This
//	          is a retracted sentence being asserted again, and it FAILS.
//	QUOTED    the wording appears inside a double-quoted or backticked span
//	          in a comment. That is the historical record refuting itself,
//	          and the count is pinned by wantQuoted.
//	OUTSIDE   the wording appears in the file but in no comment — a string
//	          literal. It FAILS: a refusal message restating a withdrawn
//	          sentence is the same defect wearing a different hat.
//
// THE REGISTRY'S OWN DECLARATION IS EXEMPT FROM BOTH ARMS, and it has to be,
// because withdrawnPhrasings holds every withdrawn wording as a string
// literal and the OUTSIDE arm reads string literals. The two entries that
// shipped first escaped only because their text is written as a line-wrapped
// concatenation, which no rule anywhere required — `" + "` lands in the middle
// of the sentence and the needle stops matching. AN AUTHOR WRITING ENTRY THREE
// AS ONE STRING LITERAL WOULD HAVE TURNED THIS TEST RED ON ITS OWN CONTENTS,
// with a message telling them a refusal message was restating a retracted
// claim. That was a precondition dressed up as a weakness, so it is a
// precondition no more: scanWithdrawn locates the withdrawnPhrasings
// declaration in whatever file it is reading and blanks that byte range out of
// the raw arm, and skips comments inside it. The registry is the DEFINITION of
// the withdrawn text and definitions are not assertions. Its doc comment is
// not exempt — a GenDecl's span starts at the `var` keyword — because a doc
// comment is prose like any other. Cases 8, 9 and 10 assert all three.
//
// Matching is done on COLLAPSED prose: comment markers are replaced by spaces
// and every run of whitespace becomes one space. That is the whole mechanism,
// and it is the part that matters. The two copies of entry 1 were wrapped
// differently — one broke the line after "every indecisive", the other after
// "every" — so any check comparing lines, or comparing raw source, would have
// seen two different strings. Collapsed, they are one.
//
// THE SCAN IS PACKAGE-WIDE, not scoped to the two files D.27 owns. Reading is
// free and a retracted sentence resurfacing in coverage.go is worth knowing
// about; the failure message says so, because fixing it there is a REPORT and
// not an edit under this packet's write scope.
//
// ===========================================================================
// WHAT IT CANNOT SEE, AND THIS IS THE PRICE OF THE WHOLE IDEA
// ===========================================================================
//
//	A FALSE SENTENCE NOBODY HAS REGISTERED. This is a denylist, which is the
//	    shape this file distrusts everywhere else, and the distrust is
//	    correct: it finds nothing new. What it makes impossible is the
//	    HALF-CORRECTION of something already found, which is the failure that
//	    actually recurred five times running. The two jobs are different and
//	    only the second is mechanisable at this price.
//	A PARAPHRASE. Change one word of a registered sentence and it is
//	    invisible here. Asserted, not conceded, by case 6 below.
//	A WORDING SPLIT ACROSS A Go STRING CONCATENATION. The outside-comments
//	    arm reads the raw file, where two adjacent literals do not collapse
//	    into one string, so a withdrawn sentence assembled from a pair of
//	    them is not matched.
//	ANY FILE OUTSIDE THIS PACKAGE DIRECTORY, including plan/*.md, where the
//	    standing orders already record two stale lines.
func TestNoWithdrawnPhrasingSurvivesAsLiveProse(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	if len(withdrawnPhrasings) == 0 {
		t.Fatal("the registry is empty, so this test measures nothing. It is not a " +
			"place to keep a zero — delete the test or enter the sentence")
	}

	for i, w := range withdrawnPhrasings {
		needle := collapseProse(w.text)
		if needle == "" {
			t.Fatalf("registry entry %d collapses to nothing: %q", i+1, w.text)
		}
		quoted, asserted, inStrings := 0, 0, 0
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			b, rerr := os.ReadFile(e.Name())
			if rerr != nil {
				t.Fatalf("reading %s: %v", e.Name(), rerr)
			}
			wfset := token.NewFileSet()
			f, perr := parser.ParseFile(wfset, e.Name(), b,
				parser.ParseComments|parser.SkipObjectResolution)
			if perr != nil {
				t.Fatalf("parsing %s: %v", e.Name(), perr)
			}
			live, q, outside := scanWithdrawn(wfset, f, string(b), needle)
			quoted += q
			asserted += len(live)
			if outside > 0 {
				inStrings += outside
			}
			for _, line := range live {
				t.Errorf("%s:%d ASSERTS A WITHDRAWN SENTENCE.\n"+
					"    %s\n"+
					"Why it was withdrawn: %s.\n"+
					"This wording is entry %d of withdrawnPhrasings. It may appear "+
					"inside a quotation, where it is history being refuted, and "+
					"nowhere else. If this file is outside D.27's write scope, that "+
					"is a REPORT to the orchestrator, not an edit.",
					e.Name(), line, w.text, w.why, i+1)
			}
			if outside > 0 {
				t.Errorf("%s restates a withdrawn sentence %d time(s) outside any "+
					"comment — a string literal.\n    %s\n"+
					"A refusal message repeating a retracted claim is the same defect "+
					"the comment was", e.Name(), outside, w.text)
			}
			if outside < 0 {
				t.Fatalf("%s: the comment arm found more occurrences than the whole "+
					"file does, so the two arms are not reading the same text and "+
					"this test's own numbers cannot be trusted", e.Name())
			}
		}
		if quoted != w.wantQuoted {
			t.Errorf("the withdrawn sentence\n    %s\nis quoted %d time(s) in this "+
				"package and the registry says %d. A quotation is how the retraction "+
				"stays readable; if it was deliberately deleted, move wantQuoted in "+
				"this diff so the entry does not go silently vacuous",
				w.text, quoted, w.wantQuoted)
		}
		t.Logf("entry %d across %d package file(s): %d asserted, %d quoted, "+
			"%d in string literals", i+1, len(entries), asserted, quoted, inStrings)
	}

	// ===================================================================
	// THE MECHANISM, ASSERTED. Every line of the description above is a
	// claim about scanWithdrawn, so each is driven against a synthetic
	// source rather than trusted — including the two holes it cannot see.
	// ===================================================================
	sentence := withdrawnPhrasings[0].text
	needle := collapseProse(sentence)

	for _, tc := range []struct {
		name                    string
		src                     string
		wantLive                int
		wantQuoted, wantOutside int
		why                     string
	}{
		{
			name: "1_the_wording_wrapped_the_way_confirm_gate_go_wrapped_it",
			src: "package p\n" +
				"// It read: decide()'s rule 2 routes every indecisive\n" +
				"// run to ReasonReprobeIndecisive before ReasonDidNotReproduce can be reached.\n" +
				"func f() {}\n",
			wantLive: 1,
			why:      "one of the two wrappings that actually shipped",
		},
		{
			name: "2_the_wording_wrapped_the_way_confirm_gate_test_go_wrapped_it",
			src: "package p\n" +
				"// it returned non-zero zero times, because decide()'s rule 2 routes every\n" +
				"// indecisive run to ReasonReprobeIndecisive before ReasonDidNotReproduce can\n" +
				"// be reached. The report that called it a second line was wrong.\n" +
				"func f() {}\n",
			wantLive: 1,
			why: "THE COPY FIVE ROUNDS WALKED PAST. It breaks lines in three different " +
				"places from case 1 and it is the same sentence; this is the case that " +
				"makes the half-correction impossible rather than unlikely",
		},
		{
			name:     "3_the_wording_on_one_unwrapped_line",
			src:      "package p\n// " + sentence + "\nfunc f() {}\n",
			wantLive: 1,
			why:      "a third wrapping, to show the collapse is not tuned to the two real ones",
		},
		{
			name: "4_the_wording_inside_a_quotation",
			src: "package p\n" +
				"// The withdrawn sentence read \"decide()'s rule 2 routes every indecisive\n" +
				"// run to ReasonReprobeIndecisive before ReasonDidNotReproduce can be reached\"\n" +
				"// and rule 2 is the over-quoted rule, so it is false.\n" +
				"func f() {}\n",
			wantQuoted: 1,
			why: "the refutation has to be allowed to restate what it refutes, or the " +
				"registry would delete the historical record it depends on",
		},
		{
			name: "5_the_wording_in_a_string_literal",
			src: "package p\n" +
				"func f() string { return \"" + sentence + "\" }\n",
			wantOutside: 1,
			why:         "a refusal message is prose too, and it is outside every comment",
		},
		{
			name: "6_a_paraphrase",
			src: "package p\n" +
				"// Rule 2 of decide() sends any indecisive run to ReasonReprobeIndecisive\n" +
				"// before ReasonDidNotReproduce is ever considered.\n" +
				"func f() {}\n",
			why: "THE HOLE, ASSERTED. Same false claim, different words, entirely " +
				"invisible here. A registry is a denylist and this is what a denylist " +
				"costs; it is written down rather than discovered later",
		},
		{
			name: "7_an_unrelated_comment_naming_the_same_rule",
			src: "package p\n" +
				"// decide()'s rule 2 is the over-quoted rule.\n" +
				"func f() {}\n",
			why: "the control. A comment that names the same function and the same rule " +
				"number is not the withdrawn sentence, and a check that fired here " +
				"would be unusable",
		},
		{
			name: "8_a_registry_entry_written_as_one_unbroken_literal",
			src: "package p\n" +
				"type withdrawnPhrasing struct{ text string }\n" +
				"var withdrawnPhrasings = []withdrawnPhrasing{\n" +
				"\t{text: \"" + sentence + "\"},\n" +
				"}\n",
			why: "THE PRECONDITION, REMOVED. The two shipped entries escape the OUTSIDE " +
				"arm only because their text happens to be a line-wrapped " +
				"concatenation; written as one literal, an entry used to report itself " +
				"as a refusal message restating a retracted claim. The registry is the " +
				"definition of the wording and is now blanked before the raw arm reads " +
				"anything",
		},
		{
			name: "9_the_same_literal_in_a_variable_that_is_not_the_registry",
			src: "package p\n" +
				"var refusalText = \"" + sentence + "\"\n",
			wantOutside: 1,
			why: "THE CONTROL ON CASE 8. What is exempt is the declaration named " +
				"withdrawnPhrasings, not string literals in general; a refusal message " +
				"carrying the same sentence is still the defect the comment was",
		},
		{
			name: "10_a_doc_comment_on_the_registry_asserting_the_sentence",
			src: "package p\n" +
				"type withdrawnPhrasing struct{ text string }\n" +
				"\n" +
				"// " + sentence + "\n" +
				"var withdrawnPhrasings = []withdrawnPhrasing{}\n",
			wantLive: 1,
			why: "THE EXEMPTION STOPS AT THE `var` KEYWORD. A GenDecl's position is its " +
				"token, so the doc comment above the registry is prose like any other " +
				"and asserting a withdrawn sentence there still fails",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sfset := token.NewFileSet()
			f, perr := parser.ParseFile(sfset, "synthetic.go", tc.src,
				parser.ParseComments|parser.SkipObjectResolution)
			if perr != nil {
				t.Fatalf("parsing the synthetic source: %v", perr)
			}
			live, quoted, outside := scanWithdrawn(sfset, f, tc.src, needle)
			if len(live) != tc.wantLive || quoted != tc.wantQuoted ||
				outside != tc.wantOutside {
				t.Fatalf("scanWithdrawn = %d live, %d quoted, %d outside; want "+
					"%d, %d, %d. %s\nsource:\n%s",
					len(live), quoted, outside,
					tc.wantLive, tc.wantQuoted, tc.wantOutside, tc.why, tc.src)
			}
		})
	}
}

// whitespaceRun is every run of spaces, tabs and newlines, which is exactly
// what line wrapping is made of.
var whitespaceRun = regexp.MustCompile(`\s+`)

// collapseProse reduces source text to the prose it contains, so that two
// copies of one sentence wrapped at different columns become one string.
//
// Comment markers become spaces before the collapse, because a wrapped
// sentence has a `//` sitting in the middle of it and that is the whole
// reason the two shipped copies of entry 1 did not look alike.
func collapseProse(s string) string {
	s = strings.ReplaceAll(s, "//", " ")
	return strings.TrimSpace(whitespaceRun.ReplaceAllString(s, " "))
}

// quotationSpan is what a comment QUOTES rather than asserts. It is the same
// distinction quotedSpan draws for the arithmetic guard, narrowed to the two
// forms a retraction actually uses.
var quotationSpan = regexp.MustCompile("(`[^`]*`|\"[^\"]*\")")

// occurrencesOf counts every occurrence of needle in hay and how many of them
// fall entirely inside a quotation.
func occurrencesOf(hay, needle string) (total, quoted int) {
	regions := quotationSpan.FindAllStringIndex(hay, -1)
	for i := 0; ; {
		j := strings.Index(hay[i:], needle)
		if j < 0 {
			return total, quoted
		}
		s := i + j
		e := s + len(needle)
		total++
		for _, r := range regions {
			if r[0] <= s && e <= r[1] {
				quoted++
				break
			}
		}
		i = s + 1
	}
}

// scanWithdrawn sorts one file's occurrences of needle into the three piles
// TestNoWithdrawnPhrasingSurvivesAsLiveProse describes: live comment prose
// (returned as the line of each offending comment group), quotations, and
// occurrences that are in the file but in no comment at all.
//
// The third pile is computed by DIFFERENCE — everything the raw file holds,
// less everything the comments hold — rather than by walking string literals,
// so a form of literal nobody thought of still lands somewhere countable
// instead of vanishing.
//
// THE REGISTRY'S OWN DECLARATION IS BLANKED FIRST, from both arms, for the
// reason the caller's doc gives: withdrawnPhrasings stores each withdrawn
// wording as a string literal, so without this a registry entry written as one
// unbroken literal reports itself as a restatement. Blanking is done with
// spaces so byte offsets keep lining up, and the collapse afterwards folds the
// run into one space.
func scanWithdrawn(fset *token.FileSet, f *ast.File, src, needle string) (
	live []int, quoted, outside int) {
	span := registryDeclSpan(fset, f, len(src))
	inSpan := func(p token.Pos) bool {
		if span == nil {
			return false
		}
		off := fset.Position(p).Offset
		return off >= span[0] && off < span[1]
	}
	inComments := 0
	for _, g := range f.Comments {
		if inSpan(g.Pos()) {
			continue
		}
		total, q := occurrencesOf(collapseProse(g.Text()), needle)
		inComments += total
		quoted += q
		for i := 0; i < total-q; i++ {
			live = append(live, fset.Position(g.Pos()).Line)
		}
	}
	raw := src
	if span != nil {
		raw = src[:span[0]] + strings.Repeat(" ", span[1]-span[0]) + src[span[1]:]
	}
	rawTotal, _ := occurrencesOf(collapseProse(raw), needle)
	return live, quoted, rawTotal - inComments
}

// registryDeclSpan is the byte range of the withdrawnPhrasings declaration in
// f, or nil if this file does not declare it.
//
// The range runs from the `var` keyword, NOT from the doc comment above it: a
// GenDecl's own position is its token, and exempting the doc would exempt the
// one part of the registry that is prose.
func registryDeclSpan(fset *token.FileSet, f *ast.File, srcLen int) []int {
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR {
			continue
		}
		for _, sp := range g.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				if n.Name != "withdrawnPhrasings" {
					continue
				}
				lo := fset.Position(g.Pos()).Offset
				hi := fset.Position(g.End()).Offset
				if lo < 0 || hi > srcLen || hi <= lo {
					return nil
				}
				return []int{lo, hi}
			}
		}
	}
	return nil
}

// ===========================================================================
// D.32 — A NAME IN PROSE MUST RESOLVE TO A DECLARATION
// ===========================================================================

// proseNameException is one camel-case name this package's prose uses on
// purpose that NOTHING IN THIS MODULE DECLARES OR SPELLS, together with the
// reason it is allowed to stand.
//
// THE REGISTRY IS AN ALLOWLIST AND THAT IS THE WHOLE DIFFERENCE FROM THE ONE
// ABOVE IT. withdrawnPhrasings is a denylist keyed on wording: it makes a
// half-corrected sentence impossible and it finds nothing new, because a
// paraphrase is invisible to it. Six rounds each corrected the sentence they
// were pointed at and left one behind, and the sixth left a false ATTRIBUTION
// rather than a false wording — a doc crediting a constructor that has never
// existed. The registry behaved exactly as designed and the defect walked
// past it.
//
// A name is not a wording. It either resolves to something a reader can go and
// read or it does not, and that question needs no list of sentences somebody
// remembered to write down. So the rule is the general one — every camel-case
// name in these two files' comments must resolve — and the exceptions are
// enumerated here, where a new dangling name fails by default and a deliberate
// one is a visible, reviewed entry.
type proseNameException struct {
	// name is the token as it appears in prose.
	name string
	// why is the reason a reader will not find it in the tree. An entry
	// without one is refused: the registry is a review record, not a
	// silencer.
	why string
}

// proseNamesWithNoDeclaration is every such name in confirm_gate.go and
// confirm_gate_test.go, grouped by why the tree does not hold it.
//
// EVERY ENTRY IS PINNED IN BOTH DIRECTIONS by
// TestEveryNameInProseResolvesToADeclaration: an entry whose name has stopped
// appearing in the two files is a stale exemption and fails, and an entry
// whose name the module has since declared is an exemption that now hides a
// real resolution and fails too. Neither can go quietly vacuous.
var proseNamesWithNoDeclaration = []proseNameException{
	// ----------------------------------------------------------------
	// NAMES THIS PACKAGE ONCE HAD, OR NEVER HAD. These four are the
	// reason the sweep exists; every other group below is the tokenizer
	// being honest about what it cannot tell apart.
	// ----------------------------------------------------------------
	{
		name: "newEvidenceRef",
		why: "NEVER DECLARED, ANYWHERE, EVER — and it is the defect this whole " +
			"guard was built for. Two paragraphs credited an EvidenceRef " +
			"constructor by that name. One was withdrawn at length and the other " +
			"stood underneath the withdrawal, in live prose, for six rounds. Both " +
			"surviving mentions now narrate a name that does not exist, which is " +
			"the only honest way to say so, and entry 2 of withdrawnPhrasings " +
			"keeps the retracted sentence itself from coming back",
	},
	{
		name: "spanTruncatedFrom",
		why: "DELETED BY RENAME. It is the field spanOverBroadBytes replaced, and " +
			"the rename was the fix rather than a tidy-up — truncating an " +
			"over-broad match still inlines a raw body prefix. Both mentions are " +
			"about the removal. A reader who goes looking for it should find " +
			"nothing, and finding nothing is the point",
	},
	{
		name: "IndecisiveRejectionCount",
		why: "DELETED METHOD. Ledger carried it, a sweep of ConfirmAll measured it " +
			"unreachable from production, and assertRejectionIsDecisive states the " +
			"same invariant where it can fire. All three mentions are about its " +
			"replacement",
	},
	{
		name: "defensiveStatuses",
		why: "DELETED VARIABLE. It was the four-status denylist that the " +
			"application-answered allowlist inverted, and it is named once, in the " +
			"paragraph explaining the inversion",
	},

	// ----------------------------------------------------------------
	// SYNTHETIC NAMES — invented for a worked example or a template, and
	// declared nowhere on purpose.
	// ----------------------------------------------------------------
	{
		name: "TestY",
		why: "SYNTHETIC. The measurement half of the citation template, standing " +
			"for whatever test an author is about to name. A real test called TestY " +
			"would make the template unreadable",
	},
	{
		name: "zzCarrier",
		why: "SYNTHETIC. A two-field struct in the worked example of how the " +
			"closure walker marks a type it has already seen. It exists to be " +
			"walked in prose and nowhere else",
	},
	{
		name: "AloneAreACleanScan",
		why: "A MISSPELLING, QUOTED SO THE CORRECTION IS CHECKABLE. It is the tail " +
			"of a test name as a stale plan line spells it; no test has ever been " +
			"declared with that ending",
	},

	// ----------------------------------------------------------------
	// FRAGMENTS OF SOMETHING LARGER. The tokenizer splits on word
	// boundaries, and these are pieces of a command line or of a pattern
	// rather than names anybody wrote.
	// ----------------------------------------------------------------
	{
		name: "BenignCorpus",
		why: "A FRAGMENT OF A COMMAND LINE. It is one alternative inside the -bench " +
			"regex of the reproduction command for the benchmark figures. The " +
			"declared names that regex selects, BenchmarkBenignCorpusBuild and " +
			"buildBenignCorpus, both resolve on their own lines",
	},
	{
		name: "RefuseOverBroad",
		why: "A FRAGMENT OF THE SAME COMMAND LINE, selecting " +
			"BenchmarkRefuseOverBroadPattern, which resolves on the line above it",
	},
	{
		name: "zA",
		why: "A FRAGMENT OF A CHARACTER CLASS. It is the middle of `[a-zA-Z]` and " +
			"of `[0-9a-zA-Z]`, which this file quotes as regex specimens on nearly " +
			"every page. A tokenizer cannot tell a specimen from a name, and this " +
			"is the shape of that cost",
	},
	{
		name: "eyJ",
		why: "A LITERAL, NOT A NAME. The three bytes every JWT begins with, and the " +
			"literal footing of the pattern the over-broad rule is worked through",
	},

	// ----------------------------------------------------------------
	// WORDS THAT ARE NOT NAMES AT ALL, but that carry an internal
	// capital.
	// ----------------------------------------------------------------
	{
		name: "KiB",
		why:  "A UNIT. Binary kibibytes, in the body-cap and corpus arithmetic",
	},
	{
		name: "MiB",
		why:  "A UNIT. Binary mebibytes, in the same arithmetic",
	},
	{
		name: "BASE64URL",
		why: "A SHOUTED WORD, not a name. The digit-then-capital inside it reads to " +
			"camelCased as a name boundary, which is the one place that rule is " +
			"looser than the English it is trying to skip",
	},
	{
		name: "GitHub",
		why:  "A PROPER NOUN, in the provenance of a real-world secret pattern",
	},
	{
		name: "GitLab",
		why:  "A PROPER NOUN, in the same list",
	},
	{
		name: "OpenAI",
		why:  "A PROPER NOUN, in the same list",
	},
	{
		name: "ModSecurity",
		why: "A PROPER NOUN. The WAF that ships the two configurable block statuses " +
			"the answered-as-application allowlist has to reason about",
	},
}

// TestEveryNameInProseResolvesToADeclaration is ruling 18, mechanised.
//
// ===========================================================================
// WHAT IT DOES
// ===========================================================================
//
// It reads every comment in confirm_gate.go and confirm_gate_test.go, pulls
// out every camel-case token, and requires each one to be a name this module
// actually holds. A token that is not, and is not registered in
// proseNamesWithNoDeclaration, FAILS.
//
// THE UNIVERSE IS DECLARED-OR-SPELLED, and the second half is a deliberate
// widening with a measured price. Declared alone is every function, method,
// type, constant, variable and field name in the module. That set does not
// hold OpAlternate, SelectorExpr, MatchString or WriteString, all of which
// this file's prose names correctly and a reader can go and read: they are
// declared in the standard library and SPELLED by this module's code. So the
// universe is both, and a name in prose must be a name the module's own syntax
// tree spells somewhere. moduleNameUniverse returns the two sets separately so
// the widening is counted on every run rather than assumed.
//
// THE TOKEN RULE IS A LOWER-TO-UPPER TRANSITION and nothing else. bodyHash has
// one, hash does not, MEASURED does not, and Finding does not either. That
// last one is a real hole rather than an oversight and it is asserted below: a
// single capitalised word is a sentence opener as often as it is a type, and a
// sweep that read them would fire on the first word of half the paragraphs in
// this file. Underscores are separators rather than name characters, so a
// subtest name like the_window_is_exactly_what_commentProse_leaves contributes
// commentProse and a pile of English.
//
// ===========================================================================
// WHAT IT CANNOT SEE — MEASURED, NOT CONCEDED
// ===========================================================================
//
// Each of these is driven against a synthetic source by the reach table below,
// so the disclosure is produced rather than remembered.
//
//	A FALSE ATTRIBUTION TO A NAME THAT DOES EXIST. Rewrite the defect this
//	    guard was built for as "e came from NewSignature" and it passes
//	    clean: NewSignature is a real declaration in this very file, and
//	    nothing here reads what it does. This is the ceiling on the whole
//	    idea. What the sweep buys is that the name a paragraph credits is now
//	    a name a reader can go and check, which is where checking has to
//	    start. Case 4.
//	A FALSE ATTRIBUTION TO A SINGLE-WORD NAME. "came from decide", "came
//	    from Finding" — no case boundary, no token, no check. Case 5.
//	A FALSE ATTRIBUTION IN ENGLISH. "the value came from the constructor"
//	    names nothing at all, so there is nothing to resolve. Case 6.
//	A REGISTERED NAME IN A BRAND NEW FALSE SENTENCE. Once newEvidenceRef is
//	    an entry in the registry it may be written anywhere in these two
//	    files, including into a fresh claim that it constructs something. The
//	    registry exempts the NAME, not the sentence; the sentence is
//	    withdrawnPhrasings' job, and only for wordings somebody has entered.
//	A NAME IN A STRING LITERAL. Comments only. A refusal message naming a
//	    dead function is out of reach here, where the withdrawn-phrasing scan
//	    would see it. Case 7.
//	ANY FILE OTHER THAN THE TWO. Package-wide would be free to read, but
//	    coverage.go and coverage_test.go are outside this packet's write
//	    scope, and a red test nobody may fix is a red test somebody disables.
//	    Widening it is one entry in owned below.
//
// A NAME INSIDE A QUOTATION IS NOT EXEMPT, unlike the withdrawn-phrasing scan.
// A retracted sentence quoted in order to be refuted is history, but a name
// quoted out of one is still a name a reader will go looking for, so the
// registry is where a quoted dead name gets its disposition. Case 3 asserts
// it, and both quoted mentions of newEvidenceRef are registered for exactly
// that reason.
func TestEveryNameInProseResolvesToADeclaration(t *testing.T) {
	owned := []string{"confirm_gate.go", "confirm_gate_test.go"}

	declared, spelled := moduleNameUniverse(t)
	universe := map[string]bool{}
	for n := range declared {
		universe[n] = true
	}
	widened := 0
	for n := range spelled {
		if !universe[n] {
			universe[n] = true
			widened++
		}
	}
	if widened == 0 {
		t.Fatal("the spelled half of the universe adds nothing, so the walk is " +
			"collecting only declarations and the disclosure above describes a " +
			"widening that is not happening")
	}
	t.Logf("module universe: %d declared, %d spelled-only, %d total",
		len(declared), widened, len(universe))

	// The positive control on the universe, in both halves. A walk that
	// silently returned an empty or partial set would exempt everything.
	for _, must := range []string{
		"matchQuotesMoreThanItSpells", "spanOverBroadBytes", "buildBenignCorpus",
	} {
		if !declared[must] {
			t.Fatalf("the module walk cannot see the declaration of %s, so it is "+
				"reading the wrong tree and every name in prose would resolve for "+
				"the wrong reason", must)
		}
	}
	for _, must := range []string{"OpAlternate", "MatchString"} {
		if declared[must] || !spelled[must] {
			t.Fatalf("%s is supposed to be spelled by this module and declared "+
				"outside it; declared=%v spelled=%v. The widening this test "+
				"discloses is not the widening it is doing",
				must, declared[must], spelled[must])
		}
	}

	registered := map[string]string{}
	for i, e := range proseNamesWithNoDeclaration {
		if e.name == "" || e.why == "" {
			t.Fatalf("registry entry %d has an empty name or an empty reason. An "+
				"exemption nobody justified is a silencer", i+1)
		}
		if _, dup := registered[e.name]; dup {
			t.Fatalf("registry entry %d repeats %s; two reasons for one name means "+
				"one of them is not being read", i+1, e.name)
		}
		if universe[e.name] {
			t.Errorf("registry entry %d exempts %s, and this module now declares or "+
				"spells that name. The exemption is hiding a real resolution: delete "+
				"the entry.\nIt was registered because: %s", i+1, e.name, e.why)
		}
		registered[e.name] = e.why
	}

	seen := map[string]int{}
	total := 0
	for _, name := range owned {
		for tok, lines := range proseNamesIn(t, name, "") {
			total += len(lines)
			seen[tok] += len(lines)
			if universe[tok] {
				continue
			}
			if _, ok := registered[tok]; ok {
				continue
			}
			t.Errorf("%s:%v names %s in a comment, and nothing in this module "+
				"declares or spells it.\n"+
				"A paragraph crediting a mechanism a reader cannot go and read is "+
				"worse than one crediting nothing, because it stops them looking. "+
				"Either name what the code actually does, or enter %s in "+
				"proseNamesWithNoDeclaration with the reason the tree does not hold "+
				"it.", name, lines, tok, tok)
		}
	}
	if total < 500 {
		t.Fatalf("only %d camel-case name occurrences were found across the two "+
			"files; these files name their own machinery on nearly every page and "+
			"a sweep finding this few is not reading them", total)
	}
	for name, why := range registered {
		if seen[name] == 0 {
			t.Errorf("%s is registered as a name with no declaration and it does not "+
				"appear in either owned file any more. A stale exemption is one "+
				"nobody can review: delete it.\nIts reason was: %s", name, why)
		}
	}
	t.Logf("%d camel-case name occurrences across %d files; %d distinct; "+
		"%d registered exceptions", total, len(owned), len(seen), len(registered))

	// ===================================================================
	// THE MECHANISM AND ITS REACH, DRIVEN. Every line of the disclosure
	// above is a claim about this scan, so each is put to a synthetic
	// source rather than trusted: the catch first, then every hole under
	// it. wantDangling is the set of camel-case names in the source that
	// the universe does not hold.
	// ===================================================================
	for _, tc := range []struct {
		name         string
		src          string
		wantDangling []string
		why          string
	}{
		{
			name: "1_the_attribution_this_guard_was_built_for",
			src: "package p\n" +
				"// Constructed reports whether e came from newEvidenceRef.\n" +
				"func f() {}\n",
			wantDangling: []string{"newEvidenceRef"},
			why: "THE DEFECT, REPLANTED. Six rounds of human sweeping walked past " +
				"this sentence; the scan takes it every time, and it knows nothing " +
				"about evidence, constructors or this package",
		},
		{
			name: "2_a_fresh_dangling_name_nobody_has_ever_seen",
			src: "package p\n" +
				"// The bound is re-checked by assertSpanFootingIsSane on every\n" +
				"// Finding the gate assembles.\n" +
				"func f() {}\n",
			wantDangling: []string{"assertSpanFootingIsSane"},
			why: "THE POINT OF AN ALLOWLIST. This name was invented for this case and " +
				"no denylist could have held it. withdrawnPhrasings is keyed on " +
				"wording and would not have blinked",
		},
		{
			name: "3_a_dangling_name_inside_a_quotation",
			src: "package p\n" +
				"// The withdrawn sentence read \"and newEvidenceRef bounds its\n" +
				"// span\", which credited a function that does not exist.\n" +
				"func f() {}\n",
			wantDangling: []string{"newEvidenceRef"},
			why: "NO QUOTATION EXEMPTION, asserted rather than described. A reader " +
				"chasing a name does not stop at the quotation marks, so the registry " +
				"is where a quoted dead name gets its disposition",
		},
		{
			name: "4_the_same_claim_credited_to_a_name_that_exists",
			src: "package p\n" +
				"// Constructed reports whether e came from NewSignature.\n" +
				"func f() {}\n",
			why: "THE CEILING, MEASURED. Every bit as false as case 1 — Constructed " +
				"reads two fields and NewSignature builds signatures — and clean " +
				"here, because the name resolves. This scan checks that a citation " +
				"can be followed, never that it is true",
		},
		{
			name: "5_the_same_claim_credited_to_a_single_word_name",
			src: "package p\n" +
				"// The span bound is applied by decide rather than by extractSpan.\n" +
				"func f() {}\n",
			why: "THE TOKEN RULE'S HOLE. decide is a real declaration and the sentence " +
				"is false about it, and a one-word name has no case boundary, so " +
				"nothing here would have looked even if it had been invented",
		},
		{
			name: "6_the_same_claim_with_no_name_in_it_at_all",
			src: "package p\n" +
				"// The value can only have come from the constructor, which is\n" +
				"// what bounds it.\n" +
				"func f() {}\n",
			why: "PROSE THAT NAMES NOTHING RESOLVES NOTHING. This is the shape the " +
				"withdrawn sentence had before somebody gave it a name, and it is " +
				"invisible to every mechanical check in this file",
		},
		{
			name: "7_a_name_in_a_string_literal_rather_than_a_comment",
			src: "package p\n" +
				"func f() string { return \"built by newEvidenceRef\" }\n",
			why: "COMMENTS ONLY. The withdrawn-phrasing scan reads literals by " +
				"difference and this one does not, so a refusal message naming a dead " +
				"function is out of reach here",
		},
		{
			name: "8_the_control",
			src: "package p\n" +
				"// extractSpan bounds the match and matchQuotesMoreThanItSpells\n" +
				"// decides whether spanOverBroadBytes is set.\n" +
				"func f() {}\n",
			why: "three real names in one sentence. A scan that fired here would be " +
				"unusable and would be switched off within a round",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := map[string]bool{}
			for _, n := range tc.wantDangling {
				want[n] = true
			}
			got := map[string]bool{}
			for tok := range proseNamesIn(t, "synthetic.go", tc.src) {
				if !universe[tok] {
					got[tok] = true
				}
			}
			for n := range want {
				if !got[n] {
					t.Errorf("the scan did not report %s as dangling. %s\nsource:\n%s",
						n, tc.why, tc.src)
				}
			}
			for n := range got {
				if !want[n] {
					t.Errorf("the scan reported %s as dangling and this case expects "+
						"nothing of the sort. %s\nsource:\n%s", n, tc.why, tc.src)
				}
			}
		})
	}
}

// camelWord is an identifier-shaped run. Underscores are NOT part of one: a
// subtest name is words joined by them, and splitting there is what lets a
// mention of the_window_is_exactly_what_commentProse_leaves resolve
// commentProse instead of failing on the whole token.
var camelWord = regexp.MustCompile(`[A-Za-z][A-Za-z0-9]*`)

// camelCased is the lower-to-upper transition that separates a NAME from a
// word. See TestEveryNameInProseResolvesToADeclaration for what it costs at
// each end.
var camelCased = regexp.MustCompile(`[a-z0-9][A-Z]`)

// camelNamesInComment is every camel-case token in one comment's text.
func camelNamesInComment(text string) []string {
	var out []string
	for _, w := range camelWord.FindAllString(text, -1) {
		if camelCased.MatchString(w) {
			out = append(out, w)
		}
	}
	return out
}

// proseNamesIn maps every camel-case name in filename's COMMENTS to the lines
// carrying it. An empty src means read the file from disk; a non-empty one is
// a synthetic source parsed under that name.
func proseNamesIn(t *testing.T, filename, src string) map[string][]int {
	t.Helper()
	pfset := token.NewFileSet()
	var from any
	if src != "" {
		from = src
	}
	f, err := parser.ParseFile(pfset, filename, from,
		parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s for the names in its prose: %v", filename, err)
	}
	out := map[string][]int{}
	for _, g := range f.Comments {
		for _, c := range g.List {
			line := pfset.Position(c.Pos()).Line
			for _, w := range camelNamesInComment(c.Text) {
				out[w] = append(out[w], line)
			}
		}
	}
	return out
}

// moduleNameUniverse is every name this module DECLARES and every name its
// code SPELLS, returned separately so the second set's contribution can be
// counted rather than assumed.
//
// Declarations are functions, methods, types, constants, variables and fields
// — the same shapes declaredIdentsInPackage collects, module-wide instead of
// package-wide. Spellings are every ast.Ident node, which is what brings in a
// standard-library name this package's code reaches through a selector.
//
// LOCAL BINDINGS ARE IN THE SPELLED SET, since a short variable declaration
// carries an ast.Ident like any other. That is a widening rather than a
// decision, and it is why the spelled half is disclosed and counted.
func moduleNameUniverse(t *testing.T) (declared, spelled map[string]bool) {
	t.Helper()
	declared, spelled = map[string]bool{}, map[string]bool{}
	root := filepath.Join("..", "..", "..")
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
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		mfset := token.NewFileSet()
		f, perr := parser.ParseFile(mfset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parsing %s for the names it holds: %w", path, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				declared[v.Name.Name] = true
			case *ast.ValueSpec:
				for _, id := range v.Names {
					declared[id.Name] = true
				}
			case *ast.TypeSpec:
				declared[v.Name.Name] = true
			case *ast.Field:
				for _, id := range v.Names {
					declared[id.Name] = true
				}
			case *ast.Ident:
				spelled[v.Name] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module for the names it holds: %v", err)
	}
	if len(declared) < 1000 {
		t.Fatalf("the module walk found %d declared names, which is not this "+
			"module. Every name in prose would resolve, or fail, for the wrong "+
			"reason", len(declared))
	}
	return declared, spelled
}
