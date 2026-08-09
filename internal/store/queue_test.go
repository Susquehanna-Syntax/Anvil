package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const (
	recutTargetID      = 1
	recutScanRunID     = 1
	recutAuditRecordID = 1
	recutAuditID       = "1"
	recutTokens        = 10000
)

// recutFixture is one audit with a queue behind it. Every row goes in through
// schema.sql's own constraints, so a fixture that could not exist in production
// fails here rather than proving something about a shape the store forbids.
type recutFixture struct {
	t           *testing.T
	db          *sql.DB
	nextFinding int64
	nextHandoff int64
}

func newRecutFixture(t *testing.T, dastStatus record.DastStatus) *recutFixture {
	t.Helper()
	db := newDB(t)

	mustExec(t, db,
		`INSERT INTO target (target_id, kind, locator) VALUES (?, 'repo', 'https://example.invalid/r.git')`,
		recutTargetID)
	mustExec(t, db,
		`INSERT INTO scan_run (scan_run_id, target_id, trigger_ref, commit_sha, started_at, status, ruleset_version)
		 VALUES (?, ?, 'v1.0.0', 'deadbeef', '2026-08-08T00:00:00Z', ?, 'rs/1')`,
		recutScanRunID, recutTargetID, string(record.ScanRunStatusOK))
	mustExec(t, db,
		`INSERT INTO audit_record (audit_record_id, scan_run_id, schema_version, audit_version, state,
		                           sast_status, sast_sealed_at, dast_status, target_provenance,
		                           deadline_at, payload_sha256, created_at)
		 VALUES (?, ?, ?, 1, ?, ?, '2026-08-08T01:00:00Z', ?, ?, '2026-08-08T08:00:00Z', ?, '2026-08-08T00:00:00Z')`,
		recutAuditRecordID, recutScanRunID, record.SchemaVersion,
		string(record.StateSastSealed), string(record.HalfStatusSealed),
		string(dastStatus), string(record.TargetProvenanceBootedClean),
		"00112233445566778899001122334455667788990011223344556677889900aa")

	return &recutFixture{t: t, db: db, nextFinding: 1, nextHandoff: 1}
}

// detectorFor maps an evidence class onto a legal `finding.detector`. It exists
// so the fixture never writes a bare literal for either vocabulary.
func detectorFor(t *testing.T, class record.EvidenceClass) record.DetectorKind {
	t.Helper()
	switch class {
	case record.EvidenceClassDastConfirmed:
		return record.DetectorKindDast
	case record.EvidenceClassSastReachable, record.EvidenceClassSastStaticOnly:
		return record.DetectorKindSast
	case record.EvidenceClassSCA:
		return record.DetectorKindSCA
	case record.EvidenceClassHost:
		return record.DetectorKindHost
	default:
		t.Fatalf("no detector mapping for evidence class %q", class)
		return ""
	}
}

func consumptionFor(class record.EvidenceClass) record.ConsumptionClass {
	if class == record.EvidenceClassDastConfirmed {
		return record.ConsumptionClassRequiresDynamicConfirmation
	}
	return record.ConsumptionClassStaticOnly
}

// enqueue inserts one finding and one ready handoff row for it, returning the
// handoff_id.
func (f *recutFixture) enqueue(class record.EvidenceClass, severity string) int64 {
	f.t.Helper()

	findingID := f.nextFinding
	handoffID := f.nextHandoff
	f.nextFinding++
	f.nextHandoff++

	detector := detectorFor(f.t, class)
	remediable := 1
	if detector == record.DetectorKindHost {
		remediable = 0
	}
	fp := fmt.Sprintf("%064x", findingID)

	mustExec(f.t, f.db,
		`INSERT INTO finding (finding_id, target_id, fingerprint, detector, evidence_class, rule_id,
		                      remediable_by_agent, severity, title, state, first_seen_scan, first_seen_at)
		 VALUES (?, ?, ?, ?, ?, 'anvil.py.sqli/v3', ?, ?, 'finding', ?, ?, '2026-08-08T00:30:00Z')`,
		findingID, recutTargetID, fp, string(detector), string(class), remediable, severity,
		string(record.FindingStateOpen), recutScanRunID)

	mustExec(f.t, f.db,
		`INSERT INTO handoff (handoff_id, finding_id, audit_record_id, fingerprint, state, consumption_class,
		                      attempts, max_attempts, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, 2, '2026-08-08T00:00:00Z', '2026-08-08T00:00:00Z')`,
		handoffID, findingID, recutAuditRecordID, fp,
		string(record.HandoffStateReady), string(consumptionFor(class)))

	return handoffID
}

func (f *recutFixture) enqueueMany(n int, class record.EvidenceClass, severity string) []int64 {
	f.t.Helper()
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		ids = append(ids, f.enqueue(class, severity))
	}
	return ids
}

// lease moves a ready row to 'leased' with a holder, satisfying
// ck_handoff_lease_requires_holder.
func (f *recutFixture) lease(handoffID int64, worker string) {
	f.t.Helper()
	mustExec(f.t, f.db,
		`UPDATE handoff SET state = ?, claimed_by = ?, lease_expires_at = '2026-08-08T00:20:00Z',
		                    attempts = attempts + 1, updated_at = '2026-08-08T00:05:00Z'
		 WHERE handoff_id = ? AND state = ?`,
		string(record.HandoffStateLeased), worker, handoffID, string(record.HandoffStateReady))
}

// consume walks a row the long way — ready -> leased -> validated — so the
// fixture never implies an edge internal/handoff's state machine forbids. It
// is how the test spends budget between two cuts.
func (f *recutFixture) consume(handoffIDs []int64) {
	f.t.Helper()
	for _, id := range handoffIDs {
		f.lease(id, "worker-consumer")
		mustExec(f.t, f.db,
			`UPDATE handoff SET state = ?, claimed_by = NULL, lease_expires_at = NULL,
			                    updated_at = '2026-08-08T00:10:00Z'
			 WHERE handoff_id = ? AND state = ?`,
			string(record.HandoffStateValidated), id, string(record.HandoffStateLeased))
	}
}

func (f *recutFixture) bumpVersion(to int64, dastStatus record.DastStatus) {
	f.t.Helper()
	mustExec(f.t, f.db,
		`UPDATE audit_record SET audit_version = ?, dast_status = ?, state = ?
		 WHERE audit_record_id = ?`,
		to, string(dastStatus), string(record.StateBothSealed), recutAuditRecordID)
}

func (f *recutFixture) state(handoffID int64) record.HandoffState {
	f.t.Helper()
	var s string
	if err := f.db.QueryRow(`SELECT state FROM handoff WHERE handoff_id = ?`, handoffID).Scan(&s); err != nil {
		f.t.Fatalf("reading handoff %d state: %v", handoffID, err)
	}
	if err := record.ValidateHandoffState(s); err != nil {
		f.t.Fatalf("handoff %d holds an illegal state: %v", handoffID, err)
	}
	return record.HandoffState(s)
}

func (f *recutFixture) countState(s record.HandoffState) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(
		`SELECT COUNT(*) FROM handoff WHERE audit_record_id = ? AND state = ?`,
		recutAuditRecordID, string(s)).Scan(&n); err != nil {
		f.t.Fatalf("counting handoff rows in %s: %v", s, err)
	}
	return n
}

func (f *recutFixture) recutter(cfg RecutConfig) *Recutter {
	f.t.Helper()
	if cfg.TokensPerCandidate == 0 {
		cfg.TokensPerCandidate = recutTokens
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC) }
	}
	r, err := NewRecutter(f.db, cfg)
	if err != nil {
		f.t.Fatalf("NewRecutter: %v", err)
	}
	return r
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %s: %v", firstLine(query), err)
	}
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

func mustRecut(t *testing.T, r *Recutter, remaining int) Cut {
	t.Helper()
	cut, err := r.RecutQueueContext(context.Background(), recutAuditID, remaining)
	if err != nil {
		t.Fatalf("RecutQueueContext(%d): %v", remaining, err)
	}
	return cut
}

// ---------------------------------------------------------------------------
// THE test: the inversion S6 describes, reproduced and then prevented.
// ---------------------------------------------------------------------------

// arrivalSequence is one run of plan/00-SPINE.md S6's scenario, driven by a
// single knob: the reserve fraction. Everything else — the findings, their
// arrival order, the window size, the per-candidate cost — is identical between
// runs, so any difference in outcome is attributable to the reservation and to
// nothing else.
//
// The sequence is the real one, in the real order:
//
//	t0  version 1. The SAST half has sealed. 20 static findings are queued.
//	    NOTHING IS dast_confirmed YET — that is the whole point; the DAST half
//	    is still running, so ranking by evidence class has nothing to rank.
//	t1  the queue is cut against the full window.
//	t2  consumers work everything the cut admitted. Those tokens are gone.
//	t3  the DAST half seals with findings. anvil/version bumps to 2 and five
//	    dast_confirmed findings — each carrying a runtime reproduction — are
//	    enqueued.
//	t4  the queue is re-cut against what is LEFT of the window.
type arrivalOutcome struct {
	firstCut  Cut
	secondCut Cut
	dastIDs   []int64
	sastIDs   []int64
	fixture   *recutFixture
}

func runArrivalSequence(t *testing.T, fraction *float64, window, dastCount int) arrivalOutcome {
	t.Helper()

	// t0 — the DAST half is still running, so late arrivals are possible.
	f := newRecutFixture(t, record.DastStatusRunning)
	sastIDs := f.enqueueMany(20, record.EvidenceClassSastReachable, "high")

	r := f.recutter(RecutConfig{DastReserveFraction: fraction})

	// t1 — first cut, full window.
	first := mustRecut(t, r, window)
	if !first.Performed {
		t.Fatalf("first cut did not run: %s", first.NotCutReason)
	}
	if got := first.AdmittedDastConfirmedTokens(); got != 0 {
		t.Fatalf("first cut admitted %d dast_confirmed tokens; nothing is dast_confirmed when the queue is first cut", got)
	}

	// t2 — the admitted static work is done. Those tokens are spent for good.
	admitted := make([]int64, 0, len(first.Admitted))
	for _, c := range first.Admitted {
		admitted = append(admitted, c.HandoffID)
	}
	f.consume(admitted)
	remaining := window - first.AdmittedTokens()

	// t3 — the DAST half seals with findings; anvil/version bumps; the
	// proof-carrying findings arrive.
	f.bumpVersion(2, record.DastStatusCompletedFindings)
	dastIDs := f.enqueueMany(dastCount, record.EvidenceClassDastConfirmed, "high")

	// t4 — re-cut against REMAINING budget.
	second := mustRecut(t, r, remaining)
	if !second.Performed {
		t.Fatalf("the version bump did not re-cut the queue: %s", second.NotCutReason)
	}
	return arrivalOutcome{firstCut: first, secondCut: second, dastIDs: dastIDs, sastIDs: sastIDs, fixture: f}
}

// TestRecutInvertsPriorityWithoutReservationAndDoesNotWithIt is the test the
// R.11 packet demands: it demonstrates the inversion happening without the
// reservation and not happening with it. Asserting that a float equals 0.5
// would prove nothing about either.
func TestRecutInvertsPriorityWithoutReservationAndDoesNotWithIt(t *testing.T) {
	const (
		window     = 200000 // 20 static candidates * 10,000 tok
		dastCount  = 5      // 50,000 tok of proof-carrying work, arriving late
		dastDemand = dastCount * recutTokens
	)

	t.Run("no reservation inverts the priority scheme", func(t *testing.T) {
		out := runArrivalSequence(t, ReserveFraction(0), window, dastCount)

		// The first cut spent the entire window on findings that carry no
		// proof, because at that moment there was nothing else to spend it on.
		if got, want := out.firstCut.ReservedTokens, 0; got != want {
			t.Fatalf("ReservedTokens = %d, want %d", got, want)
		}
		if got, want := len(out.firstCut.Admitted), 20; got != want {
			t.Fatalf("first cut admitted %d static findings, want %d (the whole window)", got, want)
		}
		if got, want := out.firstCut.AdmittedTokens(), window; got != want {
			t.Fatalf("first cut committed %d tok of a %d tok window, want the lot", got, want)
		}

		// THE INVERSION. Every finding with a working reproduction is now
		// "found, not fixed", while 20 static alarms got the window.
		if got, want := len(out.secondCut.Deferred), dastCount; got != want {
			t.Fatalf("second cut deferred %d dast_confirmed findings, want %d", got, want)
		}
		if got := out.secondCut.AdmittedDastConfirmedTokens(); got != 0 {
			t.Fatalf("second cut admitted %d dast_confirmed tokens; the window was already spent", got)
		}
		for _, id := range out.dastIDs {
			if got := out.fixture.state(id); got != record.HandoffStateSkippedBudget {
				t.Fatalf("dast_confirmed handoff %d is %s, want %s", id, got, record.HandoffStateSkippedBudget)
			}
		}
		// ... and the inversion is exactly that a weaker class was admitted
		// while the strongest was not.
		if !crossCutInversion(out) {
			t.Fatal("expected the cross-cut priority inversion S6 describes, and it did not occur")
		}
	})

	t.Run("the default reservation prevents it", func(t *testing.T) {
		out := runArrivalSequence(t, nil, window, dastCount) // nil selects DefaultDastReserveFraction

		if got, want := out.firstCut.ReserveFraction, DefaultDastReserveFraction; got != want {
			t.Fatalf("ReserveFraction = %v, want the documented default %v", got, want)
		}
		reserved := out.firstCut.ReservedTokens
		if got, want := reserved, window/2; got != want {
			t.Fatalf("ReservedTokens = %d, want %d", got, want)
		}
		if got, want := len(out.firstCut.Admitted), 10; got != want {
			t.Fatalf("first cut admitted %d static findings, want %d (half the window)", got, want)
		}

		// Every proof-carrying finding arriving after the bump is admitted.
		//
		// A reservation guarantees AVAILABILITY, not consumption: here the late
		// demand (50,000 tok) is below the 100,000 held back, so the right
		// assertion is that the class took everything it asked for.
		// TestRecutGivesDastConfirmedAtLeastTheReservation drives the other
		// side, where demand exceeds the reserve.
		if len(out.secondCut.Deferred) != 0 {
			t.Fatalf("second cut deferred %d dast_confirmed findings, want none", len(out.secondCut.Deferred))
		}
		if want := min(reserved, dastDemand); out.secondCut.AdmittedDastConfirmedTokens() < want {
			t.Fatalf("dast_confirmed findings received %d tok, want at least %d",
				out.secondCut.AdmittedDastConfirmedTokens(), want)
		}
		for _, id := range out.dastIDs {
			if got := out.fixture.state(id); got != record.HandoffStateReady {
				t.Fatalf("dast_confirmed handoff %d is %s, want %s", id, got, record.HandoffStateReady)
			}
		}
		if crossCutInversion(out) {
			t.Fatal("the reservation was applied and the priority scheme inverted anyway")
		}
	})
}

// crossCutInversion is S6's failure mode stated as a predicate over the whole
// arrival sequence rather than over one cut: a weaker evidence class was
// admitted earlier, and a dast_confirmed finding arriving later found no budget.
func crossCutInversion(out arrivalOutcome) bool {
	weakerAdmitted := false
	for _, c := range out.firstCut.Admitted {
		if !c.DastConfirmed() {
			weakerAdmitted = true
			break
		}
	}
	return weakerAdmitted && out.secondCut.DeferredDastConfirmed() > 0
}

// TestRecutReserveIsConfigDriven runs the same sequence at the default 50% and
// at an overridden 25%, which is the R.11 packet's stop condition: the value
// must be read from configuration, not compiled in. A change in the
// configuration must change the arithmetic AND the row states, or the knob is
// decorative.
func TestRecutReserveIsConfigDriven(t *testing.T) {
	const (
		window     = 200000
		dastCount  = 5
		dastDemand = dastCount * recutTokens
	)

	cases := []struct {
		name              string
		fraction          *float64
		wantFraction      float64
		wantReserved      int
		wantFirstAdmitted int
	}{
		{"default 50%", nil, 0.5, 100000, 10},
		{"overridden 50%", ReserveFraction(0.5), 0.5, 100000, 10},
		{"overridden 25%", ReserveFraction(0.25), 0.25, 50000, 15},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runArrivalSequence(t, tc.fraction, window, dastCount)

			if got := out.firstCut.ReserveFraction; got != tc.wantFraction {
				t.Fatalf("ReserveFraction = %v, want %v", got, tc.wantFraction)
			}
			if got := out.firstCut.ReservedTokens; got != tc.wantReserved {
				t.Fatalf("ReservedTokens = %d, want %d", got, tc.wantReserved)
			}
			// The configuration changed the row states, not just a report
			// field: a different fraction admits a different number of static
			// findings at the first cut.
			if got := len(out.firstCut.Admitted); got != tc.wantFirstAdmitted {
				t.Fatalf("first cut admitted %d, want %d", got, tc.wantFirstAdmitted)
			}

			// The packet's own validation clause: dast_confirmed findings
			// arriving after the bump receive at least the configured fraction
			// of the budget that remained when the reservation was made — or
			// all of what they asked for, when that is less.
			if want := min(tc.wantReserved, dastDemand); out.secondCut.AdmittedDastConfirmedTokens() < want {
				t.Fatalf("dast_confirmed findings received %d tok, want at least %d (%v of the %d remaining at the cut)",
					out.secondCut.AdmittedDastConfirmedTokens(), want, tc.wantFraction, window)
			}
			if crossCutInversion(out) {
				t.Fatalf("priority inverted at fraction %v", tc.wantFraction)
			}
		})
	}
}

// TestRecutGivesDastConfirmedAtLeastTheReservation drives the side the
// inversion test does not: late dynamic demand that EXCEEDS the reserve. The
// claim under test is the packet's literal one — the class receives at least
// the configured fraction of the budget remaining at the cut that reserved it —
// and it is only meaningful when the class could have taken more.
func TestRecutGivesDastConfirmedAtLeastTheReservation(t *testing.T) {
	const (
		window    = 200000
		dastCount = 12 // 120,000 tok of demand against a 100,000 tok reserve
	)

	cases := []struct {
		name         string
		fraction     *float64
		wantReserved int
		wantAdmitted int
	}{
		{"default 50%", nil, 100000, 10},
		{"overridden 25%", ReserveFraction(0.25), 50000, 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runArrivalSequence(t, tc.fraction, window, dastCount)

			if got := out.firstCut.ReservedTokens; got != tc.wantReserved {
				t.Fatalf("ReservedTokens = %d, want %d", got, tc.wantReserved)
			}
			if got := len(out.secondCut.Admitted); got != tc.wantAdmitted {
				t.Fatalf("second cut admitted %d dast_confirmed findings, want %d", got, tc.wantAdmitted)
			}
			if got := out.secondCut.AdmittedDastConfirmedTokens(); got < tc.wantReserved {
				t.Fatalf("dast_confirmed findings received %d tok, want at least the %d reserved for them",
					got, tc.wantReserved)
			}
			// The overflow is deferred, not dropped: research/24 step 9's
			// "found, not fixed".
			for _, c := range out.secondCut.Deferred {
				if out.fixture.state(c.HandoffID) != record.HandoffStateSkippedBudget {
					t.Fatalf("overflow handoff %d was not recorded as %s", c.HandoffID, record.HandoffStateSkippedBudget)
				}
			}
		})
	}

	// Control: with no reservation the same demand gets nothing at all.
	out := runArrivalSequence(t, ReserveFraction(0), window, dastCount)
	if got := out.secondCut.AdmittedDastConfirmedTokens(); got != 0 {
		t.Fatalf("unreserved control admitted %d dast_confirmed tokens, want 0", got)
	}
	if !crossCutInversion(out) {
		t.Fatal("unreserved control did not invert the priority scheme")
	}
}

// TestRecutReservesFromRemainingNotTotalBudget pins the R.11 packet's
// Forbidden action: "Do not let the reservation apply to total budget rather
// than *remaining* budget at re-cut time." The window is the same; only what is
// left of it differs.
func TestRecutReservesFromRemainingNotTotalBudget(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusRunning)
	f.enqueueMany(20, record.EvidenceClassSastReachable, "high")
	r := f.recutter(RecutConfig{})

	first := mustRecut(t, r, 200000)
	if got, want := first.ReservedTokens, 100000; got != want {
		t.Fatalf("first cut ReservedTokens = %d, want %d", got, want)
	}

	// Time passed and the window shrank. The reservation must shrink with it.
	f.bumpVersion(2, record.DastStatusCompletedFindings)
	second := mustRecut(t, r, 40000)

	if got, want := second.RemainingBudgetTokens, 40000; got != want {
		t.Fatalf("RemainingBudgetTokens = %d, want %d", got, want)
	}
	if got, want := second.ReservedTokens, 20000; got != want {
		t.Fatalf("second cut ReservedTokens = %d, want %d (half of REMAINING, not of the 200000 total)", got, want)
	}
	if got, want := second.OpenTokens, 20000; got != want {
		t.Fatalf("second cut OpenTokens = %d, want %d", got, want)
	}
}

// ---------------------------------------------------------------------------
// The trigger
// ---------------------------------------------------------------------------

// TestRecutTriggersOnVersionBumpAndNotOnHandoffWrites pins the other Forbidden
// action: "Do not re-cut on every write to `handoff` — only on an
// `audit_record.audit_version` bump."
func TestRecutTriggersOnVersionBumpAndNotOnHandoffWrites(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusRunning)
	f.enqueueMany(4, record.EvidenceClassSastReachable, "high")
	r := f.recutter(RecutConfig{})

	first := mustRecut(t, r, 20000)
	if !first.Performed {
		t.Fatalf("first cut did not run: %s", first.NotCutReason)
	}
	if got, want := len(first.Admitted), 1; got != want {
		t.Fatalf("admitted %d, want %d", got, want)
	}

	// A write to `handoff` — a new finding enqueued, no version bump.
	late := f.enqueue(record.EvidenceClassSastReachable, "high")

	second := mustRecut(t, r, 20000)
	if second.Performed {
		t.Fatal("a handoff write re-cut the queue; only an audit_version bump may")
	}
	if second.NotCutReason == "" {
		t.Fatal("a declined cut must say which guard declined")
	}
	if got := f.state(late); got != record.HandoffStateReady {
		t.Fatalf("the late row is %s after a declined cut, want it untouched at %s", got, record.HandoffStateReady)
	}

	// Bump the version and the same call now re-cuts.
	f.bumpVersion(2, record.DastStatusCompletedFindings)
	third := mustRecut(t, r, 20000)
	if !third.Performed {
		t.Fatalf("a version bump did not re-cut: %s", third.NotCutReason)
	}
	if got := f.state(late); got != record.HandoffStateSkippedBudget {
		t.Fatalf("the late row is %s, want %s after a re-cut it did not fit", got, record.HandoffStateSkippedBudget)
	}
}

// ---------------------------------------------------------------------------
// The CRITIQUE-02 §7 decision, asserted
// ---------------------------------------------------------------------------

// TestRecutLeavesLeasedRowsAloneAndNeverWritesSuperseded is the executable form
// of this file's ruling on CRITIQUE-02 §7: a version bump does NOT dispose the
// rows leased at the old version. internal/handoff's checkRecordVersion makes
// such a lease unable to renew, release or touch its packet, and its reaper is
// the only component authorised to take a lease its holder still has. A re-cut
// that yanked it would be the "expire a live claim" that research/08 §4 point 2
// forbids and that CRITIQUE-02 verdict (e) currently passes.
func TestRecutLeavesLeasedRowsAloneAndNeverWritesSuperseded(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusRunning)
	ids := f.enqueueMany(6, record.EvidenceClassSastReachable, "high")
	f.lease(ids[0], "worker-old-version")

	r := f.recutter(RecutConfig{})

	// Budget for two candidates' worth. The leased row is charged first, so
	// only one further row can be admitted from the open half.
	f.bumpVersion(2, record.DastStatusCompletedFindings)
	cut := mustRecut(t, r, 40000)

	if got, want := cut.InFlightTokens, recutTokens; got != want {
		t.Fatalf("InFlightTokens = %d, want %d (the leased row is charged, not deferred)", got, want)
	}
	if got := f.state(ids[0]); got != record.HandoffStateLeased {
		t.Fatalf("the leased row is %s after a version-bump re-cut, want %s", got, record.HandoffStateLeased)
	}
	var claimedBy string
	if err := f.db.QueryRow(`SELECT claimed_by FROM handoff WHERE handoff_id = ?`, ids[0]).Scan(&claimedBy); err != nil {
		t.Fatalf("reading claimed_by: %v", err)
	}
	if claimedBy != "worker-old-version" {
		t.Fatalf("claimed_by = %q, want the original holder", claimedBy)
	}

	// No row anywhere in the audit was superseded or withdrawn: a budget
	// decision's only disposition is skipped_budget.
	for _, forbidden := range []record.HandoffState{
		record.HandoffStateSuperseded,
		record.HandoffStateWithdrawn,
		record.HandoffStateExpired,
	} {
		if n := f.countState(forbidden); n != 0 {
			t.Fatalf("the re-cut wrote %d rows as %s; a budget decision defers as %s and nothing else",
				n, forbidden, record.HandoffStateSkippedBudget)
		}
	}
	for _, c := range cut.Deferred {
		if c.State != record.HandoffStateSkippedBudget {
			t.Fatalf("deferred candidate %d reported state %s, want %s", c.HandoffID, c.State, record.HandoffStateSkippedBudget)
		}
	}
}

// TestRecutIsMonotoneAndCannotReadmit records the interaction with
// internal/handoff's state machine, in which skipped_budget is terminal
// ("Terminal is terminal"): a later cut with a bigger budget must not — and
// cannot — pull a deferred row back to 'ready'.
func TestRecutIsMonotoneAndCannotReadmit(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusRunning)
	ids := f.enqueueMany(4, record.EvidenceClassSastReachable, "high")
	r := f.recutter(RecutConfig{})

	first := mustRecut(t, r, 20000)
	if got, want := len(first.Deferred), 3; got != want {
		t.Fatalf("first cut deferred %d, want %d", got, want)
	}

	f.bumpVersion(2, record.DastStatusCompletedFindings)
	second := mustRecut(t, r, 10000000)

	if len(second.Deferred) != 0 {
		t.Fatalf("second cut deferred %d with an enormous budget, want none", len(second.Deferred))
	}
	if got, want := len(second.Admitted), 1; got != want {
		t.Fatalf("second cut saw %d candidates, want %d — deferred rows are terminal and out of the candidate set", got, want)
	}
	for _, id := range ids[1:] {
		if got := f.state(id); got != record.HandoffStateSkippedBudget {
			t.Fatalf("handoff %d is %s, want it to have stayed %s", id, got, record.HandoffStateSkippedBudget)
		}
	}
}

// ---------------------------------------------------------------------------
// The reservation's gate
// ---------------------------------------------------------------------------

// TestLateDastArrivalsPossibleIsTotalOverTheFrozenEnum asserts the predicate
// decides every one of the ten frozen anvil/dastStatus values explicitly, so a
// future eleventh value cannot land as a silent default.
func TestLateDastArrivalsPossibleIsTotalOverTheFrozenEnum(t *testing.T) {
	want := map[record.DastStatus]bool{
		record.DastStatusNotRun:            false,
		record.DastStatusSkippedNoManifest: false,
		record.DastStatusRunning:           true,
		record.DastStatusCompletedClean:    false,
		record.DastStatusCompletedFindings: true,
		record.DastStatusCompletedPartial:  true,
		record.DastStatusCompletedFailed:   true,
		record.DastStatusTargetBootFailed:  false,
		record.DastStatusTargetUnreachable: false,
		record.DastStatusTimedOut:          true,
	}

	values := record.DastStatusValues()
	if got, want := len(values), 10; got != want {
		t.Fatalf("record.DastStatusValues() has %d values, want %d; "+
			"plan/IMPLEMENTATION-PLAN.md §6 freezes ten. Decide the new one here.", got, want)
	}
	for _, v := range values {
		expected, ok := want[v]
		if !ok {
			t.Fatalf("dastStatus %q has no reservation ruling in this test or in LateDastArrivalsPossible", v)
		}
		if got := LateDastArrivalsPossible(v); got != expected {
			t.Fatalf("LateDastArrivalsPossible(%q) = %v, want %v", v, got, expected)
		}
	}
	if len(want) != len(values) {
		t.Fatalf("the expectation table has %d entries and the enum has %d", len(want), len(values))
	}
}

// TestRecutReleasesTheReserveWhenNoLateArrivalIsPossible: holding budget for a
// class that provably cannot arrive would starve the classes that did.
func TestRecutReleasesTheReserveWhenNoLateArrivalIsPossible(t *testing.T) {
	for _, status := range []record.DastStatus{
		record.DastStatusNotRun,
		record.DastStatusSkippedNoManifest,
		record.DastStatusCompletedClean,
		record.DastStatusTargetBootFailed,
		record.DastStatusTargetUnreachable,
	} {
		t.Run(string(status), func(t *testing.T) {
			f := newRecutFixture(t, status)
			f.enqueueMany(20, record.EvidenceClassSastReachable, "high")
			r := f.recutter(RecutConfig{})

			cut := mustRecut(t, r, 200000)
			if cut.LateDastArrivalsPossible {
				t.Fatalf("dast_status %q: late arrivals reported possible", status)
			}
			if cut.ReserveFraction != 0 || cut.ReservedTokens != 0 {
				t.Fatalf("dast_status %q: reserved %d tok at fraction %v, want nothing held back",
					status, cut.ReservedTokens, cut.ReserveFraction)
			}
			if got, want := cut.OpenTokens, 200000; got != want {
				t.Fatalf("OpenTokens = %d, want the whole %d", got, want)
			}
			if got, want := len(cut.Admitted), 20; got != want {
				t.Fatalf("admitted %d, want %d", got, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Ordering, vocabulary, and the boring but load-bearing parts
// ---------------------------------------------------------------------------

// TestEvidenceClassRankFollowsTheFrozenEnumOrder proves the rank is derived
// from record.EvidenceClassValues() and is not a second copy of that ordering.
func TestEvidenceClassRankFollowsTheFrozenEnumOrder(t *testing.T) {
	values := record.EvidenceClassValues()
	if values[0] != record.EvidenceClassDastConfirmed {
		t.Fatalf("the frozen enum no longer leads with %s; the reservation's premise changed",
			record.EvidenceClassDastConfirmed)
	}
	for i, v := range values {
		if got := EvidenceClassRank(v); got != i {
			t.Fatalf("EvidenceClassRank(%q) = %d, want %d", v, got, i)
		}
	}
	for i := 1; i < len(values); i++ {
		if EvidenceClassRank(values[i-1]) >= EvidenceClassRank(values[i]) {
			t.Fatalf("rank is not strictly increasing at %q -> %q", values[i-1], values[i])
		}
	}
}

// TestRecutRanksDastConfirmedAheadOfEveryWeakerClass drives a mixed queue too
// small for all of it and checks who survives the cut.
func TestRecutRanksDastConfirmedAheadOfEveryWeakerClass(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusCompletedFindings)
	// Deliberately enqueued weakest-first, so an implementation that honoured
	// insertion order rather than rank would fail here.
	host := f.enqueue(record.EvidenceClassHost, "high")
	sca := f.enqueue(record.EvidenceClassSCA, "high")
	static := f.enqueue(record.EvidenceClassSastStaticOnly, "high")
	reachable := f.enqueue(record.EvidenceClassSastReachable, "high")
	confirmed := f.enqueue(record.EvidenceClassDastConfirmed, "high")

	r := f.recutter(RecutConfig{})
	// 20,000 tok: reserve 10,000 (one dast_confirmed row), open 10,000 (one
	// weaker row).
	cut := mustRecut(t, r, 20000)

	if got := f.state(confirmed); got != record.HandoffStateReady {
		t.Fatalf("the dast_confirmed row is %s, want %s", got, record.HandoffStateReady)
	}
	if got := f.state(reachable); got != record.HandoffStateReady {
		t.Fatalf("the strongest static row is %s, want %s", got, record.HandoffStateReady)
	}
	for name, id := range map[string]int64{"sast_static_only": static, "sca": sca, "host": host} {
		if got := f.state(id); got != record.HandoffStateSkippedBudget {
			t.Fatalf("the %s row is %s, want %s", name, got, record.HandoffStateSkippedBudget)
		}
	}
	if cut.InvertedPriority() {
		t.Fatal("InvertedPriority reported an inversion in a correctly ordered cut")
	}
}

// TestRecutSeverityRankOrdersWithinAClass checks the configured severity order
// is honoured, and that it is configuration rather than a vocabulary this file
// froze.
func TestRecutSeverityRankOrdersWithinAClass(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusCompletedClean)
	low := f.enqueue(record.EvidenceClassSastReachable, "low")
	critical := f.enqueue(record.EvidenceClassSastReachable, "critical")
	unknown := f.enqueue(record.EvidenceClassSastReachable, "spicy")

	r := f.recutter(RecutConfig{
		SeverityRank: map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3},
	})
	cut := mustRecut(t, r, 10000)

	if got, want := len(cut.Admitted), 1; got != want {
		t.Fatalf("admitted %d, want %d", got, want)
	}
	if cut.Admitted[0].HandoffID != critical {
		t.Fatalf("admitted handoff %d, want the 'critical' row %d", cut.Admitted[0].HandoffID, critical)
	}
	// An unranked severity sorts last, not first: an unknown token must never
	// outrank a configured one.
	if f.state(low) != record.HandoffStateSkippedBudget || f.state(unknown) != record.HandoffStateSkippedBudget {
		t.Fatal("the lower-ranked rows were not deferred")
	}
}

// TestRecutDeferralUsesTheFrozenLiteralAndHandoffTimestampFormat pins both
// halves of the write: the state token comes from the frozen enum, and
// updated_at is in the exact layout internal/handoff parses.
func TestRecutDeferralUsesTheFrozenLiteralAndHandoffTimestampFormat(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusCompletedClean)
	ids := f.enqueueMany(2, record.EvidenceClassSastReachable, "high")
	at := time.Date(2026, 8, 8, 3, 4, 5, 123456789, time.UTC)
	r := f.recutter(RecutConfig{Clock: func() time.Time { return at }})

	mustRecut(t, r, 10000)

	var state, updatedAt string
	if err := f.db.QueryRow(
		`SELECT state, updated_at FROM handoff WHERE handoff_id = ?`, ids[1]).Scan(&state, &updatedAt); err != nil {
		t.Fatalf("reading the deferred row: %v", err)
	}
	if state != string(record.HandoffStateSkippedBudget) {
		t.Fatalf("state = %q, want %q", state, string(record.HandoffStateSkippedBudget))
	}
	if err := record.ValidateHandoffState(state); err != nil {
		t.Fatalf("the written state is not a frozen handoff.state literal: %v", err)
	}
	// The literal layout, spelled out: it must stay identical to
	// internal/handoff/state_machine.go's unexported timeLayout, which
	// internal/store cannot import.
	const handoffLayout = "2006-01-02T15:04:05.000000000Z"
	if recutTimestampLayout != handoffLayout {
		t.Fatalf("recutTimestampLayout = %q, want internal/handoff's %q", recutTimestampLayout, handoffLayout)
	}
	parsed, err := time.Parse(handoffLayout, updatedAt)
	if err != nil {
		t.Fatalf("updated_at %q does not parse with internal/handoff's layout: %v", updatedAt, err)
	}
	if !parsed.Equal(at) {
		t.Fatalf("updated_at = %v, want %v", parsed, at)
	}
}

// TestRecutRejectsBadConfigurationAndBudget: a fraction outside [0,1] or a
// negative budget is a caller bug and is refused, not clamped. Clamping would
// hide an arithmetic error inside the component whose entire job is arithmetic.
func TestRecutRejectsBadConfigurationAndBudget(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusRunning)
	f.enqueue(record.EvidenceClassSastReachable, "high")

	for _, bad := range []float64{-0.01, 1.01, 2} {
		if _, err := NewRecutter(f.db, RecutConfig{DastReserveFraction: ReserveFraction(bad)}); !errors.Is(err, ErrInvalidReserveFraction) {
			t.Fatalf("NewRecutter(fraction=%v) error = %v, want ErrInvalidReserveFraction", bad, err)
		}
	}
	// 0 and 1 are both legal: 0 is the control arm and 1 hands the whole
	// remaining window to late dynamic evidence.
	for _, ok := range []float64{0, 1} {
		if _, err := NewRecutter(f.db, RecutConfig{DastReserveFraction: ReserveFraction(ok)}); err != nil {
			t.Fatalf("NewRecutter(fraction=%v): %v", ok, err)
		}
	}

	r := f.recutter(RecutConfig{})
	if err := r.RecutQueue(recutAuditID, -1); !errors.Is(err, ErrInvalidBudget) {
		t.Fatalf("RecutQueue(-1) error = %v, want ErrInvalidBudget", err)
	}
	if _, err := NewRecutter(nil, RecutConfig{}); err == nil {
		t.Fatal("NewRecutter(nil db) returned no error")
	}
}

// TestResolveAuditRecordID covers the packet's `auditID string` against a
// schema that has no string audit key.
func TestResolveAuditRecordID(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusRunning)
	ctx := context.Background()

	got, err := ResolveAuditRecordID(ctx, f.db, "  1 ")
	if err != nil {
		t.Fatalf("ResolveAuditRecordID: %v", err)
	}
	if got != recutAuditRecordID {
		t.Fatalf("ResolveAuditRecordID = %d, want %d", got, recutAuditRecordID)
	}

	for _, bad := range []string{"", "   ", "0", "-3", "anvil-2026-08-08-abc", "1; DROP TABLE handoff"} {
		if _, err := ResolveAuditRecordID(ctx, f.db, bad); !errors.Is(err, ErrNoSuchAudit) {
			t.Fatalf("ResolveAuditRecordID(%q) error = %v, want ErrNoSuchAudit", bad, err)
		}
	}
	if _, err := ResolveAuditRecordID(ctx, f.db, "99"); !errors.Is(err, ErrNoSuchAudit) {
		t.Fatalf("ResolveAuditRecordID(unknown) error = %v, want ErrNoSuchAudit", err)
	}
	if err := f.recutter(RecutConfig{}).RecutQueue("99", 1000); !errors.Is(err, ErrNoSuchAudit) {
		t.Fatalf("RecutQueue(unknown audit) error = %v, want ErrNoSuchAudit", err)
	}
}

// TestRecutChargesInFlightLeasesBeforeAdmittingAnything: a queue whose leases
// already exceed the remaining window admits nothing new, and says by how much
// it is overdrawn rather than hiding it.
func TestRecutChargesInFlightLeasesBeforeAdmittingAnything(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusCompletedClean)
	ids := f.enqueueMany(4, record.EvidenceClassSastReachable, "high")
	f.lease(ids[0], "w1")
	f.lease(ids[1], "w2")

	r := f.recutter(RecutConfig{})
	cut := mustRecut(t, r, 15000)

	if got, want := cut.InFlightTokens, 2*recutTokens; got != want {
		t.Fatalf("InFlightTokens = %d, want %d", got, want)
	}
	if got, want := cut.InFlightOverdraftTokens, 5000; got != want {
		t.Fatalf("InFlightOverdraftTokens = %d, want %d", got, want)
	}
	if len(cut.Admitted) != 0 {
		t.Fatalf("admitted %d candidates while overdrawn, want none", len(cut.Admitted))
	}
	if got, want := len(cut.Deferred), 2; got != want {
		t.Fatalf("deferred %d, want %d", got, want)
	}
	if got := f.state(ids[0]); got != record.HandoffStateLeased {
		t.Fatalf("in-flight row is %s, want %s", got, record.HandoffStateLeased)
	}
}

// TestRecutCostFuncIsConfigurable proves the per-candidate charge is a
// configuration seam too, so a later step can charge a measured prompt size
// without editing queue.go.
func TestRecutCostFuncIsConfigurable(t *testing.T) {
	f := newRecutFixture(t, record.DastStatusCompletedClean)
	f.enqueueMany(4, record.EvidenceClassSastReachable, "high")

	r := f.recutter(RecutConfig{
		CostTokens: func(c Candidate) int { return 1000 * int(c.FindingID) },
	})
	cut := mustRecut(t, r, 6000)

	// 1000 + 2000 + 3000 = 6000 fits; the fourth (4000) does not and closes
	// the cut. A knapsack would have skipped the third to fit the fourth.
	if got, want := len(cut.Admitted), 3; got != want {
		t.Fatalf("admitted %d, want %d", got, want)
	}
	if got, want := cut.AdmittedTokens(), 6000; got != want {
		t.Fatalf("AdmittedTokens = %d, want %d", got, want)
	}
	if got, want := len(cut.Deferred), 1; got != want {
		t.Fatalf("deferred %d, want %d", got, want)
	}
}
