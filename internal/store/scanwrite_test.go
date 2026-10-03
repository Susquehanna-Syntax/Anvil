package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

var swClock = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func swOpen(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "anvil.db"), "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func swResult(fp string) record.Result {
	return record.Result{
		RuleID:              "CVE-2026-1001",
		Message:             record.Message{Text: "zzpkg 1.0 is affected by CVE-2026-1001"},
		PartialFingerprints: map[string]string{record.PartialFingerprintAnvilFindingID: fp},
		Properties: record.ResultProperties{
			FindingID:     "f-" + fp[:8],
			Half:          record.HalfSast,
			Confidence:    1,
			Verdict:       record.VerdictTruePositive,
			EvidenceClass: record.EvidenceClassHost,
			Detector:      record.DetectorRef{Kind: record.DetectorKindHost},
			Trust:         record.TrustAssertion{Default: record.TrustUntrusted},
		},
	}
}

// swScan seals one audit with the given SAST status and results and returns
// what WriteScan takes. Each call is a separate audit on a separate Sealer.
func swScan(t *testing.T, n int, status record.HalfStatus, complete bool, fps ...string) ScanWrite {
	t.Helper()
	s := record.NewSealer()
	start := swClock.Add(time.Duration(n) * time.Hour)
	s.SetClock(func() time.Time { return start.Add(time.Minute) })
	id := "audit-" + string(rune('a'+n))
	if _, err := s.BeginAudit(record.AuditConfig{AuditID: id, StartedAt: start}); err != nil {
		t.Fatal(err)
	}
	if err := s.SealHalf(id, record.HalfSast, status); err != nil {
		t.Fatal(err)
	}
	seal, _ := s.Inspect(id)
	var rs []record.Result
	for _, fp := range fps {
		rs = append(rs, swResult(fp))
	}
	l, err := record.Assemble(record.Assembly{
		Seal: seal, Version: 1,
		Target:      record.Target{Provenance: record.TargetProvenanceNoTargetDeclared},
		SastTool:    record.ToolComponent{Name: "anvil"},
		SastResults: rs,
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	return ScanWrite{
		TargetKind: TargetKindHost, TargetLocator: "host:zzhostqx", RulesetVersion: "lanea/v1",
		FinishedAt: start.Add(2 * time.Minute), Seal: seal, AuditVersion: 1, Complete: complete,
		DetectorsRun: []record.DetectorKind{record.DetectorKindHost}, Log: l,
	}
}

func fpOf(c byte) string { return strings.Repeat(string(c), 64) }

func marks(r WriteResult) map[string]MarkKind {
	m := map[string]MarkKind{}
	for _, x := range r.Marks {
		m[x.Fingerprint[:1]] = x.Kind
	}
	return m
}

func swWrite(t *testing.T, db *sql.DB, w ScanWrite) WriteResult {
	t.Helper()
	r, err := WriteScan(context.Background(), db, w)
	if err != nil {
		t.Fatalf("WriteScan: %v", err)
	}
	return r
}

func TestRegressionMarking(t *testing.T) {
	db := swOpen(t)

	r1 := swWrite(t, db, swScan(t, 0, record.HalfStatusSealed, true, fpOf('a'), fpOf('b')))
	if got := marks(r1); got["a"] != MarkNew || got["b"] != MarkNew || len(got) != 2 {
		t.Fatalf("first scan marks = %v, want a and b new", got)
	}
	if r1.Status != "ok" {
		t.Fatalf("status = %q", r1.Status)
	}

	// b is gone, c is new, a persists.
	r2 := swWrite(t, db, swScan(t, 1, record.HalfStatusSealed, true, fpOf('a'), fpOf('c')))
	if got := marks(r2); got["a"] != MarkPersisting || got["b"] != MarkFixed || got["c"] != MarkNew || len(got) != 3 {
		t.Fatalf("second scan marks = %v, want a persisting, b fixed, c new", got)
	}

	// b returns: regressed.
	r3 := swWrite(t, db, swScan(t, 2, record.HalfStatusSealed, true, fpOf('a'), fpOf('b'), fpOf('c')))
	if got := marks(r3); got["b"] != MarkRegressed || got["a"] != MarkPersisting || got["c"] != MarkPersisting {
		t.Fatalf("third scan marks = %v, want b regressed", got)
	}

	var state string
	if err := db.QueryRow(`SELECT state FROM finding WHERE fingerprint = ?`, fpOf('b')).Scan(&state); err != nil || state != "regressed" {
		t.Fatalf("b's state = %q (%v), want regressed", state, err)
	}
	var events int
	if err := db.QueryRow(`SELECT count(*) FROM finding_state_event`).Scan(&events); err != nil || events != 5 {
		t.Fatalf("state events = %d (%v), want 5: three first_seen, one absent_in_scan, one regression", events, err)
	}
	var occ int
	if err := db.QueryRow(`SELECT count(*) FROM finding_occurrence`).Scan(&occ); err != nil || occ != 7 {
		t.Fatalf("occurrences = %d (%v), want 7 (2 + 2 + 3)", occ, err)
	}
}

// A failed half, or a sealed half with incomplete coverage, never turns an
// absent finding into fixed.
func TestOnlyACleanSealFixesAFinding(t *testing.T) {
	for _, c := range []struct {
		name     string
		status   record.HalfStatus
		complete bool
		run      string
	}{
		{"failed half", record.HalfStatusFailed, true, "failed"},
		{"timed-out half", record.HalfStatusTimedOut, true, "failed"},
		{"skipped half", record.HalfStatusSkipped, true, "failed"},
		{"sealed but incomplete", record.HalfStatusSealed, false, "partial"},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := swOpen(t)
			swWrite(t, db, swScan(t, 0, record.HalfStatusSealed, true, fpOf('a')))
			r := swWrite(t, db, swScan(t, 1, c.status, c.complete))
			if r.Status != c.run {
				t.Errorf("scan_run.status = %q, want %q", r.Status, c.run)
			}
			if len(r.Marks) != 0 {
				t.Errorf("marks = %v; a scan that did not seal cleanly marked a finding", r.Marks)
			}
			var state string
			_ = db.QueryRow(`SELECT state FROM finding WHERE fingerprint = ?`, fpOf('a')).Scan(&state)
			if state != "open" {
				t.Errorf("state = %q, want open", state)
			}
		})
	}
}

// A scan resolves only the detectors it ran.
func TestAScanResolvesOnlyItsOwnDetectors(t *testing.T) {
	db := swOpen(t)
	swWrite(t, db, swScan(t, 0, record.HalfStatusSealed, true, fpOf('a')))
	w := swScan(t, 1, record.HalfStatusSealed, true)
	w.DetectorsRun = []record.DetectorKind{record.DetectorKindSCA}
	if r := swWrite(t, db, w); len(r.Marks) != 0 {
		t.Fatalf("an SCA-only scan marked host findings: %v", r.Marks)
	}
}

func TestThePayloadIsTheRecord(t *testing.T) {
	db := swOpen(t)
	w := swScan(t, 0, record.HalfStatusSealed, true, fpOf('a'))
	r := swWrite(t, db, w)
	var payload []byte
	var sum, state, sast, dast string
	if err := db.QueryRow(`SELECT payload, payload_sha256, state, sast_status, dast_status
		FROM audit_record WHERE audit_record_id = ?`, r.AuditRecordID).Scan(&payload, &sum, &state, &sast, &dast); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodePayload(payload, sum)
	if err != nil {
		t.Fatal(err)
	}
	var back record.SARIFLog
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Properties.AuditID != w.Seal.AuditID || len(back.Runs[0].Results) != 1 {
		t.Fatalf("payload decodes to audit %q with %d results", back.Properties.AuditID, len(back.Runs[0].Results))
	}
	if state != string(record.StateBothSealed) || sast != string(record.HalfStatusSealed) || dast != string(record.DastStatusNotRun) {
		t.Errorf("audit_record state=%q sast=%q dast=%q", state, sast, dast)
	}
}

func TestWriteScanRefusesAnUnfinishedHalf(t *testing.T) {
	db := swOpen(t)
	w := swScan(t, 0, record.HalfStatusSealed, true)
	w.Seal.Sast.Status = record.HalfStatusRunning
	if _, err := WriteScan(context.Background(), db, w); err == nil {
		t.Fatal("a running half was written")
	}
}
