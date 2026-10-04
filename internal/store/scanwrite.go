// This file is the store's writer for one finished scan: scan_run,
// audit_record, and the finding / finding_occurrence / finding_state_event
// rows that make regression checking possible (plan node daemon).
//
// ONE TRANSACTION, TAKEN WITH BEGIN IMMEDIATE. The write lock is acquired
// before the first read, so two writers cannot both read "this finding is new"
// and both insert it; the second waits on busy_timeout instead. That, plus WAL,
// is the "one writer" the store's design asks for.
//
// REGRESSION MARKING KEYS ON THE FINGERPRINT AND NOTHING ELSE. A result's
// anvil-fp/v1 digest (partialFingerprints["anvilFindingId/v1"]) is the
// finding's identity on its target, `UNIQUE (target_id, fingerprint)`:
//
//	new         no finding with that fingerprint on the target
//	persisting  an open, regressed or suppressed finding seen again
//	regressed   a resolved finding seen again
//	fixed       an open or regressed finding NOT seen again, and only when this
//	            scan sealed the same half cleanly with complete coverage
//
// A FINDING IS FIXED ONLY BY A CLEAN SEAL. A failed, skipped or timed-out half
// saw less than it was asked to, and so does a sealed half whose coverage was
// incomplete (a refused ecosystem, an inventory the comparator could not
// place); "absent" from such a scan means "not looked at", and turning that
// into "fixed" would be the silent-clean failure the whole record exists to
// prevent. Resolution is also limited to the detectors this scan ran, so a
// Lane A scan never resolves a finding another lane produced.

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// MarkKind is what one scan says about one finding.
type MarkKind string

// The four marks.
const (
	MarkNew        MarkKind = "new"
	MarkPersisting MarkKind = "persisting"
	MarkRegressed  MarkKind = "regressed"
	MarkFixed      MarkKind = "fixed"
)

// Target kinds, `target.kind`.
const (
	TargetKindRepo = "repo"
	TargetKindHost = "host"
)

// ScanWrite is one finished scan as the store records it.
type ScanWrite struct {
	TargetKind    string // TargetKindRepo or TargetKindHost
	TargetLocator string // a repository path or URL, or a host identifier

	TriggerRef        string
	CommitSHA         string
	RulesetVersion    string // scan_run.ruleset_version, required
	SastEngineVersion string
	AdvisorySnapshot  string
	FinishedAt        time.Time

	// Seal is the sealer's snapshot after the SAST half's terminal seal.
	Seal         record.AuditSeal
	AuditVersion int

	// Complete is true when the scan saw everything it was asked to see. A
	// sealed half with Complete false records scan_run.status 'partial' and
	// resolves nothing.
	Complete bool

	// DetectorsRun are the detector kinds this scan ran; only findings of
	// these kinds can be resolved by it.
	DetectorsRun []record.DetectorKind

	// RecallCandidates is Lane B's candidates-per-scan count, written to
	// scan_run.recall_candidates (migration 0002). Nil means Lane B did not
	// run; a pointer to 0 means it ran and matched nothing.
	RecallCandidates *int

	// Log is the assembled record. Its SAST results become the findings, and
	// its canonical JSON becomes audit_record.payload.
	Log *record.SARIFLog
}

// Mark is one finding's mark from this scan.
type Mark struct {
	FindingID   int64
	Fingerprint string
	RuleID      string
	Title       string
	Kind        MarkKind
}

// WriteResult is what WriteScan recorded.
type WriteResult struct {
	TargetID      int64
	ScanRunID     int64
	AuditRecordID int64
	Status        string // scan_run.status
	Marks         []Mark
}

// WriteScan records one finished scan in a single transaction.
func WriteScan(ctx context.Context, db *sql.DB, w ScanWrite) (WriteResult, error) {
	if err := w.check(); err != nil {
		return WriteResult{}, err
	}
	canonical, err := json.Marshal(w.Log)
	if err != nil {
		return WriteResult{}, fmt.Errorf("store: marshalling the record: %w", err)
	}
	payload, payloadSHA, err := EncodePayload(canonical)
	if err != nil {
		return WriteResult{}, err
	}
	seen, err := findingsOf(w.Log)
	if err != nil {
		return WriteResult{}, err
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return WriteResult{}, fmt.Errorf("store: taking a connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return WriteResult{}, fmt.Errorf("store: taking the write lock: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	tx := &writer{ctx: ctx, c: conn, now: ts(w.FinishedAt)}
	res := WriteResult{Status: w.runStatus()}
	if res.TargetID, err = tx.target(w.TargetKind, w.TargetLocator); err != nil {
		return WriteResult{}, err
	}
	if res.ScanRunID, err = tx.scanRun(res.TargetID, w, res.Status, rollup(seen)); err != nil {
		return WriteResult{}, err
	}
	if res.AuditRecordID, err = tx.auditRecord(res.ScanRunID, w, payload, payloadSHA); err != nil {
		return WriteResult{}, err
	}
	for _, f := range seen {
		m, err := tx.observe(res.TargetID, res.ScanRunID, f)
		if err != nil {
			return WriteResult{}, err
		}
		res.Marks = append(res.Marks, m)
	}
	if res.Status == scanRunOK {
		fixed, err := tx.resolveAbsent(res.TargetID, res.ScanRunID, w.DetectorsRun, seen)
		if err != nil {
			return WriteResult{}, err
		}
		res.Marks = append(res.Marks, fixed...)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return WriteResult{}, fmt.Errorf("store: committing scan run: %w", err)
	}
	committed = true
	sort.SliceStable(res.Marks, func(i, j int) bool { return res.Marks[i].Fingerprint < res.Marks[j].Fingerprint })
	return res, nil
}

const (
	scanRunOK      = "ok"
	scanRunPartial = "partial"
	scanRunFailed  = "failed"
)

func (w ScanWrite) check() error {
	switch {
	case w.TargetKind != TargetKindRepo && w.TargetKind != TargetKindHost:
		return fmt.Errorf("store: target kind %q is neither %q nor %q", w.TargetKind, TargetKindRepo, TargetKindHost)
	case strings.TrimSpace(w.TargetLocator) == "":
		return errors.New("store: a scan needs a target locator")
	case strings.TrimSpace(w.RulesetVersion) == "":
		return errors.New("store: scan_run.ruleset_version is required")
	case w.FinishedAt.IsZero():
		return errors.New("store: a scan needs its finish time")
	case w.Log == nil:
		return errors.New("store: a scan needs its assembled record")
	case w.Seal.AuditID == "" || w.Seal.AuditID != w.Log.Properties.AuditID:
		return fmt.Errorf("store: the seal (%q) and the record (%q) are different audits", w.Seal.AuditID, w.Log.Properties.AuditID)
	case w.RecallCandidates != nil && *w.RecallCandidates < 0:
		return fmt.Errorf("store: a candidate count of %d is not a count", *w.RecallCandidates)
	case !record.IsTerminalHalfStatus(w.Seal.Sast.Status):
		return fmt.Errorf("store: the SAST half is %q; a scan is written after its half reaches a terminal status", w.Seal.Sast.Status)
	}
	return nil
}

// runStatus is scan_run.status: ok only for a cleanly sealed, complete half.
func (w ScanWrite) runStatus() string {
	if w.Seal.Sast.Status != record.HalfStatusSealed {
		return scanRunFailed
	}
	if !w.Complete {
		return scanRunPartial
	}
	return scanRunOK
}

// seenFinding is one SAST result in the store's terms.
type seenFinding struct {
	fingerprint, detector, evidenceClass, ruleID, verdict, severity, title, message string
	remediable                                                                      bool
	advisoryAsOf                                                                    string
	staleness                                                                       *int
	parseDegraded                                                                   bool
	evidenceRef                                                                     string
}

func findingsOf(l *record.SARIFLog) ([]seenFinding, error) {
	var out []seenFinding
	seenFP := map[string]bool{}
	for ri, run := range l.Runs {
		if run.Properties.Half != record.HalfSast {
			continue
		}
		for i, r := range run.Results {
			fp := r.PartialFingerprints[record.PartialFingerprintAnvilFindingID]
			if len(fp) != record.FingerprintDigestHexLen {
				return nil, fmt.Errorf("store: result %d has no anvil-fp/v1 fingerprint", i)
			}
			if seenFP[fp] {
				// One finding per fingerprint per scan: a second result with
				// the same identity is the same finding observed twice.
				continue
			}
			seenFP[fp] = true
			f := seenFinding{
				fingerprint:   fp,
				detector:      string(r.Properties.Detector.Kind),
				evidenceClass: string(r.Properties.EvidenceClass),
				ruleID:        r.RuleID,
				verdict:       string(r.Properties.Verdict),
				remediable:    r.Properties.RemediableByAgent,
				severity:      severityOf(r),
				title:         capText(r.Message.Text, 200),
				message:       capText(r.Message.Text, MaxDurableTextBytes),
				evidenceRef:   fmt.Sprintf("audit:%s#/runs/%d/results/%d", l.Properties.AuditID, ri, i),
			}
			if a := r.Properties.Advisory; a != nil {
				f.advisoryAsOf = ts(a.AsOf)
				s := a.StalenessSeconds
				f.staleness = &s
				f.parseDegraded = a.ParseDegraded
			}
			if f.title == "" {
				f.title = r.RuleID
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// severityOf bands the CVSS v4.0 base score the record carries by FIRST's
// qualitative scale (0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10
// critical). A result with no score is "unrated": the column has no default,
// and inventing a band would be a severity nobody measured.
func severityOf(r record.Result) string {
	if r.Properties.Risk == nil || r.Properties.Risk.CvssV4Base == nil {
		return "unrated"
	}
	switch s := *r.Properties.Risk.CvssV4Base; {
	case s >= 9.0:
		return "critical"
	case s >= 7.0:
		return "high"
	case s >= 4.0:
		return "medium"
	case s > 0:
		return "low"
	default:
		return "none"
	}
}

func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8Start(s[len(s)-1:]) {
		s = s[:len(s)-1]
	}
	return s
}

// utf8Start reports whether b is not a UTF-8 continuation byte, so a cut
// lands on a rune boundary.
func utf8Start(b string) bool { return b[0]&0xC0 != 0x80 }

func rollup(seen []seenFinding) string {
	fps := make([]string, 0, len(seen))
	for _, f := range seen {
		fps = append(fps, f.fingerprint)
	}
	sort.Strings(fps)
	sum := sha256.Sum256([]byte(strings.Join(fps, "\n")))
	return hex.EncodeToString(sum[:])
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// writer is one write transaction's statements.
type writer struct {
	ctx context.Context
	c   *sql.Conn
	now string
}

func (t *writer) target(kind, locator string) (int64, error) {
	var (
		id  int64
		got string
	)
	err := t.c.QueryRowContext(t.ctx, `SELECT target_id, kind FROM target WHERE locator = ?`, locator).
		Scan(&id, &got)
	if err == nil {
		if got != kind {
			return 0, fmt.Errorf("store: target %q is recorded as a %s, not a %s", locator, got, kind)
		}
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("store: reading target %q: %w", locator, err)
	}
	r, err := t.c.ExecContext(t.ctx, `INSERT INTO target (kind, locator) VALUES (?, ?)`, kind, locator)
	if err != nil {
		return 0, fmt.Errorf("store: recording target %q: %w", locator, err)
	}
	return r.LastInsertId()
}

func (t *writer) scanRun(targetID int64, w ScanWrite, status, rollupHash string) (int64, error) {
	r, err := t.c.ExecContext(t.ctx, `
INSERT INTO scan_run (target_id, trigger_ref, commit_sha, started_at, finished_at, status,
                      sast_engine_ver, ruleset_version, advisory_snapshot, rollup_hash, recall_candidates)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		targetID, nullString(w.TriggerRef), nullString(w.CommitSHA), ts(w.Seal.StartedAt), t.now, status,
		nullString(w.SastEngineVersion), w.RulesetVersion, nullString(w.AdvisorySnapshot), rollupHash, nullInt(w.RecallCandidates))
	if err != nil {
		return 0, fmt.Errorf("store: recording scan run: %w", err)
	}
	return r.LastInsertId()
}

func (t *writer) auditRecord(scanRunID int64, w ScanWrite, payload []byte, payloadSHA string) (int64, error) {
	s := w.Seal
	var sastSealed, dastSealed any
	if s.Sast.SealedAt != nil {
		sastSealed = ts(*s.Sast.SealedAt)
	}
	if s.Dast.SealedAt != nil {
		dastSealed = ts(*s.Dast.SealedAt)
	}
	var dastDeadline any
	if s.DastDeadlineSeconds != nil {
		dastDeadline = *s.DastDeadlineSeconds
	}
	r, err := t.c.ExecContext(t.ctx, `
INSERT INTO audit_record (scan_run_id, schema_version, audit_version, state, sast_status, sast_sealed_at,
                          dast_status, dast_sealed_at, target_provenance, deadline_at,
                          claim_timeout_seconds, dast_deadline_seconds, payload, payload_sha256, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanRunID, record.SchemaVersion, w.AuditVersion, string(s.State), string(s.Sast.Status), sastSealed,
		string(s.DastStatus), dastSealed, string(w.Log.Properties.Target.Provenance), ts(s.DeadlineAt),
		s.ClaimTimeoutSeconds, dastDeadline, payload, payloadSHA, ts(s.StartedAt))
	if err != nil {
		return 0, fmt.Errorf("store: recording audit record: %w", err)
	}
	return r.LastInsertId()
}

// observe records one finding seen in this scan and returns its mark.
func (t *writer) observe(targetID, scanRunID int64, f seenFinding) (Mark, error) {
	m := Mark{Fingerprint: f.fingerprint, RuleID: f.ruleID, Title: f.title}
	var state string
	err := t.c.QueryRowContext(t.ctx,
		`SELECT finding_id, state FROM finding WHERE target_id = ? AND fingerprint = ?`,
		targetID, f.fingerprint).Scan(&m.FindingID, &state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		r, err := t.c.ExecContext(t.ctx, `
INSERT INTO finding (target_id, fingerprint, detector, evidence_class, rule_id, verdict, remediable_by_agent,
                     severity, title, state, first_seen_scan, first_seen_at, last_seen_scan, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)`,
			targetID, f.fingerprint, f.detector, f.evidenceClass, f.ruleID, f.verdict, boolInt(f.remediable),
			f.severity, f.title, scanRunID, t.now, scanRunID, t.now)
		if err != nil {
			return Mark{}, fmt.Errorf("store: recording finding %s: %w", f.fingerprint, err)
		}
		if m.FindingID, err = r.LastInsertId(); err != nil {
			return Mark{}, err
		}
		if _, err := t.c.ExecContext(t.ctx, `
INSERT INTO finding_fingerprint (finding_id, kind, alg, value) VALUES (?, 'primary', ?, ?)`,
			m.FindingID, record.FingerprintAlgV1, f.fingerprint); err != nil {
			return Mark{}, fmt.Errorf("store: recording fingerprint %s: %w", f.fingerprint, err)
		}
		if err := t.event(m.FindingID, scanRunID, "", "open", "first_seen"); err != nil {
			return Mark{}, err
		}
		m.Kind = MarkNew
	case err != nil:
		return Mark{}, fmt.Errorf("store: reading finding %s: %w", f.fingerprint, err)
	case state == "resolved":
		if _, err := t.c.ExecContext(t.ctx, `
UPDATE finding SET state = 'regressed', resolved_at = NULL, last_seen_scan = ?, last_seen_at = ?
WHERE finding_id = ?`, scanRunID, t.now, m.FindingID); err != nil {
			return Mark{}, fmt.Errorf("store: marking %s regressed: %w", f.fingerprint, err)
		}
		if err := t.event(m.FindingID, scanRunID, "resolved", "regressed", "regression"); err != nil {
			return Mark{}, err
		}
		m.Kind = MarkRegressed
	default:
		if _, err := t.c.ExecContext(t.ctx,
			`UPDATE finding SET last_seen_scan = ?, last_seen_at = ? WHERE finding_id = ?`,
			scanRunID, t.now, m.FindingID); err != nil {
			return Mark{}, fmt.Errorf("store: updating %s: %w", f.fingerprint, err)
		}
		m.Kind = MarkPersisting
	}
	var staleness any
	if f.staleness != nil {
		staleness = *f.staleness
	}
	if _, err := t.c.ExecContext(t.ctx, `
INSERT INTO finding_occurrence (finding_id, scan_run_id, message, evidence_ref, advisory_as_of,
                                advisory_staleness_seconds, advisory_parse_degraded)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		m.FindingID, scanRunID, nullString(f.message), f.evidenceRef, nullString(f.advisoryAsOf), staleness,
		boolInt(f.parseDegraded)); err != nil {
		return Mark{}, fmt.Errorf("store: recording occurrence of %s: %w", f.fingerprint, err)
	}
	return m, nil
}

// resolveAbsent marks fixed every open or regressed finding of the detectors
// this scan ran that the scan did not see. It runs only for a scan whose
// status is ok.
func (t *writer) resolveAbsent(targetID, scanRunID int64, detectors []record.DetectorKind, seen []seenFinding) ([]Mark, error) {
	if len(detectors) == 0 {
		return nil, nil
	}
	seenFP := map[string]bool{}
	for _, f := range seen {
		seenFP[f.fingerprint] = true
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(detectors)), ",")
	args := []any{targetID}
	for _, d := range detectors {
		args = append(args, string(d))
	}
	rows, err := t.c.QueryContext(t.ctx, `
SELECT finding_id, fingerprint, rule_id, title, state FROM finding
WHERE target_id = ? AND state IN ('open', 'regressed') AND detector IN (`+ph+`)
ORDER BY fingerprint`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: reading open findings: %w", err)
	}
	type candidate struct {
		m     Mark
		state string
	}
	var absent []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.m.FindingID, &c.m.Fingerprint, &c.m.RuleID, &c.m.Title, &c.state); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if !seenFP[c.m.Fingerprint] {
			absent = append(absent, c)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var out []Mark
	for _, c := range absent {
		if _, err := t.c.ExecContext(t.ctx,
			`UPDATE finding SET state = 'resolved', resolved_at = ? WHERE finding_id = ?`,
			t.now, c.m.FindingID); err != nil {
			return nil, fmt.Errorf("store: resolving %s: %w", c.m.Fingerprint, err)
		}
		if err := t.event(c.m.FindingID, scanRunID, c.state, "resolved", "absent_in_scan"); err != nil {
			return nil, err
		}
		c.m.Kind = MarkFixed
		out = append(out, c.m)
	}
	return out, nil
}

func (t *writer) event(findingID, scanRunID int64, from, to, cause string) error {
	_, err := t.c.ExecContext(t.ctx, `
INSERT INTO finding_state_event (finding_id, scan_run_id, from_state, to_state, cause, at)
VALUES (?, ?, ?, ?, ?, ?)`, findingID, scanRunID, nullString(from), to, cause, t.now)
	if err != nil {
		return fmt.Errorf("store: recording state event: %w", err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// FindingRow is one finding as `anvil findings` lists it.
type FindingRow struct {
	Target, Detector, RuleID, Severity, Title, State, Fingerprint string
	FirstSeenAt, LastSeenAt                                       string
}

// ListFindings reads findings back, open and regressed ones only unless all is
// set, optionally for one target locator.
func ListFindings(ctx context.Context, db *sql.DB, targetLocator string, all bool) ([]FindingRow, error) {
	q := `
SELECT t.locator, f.detector, f.rule_id, f.severity, f.title, f.state, f.fingerprint,
       f.first_seen_at, ifnull(f.last_seen_at, '')
FROM finding f JOIN target t ON t.target_id = f.target_id
WHERE (? = '' OR t.locator = ?) AND (? OR f.state IN ('open', 'regressed'))
ORDER BY t.locator, f.state, f.rule_id, f.fingerprint`
	rows, err := db.QueryContext(ctx, q, targetLocator, targetLocator, all)
	if err != nil {
		return nil, fmt.Errorf("store: listing findings: %w", err)
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		if err := rows.Scan(&r.Target, &r.Detector, &r.RuleID, &r.Severity, &r.Title, &r.State,
			&r.Fingerprint, &r.FirstSeenAt, &r.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
