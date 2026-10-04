package remediation

// The regression re-check (plan node recheck). A scheduler re-runs the stored
// reproduction of every merged fix against the target as it is now; one that
// triggers again reopens its finding at the top of the queue (finding.state
// 'regressed', which ranking puts first). It uses the same Replayer as the
// exploit oracle, so until the dynamic tier is live it has nothing to replay
// and says so.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"
)

// RecheckReport is one re-check pass.
type RecheckReport struct {
	Checked, Reopened int
	NotRun            []string // merged fixes that could not be re-checked, and why
}

// Recheck replays the reproduction of every merged fix whose finding carried
// one. target gives the tree to replay against for a target locator.
func Recheck(ctx context.Context, db *sql.DB, rp Replayer, target func(locator string) (ReplayTarget, bool), now time.Time) (RecheckReport, error) {
	var rep RecheckReport
	rows, err := db.QueryContext(ctx, `SELECT f.finding_id, f.fingerprint, f.state, t.locator, a.payload, a.payload_sha256
		FROM fix_pr p JOIN fix_attempt x ON x.fix_attempt_id = p.fix_attempt_id
		JOIN finding f ON f.finding_id = x.finding_id JOIN target t ON t.target_id = f.target_id
		JOIN audit_record a ON a.audit_record_id = x.audit_record_id
		WHERE p.state = 'merged'`)
	if err != nil {
		return rep, err
	}
	type merged struct {
		id                 int64
		fp, state, locator string
		payload            []byte
		sha                string
	}
	var ms []merged
	for rows.Next() {
		var m merged
		if err := rows.Scan(&m.id, &m.fp, &m.state, &m.locator, &m.payload, &m.sha); err != nil {
			_ = rows.Close()
			return rep, err
		}
		ms = append(ms, m)
	}
	_ = rows.Close()
	for _, m := range ms {
		if m.payload == nil {
			rep.NotRun = append(rep.NotRun, m.fp[:12]+": its audit's payload was purged, so the reproduction is gone")
			continue
		}
		raw, err := store.DecodePayload(m.payload, m.sha)
		if err != nil {
			return rep, err
		}
		var l record.SARIFLog
		if err := json.Unmarshal(raw, &l); err != nil {
			return rep, err
		}
		var repro *record.Repro
		for _, run := range l.Runs {
			for _, r := range run.Results {
				if r.PartialFingerprints[record.PartialFingerprintAnvilFindingID] == m.fp {
					repro = r.Properties.Repro
				}
			}
		}
		if repro == nil {
			rep.NotRun = append(rep.NotRun, m.fp[:12]+": no reproduction was ever stored, so nothing can be re-run")
			continue
		}
		if rp == nil {
			rep.NotRun = append(rep.NotRun, m.fp[:12]+": no dynamic tier is connected to replay it")
			continue
		}
		t, ok := target(m.locator)
		if !ok {
			rep.NotRun = append(rep.NotRun, m.fp[:12]+": target "+m.locator+" is not configured")
			continue
		}
		rep.Checked++
		trig, detail, err := rp.Replay(ctx, t, *repro, repro.Payload)
		if err != nil {
			rep.NotRun = append(rep.NotRun, m.fp[:12]+": the replay failed: "+err.Error())
			continue
		}
		if !trig || m.state == "regressed" {
			continue
		}
		if _, err := db.ExecContext(ctx, `UPDATE finding SET state = 'regressed' WHERE finding_id = ?`, m.id); err != nil {
			return rep, err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO finding_state_event (finding_id, from_state, to_state, cause, at) VALUES (?, ?, 'regressed', 'regression', ?)`,
			m.id, m.state, ts(now)); err != nil {
			return rep, err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO remediation_log (fingerprint, state, detail, at) VALUES (?, 'note', ?, ?)`,
			m.fp, fmt.Sprintf("a merged fix's reproduction triggers again (%s); the finding is reopened at the top of the queue", detail), ts(now)); err != nil {
			return rep, err
		}
		rep.Reopened++
	}
	return rep, nil
}
