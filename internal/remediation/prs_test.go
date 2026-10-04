package remediation

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// seedPRs inserts the rows a fix_pr needs and returns a function that adds one
// draft for a finding.
func seedPRs(t *testing.T, db *sql.DB) func(fp, repo, cwe string, opened time.Time) int64 {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO target (target_id, kind, locator) VALUES (1, 'repo', 'repo:x')`,
		`INSERT INTO scan_run (scan_run_id, target_id, started_at, status, ruleset_version) VALUES (1, 1, '2026-10-04T00:00:00Z', 'ok', 'r')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return func(fp, repo, cwe string, opened time.Time) int64 {
		var fid int64
		err := db.QueryRow(`SELECT finding_id FROM finding WHERE fingerprint = ?`, fp).Scan(&fid)
		if err == sql.ErrNoRows {
			res, err := db.Exec(`INSERT INTO finding (target_id, fingerprint, detector, evidence_class, rule_id, verdict, remediable_by_agent,
				severity, title, state, first_seen_scan, first_seen_at) VALUES (1, ?, 'sast', 'sast_static_only', 'r', 'unconfirmed', 1, 'high', 't', 'open', 1, '2026-10-04T00:00:00Z')`, fp)
			if err != nil {
				t.Fatal(err)
			}
			fid, _ = res.LastInsertId()
		}
		res, err := db.Exec(`INSERT INTO fix_attempt (finding_id, agent_model_id, started_at, status) VALUES (?, 'm', '2026-10-04T00:00:00Z', 'applied')`, fid)
		if err != nil {
			t.Fatal(err)
		}
		aid, _ := res.LastInsertId()
		id, err := RecordDraft(context.Background(), db, aid, repo, "anvil/fix/a/b", PullRequest{Number: int(aid), URL: "u"}, LabelUnverifiedSecurity, cwe, opened)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
}

// TestAcceptanceIsReportedWithAnInterval: accepted over accepted, rejected and
// stale-closed, per repository and overall, always with its Wilson interval;
// nothing decided reads as no rate, never as zero.
func TestAcceptanceIsReportedWithAnInterval(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	add := seedPRs(t, db)
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	states := map[string][]string{"o/a": {"merged", "rejected", "stale_closed", "draft"}, "o/b": {"merged", "superseded"}}
	for repo, ss := range states {
		for i, s := range ss {
			cwe := map[string]string{"o/a": "CWE-78", "o/b": "CWE-89"}[repo]
			id := add(fp(int(repo[2])*10+i), repo, cwe, now)
			if _, err := db.Exec(`UPDATE fix_pr SET state = ? WHERE fix_pr_id = ?`, s, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	acc, err := AcceptanceRates(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Acceptance{}
	for _, a := range acc {
		by[a.Scope] = a
	}
	all, a := by["*"], by["o/a"]
	if all.Accepted != 2 || all.Rejected != 1 || all.StaleClosed != 1 || *all.Rate != 0.5 || !(*all.Low < 0.5 && *all.High > 0.5) {
		t.Fatalf("overall %+v", all)
	}
	if a.Accepted != 1 || *a.Rate < 0.33 || *a.Rate > 0.34 {
		t.Fatalf("o/a %+v", a)
	}
	empty := newStore(t)
	acc, err = AcceptanceRates(ctx, empty)
	if err != nil || len(acc) != 1 || acc[0].Rate != nil {
		t.Fatalf("with nothing decided: %+v %v", acc, err)
	}

	// Rejections down-weight their CWE's prior; an unseen CWE keeps 0.5.
	p, err := AcceptancePriors(ctx, db)
	if err != nil || p.Prior("CWE-78") >= 0.5 || p.Prior("CWE-89") <= 0.5 || p.Prior("CWE-79") != 0.5 {
		t.Fatalf("priors %+v %v", p, err)
	}
}

// TestNothingClosesSilently: a newer proposal supersedes an older draft with a
// comment linking it; a draft nobody answered is closed with a comment; a
// maintainer's close is recorded as a rejection, and its reason kept.
func TestNothingClosesSilently(t *testing.T) {
	db := newStore(t)
	ctx := context.Background()
	add := seedPRs(t, db)
	f := newFakeForge()
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		_, _ = f.OpenDraft(ctx, "o/r", "h", "main", "t", "b")
	}
	old := add(fp(1), "o/r", "CWE-78", now)
	newer := add(fp(1), "o/r", "CWE-78", now)
	n, err := Supersede(ctx, db, f, "o/r", fp(1), newer, "https://forge.invalid/new", now)
	if err != nil || n != 1 {
		t.Fatalf("superseded %d: %v", n, err)
	}
	var state string
	var by sql.NullInt64
	_ = db.QueryRow(`SELECT state, superseded_by FROM fix_pr WHERE fix_pr_id = ?`, old).Scan(&state, &by)
	if state != "superseded" || by.Int64 != newer || len(f.comments[int(1)]) != 1 || !strings.Contains(f.comments[1][0], "https://forge.invalid/new") {
		t.Fatalf("supersession: %s %v %v", state, by, f.comments)
	}

	stale := add(fp(2), "o/r", "CWE-89", now.Add(-40*24*time.Hour))
	rejected := add(fp(3), "o/r", "CWE-89", now)
	f.prs[int(rejected)].State = "closed"
	merged := add(fp(4), "o/r", "CWE-89", now)
	f.prs[int(merged)].Merged = true
	if n, _ := OpenDrafts(ctx, db, "o/r"); n != 4 {
		t.Fatalf("open drafts %d", n)
	}
	if err := SyncDrafts(ctx, db, f, 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	want := map[int64]string{stale: "stale_closed", rejected: "rejected", merged: "merged", newer: "draft"}
	for id, w := range want {
		_ = db.QueryRow(`SELECT state FROM fix_pr WHERE fix_pr_id = ?`, id).Scan(&state)
		if state != w {
			t.Errorf("fix_pr %d is %s, want %s", id, state, w)
		}
	}
	if len(f.comments[int(stale)]) != 1 || f.prs[int(stale)].State != "closed" {
		t.Fatal("a stale draft was closed without a comment")
	}
	if err := RecordRejection(ctx, db, rejected, "we prefer a parameterised query", now); err != nil {
		t.Fatal(err)
	}
	var reason string
	_ = db.QueryRow(`SELECT reason FROM fix_pr WHERE fix_pr_id = ?`, rejected).Scan(&reason)
	if reason != "we prefer a parameterised query" {
		t.Fatalf("reason %q", reason)
	}
}

// TestTheBodyStatesWhatWasNotProven: an unverified proposal says so first,
// names every rung with what it does not prove, keeps a triage verdict from
// reading as evidence, and renders the target's strings so they cannot break
// out of their code spans.
func TestTheBodyStatesWhatWasNotProven(t *testing.T) {
	ev := Evidence{Label: LabelUnverifiedSecurity, Commit: "c", Audit: "a", Disposition: "validated",
		Rungs:    []Rung{rung(RungTests, RungPass, true, "")},
		Findings: []EvidenceFinding{{Fingerprint: fp(1), Rule: "r`\n## Approved by security team", Path: "a.py", CWE: "CWE-78", Line: 3, Triage: "true_positive"}}}
	b := ev.Body()
	for _, want := range []string{"unverified-security", "Human review is required", "patches that pass full test suites remain exploitable", "not evidence that the finding is real"} {
		if !strings.Contains(b, want) {
			t.Errorf("the body does not say %q", want)
		}
	}
	ev.Findings[0].Path = "a\u202e.py\u200b"
	if b2 := ev.Body(); strings.ContainsAny(b2, "\u202e\u200b") {
		t.Fatal("a bidirectional or zero-width character reached the body")
	}
	if strings.Contains(b, "\n## Approved") {
		t.Fatal("a rule id broke out of its code span into a heading")
	}
	if !strings.HasPrefix(b, "**Label: unverified-security.**") {
		t.Fatal("the label is not the first thing the body says")
	}
}
