package remediation

// Draft pull requests in the store (fix_pr, migration 0003): the open limit,
// the evidence body, supersession, syncing a draft's fate from the forge, and
// the acceptance rate the regression re-check reports (plan nodes prs and
// recheck).

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// MaxOpenPerRepository is gate 16's ceiling: at most three open Anvil pull
// requests per repository. Pull-request spam is how maintainer channels
// close, so the limit is part of the lifecycle, not an afterthought.
const MaxOpenPerRepository = 3

// OpenDrafts counts Anvil's open drafts on a repository.
func OpenDrafts(ctx context.Context, db *sql.DB, repo string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM fix_pr WHERE repository = ? AND state = 'draft'`, repo).Scan(&n)
	return n, err
}

// Evidence is what a pull request body states.
type Evidence struct {
	Label       Label
	Findings    []EvidenceFinding
	Rungs       []Rung
	Oracle      OracleResult
	Disposition string
	Commit      string
	Audit       string
}

// EvidenceFinding is one finding in the group, as the body names it.
type EvidenceFinding struct {
	Fingerprint, Rule, CWE, Path string
	Line                         int
	Triage                       string // "" when no triage ran
}

// inlineCode renders untrusted text as one Markdown code span that cannot
// break out: no newline, no backtick.
func inlineCode(s string) string {
	return "`" + strings.ReplaceAll(plainText(s, 200), "`", " ") + "`"
}

// Body renders the pull request's body: every rung's result with what it
// proves and does not, the label it earned, and the disposition report.
func (e Evidence) Body() string {
	var b strings.Builder
	switch e.Label {
	case LabelVerifiedFixed:
		b.WriteString("**Label: verified fixed.** The stored reproduction and every mutated payload no longer trigger against the patched target.\n\n")
	default:
		b.WriteString("**Label: unverified-security.** No reproduction proved this patch fixes the finding. " +
			"It built and passed the checks below, and none of them shows the vulnerability is gone. " +
			"Human review is required and cannot be waived.\n\n")
	}
	b.WriteString("This is a draft proposed by Anvil, a scanner. Nothing merges without a maintainer.\n\n## Findings\n\n")
	for _, f := range e.Findings {
		fmt.Fprintf(&b, "- %s at %s line %d (%s), fingerprint %s", inlineCode(f.Rule), inlineCode(f.Path), f.Line, inlineCode(f.CWE), inlineCode(f.Fingerprint))
		if f.Triage != "" {
			fmt.Fprintf(&b, "; triage gate: %s (a triage verdict is not evidence that the finding is real)", f.Triage)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Validation\n\n| Check | Result | Proves | Does not prove |\n|---|---|---|---|\n")
	for _, r := range e.Rungs {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.Name, r.Result, r.Proves, r.DoesNotProve)
	}
	fmt.Fprintf(&b, "\nExploit oracle: %s", e.Oracle.Verdict)
	if e.Oracle.Detail != "" {
		fmt.Fprintf(&b, " (%s)", e.Oracle.Detail)
	}
	fmt.Fprintf(&b, "\n\n## Disposition\n\n%s. Commit %s, audit %s.\n", e.Disposition, inlineCode(e.Commit), inlineCode(e.Audit))
	return b.String()
}

// RecordDraft stores a newly opened draft.
func RecordDraft(ctx context.Context, db *sql.DB, attemptID int64, repo, branch string, pr PullRequest, label Label, cwe string, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `INSERT INTO fix_pr (fix_attempt_id, repository, branch, number, url, label, state, cwe, opened_at)
		VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?)`, attemptID, repo, branch, pr.Number, pr.URL, string(label), cwe, ts(now))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Supersede closes older open drafts for the same finding with a comment
// linking the newer one. A better later patch replaces an older draft; it
// never sits beside it, and nothing closes silently.
func Supersede(ctx context.Context, db *sql.DB, f Forge, repo, fingerprint string, newPR int64, newURL string, now time.Time) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT p.fix_pr_id, p.repository, p.number FROM fix_pr p
		JOIN fix_attempt a ON a.fix_attempt_id = p.fix_attempt_id
		JOIN finding fi ON fi.finding_id = a.finding_id
		WHERE fi.fingerprint = ? AND p.repository = ? AND p.state = 'draft' AND p.fix_pr_id != ?`, fingerprint, repo, newPR)
	if err != nil {
		return 0, err
	}
	type old struct {
		id     int64
		repo   string
		number int
	}
	var olds []old
	for rows.Next() {
		var o old
		if err := rows.Scan(&o.id, &o.repo, &o.number); err != nil {
			_ = rows.Close()
			return 0, err
		}
		olds = append(olds, o)
	}
	_ = rows.Close()
	for _, o := range olds {
		if err := f.Comment(ctx, o.repo, o.number, "Superseded by a newer Anvil proposal for the same finding: "+newURL); err != nil {
			return 0, err
		}
		if err := f.Close(ctx, o.repo, o.number); err != nil {
			return 0, err
		}
		if _, err := db.ExecContext(ctx, `UPDATE fix_pr SET state = 'superseded', superseded_by = ?, closed_at = ?, reason = ?
			WHERE fix_pr_id = ?`, newPR, ts(now), "superseded by a newer proposal", o.id); err != nil {
			return 0, err
		}
	}
	return len(olds), nil
}

// SyncDrafts reads each open draft's fate from the forge: merged, closed by a
// maintainer (rejected, with reason when one was recorded), or left open past
// staleAfter (closed by Anvil with a comment, stale_closed).
func SyncDrafts(ctx context.Context, db *sql.DB, f Forge, staleAfter time.Duration, now time.Time) error {
	rows, err := db.QueryContext(ctx, `SELECT fix_pr_id, repository, number, opened_at FROM fix_pr WHERE state = 'draft' AND number IS NOT NULL`)
	if err != nil {
		return err
	}
	type open struct {
		id     int64
		repo   string
		number int
		opened time.Time
	}
	var opens []open
	for rows.Next() {
		var o open
		var at string
		if err := rows.Scan(&o.id, &o.repo, &o.number, &at); err != nil {
			_ = rows.Close()
			return err
		}
		o.opened, _ = time.Parse(time.RFC3339, at)
		opens = append(opens, o)
	}
	_ = rows.Close()
	for _, o := range opens {
		pr, err := f.Get(ctx, o.repo, o.number)
		if err != nil {
			return err
		}
		switch {
		case pr.Merged:
			_, err = db.ExecContext(ctx, `UPDATE fix_pr SET state = 'merged', closed_at = ? WHERE fix_pr_id = ?`, ts(now), o.id)
		case pr.State == "closed":
			_, err = db.ExecContext(ctx, `UPDATE fix_pr SET state = 'rejected', closed_at = ?, reason = COALESCE(reason, 'closed by a maintainer without merging') WHERE fix_pr_id = ?`, ts(now), o.id)
		case staleAfter > 0 && now.Sub(o.opened) > staleAfter:
			if err = f.Comment(ctx, o.repo, o.number, fmt.Sprintf("Closing: this Anvil proposal had no response for %s.", staleAfter)); err != nil {
				return err
			}
			if err = f.Close(ctx, o.repo, o.number); err != nil {
				return err
			}
			_, err = db.ExecContext(ctx, `UPDATE fix_pr SET state = 'stale_closed', closed_at = ?, reason = 'no response' WHERE fix_pr_id = ?`, ts(now), o.id)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// RecordRejection stores a maintainer's stated reason for closing a draft.
func RecordRejection(ctx context.Context, db *sql.DB, prID int64, reason string, now time.Time) error {
	if len(reason) > 2000 {
		reason = reason[:2000]
	}
	_, err := db.ExecContext(ctx, `UPDATE fix_pr SET state = 'rejected', reason = ?, closed_at = COALESCE(closed_at, ?) WHERE fix_pr_id = ?`, reason, ts(now), prID)
	return err
}

// Acceptance is an acceptance rate with its 95% Wilson interval. Early numbers
// are small samples; the interval is reported, never a point estimate alone.
type Acceptance struct {
	Scope                           string
	Accepted, Rejected, StaleClosed int
	// Rate, Low and High are nil when nothing has been decided.
	Rate, Low, High *float64
}

// AcceptanceRates is accepted over accepted, rejected and stale-closed, per
// repository and over all of them (scope "*"). Superseded and still-open
// drafts are not decided and not counted.
func AcceptanceRates(ctx context.Context, db *sql.DB) ([]Acceptance, error) {
	rows, err := db.QueryContext(ctx, `SELECT repository, state, count(*) FROM fix_pr
		WHERE state IN ('merged', 'rejected', 'stale_closed') GROUP BY repository, state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]*Acceptance{"*": {Scope: "*"}}
	for rows.Next() {
		var repo, state string
		var n int
		if err := rows.Scan(&repo, &state, &n); err != nil {
			return nil, err
		}
		if by[repo] == nil {
			by[repo] = &Acceptance{Scope: repo}
		}
		for _, a := range []*Acceptance{by[repo], by["*"]} {
			switch state {
			case "merged":
				a.Accepted += n
			case "rejected":
				a.Rejected += n
			case "stale_closed":
				a.StaleClosed += n
			}
		}
	}
	var out []Acceptance
	for _, a := range by {
		if n := a.Accepted + a.Rejected + a.StaleClosed; n > 0 {
			r, lo, hi := wilson(a.Accepted, n)
			a.Rate, a.Low, a.High = &r, &lo, &hi
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out, rows.Err()
}

func wilson(k, n int) (rate, low, high float64) {
	const z = 1.959963984540054
	p := float64(k) / float64(n)
	nf := float64(n)
	den := 1 + z*z/nf
	mid := (p + z*z/(2*nf)) / den
	half := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf)) / den
	return p, math.Max(0, mid-half), math.Min(1, mid+half)
}

// AcceptancePriors learns the per-CWE prior from Anvil's own outcomes: a
// Laplace-smoothed acceptance rate, so a CWE with no history keeps the
// uniform 0.5 and each rejection down-weights its CWE.
func AcceptancePriors(ctx context.Context, db *sql.DB) (Priors, error) {
	p := Priors{Default: 0.5, ByCWE: map[string]float64{}}
	rows, err := db.QueryContext(ctx, `SELECT cwe, sum(state = 'merged'), count(*) FROM fix_pr
		WHERE cwe IS NOT NULL AND state IN ('merged', 'rejected', 'stale_closed') GROUP BY cwe`)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var cwe string
		var acc, n int
		if err := rows.Scan(&cwe, &acc, &n); err != nil {
			return p, err
		}
		p.ByCWE[cwe] = (float64(acc) + 1) / (float64(n) + 2)
	}
	return p, rows.Err()
}
