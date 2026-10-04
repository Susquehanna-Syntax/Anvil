package remediation

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/handoff"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/laneb"
	"github.com/Susquehanna-Syntax/Anvil/internal/recall/recalltest"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/scan"
	"github.com/Susquehanna-Syntax/Anvil/internal/scanctl"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"
)

const fixtureLocator = "repo:laneb-fixture"

// world is one remediation installation in a temporary directory: a git
// checkout of Lane B's fixture, the store, the advisory cache and a controller
// wired to a scripted model, an in-process forge and a pass-through sandbox.
type world struct {
	t       *testing.T
	repo    string
	db      *sql.DB
	cache   *sql.DB
	q       *handoff.Queue
	ctl     *Controller
	gen     *fakeGen
	forge   *fakeForge
	pushes  *[]string
	snippet map[string][2]string // fingerprint -> path, code
}

type recordingPusher struct {
	mu     *sync.Mutex
	pushes *[]string
}

func (p recordingPusher) Push(_ context.Context, _, branch string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	*p.pushes = append(*p.pushes, branch)
	return nil
}

// newWorld copies the fixture into a fresh git repository, letting edit change
// files first.
func newWorld(t *testing.T, edit func(dir string)) *world {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "laneb-fixture")
	src := recalltest.FixtureRoot()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(repo, rel), 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(repo, rel), raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(repo)
	}
	g := Git{Dir: repo}
	ctx := context.Background()
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "-A"}, {"commit", "-q", "-m", "fixture"}} {
		if _, err := g.run(ctx, nil, args...); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	c, err := cache.Open(ctx, filepath.Join(dir, "anvil-cache.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := cache.Migrate(ctx, c); err != nil {
		t.Fatal(err)
	}
	db := newStore(t)
	q, err := handoff.New(db, handoff.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cons, err := scanctl.NewConsumer(q, scanctl.DeadlinePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, repo: repo, db: db, cache: c, q: q, forge: newFakeForge(), pushes: &[]string{}, snippet: map[string][2]string{}}
	w.gen = &fakeGen{answer: w.answer}
	w.ctl = &Controller{
		DB: db, Consumer: cons, Gen: w.gen, Triage: TriageGate, WorkDir: filepath.Join(dir, "work"),
		WorkerID: "worker-1", Bwrap: passSandbox(t), Forge: w.forge,
		Pusher: func(Target) Pusher { return recordingPusher{mu: &sync.Mutex{}, pushes: w.pushes} },
		Targets: map[string]Target{fixtureLocator: {Locator: fixtureLocator, Source: repo, Build: exportOnlyBuild, Test: []string{"true"},
			Repository: "upstream/fixture", Fork: "anvil-bot/fixture", BaseBranch: "main"}},
		Rescan: func(string) func(context.Context, string, []string) (map[string]bool, error) { return w.rescan },
	}
	return w
}

// scan runs a repository scan of the checkout through the scan path, with
// Lane B's recorded tool output, and enqueues the sealed audit.
func (w *world) scan() int64 {
	w.t.Helper()
	ctx := context.Background()
	res, err := scan.Run(ctx, scan.Request{
		Kind: scan.KindRepo, RepoPath: w.repo, TargetName: "laneb-fixture", Event: "manual",
		Cache: w.cache, Store: w.db, AnvilVersion: "test",
		LaneB: &laneb.Config{Rules: recalltest.RulePack(), Tools: recalltest.Tools(), Exec: &recalltest.Replay{Root: w.repo}},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	for _, r := range res.Log.Runs[0].Results {
		loc := r.Locations[0].PhysicalLocation
		w.snippet[r.PartialFingerprints[record.PartialFingerprintAnvilFindingID]] = [2]string{loc.ArtifactLocation.URI, loc.Region.Snippet.Text}
	}
	id, err := store.ResolveAuditRecordID(ctx, w.db, res.AuditID)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.ctl.EnqueueAudit(ctx, w.q, id); err != nil {
		w.t.Fatal(err)
	}
	return id
}

// newBug is the fingerprint the scripted rescan reports for a file carrying
// the marker NEWBUG: a finding the scanned audit did not have.
var newBug = fp(999)

// rescan stands in for Lane B over the patched files: a finding is still
// there while its matched code is.
func (w *world) rescan(_ context.Context, root string, files []string) (map[string]bool, error) {
	found := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(raw), "NEWBUG") {
			found[newBug] = true
		}
		for fp, s := range w.snippet {
			if s[0] == f && strings.Contains(string(raw), s[1]) {
				found[fp] = true
			}
		}
	}
	return found, nil
}

const appPyFixed = `"""Planted for Lane B's fixture. Never run."""
import subprocess
import sys
import ast


def run_expression():
    return ast.literal_eval(sys.argv[1])


def run_command(cmd):
    return subprocess.call(cmd.split(), shell=False)
`

// answer is the scripted model: a triage verdict by finding, and an edit (or
// nonsense) by file.
func (w *world) answer(msgs []Message) (string, error) {
	text := userText(msgs)
	has := func(path string) bool { return strings.Contains(text, Fence("path", path)) }
	if isTriage(msgs) {
		switch {
		case has("src/Digest.java"):
			return `{"verdict": "false_positive", "reason": "a fixture"}`, nil
		case strings.Contains(text, "B404"):
			return `{"verdict": "insufficient_context", "reason": "an import alone says nothing"}`, nil
		}
		return `{"verdict": "plausible", "reason": "input reaches the sink"}`, nil
	}
	switch {
	case has("src/copy.c"):
		return edit("src/copy.c", "    strcpy(buf, src);", `    snprintf(buf, sizeof buf, "%s", src);`), nil
	case has("src/app.py"):
		return "FILE: src/app.py\n<<<<<<< WHOLE\n" + appPyFixed + ">>>>>>> WHOLE\n", nil
	case has("src/main.go"):
		return edit("src/main.go", `	return exec.Command("sh", "-c", name).Run()`, `	return exec.Command("sh", "-c", name).Run() // NEWBUG`), nil
	case has("src/suppressed.py"):
		return edit("src/suppressed.py", `"""Planted`, `"""Still planted`), nil
	}
	return "I would rather not.", nil
}

func (w *world) states() map[string]string {
	w.t.Helper()
	rows, err := w.db.Query(`SELECT fingerprint, state FROM handoff WHERE audit_record_id = (SELECT max(audit_record_id) FROM handoff)`)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var fp, s string
		_ = rows.Scan(&fp, &s)
		out[fp] = s
	}
	return out
}

// allStates is every state any handoff row holds, across audits.
func (w *world) allStates() map[string]string {
	w.t.Helper()
	rows, err := w.db.Query(`SELECT DISTINCT state FROM handoff`)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out[s] = s
	}
	return out
}

func (w *world) byPath(states map[string]string) map[string][]string {
	out := map[string][]string{}
	for fp, s := range states {
		out[w.snippet[fp][0]] = append(out[w.snippet[fp][0]], s)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

func (w *world) count(q string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.db.QueryRow(q, args...).Scan(&n); err != nil {
		w.t.Fatal(err)
	}
	return n
}

// fixCommits lists every commit on Anvil's fix branches in the controller's
// clone.
func (w *world) fixCommits() []string {
	w.t.Helper()
	g := Git{Dir: w.ctl.workDir(fixtureLocator)}
	base, err := (Git{Dir: w.repo}).Head(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	out, err := g.run(context.Background(), nil, "log", "--branches=anvil/fix/*", "--not", base, "--format=%H")
	if err != nil {
		w.t.Fatal(err)
	}
	return strings.Fields(string(out))
}

// TestTheControllerConsumesAnAuditToItsDispositions drives one sealed Lane B
// audit through the whole lane: every finding is taken, the triage gate
// decides each, and each group ends in the disposition its patch earned.
func TestTheControllerConsumesAnAuditToItsDispositions(t *testing.T) {
	w := newWorld(t, nil)
	auditRecordID := w.scan()
	ctx := context.Background()

	if n := w.count(`SELECT count(*) FROM handoff WHERE state = 'ready'`); n != 12 {
		t.Fatalf("%d ready rows after enqueue, want all 12 Lane B findings", n)
	}
	rep, err := w.ctl.Cycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := w.byPath(w.states())
	want := map[string][]string{
		"src/copy.c":        {"validated", "validated"},
		"src/Digest.java":   {"false_positive", "false_positive"},
		"src/main.go":       {"regression_introduced"},
		"web/app.js":        {"failed_format"},
		"src/suppressed.py": {"failed_validation", "failed_validation"},
	}
	for path, states := range want {
		if strings.Join(got[path], ",") != strings.Join(states, ",") {
			t.Errorf("%s: %v, want %v", path, got[path], states)
		}
	}
	// app.py: one group validated, the other fixed by that commit, and the
	// import, which the rewrite left as it was, judged by triage.
	app := strings.Join(got["src/app.py"], ",")
	if app != "fixed_incidentally,validated,withdrawn" && app != "fixed_incidentally,fixed_incidentally,validated,withdrawn" &&
		app != "fixed_incidentally,validated,validated,withdrawn" {
		t.Errorf("src/app.py: %v", got["src/app.py"])
	}
	if len(rep.PullRequests) != 2 || len(*w.pushes) != 2 {
		t.Fatalf("pull requests %v pushes %v notes %v", rep.PullRequests, *w.pushes, rep.Notes)
	}
	for _, c := range w.forge.calls {
		if strings.HasPrefix(c, "open ") && !strings.Contains(c, "anvil-bot:anvil/fix/") {
			t.Errorf("a pull request was not opened from the fork: %s", c)
		}
	}
	for n, body := range w.forge.bodies {
		if !strings.HasPrefix(body, "**Label: unverified-security.**") || !strings.Contains(body, "triage gate: true_positive (a triage verdict is not evidence") {
			t.Errorf("draft %d's body:\n%s", n, body)
		}
	}
	// Lane B's evidence is untouched: the record and the store still say
	// unconfirmed, and the triage gate's verdicts are their own rows.
	if n := w.count(`SELECT count(*) FROM finding WHERE verdict != 'unconfirmed'`); n != 0 {
		t.Fatalf("%d findings' verdicts were overwritten", n)
	}
	if n := w.count(`SELECT count(*) FROM triage_verdict WHERE audit_record_id = ?`, auditRecordID); n < 9 {
		t.Fatalf("%d triage verdicts stored", n)
	}
	// Every disposition is in the audit log with a reason.
	if n := w.count(`SELECT count(*) FROM handoff h WHERE NOT EXISTS (SELECT 1 FROM remediation_log l WHERE l.handoff_id = h.handoff_id AND l.state = h.state)`); n != 0 {
		t.Fatalf("%d dispositions have no audit-log line", n)
	}
	if n := w.count(`SELECT count(*) FROM remediation_log WHERE state = 'false_positive' AND detail LIKE 'triage gate: false positive%'`); n != 2 {
		t.Fatalf("the triage gate's false positives in the audit log: %d", n)
	}
	// A blocked patch is kept as a blob, never on a branch.
	if n := w.count(`SELECT count(*) FROM fix_attempt WHERE status = 'rejected' AND patch_ref LIKE 'blob:%'`); n < 3 {
		t.Fatalf("rejected attempts kept: %d", n)
	}
	if n := w.count(`SELECT count(*) FROM verification v JOIN fix_attempt a ON a.fix_attempt_id = v.fix_attempt_id WHERE a.status = 'applied' AND v.kind = 'human_review' AND v.result = 'inconclusive'`); n == 0 {
		t.Fatal("no validated attempt records the human review it still needs")
	}
	checkTrailers(t, w)
	// The scanned checkout itself was never written to.
	if out, _ := (Git{Dir: w.repo}).run(ctx, nil, "status", "--porcelain"); len(out) != 0 {
		t.Fatalf("the scanned checkout changed: %s", out)
	}
}

// checkTrailers is the remediation exit gate's row "every commit carries its
// three trailers": one audit, and for every finding its fingerprint and the
// idempotency key the handoff row holds for it.
func checkTrailers(t *testing.T, w *world) {
	t.Helper()
	ctx := context.Background()
	commits := w.fixCommits()
	if len(commits) == 0 {
		t.Fatal("no commit to check")
	}
	g := Git{Dir: w.ctl.workDir(fixtureLocator)}
	for _, sha := range commits {
		tr, err := g.TrailersOf(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Audit == "" || len(tr.Findings) == 0 || len(tr.Findings) != len(tr.Keys) {
			t.Fatalf("commit %s trailers %+v", sha, tr)
		}
		for i, f := range tr.Findings {
			var key string
			if err := w.db.QueryRow(`SELECT h.idempotency_key FROM handoff h JOIN audit_record a ON a.audit_record_id = h.audit_record_id
				WHERE h.fingerprint = ? AND a.audit_id = ?`, f, tr.Audit).Scan(&key); err != nil {
				t.Fatalf("commit %s names finding %s of audit %s, which has no handoff row: %v", sha, f, tr.Audit, err)
			}
			if key != tr.Keys[i] {
				t.Fatalf("commit %s: key %s, the handoff row holds %s", sha, tr.Keys[i], key)
			}
		}
	}
}

// TestReRunsAreIdempotent is the remediation exit gate's row "re-runs are
// idempotent": running again against the same audit and base commit makes no
// duplicate row, commit or pull request, and a crash between commit and
// disposition is recovered from the trailers without generating again.
func TestReRunsAreIdempotent(t *testing.T) {
	w := newWorld(t, nil)
	auditRecordID := w.scan()
	ctx := context.Background()
	if _, err := w.ctl.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	tables := []string{"handoff", "fix_attempt", "verification", "fix_pr", "triage_verdict"}
	before := map[string]int{}
	for _, tbl := range tables {
		before[tbl] = w.count(`SELECT count(*) FROM ` + tbl)
	}
	commits := len(w.fixCommits())
	prompts := len(w.gen.prompts)

	if rep, err := w.ctl.EnqueueAudit(ctx, w.q, auditRecordID); err != nil || rep.Superseded != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := w.ctl.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range tables {
		if n := w.count(`SELECT count(*) FROM ` + tbl); n != before[tbl] {
			t.Errorf("%s: %d rows after a re-run, %d before", tbl, n, before[tbl])
		}
	}
	if len(w.fixCommits()) != commits || len(w.gen.prompts) != prompts {
		t.Fatalf("a re-run committed or prompted again: commits %d -> %d, prompts %d -> %d", commits, len(w.fixCommits()), prompts, len(w.gen.prompts))
	}

	// The crash: the commit landed, the disposition did not, and the lease
	// lapsed and was reclaimed. The successor finds the trailers.
	if _, err := w.db.Exec(`UPDATE handoff SET state = 'ready', claimed_by = NULL, lease_expires_at = NULL WHERE state = 'validated'`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ctl.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	if n := w.count(`SELECT count(*) FROM handoff WHERE state = 'validated'`); n != 4 {
		t.Fatalf("%d validated after recovery", n)
	}
	if n := w.count(`SELECT count(*) FROM remediation_log WHERE detail LIKE 'already processed: commit % carries this idempotency key'`); n != 4 {
		t.Fatalf("%d recoveries logged", n)
	}
	for _, tbl := range []string{"fix_attempt", "fix_pr"} {
		if n := w.count(`SELECT count(*) FROM ` + tbl); n != before[tbl] {
			t.Errorf("%s: %d rows after recovery, %d before", tbl, n, before[tbl])
		}
	}
	if len(w.fixCommits()) != commits {
		t.Fatal("recovery committed again")
	}
	triage := 0
	for _, p := range w.gen.prompts[prompts:] {
		if !isTriage(p) {
			t.Fatal("recovery generated a patch again")
		}
		triage++
	}
	if triage != 0 {
		t.Fatalf("recovery asked the triage gate again %d times, though nothing changed", triage)
	}
}

// TestALostLeaseWritesNothing: the lease is taken from under the controller
// (it lapses and another worker claims the finding), once during generation
// and once during the ladder's rescan, the last step before the commit. The
// controller yields at the next step boundary: no commit, no attempt row, and
// the thief keeps the lease.
func TestALostLeaseWritesNothing(t *testing.T) {
	for _, stage := range []string{"generation", "rescan"} {
		t.Run(stage, func(t *testing.T) { lostLease(t, stage) })
	}
}

func lostLease(t *testing.T, stage string) {
	w := newWorld(t, nil)
	w.scan()
	ctx := context.Background()
	thief, err := scanctl.NewConsumer(w.q, scanctl.DeadlinePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	var stolen string
	steal := func() {
		if stolen != "" {
			return
		}
		// Expire every live lease, reclaim, and take copy.c's findings.
		if _, err := w.db.Exec(`UPDATE handoff SET lease_expires_at = '2000-01-01T00:00:00.000000000Z' WHERE state = 'leased'`); err != nil {
			t.Fatal(err)
		}
		if _, err := thief.ReclaimExpired(); err != nil {
			t.Fatal(err)
		}
		for fp, s := range w.snippet {
			if s[0] == "src/copy.c" {
				if _, err := thief.ClaimContext(ctx, fp, "thief"); err != nil {
					t.Fatal(err)
				}
				stolen = fp
			}
		}
	}
	w.gen.answer = func(msgs []Message) (string, error) {
		if stage == "generation" && !isTriage(msgs) && strings.Contains(userText(msgs), Fence("path", "src/copy.c")) {
			steal()
		}
		return w.answer(msgs)
	}
	w.ctl.Rescan = func(string) func(context.Context, string, []string) (map[string]bool, error) {
		return func(ctx context.Context, root string, files []string) (map[string]bool, error) {
			if stage == "rescan" && len(files) == 1 && files[0] == "src/copy.c" {
				steal()
			}
			return w.rescan(ctx, root, files)
		}
	}
	w.ctl.Targets = map[string]Target{fixtureLocator: {Locator: fixtureLocator, Source: w.repo, Build: []string{"true"}, Test: []string{"true"}}}
	rep, err := w.ctl.Cycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stolen == "" {
		t.Fatal("the theft never happened")
	}
	if n := w.count(`SELECT count(*) FROM handoff WHERE state = 'leased' AND claimed_by = 'thief'`); n != 2 {
		t.Fatalf("the thief holds %d leases", n)
	}
	for _, sha := range w.fixCommits() {
		tr, _ := Git{Dir: w.ctl.workDir(fixtureLocator)}.TrailersOf(ctx, sha)
		for _, f := range tr.Findings {
			if w.snippet[f][0] == "src/copy.c" {
				t.Fatalf("a commit for copy.c landed after its lease was lost: %s", sha)
			}
		}
	}
	if n := w.count(`SELECT count(*) FROM fix_attempt a JOIN finding f ON f.finding_id = a.finding_id WHERE f.fingerprint = ?`, stolen); n != 0 {
		t.Fatalf("%d attempt rows for a lost lease", n)
	}
	yielded := false
	for _, n := range rep.Notes {
		yielded = yielded || strings.Contains(n, "yielding")
	}
	if !yielded {
		t.Fatalf("no yield was reported: %v", rep.Notes)
	}
}

// TestEveryDispositionIsReachable is the remediation exit gate's row "every
// disposition is reachable and tested": all thirteen handoff.state literals
// are reached through the code that writes them in production.
func TestEveryDispositionIsReachable(t *testing.T) {
	reached := map[string]bool{}
	note := func(states map[string]string) {
		for _, s := range states {
			reached[s] = true
		}
	}
	ctx := context.Background()

	// The full lane: validated, false_positive, regression_introduced,
	// failed_format, failed_validation, fixed_incidentally, withdrawn.
	a := newWorld(t, nil)
	a.scan()
	if _, err := a.ctl.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	note(a.allStates())

	// superseded, ready (handed back at the open limit), leased (seen from
	// inside generation), split_required (a file too large for the prompt).
	b := newWorld(t, func(dir string) {
		big := "/* " + strings.Repeat("padding ", 7000) + "*/\n"
		raw, _ := os.ReadFile(filepath.Join(dir, "src/copy.c"))
		_ = os.WriteFile(filepath.Join(dir, "src/copy.c"), append(raw, big...), 0o644)
	})
	b.scan()
	b.scan()
	note(b.allStates())
	if !reached["superseded"] {
		t.Fatal("a second audit did not supersede the first's ready rows")
	}
	for i := 0; i < MaxOpenPerRepository; i++ {
		if _, err := b.db.Exec(`INSERT INTO fix_attempt (finding_id, agent_model_id, started_at, status) VALUES ((SELECT min(finding_id) FROM finding), 'm', 'x', 'applied')`); err != nil {
			t.Fatal(err)
		}
		if _, err := RecordDraft(ctx, b.db, int64(i+1), "upstream/fixture", "b", PullRequest{Number: 100 + i}, LabelUnverifiedSecurity, "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := b.ctl.Cycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	limited := false
	for _, n := range rep.Notes {
		limited = limited || strings.Contains(n, "open Anvil drafts, the limit")
	}
	if !limited || b.count(`SELECT count(*) FROM handoff WHERE state = 'ready' AND attempts = 0`) == 0 {
		t.Fatalf("nothing was handed back at the open limit: %v", rep.Notes)
	}
	reached["ready"] = true
	if _, err := b.db.Exec(`UPDATE fix_pr SET state = 'merged'`); err != nil {
		t.Fatal(err)
	}
	b.gen.answer = func(msgs []Message) (string, error) {
		if !isTriage(msgs) {
			var s string
			_ = b.db.QueryRow(`SELECT group_concat(DISTINCT state) FROM handoff WHERE state = 'leased'`).Scan(&s)
			if s == "leased" {
				reached["leased"] = true
			}
		}
		return b.answer(msgs)
	}
	if _, err := b.ctl.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	note(b.allStates())
	if b.byPath(b.states())["src/copy.c"][0] != "split_required" {
		t.Fatalf("copy.c's group: %v", b.byPath(b.states())["src/copy.c"])
	}

	// skipped_budget (the queue cut, run by the controller against its
	// budget) and expired (the claim-timeout sweep).
	c := newWorld(t, nil)
	c.scan()
	c.ctl.BudgetTokens = 3 * store.DefaultTokensPerCandidate
	c.ctl.Targets = map[string]Target{} // cut, then leave the rest ready: the target is not configured
	rep, err = c.ctl.Cycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Dispositions[record.HandoffStateSkippedBudget] != 0 {
		t.Fatal("an unconfigured target's queue was cut")
	}
	c.ctl.Targets = map[string]Target{fixtureLocator: {Locator: fixtureLocator, Source: c.repo}}
	c.gen.answer = func([]Message) (string, error) { return "", errors.New("the model is down") }
	c.ctl.Triage = TriageOff
	rep, err = c.ctl.Cycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Dispositions[record.HandoffStateSkippedBudget] == 0 || c.count(`SELECT count(*) FROM handoff WHERE state = 'skipped_budget'`) == 0 {
		t.Fatalf("the controller's budget cut nothing: %+v", rep.Dispositions)
	}
	note(c.allStates())

	// expired: findings of a target nobody configured wait, unclaimed, until
	// the claim-timeout sweep closes their window.
	d := newWorld(t, nil)
	d.scan()
	d.ctl.Targets = map[string]Target{}
	if _, err := d.ctl.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	late, err := handoff.New(d.db, handoff.Options{Clock: func() time.Time { return time.Now().Add(9 * time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := late.ExpireClaimTimeouts(); err != nil {
		t.Fatal(err)
	}
	note(d.allStates())

	for _, s := range record.HandoffStateValues() {
		if !reached[string(s)] {
			t.Errorf("handoff.state %q was never reached", s)
		}
	}
}

// TestUnmeasuredTriageGatesNothingByDefault: with the triage gate off (the
// default, because its precision is unmeasured) no model is called and every
// unconfirmed finding is withdrawn to report-only; in record mode the verdicts
// are stored and still nothing is generated.
func TestUnmeasuredTriageGatesNothingByDefault(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []TriageMode{"", TriageOff, TriageRecord} {
		w := newWorld(t, nil)
		w.ctl.Triage = mode
		w.scan()
		if _, err := w.ctl.Cycle(ctx); err != nil {
			t.Fatal(err)
		}
		if n := w.count(`SELECT count(*) FROM handoff WHERE state != 'withdrawn'`); n != 0 {
			t.Errorf("mode %q: %d findings were not withdrawn", mode, n)
		}
		for _, p := range w.gen.prompts {
			if !isTriage(p) {
				t.Fatalf("mode %q: a patch was generated", mode)
			}
		}
		stored := w.count(`SELECT count(*) FROM triage_verdict`)
		if mode == TriageRecord && (stored == 0 || len(w.gen.prompts) == 0) {
			t.Errorf("record mode stored %d verdicts", stored)
		}
		if mode != TriageRecord && (stored != 0 || len(w.gen.prompts) != 0) {
			t.Errorf("mode %q called the model %d times", mode, len(w.gen.prompts))
		}
	}
}

// TestAFindingThatVanishedWithoutItsCodeChangingIsNotFixed: after a commit, a
// ready finding in a touched file is fixed incidentally only when its rule no
// longer matches AND its code changed. A finding the rescan stopped reporting
// while its code stayed (the path exclusions can hide code that way) stays in
// the queue.
func TestAFindingThatVanishedWithoutItsCodeChangingIsNotFixed(t *testing.T) {
	w := newWorld(t, nil)
	id := w.scan()
	ctx := context.Background()
	a, err := w.ctl.loadAudit(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(w.repo, "src/app.py"))
	next := map[string]string{"src/app.py": strings.Replace(string(raw), "shell=True", "shell=False", 1)}
	if err := w.ctl.reanchor(ctx, a, next, map[string]bool{}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	for fp, state := range w.states() {
		s := w.snippet[fp]
		if s[0] != "src/app.py" {
			continue
		}
		changed := !strings.Contains(next["src/app.py"], s[1])
		want := map[bool]string{true: "fixed_incidentally", false: "ready"}[changed]
		if state != want {
			t.Errorf("%q (code changed: %v) is %s, want %s", s[1], changed, state, want)
		}
	}
	if n := w.count(`SELECT count(*) FROM handoff WHERE state = 'fixed_incidentally'`); n == 0 {
		t.Fatal("nothing was fixed incidentally, so the test shows nothing")
	}
}

// TestACrashBeforeThePullRequestIsRecovered: the commit landed and the
// process died before the pull request was opened (here: no forge was
// configured for the first run). The next run finds the commit by its
// trailers, keeps the attempt the first run recorded, and opens the pull
// request from that attempt's evidence; a draft already open from the same
// branch is adopted, never doubled; a third run changes nothing.
func TestACrashBeforeThePullRequestIsRecovered(t *testing.T) {
	w := newWorld(t, nil)
	w.scan()
	ctx := context.Background()
	w.ctl.Forge, w.ctl.Pusher = nil, nil
	if _, err := w.ctl.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	commits := len(w.fixCommits())
	attempts := w.count(`SELECT count(*) FROM fix_attempt`)
	if commits != 2 || w.count(`SELECT count(*) FROM fix_pr`) != 0 {
		t.Fatalf("commits %d, pull requests %d", commits, w.count(`SELECT count(*) FROM fix_pr`))
	}
	// One of the two drafts was opened before the crash, but never recorded.
	var orphanBranch string
	if err := w.db.QueryRow(`SELECT min(branch_name) FROM fix_attempt WHERE status = 'applied'`).Scan(&orphanBranch); err != nil {
		t.Fatal(err)
	}
	if _, err := w.forge.OpenDraft(ctx, "upstream/fixture", "anvil-bot:"+orphanBranch, "main", "t", "b"); err != nil {
		t.Fatal(err)
	}
	w.ctl.Forge = w.forge
	w.ctl.Pusher = func(Target) Pusher { return recordingPusher{mu: &sync.Mutex{}, pushes: w.pushes} }
	if _, err := w.db.Exec(`UPDATE handoff SET state = 'ready', claimed_by = NULL, lease_expires_at = NULL WHERE state = 'validated'`); err != nil {
		t.Fatal(err)
	}
	prompts := len(w.gen.prompts)
	rep, err := w.ctl.Cycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.PullRequests) != 2 || w.count(`SELECT count(*) FROM fix_pr`) != 2 || w.forge.next != 2 {
		t.Fatalf("recovery opened %v; fix_pr %d; forge holds %d drafts", rep.PullRequests, w.count(`SELECT count(*) FROM fix_pr`), w.forge.next)
	}
	if len(w.fixCommits()) != commits || w.count(`SELECT count(*) FROM fix_attempt`) != attempts {
		t.Fatal("recovery committed or recorded an attempt again")
	}
	for _, p := range w.gen.prompts[prompts:] {
		if !isTriage(p) {
			t.Fatal("recovery generated a patch again")
		}
	}
	for n, body := range w.forge.bodies {
		if n == 1 {
			continue // the orphan, opened before the crash
		}
		if !strings.Contains(body, RungTests) || !strings.Contains(body, RungRescan) {
			t.Fatalf("the recovered pull request lost its evidence:\n%s", body)
		}
	}
	if _, err := w.db.Exec(`UPDATE handoff SET state = 'ready', claimed_by = NULL, lease_expires_at = NULL WHERE state = 'validated'`); err != nil {
		t.Fatal(err)
	}
	if rep, err := w.ctl.Cycle(ctx); err != nil || len(rep.PullRequests) != 0 || w.count(`SELECT count(*) FROM fix_pr`) != 2 {
		t.Fatalf("a third run opened %v (%v)", rep.PullRequests, err)
	}
}

// TestTwoWorkersNeverShareAClone: the clone's lock is exclusive.
func TestTwoWorkersNeverShareAClone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "clone")
	unlock, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		second, err := lockDir(dir)
		if err == nil {
			second()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a second worker took the lock while the first held it")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was never released")
	}
}

// TestTheProductionRescanIsLaneB: LaneBRescan, the rescan the controller is
// configured with in production, finds a finding still present with the very
// fingerprint the scan recorded, and refuses a narrowed plan that reads none
// of the touched files rather than reporting that nothing matched.
func TestTheProductionRescanIsLaneB(t *testing.T) {
	w := newWorld(t, nil)
	w.scan()
	cfg := laneb.Config{Rules: recalltest.RulePack(), Tools: recalltest.Tools(), Exec: &recalltest.Replay{Root: w.repo}}
	found, err := LaneBRescan(cfg, fixtureLocator)(context.Background(), w.repo, []string{"src/copy.c"})
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for fp, s := range w.snippet {
		if s[0] == "src/copy.c" {
			want++
			if !found[fp] {
				t.Fatalf("the rescan did not find %s with the scan's fingerprint", fp[:12])
			}
		}
	}
	if want == 0 || len(found) != want {
		t.Fatalf("found %d, want %d", len(found), want)
	}
	if _, err := LaneBRescan(cfg, fixtureLocator)(context.Background(), w.repo, []string{"README.md"}); err == nil {
		t.Fatal("a rescan that read none of the touched files reported success")
	}
}

// exportOnlyBuild is the test installation's build: it fails unless it runs
// in an export of the patched tree, with the sources and no .git.
var exportOnlyBuild = []string{"sh", "-c", "test ! -e .git && test -f src/copy.c"}
