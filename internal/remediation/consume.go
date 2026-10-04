package remediation

// The consumption controller (plan node consume): a sub-machine of the scan
// controller, not a second controller. It holds no lease clock, no queue and
// no state of its own; it drives internal/scanctl's Consumer (and through it
// internal/handoff) and writes only its own statements: triage verdicts, the
// audit log, fix attempts and draft pull requests.
//
// One cycle: enqueue (EnqueueAudit, after a scan seals), then for each audit
// with ready work: rank, group, and for each group lease, persist, triage,
// generate, apply, validate, commit, re-anchor and emit, renewing every lease
// at every step boundary and yielding the moment one is lost. The idempotency
// key is the audit, the fingerprint and the base commit: a re-run against the
// same audit and base commit finds its own trailers and writes nothing twice.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Susquehanna-Syntax/Anvil/internal/handoff"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/scanctl"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"
)

// Target is one repository the operator lets the agent propose fixes for.
type Target struct {
	// Locator is target.locator, as the scan recorded it ("repo:anvil").
	Locator string
	// Source is the checkout Anvil scanned; the controller clones it and
	// never writes to it.
	Source string
	// Build and Test are the operator's commands for the ladder.
	Build, Test []string
	// SandboxEnv is added to the sandbox's minimal environment, and
	// SandboxReadOnly are directories the build may read (a toolchain).
	SandboxEnv, SandboxReadOnly []string
	// Repository is the upstream "owner/name"; empty means commits only, no
	// pull requests. Fork is the "owner/name" the branch is pushed to, and
	// BaseBranch the pull request's base.
	Repository, Fork, BaseBranch string
}

// Controller is the consumption controller.
type Controller struct {
	DB       *sql.DB
	Consumer *scanctl.Consumer
	Gen      Generator
	Triage   TriageMode
	Targets  map[string]Target
	WorkDir  string
	GitBin   string
	WorkerID string
	// Rescan is the diff-aware rescan for a target: the recall tier over the
	// named files of a tree, returning the fingerprints found there.
	Rescan   func(locator string) func(ctx context.Context, root string, files []string) (map[string]bool, error)
	Forge    Forge
	Pusher   func(Target) Pusher
	Replayer Replayer
	// Bwrap is the bubblewrap executable for the build sandbox ("" is bwrap
	// on PATH); Hide are directories the sandbox must not show (where the
	// operator keeps the forge token or the endpoint key).
	Bwrap string
	Hide  []string
	Now   func() time.Time
	// BudgetTokens is the prompt-token budget one cycle may spend on an audit.
	// When it is set, each audit's queue is re-cut against it first
	// (internal/store's queue cut): what does not fit is skipped_budget,
	// found but not fixed, and a fraction is held back for findings the
	// dynamic tier confirms later. Zero leaves the queue uncut.
	BudgetTokens int
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// logState writes one line of the audit log.
func (c *Controller) logState(ctx context.Context, handoffID int64, fp string, state string, detail string) error {
	if len(detail) > 2000 {
		detail = detail[:2000]
	}
	var hid any
	if handoffID != 0 {
		hid = handoffID
	}
	_, err := c.DB.ExecContext(ctx, `INSERT INTO remediation_log (handoff_id, fingerprint, state, detail, at) VALUES (?, ?, ?, ?, ?)`,
		hid, fp, state, detail, ts(c.now()))
	return err
}

// audit is one sealed audit, loaded for consumption.
type audit struct {
	recordID int64
	auditID  string
	targetID int64
	locator  string
	base     string
	log      *record.SARIFLog
	cards    map[string]record.TaskCard // by fingerprint
	results  map[string]record.Result   // by fingerprint
}

// loadAudit decodes an audit's sealed payload and builds its task cards
// through the read path, which refuses a half that has not sealed.
func (c *Controller) loadAudit(ctx context.Context, auditRecordID int64) (*audit, error) {
	a := &audit{recordID: auditRecordID}
	var payload []byte
	var sha string
	var auditID, base sql.NullString
	err := c.DB.QueryRowContext(ctx, `SELECT a.payload, a.payload_sha256, a.audit_id, s.commit_sha, s.target_id, t.locator
		FROM audit_record a JOIN scan_run s ON s.scan_run_id = a.scan_run_id JOIN target t ON t.target_id = s.target_id
		WHERE a.audit_record_id = ?`, auditRecordID).Scan(&payload, &sha, &auditID, &base, &a.targetID, &a.locator)
	if err != nil {
		return nil, fmt.Errorf("remediation: audit_record %d: %w", auditRecordID, err)
	}
	if payload == nil {
		return nil, fmt.Errorf("remediation: audit_record %d's payload was purged at its claim deadline", auditRecordID)
	}
	raw, err := store.DecodePayload(payload, sha)
	if err != nil {
		return nil, err
	}
	a.log = &record.SARIFLog{}
	if err := json.Unmarshal(raw, a.log); err != nil {
		return nil, fmt.Errorf("remediation: audit_record %d's payload: %w", auditRecordID, err)
	}
	a.auditID = a.log.Properties.AuditID
	if auditID.Valid && auditID.String != a.auditID {
		return nil, fmt.Errorf("remediation: audit_record %d names audit %q but its payload is %q", auditRecordID, auditID.String, a.auditID)
	}
	a.base = base.String
	cards, err := record.NewReader(nil).CardsFromLog(a.log)
	if err != nil {
		return nil, err
	}
	a.cards = map[string]record.TaskCard{}
	for _, card := range cards {
		a.cards[card.Fingerprint.AnvilFindingID] = card
	}
	a.results = map[string]record.Result{}
	for _, run := range a.log.Runs {
		for _, r := range run.Results {
			a.results[r.PartialFingerprints[record.PartialFingerprintAnvilFindingID]] = r
		}
	}
	return a, nil
}

// EnqueueReport is what EnqueueAudit did.
type EnqueueReport struct {
	Enqueued   int
	Disposed   map[record.HandoffState]int
	Superseded int
}

// EnqueueAudit puts every patchable finding of a sealed audit into the
// handoff table. Every Lane B finding is taken: `unconfirmed` is neither
// dropped nor demoted for being unconfirmed; the triage gate decides it when
// it is leased. A finding the record already judged is disposed of at once,
// with its reason in the audit log: false_positive is dropped, and
// insufficient_context, a dependency (SCA) finding and a finding with no
// recorded base commit are withdrawn to report-only. Host findings are never
// patchable and are not enqueued. Older ready rows for the same fingerprint
// are superseded by this audit's. Running it twice changes nothing.
func (c *Controller) EnqueueAudit(ctx context.Context, q *handoff.Queue, auditRecordID int64) (EnqueueReport, error) {
	rep := EnqueueReport{Disposed: map[record.HandoffState]int{}}
	a, err := c.loadAudit(ctx, auditRecordID)
	if err != nil {
		return rep, err
	}
	fps := make([]string, 0, len(a.cards))
	for fp := range a.cards {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	for _, fp := range fps {
		card := a.cards[fp]
		r := a.results[fp]
		if card.Half != record.HalfSast || !card.RemediableByAgent || record.IsHostFinding(&r) {
			continue
		}
		var findingID int64
		if err := c.DB.QueryRowContext(ctx, `SELECT finding_id FROM finding WHERE target_id = ? AND fingerprint = ?`, a.targetID, fp).Scan(&findingID); err != nil {
			return rep, fmt.Errorf("remediation: finding %s of audit_record %d: %w", fp, auditRecordID, err)
		}
		row, err := q.EnqueueContext(ctx, handoff.EnqueueRequest{
			FindingID: findingID, AuditRecordID: auditRecordID, AuditID: a.auditID,
			Fingerprint: fp, ConsumptionClass: card.ConsumptionClass,
		})
		if err != nil {
			return rep, err
		}
		rep.Enqueued++
		if row.State != record.HandoffStateReady {
			continue
		}
		var to record.HandoffState
		var why string
		switch {
		case card.Verdict == record.VerdictFalsePositive:
			to, why = record.HandoffStateFalsePositive, "the record's verdict is false_positive: dropped"
		case card.Verdict == record.VerdictInsufficientContext:
			to, why = record.HandoffStateWithdrawn, "the record's verdict is insufficient_context: report-only"
		case r.Properties.Detector.Kind == record.DetectorKindSCA:
			to, why = record.HandoffStateWithdrawn, "a dependency finding: report-only in v1, because its fix edits a dependency manifest, which the agent never touches"
		case a.base == "":
			to, why = record.HandoffStateWithdrawn, "the scan recorded no base commit (not a git checkout, or uncommitted changes), so no patch can name the blob it changes"
		}
		if to != "" {
			if err := q.DisposeContext(ctx, row.HandoffID, to); err != nil {
				return rep, err
			}
			rep.Disposed[to]++
			if err := c.logState(ctx, row.HandoffID, fp, string(to), why); err != nil {
				return rep, err
			}
			continue
		}
		// This audit's row supersedes any older ready row for the finding.
		rows, err := c.DB.QueryContext(ctx, `SELECT h.handoff_id FROM handoff h
			JOIN audit_record a ON a.audit_record_id = h.audit_record_id JOIN scan_run s ON s.scan_run_id = a.scan_run_id
			WHERE h.fingerprint = ? AND h.state = 'ready' AND h.audit_record_id < ? AND s.target_id = ?`, fp, auditRecordID, a.targetID)
		if err != nil {
			return rep, err
		}
		var olds []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return rep, err
			}
			olds = append(olds, id)
		}
		_ = rows.Close()
		for _, id := range olds {
			if err := q.DisposeContext(ctx, id, record.HandoffStateSuperseded); err != nil {
				return rep, err
			}
			rep.Superseded++
			if err := c.logState(ctx, id, fp, string(record.HandoffStateSuperseded), "a newer audit re-reported this finding: audit "+a.auditID); err != nil {
				return rep, err
			}
		}
	}
	return rep, nil
}

// CycleReport is what one Cycle did.
type CycleReport struct {
	Dispositions map[record.HandoffState]int
	Notes        []string
	PullRequests []string
}

// Cycle consumes every claimable group once.
func (c *Controller) Cycle(ctx context.Context) (CycleReport, error) {
	rep := CycleReport{Dispositions: map[record.HandoffState]int{}}
	rows, err := c.DB.QueryContext(ctx, `SELECT DISTINCT audit_record_id FROM handoff WHERE state = 'ready' ORDER BY audit_record_id`)
	if err != nil {
		return rep, err
	}
	var audits []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return rep, err
		}
		audits = append(audits, id)
	}
	_ = rows.Close()
	priors, err := AcceptancePriors(ctx, c.DB)
	if err != nil {
		return rep, err
	}
	for _, id := range audits {
		if err := c.cycleAudit(ctx, id, priors, &rep); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func (c *Controller) cycleAudit(ctx context.Context, auditRecordID int64, priors Priors, rep *CycleReport) error {
	a, err := c.loadAudit(ctx, auditRecordID)
	if err != nil {
		return err
	}
	tgt, ok := c.Targets[a.locator]
	if !ok {
		rep.Notes = append(rep.Notes, fmt.Sprintf("audit %s: target %q is not configured for remediation; its findings wait in the queue until their claim window closes", a.auditID, a.locator))
		return nil
	}
	if c.BudgetTokens > 0 {
		r, err := store.NewRecutter(c.DB, store.RecutConfig{Clock: c.Now})
		if err != nil {
			return err
		}
		cut, err := r.RecutQueueContext(ctx, a.auditID, c.BudgetTokens)
		if err != nil {
			return err
		}
		for _, d := range cut.Deferred {
			if err := c.logState(ctx, d.HandoffID, d.Fingerprint, string(record.HandoffStateSkippedBudget), "the queue cut: over this cycle's token budget, found but not fixed"); err != nil {
				return err
			}
			rep.Dispositions[record.HandoffStateSkippedBudget]++
		}
	}
	rows, err := c.DB.QueryContext(ctx, `SELECT h.fingerprint, f.state FROM handoff h JOIN finding f ON f.finding_id = h.finding_id
		WHERE h.audit_record_id = ? AND h.state = 'ready'`, auditRecordID)
	if err != nil {
		return err
	}
	var items []Item
	for rows.Next() {
		var fp, fstate string
		if err := rows.Scan(&fp, &fstate); err != nil {
			_ = rows.Close()
			return err
		}
		items = append(items, itemOf(fp, a.cards[fp], a.results[fp], fstate == "regressed"))
	}
	_ = rows.Close()
	for _, g := range Groups(a.auditID, items, priors) {
		if err := c.group(ctx, a, tgt, g, rep); err != nil {
			return err
		}
	}
	return nil
}

func itemOf(fp string, card record.TaskCard, r record.Result, regressed bool) Item {
	it := Item{Fingerprint: fp, Path: card.Locus.Path, Symbol: card.Locus.EnclosingSymbol,
		Evidence: card.EvidenceClass, Proximity: card.Locus.ProximityClass, Regressed: regressed, Risk: r.Properties.Risk}
	if len(r.Taxa) > 0 {
		it.CWE = r.Taxa[0].ID
	}
	return it
}

// member is one leased finding of a group.
type member struct {
	task scanctl.Task
	item Item
	card record.TaskCard
	res  record.Result
	row  handoff.Row
	note string // the triage gate's verdict, for the pull request
}

// errYield means a lease was lost at a step boundary: the controller stops
// work on the group and writes nothing more for it.
var errYield = errors.New("remediation: a lease was lost; yielding")

func (c *Controller) renew(ctx context.Context, ms []*member) error {
	for _, m := range ms {
		t, err := c.Consumer.RenewLeaseContext(ctx, m.task)
		if err != nil {
			return fmt.Errorf("%w: %v", errYield, err)
		}
		m.task = t
	}
	return nil
}

func (c *Controller) release(ctx context.Context, rep *CycleReport, m *member, to record.HandoffState, why string) error {
	if err := c.Consumer.ReleaseLeaseContext(ctx, m.task, to); err != nil {
		if errors.Is(err, handoff.ErrLeaseLost) || errors.Is(err, handoff.ErrRecordVersionChanged) {
			return fmt.Errorf("%w: %v", errYield, err)
		}
		return err
	}
	rep.Dispositions[to]++
	return c.logState(ctx, m.row.HandoffID, m.task.Fingerprint, string(to), why)
}

func (c *Controller) releaseAll(ctx context.Context, rep *CycleReport, ms []*member, to record.HandoffState, why string) error {
	for _, m := range ms {
		if err := c.release(ctx, rep, m, to, why); err != nil {
			return err
		}
	}
	return nil
}

// group runs one fix group from lease to emission.
func (c *Controller) group(ctx context.Context, a *audit, tgt Target, g Group, rep *CycleReport) error {
	var ms []*member
	for _, it := range g.Members {
		t, err := c.Consumer.ClaimContext(ctx, it.Fingerprint, c.WorkerID)
		if err != nil {
			if errors.Is(err, handoff.ErrAlreadyClaimed) || errors.Is(err, handoff.ErrNotEligible) || errors.Is(err, handoff.ErrExhausted) || errors.Is(err, handoff.ErrNotFound) {
				continue
			}
			return err
		}
		row, err := c.Consumer.Queue().GetContext(ctx, t.HandoffID())
		if err != nil {
			return err
		}
		ms = append(ms, &member{task: t, item: it, card: a.cards[it.Fingerprint], res: a.results[it.Fingerprint], row: row})
	}
	if len(ms) == 0 {
		return nil
	}
	err := c.work(ctx, a, tgt, g, ms, rep)
	if errors.Is(err, errYield) {
		rep.Notes = append(rep.Notes, "group "+g.ID+": "+err.Error())
		return nil
	}
	if err != nil {
		// An attempt that failed without a verdict: the reaper's rule.
		for _, m := range ms {
			if relErr := c.release(ctx, rep, m, scanctl.FailureDisposition(m.task), "the attempt failed: "+err.Error()); relErr != nil && !errors.Is(relErr, errYield) {
				return relErr
			}
		}
		rep.Notes = append(rep.Notes, "group "+g.ID+": "+err.Error())
	}
	return nil
}

func (c *Controller) workDir(locator string) string {
	sum := sha256.Sum256([]byte(locator))
	return filepath.Join(c.WorkDir, hex.EncodeToString(sum[:8]))
}

func (c *Controller) work(ctx context.Context, a *audit, tgt Target, g Group, ms []*member, rep *CycleReport) error {
	// Persist before working: the group id goes on every row's log line now,
	// so a crash leaves a trace of what was attempted.
	for _, m := range ms {
		if err := c.logState(ctx, m.row.HandoffID, m.task.Fingerprint, "leased", "group "+g.ID+", attempt "+fmt.Sprint(m.task.Attempt)); err != nil {
			return err
		}
	}

	// The triage gate, for findings nothing has judged.
	var kept []*member
	for _, m := range ms {
		if m.card.Verdict != record.VerdictUnconfirmed {
			kept = append(kept, m)
			continue
		}
		if c.Triage == TriageOff || c.Triage == "" || c.Gen == nil {
			if err := c.release(ctx, rep, m, record.HandoffStateWithdrawn,
				"unconfirmed and the triage gate is off: report-only (its precision is unmeasured, so it does not gate generation by default)"); err != nil {
				return err
			}
			continue
		}
		v, err := Triage(ctx, c.DB, c.Gen, a.targetID, a.recordID, TriageInputOf(m.res), c.now())
		if err != nil {
			return err
		}
		m.note = string(v.Verdict)
		if err := c.renew(ctx, []*member{m}); err != nil {
			return err
		}
		switch {
		case c.Triage == TriageRecord:
			err = c.release(ctx, rep, m, record.HandoffStateWithdrawn, "triage gate recorded "+string(v.Verdict)+" ("+v.Reason+"); report-only, because triage is in record mode")
		case v.Verdict == record.VerdictFalsePositive:
			err = c.release(ctx, rep, m, record.HandoffStateFalsePositive, "triage gate: false positive: "+v.Reason)
		case v.Verdict == record.VerdictInsufficientContext:
			err = c.release(ctx, rep, m, record.HandoffStateWithdrawn, "triage gate: insufficient context, report-only: "+v.Reason)
		default:
			kept = append(kept, m)
		}
		if err != nil {
			return err
		}
	}
	ms = kept
	if len(ms) == 0 {
		return nil
	}

	if err := os.MkdirAll(c.WorkDir, 0o700); err != nil {
		return err
	}
	unlock, err := lockDir(c.workDir(tgt.Locator))
	if err != nil {
		return err
	}
	defer unlock()
	git, err := Prepare(ctx, c.GitBin, tgt.Source, c.workDir(tgt.Locator), a.base)
	if err != nil {
		return err
	}

	// Already processed: a crash between commit and disposition is recovered
	// from the trailers, never redone. Every member's key is looked up, and a
	// commit whose pull request never opened gets it now.
	done := map[string][]*member{}
	var rest []*member
	for _, m := range ms {
		sha, found, err := git.CommitWithKey(ctx, m.task.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			done[sha] = append(done[sha], m)
		} else {
			rest = append(rest, m)
		}
	}
	if len(done) > 0 {
		shas := make([]string, 0, len(done))
		for sha := range done {
			shas = append(shas, sha)
		}
		sort.Strings(shas)
		for _, sha := range shas {
			note, err := c.recover(ctx, tgt, git, a, done[sha], sha, rep)
			if err != nil {
				return err
			}
			for _, m := range done[sha] {
				if err := c.release(ctx, rep, m, record.HandoffStateValidated, "already processed: commit "+sha+" carries this idempotency key"+note); err != nil {
					return err
				}
			}
		}
		// The rest are regrouped on the next cycle, with no attempt spent.
		for _, m := range rest {
			if err := c.Consumer.HandBackContext(ctx, m.task); err != nil {
				return err
			}
		}
		return nil
	}

	if tgt.Repository != "" {
		n, err := OpenDrafts(ctx, c.DB, tgt.Repository)
		if err != nil {
			return err
		}
		if n >= MaxOpenPerRepository {
			for _, m := range ms {
				if err := c.Consumer.HandBackContext(ctx, m.task); err != nil {
					return err
				}
			}
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s has %d open Anvil drafts, the limit; group %s waits", tgt.Repository, n, g.ID))
			return nil
		}
	}

	// The prompt: task cards and the files at the scanned commit.
	base := map[string]string{}
	blobs := map[string][2]string{}
	var files []FileView
	var cards []string
	for _, m := range ms {
		p := m.item.Path
		if _, ok := base[p]; !ok {
			content, blob, mode, err := git.Blob(ctx, a.base, p)
			if err != nil {
				return c.releaseAll(ctx, rep, ms, record.HandoffStateFailedValidation, "the scanned file is not in the base commit: "+err.Error())
			}
			base[p], blobs[p] = content, [2]string{blob, mode}
			files = append(files, FileView{Path: p, Content: content, Lines: lineCount(content)})
		}
		raw, err := json.Marshal(m.card)
		if err != nil {
			return err
		}
		cards = append(cards, string(raw))
	}
	msgs := GenerationPrompt(cards, files)
	if n := EstimateTokens(msgs); n > TokenCeiling {
		return c.releaseAll(ctx, rep, ms, record.HandoffStateSplitRequired, fmt.Sprintf("the group's prompt is about %d tokens, over the ceiling of %d: too large", n, TokenCeiling))
	}

	// Generate, then at most one anchor-repair turn, then stop.
	if err := c.renew(ctx, ms); err != nil {
		return err
	}
	reply, err := c.Gen.Generate(ctx, msgs, 4096)
	if err != nil {
		return err
	}
	next, aerr := Anchor(base, ParseEdits(reply))
	if aerr != nil {
		var an *ErrAnchor
		if !errors.As(aerr, &an) {
			return aerr
		}
		if err := c.renew(ctx, ms); err != nil {
			return err
		}
		reply2, err := c.Gen.Generate(ctx, RepairPrompt(msgs, reply, an.Problems), 4096)
		if err != nil {
			return err
		}
		if next, aerr = Anchor(base, ParseEdits(reply2)); aerr != nil {
			return c.releaseAll(ctx, rep, ms, record.HandoffStateFailedFormat, "two anchor failures: "+aerr.Error())
		}
	}

	paths := make([]string, 0, len(next))
	for p := range next {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var patch strings.Builder
	for _, p := range paths {
		d, err := git.Diff(ctx, p, blobs[p][0], blobs[p][1], next[p])
		if err != nil {
			return err
		}
		patch.WriteString(d)
	}
	if err := git.Apply(ctx, patch.String()); err != nil {
		return c.releaseAll(ctx, rep, ms, record.HandoffStateFailedValidation, "the diff did not apply to the scanned blob: "+err.Error())
	}
	// The index must hold exactly the patch: the commit is made from it, and
	// every rung judges an export of it.
	staged, err := git.StagedPaths(ctx, a.base)
	if err != nil {
		return err
	}
	if strings.Join(staged, "\x00") != strings.Join(paths, "\x00") {
		_ = git.Rollback(ctx)
		return c.releaseAll(ctx, rep, ms, record.HandoffStateFailedValidation, fmt.Sprintf("the applied diff changed %v, not exactly the patched files %v", staged, paths))
	}
	tree, err := git.WriteTree(ctx)
	if err != nil {
		return err
	}
	exportOf := func(treeish string) func(context.Context) (string, func(), error) {
		return func(ctx context.Context) (string, func(), error) {
			parent := filepath.Join(c.WorkDir, "exports")
			if err := os.MkdirAll(parent, 0o700); err != nil {
				return "", nil, err
			}
			tmp, err := os.MkdirTemp(parent, "tree-")
			if err != nil {
				return "", nil, err
			}
			dir := filepath.Join(tmp, "src")
			if err := git.Export(ctx, treeish, dir); err != nil {
				_ = os.RemoveAll(tmp)
				return "", nil, err
			}
			return dir, func() { _ = os.RemoveAll(tmp) }, nil
		}
	}
	if err := c.renew(ctx, ms); err != nil {
		_ = git.Rollback(ctx)
		return err
	}

	// The ladder.
	allowed, group, baseFPs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range ms {
		allowed[m.item.Path] = true
		group[m.task.Fingerprint] = true
	}
	for fp, card := range a.cards {
		if next[card.Locus.Path] != "" {
			baseFPs[fp] = true
		}
	}
	var rescan func(context.Context, string, []string) (map[string]bool, error)
	if c.Rescan != nil {
		rescan = c.Rescan(a.locator)
	}
	ladder := Ladder{Sandbox: Sandbox{Bwrap: c.Bwrap, Env: tgt.SandboxEnv, ReadOnly: tgt.SandboxReadOnly, Hide: c.Hide},
		Build: tgt.Build, Test: tgt.Test, Rescan: rescan}
	out := ladder.Run(ctx, Patch{Export: exportOf(tree), Files: next, Base: base, Diff: patch.String(), Allowed: allowed,
		Fingerprints: group, BaseFingerprints: baseFPs})
	rungs := append([]Rung{
		rung(RungAlreadyProcessed, RungPass, true, ""),
		rung(RungAnchorsApply, RungPass, true, fmt.Sprintf("%d file(s)", len(next))),
	}, out.Rungs...)
	if why := out.Blocked(); why != "" {
		_ = git.Rollback(ctx)
		if _, err := c.recordAttempt(ctx, git, a, ms, "rejected", patch.String(), rungs); err != nil {
			return err
		}
		to := record.HandoffStateFailedValidation
		if out.Regression {
			to = record.HandoffStateRegressionIntroduced
		}
		return c.releaseAll(ctx, rep, ms, to, why)
	}

	// The exploit oracle, for findings that carry a reproduction: the scanned
	// tree and the patched tree, each a fresh export.
	var combined OracleResult
	for i, m := range ms {
		o := c.oracle(ctx, exportOf, a.base+"^{tree}", tree, m.res.Properties.Repro)
		if o.Blocking() {
			_ = git.Rollback(ctx)
			if _, err := c.recordAttempt(ctx, git, a, ms, "rejected", patch.String(), rungs); err != nil {
				return err
			}
			return c.releaseAll(ctx, rep, ms, record.HandoffStateFailedValidation, "exploit oracle: "+string(o.Verdict)+": "+o.Detail)
		}
		// The group is verified only if every member is.
		if i == 0 || LabelFor(o) == LabelUnverifiedSecurity {
			combined = o
		}
	}
	label := LabelFor(combined)

	// Commit, with every lease confirmed held at the boundary: this renew is
	// the last check after the ladder and the oracle, and nothing is written
	// between it and the commit.
	if err := c.renew(ctx, ms); err != nil {
		_ = git.Rollback(ctx)
		return err
	}
	branch := "anvil/fix/" + a.auditID + "/" + g.ID
	tr := Trailers{Audit: a.auditID}
	for _, m := range ms {
		tr.Findings = append(tr.Findings, m.task.Fingerprint)
		tr.Keys = append(tr.Keys, m.task.IdempotencyKey)
	}
	subject := "Anvil: fix " + plainText(ms[0].item.CWE, 20) + " in " + plainText(ms[0].item.Path, 120)
	rungs = append(rungs, rung(RungProvenance, RungPass, false, "tree "+tree))
	// The attempt is written before the commit, keyed by the tree, so a crash
	// after the commit finds it (recover) and the evidence is not lost.
	attemptID, err := c.recordAttempt(ctx, git, a, ms, "proposed", "tree:"+tree, rungs)
	if err != nil {
		_ = git.Rollback(ctx)
		return err
	}
	sha, err := git.CommitTree(ctx, tree, branch, a.base, subject, tr)
	if err != nil {
		_ = git.Rollback(ctx)
		return err
	}
	if _, err := c.DB.ExecContext(ctx, `UPDATE fix_attempt SET status = 'applied', patch_ref = ?, branch_name = ? WHERE patch_ref = ?`,
		sha, branch, "tree:"+tree); err != nil {
		return err
	}

	// Re-anchor: a ready finding in a touched file whose rule no longer
	// matches AND whose code changed is fixed incidentally. One whose code is
	// unchanged stays: a finding that vanished without its code changing is
	// not fixed (the path exclusions can hide code by moving it).
	if err := c.reanchor(ctx, a, next, out.Found, group); err != nil {
		return err
	}

	disposition := "validated: every blocking rung passed; committed to " + branch
	if tgt.Repository != "" && c.Forge != nil && c.Pusher != nil {
		url, err := c.openPR(ctx, tgt, git, a, ms, branch, sha, attemptID, label, rungs, combined)
		if err != nil {
			disposition += "; the pull request was not opened: " + err.Error()
		} else {
			disposition += "; draft pull request " + url
			rep.PullRequests = append(rep.PullRequests, url)
		}
	}
	for _, m := range ms {
		to := record.HandoffStateValidated
		if err := c.release(ctx, rep, m, to, disposition+"; label "+string(label)); err != nil {
			if errors.Is(err, handoff.ErrNoDynamicEvidence) {
				if err := c.release(ctx, rep, m, record.HandoffStateFailedValidation, "the audit's DAST half produced no reproduction for a finding that requires one"); err != nil {
					return err
				}
				continue
			}
			return err
		}
	}
	return nil
}

// oracle runs the exploit oracle for one finding, exporting the scanned and
// the patched trees only when there is a reproduction to replay.
func (c *Controller) oracle(ctx context.Context, exportOf func(string) func(context.Context) (string, func(), error), baseTree, tree string, repro *record.Repro) OracleResult {
	if repro == nil || repro.Payload == "" || c.Replayer == nil {
		return RunOracle(ctx, c.Replayer, ReplayTarget{}, ReplayTarget{}, repro)
	}
	baseDir, doneBase, err := exportOf(baseTree)(ctx)
	if err != nil {
		return OracleResult{Verdict: OracleReplayFailed, Detail: err.Error()}
	}
	defer doneBase()
	patchedDir, donePatched, err := exportOf(tree)(ctx)
	if err != nil {
		return OracleResult{Verdict: OracleReplayFailed, Detail: err.Error()}
	}
	defer donePatched()
	return RunOracle(ctx, c.Replayer, ReplayTarget{Dir: baseDir, Tree: baseTree}, ReplayTarget{Dir: patchedDir, Tree: tree}, repro)
}

// recover completes a commit an earlier attempt made but did not finish
// recording: its attempt row moves to applied, and, when a forge is
// configured and no pull request was recorded for it, the pull request is
// opened now from the evidence the attempt stored.
func (c *Controller) recover(ctx context.Context, tgt Target, git Git, a *audit, ms []*member, sha string, rep *CycleReport) (string, error) {
	treeOut, err := git.run(ctx, nil, "rev-parse", sha+"^{tree}")
	if err != nil {
		return "", err
	}
	tree := strings.TrimSpace(string(treeOut))
	branches, err := git.BranchesContaining(ctx, sha)
	if err != nil {
		return "", err
	}
	if len(branches) == 0 {
		return "", fmt.Errorf("remediation: commit %s carries trailers but is on no fix branch", sha)
	}
	branch := branches[0]
	if _, err := c.DB.ExecContext(ctx, `UPDATE fix_attempt SET status = 'applied', patch_ref = ?, branch_name = ? WHERE patch_ref = ?`,
		sha, branch, "tree:"+tree); err != nil {
		return "", err
	}
	var attemptID int64
	err = c.DB.QueryRowContext(ctx, `SELECT min(fix_attempt_id) FROM fix_attempt WHERE patch_ref = ?`, sha).Scan(&attemptID)
	if err != nil || attemptID == 0 {
		return "; its attempt row was lost, so no pull request is opened for it", nil
	}
	var prs int
	if err := c.DB.QueryRowContext(ctx, `SELECT count(*) FROM fix_pr WHERE branch = ?`, branch).Scan(&prs); err != nil {
		return "", err
	}
	if prs > 0 || tgt.Repository == "" || c.Forge == nil || c.Pusher == nil {
		return "", nil
	}
	rungs, err := c.rungsOf(ctx, attemptID)
	if err != nil {
		return "", err
	}
	o := OracleResult{Verdict: OracleNoReproduction, Detail: "recovered from the trailers; the oracle's result was not recorded"}
	url, err := c.openPR(ctx, tgt, git, a, ms, branch, sha, attemptID, LabelUnverifiedSecurity, rungs, o)
	if err != nil {
		return "; the pull request was not opened: " + err.Error(), nil
	}
	rep.PullRequests = append(rep.PullRequests, url)
	return "; draft pull request " + url + " opened on recovery", nil
}

// rungsOf reads an attempt's ladder back from its verification rows.
func (c *Controller) rungsOf(ctx context.Context, attemptID int64) ([]Rung, error) {
	rows, err := c.DB.QueryContext(ctx, `SELECT details_json FROM verification WHERE fix_attempt_id = ? ORDER BY verification_id`, attemptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rung
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r Rung
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// plainText makes a target-controlled string safe for a commit subject or a
// pull-request title: one line, no control or format characters, bounded.
func plainText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// reanchor disposes of ready findings the commit fixed incidentally.
func (c *Controller) reanchor(ctx context.Context, a *audit, next map[string]string, found, group map[string]bool) error {
	if found == nil {
		return nil
	}
	rows, err := c.DB.QueryContext(ctx, `SELECT handoff_id, fingerprint FROM handoff WHERE audit_record_id = ? AND state = 'ready'`, a.recordID)
	if err != nil {
		return err
	}
	type ready struct {
		id int64
		fp string
	}
	var rs []ready
	for rows.Next() {
		var r ready
		if err := rows.Scan(&r.id, &r.fp); err != nil {
			_ = rows.Close()
			return err
		}
		rs = append(rs, r)
	}
	_ = rows.Close()
	for _, r := range rs {
		card := a.cards[r.fp]
		content, touched := next[card.Locus.Path]
		if !touched || group[r.fp] || found[r.fp] || card.Static == nil || card.Static.Code == "" {
			continue
		}
		if strings.Contains(strings.ReplaceAll(content, "\r\n", "\n"), strings.ReplaceAll(card.Static.Code, "\r\n", "\n")) {
			continue // the code is unchanged: not fixed, whatever the rule says
		}
		if err := c.Consumer.Queue().DisposeContext(ctx, r.id, record.HandoffStateFixedIncidentally); err != nil {
			return err
		}
		if err := c.logState(ctx, r.id, r.fp, string(record.HandoffStateFixedIncidentally), "another group's commit changed this finding's code and its rule no longer matches"); err != nil {
			return err
		}
	}
	return nil
}

// recordAttempt writes fix_attempt and one verification row per rung. A
// rejected patch is kept as a blob in the working clone (patch_ref), never on
// a branch.
func (c *Controller) recordAttempt(ctx context.Context, git Git, a *audit, ms []*member, status, patchOrRef string, rungs []Rung) (int64, error) {
	ref := patchOrRef
	if status == "rejected" {
		out, err := git.run(ctx, []byte(patchOrRef), "hash-object", "-w", "--stdin")
		if err != nil {
			return 0, err
		}
		ref = "blob:" + strings.TrimSpace(string(out))
	}
	now := ts(c.now())
	var first int64
	for i, m := range ms {
		res, err := c.DB.ExecContext(ctx, `INSERT INTO fix_attempt (finding_id, audit_record_id, agent_model_id, started_at, finished_at, status, patch_ref, branch_name)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, m.row.FindingID, a.recordID, c.Gen.Model(), now, now, status, ref, nil)
		if err != nil {
			return 0, err
		}
		id, _ := res.LastInsertId()
		if i == 0 {
			first = id
		}
		for _, r := range rungs {
			result := map[RungResult]string{RungPass: "pass", RungFail: "fail"}[r.Result]
			if result == "" {
				result = "inconclusive"
			}
			details, _ := json.Marshal(r)
			if _, err := c.DB.ExecContext(ctx, `INSERT INTO verification (fix_attempt_id, kind, result, details_json, verified_at) VALUES (?, ?, ?, ?, ?)`,
				id, r.Name, result, string(details), now); err != nil {
				return 0, err
			}
		}
	}
	return first, nil
}

func (c *Controller) openPR(ctx context.Context, tgt Target, git Git, a *audit, ms []*member, branch, sha string, attemptID int64, label Label, rungs []Rung, o OracleResult) (string, error) {
	if err := CheckPushScope(ctx, c.Forge, tgt.Repository); err != nil {
		return "", err
	}
	if err := c.Pusher(tgt).Push(ctx, git.Dir, branch); err != nil {
		return "", err
	}
	ev := Evidence{Label: label, Rungs: rungs, Oracle: o, Commit: sha, Audit: a.auditID, Disposition: "validated"}
	for _, m := range ms {
		ev.Findings = append(ev.Findings, EvidenceFinding{Fingerprint: m.task.Fingerprint, Rule: m.res.RuleID, CWE: m.item.CWE, Path: m.item.Path, Line: m.card.Locus.StartLine, Triage: m.note})
	}
	head := branch
	if tgt.Fork != "" {
		head = strings.SplitN(tgt.Fork, "/", 2)[0] + ":" + branch
	}
	baseBranch := tgt.BaseBranch
	if baseBranch == "" {
		baseBranch = "main"
	}
	// A draft from an earlier, interrupted attempt is adopted, never doubled.
	pr, open, err := c.Forge.FindOpen(ctx, tgt.Repository, head)
	if err != nil {
		return "", err
	}
	if !open {
		title := "Anvil: fix " + plainText(ms[0].item.CWE, 20) + " in " + plainText(ms[0].item.Path, 120)
		if pr, err = c.Forge.OpenDraft(ctx, tgt.Repository, head, baseBranch, title, ev.Body()); err != nil {
			return "", err
		}
	}
	id, err := RecordDraft(ctx, c.DB, attemptID, tgt.Repository, branch, pr, label, ms[0].item.CWE, c.now())
	if err != nil {
		return "", err
	}
	if _, err := c.DB.ExecContext(ctx, `UPDATE fix_attempt SET branch_name = ?, pr_url = ? WHERE fix_attempt_id = ?`, branch, pr.URL, attemptID); err != nil {
		return "", err
	}
	for _, m := range ms {
		if _, err := Supersede(ctx, c.DB, c.Forge, tgt.Repository, m.task.Fingerprint, id, pr.URL, c.now()); err != nil {
			return "", err
		}
	}
	return pr.URL, nil
}
