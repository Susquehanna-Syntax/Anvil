// This file is the Lane B pipeline's two steps, as the scan controller's
// caller (internal/scan) uses them: Prepare before the audit begins, so a
// missing tool or a refused rule pack stops the scan with nothing recorded,
// then Run once the audit is open.

package laneb

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/recall"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// FullScanBudget is the affordability bar for one full scan: under 500
// candidates (the candidates-per-scan register row). A scan at or over it is
// flagged on every scan, because candidate volume moves with every rule
// update and every repository.
const FullScanBudget = 500

// Config is how an installation runs Lane B.
type Config struct {
	// Rules is the rule pack directory (data/rules in a checkout).
	Rules string
	Tools recall.Tools
	Exec  recall.Exec
}

// Lane is a prepared Lane B scan of one tree.
type Lane struct {
	scanner recall.Scanner
	plan    recall.Plan
}

// Prepare verifies the rule pack, enumerates root and resolves every tool
// the tree needs. Its errors wrap recall.ErrRulePack, recall.ErrToolAbsent or
// recall.ErrToolFailed (a tool at the wrong version).
func Prepare(ctx context.Context, cfg Config, root string) (*Lane, error) {
	pack, err := recall.LoadPack(cfg.Rules)
	if err != nil {
		return nil, err
	}
	s := recall.Scanner{Pack: pack, Tools: cfg.Tools, Exec: cfg.Exec}
	plan, err := s.Prepare(ctx, root)
	if err != nil {
		return nil, err
	}
	return &Lane{scanner: s, plan: plan}, nil
}

// RulesetVersion names the rule selection, for scan_run.ruleset_version.
func (l *Lane) RulesetVersion() string {
	return "laneb/selection@" + l.scanner.Pack.SelectionSHA256[:12]
}

// EngineVersion names the tools this scan runs, at their pinned versions.
func (l *Lane) EngineVersion() string {
	var parts []string
	for _, t := range l.plan.Needs() {
		pin, _ := l.scanner.Pack.Tool(t)
		parts = append(parts, t+" "+pin.Version)
	}
	if len(parts) == 0 {
		return "none (no source file in a covered language)"
	}
	return strings.Join(parts, ", ")
}

// Snapshot is the SAST run's anvil/advisorySnapshot when no advisory feed was
// read: the rule pack is the corpus Lane B matched against, named by its
// selection digest and dated by the owner's decision that fixed it.
func (l *Lane) Snapshot() *record.AdvisorySnapshot {
	at, err := time.Parse("2006-01-02", l.scanner.Pack.Selection.DecidedOn)
	if err != nil {
		at = time.Time{}
	}
	return &record.AdvisorySnapshot{
		FeedIDs:        []string{"laneb-rule-pack"},
		SnapshotDigest: l.RulesetVersion(),
		ScrapedAt:      at.UTC(),
	}
}

// Output is one Lane B run.
type Output struct {
	Emission
	Recall      recall.Result
	SpecHarvest *record.SpecHarvest
	// Problems make the scan incomplete; Notes do not.
	Problems []string
	Notes    []string
}

// Run scans the prepared tree for the target targetID and places every
// candidate on the record.
func (l *Lane) Run(ctx context.Context, targetID string) (Output, error) {
	var out Output
	res, err := l.scanner.Scan(ctx, l.plan)
	if err != nil {
		return out, err
	}
	out.Recall = res
	out.Problems = append(out.Problems, res.Problems...)
	if l.plan.Empty() {
		out.Problems = append(out.Problems, fmt.Sprintf(
			"Lane B found no source file in a language its rules cover (%s), so it scanned nothing; that is not a clean repository",
			strings.Join(l.scanner.Pack.Languages(), ", ")))
	}
	em, err := Emit(targetID, res.Candidates)
	if err != nil {
		return out, err
	}
	out.Emission = em
	for _, r := range em.Refused {
		out.Problems = append(out.Problems, "a candidate could not be placed on the record: "+r)
	}
	if out.SpecHarvest, err = Harvest(l.plan.Root); err != nil {
		return out, fmt.Errorf("laneb: the spec harvest failed: %w", err)
	}
	if res.Count >= FullScanBudget {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"Lane B produced %d candidates, at or over the budget of %d a full scan: the recall tier needs re-scoping for this repository (eval/register.yaml, candidates-per-scan)",
			res.Count, FullScanBudget))
	}
	if res.PartialParses > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("opengrep parsed %d file(s) only in part", res.PartialParses))
	}
	tools := make([]string, 0, len(res.ByTool))
	for t, n := range res.ByTool {
		tools = append(tools, fmt.Sprintf("%s %d", t, n))
	}
	sort.Strings(tools)
	out.Notes = append(out.Notes, fmt.Sprintf("Lane B: %d candidate(s) from %d file(s) (%s); %d excluded by the selection's paths",
		res.Count, res.Files, strings.Join(tools, ", "), l.plan.Excluded))
	return out, nil
}
