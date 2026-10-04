package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/laneb"
	"github.com/Susquehanna-Syntax/Anvil/internal/recall/recalltest"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"
)

func laneBRequest(t *testing.T, e env, root string) Request {
	t.Helper()
	req := e.req
	req.Kind, req.RepoPath, req.TargetName = KindRepo, root, "laneb-fixture"
	req.LaneB = &laneb.Config{Rules: recalltest.RulePack(), Tools: recalltest.Tools(), Exec: &recalltest.Replay{Root: root}}
	return req
}

// TestEveryCandidateReachesTheRecordUnconfirmed is the Lane B pipeline's
// integration test of its verdict mapping: every recall candidate, through the
// scan controller, the assembler, the record's own validation and the store,
// arrives as anvil/verdict unconfirmed with confidence 1, no model, no rank,
// and a rule whose provenance resolves in full.
func TestEveryCandidateReachesTheRecordUnconfirmed(t *testing.T) {
	e := newEnv(t)
	root, err := filepath.Abs(recalltest.FixtureRoot())
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), laneBRequest(t, e, root))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeFindings || res.Emitted != 12 || res.RecallCandidates == nil || *res.RecallCandidates != 12 {
		t.Fatalf("outcome %q emitted %d candidates %v problems %v", res.Outcome, res.Emitted, res.RecallCandidates, res.Problems)
	}
	if len(res.NotRun) != 1 || !strings.Contains(res.NotRun[0], "repository SCA did not run") {
		t.Errorf("not run: %v", res.NotRun)
	}
	run := res.Log.Runs[0]
	if len(run.Results) != 12 || run.Properties.SpecHarvest == nil || len(run.Properties.SpecHarvest.Files) != 1 {
		t.Fatalf("results %d spec harvest %+v", len(run.Results), run.Properties.SpecHarvest)
	}
	for _, r := range run.Results {
		p := r.Properties
		if p.Verdict != record.VerdictUnconfirmed || p.Confidence != 1 || p.Detector.Kind != record.DetectorKindSast ||
			p.Detector.Model != "" || p.Detector.Revision != "" || r.Rank != nil || p.Half != record.HalfSast {
			t.Errorf("%s: %+v rank %v", r.RuleID, p, r.Rank)
		}
		ext := run.Tool.Extensions[*r.Rule.ToolComponent.Index]
		var prov *record.RuleProvenance
		for _, d := range ext.Rules {
			if d.ID == r.RuleID {
				prov = d.Properties.RuleProvenance
			}
		}
		if err := prov.Validate(); err != nil {
			t.Errorf("%s: %v", r.RuleID, err)
		}
	}
	if snap := run.Properties.AdvisorySnapshot; snap == nil || snap.FeedIDs[0] != "laneb-rule-pack" {
		t.Errorf("advisory snapshot %+v", snap)
	}

	var verdicts, unconfirmed, count int
	if err := e.store.QueryRow(`SELECT count(*), sum(verdict = 'unconfirmed') FROM finding`).Scan(&verdicts, &unconfirmed); err != nil {
		t.Fatal(err)
	}
	if verdicts != 12 || unconfirmed != 12 {
		t.Fatalf("the store holds %d findings, %d unconfirmed", verdicts, unconfirmed)
	}
	if err := e.store.QueryRow(`SELECT recall_candidates FROM scan_run`).Scan(&count); err != nil || count != 12 {
		t.Fatalf("scan_run.recall_candidates = %d (%v)", count, err)
	}

	// The same tree again: every finding persists, none is new or fixed.
	again, err := Run(context.Background(), laneBRequest(t, e, root))
	if err != nil {
		t.Fatal(err)
	}
	marks := map[store.MarkKind]int{}
	for _, m := range again.Write.Marks {
		marks[m.Kind]++
	}
	if marks[store.MarkPersisting] != 12 || len(marks) != 1 {
		t.Fatalf("second scan marks %v", marks)
	}
}

// TestALaneBScanOfNothingIsNotClean: a tree with no source in a covered
// language is refused, never reported clean.
func TestALaneBScanOfNothingIsNotClean(t *testing.T) {
	e := newEnv(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("docs only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), laneBRequest(t, e, root))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeRefused || res.Complete {
		t.Fatalf("outcome %q complete %v problems %v", res.Outcome, res.Complete, res.Problems)
	}
	var count int
	if err := e.store.QueryRow(`SELECT recall_candidates FROM scan_run`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("recall_candidates = %d (%v); a scan that ran and found nothing records 0, not NULL", count, err)
	}
}

// TestAMissingRulePackIsAMissingTool: a refused rule pack stops the scan
// before any audit exists.
func TestAMissingRulePackIsAMissingTool(t *testing.T) {
	e := newEnv(t)
	root, _ := filepath.Abs(recalltest.FixtureRoot())
	req := laneBRequest(t, e, root)
	req.LaneB.Rules = filepath.Join(t.TempDir(), "no-rules")
	if _, err := Run(context.Background(), req); !errors.Is(err, ErrMissingTool) {
		t.Fatalf("err = %v, want ErrMissingTool", err)
	}
	var n int
	if err := e.store.QueryRow(`SELECT count(*) FROM scan_run`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused scan left %d scan runs (%v)", n, err)
	}
}

// TestAPolicyThatExcludesEveryEnabledLaneRefuses: Lane B on, SCA off, and a
// policy whose detectors are sca only, leaves nothing to run.
func TestAPolicyThatExcludesEveryEnabledLaneRefuses(t *testing.T) {
	e := newEnv(t)
	root, _ := filepath.Abs(recalltest.FixtureRoot())
	req := laneBRequest(t, e, root)
	req.PolicyPath = filepath.Join(t.TempDir(), "policy.yml")
	if err := os.WriteFile(req.PolicyPath, []byte("version: 1\ndefaults:\n  detectors: [sca]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), req); !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("err = %v, want ErrPolicyRefused", err)
	}
}
