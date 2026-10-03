package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/host"
	"github.com/Susquehanna-Syntax/Anvil/internal/collector/repo"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/offline"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"
)

const fixture = "../../testdata/lanea-fixture"

var scanClock = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

type env struct {
	cache, store *sql.DB
	req          Request
}

func newEnv(t *testing.T) env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	c, err := cache.Open(ctx, filepath.Join(dir, "anvil-cache.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := cache.Migrate(ctx, c); err != nil {
		t.Fatal(err)
	}
	rep, err := offline.Import(ctx, c, fixture)
	if err != nil {
		t.Fatalf("importing the fixture: %v", err)
	}
	if len(rep.Feeds) != 1 || rep.Feeds[0].Refused != "" || rep.Feeds[0].Documents != 5 {
		t.Fatalf("fixture import: %+v", rep.Feeds)
	}
	s, err := store.Open(ctx, filepath.Join(dir, "anvil.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	feeds, err := offline.Load(fixture)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	return env{cache: c, store: s, req: Request{
		Event: "manual", Cache: c, Store: s, Feeds: feeds, AnvilVersion: "test",
		Now: func() time.Time { n++; return scanClock.Add(time.Duration(n) * time.Second) },
	}}
}

func inventory(t *testing.T, name string) *host.Inventory {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture, "host", name))
	if err != nil {
		t.Fatal(err)
	}
	var inv host.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	return &inv
}

func ruleIDs(l *record.SARIFLog) []string {
	var out []string
	for _, r := range l.Runs[0].Results {
		out = append(out, r.RuleID)
	}
	sort.Strings(out)
	return out
}

func marksByRule(w store.WriteResult) map[string]store.MarkKind {
	m := map[string]store.MarkKind{}
	for _, x := range w.Marks {
		m[x.RuleID] = x.Kind
	}
	return m
}

// TestHostScanEndToEnd is the host half of Phase 4's exit gate on the
// fixture: a sealed SAST half with Lane A findings in the store and the
// record, then a second run that marks each finding new, persisting or fixed.
func TestHostScanEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	req := e.req
	req.Kind, req.Inventory = KindHost, inventory(t, "inventory-1.json")
	first, err := Run(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != OutcomeFindings || !first.Complete {
		t.Fatalf("first run: outcome %q complete %v problems %v", first.Outcome, first.Complete, first.Problems)
	}
	// The Debian 11 advisory for zzanvil-cleanfixture is NOT a finding on a
	// Debian 12 host: the release scope holds.
	if got := ruleIDs(first.Log); len(got) != 3 || got[0] != "CVE-2026-1101" || got[1] != "CVE-2026-1102" || got[2] != "CVE-2026-1103" {
		t.Fatalf("first run rules = %v, want CVE-2026-1101..1103", got)
	}
	if first.Log.Properties.State != record.StateBothSealed || first.Log.Runs[0].Properties.Status != record.HalfStatusSealed {
		t.Fatalf("first run: state %q, sast %q", first.Log.Properties.State, first.Log.Runs[0].Properties.Status)
	}
	for _, r := range first.Log.Runs[0].Results {
		if r.Properties.RemediableByAgent || r.Properties.Detector.Kind != record.DetectorKindHost {
			t.Errorf("%s: detector %q remediable %v", r.RuleID, r.Properties.Detector.Kind, r.Properties.RemediableByAgent)
		}
	}
	if m := marksByRule(first.Write); m["CVE-2026-1101"] != store.MarkNew || m["CVE-2026-1102"] != store.MarkNew || m["CVE-2026-1103"] != store.MarkNew {
		t.Fatalf("first run marks = %v", m)
	}

	// The second inventory upgrades the library past 1101's fix and adds a
	// package 1104 affects.
	req.Inventory = inventory(t, "inventory-2.json")
	second, err := Run(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]store.MarkKind{
		"CVE-2026-1101": store.MarkFixed,
		"CVE-2026-1102": store.MarkPersisting,
		"CVE-2026-1103": store.MarkPersisting,
		"CVE-2026-1104": store.MarkNew,
	}
	got := marksByRule(second.Write)
	if len(got) != len(want) {
		t.Fatalf("second run marks = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s marked %q, want %q", k, got[k], v)
		}
	}
}

// An inventory from a release the cache holds nothing for is not a clean
// host: the half fails and the scan says why.
func TestAHostTheCacheCannotDecideIsNotClean(t *testing.T) {
	e := newEnv(t)
	req := e.req
	inv := inventory(t, "inventory-1.json")
	inv.OSRelease.VersionID = "13"
	req.Kind, req.Inventory = KindHost, inv
	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeRefused || res.Log.Runs[0].Properties.Status != record.HalfStatusFailed {
		t.Fatalf("outcome %q status %q problems %v", res.Outcome, res.Log.Runs[0].Properties.Status, res.Problems)
	}
	if res.Write.Status != "failed" {
		t.Errorf("scan_run.status = %q", res.Write.Status)
	}
}

func TestAHostInventoryWithNoHostnameIsRefused(t *testing.T) {
	e := newEnv(t)
	req := e.req
	inv := inventory(t, "inventory-1.json")
	inv.Provenance.Hostname = ""
	req.Kind, req.Inventory = KindHost, inv
	if _, err := Run(context.Background(), req); !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("err = %v, want ErrPolicyRefused", err)
	}
}

// Repository SCA is off unless the operator enabled the Trivy database (the
// owner's accelerator decision, 2026-10-03), and the refusal comes before any
// audit exists.
func TestRepoSCAIsOffByDefault(t *testing.T) {
	e := newEnv(t)
	req := e.req
	req.Kind, req.RepoPath = KindRepo, filepath.Join(fixture, "repo")
	if _, err := Run(context.Background(), req); !errors.Is(err, ErrRepoSCANotEnabled) {
		t.Fatalf("err = %v, want ErrRepoSCANotEnabled", err)
	}
	var n int
	if err := e.store.QueryRow(`SELECT count(*) FROM scan_run`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused scan left %d scan runs (%v)", n, err)
	}
}

func TestAMissingTrivyIsAMissingTool(t *testing.T) {
	e := newEnv(t)
	req := e.req
	req.Kind, req.RepoPath, req.TrivyDB = KindRepo, filepath.Join(fixture, "repo"), TrivyDB{Enabled: true}
	req.Trivy = repo.DefaultConfig()
	req.Trivy.Binary = "anvil-no-such-trivy"
	if _, err := Run(context.Background(), req); !errors.Is(err, ErrMissingTool) {
		t.Fatalf("err = %v, want ErrMissingTool", err)
	}
}

// TestRepoScanEndToEnd runs the real Trivy over the fixture repository when
// Trivy and its database are installed. Where they are not, the same request
// must come back as a missing tool, never as clean; the Lane A chain ledger
// records which of the two this machine proved.
func TestRepoScanEndToEnd(t *testing.T) {
	e := newEnv(t)
	req := e.req
	req.Kind, req.RepoPath, req.TrivyDB = KindRepo, filepath.Join(fixture, "repo"), TrivyDB{Enabled: true}
	req.Trivy = repo.DefaultConfig()
	res, err := Run(context.Background(), req)
	if _, lookErr := repo.ResolveBinary(repo.BinaryName); lookErr != nil {
		if !errors.Is(err, ErrMissingTool) {
			t.Fatalf("no trivy on PATH, and the scan said %v rather than a missing tool", err)
		}
		t.Logf("trivy is not on PATH: the repo scan refused as a missing tool, as it must")
		return
	}
	if errors.Is(err, ErrMissingTool) {
		t.Logf("trivy is on PATH but has no database: %v", err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeFindings {
		t.Fatalf("outcome %q problems %v", res.Outcome, res.Problems)
	}
	for _, r := range res.Log.Runs[0].Results {
		a := r.Properties.Advisory
		if a == nil || a.LicenseSpdx != LicenseTrivyDBTier2 {
			t.Errorf("%s does not carry tier-2 attribution: %+v", r.RuleID, a)
		}
		if r.Properties.Detector.Kind != record.DetectorKindSCA {
			t.Errorf("%s: detector %q", r.RuleID, r.Properties.Detector.Kind)
		}
	}
	t.Logf("trivy decided %d finding(s) in the fixture repository: %v", len(res.Log.Runs[0].Results), ruleIDs(res.Log))
}
