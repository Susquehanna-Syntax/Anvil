package record

// Independent re-verification probes for CRITIQUE-03's claimed fixes.
// Written by the re-verifying critic; each probe is shaped to reproduce the
// ORIGINAL defect and must now fail to reproduce it.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// B1 — the GitHub projection refuses an unsealed half
// ---------------------------------------------------------------------------

func TestXVB1GitHubProjectionRefusesUnsealedHalves(t *testing.T) {
	for _, status := range HalfStatusValues() {
		status := status
		t.Run(string(status), func(t *testing.T) {
			log := ghOneRunLog(HalfSast, []Result{
				ghSastResult("sast:0001", "app/db.py", 412),
			})
			log.Runs[0].Properties.Status = status
			if status != HalfStatusSealed {
				log.Runs[0].Properties.SealedAt = nil
				log.Properties.State = StateCollecting
			}

			files, err := ProjectForGitHub(log)
			if err != nil {
				t.Fatalf("ProjectForGitHub: %v", err)
			}
			carried := 0
			for _, f := range files {
				carried += f.ResultCount
				for _, run := range f.Log.Runs {
					carried += len(run.Results)
				}
			}
			loss := GitHubLossOf(files)
			readable := halfSealOfRun(log, &log.Runs[0]).Readable()
			t.Logf("half status %-9s readable=%-5v -> projection carries %d results, %d dropped (%s=%d)",
				status, readable, carried, loss.TotalDropped(),
				GitHubDropHalfNotReadable, loss.DropCounts[GitHubDropHalfNotReadable])

			if readable {
				if carried == 0 {
					t.Errorf("a sealed half carried nothing; the gate is a wall")
				}
				return
			}
			if carried != 0 {
				t.Errorf("B1 REPRODUCED: unsealed half (%s) carried %d results into the GitHub projection", status, carried)
			}
			if loss.DropCounts[GitHubDropHalfNotReadable] != loss.SourceResultCount {
				t.Errorf("B1 REPRODUCED (silent): %d of %d withheld results ledgered under %q",
					loss.DropCounts[GitHubDropHalfNotReadable], loss.SourceResultCount, GitHubDropHalfNotReadable)
			}
			// The projected bytes must not carry the source snippet.
			for _, f := range files {
				if strings.Contains(string(f.JSON), "cur.execute") {
					t.Errorf("B1 REPRODUCED: projected bytes carry the source snippet of an unsealed half")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// M1 — an EXPIRED audit is refused by the read path, not merely an unsealed
// half
// ---------------------------------------------------------------------------

func TestXVM1ExpiredAuditIsRefusedEverywhere(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) { l.Properties.State = StateExpired })
	rd := NewReader(RecordMap{rpAuditID: l})

	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	cards, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	actionable := ActionableTaskCards(cards)

	t.Logf("expired audit: manifest cards=%d, task cards=%d, actionable=%d",
		len(m.Cards), len(cards), len(actionable))
	for _, h := range m.Halves {
		t.Logf("  manifest half %-4s status=%-6s Readable=%v refusal=%q results=%d cards=%d",
			h.Half, h.Status, h.Readable, h.ReadRefusal, h.Results, h.Cards)
		if h.Readable {
			t.Errorf("M1 REPRODUCED: manifest half %s claims Readable on an expired audit", h.Half)
		}
		if h.Results == 0 {
			t.Errorf("an expired half reports 0 results; 'expired' and 'empty' must stay distinguishable")
		}
		if h.ReadRefusal == "" {
			t.Errorf("half %s is unreadable with no refusal reason", h.Half)
		}
	}
	if len(m.Cards) != 0 {
		t.Errorf("M1 REPRODUCED: %d card refs from an expired audit", len(m.Cards))
	}
	if len(cards) != 0 {
		t.Errorf("M1 REPRODUCED: %d task cards from an expired audit", len(cards))
	}
	if len(actionable) != 0 {
		t.Errorf("M1 REPRODUCED: %d ACTIONABLE cards from an expired audit", len(actionable))
	}

	files, err := ProjectForGitHub(l)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	carried := 0
	for _, f := range files {
		carried += f.ResultCount
	}
	loss := GitHubLossOf(files)
	t.Logf("expired audit: GitHub projection carries %d results, %d ledgered under %q",
		carried, loss.DropCounts[GitHubDropHalfNotReadable], GitHubDropHalfNotReadable)
	if carried != 0 {
		t.Errorf("M1 REPRODUCED: GitHub projection carried %d results from an expired audit", carried)
	}
	if loss.DropCounts[GitHubDropHalfNotReadable] != loss.SourceResultCount {
		t.Errorf("expired drops not fully ledgered: %d of %d",
			loss.DropCounts[GitHubDropHalfNotReadable], loss.SourceResultCount)
	}
	// The drop entries must name the audit state, not merely the status.
	for _, d := range loss.DroppedResults {
		if d.AuditState != StateExpired {
			t.Errorf("drop entry for %s records auditState=%q, want %q", d.FindingID, d.AuditState, StateExpired)
		}
		if d.HalfStatus != HalfStatusSealed {
			t.Errorf("drop entry for %s records halfStatus=%q; the halves ARE sealed here", d.FindingID, d.HalfStatus)
		}
	}
	// Sealing-side agreement.
	for i := range l.Runs {
		if halfSealOfRun(l, &l.Runs[i]).Readable() {
			t.Errorf("halfSealOfRun(...).Readable() is true on an expired audit")
		}
	}
}

// TestXVM1ExpiredIsDistinctFromUnsealed asserts the refusal STRINGS differ, so
// "the window closed" and "never sealed" do not arrive as one observation.
func TestXVM1ExpiredIsDistinctFromUnsealed(t *testing.T) {
	expired := halfReadRefusal(HalfSeal{Half: HalfSast, Status: HalfStatusSealed, AuditState: StateExpired})
	unsealed := halfReadRefusal(HalfSeal{Half: HalfSast, Status: HalfStatusRunning, AuditState: StateCollecting})
	t.Logf("expired refusal  = %q", expired)
	t.Logf("unsealed refusal = %q", unsealed)
	if expired == "" || unsealed == "" {
		t.Fatal("a refusal is empty; the gate is open where it must not be")
	}
	if expired == unsealed {
		t.Error("expired and unsealed give the same refusal string")
	}
	// And an expired audit holding a sealed half must report the EXPIRY.
	if !strings.Contains(expired, "timeout") && !strings.Contains(expired, "expired") {
		t.Errorf("an expired audit reports %q, which does not name the expiry", expired)
	}
}

// ---------------------------------------------------------------------------
// M2 — the unreferenced-rule ledger counts against the SHARD SET
// ---------------------------------------------------------------------------

func TestXVM2UnreferencedRuleLedgerIsAgainstTheShardSet(t *testing.T) {
	const n = GitHubMaxResultsPerRun + 10

	results := make([]Result, 0, n)
	for i := 0; i < n; i++ {
		r := ghSastResult(fmt.Sprintf("sast:%d", i), fmt.Sprintf("app/pkg%d/file%d.py", i%64, i), (i%900)+1)
		// rule.0 is referenced only by results that land in shard 1; rule.3
		// only by results that land in shard 2. rule.1 and rule.2 are never
		// referenced and are the only genuinely lost rules.
		if i < GitHubMaxResultsPerRun {
			r.RuleID = "rule.0"
		} else {
			r.RuleID = "rule.3"
		}
		results = append(results, r)
	}
	log := ghOneRunLog(HalfSast, results)
	log.Runs[0].Tool.Driver.Rules = []ReportingDescriptor{
		{ID: "rule.0"}, {ID: "rule.1"}, {ID: "rule.2"}, {ID: "rule.3"},
	}

	files, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("expected >=2 shards, got %d", len(files))
	}

	delivered := map[string]bool{}
	for _, f := range files {
		for _, run := range f.Log.Runs {
			for _, rule := range run.Tool.Driver.Rules {
				delivered[rule.ID] = true
			}
		}
	}
	keys := make([]string, 0, len(delivered))
	for k := range delivered {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	loss := GitHubLossOf(files)
	got := loss.StripCounts[GitHubStripUnreferencedRule]
	srcRules := len(log.Runs[0].Tool.Driver.Rules)
	trulyLost := srcRules - len(delivered)

	t.Logf("shards=%d rules delivered across shards=%v", len(files), keys)
	t.Logf("StripCounts[%s] = %d ; source rules = %d ; truly lost = %d",
		GitHubStripUnreferencedRule, got, srcRules, trulyLost)

	if got > srcRules {
		t.Errorf("M2 REPRODUCED: ledger reports %d unreferenced rules but the source run has only %d", got, srcRules)
	}
	if got != trulyLost {
		t.Errorf("M2 REPRODUCED: ledger says %d unreferenced, truly lost is %d", got, trulyLost)
	}
	// It must not scale with shard count: with one shard the answer is the same.
	single := ghOneRunLog(HalfSast, results[:10])
	single.Runs[0].Tool.Driver.Rules = log.Runs[0].Tool.Driver.Rules
	for i := range single.Runs[0].Results {
		single.Runs[0].Results[i].RuleID = "rule.0"
	}
	sf, err := ProjectForGitHub(single)
	if err != nil {
		t.Fatalf("ProjectForGitHub(single): %v", err)
	}
	sl := GitHubLossOf(sf)
	t.Logf("one shard, same 4 rules, only rule.0 referenced: StripCounts[%s] = %d",
		GitHubStripUnreferencedRule, sl.StripCounts[GitHubStripUnreferencedRule])
	if sl.StripCounts[GitHubStripUnreferencedRule] != 3 {
		t.Errorf("single-shard control: want 3 unreferenced, got %d", sl.StripCounts[GitHubStripUnreferencedRule])
	}
}

// ---------------------------------------------------------------------------
// M3 (task numbering) — relatedLocations count against the per-result cap
// ---------------------------------------------------------------------------

func TestXVM3RelatedLocationsAreCapped(t *testing.T) {
	cases := []struct{ locs, related int }{
		{3000, 3000},
		{0, 3000},
		{999, 3000},
		{1000, 1},
		{500, 400},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("loc%d_rel%d", tc.locs, tc.related), func(t *testing.T) {
			r := ghSastResult("sast:fanout", "app/db.py", 412)
			r.Locations = nil
			for i := 0; i < tc.locs; i++ {
				r.Locations = append(r.Locations, Location{PhysicalLocation: &PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: fmt.Sprintf("app/l%d.py", i)},
					Region:           &Region{StartLine: i + 1},
				}})
			}
			r.RelatedLocations = nil
			for i := 0; i < tc.related; i++ {
				r.RelatedLocations = append(r.RelatedLocations, Location{PhysicalLocation: &PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: fmt.Sprintf("app/r%d.py", i)},
					Region:           &Region{StartLine: i + 1},
				}})
			}
			log := ghOneRunLog(HalfSast, []Result{r})
			files, err := ProjectForGitHub(log)
			if err != nil {
				t.Fatalf("ProjectForGitHub: %v", err)
			}
			if len(files) != 1 || len(files[0].Log.Runs) != 1 {
				t.Fatalf("unexpected shape: %d files", len(files))
			}
			if len(files[0].Log.Runs[0].Results) == 0 {
				// GitHub requires a physical location; a result with an empty
				// `locations` array is dropped outright and ledgered. That is
				// a different rule from the cap and not what this probe is
				// measuring.
				t.Skipf("result dropped before the cap ran: %s", GitHubLossOf(files).Summary())
			}
			out := files[0].Log.Runs[0].Results[0]
			total := len(out.Locations) + len(out.RelatedLocations)
			t.Logf("in: locations=%d relatedLocations=%d -> out: locations=%d relatedLocations=%d total=%d (cap %d)",
				tc.locs, tc.related, len(out.Locations), len(out.RelatedLocations), total, GitHubMaxLocationsPerResult)
			if total > GitHubMaxLocationsPerResult {
				t.Errorf("M3 REPRODUCED: %d locations+relatedLocations exceeds the %d cap",
					total, GitHubMaxLocationsPerResult)
			}
			if err := files[0].WithinCaps(); err != nil {
				t.Errorf("M3 REPRODUCED: WithinCaps refuses the file it just built: %v", err)
			}
			// The overflow must be countable.
			loss := GitHubLossOf(files)
			want := 0
			if tc.locs+tc.related > GitHubMaxLocationsPerResult {
				want = tc.locs + tc.related - GitHubMaxLocationsPerResult
			}
			if got := loss.StripCounts[GitHubStripLocationsOverCap]; got != want {
				t.Errorf("overflow tally = %d, want %d (silent truncation)", got, want)
			}
		})
	}
}

// TestXVM3WithinCapsWouldCatchAnUncappedPair is a direct mutation of the
// POST-CONDITION: hand WithinCaps a file whose pair exceeds the cap and it
// must refuse. If it does not, the "independent check" is decorative.
func TestXVM3WithinCapsCountsThePair(t *testing.T) {
	f := &GitHubSarifFile{
		Name: "probe.sarif",
		Log: GitHubSARIFLog{Runs: []GitHubRun{{Results: []GitHubResult{{
			Locations:        make([]GitHubLocation, GitHubMaxLocationsPerResult),
			RelatedLocations: make([]GitHubLocation, 1),
		}}}}},
	}
	err := f.WithinCaps()
	t.Logf("WithinCaps(1000 locations + 1 relatedLocation) = %v", err)
	if err == nil {
		t.Error("M3 REPRODUCED: WithinCaps accepts 1001 locations across the pair")
	}
}

// ---------------------------------------------------------------------------
// M4 (task numbering) — NewReader / Reader.Blobs: a spill is not a dangling
// reference on the default path
// ---------------------------------------------------------------------------

func TestXVM4NewReaderRetainsSpilledBlobs(t *testing.T) {
	// Enough findings to force the byPath/byCwe/byCluster/cards spills.
	l := rpFixture(t, func(l *SARIFLog) {
		for i := 0; i < 120; i++ {
			r := rpSastResult(fmt.Sprintf("sast:9%03d", i), 30.0, EvidenceClassSastStaticOnly,
				VerdictTruePositive, true, fmt.Sprintf("app/gen/mod%d/file%d.py", i%16, i), byte(i%251))
			r.PartialFingerprints[PartialFingerprintAnvilFindingID] = rpDigest(byte(100 + i%150))
			l.Runs[0].Results = append(l.Runs[0].Results, r)
		}
	})
	rd := NewReader(RecordMap{rpAuditID: l})
	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if len(m.Spills) == 0 {
		t.Fatalf("fixture did not spill; the probe asserts nothing (bytes=%d)", m.Bytes)
	}

	retained := rd.RetainedBlobs()
	t.Logf("manifest bytes=%d spills=%d retained blobs=%d manifest.Blobs=%d",
		m.Bytes, len(m.Spills), len(retained), len(m.Blobs))
	for _, sp := range m.Spills {
		t.Logf("  spill field=%-22s ref=%s items=%d", sp.Field, sp.Ref, sp.Items)
		if _, ok := retained[sp.Ref]; !ok {
			t.Errorf("M4 REPRODUCED: spill %q references %s but the default Reader retained nothing for it",
				sp.Field, sp.Ref)
		}
	}
	// A caller that marshals the manifest and drops the struct must still be
	// able to resolve every reference from the Reader.
	drained := rd.DrainRetainedBlobs()
	if len(drained) != len(retained) {
		t.Errorf("DrainRetainedBlobs returned %d, RetainedBlobs %d", len(drained), len(retained))
	}
	if after := rd.RetainedBlobs(); len(after) != 0 {
		t.Errorf("drain left %d blobs behind", len(after))
	}
	// The blob content must be the real payload, and its ref must verify.
	for ref, content := range drained {
		if got := BlobRef(content); got != ref {
			t.Errorf("retained blob keyed %s but hashes to %s", ref, got)
		}
	}
}

// TestXVM4SpilledBlobsFromAnUnreadableHalfAreEmpty checks the blob store is
// not a back door around the gate.
func TestXVM4RetainedBlobsCarryNothingFromAnUnreadableHalf(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		l.Properties.State = StateExpired
		for i := 0; i < 200; i++ {
			r := rpSastResult(fmt.Sprintf("sast:8%03d", i), 30.0, EvidenceClassSastStaticOnly,
				VerdictTruePositive, true, fmt.Sprintf("app/secret/mod%d/file%d.py", i%16, i), byte(i%251))
			r.PartialFingerprints[PartialFingerprintAnvilFindingID] = rpDigest(byte(50 + i%200))
			l.Runs[0].Results = append(l.Runs[0].Results, r)
		}
	})
	rd := NewReader(RecordMap{rpAuditID: l})
	if _, err := rd.BuildManifest(rpAuditID); err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	retained := rd.RetainedBlobs()
	t.Logf("expired audit: retained blobs=%d", len(retained))
	for ref, content := range retained {
		if strings.Contains(string(content), "app/secret/") {
			t.Errorf("GATE BYPASS: blob %s carries a path from an unreadable half", ref)
		}
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 M3 part 1 — the Tier-0 all-or-nothing degradation
// ---------------------------------------------------------------------------

// TestXVTier0DegradationIsStillAllOrNothing MEASURES the crossover the critique
// described. It does not fail: it records the number so the reviewer can see
// whether the proposed partial-cards fix landed.
func TestXVTier0BudgetUtilisationAcrossSizes(t *testing.T) {
	for _, extra := range []int{0, 10, 20, 30, 40, 50, 120, 400} {
		extra := extra
		t.Run(fmt.Sprintf("extra%d", extra), func(t *testing.T) {
			l := rpFixture(t, func(l *SARIFLog) {
				for i := 0; i < extra; i++ {
					r := rpSastResult(fmt.Sprintf("sast:7%03d", i), 30.0, EvidenceClassSastStaticOnly,
						VerdictTruePositive, true, fmt.Sprintf("app/svc/mod%d/file%d.py", i%16, i), byte(i%251))
					r.PartialFingerprints[PartialFingerprintAnvilFindingID] = rpDigest(byte(30 + i%220))
					l.Runs[0].Results = append(l.Runs[0].Results, r)
				}
			})
			rd := NewReader(RecordMap{rpAuditID: l})
			m, err := rd.BuildManifest(rpAuditID)
			if err != nil {
				t.Fatalf("BuildManifest: %v", err)
			}
			fields := make([]string, 0, len(m.Spills))
			for _, sp := range m.Spills {
				fields = append(fields, sp.Field)
			}
			total := 0
			for i := range l.Runs {
				total += len(l.Runs[i].Results)
			}
			t.Logf("findings=%3d bytes=%5d (budget %d, used %.0f%%) cards=%3d spills=%v",
				total, m.Bytes, MaxTier0ManifestBytes,
				100*float64(m.Bytes)/float64(MaxTier0ManifestBytes), len(m.Cards), fields)
		})
	}
}

// ---------------------------------------------------------------------------
// THE CONSOLIDATION — my own enumeration, not the package's list
// ---------------------------------------------------------------------------

// xvResultBearing is DELIBERATELY WIDER than the package's own
// TestResultBearingEntryPointsAreAllAudited type set. That test omits Result,
// Run and SARIFLog, which are the most natural spellings of "a half's
// results".
func xvResultBearing() map[string]bool {
	return map[string]bool{
		"Manifest": true, "ManifestHalf": true, "CardRef": true, "TaskCard": true,
		"GitHubSarifFile": true, "GitHubSARIFLog": true, "GitHubRun": true, "GitHubResult": true,
		"HalfSeal": true, "AuditSeal": true,
		// The wider set the package's own guard does NOT cover:
		"Result": true, "Run": true, "SARIFLog": true, "Location": true,
		"CodeFlow": true, "Correlation": true, "TierSpill": true,
	}
}

// TestXVEnumerateEveryExportedResultBearingEntryPoint is the independent
// census. It never fails on membership; it PRINTS the census plus which names
// the package's own gateAuditedEntryPoints covers, so a surviving hole is
// visible in the log.
func TestXVEnumerateEveryExportedResultBearingEntryPoint(t *testing.T) {
	audited := map[string]bool{}
	for _, e := range gateAuditedEntryPoints() {
		audited[e.name] = true
	}
	bearing := xvResultBearing()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	type row struct{ name, file, types string }
	var rows []row
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !fn.Name.IsExported() || fn.Type.Results == nil {
					continue
				}
				name := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) == 1 {
					recv := gateBaseTypeName(fn.Recv.List[0].Type)
					if recv == "" || !ast.IsExported(recv) {
						continue
					}
					name = recv + "." + name
				}
				var hit []string
				for _, res := range fn.Type.Results.List {
					if b := gateBaseTypeName(res.Type); bearing[b] {
						hit = append(hit, b)
					}
				}
				if len(hit) == 0 {
					continue
				}
				rows = append(rows, row{name, filepath.Base(path), strings.Join(hit, ",")})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	t.Logf("WIDE census: %d exported entry points return a result-bearing type", len(rows))
	for _, r := range rows {
		mark := "AUDITED  "
		if !audited[r.name] {
			mark = "NOT-LISTED"
		}
		t.Logf("  %-10s %-32s %-18s returns %s", mark, r.name, r.file, r.types)
	}
}

// TestXVCountGateSpellings greps the non-test source for every place that
// decides readability, so a fifth spelling alongside the one gate is visible.
func TestXVCountGateSpellings(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	needles := []string{
		"== HalfStatusSealed", "!= HalfStatusSealed",
		"IsReadableHalfStatus(", "== StateExpired", "!= StateExpired",
		"HalfReadGate(", ".Readable()", "halfReadRefusal(",
	}
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".go") || strings.HasSuffix(de.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(de.Name())
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, n := range needles {
				if strings.Contains(line, n) {
					t.Logf("%s:%d  [%s]  %s", de.Name(), i+1, n, trimmed)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// The full per-function gate table, driven by MY OWN scenarios rather than the
// package's gateScenarios.
// ---------------------------------------------------------------------------

func xvScenario(t *testing.T, name string, expire bool, status HalfStatus) (string, *SARIFLog, *Sealer) {
	t.Helper()
	auditID := "0198e2c1-6a4b-7d3e-9f10-2b7c5d8a4e" + name
	l := rpFixture(t, func(l *SARIFLog) {
		l.Properties.AuditID = auditID
		for i := range l.Runs {
			l.Runs[i].AutomationDetails.CorrelationGUID = auditID
			if !expire {
				l.Runs[i].Properties.Status = status
				l.Runs[i].Properties.SealedAt = nil
			}
		}
		if expire {
			l.Properties.State = StateExpired
		} else {
			l.Properties.State = StateCollecting
			l.Properties.DastStatus = DastStatusRunning
		}
	})

	cfg := AuditConfig{AuditID: auditID, StartedAt: rpTime(), ClaimTimeoutSeconds: 3600, DastEnabled: true}
	if expire {
		cfg.StartedAt = time.Now().Add(-72 * time.Hour)
		cfg.ClaimTimeoutSeconds = 1
	}
	s := NewSealer()
	if _, err := s.BeginAudit(cfg); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if expire {
		for _, half := range HalfValues() {
			if err := s.SealHalf(auditID, half, HalfStatusSealed); err != nil {
				t.Fatalf("SealHalf: %v", err)
			}
		}
		if done, err := s.ExpireIfDue(auditID); err != nil || !done {
			t.Fatalf("ExpireIfDue = %v, %v", done, err)
		}
	}
	return auditID, l, s
}

// TestXVGateTable produces the function-by-function table the review asks for.
func TestXVGateTable(t *testing.T) {
	type scen struct {
		label   string
		auditID string
		log     *SARIFLog
		sealer  *Sealer
	}
	id1, l1, s1 := xvScenario(t, "01", false, HalfStatusRunning)
	id2, l2, s2 := xvScenario(t, "02", true, HalfStatusSealed)
	scens := []scen{
		{"unsealed(running)", id1, l1, s1},
		{"expired(sealed)", id2, l2, s2},
	}

	type fn struct {
		name  string
		count func(t *testing.T, auditID string, l *SARIFLog, s *Sealer) int
	}
	fns := []fn{
		{"Reader.BuildManifest", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			m, err := NewReader(RecordMap{id: l}).BuildManifest(id)
			if err != nil {
				t.Fatalf("%v", err)
			}
			n := len(m.Cards)
			for _, h := range m.Halves {
				if h.Readable {
					n++
				}
			}
			return n
		}},
		{"Reader.ManifestFromLog", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			m, err := NewReader(RecordMap{id: l}).ManifestFromLog(l)
			if err != nil {
				t.Fatalf("%v", err)
			}
			n := len(m.Cards)
			for _, h := range m.Halves {
				if h.Readable {
					n++
				}
			}
			return n
		}},
		{"Reader.BuildTaskCards", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			c, err := NewReader(RecordMap{id: l}).BuildTaskCards(id)
			if err != nil {
				t.Fatalf("%v", err)
			}
			return len(c)
		}},
		{"Reader.CardsFromLog", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			c, err := NewReader(RecordMap{id: l}).CardsFromLog(l)
			if err != nil {
				t.Fatalf("%v", err)
			}
			return len(c)
		}},
		{"ActionableTaskCards", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			c, err := NewReader(RecordMap{id: l}).BuildTaskCards(id)
			if err != nil {
				t.Fatalf("%v", err)
			}
			return len(ActionableTaskCards(c))
		}},
		{"ProjectForGitHub", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			files, err := ProjectForGitHub(l)
			if err != nil {
				t.Fatalf("%v", err)
			}
			n := 0
			for _, f := range files {
				n += f.ResultCount
				for _, r := range f.Log.Runs {
					n += len(r.Results)
				}
			}
			return n
		}},
		{"GitHubLossOf", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			files, err := ProjectForGitHub(l)
			if err != nil {
				t.Fatalf("%v", err)
			}
			loss := GitHubLossOf(files)
			if loss == nil {
				t.Fatal("no ledger")
			}
			return loss.ProjectedResultCount
		}},
		{"Reader.RetainedBlobs", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			rd := NewReader(RecordMap{id: l})
			if _, err := rd.BuildManifest(id); err != nil {
				t.Fatalf("%v", err)
			}
			n := 0
			for _, b := range rd.RetainedBlobs() {
				if strings.Contains(string(b), "app/db.py") || strings.Contains(string(b), "sast:0001") {
					n++
				}
			}
			return n
		}},
		{"Sealer.ReadHalf", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			n := 0
			for _, h := range HalfValues() {
				seal, err := s.ReadHalf(id, h)
				if err == nil {
					n++
				}
				if seal.Readable() {
					n++
				}
			}
			return n
		}},
		{"Sealer.Inspect", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			a, ok := s.Inspect(id)
			if !ok {
				t.Fatalf("Inspect(%q) unknown", id)
			}
			return gateReadableHalves(a)
		}},
		{"Sealer.ReadyForConsumption", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			n := 0
			sast, dast := s.ReadyForConsumption(id)
			if sast {
				n++
			}
			if dast {
				n++
			}
			return n
		}},
		{"HalfSeal.Readable", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			n := 0
			for i := range l.Runs {
				if halfSealOfRun(l, &l.Runs[i]).Readable() {
					n++
				}
			}
			return n
		}},
		{"HalfReadGate", func(t *testing.T, id string, l *SARIFLog, s *Sealer) int {
			n := 0
			for i := range l.Runs {
				if HalfReadGate(id, halfSealOfRun(l, &l.Runs[i])) == nil {
					n++
				}
			}
			return n
		}},
	}

	for _, sc := range scens {
		for _, f := range fns {
			f := f
			sc := sc
			t.Run(sc.label+"/"+f.name, func(t *testing.T) {
				n := f.count(t, sc.auditID, sc.log, sc.sealer)
				verdict := "REFUSED"
				if n != 0 {
					verdict = "LEAKED"
				}
				t.Logf("%-24s %-26s -> %d  %s", sc.label, f.name, n, verdict)
				if n != 0 {
					t.Errorf("BYPASS: %s handed out %d while %s", f.name, n, sc.label)
				}
			})
		}
	}
}
