package record

// sarif_github_test.go — R.14's evidence.
//
// The packet's stop condition is two tests: the sharding test and the
// DAST-exclusion-is-logged test. Both are here (TestGitHubShardsBeyondResults
// PerRunCap, TestGitHubDastOnlyExclusionIsCountedNotSilent). The rest of the
// file exists because the two named tests do not, on their own, establish the
// property this projection is for: that the loss is TOTAL and ENUMERABLE
// rather than merely small.
//
// In particular:
//
//   - TestGitHubProjectionEmitsNoUnsupportedBytes searches the produced upload
//     bytes for the forbidden constructs. Asserting on the Go structs would
//     pass while the encoder emitted `"properties":{"anvil/findingId":""}`;
//     asserting on the bytes cannot.
//   - TestGitHubProjectedTypesHaveNoPropertiesMember proves the same thing
//     structurally, so a later edit that adds a properties member to a
//     projected type fails even if no fixture happens to populate it.
//   - TestGitHubDropReasonTableIsExhaustive fails when a new
//     GitHubDropReason is added without a test that produces it. A drop
//     reason nothing exercises is a claim, not a behaviour.
//   - TestGitHubSplitsOnGzipCapAndDropsUnshardableResult crosses the real
//     10 MB boundary with real incompressible bytes rather than lowering the
//     cap for the test. Lowering it would test the arithmetic and not the
//     guarantee.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixtures
//
// Names are prefixed `gh` throughout: this file shares a package with
// contract_test.go, fingerprint_test.go, mask_test.go and sealing_test.go,
// and a helper collision across test files is a compile error in a package
// nobody owns end to end.
// ---------------------------------------------------------------------------

const (
	ghAuditID = "3f0c8c1a-77e2-4b19-9c33-8a1d5f0e2b41"

	// ghHash64 is a 64-character lowercase hex digest. Validate() requires
	// exactly FingerprintDigestHexLen characters and never a truncation.
	ghHash64 = "8c1e4b0f9a2d77c5e31048ab6f2c9d5e77b1a3c4d2e5f60718293a4b5c6d7e8f"

	// ghLineHash is the shape research/18's annotated record shows for
	// primaryLocationLineHash: a digest, a colon, and an ordinal.
	ghLineHash = "4f2a9c71e3b85d60:1"

	// ghEndpoint is an internal hostname. It must never appear in an upload:
	// GitHub cannot render it as an alert, and publishing it leaks the
	// staging topology to a third party.
	ghEndpoint = "https://staging.payments.internal/api/login"
)

func ghTime() time.Time { return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC) }

// ghUntrusted is the trust assertion every fixture result carries. Default
// untrusted is legal for every external string and is REQUIRED on any result
// carrying a webResponse (contract.go, ValidateResultTrust).
func ghUntrusted() TrustAssertion { return TrustAssertion{Default: TrustUntrusted} }

// ghSastResult builds a SAST result GitHub can render: repo-relative path,
// positive start line, both identity fingerprints.
func ghSastResult(findingID, uri string, line int) Result {
	return Result{
		RuleID:  "anvil.sqli.raw-concat",
		Level:   LevelError,
		Message: Message{Text: "String-concatenated SQL reaches cur.execute()."},
		Locations: []Location{{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: uri, URIBaseID: "REPOROOT"},
				Region:           &Region{StartLine: line, Snippet: &Snippet{Text: "query = \"SELECT * FROM users WHERE name = '\" + name"}},
			},
		}},
		PartialFingerprints: map[string]string{
			PartialFingerprintAnvilFindingID:          ghHash64,
			PartialFingerprintPrimaryLocationLineHash: ghLineHash,
		},
		Properties: ResultProperties{
			FindingID:     findingID,
			Half:          HalfSast,
			Confidence:    0.9,
			Verdict:       VerdictTruePositive,
			EvidenceClass: EvidenceClassSastReachable,
			Detector:      DetectorRef{Kind: DetectorKindSast, Model: "m", Revision: "r"},
			Trust:         ghUntrusted(),
		},
	}
}

// ghDastResult builds the DAST result research/18's annotated record shows:
// an ENDPOINT location carrying the `startLine: 1` "placeholder so GitHub can
// render it". The placeholder is exactly what this projection must refuse.
func ghDastResult(findingID string) Result {
	return Result{
		RuleID:  "anvil.dast.sqli",
		Level:   LevelError,
		Message: Message{Text: "POST /api/login returned HTTP 500 after a quote was injected."},
		Locations: []Location{{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: ghEndpoint},
				Region:           &Region{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 2},
			},
			Properties: map[string]any{PropLocationKind: "httpEndpoint"},
		}},
		WebRequest:  &WebRequest{Method: "POST", Target: ghEndpoint},
		WebResponse: &WebResponse{StatusCode: 500, Body: &ArtifactContent{Text: "sqlite3.OperationalError"}},
		PartialFingerprints: map[string]string{
			PartialFingerprintAnvilFindingID:          ghHash64,
			PartialFingerprintPrimaryLocationLineHash: ghLineHash,
		},
		Properties: ResultProperties{
			FindingID:     findingID,
			Half:          HalfDast,
			Confidence:    0.8,
			Verdict:       VerdictTruePositive,
			EvidenceClass: EvidenceClassDastConfirmed,
			Detector:      DetectorRef{Kind: DetectorKindDast, Model: "m", Revision: "r"},
			Trust:         ghUntrusted(),
		},
	}
}

// ghDastResultNoLocation is the other DAST shape: no file, no endpoint
// placeholder, no locations at all.
func ghDastResultNoLocation(findingID string) Result {
	r := ghDastResult(findingID)
	r.Locations = nil
	return r
}

func ghDastCoverage() *DastCoverage {
	return &DastCoverage{
		ProbedCount:            1,
		InventoryUnionCount:    2,
		EndpointCoverage:       0.5,
		InventoryProvenanceMix: map[InventoryProvenance]int{},
		ConfirmedCount:         1,
		CandidateCount:         1,
	}
}

// ghValidAudit builds a record that passes SARIFLog.Validate(): both halves
// sealed, deadline anchored to scan start, every frozen enum populated.
//
// Projecting a record that a producer could not legally emit would prove
// nothing, so the tests that assert projection semantics run against this.
func ghValidAudit(t *testing.T) *SARIFLog {
	t.Helper()
	created := ghTime()
	sealed := created.Add(time.Hour)

	sast := ghSastResult("sast:1", "app/db.py", 414)
	// Cross-half pointer at the DAST endpoint (research/18's construct), a
	// CWE taxon, regression provenance, a proposed fix, a third
	// partialFingerprint key, and a code flow with one endpoint step: every
	// one of these must be stripped.
	sast.RelatedLocations = []Location{{
		ID:               ghPtrInt(1),
		PhysicalLocation: &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: ghEndpoint}, Region: &Region{StartLine: 1}},
	}}
	sast.Taxa = []ReportingDescriptorReference{{ID: "89", Index: ghPtrInt(0)}}
	sast.Provenance = &ResultProvenance{FirstDetectionRunGUID: "1c0b77aa-2d4e-4f11-9a3c-6e5d4c3b2a19"}
	sast.Fixes = []Fix{{ArtifactChanges: []ArtifactChange{{ArtifactLocation: ArtifactLocation{URI: "app/db.py"}}}}}
	sast.PartialFingerprints[PartialFingerprintRegionSHA256] = ghHash64
	sast.CodeFlows = []CodeFlow{{ThreadFlows: []ThreadFlow{{Locations: []ThreadFlowLocation{
		{Location: Location{PhysicalLocation: &PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "app/routes.py"}, Region: &Region{StartLine: 88}}}},
		{Location: Location{PhysicalLocation: &PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: ghEndpoint}, Region: &Region{StartLine: 1}}}},
	}}}}}

	return &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Properties: AuditProperties{
			SchemaVersion: SchemaVersion,
			AuditID:       ghAuditID,
			State:         StateBothSealed,
			Version:       1,
			CreatedAt:     created,
			Target: Target{
				RepoURL:      "https://example.invalid/repo.git",
				Provenance:   TargetProvenanceBootedClean,
				Provisioning: TargetProvisioningEphemeralManifest,
			},
			Deadline: Deadline{
				DeadlineAt:          created.Add(time.Duration(DefaultClaimTimeoutSeconds) * time.Second),
				ClaimTimeoutSeconds: DefaultClaimTimeoutSeconds,
			},
			Index:      Index{ReadOrder: DefaultReadOrder()},
			DastStatus: DastStatusCompletedFindings,
		},
		Runs: []Run{
			{
				Tool: Tool{Driver: ToolComponent{
					Name: "anvil-sast",
					Rules: []ReportingDescriptor{
						{ID: "anvil.sqli.raw-concat",
							ShortDescription: &Message{Text: "SQL injection"},
							FullDescription:  &Message{Text: "Concatenated SQL reaches a sink."},
							Help:             &Message{Text: "Parameterise the query."},
							Relationships:    []ReportingDescriptorRelationship{{Target: ReportingDescriptorReference{ID: "89"}}}},
						{ID: "anvil.unused.rule", ShortDescription: &Message{Text: "unreferenced"}},
					},
					Taxa: []ReportingDescriptor{{ID: "89"}},
				}},
				AutomationDetails: RunAutomationDetails{
					ID: "anvil-sast/", GUID: "aaaaaaaa-0000-4000-8000-000000000001", CorrelationGUID: ghAuditID,
				},
				Taxonomies: []ToolComponent{{Name: "CWE"}},
				Results:    []Result{sast},
				Properties: RunProperties{
					Half: HalfSast, Status: HalfStatusSealed, SealedAt: &sealed,
					AdvisorySnapshot: &AdvisorySnapshot{SnapshotDigest: ghHash64, ScrapedAt: created},
				},
			},
			{
				Tool: Tool{Driver: ToolComponent{Name: "anvil-dast"}},
				AutomationDetails: RunAutomationDetails{
					ID: "anvil-dast/", GUID: "aaaaaaaa-0000-4000-8000-000000000002", CorrelationGUID: ghAuditID,
				},
				Results: []Result{ghDastResult("dast:1"), ghDastResultNoLocation("dast:2")},
				Properties: RunProperties{
					Half: HalfDast, Status: HalfStatusSealed, SealedAt: &sealed,
					DastCoverage:  ghDastCoverage(),
					RuntimeTarget: &RuntimeTarget{BaseURL: "https://staging.payments.internal"},
				},
			},
		},
	}
}

func ghPtrInt(n int) *int { return &n }

// ---------------------------------------------------------------------------
// The packet's two named tests
// ---------------------------------------------------------------------------

// TestGitHubShardsBeyondResultsPerRunCap is the packet's sharding stop
// condition: a fixture exceeding 25,000 results shards into multiple files,
// none exceeding a cap, and nothing is truncated away.
func TestGitHubShardsBeyondResultsPerRunCap(t *testing.T) {
	const n = GitHubMaxResultsPerRun + 1

	results := make([]Result, 0, n)
	for i := 0; i < n; i++ {
		results = append(results, ghSastResult(fmt.Sprintf("sast:%d", i), fmt.Sprintf("app/pkg%d/file%d.py", i%64, i), (i%900)+1))
	}
	log := ghOneRunLog(HalfSast, results)

	files, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("a %d-result run must shard into multiple files, got %d", n, len(files))
	}

	total := 0
	seenAutomationID := map[string]bool{}
	for i, f := range files {
		if err := f.WithinCaps(); err != nil {
			t.Errorf("file %d: %v", i, err)
		}
		if got := len(f.Log.Runs); got != GitHubRunsPerProjectedFile {
			t.Errorf("file %d: %d runs, want %d (one run per file is the shard policy)", i, got, GitHubRunsPerProjectedFile)
		}
		if f.ResultCount > GitHubMaxResultsPerRun {
			t.Errorf("file %d: %d results exceeds the %d cap", i, f.ResultCount, GitHubMaxResultsPerRun)
		}
		if f.GzipBytes > GitHubMaxGzipBytes {
			t.Errorf("file %d: %d gzip bytes exceeds the %d cap", i, f.GzipBytes, GitHubMaxGzipBytes)
		}
		if f.ShardCount != len(files) {
			t.Errorf("file %d: ShardCount %d, want %d", i, f.ShardCount, len(files))
		}
		// A repeated automationDetails.id would make GitHub treat the second
		// shard as REPLACING the first, losing half the alerts silently.
		id := f.Log.Runs[0].AutomationDetails.ID
		if seenAutomationID[id] {
			t.Errorf("file %d: automationDetails.id %q repeats across shards; GitHub would replace, not append", i, id)
		}
		seenAutomationID[id] = true
		total += f.ResultCount
	}

	if total != n {
		t.Errorf("sharding lost results: %d across shards, want %d (shard by run, never truncate)", total, n)
	}
	loss := GitHubLossOf(files)
	if loss == nil {
		t.Fatal("no loss ledger reachable from the projection")
	}
	if loss.TotalDropped() != 0 {
		t.Errorf("nothing should have been dropped, got %d:\n%s", loss.TotalDropped(), loss.Summary())
	}
	if loss.ProjectedResultCount != n || loss.SourceResultCount != n {
		t.Errorf("ledger counts %d source / %d projected, want %d / %d",
			loss.SourceResultCount, loss.ProjectedResultCount, n, n)
	}

	// The greedy count split must fill a shard before opening the next one,
	// so a 25,001-result run is 25,000 + 1 and not two half-full files.
	if files[0].ResultCount != GitHubMaxResultsPerRun {
		t.Errorf("first shard holds %d results, want a full %d", files[0].ResultCount, GitHubMaxResultsPerRun)
	}
}

// TestGitHubDastOnlyExclusionIsCountedNotSilent is the packet's second stop
// condition. It covers BOTH DAST-only shapes: the one with no locations, and
// research/18's endpoint location carrying the `startLine: 1` placeholder —
// which passes contract.go's looser hasPhysicalCodeLocation and would sail
// through a naive filter.
func TestGitHubDastOnlyExclusionIsCountedNotSilent(t *testing.T) {
	log := ghOneRunLog(HalfDast, []Result{
		ghDastResult("dast:endpoint-placeholder"),
		ghDastResultNoLocation("dast:no-location"),
		ghDastResult("dast:endpoint-2"),
	})

	files, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}

	// The loss here is TOTAL. A projection that returned no files at all
	// would take the explanation with it, which is the silent-drop failure
	// this packet exists to prevent.
	if len(files) != 1 {
		t.Fatalf("a fully-dropped run must still yield one file so the ledger is reachable, got %d files", len(files))
	}
	if files[0].ResultCount != 0 {
		t.Fatalf("expected an empty projected run, got %d results", files[0].ResultCount)
	}

	loss := GitHubLossOf(files)
	if loss == nil {
		t.Fatal("no loss ledger reachable")
	}
	if loss.TotalDropped() != 3 {
		t.Fatalf("want 3 dropped results, got %d:\n%s", loss.TotalDropped(), loss.Summary())
	}
	if got := loss.DropCounts[GitHubDropLocationNotRepoRelative]; got != 2 {
		t.Errorf("endpoint-located DAST results dropped: %d, want 2", got)
	}
	if got := loss.DropCounts[GitHubDropNoLocations]; got != 1 {
		t.Errorf("location-free DAST results dropped: %d, want 1", got)
	}

	// "Logged count rather than silently dropped": the finding ids are
	// recoverable, not just a number.
	wantIDs := map[string]bool{"dast:endpoint-placeholder": true, "dast:endpoint-2": true}
	for _, d := range loss.DroppedFor(GitHubDropLocationNotRepoRelative) {
		if !wantIDs[d.FindingID] {
			t.Errorf("unexpected dropped finding id %q", d.FindingID)
		}
		delete(wantIDs, d.FindingID)
		if d.Half != HalfDast {
			t.Errorf("dropped %q recorded half %q, want %q", d.FindingID, d.Half, HalfDast)
		}
		if d.SourceRunIndex != 0 {
			t.Errorf("dropped %q recorded source run %d, want 0", d.FindingID, d.SourceRunIndex)
		}
	}
	if len(wantIDs) != 0 {
		t.Errorf("these dropped findings were never recorded: %v", wantIDs)
	}

	summary := loss.Summary()
	for _, want := range []string{
		string(GitHubDropLocationNotRepoRelative),
		string(GitHubDropNoLocations),
		"3 dropped",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("Summary() omits %q:\n%s", want, summary)
		}
	}
}

// ghOneRunLog builds a minimal single-run log. It is deliberately NOT
// Validate()-clean for every half: several drop-reason cases describe records
// a producer should never emit, and the projection must survive them anyway.
func ghOneRunLog(half Half, results []Result) *SARIFLog {
	sealed := ghTime().Add(time.Hour)
	rp := RunProperties{Half: half, Status: HalfStatusSealed, SealedAt: &sealed}
	if half == HalfDast {
		rp.DastCoverage = ghDastCoverage()
	}
	return &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Properties: AuditProperties{
			SchemaVersion: SchemaVersion,
			AuditID:       ghAuditID,
			State:         StateBothSealed,
			Version:       1,
			CreatedAt:     ghTime(),
			DastStatus:    DastStatusCompletedFindings,
		},
		Runs: []Run{{
			Tool: Tool{Driver: ToolComponent{Name: "anvil-" + string(half), Rules: []ReportingDescriptor{
				{ID: "anvil.sqli.raw-concat"}, {ID: "anvil.dast.sqli"},
			}}},
			AutomationDetails: RunAutomationDetails{ID: "anvil-" + string(half) + "/", CorrelationGUID: ghAuditID},
			Results:           results,
			Properties:        rp,
		}},
	}
}

// ---------------------------------------------------------------------------
// The loss is total and enumerable
// ---------------------------------------------------------------------------

// TestGitHubProjectionEmitsNoUnsupportedBytes asserts on the UPLOAD BYTES,
// not on the Go structs. A zeroed ResultProperties would still marshal to a
// bag of empty `anvil/*` keys, and only a byte search catches that.
func TestGitHubProjectionEmitsNoUnsupportedBytes(t *testing.T) {
	log := ghValidAudit(t)
	if err := log.Validate(); err != nil {
		t.Fatalf("the fixture must be a record a producer could legally emit: %v", err)
	}

	files, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}

	forbidden := []struct{ needle, why string }{
		{"anvil/", "an anvil/* property bag reached the upload"},
		{"webRequest", "SARIF §3.27.14 DAST evidence reached the upload"},
		{"webResponse", "SARIF §3.27.15 DAST evidence reached the upload"},
		{"taxonomies", "taxonomies-as-relationships reached the upload"},
		{"\"taxa\"", "a result taxa reference reached the upload with no taxonomies array to resolve it"},
		{"relationships", "a rule's taxonomy relationship reached the upload"},
		{"provenance", "SARIF §3.48 regression history reached the upload"},
		{"\"fixes\"", "a proposed fix reached the upload (00-SPINE.md S7: propose only)"},
		{"externalPropertyFileReferences", "a reference GitHub will never fetch reached the upload"},
		{ghEndpoint, "an internal hostname was published to GitHub"},
		{PartialFingerprintRegionSHA256, "an unread partial fingerprint reached the upload"},
	}

	for i, f := range files {
		for _, fb := range forbidden {
			if bytes.Contains(f.JSON, []byte(fb.needle)) {
				t.Errorf("file %d (%s): %s — found %q", i, f.Name, fb.why, fb.needle)
			}
		}
		// The gzip must be the gzip OF THE RETURNED JSON: a caller that
		// uploads f.Gzip must be uploading exactly what was measured.
		if got := ghGunzip(t, f.Gzip); !bytes.Equal(got, f.JSON) {
			t.Errorf("file %d: Gzip is not the compression of JSON", i)
		}
	}

	// What DID survive: exactly the one renderable SAST result.
	loss := GitHubLossOf(files)
	if loss.ProjectedResultCount != 1 {
		t.Fatalf("want 1 projected result, got %d:\n%s", loss.ProjectedResultCount, loss.Summary())
	}
	var kept *GitHubResult
	for i := range files {
		if len(files[i].Log.Runs[0].Results) == 1 {
			kept = &files[i].Log.Runs[0].Results[0]
		}
	}
	if kept == nil {
		t.Fatal("the renderable SAST result did not survive the projection")
	}
	if got := kept.PartialFingerprints[PartialFingerprintPrimaryLocationLineHash]; got != ghLineHash {
		t.Errorf("primaryLocationLineHash is %q, want %q — GitHub reads only this key", got, ghLineHash)
	}
	if got := kept.PartialFingerprints[PartialFingerprintAnvilFindingID]; got != ghHash64 {
		t.Errorf("the anvil finding id must survive so an alert traces back to a record finding, got %q", got)
	}
	if len(kept.PartialFingerprints) != 2 {
		t.Errorf("partialFingerprints carries %d keys, want exactly the two identity keys", len(kept.PartialFingerprints))
	}
	if len(kept.RelatedLocations) != 0 {
		t.Errorf("the endpoint relatedLocation must not survive, got %d", len(kept.RelatedLocations))
	}
	// The code flow keeps its repo step and loses its endpoint step.
	if n := countThreadFlowLocations(kept.CodeFlows); n != 1 {
		t.Errorf("code flow kept %d steps, want 1 (the repo step, not the endpoint step)", n)
	}
}

// TestGitHubStripsAreCounted checks the second half of "enumerable": a field
// removed from a result that DID reach GitHub is counted by kind.
func TestGitHubStripsAreCounted(t *testing.T) {
	files, err := ProjectForGitHub(ghValidAudit(t))
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	loss := GitHubLossOf(files)

	want := map[GitHubStripReason]int{
		GitHubStripAuditProperties:                   1,
		GitHubStripRunProperties:                     2,
		GitHubStripRunTaxonomies:                     1,
		GitHubStripDriverTaxa:                        1,
		GitHubStripResultTaxa:                        1,
		GitHubStripRuleRelationships:                 1,
		GitHubStripResultProvenance:                  1,
		GitHubStripResultFixes:                       1,
		GitHubStripResultProperties:                  1,
		GitHubStripPartialFingerprintKey:             1,
		GitHubStripRelatedLocationNotRepoRelative:    1,
		GitHubStripThreadFlowLocationNotRepoRelative: 1,
		GitHubStripUnreferencedRule:                  1,
	}
	for reason, n := range want {
		if got := loss.StripCounts[reason]; got != n {
			t.Errorf("StripCounts[%s] = %d, want %d\n%s", reason, got, n, loss.Summary())
		}
	}
	// webRequest/webResponse belong to results that were DROPPED whole, so
	// they are accounted as a drop and not double-counted as a strip.
	if got := loss.StripCounts[GitHubStripWebResponse]; got != 0 {
		t.Errorf("a dropped result's webResponse was counted twice: strip count %d", got)
	}
	for reason := range loss.StripCounts {
		if !reason.Valid() {
			t.Errorf("ledger carries a strip reason outside the closed vocabulary: %q", reason)
		}
	}
}

// TestGitHubDropReasonTableIsExhaustive drives one minimal record per drop
// reason and then asserts the table covered the whole vocabulary. Adding a
// GitHubDropReason without a case that produces it fails here.
func TestGitHubDropReasonTableIsExhaustive(t *testing.T) {
	base := func(mutate func(*Result)) *SARIFLog {
		r := ghSastResult("sast:probe", "app/db.py", 12)
		mutate(&r)
		return ghOneRunLog(HalfSast, []Result{r})
	}

	// unreadable builds a run that is otherwise perfectly projectable and whose
	// HALF the read gate refuses. It is first in the table because the gate is
	// evaluated first: none of the per-result questions below is worth asking
	// about results a consumer may not read at all.
	unreadable := func(status HalfStatus, state State) *SARIFLog {
		l := ghOneRunLog(HalfSast, []Result{ghSastResult("sast:probe", "app/db.py", 12)})
		l.Runs[0].Properties.Status = status
		if status != HalfStatusSealed {
			l.Runs[0].Properties.SealedAt = nil
		}
		l.Properties.State = state
		return l
	}

	cases := []struct {
		name string
		log  *SARIFLog
		want GitHubDropReason
	}{
		{"half still running", unreadable(HalfStatusRunning, StateCollecting), GitHubDropHalfNotReadable},
		{"half failed", unreadable(HalfStatusFailed, StateCollecting), GitHubDropHalfNotReadable},
		{"audit expired holding a sealed half", unreadable(HalfStatusSealed, StateExpired), GitHubDropHalfNotReadable},
		{"no locations", base(func(r *Result) { r.Locations = nil }), GitHubDropNoLocations},
		{"no physical location", base(func(r *Result) {
			r.Locations = []Location{{LogicalLocations: []LogicalLocation{{FullyQualifiedName: "pkg.fn"}}}}
		}), GitHubDropNoPhysicalLocation},
		{"absolute http uri", base(func(r *Result) {
			r.Locations[0].PhysicalLocation.ArtifactLocation.URI = ghEndpoint
		}), GitHubDropLocationNotRepoRelative},
		{"absolute host path", base(func(r *Result) {
			r.Locations[0].PhysicalLocation.ArtifactLocation.URI = "/etc/nginx/nginx.conf"
		}), GitHubDropLocationNotRepoRelative},
		{"escapes repo root", base(func(r *Result) {
			r.Locations[0].PhysicalLocation.ArtifactLocation.URI = "../outside/db.py"
		}), GitHubDropLocationNotRepoRelative},
		{"no start line", base(func(r *Result) {
			r.Locations[0].PhysicalLocation.Region = nil
		}), GitHubDropNoStartLine},
		{"zero start line", base(func(r *Result) {
			r.Locations[0].PhysicalLocation.Region = &Region{StartLine: 0}
		}), GitHubDropNoStartLine},
		{"missing line hash", base(func(r *Result) {
			delete(r.PartialFingerprints, PartialFingerprintPrimaryLocationLineHash)
		}), GitHubDropNoPrimaryLocationLineHash},
		{"blank line hash", base(func(r *Result) {
			r.PartialFingerprints[PartialFingerprintPrimaryLocationLineHash] = ""
		}), GitHubDropNoPrimaryLocationLineHash},
		{"blank message", base(func(r *Result) { r.Message = Message{Text: "   "} }), GitHubDropNoMessageText},
	}

	covered := map[GitHubDropReason]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files, err := ProjectForGitHub(tc.log)
			if err != nil {
				t.Fatalf("ProjectForGitHub: %v", err)
			}
			loss := GitHubLossOf(files)
			if loss.TotalDropped() != 1 {
				t.Fatalf("want exactly 1 drop, got %d:\n%s", loss.TotalDropped(), loss.Summary())
			}
			if got := loss.DroppedResults[0].Reason; got != tc.want {
				t.Fatalf("drop reason %q, want %q", got, tc.want)
			}
			if !tc.want.Valid() {
				t.Fatalf("%q is outside the closed drop vocabulary", tc.want)
			}
			if tc.want.Explain() == "unknown drop reason" {
				t.Errorf("%q has no explanation; a consumer asking WHY gets nothing", tc.want)
			}
		})
		covered[tc.want] = true
	}

	// GitHubDropExceedsFileSizeCap is produced by the gzip-cap test below;
	// it needs a 10 MB fixture and does not belong in this table.
	covered[GitHubDropExceedsFileSizeCap] = true
	for _, r := range GitHubDropReasonValues() {
		if !covered[r] {
			t.Errorf("drop reason %q is declared but no test produces it", r)
		}
	}
}

// TestGitHubSplitsOnGzipCapAndDropsUnshardableResult crosses the real 10 MB
// gzip boundary with real incompressible bytes.
//
// Two properties are proved at once. A run whose results do not fit is SPLIT
// rather than truncated; and the one case that cannot be split — a single
// result whose own file exceeds the cap — is dropped with a named reason
// instead of being allowed to break the guarantee.
func TestGitHubSplitsOnGzipCapAndDropsUnshardableResult(t *testing.T) {
	// ~13.5 MiB of high-entropy text. gzip's floor on 64-symbol data is
	// 6 bits per byte, so this cannot compress below ~10.1 MiB.
	giant := ghSastResult("sast:giant", "app/giant.py", 1)
	giant.Locations[0].PhysicalLocation.Region.Snippet = &Snippet{Text: ghHighEntropyText(14_200_000)}

	results := []Result{
		ghSastResult("sast:a", "app/a.py", 10),
		giant,
		ghSastResult("sast:b", "app/b.py", 20),
	}
	files, err := ProjectForGitHub(ghOneRunLog(HalfSast, results))
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}

	loss := GitHubLossOf(files)
	if got := loss.DropCounts[GitHubDropExceedsFileSizeCap]; got != 1 {
		t.Fatalf("want the unshardable result dropped once, got %d:\n%s", got, loss.Summary())
	}
	// A drop that happens LATE, during size bisection, must still name the
	// record finding it came from. A count without an identity is not an
	// enumeration.
	dropped := loss.DroppedFor(GitHubDropExceedsFileSizeCap)
	if dropped[0].FindingID != "sast:giant" {
		t.Errorf("size-dropped result recorded finding id %q, want %q", dropped[0].FindingID, "sast:giant")
	}
	if dropped[0].SourceResultIndex != 1 {
		t.Errorf("size-dropped result recorded source index %d, want 1", dropped[0].SourceResultIndex)
	}
	total := 0
	for i, f := range files {
		if err := f.WithinCaps(); err != nil {
			t.Errorf("file %d: %v", i, err)
		}
		if f.GzipBytes > GitHubMaxGzipBytes {
			t.Errorf("file %d: %d gzip bytes exceeds the %d cap", i, f.GzipBytes, GitHubMaxGzipBytes)
		}
		total += f.ResultCount
	}
	if total != 2 {
		t.Errorf("the two small results must survive, got %d", total)
	}
	if loss.ProjectedResultCount != 2 || loss.SourceResultCount != 3 {
		t.Errorf("ledger says %d of %d projected, want 2 of 3", loss.ProjectedResultCount, loss.SourceResultCount)
	}

	// The harder case: the oversized result is the ONLY result, so the run
	// bisects down to nothing. A projection that returned no files here
	// would return no ledger either, and the loss would become invisible at
	// exactly the moment it became total.
	t.Run("only result is unshardable", func(t *testing.T) {
		solo := ghSastResult("sast:solo-giant", "app/giant.py", 1)
		solo.Locations[0].PhysicalLocation.Region.Snippet = giant.Locations[0].PhysicalLocation.Region.Snippet
		files, err := ProjectForGitHub(ghOneRunLog(HalfSast, []Result{solo}))
		if err != nil {
			t.Fatalf("ProjectForGitHub: %v", err)
		}
		if len(files) != 1 || files[0].ResultCount != 0 {
			t.Fatalf("want one empty file carrying the ledger, got %d files", len(files))
		}
		loss := GitHubLossOf(files)
		if loss == nil || loss.DropCounts[GitHubDropExceedsFileSizeCap] != 1 {
			t.Fatalf("the total loss was not recorded: %#v", loss)
		}
		if err := files[0].WithinCaps(); err != nil {
			t.Errorf("the fallback empty file breaks a cap: %v", err)
		}
	})
}

// ghHighEntropyText returns n bytes drawn from a 64-symbol alphabet by a
// deterministic xorshift. Deterministic because a test that sometimes crosses
// a size boundary is not a test; 64 symbols because that is the JSON-safe
// alphabet with the highest entropy per byte, and therefore the cheapest way
// to defeat gzip.
func ghHighEntropyText(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
	b := make([]byte, n)
	x := uint64(0x9E3779B97F4A7C15)
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = alphabet[x&63]
	}
	return string(b)
}

func ghGunzip(t *testing.T, gz []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------------
// Structural guarantees
// ---------------------------------------------------------------------------

// TestGitHubProjectedTypesHaveNoPropertiesMember proves the anvil/* bag
// cannot be emitted, independently of any fixture. The byte test above can
// only catch a bag a fixture happened to populate; this catches the type.
func TestGitHubProjectedTypesHaveNoPropertiesMember(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(GitHubSARIFLog{}),
		reflect.TypeOf(GitHubRun{}),
		reflect.TypeOf(GitHubResult{}),
		reflect.TypeOf(GitHubLocation{}),
		reflect.TypeOf(GitHubCodeFlow{}),
		reflect.TypeOf(GitHubThreadFlow{}),
		reflect.TypeOf(GitHubThreadFlowLocation{}),
	}
	for _, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "properties" || f.Name == "Properties" {
				t.Errorf("%s.%s is a properties member; a projected type must have none, "+
					"or an anvil/* bag can reach GitHub", typ.Name(), f.Name)
			}
		}
	}
}

// TestGitHubCapsMatchTheDocumentedNumbers pins every cap to the value
// research/18 quotes from GitHub's documentation [S2]. GitHub's limits "can
// change without notice"; when they do, this test is the one place that has
// to be edited, and it fails loudly rather than letting a silently-edited
// constant ship.
func TestGitHubCapsMatchTheDocumentedNumbers(t *testing.T) {
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"results per run", GitHubMaxResultsPerRun, 25000},
		{"displayed results per run", GitHubDisplayedResultsPerRun, 5000},
		{"runs per file", GitHubMaxRunsPerFile, 20},
		{"gzip bytes per file", GitHubMaxGzipBytes, 10 * 1024 * 1024},
		{"rules per run", GitHubMaxRulesPerRun, 25000},
		{"tool extensions per run", GitHubMaxToolExtensionsPerRun, 100},
		{"locations per result", GitHubMaxLocationsPerResult, 1000},
		{"thread-flow locations per result", GitHubMaxThreadFlowLocationsPerResult, 10000},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want GitHub's documented %d", c.name, c.got, c.want)
		}
	}
	if GitHubRunsPerProjectedFile > GitHubMaxRunsPerFile {
		t.Errorf("Anvil's own shard policy (%d runs/file) exceeds GitHub's limit (%d)",
			GitHubRunsPerProjectedFile, GitHubMaxRunsPerFile)
	}
}

// TestGitHubPinsSarifVersion: GitHub supports SARIF 2.1.0 only, and the
// projection must not track the unratified 2.2 draft.
func TestGitHubPinsSarifVersion(t *testing.T) {
	files, err := ProjectForGitHub(ghValidAudit(t))
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	for i, f := range files {
		if f.Log.Version != SARIFVersion {
			t.Errorf("file %d: version %q, want %q", i, f.Log.Version, SARIFVersion)
		}
		if f.Log.Schema != SARIFSchemaURI {
			t.Errorf("file %d: $schema %q, want %q", i, f.Log.Schema, SARIFSchemaURI)
		}
	}
}

// TestGitHubRuleIndexIsRemappedNotStale: filtering rules invalidates every
// source ruleIndex. A stale index does not fail loudly — it names a DIFFERENT
// rule, so GitHub renders the wrong description on the alert.
func TestGitHubRuleIndexIsRemappedNotStale(t *testing.T) {
	// Two rules, the referenced one second, so a copied index would point at
	// the wrong rule and a dropped index would point at nothing.
	log := ghOneRunLog(HalfSast, []Result{ghSastResult("sast:1", "app/db.py", 5)})
	log.Runs[0].Tool.Driver.Rules = []ReportingDescriptor{
		{ID: "anvil.unused.rule"},
		{ID: "anvil.sqli.raw-concat"},
	}
	log.Runs[0].Results[0].RuleIndex = ghPtrInt(1)

	files, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	run := files[0].Log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("want only the referenced rule emitted, got %d", len(run.Tool.Driver.Rules))
	}
	res := run.Results[0]
	if res.RuleIndex == nil {
		t.Fatal("ruleIndex was dropped; the alert loses its rule metadata link")
	}
	if got := *res.RuleIndex; got != 0 {
		t.Fatalf("ruleIndex = %d, want 0 after re-indexing", got)
	}
	if run.Tool.Driver.Rules[*res.RuleIndex].ID != res.RuleID {
		t.Fatalf("ruleIndex %d names rule %q but the result's ruleId is %q",
			*res.RuleIndex, run.Tool.Driver.Rules[*res.RuleIndex].ID, res.RuleID)
	}
}

// TestGitHubProjectionIsDeterministic: two projections of one record must be
// byte-identical. An upload that changes shape between runs makes GitHub's
// de-duplication unreliable no matter what the fingerprints say.
func TestGitHubProjectionIsDeterministic(t *testing.T) {
	log := ghValidAudit(t)
	a, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	b, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("file counts differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			t.Errorf("file %d name differs: %q vs %q", i, a[i].Name, b[i].Name)
		}
		if !bytes.Equal(a[i].JSON, b[i].JSON) {
			t.Errorf("file %d JSON differs between identical projections", i)
		}
	}
	if GitHubLossOf(a).Summary() != GitHubLossOf(b).Summary() {
		t.Error("loss Summary() differs between identical projections; map order reached the output")
	}
	// The ledger must survive a round trip, since the intended use is to
	// persist it next to the upload.
	raw, err := json.Marshal(GitHubLossOf(a))
	if err != nil {
		t.Fatalf("marshal ledger: %v", err)
	}
	var back GitHubProjectionLoss
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ledger: %v", err)
	}
	if back.TotalDropped() != GitHubLossOf(a).TotalDropped() {
		t.Errorf("ledger round trip lost drops: %d vs %d", back.TotalDropped(), GitHubLossOf(a).TotalDropped())
	}
}

// TestGitHubLedgerReconciles: source == projected + dropped, on every fixture
// in this file. This is the arithmetic that makes "the loss is total" a
// checkable claim rather than a comment.
func TestGitHubLedgerReconciles(t *testing.T) {
	logs := map[string]*SARIFLog{
		"valid audit": ghValidAudit(t),
		"dast only":   ghOneRunLog(HalfDast, []Result{ghDastResult("d1"), ghDastResultNoLocation("d2")}),
		"sast only":   ghOneRunLog(HalfSast, []Result{ghSastResult("s1", "a.py", 1), ghSastResult("s2", "b.py", 2)}),
		"empty run":   ghOneRunLog(HalfSast, nil),
	}
	for name, log := range logs {
		t.Run(name, func(t *testing.T) {
			files, err := ProjectForGitHub(log)
			if err != nil {
				t.Fatalf("ProjectForGitHub: %v", err)
			}
			loss := GitHubLossOf(files)
			if got := loss.ProjectedResultCount + loss.TotalDropped(); got != loss.SourceResultCount {
				t.Errorf("%d projected + %d dropped = %d, want %d source results\n%s",
					loss.ProjectedResultCount, loss.TotalDropped(), got, loss.SourceResultCount, loss.Summary())
			}
			if loss.AuditID != ghAuditID {
				t.Errorf("ledger audit id %q, want %q", loss.AuditID, ghAuditID)
			}
			// Every run contributes at least one file, so the ledger is
			// always reachable.
			if len(files) < len(log.Runs) {
				t.Errorf("%d files for %d source runs; a run with no surviving results still owes a file",
					len(files), len(log.Runs))
			}
			for i := range files {
				if files[i].Loss != loss {
					t.Errorf("file %d points at a different ledger; the ledger is whole-projection", i)
				}
			}
		})
	}
}

// TestIsRepoRelativeURI pins the predicate that decides what GitHub can
// render. It is stricter than contract.go's hasPhysicalCodeLocation on
// purpose — see the header of sarif_github.go.
func TestIsRepoRelativeURI(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"app/db.py", true},
		{"src/main/java/com/x/Y.java", true},
		{"file.go", true},
		{"a..b/c.go", true},
		{"", false},
		{"/etc/passwd", false},
		{`\windows\system32\x.dll`, false},
		{"https://staging.payments.internal/api/login", false},
		{"http://x/y", false},
		{"file:///tmp/x", false},
		{"C:/Users/x/y.go", false},
		{"../outside.py", false},
		{"a/../../b.py", false},
	}
	for _, c := range cases {
		if got := isRepoRelativeURI(c.uri); got != c.want {
			t.Errorf("isRepoRelativeURI(%q) = %v, want %v", c.uri, got, c.want)
		}
	}
}

// TestGitHubShardAutomationIDsAreDistinct pins the id derivation, because the
// failure it prevents is silent: GitHub keys an analysis on
// automationDetails.id, and a duplicate makes the second upload replace the
// first.
func TestGitHubShardAutomationIDsAreDistinct(t *testing.T) {
	cases := []struct {
		id    string
		shard int
		want  string
	}{
		{"anvil/sast/", 2, "anvil/sast/shard-002/"},
		{"anvil/sast", 3, "anvil/sast/shard-003/"},
		{"", 2, "shard-002/"},
	}
	for _, c := range cases {
		if got := shardAutomationID(c.id, c.shard); got != c.want {
			t.Errorf("shardAutomationID(%q, %d) = %q, want %q", c.id, c.shard, got, c.want)
		}
	}
}

// TestGitHubNilRecordIsAnError: a nil record is a caller bug, not an empty
// projection. Returning "no files, no error" would read as "nothing to
// upload".
func TestGitHubNilRecordIsAnError(t *testing.T) {
	if _, err := ProjectForGitHub(nil); err == nil {
		t.Fatal("want an error for a nil record")
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 B1 — the read gate reaches the most externally visible consumer
// ---------------------------------------------------------------------------

// TestGitHubNeverPublishesAnUnreadableHalf is the regression test for the
// blocker: ProjectForGitHub consulted no read gate at all, so a half at
// `running`, `failed`, `timed_out` or `skipped` — and a cleanly sealed half in
// an EXPIRED audit — projected its results to GitHub code scanning
// unconditionally, with the loss ledger recording zero drops in every case.
//
// The consequences are ordered in CRITIQUE-03 §6 B1 and the worst is not the
// first: because GitHub keys an analysis on `runAutomationDetails.id`, a
// premature upload of a `running` half is REPLACED by the real upload after
// the seal, so the visible alert set silently depends on upload order.
func TestGitHubNeverPublishesAnUnreadableHalf(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status HalfStatus
		state  State
	}{
		{"running", HalfStatusRunning, StateCollecting},
		{"failed", HalfStatusFailed, StateCollecting},
		{"timed_out", HalfStatusTimedOut, StateCollecting},
		{"skipped", HalfStatusSkipped, StateCollecting},
		{"sealed but the audit expired", HalfStatusSealed, StateExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := ghOneRunLog(HalfSast, []Result{
				ghSastResult("sast:1", "app/db.py", 414),
				ghSastResult("sast:2", "app/routes.py", 88),
			})
			log.Runs[0].Properties.Status = tc.status
			if tc.status != HalfStatusSealed {
				log.Runs[0].Properties.SealedAt = nil
			}
			log.Properties.State = tc.state

			files, err := ProjectForGitHub(log)
			if err != nil {
				t.Fatalf("ProjectForGitHub: %v", err)
			}

			// Nothing is published, and the projected BYTES are searched, not
			// just the counts: a result that survived into Log.Runs would
			// still reach GitHub even if ResultCount were reported as zero.
			for i, f := range files {
				if f.ResultCount != 0 {
					t.Errorf("file %d carries %d results from a half whose status is %q and audit state %q",
						i, f.ResultCount, tc.status, tc.state)
				}
				if bytes.Contains(f.JSON, []byte("app/db.py")) {
					t.Errorf("file %d publishes a source path from an unreadable half", i)
				}
			}

			// The loss is COUNTABLE. A withheld result that is not ledgered is
			// a silent drop, and the ledger is the entire mechanism by which
			// R.14 answers research/18 Risk #6.
			loss := GitHubLossOf(files)
			if loss == nil {
				t.Fatal("a fully-withheld projection must still carry a reachable ledger")
			}
			if got := loss.DropCounts[GitHubDropHalfNotReadable]; got != 2 {
				t.Errorf("DropCounts[%s] = %d, want 2\n%s", GitHubDropHalfNotReadable, got, loss.Summary())
			}
			for _, d := range loss.DroppedFor(GitHubDropHalfNotReadable) {
				if d.FindingID == "" {
					t.Error("a withheld result was ledgered with no finding id; a count without an identity is not an enumeration")
				}
				if d.HalfStatus != tc.status || d.AuditState != tc.state {
					t.Errorf("ledger entry for %q records status %q / state %q, want %q / %q",
						d.FindingID, d.HalfStatus, d.AuditState, tc.status, tc.state)
				}
			}
			if !strings.Contains(loss.Summary(), string(GitHubDropHalfNotReadable)) {
				t.Errorf("Summary() does not name the refusal:\n%s", loss.Summary())
			}
		})
	}
}

// The projection and readpath.go must agree about which halves are readable.
// Two gates would be two answers, which is the shape CRITIQUE-02 F6 recorded
// and CRITIQUE-03 found twice more.
func TestGitHubReadGateAgreesWithTheReadPath(t *testing.T) {
	for _, status := range HalfStatusValues() {
		for _, state := range StateValues() {
			log := ghOneRunLog(HalfSast, []Result{ghSastResult("sast:1", "app/db.py", 414)})
			log.Runs[0].Properties.Status = status
			if status != HalfStatusSealed {
				log.Runs[0].Properties.SealedAt = nil
			}
			log.Properties.State = state

			files, err := ProjectForGitHub(log)
			if err != nil {
				t.Fatalf("status %q state %q: %v", status, state, err)
			}
			published := 0
			for _, f := range files {
				published += f.ResultCount
			}
			readable := halfSealOfRun(log, &log.Runs[0]).Readable()
			if (published > 0) != readable {
				t.Errorf("status %q state %q: the projection published %d results but the read gate says readable=%t",
					status, state, published, readable)
			}
		}
	}
}

// Masking is a precondition here for the same reason it is one on the Reader:
// this projection strips every surface MaskRecord covers, so its safety rests
// entirely on that strip list staying exhaustive.
func TestGitHubRefusesAnUnmaskedRecord(t *testing.T) {
	r := ghSastResult("sast:1", "app/db.py", 414)
	r.WebRequest = &WebRequest{
		Method: "POST", Target: ghEndpoint,
		Headers: map[string]string{"Authorization": "Bearer sk-live-0123456789abcdefghij"},
	}
	log := ghOneRunLog(HalfSast, []Result{r})

	if _, err := ProjectForGitHub(log); err == nil {
		t.Fatal("an unmasked record must be refused, not projected")
	}
	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	if _, err := ProjectForGitHub(log); err != nil {
		t.Fatalf("the same record, masked, must project: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 M2 — the rule ledger counts against the shard set
// ---------------------------------------------------------------------------

// A rule referenced only by shard 2 used to be tallied as "stripped" while
// shard 1 was built, so the count scaled with shard count and could exceed the
// number of rules that exist. The ledger's own stated principle is that
// over-reporting loss is as untrustworthy as under-reporting it.
func TestGitHubUnreferencedRuleCountIsAgainstTheShardSetNotPerShard(t *testing.T) {
	const n = GitHubMaxResultsPerRun + 10

	results := make([]Result, 0, n)
	for i := 0; i < n; i++ {
		r := ghSastResult(fmt.Sprintf("sast:%d", i), fmt.Sprintf("app/pkg%d/file%d.py", i%64, i), (i%900)+1)
		// rule.0 is referenced only by the first (full) shard; rule.3 only by
		// the overflow shard. rule.1 and rule.2 are referenced by nothing and
		// are the only rules genuinely lost.
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
		t.Fatalf("the fixture must shard to exercise the defect, got %d files", len(files))
	}

	delivered := map[string]bool{}
	for _, f := range files {
		for _, run := range f.Log.Runs {
			for _, rule := range run.Tool.Driver.Rules {
				delivered[rule.ID] = true
			}
		}
	}
	if !delivered["rule.0"] || !delivered["rule.3"] {
		t.Fatalf("both referenced rules must reach GitHub across the shard set, delivered=%v", delivered)
	}

	loss := GitHubLossOf(files)
	if got := loss.StripCounts[GitHubStripUnreferencedRule]; got != 2 {
		t.Errorf("StripCounts[%s] = %d, want 2 (rule.1 and rule.2); "+
			"a rule delivered in ANY shard is not lost, and a count that exceeds the "+
			"%d rules in the source run cannot be a count of anything real\n%s",
			GitHubStripUnreferencedRule, got, len(log.Runs[0].Tool.Driver.Rules), loss.Summary())
	}
	if got := loss.StripCounts[GitHubStripUnreferencedRule]; got > len(log.Runs[0].Tool.Driver.Rules) {
		t.Errorf("the ledger reports more lost rules (%d) than the run has (%d)",
			got, len(log.Runs[0].Tool.Driver.Rules))
	}
}

// A relationship on one source descriptor is one loss however many shards
// carry that rule — the same per-shard inflation, one field over.
func TestGitHubRuleRelationshipsAreCountedOncePerSourceRule(t *testing.T) {
	const n = GitHubMaxResultsPerRun + 5
	results := make([]Result, 0, n)
	for i := 0; i < n; i++ {
		results = append(results, ghSastResult(
			fmt.Sprintf("sast:%d", i), fmt.Sprintf("app/pkg%d/file%d.py", i%64, i), (i%900)+1))
	}
	log := ghOneRunLog(HalfSast, results)
	log.Runs[0].Tool.Driver.Rules = []ReportingDescriptor{{
		ID:            "anvil.sqli.raw-concat",
		Relationships: []ReportingDescriptorRelationship{{Target: ReportingDescriptorReference{ID: "89"}}},
	}}

	files, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("the fixture must shard to exercise the defect, got %d files", len(files))
	}
	if got := GitHubLossOf(files).StripCounts[GitHubStripRuleRelationships]; got != 1 {
		t.Errorf("StripCounts[%s] = %d across %d shards, want 1: one source descriptor, one loss",
			GitHubStripRuleRelationships, got, len(files))
	}
}

// The one drop this file used to make silently: a second descriptor for a rule
// id already emitted.
func TestGitHubDuplicateRuleDescriptorIsCounted(t *testing.T) {
	log := ghOneRunLog(HalfSast, []Result{ghSastResult("sast:1", "app/db.py", 414)})
	log.Runs[0].Tool.Driver.Rules = []ReportingDescriptor{
		{ID: "anvil.sqli.raw-concat", ShortDescription: &Message{Text: "first"}},
		{ID: "anvil.sqli.raw-concat", ShortDescription: &Message{Text: "duplicate"}},
	}

	files, err := ProjectForGitHub(log)
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}
	if got := GitHubLossOf(files).StripCounts[GitHubStripDuplicateRule]; got != 1 {
		t.Errorf("StripCounts[%s] = %d, want 1; a duplicate descriptor cannot be carried "+
			"and must not be dropped in silence", GitHubStripDuplicateRule, got)
	}
	for _, f := range files {
		for _, run := range f.Log.Runs {
			if n := len(run.Tool.Driver.Rules); n != 1 {
				t.Errorf("a shard emitted %d descriptors for one rule id", n)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 M4 — relatedLocations count against the locations cap
// ---------------------------------------------------------------------------

// `locations` was truncated at GitHubMaxLocationsPerResult and
// `relatedLocations` was appended without limit, so a fan-out finding shipped
// four times the cap. Neither reading of [S2] makes an asymmetry correct: if
// related locations count, this was a cap violation; if they do not, the file
// applied a documented cap to one of two arrays with nothing explaining why.
func TestGitHubRelatedLocationsCountAgainstTheLocationsCap(t *testing.T) {
	const fanOut = 3000

	r := ghSastResult("sast:fanout", "app/db.py", 1)
	for i := 0; i < fanOut; i++ {
		loc := Location{PhysicalLocation: &PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: fmt.Sprintf("app/gen/f%04d.py", i)},
			Region:           &Region{StartLine: i + 1},
		}}
		r.Locations = append(r.Locations, loc)
		r.RelatedLocations = append(r.RelatedLocations, loc)
	}

	files, err := ProjectForGitHub(ghOneRunLog(HalfSast, []Result{r}))
	if err != nil {
		t.Fatalf("ProjectForGitHub: %v", err)
	}

	var kept *GitHubResult
	for i := range files {
		for j := range files[i].Log.Runs[0].Results {
			kept = &files[i].Log.Runs[0].Results[j]
		}
	}
	if kept == nil {
		t.Fatal("the fan-out result did not survive the projection")
	}

	total := len(kept.Locations) + len(kept.RelatedLocations)
	t.Logf("locations=%d relatedLocations=%d total=%d cap=%d",
		len(kept.Locations), len(kept.RelatedLocations), total, GitHubMaxLocationsPerResult)
	if total > GitHubMaxLocationsPerResult {
		t.Errorf("the result carries %d locations across both arrays, over the %d cap",
			total, GitHubMaxLocationsPerResult)
	}
	// `locations` fills first: locations[0] is the primary and the whole
	// projection's identity story rests on it.
	if len(kept.Locations) != GitHubMaxLocationsPerResult {
		t.Errorf("locations = %d, want the cap filled from locations first (%d)",
			len(kept.Locations), GitHubMaxLocationsPerResult)
	}
	if len(kept.RelatedLocations) != 0 {
		t.Errorf("relatedLocations = %d, want 0 once locations has taken the whole cap",
			len(kept.RelatedLocations))
	}

	// The truncation is counted, not silent.
	want := (1 + fanOut - GitHubMaxLocationsPerResult) + fanOut
	if got := GitHubLossOf(files).StripCounts[GitHubStripLocationsOverCap]; got != want {
		t.Errorf("StripCounts[%s] = %d, want %d (%d over the cap in locations, %d in relatedLocations)",
			GitHubStripLocationsOverCap, got, want, 1+fanOut-GitHubMaxLocationsPerResult, fanOut)
	}

	// WithinCaps must ask the same question the builder answered, or the
	// independent check certifies a narrower guarantee than the file promises.
	over := GitHubSarifFile{
		Name: "probe",
		Log: GitHubSARIFLog{Runs: []GitHubRun{{Results: []GitHubResult{{
			Locations:        make([]GitHubLocation, GitHubMaxLocationsPerResult),
			RelatedLocations: make([]GitHubLocation, 1),
		}}}}},
	}
	if err := over.WithinCaps(); err == nil {
		t.Errorf("WithinCaps accepted %d locations + %d relatedLocations against a %d cap",
			GitHubMaxLocationsPerResult, 1, GitHubMaxLocationsPerResult)
	}
}
