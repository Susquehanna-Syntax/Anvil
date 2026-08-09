package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixture
//
// One realistic record: a correlated cluster (one SAST + one DAST finding),
// several SAST-only findings including an SCA finding and a HOST finding, and
// one DAST-only finding. That is exactly R.13's stop condition.
//
// The fixture is built, then VALIDATED against contract.go, then MASKED by
// R.8. Both steps are deliberate: a fixture that could not survive the
// producer's own gates would prove nothing about the read path, and the read
// path refuses an unmasked record by design.
// ---------------------------------------------------------------------------

const (
	rpAuditID   = "0198e2c1-6a4b-7d3e-9f10-2b7c5d8a4e11"
	rpClusterID = "9f2c7a10-4e88-4d1b-b6c2-1a5f77e40d3e"
)

func rpDigest(seed byte) string {
	b := make([]byte, FingerprintDigestHexLen)
	const hex = "0123456789abcdef"
	for i := range b {
		b[i] = hex[(int(seed)+i*7)%16]
	}
	return string(b)
}

func rpFloat(f float64) *float64 { return &f }

func rpTime() time.Time { return time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC) }

// rpSastResult is the common shape of a static finding.
func rpSastResult(id string, rank float64, ec EvidenceClass, v Verdict, remediable bool, path string, seed byte) Result {
	return Result{
		RuleID: "anvil.sql-injection",
		Kind:   KindFail,
		Level:  LevelError,
		Rank:   rpFloat(rank),
		Message: Message{Text: fmt.Sprintf(
			"Fix the tainted value reaching the sink in %s and keep the existing behaviour.", path)},
		Locations: []Location{{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: path},
				Region: &Region{
					StartLine: 412, EndLine: 414,
					Snippet: &Snippet{Text: "    query = \"SELECT id FROM users WHERE name = '\" + username + \"'\"\n    cur.execute(query)"},
				},
				ContextRegion: &Region{
					StartLine: 404, EndLine: 421,
					Snippet: &Snippet{Text: "def authenticate(conn, username, password):\n    ...\n    return None"},
				},
			},
			LogicalLocations: []LogicalLocation{{FullyQualifiedName: "app.db.authenticate", Kind: "function"}},
		}},
		Taxa: []ReportingDescriptorReference{{ID: "CWE-89"}},
		PartialFingerprints: map[string]string{
			PartialFingerprintAnvilFindingID:          rpDigest(seed),
			PartialFingerprintPrimaryLocationLineHash: "7a1c9e0b4d2f6813",
		},
		Properties: ResultProperties{
			FindingID:         id,
			Half:              HalfSast,
			Confidence:        0.88,
			Verdict:           v,
			RemediableByAgent: remediable,
			Reasoning:         "The username parameter reaches execute() by string concatenation with no parameterisation.",
			Detector: DetectorRef{
				Kind: DetectorKindSast, Model: "anvil-sast", Revision: "2026.07.1",
			},
			EvidenceClass: ec,
			Trust:         TrustAssertion{Default: TrustUntrusted},
			Locus:         &Locus{ProximityClass: "same_symbol"},
			PatchContext: &PatchContext{
				Language: "python3.12", Framework: "flask", DBDriver: "sqlite3",
				EditableFiles: []string{path},
				TestCommand:   "pytest tests/test_db.py -k authenticate",
			},
		},
	}
}

// rpFixtureLog builds the base record. It is deliberately NOT masked or
// validated here: rpFixture does both, and a few tests need a record that
// fails one of them.
func rpFixtureLog() *SARIFLog {
	created := rpTime()
	sealed := created.Add(20 * time.Minute)

	s1 := rpSastResult("sast:0001", 97.0, EvidenceClassSastReachable, VerdictTruePositive, true, "app/db.py", 1)
	s1.CorrelationGUID = rpClusterID
	s1.CodeFlows = []CodeFlow{{ThreadFlows: []ThreadFlow{{Locations: []ThreadFlowLocation{
		{Location: Location{PhysicalLocation: &PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "app/routes.py"},
			Region:           &Region{StartLine: 91, Snippet: &Snippet{Text: "username = request.json[\"username\"]"}},
		}}},
		{Location: Location{PhysicalLocation: &PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "app/db.py"},
			Region:           &Region{StartLine: 414, Snippet: &Snippet{Text: "cur.execute(query)"}},
		}}},
	}}}}}
	s1.Properties.Correlation = &Correlation{
		ClusterID: rpClusterID, Role: HalfSast, Peers: []string{"dast:0101"},
		Signals: []SignalWeight{
			{Name: CorrelationSignalResponseStackTrace, Weight: 0.7, Detail: "stack trace names app/db.py:414"},
			{Name: CorrelationSignalParameterName, Weight: 0.24, Detail: "username"},
		},
		Confidence: 0.94, Verified: true,
		VerificationMethod: "response stack trace inside the static region",
	}
	s1.Properties.Advisory = &AdvisoryContext{
		IDs: []string{"CWE-89"}, SourceFeed: "cwe", SnapshotDigest: "sha256:aa",
		AsOf: created.Add(-48 * time.Hour), StalenessSeconds: 172800,
		Excerpt: &TrustedString{
			Text:  "Use a parameterised query; sqlite3 accepts a params tuple as execute()'s second argument.",
			Trust: TrustUntrusted,
		},
	}

	s2 := rpSastResult("sast:0002", 61.0, EvidenceClassSastReachable, VerdictTruePositive, true, "app/routes.py", 2)
	s3 := rpSastResult("sast:0003", 40.0, EvidenceClassSastStaticOnly, VerdictInsufficientContext, true, "app/util.py", 3)
	s4 := rpSastResult("sast:0004", 40.0, EvidenceClassSastStaticOnly, VerdictTruePositive, true, "app/view.py", 4)
	s7 := rpSastResult("sast:0007", 20.0, EvidenceClassSastStaticOnly, VerdictFalsePositive, true, "app/old.py", 7)

	sca := rpSastResult("sca:0005", 55.0, EvidenceClassSCA, VerdictTruePositive, true, "pom.xml", 5)
	sca.RuleID = "anvil.vulnerable-dependency"
	sca.Properties.Detector.Kind = DetectorKindSCA
	sca.Properties.Risk = &Risk{
		CvssV4Base: rpFloat(10.0), EpssScore: rpFloat(0.97), EpssPercentile: rpFloat(0.999),
		KevMember: true, KevRansomwareUse: true,
	}

	// The HOST finding. remediable_by_agent is false and must stay false:
	// 00-SPINE.md S7 makes the host agent read-only.
	host := rpSastResult("host:0006", 30.0, EvidenceClassHost, VerdictTruePositive, false, "", 6)
	host.RuleID = "anvil.host-package"
	host.Locations = nil
	host.Taxa = nil
	host.CodeFlows = nil
	host.Properties.Detector.Kind = DetectorKindHost
	host.Properties.PatchContext = nil
	host.Properties.Locus = nil
	delete(host.PartialFingerprints, PartialFingerprintPrimaryLocationLineHash)

	d1 := rpDastResult("dast:0101", 97.0, 101)
	d1.CorrelationGUID = rpClusterID
	d1.Properties.Correlation = &Correlation{
		ClusterID: rpClusterID, Role: HalfDast, Peers: []string{"sast:0001"},
		Signals: []SignalWeight{
			{Name: CorrelationSignalResponseStackTrace, Weight: 0.7},
			{Name: CorrelationSignalRouteTable, Weight: 0.24},
		},
		Confidence: 0.94, Verified: true,
	}
	d2 := rpDastResult("dast:0102", 70.0, 102)

	sastRun := Run{
		Tool: Tool{Driver: ToolComponent{
			Name: "anvil-sast", Version: "2026.07.1",
			Rules: []ReportingDescriptor{{
				ID: "anvil.sql-injection", Name: "SqlInjection",
				ShortDescription: &Message{Text: "Tainted input reaches a SQL sink."},
				HelpURI:          "https://cwe.mitre.org/data/definitions/89.html",
			}},
		}},
		AutomationDetails: RunAutomationDetails{ID: "sast/1", CorrelationGUID: rpAuditID},
		Results:           []Result{s1, s2, s3, s4, sca, host, s7},
		Properties: RunProperties{
			Half: HalfSast, Status: HalfStatusSealed, SealedAt: &sealed,
			AdvisorySnapshot: &AdvisorySnapshot{
				FeedIDs: []string{"cwe"}, SnapshotDigest: "sha256:aa", ScrapedAt: created,
			},
		},
	}

	dastSealed := created.Add(35 * time.Minute)
	dastRun := Run{
		Tool:              Tool{Driver: ToolComponent{Name: "anvil-dast", Version: "2026.07.1"}},
		AutomationDetails: RunAutomationDetails{ID: "dast/1", CorrelationGUID: rpAuditID},
		Results:           []Result{d1, d2},
		Properties: RunProperties{
			Half: HalfDast, Status: HalfStatusSealed, SealedAt: &dastSealed,
			RouteTableDigest: "sha256:7de1a0",
			RuntimeTarget: &RuntimeTarget{
				BaseURL: "https://staging.payments.internal", AuthProfileRef: "anvil.dast.yaml@a91c3f2",
				Scope: []string{"/api/**"}, Excluded: []string{"/api/admin/**"},
			},
			DastCoverage: &DastCoverage{
				ProbedCount: 31, InventoryUnionCount: 50, EndpointCoverage: 0.62,
				InventoryProvenanceMix: map[InventoryProvenance]int{
					InventoryProvenanceRuntimeSpec: 40, InventoryProvenanceCrawl: 10,
				},
				ConfirmedCount: 40, CandidateCount: 10,
			},
		},
	}

	return &SARIFLog{
		Schema: SARIFSchemaURI, Version: SARIFVersion,
		Runs: []Run{sastRun, dastRun},
		Properties: AuditProperties{
			SchemaVersion: SchemaVersion,
			AuditID:       rpAuditID,
			State:         StateBothSealed,
			Version:       1,
			CreatedAt:     created,
			Target: Target{
				RepoURL: "https://github.com/example/payments", Ref: "refs/heads/main",
				Commit: "3f2a1c0d", RuntimeBaseURL: "https://staging.payments.internal",
				Provenance: TargetProvenanceBootedClean, Provisioning: TargetProvisioningEphemeralManifest,
			},
			Trigger: Trigger{
				Kind: "push", PolicyID: "p-1", PolicyRef: "anvil.yaml@a91c3f2",
				ConfigSource: "repo", Actor: "ci", ResolvedAt: created,
			},
			Deadline: Deadline{
				DeadlineAt:          created.Add(DefaultClaimTimeoutSeconds * time.Second),
				ClaimTimeoutSeconds: DefaultClaimTimeoutSeconds,
			},
			Index:      Index{ReadOrder: DefaultReadOrder()},
			DastStatus: DastStatusCompletedFindings,
		},
	}
}

func rpDastResult(id string, rank float64, seed byte) Result {
	return Result{
		RuleID:  "anvil.sqli-error-based",
		Kind:    KindFail,
		Level:   LevelError,
		Rank:    rpFloat(rank),
		Message: Message{Text: "POST /api/login returns 500 with a database error for a quote payload."},
		Taxa:    []ReportingDescriptorReference{{ID: "CWE-89"}},
		WebRequest: &WebRequest{
			Method: "POST", Target: "https://staging.payments.internal/api/login",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    &ArtifactContent{Text: `{"username":"' OR '1'='1' -- ","password":"x"}`},
		},
		WebResponse: &WebResponse{
			StatusCode: 500, ReasonPhrase: "Internal Server Error",
			Headers: map[string]string{"Content-Type": "text/html"},
			Body:    &ArtifactContent{Text: "<pre>sqlite3.OperationalError: unrecognized token</pre>"},
		},
		PartialFingerprints: map[string]string{PartialFingerprintAnvilFindingID: rpDigest(seed)},
		Properties: ResultProperties{
			FindingID:         id,
			Half:              HalfDast,
			Confidence:        0.97,
			Verdict:           VerdictTruePositive,
			RemediableByAgent: true,
			Reasoning:         "A quote in the username flips the response from 401 to 500 with a driver error.",
			Detector:          DetectorRef{Kind: DetectorKindDast, Model: "anvil-dast", Revision: "2026.07.1"},
			EvidenceClass:     EvidenceClassDastConfirmed,
			Trust:             TrustAssertion{Default: TrustUntrusted},
			Repro: &Repro{
				Curl:            "curl -sS -X POST https://staging.payments.internal/api/login -H 'Content-Type: application/json' --data-raw '{}'",
				InjectionPoint:  ReproInjection{Kind: InjectionPointBody, Name: "username"},
				Payload:         "' OR '1'='1' -- ",
				PayloadEncoding: "utf8",
				Baseline:        &ReproBaseline{StatusCode: 401, LatencyMs: 12},
				ObservedSignal: ReproSignal{
					Kind:       EvidenceSignalDBErrorString,
					Match:      &TrustedString{Text: "sqlite3.OperationalError: unrecognized token", Trust: TrustUntrusted},
					BodySha256: "sha256:5c0d",
				},
				ExpectedAfterFix: &ReproExpectation{
					StatusCode: 401, MustNotContain: []string{"OperationalError", "Traceback"},
				},
				Env: ReproEnv{Sanitizers: []string{}, AslrEnabled: true, Arch: "amd64", OS: "linux"},
			},
		},
	}
}

// rpFixture builds, validates and masks the fixture. mutate runs before both
// gates so a test can shape the record and still get the real pipeline.
func rpFixture(t *testing.T, mutate func(*SARIFLog)) *SARIFLog {
	t.Helper()
	l := rpFixtureLog()
	if mutate != nil {
		mutate(l)
	}
	if err := l.Validate(); err != nil {
		t.Fatalf("fixture does not satisfy contract.go's own validator: %v", err)
	}
	if err := MaskRecord(l); err != nil {
		t.Fatalf("masking the fixture failed: %v", err)
	}
	if err := AssertMasked(l); err != nil {
		t.Fatalf("fixture is not masked after MaskRecord: %v", err)
	}
	return l
}

func rpReader(t *testing.T, l *SARIFLog) *Reader {
	t.Helper()
	return NewReader(RecordMap{l.Properties.AuditID: l})
}

func rpFindingIDs(cards []TaskCard) []string {
	out := make([]string, len(cards))
	for i, c := range cards {
		out[i] = c.FindingID
	}
	return out
}

func rpMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// The read order
// ---------------------------------------------------------------------------

// The bucket names are declared in this package but the ORDER is contract.go's
// DefaultReadOrder(). If the two ever disagree, the read path silently stops
// being the order R.13 mandates, so the disagreement is a test failure.
func TestReadOrderBucketsMatchTheContract(t *testing.T) {
	want := []string{BucketClusters, BucketSastByRank, BucketDastByRank}
	got := DefaultReadOrder()
	if len(got) != len(want) {
		t.Fatalf("DefaultReadOrder() = %q, this package's buckets are %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DefaultReadOrder()[%d] = %q, this package's bucket is %q", i, got[i], want[i])
		}
	}
}

func TestReadOrderIsClustersThenSastByRankThenDastByRank(t *testing.T) {
	l := rpFixture(t, nil)
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}

	want := []string{
		// The cluster first, SAST member before DAST member: the SAST finding
		// owns the file and line the agent has to edit.
		"sast:0001", "dast:0101",
		// Then SAST-only by rank. sast:0003 and sast:0004 are tied at 40, and
		// the finding-id tie-break puts 0003 first.
		"sast:0002", "sca:0005", "sast:0003", "sast:0004", "host:0006", "sast:0007",
		// Then DAST-only.
		"dast:0102",
	}
	got := rpFindingIDs(cards)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("read order\n got: %q\nwant: %q", got, want)
	}

	// The bucket sequence must never interleave.
	seen := map[string]int{}
	last := -1
	for i, c := range cards {
		idx := -1
		for j, b := range DefaultReadOrder() {
			if b == c.Bucket {
				idx = j
			}
		}
		if idx < 0 {
			t.Fatalf("card %d has bucket %q, which is not in DefaultReadOrder()", i, c.Bucket)
		}
		if idx < last {
			t.Fatalf("card %d (%s) is in bucket %q after a later bucket: buckets must not interleave",
				i, c.FindingID, c.Bucket)
		}
		last = idx
		seen[c.Bucket]++
	}
	for _, b := range DefaultReadOrder() {
		if seen[b] == 0 {
			t.Errorf("bucket %q produced no cards; the fixture is supposed to exercise all three", b)
		}
	}

	// Within each rank bucket, rank must be non-increasing.
	for i := 1; i < len(cards); i++ {
		if cards[i].Bucket != cards[i-1].Bucket || cards[i].Bucket == BucketClusters {
			continue
		}
		if cards[i].Rank > cards[i-1].Rank {
			t.Errorf("%s (rank %v) sorted after %s (rank %v) in bucket %q",
				cards[i].FindingID, cards[i].Rank, cards[i-1].FindingID, cards[i-1].Rank, cards[i].Bucket)
		}
	}
}

// Determinism, twice over: repeated calls on the same input, and the same
// input presented in a different order. The second is the one that matters —
// a sort that is merely deterministic-for-this-slice still reorders when the
// producer emits results in a different sequence, and the agent's read order
// would silently change between two scans of the same repository.
func TestReadOrderIsStableAcrossCallsAndInputPermutations(t *testing.T) {
	l := rpFixture(t, nil)
	rd := rpReader(t, l)

	first, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	firstManifest, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	wantCards := string(rpMarshal(t, first))
	wantManifest := string(rpMarshal(t, firstManifest))

	for i := 0; i < 5; i++ {
		cards, err := rd.BuildTaskCards(rpAuditID)
		if err != nil {
			t.Fatalf("BuildTaskCards call %d: %v", i, err)
		}
		if got := string(rpMarshal(t, cards)); got != wantCards {
			t.Fatalf("task cards differ between call 0 and call %d", i+1)
		}
		m, err := rd.BuildManifest(rpAuditID)
		if err != nil {
			t.Fatalf("BuildManifest call %d: %v", i, err)
		}
		if got := string(rpMarshal(t, m)); got != wantManifest {
			t.Fatalf("manifest differs between call 0 and call %d", i+1)
		}
	}

	reversed := rpFixture(t, func(l *SARIFLog) {
		for ri := range l.Runs {
			rs := l.Runs[ri].Results
			for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
				rs[i], rs[j] = rs[j], rs[i]
			}
		}
	})
	permuted, err := rpReader(t, reversed).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards on the permuted record: %v", err)
	}
	if got, want := rpFindingIDs(permuted), rpFindingIDs(first); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("reversing the record's result order changed the read order\n got: %q\nwant: %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Tier 0 — the 8 KB budget, measured
// ---------------------------------------------------------------------------

// The budget is not assumed. The manifest is marshalled and its real byte
// length is compared against MaxTier0ManifestBytes.
func TestManifestFitsTier0BudgetOnARealisticRecord(t *testing.T) {
	l := rpFixture(t, nil)
	m, err := rpReader(t, l).BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	raw := rpMarshal(t, m)
	t.Logf("tier-0 manifest: %d bytes (~%d tokens) of the %d-byte budget, %d findings",
		len(raw), ApproxTokens(len(raw)), MaxTier0ManifestBytes, m.Index.Counts.Total)

	if len(raw) > MaxTier0ManifestBytes {
		t.Fatalf("manifest is %d bytes, over the %d-byte Tier-0 budget", len(raw), MaxTier0ManifestBytes)
	}
	if m.Bytes != len(raw) {
		t.Errorf("manifest reports %d bytes but marshals to %d; the self-report must be the measurement",
			m.Bytes, len(raw))
	}
	if m.Tokens != ApproxTokens(len(raw)) {
		t.Errorf("manifest reports %d tokens, want %d", m.Tokens, ApproxTokens(len(raw)))
	}
	if len(m.Spills) != 0 {
		t.Errorf("a nine-finding record should fit Tier 0 with nothing spilled, got %d spills", len(m.Spills))
	}
	if m.Override != nil {
		t.Errorf("manifest carries a budget override it should not need: %+v", m.Override)
	}

	if m.Index.Counts.Total != 9 || m.Index.Counts.Sast != 7 || m.Index.Counts.Dast != 2 {
		t.Errorf("counts = %+v, want total 9 / sast 7 / dast 2", m.Index.Counts)
	}
	if m.Index.Counts.Clusters != 1 || m.Index.Counts.Unclustered != 7 {
		t.Errorf("counts = %+v, want 1 cluster and 7 unclustered", m.Index.Counts)
	}
	if m.Index.TaskCards != DefaultTaskCardPrefix || m.Index.Blobs != DefaultBlobPrefix {
		t.Errorf("tier prefixes = %q/%q, want %q/%q",
			m.Index.TaskCards, m.Index.Blobs, DefaultTaskCardPrefix, DefaultBlobPrefix)
	}
	if len(m.Index.ByCluster[rpClusterID]) != 2 {
		t.Errorf("byCluster[%s] = %q, want both members", rpClusterID, m.Index.ByCluster[rpClusterID])
	}
	if len(m.Index.ByPath["app/db.py"]) != 1 || len(m.Index.ByCwe["CWE-89"]) == 0 {
		t.Errorf("inverted indexes are not populated: byPath=%v byCwe=%v", m.Index.ByPath, m.Index.ByCwe)
	}
}

// A big record still fits, because the manifest degrades by SPILLING rather
// than by truncating. Nothing is lost: every dropped structure is a Tier-2
// blob named in Spills.
func TestLargeRecordManifestStaysUnderBudgetBySpilling(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		for i := 0; i < 400; i++ {
			r := rpSastResult(fmt.Sprintf("sast:9%03d", i), float64(500-i),
				EvidenceClassSastStaticOnly, VerdictTruePositive, true,
				fmt.Sprintf("app/pkg%02d/module%03d.py", i%20, i), byte(i))
			l.Runs[0].Results = append(l.Runs[0].Results, r)
		}
	})

	m, err := rpReader(t, l).BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	raw := rpMarshal(t, m)
	t.Logf("tier-0 manifest on a 409-finding record: %d bytes, %d spills", len(raw), len(m.Spills))

	if len(raw) > MaxTier0ManifestBytes {
		t.Fatalf("manifest is %d bytes, over the %d-byte budget even after spilling", len(raw), MaxTier0ManifestBytes)
	}
	if m.Override != nil {
		t.Fatalf("manifest took an override it did not need: %+v", m.Override)
	}
	if len(m.Spills) == 0 {
		t.Fatalf("a 409-finding record must have spilled something to fit 8 KB")
	}

	// The spill order is fixed: convenience indexes first, the read order last.
	wantOrder := []string{"anvil/index.byPath", "anvil/index.byCwe", "anvil/index.byCluster", "anvil/cards"}
	for i, s := range m.Spills {
		if s.Field != wantOrder[i] {
			t.Fatalf("spill %d is %q, want %q (the shrink order is fixed and is not the map's)",
				i, s.Field, wantOrder[i])
		}
	}

	// Nothing was dropped: every spill resolves to retained bytes that
	// round-trip, and the counts still describe all 409 findings.
	for _, s := range m.Spills {
		blob, ok := m.Blobs[s.Ref]
		if !ok {
			t.Fatalf("spill %s references blob %s, which was not retained", s.Field, s.Ref)
		}
		if BlobRef(blob) != s.Ref {
			t.Fatalf("blob for %s does not hash to its own reference", s.Field)
		}
		if len(blob) != s.Bytes {
			t.Errorf("spill %s reports %d bytes, blob is %d", s.Field, s.Bytes, len(blob))
		}
		if !json.Valid(blob) {
			t.Errorf("spill %s is not valid JSON", s.Field)
		}
	}
	if m.Index.Counts.Total != 409 {
		t.Errorf("counts.total = %d, want 409: spilling must not change what the manifest counts",
			m.Index.Counts.Total)
	}
	// The read order survives in full, as an inline PREFIX plus a spilled
	// TAIL: `m.Cards` then the blob is the whole order, once, in order.
	// CRITIQUE-03 M3: this step used to be all-or-nothing, which spent the
	// budget it had just freed on nothing.
	for _, s := range m.Spills {
		if s.Field != "anvil/cards" {
			continue
		}
		var tail []CardRef
		if err := json.Unmarshal(m.Blobs[s.Ref], &tail); err != nil {
			t.Fatalf("spilled read order does not unmarshal: %v", err)
		}
		if len(tail) != s.Items {
			t.Errorf("spill reports %d items, blob holds %d; TierSpill.Items is how a "+
				"consumer knows how much order is on the other side of the reference",
				s.Items, len(tail))
		}
		if len(m.Cards)+len(tail) != 409 {
			t.Errorf("%d inline refs + %d spilled = %d, want all 409: a partial spill "+
				"may move the tail, never lose it", len(m.Cards), len(tail), len(m.Cards)+len(tail))
		}
		if len(m.Cards) == 0 {
			t.Error("the whole read order spilled; the step is partial and the budget freed " +
				"by the three index spills must be spent on inline refs")
		}
		// The PREFIX is what the agent works first, so the cluster — which
		// DefaultReadOrder puts first — must be inline, not fetched.
		if len(m.Cards) < 2 || m.Cards[0].FindingID != "sast:0001" || m.Cards[1].FindingID != "dast:0101" {
			t.Errorf("the inline prefix does not start with the cluster: %v", rpCardIDs(m.Cards))
		}
		// And the tail resumes exactly where the prefix stopped: concatenating
		// them must reproduce the order BuildTaskCards emits.
		cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
		if err != nil {
			t.Fatalf("BuildTaskCards: %v", err)
		}
		joined := append(rpCardIDs(m.Cards), rpCardIDs(tail)...)
		if len(joined) != len(cards) {
			t.Fatalf("read order is %d refs but %d cards were emitted", len(joined), len(cards))
		}
		for i := range cards {
			if cards[i].FindingID != joined[i] {
				t.Fatalf("prefix+tail entry %d is %q, but the card at that position is %q; "+
					"the two halves of a partial spill must join back into ONE order",
					i, joined[i], cards[i].FindingID)
			}
		}
	}
}

// rpCardIDs is the finding ids of a read order, in order.
func rpCardIDs(refs []CardRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.FindingID)
	}
	return out
}

// An over-budget Tier 0 that cannot be shrunk is an ERROR, not a silently
// oversized manifest — and it becomes legal only with an explicit reason,
// which is then recorded in the artifact.
func TestOversizeTier0NeedsAnExplicitLoggedOverride(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		// A repo URL nothing can spill: it is envelope, not index.
		l.Properties.Target.RepoURL = "https://example.invalid/" + strings.Repeat("a", 9000)
	})

	rd := rpReader(t, l)
	if _, err := rd.BuildManifest(rpAuditID); err == nil {
		t.Fatal("an over-budget manifest with no override must be an error")
	} else {
		var be *BudgetError
		if !errors.As(err, &be) {
			t.Fatalf("want a *BudgetError, got %T: %v", err, err)
		}
		if be.Budget != MaxTier0ManifestBytes {
			t.Errorf("BudgetError.Budget = %d, want %d", be.Budget, MaxTier0ManifestBytes)
		}
	}

	rd.AllowOversizeTier0 = "R.13 evidence test: envelope alone exceeds the budget"
	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("with an explicit override, BuildManifest must succeed: %v", err)
	}
	if m.Override == nil {
		t.Fatal("the override must be recorded in the manifest, not merely honoured")
	}
	if m.Override.Reason != rd.AllowOversizeTier0 {
		t.Errorf("override reason = %q, want %q", m.Override.Reason, rd.AllowOversizeTier0)
	}
	if m.Override.Budget != MaxTier0ManifestBytes || m.Override.Bytes <= MaxTier0ManifestBytes {
		t.Errorf("override does not record the overrun honestly: %+v", m.Override)
	}
}

// TestTier0PartialSpillUsesTheBudget is CRITIQUE-03 M3 part 1's regression
// test, and it asserts the thing the previous shrink policy got wrong: not
// that the budget is RESPECTED — the all-or-nothing version respected it while
// throwing away 78% of it — but that the budget is USED.
//
// The measurement that motivated the fix, at nine sizes: below the crossover
// nothing spills and utilisation climbs to 98%; at the crossover the whole
// read order left in one step and utilisation fell to 22%, where it stayed for
// every larger record. An agent reading a 409-finding manifest therefore had
// to fetch Tier 2 before it could start on the FIRST finding, against a Tier-0
// budget that was three-quarters empty.
//
// The floor below is deliberately loose (85%). It is a REGRESSION bound, not
// the measured figure: this test must fail when the step goes back to
// all-or-nothing, and must not fail because a card ref grew a field and the
// last ref no longer fits. The measured figures are logged on every run.
func TestTier0PartialSpillUsesTheBudget(t *testing.T) {
	// The floor applies only once something has spilled: a nine-finding
	// record fits in 3,008 bytes and there is nothing to fill the rest WITH.
	const floorPct = 85.0

	for _, extra := range []int{0, 10, 20, 30, 40, 50, 80, 120, 400} {
		t.Run(fmt.Sprintf("extra%d", extra), func(t *testing.T) {
			l := rpFixture(t, func(l *SARIFLog) {
				for i := 0; i < extra; i++ {
					r := rpSastResult(fmt.Sprintf("sast:8%03d", i), 30.0, EvidenceClassSastStaticOnly,
						VerdictTruePositive, true, fmt.Sprintf("app/svc/mod%d/file%d.py", i%16, i), byte(i%251))
					r.PartialFingerprints[PartialFingerprintAnvilFindingID] = rpDigest(byte(30 + i%220))
					l.Runs[0].Results = append(l.Runs[0].Results, r)
				}
			})
			rd := rpReader(t, l)
			m, err := rd.BuildManifest(rpAuditID)
			if err != nil {
				t.Fatalf("BuildManifest: %v", err)
			}

			total := 0
			for i := range l.Runs {
				total += len(l.Runs[i].Results)
			}
			raw := rpMarshal(t, m)
			used := 100 * float64(len(raw)) / float64(MaxTier0ManifestBytes)
			t.Logf("findings=%3d bytes=%5d (budget %d, used %.0f%%) inline cards=%3d spilled=%3d",
				total, len(raw), MaxTier0ManifestBytes, used, len(m.Cards), rpSpilledCards(m))

			if len(raw) > MaxTier0ManifestBytes {
				t.Fatalf("manifest is %d bytes, over the %d-byte budget", len(raw), MaxTier0ManifestBytes)
			}
			if m.Override != nil {
				t.Fatalf("manifest took an override it did not need: %+v", m.Override)
			}
			// Nothing is ever lost, at any size.
			if got := len(m.Cards) + rpSpilledCards(m); got != total {
				t.Errorf("%d inline + %d spilled card refs = %d, want one per finding (%d)",
					len(m.Cards), rpSpilledCards(m), got, total)
			}
			if len(m.Spills) == 0 {
				return
			}
			if used < floorPct {
				t.Errorf("only %.0f%% of the %d-byte Tier-0 budget is used after spilling %d card "+
					"refs; the read order spills PARTIALLY so the budget freed by a spill is spent "+
					"on the refs the agent reads first, not left empty",
					used, MaxTier0ManifestBytes, rpSpilledCards(m))
			}
			// The prefix is non-empty exactly when the envelope leaves room,
			// which at every size here it does.
			if len(m.Cards) == 0 {
				t.Errorf("no card ref survived inline at %d findings; that is the all-or-nothing "+
					"behaviour this test exists to prevent", total)
			}
		})
	}
}

// rpSpilledCards is how many card refs left Tier 0, per the spill ledger.
func rpSpilledCards(m Manifest) int {
	n := 0
	for _, s := range m.Spills {
		if s.Field == "anvil/cards" {
			n += s.Items
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Tier 1 — the token budget, measured
// ---------------------------------------------------------------------------

func TestEveryTaskCardIsWithinTheTokenBudget(t *testing.T) {
	l := rpFixture(t, nil)
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	if len(cards) == 0 {
		t.Fatal("no cards")
	}
	for _, c := range cards {
		raw := rpMarshal(t, c)
		tok := ApproxTokens(len(raw))
		t.Logf("card %-12s %5d bytes ~%4d tokens", c.FindingID, len(raw), tok)
		if tok > MaxTier1CardTokens {
			t.Errorf("card %s is ~%d tokens, over the %d-token Tier-1 budget",
				c.FindingID, tok, MaxTier1CardTokens)
		}
		if len(raw) > MaxTier1CardBytes {
			t.Errorf("card %s is %d bytes, over the %d-byte budget", c.FindingID, len(raw), MaxTier1CardBytes)
		}
		if c.Bytes != len(raw) || c.Tokens != tok {
			t.Errorf("card %s self-reports %d bytes/%d tokens but measures %d/%d",
				c.FindingID, c.Bytes, c.Tokens, len(raw), tok)
		}
		if c.Override != nil {
			t.Errorf("card %s took a budget override it should not need: %+v", c.FindingID, c.Override)
		}
	}
}

// A finding whose evidence is enormous still produces a card inside the
// budget, by spilling in the documented order — code last, because a card
// without its snippet cannot do its one job.
func TestOversizedEvidenceSpillsInsteadOfBlowingTheCardBudget(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		r := &l.Runs[0].Results[0] // sast:0001 — the one with a code flow
		pl := r.Locations[0].PhysicalLocation
		pl.Region.Snippet.Text = strings.Repeat("x = compute(a, b)\n", 900)
		pl.ContextRegion.Snippet.Text = strings.Repeat("# context line\n", 900)
		r.Properties.Reasoning = strings.Repeat("because ", 900)
		r.CodeFlows[0].ThreadFlows[0].Locations[0].Location.PhysicalLocation.Region.Snippet.Text =
			strings.Repeat("taint step ", 400)
	})

	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	var card *TaskCard
	for i := range cards {
		if cards[i].FindingID == "sast:0001" {
			card = &cards[i]
		}
	}
	if card == nil {
		t.Fatal("sast:0001 produced no card")
	}

	raw := rpMarshal(t, card)
	if len(raw) > MaxTier1CardBytes {
		t.Fatalf("card is %d bytes after spilling, over the %d-byte budget", len(raw), MaxTier1CardBytes)
	}
	if len(card.Spills) == 0 {
		t.Fatal("an oversized card must spill, not truncate silently")
	}

	spilled := map[string]TierSpill{}
	for _, s := range card.Spills {
		spilled[s.Field] = s
		blob, ok := card.Blobs[s.Ref]
		if !ok {
			t.Fatalf("spill %s references blob %s, which was not retained", s.Field, s.Ref)
		}
		if BlobRef(blob) != s.Ref {
			t.Fatalf("blob for %s does not hash to its own reference", s.Field)
		}
	}
	for _, want := range []string{"/static/reasoning", "/static/taintPath", "/static/context/text"} {
		if _, ok := spilled[want]; !ok {
			t.Errorf("expected %s to spill before the code snippet did", want)
		}
	}
	if _, ok := spilled["/static/code"]; ok {
		// The code may spill, but only after everything else has. Assert the
		// order rather than forbidding it.
		if card.Spills[len(card.Spills)-1].Field != "/static/code" {
			t.Errorf("the code snippet spilled before something else; it must be last")
		}
	}
	// The spilled bytes are recoverable in full.
	if s, ok := spilled["/static/context/text"]; ok {
		if got := string(card.Blobs[s.Ref]); !strings.HasPrefix(got, "# context line") {
			t.Errorf("spilled context does not round-trip: %.40q", got)
		}
	}
}

// Bodies never exceed R.8's inline caps on a card either. The card budget is
// smaller than both caps, so this holds a fortiori — which is the point: prove
// it rather than assume the arithmetic.
func TestCardsNeverInlineABodyPastR8sCaps(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		d := &l.Runs[1].Results[1]
		d.WebRequest.Body.Text = strings.Repeat("a", 20*1024)
		d.WebResponse.Body.Text = strings.Repeat("b", 100*1024)
	})
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	for _, c := range cards {
		if c.Dynamic == nil {
			continue
		}
		if n := len(c.Dynamic.RequestBody); n > MaxInlineRequestBodyBytes {
			t.Errorf("card %s inlines %d request-body bytes, cap is %d", c.FindingID, n, MaxInlineRequestBodyBytes)
		}
		if n := len(c.Dynamic.ResponseExcerpt); n > MaxInlineResponseBodyBytes {
			t.Errorf("card %s inlines %d response bytes, cap is %d", c.FindingID, n, MaxInlineResponseBodyBytes)
		}
		// A field the inline cap already spilled must not spill a second time
		// when the token ladder drops it: one field, one Tier-2 reference.
		seen := map[string]int{}
		for _, s := range c.Spills {
			seen[s.Field]++
		}
		for field, n := range seen {
			if n > 1 {
				t.Errorf("card %s spilled %s %d times", c.FindingID, field, n)
			}
		}
	}
}

// The cap itself, exercised directly: a body over its limit keeps a prefix, an
// in-band pointer, and spills the whole thing to a content-addressed blob.
func TestInlineCapKeepsAPrefixAndSpillsTheRemainder(t *testing.T) {
	rd := NewReader(RecordMap{})
	c := &TaskCard{FindingID: "dast:0101", Blobs: map[string][]byte{}}
	full := strings.Repeat("q", 3*MaxInlineRequestBodyBytes)
	body := full

	if err := rd.capCardText(c, "/dynamic/requestBody", &body, MaxInlineRequestBodyBytes); err != nil {
		t.Fatalf("capCardText: %v", err)
	}
	if len(body) > MaxInlineRequestBodyBytes {
		t.Fatalf("capped body is %d bytes, cap is %d", len(body), MaxInlineRequestBodyBytes)
	}
	if len(c.Spills) != 1 {
		t.Fatalf("want exactly one spill, got %d", len(c.Spills))
	}
	s := c.Spills[0]
	if !strings.Contains(body, s.Ref) {
		t.Errorf("the truncated body must carry the sha256: reference in band, got %.80q", body)
	}
	if got := string(c.Blobs[s.Ref]); got != full {
		t.Errorf("the spilled blob is not the full body (%d of %d bytes)", len(got), len(full))
	}
	if !strings.HasPrefix(s.Ref, "sha256:") || len(s.Ref) != len("sha256:")+FingerprintDigestHexLen {
		t.Errorf("spill reference %q is not sha256:<64 hex>", s.Ref)
	}
}

// ---------------------------------------------------------------------------
// The host gate
// ---------------------------------------------------------------------------

// 00-SPINE.md S7: the host agent is read-only. The record's validator already
// rejects a host finding marked remediable; this proves the READ PATH does not
// hand one out as actionable even when the record is wrong.
func TestHostFindingIsNeverHandedOutAsActionable(t *testing.T) {
	l := rpFixture(t, nil)

	// The well-formed case first.
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	var host *TaskCard
	for i := range cards {
		if cards[i].FindingID == "host:0006" {
			host = &cards[i]
		}
	}
	if host == nil {
		t.Fatal("the host finding produced no card; it must still be REPORTED, just never actioned")
	}
	if host.Actionable || host.RemediableByAgent {
		t.Errorf("host card is actionable=%t remediable=%t, both must be false",
			host.Actionable, host.RemediableByAgent)
	}
	if len(host.ActionBlockers) == 0 || !strings.Contains(host.ActionBlockers[0], "read-only") {
		t.Errorf("the host card must say why it is not actionable, got %q", host.ActionBlockers)
	}
	for _, c := range ActionableTaskCards(cards) {
		if c.FindingID == "host:0006" {
			t.Fatal("ActionableTaskCards handed out the host finding")
		}
	}

	// Now the malformed case: a record claiming a host finding is remediable.
	// contract.go rejects it, so it is built directly rather than through
	// rpFixture's validate step — which is exactly the situation the read
	// path's own clamp exists for.
	broken := rpFixtureLog()
	for i := range broken.Runs[0].Results {
		r := &broken.Runs[0].Results[i]
		if r.Properties.FindingID == "host:0006" {
			r.Properties.RemediableByAgent = true
		}
	}
	if err := broken.Validate(); err == nil {
		t.Fatal("contract.go should still reject a remediable host finding; the fixture is not testing what it claims")
	}
	if err := MaskRecord(broken); err != nil {
		t.Fatalf("masking: %v", err)
	}
	brokenCards, err := rpReader(t, broken).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards on the malformed record: %v", err)
	}
	for _, c := range brokenCards {
		if c.FindingID != "host:0006" {
			continue
		}
		if c.RemediableByAgent {
			t.Error("the read path propagated remediableByAgent=true for a HOST finding")
		}
		if c.Actionable {
			t.Error("the read path handed out a HOST finding as actionable")
		}
	}
	for _, c := range ActionableTaskCards(brokenCards) {
		if IsHostFinding(&broken.Runs[0].Results[5]) && c.FindingID == "host:0006" {
			t.Fatal("ActionableTaskCards handed out a host finding from a malformed record")
		}
	}
}

func TestVerdictGatesActionability(t *testing.T) {
	l := rpFixture(t, nil)
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	want := map[string]bool{
		"sast:0001": true,  // true_positive
		"sast:0003": false, // insufficient_context -> report-only
		"sast:0007": false, // false_positive -> dropped by the pipeline
		"host:0006": false, // host -> read-only agent
	}
	got := map[string]bool{}
	for _, c := range cards {
		got[c.FindingID] = c.Actionable
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("card %s actionable = %t, want %t", id, got[id], w)
		}
	}
	// Report-only findings are still CARDS. research/24: never silently
	// dropped.
	if len(cards) != 9 {
		t.Errorf("got %d cards, want all 9 findings represented", len(cards))
	}
}

// ---------------------------------------------------------------------------
// What a card must carry
// ---------------------------------------------------------------------------

func TestCardCarriesTheNonNegotiableHandoffFields(t *testing.T) {
	l := rpFixture(t, nil)
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	byID := map[string]TaskCard{}
	for _, c := range cards {
		byID[c.FindingID] = c
	}

	sast := byID["sast:0001"]
	checks := []struct {
		field string
		ok    bool
	}{
		{"finding_id", sast.FindingID == "sast:0001"},
		{"fingerprint.anvilFindingId", len(sast.Fingerprint.AnvilFindingID) == FingerprintDigestHexLen},
		{"fingerprint.primary_location_line_hash", sast.Fingerprint.PrimaryLocationLineHash != ""},
		{"evidence_class", sast.EvidenceClass == EvidenceClassSastReachable},
		{"locus.path", sast.Locus.Path == "app/db.py"},
		{"locus.start_line", sast.Locus.StartLine == 412},
		{"locus.end_line", sast.Locus.EndLine == 414},
		{"locus.enclosing_symbol", sast.Locus.EnclosingSymbol == "app.db.authenticate"},
		{"locus.proximity_class", sast.Locus.ProximityClass == "same_symbol"},
		{"advisory_excerpt", sast.Advisory != nil && sast.Advisory.Excerpt != ""},
		{"group_id (reserved, empty on a fresh record)", sast.GroupID == ""},
		{"dast.reproduction (via the cluster peer)", sast.Dynamic != nil && sast.Dynamic.Curl != ""},
		{"static code", sast.Static != nil && sast.Static.Code != ""},
		{"taint path", sast.Static != nil && len(sast.Static.TaintPath) == 2},
		{"constraints", sast.Constraints != nil && sast.Constraints.TestCommand != ""},
		{"writeBackTo", sast.WriteBackTo == "/runs/0/results/0/fixes"},
		{"consumption class", sast.ConsumptionClass == ConsumptionClassStaticOnly},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("card sast:0001 is missing or wrong: %s", c.field)
		}
	}

	sca := byID["sca:0005"]
	if sca.Risk == nil || !sca.Risk.KevMember || sca.Risk.EpssScore == nil {
		t.Errorf("card sca:0005 must carry risk.*: %+v", sca.Risk)
	}

	dast := byID["dast:0102"]
	if dast.Dynamic == nil {
		t.Fatal("card dast:0102 has no dynamic section")
	}
	if dast.Dynamic.Env == nil || dast.Dynamic.Env.Sanitizers == nil {
		t.Error("a reproduction must carry its sanitizer state: a crash under ASan is a different claim")
	}
	if dast.Dynamic.ExpectedAfterFix == nil || dast.Dynamic.InjectionPoint != "body:username" {
		t.Errorf("dynamic section is incomplete: %+v", dast.Dynamic)
	}
	if dast.ConsumptionClass != ConsumptionClassRequiresDynamicConfirmation {
		t.Errorf("a dast_confirmed finding must be %q, got %q",
			ConsumptionClassRequiresDynamicConfirmation, dast.ConsumptionClass)
	}
	if dast.Trust.Default != TrustUntrusted {
		t.Errorf("a card's default trust must be %q, got %q", TrustUntrusted, dast.Trust.Default)
	}
	if got := dast.Trust.Fields["/task"]; got != TrustAnvilGenerated {
		t.Errorf("the card's own task text is Anvil-generated, got %q", got)
	}
}

// Link, never merge. Both cluster members keep their own card; each card
// carries the peer's evidence as a convenience, and neither claims a merge.
func TestClusterMembersAreLinkedNeverMerged(t *testing.T) {
	l := rpFixture(t, nil)
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	byID := map[string]TaskCard{}
	for _, c := range cards {
		byID[c.FindingID] = c
	}
	sast, dast := byID["sast:0001"], byID["dast:0101"]

	for _, c := range []TaskCard{sast, dast} {
		if c.Correlation == nil {
			t.Fatalf("card %s lost its correlation", c.FindingID)
		}
		if c.Correlation.Merged {
			t.Errorf("card %s claims merged=true", c.FindingID)
		}
		if c.Correlation.ClusterID != rpClusterID {
			t.Errorf("card %s cluster = %q", c.FindingID, c.Correlation.ClusterID)
		}
		if !c.Correlation.Verified {
			t.Errorf("card %s: a stack-trace signal is present, so verified should survive", c.FindingID)
		}
	}
	if len(sast.Correlation.Peers) != 1 || sast.Correlation.Peers[0] != "dast:0101" {
		t.Errorf("sast peers = %q", sast.Correlation.Peers)
	}
	if len(dast.Correlation.Peers) != 1 || dast.Correlation.Peers[0] != "sast:0001" {
		t.Errorf("dast peers = %q", dast.Correlation.Peers)
	}
	// The SAST card owns the file and line; the DAST card owns the proof; each
	// card sees both, and the record still holds two independent results.
	if sast.Static == nil || sast.Dynamic == nil {
		t.Error("the SAST card should carry its own static evidence and the peer's reproduction")
	}
	if dast.Static == nil || dast.Dynamic == nil {
		t.Error("the DAST card should carry its own reproduction and the peer's file and line")
	}
	if dast.Locus.Path != "app/db.py" {
		t.Errorf("the DAST card's locus should come from the SAST peer, got %q", dast.Locus.Path)
	}
	if n := len(l.Runs[0].Results) + len(l.Runs[1].Results); n != 9 {
		t.Errorf("the record must still hold both findings independently, got %d results", n)
	}
}

// ---------------------------------------------------------------------------
// Gates the read path will not open
// ---------------------------------------------------------------------------

// R.6's read gate: only HalfStatusSealed opens a half. An unsealed half yields
// no cards, and the manifest still SAYS the half exists — otherwise "no DAST
// cards" and "no dynamic vulnerabilities" become the same observation, which
// is research/23 Risk #1.
func TestUnsealedHalfYieldsNoCardsButIsStillReported(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		l.Runs[1].Properties.Status = HalfStatusRunning
		l.Runs[1].Properties.SealedAt = nil
		l.Properties.State = StateSastSealed
		l.Properties.DastStatus = DastStatusRunning
	})

	rd := rpReader(t, l)
	cards, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	for _, c := range cards {
		if c.Half == HalfDast {
			t.Errorf("card %s came from a half whose status is %q, not %q",
				c.FindingID, HalfStatusRunning, HalfStatusSealed)
		}
	}

	// The SAST member of the cluster survives — the correlation is a fact
	// recorded on ITS result, and link-never-merge means it does not depend on
	// the peer being present. What must NOT happen is the peer's evidence
	// reaching the card through the cluster projection: that would walk around
	// the seal gate rather than through it.
	var clustered *TaskCard
	for i := range cards {
		if cards[i].FindingID == "sast:0001" {
			clustered = &cards[i]
		}
	}
	if clustered == nil {
		t.Fatal("the cluster's readable member vanished when its peer became unreadable")
	}
	if clustered.Bucket != BucketClusters || clustered.ClusterID != rpClusterID {
		t.Errorf("clustered card = bucket %q cluster %q", clustered.Bucket, clustered.ClusterID)
	}
	if clustered.Dynamic != nil {
		t.Error("the card carries the unsealed peer's dynamic evidence: the seal gate was bypassed via the cluster")
	}

	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	var dastHalf *ManifestHalf
	for i := range m.Halves {
		if m.Halves[i].Half == HalfDast {
			dastHalf = &m.Halves[i]
		}
	}
	if dastHalf == nil {
		t.Fatal("the manifest dropped the unreadable half entirely; the consumer must be able to see it exists")
	}
	if dastHalf.Readable || dastHalf.Cards != 0 {
		t.Errorf("dast half readable=%t cards=%d, want false/0", dastHalf.Readable, dastHalf.Cards)
	}
	if dastHalf.Results != 2 {
		t.Errorf("the manifest must report the %d withheld results, got %d", 2, dastHalf.Results)
	}
	if m.DynamicallyScannedClean {
		t.Error("dastStatus is running; nothing may report this target as dynamically scanned clean")
	}
}

// Only completed_clean means "dynamically scanned, nothing found". Every other
// value, including the ones that also carry zero findings, must not be read
// that way.
func TestManifestNeverClaimsScannedCleanForAnyOtherDastStatus(t *testing.T) {
	for _, s := range DastStatusValues() {
		s := s
		t.Run(string(s), func(t *testing.T) {
			l := rpFixture(t, func(l *SARIFLog) {
				l.Properties.DastStatus = s
				if s == DastStatusNotRun || s == DastStatusSkippedNoManifest {
					// Both mean the DAST half produced nothing; the record's
					// own state machine then requires the half to be gone.
					l.Runs = l.Runs[:1]
				}
			})
			m, err := rpReader(t, l).BuildManifest(rpAuditID)
			if err != nil {
				t.Fatalf("BuildManifest: %v", err)
			}
			want := s == DastStatusCompletedClean
			if m.DynamicallyScannedClean != want {
				t.Errorf("dastStatus %q: dynamicallyScannedClean = %t, want %t",
					s, m.DynamicallyScannedClean, want)
			}
			if m.DastStatus != s {
				t.Errorf("the manifest must carry dastStatus verbatim, got %q", m.DastStatus)
			}
		})
	}
}

// The read path feeds a repo-credentialed agent. An unmasked record does not
// get through it.
func TestUnmaskedRecordIsRefused(t *testing.T) {
	l := rpFixtureLog()
	l.Runs[1].Results[0].WebRequest.Headers["Authorization"] = "Bearer ghp_averyrealisticlookingtoken"

	rd := NewReader(RecordMap{rpAuditID: l})
	if _, err := rd.BuildTaskCards(rpAuditID); err == nil {
		t.Fatal("BuildTaskCards accepted a record carrying a live bearer token")
	} else if !strings.Contains(err.Error(), "masking") && !strings.Contains(err.Error(), "unmasked") {
		t.Logf("refusal message: %v", err)
	}
	if _, err := rd.BuildManifest(rpAuditID); err == nil {
		t.Fatal("BuildManifest accepted an unmasked record")
	}

	if err := MaskRecord(l); err != nil {
		t.Fatalf("masking: %v", err)
	}
	if _, err := rd.BuildTaskCards(rpAuditID); err != nil {
		t.Fatalf("after masking, the same record must be accepted: %v", err)
	}
}

func TestSourceMismatchIsRefused(t *testing.T) {
	l := rpFixture(t, nil)
	rd := NewReader(RecordMap{"some-other-audit": l})
	if _, err := rd.BuildManifest("some-other-audit"); err == nil {
		t.Fatal("a source returning the wrong audit must be refused: the audit id is the join key")
	}
	if _, err := NewReader(RecordMap{}).BuildManifest(rpAuditID); err == nil {
		t.Fatal("a missing audit must be an error, not an empty manifest")
	}
}

// ---------------------------------------------------------------------------
// The card is derived; the record wins
// ---------------------------------------------------------------------------

func TestCheckAgainstRecordAcceptsDerivedCardsAndRejectsContradictions(t *testing.T) {
	l := rpFixture(t, nil)
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}

	byID := map[string]*Result{}
	for ri := range l.Runs {
		for si := range l.Runs[ri].Results {
			r := &l.Runs[ri].Results[si]
			byID[r.Properties.FindingID] = r
		}
	}
	for _, c := range cards {
		if err := c.CheckAgainstRecord(byID[c.FindingID]); err != nil {
			t.Errorf("a freshly derived card disagrees with its own record: %v", err)
		}
	}

	// A card may be LESS permissive than the record. That is the host clamp,
	// and it is not a contradiction.
	lenient := cards[0]
	lenient.Actionable = false
	lenient.RemediableByAgent = false
	if err := lenient.CheckAgainstRecord(byID[lenient.FindingID]); err != nil {
		t.Errorf("withholding an action must be legal, got: %v", err)
	}

	// A card may never be MORE permissive.
	host := byID["host:0006"]
	forged := TaskCard{
		FindingID: "host:0006", EvidenceClass: host.Properties.EvidenceClass,
		Verdict: host.Properties.Verdict, Half: host.Properties.Half,
		Confidence:        host.Properties.Confidence,
		Fingerprint:       CardFingerprint{AnvilFindingID: host.PartialFingerprints[PartialFingerprintAnvilFindingID]},
		RemediableByAgent: true, Actionable: true,
	}
	err = forged.CheckAgainstRecord(host)
	if err == nil {
		t.Fatal("a card granting an action the record forbids must be reported")
	}
	if !strings.Contains(err.Error(), "read-only") || !strings.Contains(err.Error(), "the record wins") {
		t.Errorf("the error should name the rule and the precedence, got: %v", err)
	}

	// A drifted field is a contradiction, not a rounding difference.
	drifted := cards[0]
	drifted.EvidenceClass = EvidenceClassHost
	if err := drifted.CheckAgainstRecord(byID[drifted.FindingID]); err == nil {
		t.Error("a card whose evidenceClass differs from the record must be reported")
	}
}

// The manifest's read order and the cards are the same order, by construction.
// They are built by two calls and a consumer pairs them by index, so a drift
// between them would silently hand the agent one order and one set of paths.
func TestManifestReadOrderMatchesTheCards(t *testing.T) {
	l := rpFixture(t, nil)
	rd := rpReader(t, l)
	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	cards, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	if len(m.Cards) != len(cards) {
		t.Fatalf("manifest lists %d cards, BuildTaskCards returned %d", len(m.Cards), len(cards))
	}
	for i := range cards {
		if m.Cards[i].FindingID != cards[i].FindingID {
			t.Fatalf("position %d: manifest says %q, cards say %q",
				i, m.Cards[i].FindingID, cards[i].FindingID)
		}
		if m.Cards[i].Bucket != cards[i].Bucket || m.Cards[i].Actionable != cards[i].Actionable {
			t.Errorf("position %d: manifest and card disagree on bucket/actionable", i)
		}
		if want := DefaultTaskCardPrefix + SanitizeCardFilename(cards[i].FindingID) + ".json"; m.Cards[i].Card != want {
			t.Errorf("card path = %q, want %q", m.Cards[i].Card, want)
		}
		if cards[i].Position != i {
			t.Errorf("card %s reports position %d, is at %d", cards[i].FindingID, cards[i].Position, i)
		}
	}
	// A colon is not a legal Windows path character, and finding ids carry
	// one.
	if strings.ContainsAny(m.Cards[0].Card, `:*?"<>|`) {
		t.Errorf("card path %q is not filesystem-safe", m.Cards[0].Card)
	}
}

func TestApproxTokensIsPessimistic(t *testing.T) {
	// The estimate must never UNDER-count: an under-counted card blows the
	// agent's context with no error anywhere.
	if ApproxBytesPerToken > 3 {
		t.Errorf("ApproxBytesPerToken = %d; anything above 3 makes the budget check optimistic",
			ApproxBytesPerToken)
	}
	if ApproxTokens(0) != 0 || ApproxTokens(1) != 1 || ApproxTokens(3) != 1 || ApproxTokens(4) != 2 {
		t.Errorf("ApproxTokens rounds wrongly: %d %d %d %d",
			ApproxTokens(0), ApproxTokens(1), ApproxTokens(3), ApproxTokens(4))
	}
	if MaxTier1CardBytes != MaxTier1CardTokens*ApproxBytesPerToken {
		t.Errorf("MaxTier1CardBytes is not derived from the contract's token budget")
	}
}

// Every enum-valued field the read path emits comes from contract.go. This
// catches the failure mode that produced the ten section-6 defects: a second
// copy of a literal is a second definition.
func TestReadPathEmitsOnlyFrozenEnumLiterals(t *testing.T) {
	l := rpFixture(t, nil)
	rd := rpReader(t, l)
	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if err := ValidateState(string(m.State)); err != nil {
		t.Error(err)
	}
	if err := ValidateDastStatus(string(m.DastStatus)); err != nil {
		t.Error(err)
	}
	if err := ValidateTargetProvenance(string(m.Target.Provenance)); err != nil {
		t.Error(err)
	}
	if err := ValidateTargetProvisioning(string(m.Target.Provisioning)); err != nil {
		t.Error(err)
	}
	for _, h := range m.Halves {
		if err := ValidateHalf(string(h.Half)); err != nil {
			t.Error(err)
		}
		if err := ValidateHalfStatus(string(h.Status)); err != nil {
			t.Error(err)
		}
	}
	cards, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	for _, c := range cards {
		if err := ValidateVerdict(string(c.Verdict)); err != nil {
			t.Errorf("card %s: %v", c.FindingID, err)
		}
		if err := ValidateEvidenceClass(string(c.EvidenceClass)); err != nil {
			t.Errorf("card %s: %v", c.FindingID, err)
		}
		if err := ValidateHalf(string(c.Half)); err != nil {
			t.Errorf("card %s: %v", c.FindingID, err)
		}
		if err := ValidateConsumptionClass(string(c.ConsumptionClass)); err != nil {
			t.Errorf("card %s: %v", c.FindingID, err)
		}
		if err := ValidateTrust(string(c.Trust.Default)); err != nil {
			t.Errorf("card %s: %v", c.FindingID, err)
		}
		if c.Dynamic != nil && c.Dynamic.ObservedSignal != "" {
			if err := ValidateEvidenceSignal(string(c.Dynamic.ObservedSignal)); err != nil {
				t.Errorf("card %s: %v", c.FindingID, err)
			}
		}
		if c.Correlation != nil {
			for _, s := range c.Correlation.Signals {
				if err := ValidateCorrelationSignal(s); err != nil {
					t.Errorf("card %s: %v", c.FindingID, err)
				}
			}
		}
	}
}

// ===========================================================================
// THE READ GATE — CRITIQUE-03 B1/M1, and the test that is supposed to stop
// bypass number five
// ===========================================================================
//
// FOUR separate authors have now written their own answer to "may a consumer
// read this half's results?" and four got it wrong in four different ways
// (sealing.go's read-gate section lists them: CRITIQUE-02 M2 and M3,
// CRITIQUE-03 B1 and M1). Patching each bypass as it is found is a losing
// game, so the countermeasure is this section rather than any one fix:
//
//   - sealing.go answers the question in ONE function body, halfReadRefusal,
//     reached through HalfReadGate / HalfSeal.Readable;
//   - TestEveryResultBearingEntryPointIsGated enumerates every exported entry
//     point that can hand out a half's results and asserts each one refuses an
//     unsealed half AND an expired audit;
//   - gateAuditedEntryPoints, the list that test drives off, is reconciled
//     against the package source, so an entry point that returns results and
//     is not in the list is a test failure rather than a silence.
//
// If you are here because that test failed on a function you just added:
// route it through HalfReadGate and add it to gateAuditedEntryPoints with a
// probe. If you believe it genuinely cannot leak a half's results, add it with
// an `exempt` reason — but write the reason, because "it obviously cannot" is
// what the last four authors also believed.

// gateScenario is one record-plus-Sealer pair in which NO half is readable.
// Every probe below must hand out ZERO results for every scenario.
//
// The record and the Sealer describe the SAME audit, because the two halves of
// this package's read surface — the record-side projections (readpath.go,
// taskcard.go, sarif_github.go) and the in-memory Sealer — are exactly the two
// places the gate has been bypassed, and a test that covered only one would
// have missed two of the four historical bugs.
type gateScenario struct {
	name    string
	auditID string
	log     *SARIFLog
	sealer  *Sealer
}

// gateProbe calls one exported entry point and returns the number of a half's
// results it handed out. Anything above zero is a bypass.
type gateProbe func(t *testing.T, sc gateScenario) int

// gateEntry is one exported entry point that CAN return a half's results.
//
// THE LIST BELOW IS THE BEHAVIOURAL HALF OF THE GUARD: it RUNS each entry
// point against every state in which nothing may be read and counts what came
// back. It is maintained by hand, and by hand alone it would go stale the
// moment someone adds an entry point — which is what the SOURCE half is for:
//
//	TestResultReachingEntryPointsAreGated       reads the package's AST and
//	  fails when an exported entry point can reach a half's results without
//	  the same call graph reaching the gate. It replaced a whitelist of return
//	  TYPES that three synthesised leaks walked straight past.
//	TestReadabilityAnsweringEntryPointsAreProbed
//	  fails when an exported entry point hands out a HalfSeal or an AuditSeal
//	  — the readability answer itself — without a line in this table.
//
// So: adding a new way to read a half's results, without adding a line here,
// fails the suite.
type gateEntry struct {
	// name is "Func" or "Recv.Method", exactly as the source spells it. It is
	// what the source reconciliation matches on.
	name string

	// probe is the assertion. Exactly one of probe and exempt is set.
	probe gateProbe

	// exempt records why this entry point cannot hand out an ungated result,
	// for the ones where that is structurally true. A reason, never a shrug.
	exempt string
}

// gateAuditedEntryPoints is the maintained list. See gateEntry.
func gateAuditedEntryPoints() []gateEntry {
	return []gateEntry{
		// ---- readpath.go / taskcard.go: the record-side projections -------
		{name: "Reader.BuildManifest", probe: func(t *testing.T, sc gateScenario) int {
			m, err := NewReader(RecordMap{sc.auditID: sc.log}).BuildManifest(sc.auditID)
			if err != nil {
				t.Fatalf("BuildManifest: %v", err)
			}
			return gateManifestExposure(t, m)
		}},
		{name: "Reader.ManifestFromLog", probe: func(t *testing.T, sc gateScenario) int {
			m, err := NewReader(RecordMap{sc.auditID: sc.log}).ManifestFromLog(sc.log)
			if err != nil {
				t.Fatalf("ManifestFromLog: %v", err)
			}
			return gateManifestExposure(t, m)
		}},
		{name: "Reader.BuildTaskCards", probe: func(t *testing.T, sc gateScenario) int {
			cards, err := NewReader(RecordMap{sc.auditID: sc.log}).BuildTaskCards(sc.auditID)
			if err != nil {
				t.Fatalf("BuildTaskCards: %v", err)
			}
			return len(cards)
		}},
		{name: "Reader.CardsFromLog", probe: func(t *testing.T, sc gateScenario) int {
			cards, err := NewReader(RecordMap{sc.auditID: sc.log}).CardsFromLog(sc.log)
			if err != nil {
				t.Fatalf("CardsFromLog: %v", err)
			}
			return len(cards)
		}},
		{
			name: "ActionableTaskCards",
			exempt: "a filter over a []TaskCard the caller already holds. It cannot reach a " +
				"record or a Sealer, so the only cards it can return are cards a gated entry " +
				"point above already emitted. If it ever grows a RecordSource parameter, " +
				"delete this exemption and give it a probe.",
		},

		// ---- sarif_github.go: the most externally visible consumer --------
		{name: "ProjectForGitHub", probe: func(t *testing.T, sc gateScenario) int {
			files, err := ProjectForGitHub(sc.log)
			if err != nil {
				t.Fatalf("ProjectForGitHub: %v", err)
			}
			n := 0
			for _, f := range files {
				n += f.ResultCount
				for _, run := range f.Log.Runs {
					n += len(run.Results)
				}
			}
			// The loss must also be COUNTABLE, not merely absent: CRITIQUE-03
			// B1's probe found zero drops recorded in every unsealed case, so
			// the leak was invisible as well as permitted.
			loss := GitHubLossOf(files)
			if loss == nil {
				t.Fatal("no loss ledger reachable from a fully-withheld projection")
			}
			if loss.DropCounts[GitHubDropHalfNotReadable] != loss.SourceResultCount {
				t.Errorf("%d of %d withheld results were ledgered under %q; a withheld result "+
					"that is not counted is a silent drop\n%s",
					loss.DropCounts[GitHubDropHalfNotReadable], loss.SourceResultCount,
					GitHubDropHalfNotReadable, loss.Summary())
			}
			return n
		}},

		// ---- sealing.go: the in-memory consumer gate ----------------------
		{name: "Sealer.ReadHalf", probe: func(t *testing.T, sc gateScenario) int {
			n := 0
			for _, half := range HalfValues() {
				seal, err := sc.sealer.ReadHalf(sc.auditID, half)
				if err == nil {
					n++
				} else if !errors.Is(err, ErrHalfNotSealed) {
					t.Errorf("ReadHalf(%s) refused with %v, want a *ReadGateError", half, err)
				}
				if seal.Readable() {
					n++
				}
			}
			return n
		}},
		{name: "ReadHalf", probe: func(t *testing.T, sc gateScenario) int {
			n := 0
			for _, half := range HalfValues() {
				seal, err := ReadHalf(sc.auditID, half)
				if err == nil {
					n++
				}
				if seal.Readable() {
					n++
				}
			}
			return n
		}},
		{name: "Sealer.Inspect", probe: func(t *testing.T, sc gateScenario) int {
			s, ok := sc.sealer.Inspect(sc.auditID)
			if !ok {
				t.Fatalf("Inspect(%q) does not know the audit the scenario registered", sc.auditID)
			}
			return gateReadableHalves(s)
		}},
		{name: "Inspect", probe: func(t *testing.T, sc gateScenario) int {
			s, ok := Inspect(sc.auditID)
			if !ok {
				t.Fatalf("package Inspect(%q) does not know the audit the scenario registered", sc.auditID)
			}
			return gateReadableHalves(s)
		}},
		{name: "Sealer.BeginAudit", probe: gateProbeBeginAudit},
		{name: "BeginAudit", probe: gateProbeBeginAudit},

		// ---- entry points the source reconciliation does not require, listed
		// anyway because they answer the readability question even though
		// their return types are plain bools. The table may be a superset of
		// what the source demands; it may never be a subset.
		{name: "Sealer.ReadyForConsumption", probe: func(t *testing.T, sc gateScenario) int {
			n := 0
			sast, dast := sc.sealer.ReadyForConsumption(sc.auditID)
			if sast {
				n++
			}
			if dast {
				n++
			}
			return n
		}},
		{name: "ReadyForConsumption", probe: func(t *testing.T, sc gateScenario) int {
			n := 0
			sast, dast := ReadyForConsumption(sc.auditID)
			if sast {
				n++
			}
			if dast {
				n++
			}
			return n
		}},
		{name: "HalfSeal.Readable", probe: func(t *testing.T, sc gateScenario) int {
			n := 0
			for i := range sc.log.Runs {
				if halfSealOfRun(sc.log, &sc.log.Runs[i]).Readable() {
					n++
				}
			}
			return n
		}},
		{name: "HalfReadGate", probe: func(t *testing.T, sc gateScenario) int {
			n := 0
			for i := range sc.log.Runs {
				if HalfReadGate(sc.auditID, halfSealOfRun(sc.log, &sc.log.Runs[i])) == nil {
					n++
				}
			}
			return n
		}},
	}
}

// gateProbeBeginAudit covers both spellings of BeginAudit. A freshly begun
// audit has produced nothing, so neither half may be readable — including the
// DAST half a core-`anvil` install seals immediately as skipped, which is
// terminal and unreadable at once.
func gateProbeBeginAudit(t *testing.T, sc gateScenario) int {
	t.Helper()
	s := NewSealer()
	seal, err := s.BeginAudit(AuditConfig{
		AuditID: sc.auditID + "-begin", StartedAt: rpTime(), ClaimTimeoutSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	return gateReadableHalves(seal)
}

func gateReadableHalves(s AuditSeal) int {
	n := 0
	if s.Sast.Readable() {
		n++
	}
	if s.Dast.Readable() {
		n++
	}
	return n
}

// gateManifestExposure counts what a manifest handed out: card refs (each of
// which points at a Tier-1 card built from a half's results) plus any half the
// manifest CLAIMS is readable.
//
// It deliberately does NOT count ManifestHalf.Results. The manifest must keep
// reporting that an unreadable half exists and how many results it is holding
// back — otherwise "no DAST findings" and "the DAST half never sealed" arrive
// as the same observation, which is research/23 Risk #1 and is a worse bug
// than the one this test guards.
func gateManifestExposure(t *testing.T, m Manifest) int {
	t.Helper()
	n := len(m.Cards)
	for _, h := range m.Halves {
		if h.Readable {
			n++
		}
		if !h.Readable && h.ReadRefusal == "" {
			t.Errorf("half %s is unreadable but the manifest gives no reason; "+
				"'never sealed' and 'the audit expired' must not arrive as the same observation", h.Half)
		}
		if h.Cards != 0 {
			t.Errorf("half %s reports %d cards", h.Half, h.Cards)
		}
	}
	return n
}

// gateScenarios builds the states in which NOTHING may be read. Each one is a
// real record contract.go's own Validate() accepts, plus a Sealer driven to
// the matching state through its real transitions.
func gateScenarios(t *testing.T) []gateScenario {
	t.Helper()

	// (1) Neither half has sealed. This is the arm CRITIQUE-03 B1 found the
	// GitHub projection ignoring entirely.
	unsealed := gateScenario{name: "no half has sealed", auditID: rpAuditID + "-unsealed"}
	unsealed.log = rpFixture(t, func(l *SARIFLog) {
		l.Properties.AuditID = unsealed.auditID
		for i := range l.Runs {
			l.Runs[i].Properties.Status = HalfStatusRunning
			l.Runs[i].Properties.SealedAt = nil
			l.Runs[i].AutomationDetails.CorrelationGUID = unsealed.auditID
		}
		l.Properties.State = StateCollecting
		l.Properties.DastStatus = DastStatusRunning
	})
	unsealed.sealer = gateSealer(t, unsealed.auditID, false)

	// (2) Both halves are TERMINAL but neither is READABLE. A failed half is
	// not a clean half; §6 keeps completed_failed distinct from
	// completed_partial precisely because a half that CRASHED is not a half
	// that covered part of the surface.
	failed := gateScenario{name: "both halves failed", auditID: rpAuditID + "-failed"}
	failed.log = rpFixture(t, func(l *SARIFLog) {
		l.Properties.AuditID = failed.auditID
		for i := range l.Runs {
			l.Runs[i].Properties.Status = HalfStatusFailed
			l.Runs[i].Properties.SealedAt = nil
			l.Runs[i].AutomationDetails.CorrelationGUID = failed.auditID
		}
		l.Properties.State = StateCollecting
		l.Properties.DastStatus = DastStatusCompletedFailed
	})
	failed.sealer = gateSealer(t, failed.auditID, false)

	// (3) Both halves sealed cleanly and the audit then EXPIRED. This is the
	// arm CRITIQUE-03 M1 found readpath.go ignoring: the claim window has
	// closed, the reaper drops the payload, and the handoff rows behind any
	// card are subject to ReclaimExpired — so an agent handed an actionable
	// card here has nowhere legal to land its work.
	expired := gateScenario{name: "the audit expired holding two sealed halves", auditID: rpAuditID + "-expired"}
	expired.log = rpFixture(t, func(l *SARIFLog) {
		l.Properties.AuditID = expired.auditID
		for i := range l.Runs {
			l.Runs[i].AutomationDetails.CorrelationGUID = expired.auditID
		}
		l.Properties.State = StateExpired
	})
	expired.sealer = gateSealer(t, expired.auditID, true)

	return []gateScenario{unsealed, failed, expired}
}

// gateSealer registers auditID on a fresh Sealer AND on the package-level
// DefaultSealer — the package-level ReadHalf/Inspect/ReadyForConsumption are
// exported entry points in their own right and are probed through the real
// global, not a stand-in.
//
// expire drives the audit through seal-both-then-ExpireIfDue using a claim
// clock that is already spent, so no clock is patched and no other test's view
// of time moves.
func gateSealer(t *testing.T, auditID string, expire bool) *Sealer {
	t.Helper()
	cfg := AuditConfig{AuditID: auditID, StartedAt: rpTime(), ClaimTimeoutSeconds: 3600, DastEnabled: true}
	if expire {
		cfg.StartedAt = time.Now().Add(-72 * time.Hour)
		cfg.ClaimTimeoutSeconds = 1
	}

	local := NewSealer()
	for _, s := range []*Sealer{local, DefaultSealer()} {
		if _, err := s.BeginAudit(cfg); err != nil {
			t.Fatalf("BeginAudit(%q): %v", auditID, err)
		}
		if !expire {
			continue
		}
		for _, half := range HalfValues() {
			if err := s.SealHalf(auditID, half, HalfStatusSealed); err != nil {
				t.Fatalf("SealHalf(%q, %s): %v", auditID, half, err)
			}
		}
		done, err := s.ExpireIfDue(auditID)
		if err != nil || !done {
			t.Fatalf("ExpireIfDue(%q) = %t, %v; the scenario needs an expired audit", auditID, done, err)
		}
	}
	t.Cleanup(func() { DefaultSealer().Forget(auditID) })
	return local
}

// TestEveryResultBearingEntryPointIsGated is the regression test for the
// PATTERN rather than for any one of the four bypasses. Every exported way to
// obtain a half's results, driven against every state in which no half may be
// read, must hand out nothing.
func TestEveryResultBearingEntryPointIsGated(t *testing.T) {
	entries := gateAuditedEntryPoints()
	probed := 0
	for _, sc := range gateScenarios(t) {
		for _, e := range entries {
			if e.probe == nil {
				continue
			}
			probed++
			t.Run(sc.name+"/"+e.name, func(t *testing.T) {
				if n := e.probe(t, sc); n != 0 {
					t.Errorf("%s handed out %d of the audit's results while %s. "+
						"The read gate is sealing.go's HalfReadGate and it is not this "+
						"entry point's to re-derive; see sealing.go's read-gate section.",
						e.name, n, sc.name)
				}
			})
		}
	}
	if probed == 0 {
		t.Fatal("no entry point was probed; the table drives the whole test and it is empty")
	}
}

// TestReadGateOpensOnASealedAudit is the other half of the assertion above: a
// gate that refuses everything is not a gate, it is a wall. The same surfaces,
// against a fully sealed live audit, must hand results OUT.
func TestReadGateOpensOnASealedAudit(t *testing.T) {
	l := rpFixture(t, nil)
	rd := NewReader(RecordMap{rpAuditID: l})

	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if len(m.Cards) == 0 {
		t.Error("a fully sealed audit produced no read order; the gate refuses everything")
	}
	for _, h := range m.Halves {
		if !h.Readable {
			t.Errorf("half %s is not readable on a fully sealed, live audit", h.Half)
		}
		if h.ReadRefusal != "" {
			t.Errorf("half %s is readable but carries a refusal reason %q", h.Half, h.ReadRefusal)
		}
	}
	cards, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	if len(cards) == 0 {
		t.Error("a fully sealed audit produced no task cards")
	}

	openID := rpAuditID + "-open"
	s := gateSealer(t, openID, false)
	for _, half := range HalfValues() {
		if err := s.SealHalf(openID, half, HalfStatusSealed); err != nil {
			t.Fatalf("SealHalf(%s): %v", half, err)
		}
	}
	for _, half := range HalfValues() {
		seal, err := s.ReadHalf(openID, half)
		if err != nil {
			t.Errorf("ReadHalf(%s) on a sealed live audit: %v", half, err)
		}
		if !seal.Readable() {
			t.Errorf("ReadHalf(%s) returned a seal that says it is not readable", half)
		}
	}
}

// ---------------------------------------------------------------------------
// THE SOURCE GUARD — reachability, not a whitelist of today's return types
// ---------------------------------------------------------------------------
//
// # What defeated the previous version of this guard, twice
//
// It flagged an exported function whose RETURN TYPE base name appeared in a
// hardcoded ten-entry map: Manifest, ManifestHalf, CardRef, TaskCard,
// GitHubSarifFile, GitHubSARIFLog, GitHubRun, GitHubResult, HalfSeal,
// AuditSeal. `Result`, `Run`, `SARIFLog`, `[]string` and `[]byte` were not in
// it — and they are the most natural spellings of "hand out a half's results".
// A re-verifier added three entry points and the suite stayed green both
// times:
//
//	func (rd *Reader) LeakResults(l *SARIFLog) []Result
//	func (rd *Reader) LeakLoci(l *SARIFLog) []string
//	func LeakProjectionBytes(l *SARIFLog) ([]byte, error)
//
// They handed out nine results, nine loci and 16.6 KB of record bytes from a
// half that had never sealed. A whitelist of today's return types cannot catch
// tomorrow's function, because the leak is not in the type: `[]byte` is a
// perfectly good way to hand out a record.
//
// # What this asks instead
//
// A BEHAVIOURAL question, answered from the package's own AST: can this
// exported entry point reach a half's results, and if it can, does the same
// call graph also reach the read gate?
//
//	reaches results — the entry point, or an unexported function it calls
//	                  within this package, reads `.Results` or `.Runs`; or the
//	                  entry point is handed (or hands back) a whole *SARIFLog,
//	                  a whole *Run, or Results themselves. The second arm is
//	                  what catches LeakProjectionBytes, which can marshal the
//	                  record it was given without ever spelling `.Results`.
//	reaches the gate — the same call graph CALLS HalfReadGate,
//	                  halfReadRefusal, Readable or readOrder, AND USES what
//	                  that call returned. A mention is not a call and a
//	                  discarded result is not obedience; see
//	                  "WHAT 'REACHES THE GATE' MEANS" below.
//
// # WHAT "REACHES THE GATE" MEANS — A CALL WHOSE RESULT IS USED
//
// This used to be a MENTION: marks() set reachesGate on any *ast.Ident whose
// name was in gateGateNames. An adversary ran sixteen attacks at the guard and
// that one definition lost it two of them outright:
//
//	ATTACK 9   call HalfReadGate, assign the error to `_`, return the results
//	           anyway. A call, obeyed by nobody.
//	ATTACK 10  never touch the gate at all; declare a local variable NAMED
//	           readOrder and return every result. Not even a call.
//
// So the analysis now requires BOTH halves:
//
//   - a CALL. gateCalleeName resolves the callee of an *ast.CallExpr — an
//     identifier, or the selector of a method call — and only a callee whose
//     name is in gateGateNames counts. A bare identifier, a struct field
//     called Readable, a local variable named readOrder, a string constant:
//     none of them are calls, so none of them count.
//   - a USED RESULT. gateDiscardedCalls marks every call whose result is
//     thrown away: a call in statement position, a call under `go` or
//     `defer`, and a call assigned entirely to the blank identifier. A
//     discarded call does not count. CHECKING the error is what obeying the
//     gate means; `_ = HalfReadGate(id, seal)` checks nothing.
//
// One case is deliberately left to the Go compiler rather than duplicated
// here: `err := HalfReadGate(...)` followed by no use of `err` does not
// compile ("declared and not used"), so this analysis does not need to chase
// it. `err = HalfReadGate(...)` into an already-declared err does compile, and
// is not caught — see the KNOWN LIMITS section.
//
// # HOW HONEST IS THIS? IT IS A HEURISTIC, NOT A PROOF
//
// Stated plainly so nobody mistakes a green run for a guarantee:
//
//   - The call graph is resolved by NAME. A call `x.Foo()` is treated as
//     reaching every method named Foo in the package, because this test does
//     not type-check. That over-approximates in both directions: it can decide
//     a function reaches results when its real callee does not, and it can
//     decide a function reaches the gate when the method that actually runs
//     is a different Foo.
//   - It follows CallExprs only. A function reached through a func-typed
//     STRUCT FIELD, a func value in a map, an interface method, or reflection
//     is invisible to it — `rd.Blobs(ref, raw)` is already such a call.
//     Package-level func-typed VARIABLES initialised with a func literal ARE
//     followed, both as entry points and as callees; that was attacks 11 and
//     13 and it is closed.
//   - Reaching the gate in the call graph is not the same as OBEYING it with
//     the RIGHT seal. The call must now be a call and its result must be
//     used, but nothing here checks that the seal handed to the gate is the
//     seal of the half whose results are being returned. That is attacks 14
//     and 15, and they are open: read the KNOWN LIMITS section before you
//     trust a green run.
//   - `readOrder` counts as reaching the gate, so if readOrder ITSELF were
//     rewritten to ask one arm — which is precisely what CRITIQUE-03 M1 was —
//     this test would still pass. MEASURED, by putting that defect back: this
//     guard stayed green and three others went red, including
//     TestReadGateArmsAppearOnlyInsideTheGate, which is the test that owns
//     that hazard. The three guards are a set, and none of them is the
//     whole answer.
//
// Its value is not completeness. Its value is that the OBVIOUS bypass — the
// one someone actually writes, which is a new exported function that walks
// `l.Runs` and returns what it finds — cannot be added silently. All four
// historical bypasses in sealing.go's list were exactly that shape, and so
// were all three of the re-verifier's.
//
// TestTheSourceGuardCatchesTheLeaksThatDefeatedItsPredecessor synthesises
// those three signatures and asserts this analysis flags each one, so the
// guard is never again shipped without having been seen to fail.
// TestTheSourceGuardCatchesTheAdversarysDefeats does the same for the six
// adversarial shapes that beat it afterwards.

// ===========================================================================
// KNOWN LIMITS OF THE SOURCE GUARD — A NON-EXHAUSTIVE LIST OF OPEN HOLES
// ===========================================================================
//
// READ THIS BEFORE YOU TRUST A GREEN RUN. Everything below is a hole that is
// OPEN, with the reasoning written down. A guard whose limits are written down
// is a tool; one whose limits are implied is a trap.
//
// THIS LIST IS NOT A CENSUS, AND TREATING IT AS ONE IS THE MISTAKE THIS
// PARAGRAPH EXISTS TO PREVENT. An earlier draft of this section listed two
// attacks and read as though it were complete. A second adversary then found
// three more in one sitting (recorded as NEW A/B/C below) and judged the
// section "adequate for 14 and 15 specifically, but FALSE AS A CENSUS". That
// judgement was correct. Assume there are further holes not listed here.
//
// WHAT THIS GUARD IS FOR, stated plainly so it is not over-trusted:
// it catches ACCIDENTAL bypass. That is not a small thing — FIVE independent
// authors re-derived the read gate locally and all five got it wrong, none of
// them adversarially, and CRITIQUE-02 and CRITIQUE-03 caught four of those in
// shipped code. Every shape someone writes by mistake is caught: the
// unexported-helper walk, the callback form, the struct-containing-results,
// the count-only projection, and marshalling the record you were handed
// without ever naming a field.
//
// WHAT THIS GUARD IS NOT: a security boundary. Obedience is matched BY NAME,
// so a caller can mint its own — see NEW C. Static reachability cannot
// distinguish calling the gate from obeying it about the right seal for the
// right halves. Do not cite a green run as evidence that no exported function
// can leak a half's results. It is not that, and it cannot be made into that
// without a different technique (go/types + SSA def-use, or the runtime
// redesign described under attack 15, which is the one worth doing).
//
// THREE FURTHER OPEN HOLES, found by the second adversary after the six
// cheap ones were closed. Not fixed; recorded so the list is honest.
//
// NEW A — satisfy "the error is used" while ignoring the refusal.
//   gateDiscardedCalls only marks statement-position calls, go/defer, and
//   whole-blank assignment. Three shapes slip past, all compiling:
//     A1  if err := HalfReadGate(...); err != nil { log.Printf(...) }  then
//         return every result. The error is checked, the branch is taken, and
//         the function proceeds anyway. This is the single most LIKELY of all
//         the open holes to occur by accident rather than by intent.
//     A2  _ = fmt.Sprintf("%v", HalfReadGate(...)) — the blank-assign marker
//         tags the outer call; the inner gate call counts as used.
//     A3  errs := []error{HalfReadGate(...)}; _ = errs
//
// NEW B — a method promoted from an EMBEDDED unexported type. Enumeration
//   admits an unexported receiver only when an exported function RETURNS that
//   type. Embedding is a third route into a caller's hands and neither
//   enumeration inspects it: an unexported type with a leaking method,
//   embedded in an exported zero-value-usable struct, needs no constructor.
//   Proven from OUTSIDE the package: an external package obtained results
//   through it and the guard never enumerated the method at all.
//
// NEW C — mint your own obedience by name. The callee is resolved to a bare
//   string and matched against gateGateNames; nothing checks the callee IS the
//   gate. C2 is the cheap form and it directly contradicts the fix for attack
//   10: attack 10 was "declare a local variable named readOrder", the fix
//   demanded a CALL, so make the local variable a func and call it —
//     readOrder := func(*SARIFLog) []orderedResult { return nil }
//   One pair of parentheses over the attack the fix was written against.
//   Closing this needs the callee to resolve to a package-level declaration,
//   not to any identifier that happens to carry the name.
//
// The body-hash allowlist survived every attempt, including collision and
// staleness. Its one real weakness is procedural rather than static: the
// failure message prints the new hash, which invites a copy-paste that
// re-grants the exemption without anyone re-reading the reason.
//
// TestResultReachingEntryPointsAreGated answers exactly one question:
//
//	does the call graph of this exported entry point CALL the read gate and
//	USE what the call returned?
//
// It does NOT answer, and cannot answer, "did it call the gate about the
// RIGHT half, with the RIGHT seal, and honour the answer for ALL of the
// results it went on to return". Those are dataflow questions — which value
// flowed into which parameter, and which values flowed out — and an AST
// reachability walk that pretended to answer them would hand out exactly the
// false confidence this whole exercise exists to avoid. Two attacks live in
// that gap. Both were run against this guard. Both won. Both still win.
//
// ---------------------------------------------------------------------------
// LIMIT 1 (adversary attack 14) — THE FABRICATED SEAL
// ---------------------------------------------------------------------------
//
// Call the gate. Check the error. Return the results. But hand the gate a
// HalfSeal you built yourself rather than the seal of the half you are about
// to read:
//
//	func (rd *Reader) LeakViaFabricatedSeal(l *SARIFLog) []Result {
//	        seal := HalfSeal{Half: HalfSast, Status: HalfStatusSealed, ...}
//	        if err := HalfReadGate(l.Properties.AuditID, seal); err != nil {
//	                return nil
//	        }
//	        var out []Result
//	        for ri := range l.Runs {
//	                out = append(out, l.Runs[ri].Results...)
//	        }
//	        return out
//	}
//
// To this guard that is a textbook obedient function: a real *ast.CallExpr on
// HalfReadGate, the returned error consumed by an `if`, an early return on
// refusal. Every structural property it checks is satisfied. The gate was
// asked a question about a half that does not exist and it answered honestly.
//
// WHAT A READER MUST NOT CONCLUDE: that a green
// TestResultReachingEntryPointsAreGated means the gate was consulted ABOUT the
// data returned. It means a gate call happened somewhere in the call graph and
// its result was not thrown away. The seal's provenance is unchecked.
//
// WHAT WOULD ACTUALLY CATCH IT: dataflow. The HalfSeal argument at the call
// site must be traced to its definition and required to originate from
// halfSealOfRun (or Sealer.HalfSeal) applied to the same record the results
// are read from — a def-use chain, needing go/types and SSA, not an
// ast.Inspect. Or, cheaper and stronger, a RUNTIME assertion: give HalfSeal an
// unexported provenance field that only halfSealOfRun and the Sealer can set,
// and have HalfReadGate refuse any seal without it. A fabricated composite
// literal then cannot be handed to the gate at all, and the hole closes in the
// production code rather than in a test that inspects it.
//
// ---------------------------------------------------------------------------
// LIMIT 2 (adversary attack 15) — OBEY FOR ONE HALF, RETURN BOTH
// ---------------------------------------------------------------------------
//
// Call the gate. Check the error. Obey it — for the SAST half. Then return
// every result in the record, DAST included:
//
//	func (rd *Reader) LeakViaPartialObedience(l *SARIFLog) []Result {
//	        for ri := range l.Runs {
//	                if l.Runs[ri].Properties.Half != HalfSast {
//	                        continue
//	                }
//	                if err := HalfReadGate(l.Properties.AuditID,
//	                        halfSealOfRun(l, &l.Runs[ri])); err != nil {
//	                        return nil
//	                }
//	        }
//	        var out []Result
//	        for ri := range l.Runs {
//	                out = append(out, l.Runs[ri].Results...)
//	        }
//	        return out
//	}
//
// Here the seal is genuine — halfSealOfRun over the real record — so even the
// provenance idea above would not fire. The defect is that the SET of halves
// the gate was consulted about is smaller than the SET of halves whose results
// were returned. An unsealed DAST half walks out behind a sealed SAST half's
// permission.
//
// WHAT A READER MUST NOT CONCLUDE: that a gated entry point is gated for every
// half it can return. This guard counts gate calls; it does not pair them with
// the results that leave. One honest gate call covers an entry point that
// hands out ten halves.
//
// WHAT WOULD ACTUALLY CATCH IT: dataflow again, and a harder instance —
// correlating the loop that queries the gate with the loop that accumulates
// the output, per half. Statically that is a per-index dependence analysis.
// The practical answer is not static at all: make the gate the only route to a
// result. If the results of a half were reachable only through a value that
// HalfReadGate returns — a readable-half handle, rather than a permission slip
// checked beside a []Result the caller already had — then returning the DAST
// results would require a DAST handle, and the compiler would demand a second
// gate call. That is a change to readpath.go's shape, not to this test.
//
// ---------------------------------------------------------------------------
// SMALLER OPEN EDGES, LISTED SO THEY ARE NOT DISCOVERIES LATER
// ---------------------------------------------------------------------------
//
//   - `err = HalfReadGate(...)` into an ALREADY-DECLARED err, never read
//     afterwards, counts as a used result here. The `:=` form of the same
//     mistake does not compile, so the compiler carries most of this; the `=`
//     form would need liveness analysis and does not get it.
//   - A func-typed STRUCT FIELD or map entry is still not followed.
//     `rd.Blobs(ref, raw)` is already such a call. Package-level func-literal
//     VARIABLES are followed (attacks 11 and 13); fields are not.
//   - A func-typed package-level variable declared WITHOUT a literal —
//     `var Hook ReadFunc` assigned at init — has no body to index and is
//     invisible.
//   - The allowlist body hash covers the body, not the SIGNATURE and not the
//     functions the body calls. Moving the leak one level down, into an
//     unexported helper an allowlisted function already called, changes the
//     helper rather than the allowlisted body. The reachability analysis is
//     what covers that direction, and only for entry points it enumerates.
//
// ---------------------------------------------------------------------------
// WHAT IS ACTUALLY LOAD-BEARING TODAY
// ---------------------------------------------------------------------------
//
// The behavioural half of the pair, TestEveryResultBearingEntryPointIsGated,
// RUNS every listed entry point against records in which no half is readable
// and counts what came back. It would catch both attacks above — on the entry
// points that are IN gateAuditedEntryPoints. That list is maintained by hand.
// The source guard's whole job is to notice when something is missing from it.
//
// So the honest summary of the pair is: the source guard says "a new exported
// function that reaches results without asking the gate cannot be added
// silently", and the behavioural guard says "the entry points we know about
// hand out nothing when nothing is readable". Neither says "no exported
// function can leak a half's results". Nothing in this package says that.

// gateResultAccess are the field reads that mean "this body can get at a
// half's findings". `.Runs` is included because reaching the runs is how a
// caller reaches the results inside them, and a function that walks `l.Runs`
// and stops short of `.Results` still holds every half in the record.
var gateResultAccess = map[string]bool{"Results": true, "Runs": true}

// gateGateNames are the four spellings of "this call graph asked the read
// gate". readOrder is included because it is readpath.go's own gated entry to
// the results and every card is built from what it returns.
//
// These are CALLEE names, matched against the function position of an
// *ast.CallExpr and nowhere else. A local variable named readOrder, a struct
// field named Readable, or a comment naming HalfReadGate is not a call and
// does not count; that was adversary attack 10.
var gateGateNames = map[string]bool{
	"HalfReadGate":    true,
	"halfReadRefusal": true,
	"Readable":        true,
	"readOrder":       true,
}

// gateRecordTypes are the types that CONTAIN a half's results. An entry point
// handed one, or handing one back, can project the results out of it with no
// field access this analysis would otherwise see.
var gateRecordTypes = map[string]bool{"SARIFLog": true, "Run": true, "Result": true}

// gateSourceIndex is the parsed package: every function body, indexed the two
// ways a call site can name one.
//
// "Function body" includes package-level VARIABLES initialised with a func
// literal — `var Foo = func(l *SARIFLog) []Result { ... }`. Such a variable is
// a callable value with a body, so it is synthesised into an *ast.FuncDecl and
// indexed exactly like a declared function. That is what closes adversary
// attacks 11 (hide the results read behind a package-level func value) and 13
// (an exported package-level func-typed variable, which is public API in every
// sense that matters to a caller).
type gateSourceIndex struct {
	fset     *token.FileSet           // positions, for printing bodies to hash
	decl     map[string]*ast.FuncDecl // "Func" or "Recv.Method" -> body
	file     map[string]string        // the same key -> base filename
	byName   map[string][]string      // plain function name -> keys
	byMethod map[string][]string      // method name -> keys (any receiver)
	funcVar  map[string]bool          // key was a package-level func-literal var
	keys     []string                 // every key, sorted
}

// gateParseSource parses the package's non-test files into a gateSourceIndex.
func gateParseSource(t *testing.T) *gateSourceIndex {
	t.Helper()
	files, fset := gatePackageFiles(t)
	return gateIndexFiles(t, files, fset)
}

// gatePackageFiles parses every non-test file of the package, keyed by path,
// and returns the FileSet those files were parsed into. The FileSet is needed
// because the allowlist hashes function BODIES, and printing a body back to
// source requires the positions it was parsed with.
func gatePackageFiles(t *testing.T) (map[string]*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package source: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("parsed no packages; this test asserts nothing unless it reads the source")
	}
	out := map[string]*ast.File{}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			out[path] = file
		}
	}
	return out, fset
}

// gateIndexFiles builds the call-graph index over a set of parsed files. It
// takes the files rather than reading the directory so that
// TestTheSourceGuardCatchesTheLeaksThatDefeatedItsPredecessor and
// TestTheSourceGuardCatchesTheAdversarysDefeats can index the real package
// PLUS a synthetic leak file and run the identical analysis.
func gateIndexFiles(t *testing.T, files map[string]*ast.File, fset *token.FileSet) *gateSourceIndex {
	t.Helper()
	idx := &gateSourceIndex{
		fset:     fset,
		decl:     map[string]*ast.FuncDecl{},
		file:     map[string]string{},
		byName:   map[string][]string{},
		byMethod: map[string][]string{},
		funcVar:  map[string]bool{},
	}
	add := func(path string, key string, fn *ast.FuncDecl) {
		idx.decl[key] = fn
		idx.file[key] = filepath.Base(path)
		idx.keys = append(idx.keys, key)
	}
	for path, file := range files {
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				key := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) == 1 {
					recv := gateBaseTypeName(d.Recv.List[0].Type)
					if recv == "" {
						continue
					}
					key = recv + "." + d.Name.Name
					idx.byMethod[d.Name.Name] = append(idx.byMethod[d.Name.Name], key)
				} else {
					idx.byName[key] = append(idx.byName[key], key)
				}
				add(path, key, d)
			case *ast.GenDecl:
				// `var Foo = func(...) {...}` is a function with a name, a
				// signature and a body. Index it as one — attacks 11 and 13.
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.FuncLit)
						if !ok || lit.Body == nil || name.Name == "_" {
							continue
						}
						key := name.Name
						if _, dup := idx.decl[key]; dup {
							continue
						}
						idx.byName[key] = append(idx.byName[key], key)
						idx.funcVar[key] = true
						add(path, key, &ast.FuncDecl{
							Name: name,
							Type: lit.Type,
							Body: lit.Body,
						})
					}
				}
			}
		}
	}
	sort.Strings(idx.keys)
	return idx
}

// callees returns the package-local functions the body of key can call,
// resolved by name. See the honesty section above: this is an
// over-approximation, and deliberately so.
func (idx *gateSourceIndex) callees(key string) []string {
	fn := idx.decl[key]
	if fn == nil {
		return nil
	}
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			out = append(out, idx.byName[f.Name]...)
		case *ast.SelectorExpr:
			// `json.Marshal` resolves to nothing: byMethod holds only this
			// package's own methods.
			out = append(out, idx.byMethod[f.Sel.Name]...)
		}
		return true
	})
	return out
}

// gateBodyMarks is what one function body was seen to do, before any call
// graph is followed.
type gateBodyMarks struct {
	readsResults bool
	reachesGate  bool
}

func (idx *gateSourceIndex) marks(key string) gateBodyMarks {
	var m gateBodyMarks
	fn := idx.decl[key]
	if fn == nil {
		return m
	}
	discarded := gateDiscardedCalls(fn.Body)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			if gateResultAccess[e.Sel.Name] {
				m.readsResults = true
			}
		case *ast.CallExpr:
			// A CALL to the gate, whose ANSWER is used. Neither half is
			// optional: a mention is attack 10 and a discarded error is
			// attack 9.
			if gateGateNames[gateCalleeName(e.Fun)] && !discarded[e] {
				m.reachesGate = true
			}
		}
		return true
	})
	return m
}

// gateCalleeName is the name a call site uses for its callee: `f()` -> "f",
// `x.f()` -> "f", `f[T]()` -> "f". Anything else — a call through a func
// literal, an index into a map of funcs, a conversion — returns "", which no
// gate name matches.
//
// This is the ONLY place a gate name may be recognised. Matching bare
// identifiers is what let a local variable named readOrder pass for obedience.
func gateCalleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.IndexExpr:
		return gateCalleeName(f.X)
	case *ast.IndexListExpr:
		return gateCalleeName(f.X)
	case *ast.ParenExpr:
		return gateCalleeName(f.X)
	}
	return ""
}

// gateDiscardedCalls returns every call in the body whose result is thrown
// away. A gate call in this set is not obedience:
//
//   - a call in statement position — `HalfReadGate(id, seal)` on its own line;
//   - a call under `go` or `defer`, whose result is unreachable by
//     construction;
//   - a call assigned entirely to the blank identifier — `_ = HalfReadGate(...)`,
//     which is adversary attack 9, and `_, _ = f()`.
//
// The 1:1 assignment form `a, _ := f(), g()` is handled per position, so the
// g() there is discarded and the f() is not.
//
// Assigning to a NAMED variable counts as used. The case that leaves —
// assigning to a named variable and then never reading it — is caught by the
// Go compiler for `:=` ("declared and not used") and is documented as open for
// `=` in the KNOWN LIMITS section.
func gateDiscardedCalls(body *ast.BlockStmt) map[*ast.CallExpr]bool {
	out := map[*ast.CallExpr]bool{}
	mark := func(e ast.Expr) {
		if c, ok := e.(*ast.CallExpr); ok {
			out[c] = true
		}
	}
	allBlank := func(lhs []ast.Expr) bool {
		for _, e := range lhs {
			id, ok := e.(*ast.Ident)
			if !ok || id.Name != "_" {
				return false
			}
		}
		return len(lhs) > 0
	}
	isBlank := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "_"
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ExprStmt:
			mark(s.X)
		case *ast.GoStmt:
			out[s.Call] = true
		case *ast.DeferStmt:
			out[s.Call] = true
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				// One call feeding every LHS: discarded only if no LHS
				// keeps anything.
				if allBlank(s.Lhs) {
					mark(s.Rhs[0])
				}
				return true
			}
			for i := range s.Rhs {
				if i < len(s.Lhs) && isBlank(s.Lhs[i]) {
					mark(s.Rhs[i])
				}
			}
		}
		return true
	})
	return out
}

// gateIsGateFunc reports whether a call-graph key IS one of the gate
// functions: "HalfReadGate", "HalfSeal.Readable", "Reader.readOrder".
func gateIsGateFunc(key string) bool {
	name := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		name = key[i+1:]
	}
	return gateGateNames[name]
}

// reach walks the call graph from key and returns the union of every body's
// marks, key's own included.
//
// THE GATE'S OWN BODY IS NOT TRAVERSED. halfReadRefusal calls the gate's
// arms, and HalfReadGate calls halfReadRefusal and uses its answer — so a
// closure that descended into them would mark EVERY caller of HalfReadGate as
// gate-reaching, including one that calls it and throws the error away. That
// is precisely adversary attack 9, and it is why obedience is established at
// the CALL SITE and nowhere else: a used call to the gate, in a body in this
// closure. What the gate does internally is the gate's business.
//
// The root is always marked, even when the root itself is a gate function, so
// that a leak named `Readable` cannot buy an exemption with its own name.
func (idx *gateSourceIndex) reach(key string) gateBodyMarks {
	var out gateBodyMarks
	seen := map[string]bool{key: true}
	queue := []string{key}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		m := idx.marks(cur)
		out.readsResults = out.readsResults || m.readsResults
		out.reachesGate = out.reachesGate || m.reachesGate
		for _, next := range idx.callees(cur) {
			if seen[next] || gateIsGateFunc(next) {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
	return out
}

// handlesRecord reports whether the entry point's own signature takes or
// returns a whole record, a whole run, or results — the arm that catches a
// function which marshals what it was handed without ever naming a field.
func gateHandlesRecord(fn *ast.FuncDecl) bool {
	fields := []*ast.Field{}
	if fn.Recv != nil {
		fields = append(fields, fn.Recv.List...)
	}
	if fn.Type.Params != nil {
		fields = append(fields, fn.Type.Params.List...)
	}
	if fn.Type.Results != nil {
		fields = append(fields, fn.Type.Results.List...)
	}
	for _, f := range fields {
		if gateRecordTypes[gateBaseTypeName(f.Type)] {
			return true
		}
	}
	return false
}

// gateVerdict is what the analysis concludes about one entry point.
type gateVerdict int

const (
	// gateNoResults: nothing in this call graph can get at a half's findings.
	gateNoResults gateVerdict = iota
	// gateGated: it can, and the same call graph asks the read gate.
	gateGated
	// gateUngated: it can, and nothing in the call graph asks the gate. This
	// is the finding.
	gateUngated
)

// classify is THE analysis. Both the guard and its own negative control call
// it, so the control cannot pass against a different code path than the one
// that ships.
func (idx *gateSourceIndex) classify(key string) gateVerdict {
	fn := idx.decl[key]
	if fn == nil {
		return gateNoResults
	}
	r := idx.reach(key)
	if !r.readsResults && !gateHandlesRecord(fn) {
		return gateNoResults
	}
	if r.reachesGate {
		return gateGated
	}
	return gateUngated
}

// gateHandedOutTypes returns the set of UNEXPORTED type names that an exported
// function or method hands back to a caller outside the package.
//
// A caller who holds such a value can call every exported method on it, and
// the receiver's case is irrelevant to that: `func NewThing() *thing` makes
// every exported method on `thing` public API. Adversary attack 12 was exactly
// this — an exported method on an unexported receiver, handed out by an
// exported constructor — and the previous entry-point scan skipped it on the
// strength of the receiver's lower-case letter.
func (idx *gateSourceIndex) gateHandedOutTypes() map[string]bool {
	out := map[string]bool{}
	for _, key := range idx.keys {
		fn := idx.decl[key]
		if !fn.Name.IsExported() {
			continue
		}
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			// Only count returns from something a caller can already reach.
			if recv := gateBaseTypeName(fn.Recv.List[0].Type); !ast.IsExported(recv) {
				continue
			}
		}
		if fn.Type.Results == nil {
			continue
		}
		for _, res := range fn.Type.Results.List {
			if name := gateBaseTypeName(res.Type); name != "" && !ast.IsExported(name) {
				out[name] = true
			}
		}
	}
	return out
}

// exportedEntryPoints returns the keys of every exported function, method and
// package-level func-literal variable reachable from outside the package,
// sorted.
//
// "Reachable from outside" is deliberately broader than "the receiver type is
// exported": see gateHandedOutTypes for attack 12, and gateSourceIndex for
// attack 13.
func (idx *gateSourceIndex) exportedEntryPoints() []string {
	handedOut := idx.gateHandedOutTypes()
	var out []string
	for _, key := range idx.keys {
		fn := idx.decl[key]
		if !fn.Name.IsExported() {
			continue
		}
		if fn.Recv != nil {
			recv := gateBaseTypeName(fn.Recv.List[0].Type)
			// A method on an unexported type is a public bypass exactly when
			// an exported function hands that type out. If nobody can obtain
			// the receiver, nobody can call the method.
			if !ast.IsExported(recv) && !handedOut[recv] {
				continue
			}
		}
		out = append(out, key)
	}
	return out
}

// gateExemption is one allowlist entry: why this entry point is not a leak,
// and the hash of the BODY that claim was made about.
//
// AN ALLOWLIST ENTRY IS A CLAIM ABOUT A BODY, NOT ABOUT A NAME. Adversary
// attack 16 was to leave the name alone and rewrite what the function does:
// the exemption was written for one implementation and silently inherited by
// another. The hash makes that impossible — change the body and the claim
// expires, the suite goes red, and the author has to re-read the reason and
// re-justify it against the code that is actually there now.
type gateExemption struct {
	// reason is the justification. A reason, never a shrug.
	reason string

	// body is gateBodyHash of the function body at the moment the reason was
	// written. Re-run the test after an intentional change: the failure
	// message carries the new hash.
	body string
}

// gateBodyHash is the identity of a function BODY: the body printed back to Go
// source, re-tokenised, and the TOKEN STREAM hashed, truncated to 16 hex
// characters.
//
// What it covers and what it does not, so the failure message can be trusted:
//
//   - it covers statements, expressions, names, literals and structure —
//     anything that changes what the function DOES;
//   - it does not cover comments, whitespace, indentation, blank lines or line
//     endings, because the hash is over tokens. Re-wording a comment inside an
//     allowlisted function does not expire its exemption, and neither does
//     gofmt or a CRLF checkout. A hash that expired on every doc edit would be
//     deleted by the third person it annoyed, and then attack 16 would be open
//     again with nobody noticing;
//   - it does not cover the SIGNATURE. A signature change that makes the
//     function newly result-reaching is caught by the analysis itself, and one
//     that does not is not interesting.
func (idx *gateSourceIndex) gateBodyHash(key string) string {
	fn := idx.decl[key]
	if fn == nil || fn.Body == nil || idx.fset == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := (&printer.Config{Mode: printer.RawFormat, Tabwidth: 8}).
		Fprint(&buf, idx.fset, fn.Body); err != nil {
		return ""
	}
	src := buf.Bytes()

	// Re-tokenise the printed body. Everything the compiler ignores — layout
	// and comments — is discarded here, so only a change in what the code says
	// can change the hash.
	var fs token.FileSet
	var sc scanner.Scanner
	sc.Init(fs.AddFile("", fs.Base(), len(src)), src, nil, 0)
	var stream strings.Builder
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		stream.WriteString(tok.String())
		if lit != "" {
			stream.WriteByte('\x1f')
			stream.WriteString(lit)
		}
		stream.WriteByte('\x1e')
	}
	sum := sha256.Sum256([]byte(stream.String()))
	return hex.EncodeToString(sum[:])[:16]
}

// gateUngatedAllowlist names the exported entry points that CAN reach a half's
// results but legitimately do not ask the read gate, each with the reason and
// the hash of the body that reason was written about.
//
// An allowlist with reasons is a different object from a whitelist of types.
// The whitelist said "these shapes are interesting"; a new shape walked past
// it. This says "these named function BODIES have been looked at, and here is
// why each one is not a leak" — a new function is not on it, so a new function
// is flagged, and a rewritten body is not the body that was looked at.
//
// TestResultReachingEntryPointsAreGated fails if an entry stops matching a
// real, still-ungated, still-result-reaching function, so the list cannot rot
// into a blanket: delete the function and the entry must go with it. It fails
// again if the body no longer hashes to the recorded value.
func gateUngatedAllowlist() map[string]gateExemption {
	return map[string]gateExemption{
		// ---- the SOURCE side: these hand the record IN --------------------
		"RecordMap.Record": {body: "25391599143667fe", reason: "the RecordSource a Reader loads FROM. It hands a record in, to a " +
			"read path that then applies the gate; it is the gate's input, not its output. " +
			"Callers outside this package supply their own RecordSource and this one is a " +
			"test/in-memory convenience."},
		"RecordSourceFunc.Record": {body: "c62370d3dae715ab", reason: "the func adapter for RecordSource, same direction and same " +
			"reason as RecordMap.Record: it returns whatever the caller's own function returns."},

		// ---- the PRODUCER side: these run before a half is readable -------
		"SARIFLog.Validate": {body: "5e4bedd55119ae6e", reason: "contract.go's producer-side validator. It walks every run to check " +
			"the record is well-formed and returns only an error; validation must work on a " +
			"record NO half of which has sealed yet, so gating it would make an unsealed " +
			"record unvalidatable."},
		"MaskRecord": {body: "1d1496b8964a1f30", reason: "R.8's masker, which runs BEFORE the read path and is the precondition " +
			"Reader.load asserts. It mutates the record in place and returns only an error. " +
			"Masking an unsealed half is exactly what it is for."},
		"Masker.Mask": {body: "3b1f1725f1f6decc", reason: "the same masker with a report. The report counts what was masked; it " +
			"carries no finding content out of a half."},
		"AssertMasked": {body: "930534f795ec1a22", reason: "the masking precondition itself, called by Reader.load before anything " +
			"is projected. It answers 'has R.8 run', not 'may this half be read'."},

		// ---- pure functions over data the caller ALREADY holds ------------
		"Result.ExternalStringPointers": {body: "b598635db55a205e", reason: "a pure accessor on a Result the caller already holds. " +
			"It cannot obtain one: whoever calls it got the Result from somewhere, and that " +
			"somewhere is what the gate covers."},
		"ValidateResultTrust": {body: "df1846aeedb2981a", reason: "a validator over one caller-held Result, returning only an error."},
		"IsHostFinding": {body: "eaf63949394f43ee", reason: "a pure predicate over one caller-held Result. It reads two enum fields " +
			"and returns a bool."},
		"Correlate": {body: "2f5772b9f31ae65b", reason: "the correlation engine (R.12). It is handed two []Result by the PRODUCER, " +
			"before either half is consumable, and returns clusters rather than results. " +
			"Gating it would mean no audit could ever be correlated."},
		"CorrelateWithEvidence": {body: "58f2c8a2f9b29cc0", reason: "the same engine with the evidence bundle; same direction and " +
			"same reason as Correlate."},
		"TaskCard.CheckAgainstRecord": {body: "3dcdcd66f256a036", reason: "the card's own agreement check against the Result it was " +
			"built from — a card the gate already emitted, compared with a result the caller " +
			"already holds. It returns only an error."},

		// ---- already-projected output ------------------------------------
		"GitHubSarifFile.WithinCaps": {body: "cd3276a9b07eb740", reason: "a cap check over an ALREADY-PROJECTED GitHub file. " +
			"ProjectForGitHub applies the gate; what survives into a GitHubSarifFile is what " +
			"the gate let through, and counting it again cannot un-withhold anything."},
	}
}

// TestResultReachingEntryPointsAreGated is the guard. See the long section
// above for what it asks, and for the three ways it can be fooled.
func TestResultReachingEntryPointsAreGated(t *testing.T) {
	idx := gateParseSource(t)
	allow := gateUngatedAllowlist()

	entries := idx.exportedEntryPoints()
	if len(entries) == 0 {
		t.Fatal("the source scan found no exported entry points at all; the scan is broken " +
			"and this test is guarding nothing")
	}

	var reaching, gated []string
	allowed := map[string]bool{}
	for _, key := range entries {
		verdict := idx.classify(key)
		if verdict == gateNoResults {
			continue
		}
		reaching = append(reaching, key)
		if verdict == gateGated {
			gated = append(gated, key)
			continue
		}
		if ex, ok := allow[key]; ok {
			allowed[key] = true
			if strings.TrimSpace(ex.reason) == "" {
				t.Errorf("%s is allowlisted with an empty reason; an allowlist without reasons "+
					"is the whitelist this guard replaced", key)
			}
			// ATTACK 16: the exemption was granted to a BODY. If the body
			// changed, the exemption did not survive it.
			got := idx.gateBodyHash(key)
			switch {
			case got == "":
				t.Errorf("%s is allowlisted but its body could not be hashed; the exemption "+
					"cannot be checked and must not be trusted", key)
			case strings.TrimSpace(ex.body) == "":
				t.Errorf("%s is allowlisted with no body hash. An allowlist entry is a claim "+
					"about a BODY, not about a name. Record body: %q.", key, got)
			case ex.body != got:
				t.Errorf("%s (%s) is allowlisted, but its body has CHANGED since the exemption "+
					"was written.\n"+
					"    recorded body hash %s\n"+
					"    current  body hash %s\n"+
					"    The reason on file was written about the old implementation:\n"+
					"      %s\n"+
					"    Re-read the function as it is NOW and decide again whether it can leak\n"+
					"    a half's results. If it still cannot, update the body hash to %s and\n"+
					"    say so in the reason. If it can, route it through HalfReadGate instead.\n"+
					"    An allowlist entry is a claim about a BODY, not about a name.",
					key, idx.file[key], ex.body, got, ex.reason, got)
			}
			continue
		}
		t.Errorf("%s (%s) can reach a half's results and never reaches the read gate.\n"+
			"    Route it through HalfReadGate — or halfSealOfRun + HalfReadGate for a\n"+
			"    record-side caller — and add a probe to gateAuditedEntryPoints; or, if it\n"+
			"    structurally cannot leak, add it to gateUngatedAllowlist WITH THE REASON.\n"+
			"    Five authors have now derived the read gate locally and five got it wrong;\n"+
			"    see sealing.go's read-gate section.", key, idx.file[key])
	}

	// An allowlist entry that no longer names a flagged function is a lie
	// about the code, and the next person to read it inherits the lie.
	for key := range allow {
		if allowed[key] {
			continue
		}
		switch {
		case idx.decl[key] == nil:
			t.Errorf("gateUngatedAllowlist names %q, which no longer exists in the package. "+
				"Delete the entry: an allowlist that outlives its function is a standing "+
				"exemption nobody has read.", key)
		default:
			t.Errorf("gateUngatedAllowlist names %q, which this guard no longer flags "+
				"(it now reaches the gate, or no longer reaches results). Delete the entry: "+
				"a stale exemption is how the next real one gets waved through.", key)
		}
	}

	if len(reaching) == 0 {
		t.Fatal("no exported entry point was found to reach a half's results, which cannot be " +
			"true of this package; the analysis is broken and the guard is inert")
	}
	if len(gated) == 0 {
		t.Fatal("no result-reaching entry point was found to reach the gate either, which cannot " +
			"be true while readOrder exists; the analysis is broken and would pass anything")
	}
	t.Logf("source reachability: %d exported entry points, %d can reach a half's results "+
		"(%d reach the gate, %d allowlisted)", len(entries), len(reaching), len(gated), len(allowed))
	t.Logf("  gated: %s", strings.Join(gated, ", "))
}

// gateIndexWithProbe indexes the REAL package plus one synthetic source file
// and returns the index and the live allowlist. Both negative controls use it,
// so both run the identical analysis against the shipping code — a control
// that indexed only the synthetic file would prove nothing about the guard
// that ships.
func gateIndexWithProbe(t *testing.T, src string) (*gateSourceIndex, map[string]gateExemption) {
	t.Helper()
	files, fset := gatePackageFiles(t)
	probe, err := parser.ParseFile(fset, "zz_gate_leak_probe.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the synthetic probe file: %v", err)
	}
	files["zz_gate_leak_probe.go"] = probe
	return gateIndexFiles(t, files, fset), gateUngatedAllowlist()
}

// gateLeakProbeSource is the re-verifier's three leak functions, verbatim in
// shape, as a synthetic source file in this package.
//
// They are the three that DEFEATED the previous guard — a type whitelist that
// did not name Result, []string or []byte — while handing out nine results,
// nine loci and 16.6 KB of record bytes from a half that had never sealed.
// They live here, as source text rather than as compiled code, so that the
// guard is exercised against them on EVERY run and cannot be shipped again
// without having been seen to fail. A guard that has never failed has not been
// tested; this one fails three times per run, on purpose.
//
// Each is written the way the leak would actually be written: LeakResults and
// LeakLoci walk `l.Runs` and take what they find; LeakProjectionBytes never
// names a field at all and simply marshals the record it was handed, which is
// the case the field-access arm alone would miss.
const gateLeakProbeSource = `package record

import "encoding/json"

func (rd *Reader) LeakResults(l *SARIFLog) []Result {
	var out []Result
	for ri := range l.Runs {
		out = append(out, l.Runs[ri].Results...)
	}
	return out
}

func (rd *Reader) LeakLoci(l *SARIFLog) []string {
	var out []string
	for ri := range l.Runs {
		for si := range l.Runs[ri].Results {
			if p := primaryPath(&l.Runs[ri].Results[si]); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func LeakProjectionBytes(l *SARIFLog) ([]byte, error) {
	return json.Marshal(l)
}
`

// TestTheSourceGuardCatchesTheLeaksThatDefeatedItsPredecessor is the negative
// control for TestResultReachingEntryPointsAreGated.
//
// It indexes the REAL package plus gateLeakProbeSource and runs the identical
// classification — idx.classify, the same function the guard calls — over the
// three synthetic entry points. Each must come back gateUngated, and none may
// appear in the allowlist.
//
// This is what the previous guard never had. It was a type whitelist that had
// never been shown to reject anything, so nobody noticed that the shapes it
// listed were not the shapes a leak takes.
func TestTheSourceGuardCatchesTheLeaksThatDefeatedItsPredecessor(t *testing.T) {
	idx, allow := gateIndexWithProbe(t, gateLeakProbeSource)

	// The control is only meaningful if the real package still classifies
	// correctly alongside the synthetic file.
	if got := idx.classify("Reader.ManifestFromLog"); got != gateGated {
		t.Fatalf("with the leak file indexed, Reader.ManifestFromLog classifies as %v, want "+
			"gateGated; the control is measuring something other than the real analysis", got)
	}

	for _, key := range []string{"Reader.LeakResults", "Reader.LeakLoci", "LeakProjectionBytes"} {
		t.Run(key, func(t *testing.T) {
			if idx.decl[key] == nil {
				t.Fatalf("%s is not in the index; the synthetic file was not read", key)
			}
			if _, ok := allow[key]; ok {
				t.Fatalf("%s is in gateUngatedAllowlist, which would let the control pass "+
					"without the analysis doing anything", key)
			}
			switch idx.classify(key) {
			case gateUngated:
				// The guard would report this one. Correct.
			case gateGated:
				t.Errorf("%s classifies as gateGated: the analysis believes it asks the read "+
					"gate. It does not — it walks the record and returns what it finds.", key)
			case gateNoResults:
				t.Errorf("%s classifies as gateNoResults: the analysis cannot see that it "+
					"reaches a half's results. This is EXACTLY the hole the type whitelist "+
					"had, and %s handed out a half's data through it.", key, key)
			}
		})
	}
}

// ===========================================================================
// THE ADVERSARY'S SIX CLOSED DEFEATS — permanent negative controls
// ===========================================================================
//
// An adversary ran sixteen attacks at this guard and won eight. Six of the
// eight are closed, and each closed shape lives below as source text so the
// guard is re-defeated-and-caught on every run. The two that are NOT closed —
// the fabricated seal and partial obedience — are documented in KNOWN LIMITS
// above and deliberately have no probe here, because a probe that passed would
// be a lie about what this analysis can see.
//
// Every function below is written the way the bypass would actually be
// written. None of them is exotic; that is the point.
const gateAdversaryProbeSource = `package record

// ATTACK 9 — call the gate, assign the answer to the blank identifier, hand
// out the results anyway. A call that nobody obeys.
func (rd *Reader) LeakBlankErrGate(l *SARIFLog) []Result {
	_ = HalfReadGate(l.Properties.AuditID, halfSealOfRun(l, &l.Runs[0]))
	var out []Result
	for ri := range l.Runs {
		out = append(out, l.Runs[ri].Results...)
	}
	return out
}

// ATTACK 9 (variant) — the same, with the call in statement position, which
// discards the error without even naming it.
func (rd *Reader) LeakStatementGate(l *SARIFLog) []Result {
	HalfReadGate(l.Properties.AuditID, halfSealOfRun(l, &l.Runs[0]))
	var out []Result
	for ri := range l.Runs {
		out = append(out, l.Runs[ri].Results...)
	}
	return out
}

// ATTACK 10 — never touch the gate at all. Declare locals NAMED after it and
// return every result. Against a mention-matching analysis this reads as
// obedient; it does not call anything.
func (rd *Reader) LeakNamedLocals(l *SARIFLog) []Result {
	readOrder := 0
	Readable := true
	HalfReadGate := "asked"
	var out []Result
	for ri := range l.Runs {
		readOrder++
		if Readable && HalfReadGate != "" {
			out = append(out, l.Runs[ri].Results...)
		}
	}
	return out
}

// ATTACK 11 — hide the results read behind a package-level func VALUE. The
// exported method's own signature names no record type; everything
// interesting happens inside a variable.
var hiddenLociRead = func(l *SARIFLog) []string {
	var out []string
	for ri := range l.Runs {
		for si := range l.Runs[ri].Results {
			out = append(out, l.Runs[ri].Results[si].RuleID)
		}
	}
	return out
}

func (rd *Reader) LeakLociViaFuncValue() []string {
	return hiddenLociRead(rd.loaded)
}

// ATTACK 12 — an exported method on an UNEXPORTED receiver, handed out by an
// exported constructor. The lower-case receiver is cosmetic: a caller who
// holds the value can call the method.
type leakHandle struct{ log *SARIFLog }

func NewLeakHandle(l *SARIFLog) *leakHandle { return &leakHandle{log: l} }

func (h *leakHandle) Loci() []string {
	var out []string
	for ri := range h.log.Runs {
		for si := range h.log.Runs[ri].Results {
			out = append(out, h.log.Runs[ri].Results[si].RuleID)
		}
	}
	return out
}

// ATTACK 13 — an exported package-level func-typed VARIABLE. Public API in
// every sense a caller cares about, and invisible to a scan that only walks
// FuncDecls.
var LeakExportedFuncVar = func(l *SARIFLog) []Result {
	var out []Result
	for ri := range l.Runs {
		out = append(out, l.Runs[ri].Results...)
	}
	return out
}

// POSITIVE CONTROL — an entry point that actually obeys. It must classify as
// gated, or the new call-and-use rule has been tightened into a rule that
// nothing can satisfy, and the guard would be flagging the whole package.
func (rd *Reader) HonestGatedRead(l *SARIFLog) []Result {
	var out []Result
	for ri := range l.Runs {
		if err := HalfReadGate(l.Properties.AuditID, halfSealOfRun(l, &l.Runs[ri])); err != nil {
			continue
		}
		out = append(out, l.Runs[ri].Results...)
	}
	return out
}
`

// TestTheSourceGuardCatchesTheAdversarysDefeats is the negative control for
// the six attacks that beat the previous version of this analysis.
//
// It indexes the REAL package plus gateAdversaryProbeSource and runs the
// identical classification — idx.classify and idx.exportedEntryPoints, the
// same functions the guard calls. Attacks 9, 10, 11, 12 and 13 must come back
// gateUngated; the honest one must come back gateGated, because a guard that
// flags everything is as useless as one that flags nothing.
func TestTheSourceGuardCatchesTheAdversarysDefeats(t *testing.T) {
	idx, allow := gateIndexWithProbe(t, gateAdversaryProbeSource)

	// The control is only meaningful if the real package still classifies
	// correctly alongside the synthetic file.
	if got := idx.classify("Reader.ManifestFromLog"); got != gateGated {
		t.Fatalf("with the adversary file indexed, Reader.ManifestFromLog classifies as %v, "+
			"want gateGated; the control is measuring something other than the real analysis",
			got)
	}

	entry := map[string]bool{}
	for _, key := range idx.exportedEntryPoints() {
		entry[key] = true
	}

	defeats := []struct {
		key      string
		attack   string
		what     string
		mustBeEP bool // the attack is about ENUMERATION, not just classification
	}{
		{"Reader.LeakBlankErrGate", "9",
			"calls HalfReadGate and assigns the error to the blank identifier", false},
		{"Reader.LeakStatementGate", "9v",
			"calls HalfReadGate in statement position, discarding the error", false},
		{"Reader.LeakNamedLocals", "10",
			"never calls the gate; it declares locals named after it", false},
		{"Reader.LeakLociViaFuncValue", "11",
			"reads the results inside a package-level func value", false},
		{"leakHandle.Loci", "12",
			"is an exported method on an unexported type handed out by NewLeakHandle", true},
		{"LeakExportedFuncVar", "13",
			"is an exported package-level func-typed variable", true},
	}

	for _, d := range defeats {
		t.Run("attack"+d.attack+"_"+d.key, func(t *testing.T) {
			if idx.decl[d.key] == nil {
				t.Fatalf("%s is not in the index; the synthetic file was not read, or "+
					"gateIndexFiles no longer indexes this declaration form", d.key)
			}
			if _, ok := allow[d.key]; ok {
				t.Fatalf("%s is in gateUngatedAllowlist, which would let the control pass "+
					"without the analysis doing anything", d.key)
			}
			if d.mustBeEP && !entry[d.key] {
				t.Fatalf("%s %s, but exportedEntryPoints does not enumerate it, so the guard "+
					"never classifies it at all. Attack %s is open again.",
					d.key, d.what, d.attack)
			}
			switch idx.classify(d.key) {
			case gateUngated:
				// The guard would report this one. Correct.
			case gateGated:
				t.Errorf("%s classifies as gateGated: the analysis believes it asks the read "+
					"gate. It does not — it %s. Attack %s is open again.",
					d.key, d.what, d.attack)
			case gateNoResults:
				t.Errorf("%s classifies as gateNoResults: the analysis cannot see that it "+
					"reaches a half's results, although it %s. Attack %s is open again.",
					d.key, d.what, d.attack)
			}
		})
	}

	// The other half of the claim: obedience is still recognisable.
	t.Run("positive_control_HonestGatedRead", func(t *testing.T) {
		if got := idx.classify("Reader.HonestGatedRead"); got != gateGated {
			t.Errorf("Reader.HonestGatedRead classifies as %v, want gateGated. It calls "+
				"HalfReadGate and checks the error in an if-statement, which is what obeying "+
				"the gate looks like. If this fails, the call-and-use rule rejects real "+
				"obedience and the guard is now noise.", got)
		}
	})
}

// gateAllowlistHashProbeSource and gateAllowlistHashProbeRewritten are the same
// allowlisted-looking function before and after adversary attack 16: the name
// is untouched, the body is not.
const gateAllowlistHashProbeSource = `package record

// ExemptLooking is the shape of an allowlisted entry point: it walks the
// record and returns only an error, so "it carries no finding content out of a
// half" is a true reason to write beside it.
func ExemptLooking(l *SARIFLog) error {
	for ri := range l.Runs {
		if len(l.Runs[ri].Results) == 0 {
			return errors.New("empty half")
		}
	}
	return nil
}
`

const gateAllowlistHashProbeRewritten = `package record

// ExemptLooking is the shape of an allowlisted entry point: it walks the
// record and returns only an error, so "it carries no finding content out of a
// half" is a true reason to write beside it.
func ExemptLooking(l *SARIFLog) error {
	for ri := range l.Runs {
		if len(l.Runs[ri].Results) == 0 {
			return errors.New("empty half")
		}
		leaked = append(leaked, l.Runs[ri].Results...)
	}
	return nil
}
`

const gateAllowlistHashProbeRecommented = `package record

// ExemptLooking: the comment was rewritten and nothing else. The exemption
// must survive this, or every doc edit becomes a false alarm and the hash gets
// deleted by the third person it annoys.
func ExemptLooking(l *SARIFLog) error {
	for ri := range l.Runs {
		// a half with no results is not a half
		if len(l.Runs[ri].Results) == 0 {
			return errors.New("empty half")
		}
	}
	return nil
}
`

// TestAnAllowlistEntryIsAClaimAboutABodyNotAName is the negative control for
// adversary attack 16.
//
// The attack: the allowlist matches by NAME, so rewrite the body of an
// allowlisted function and inherit an exemption that was written about
// something else. gateUngatedAllowlist now records the hash of the body the
// reason was written about, and TestResultReachingEntryPointsAreGated fails
// when the body no longer hashes to it.
//
// This test asserts the two properties that mechanism needs to be worth
// having: a changed body changes the hash, and a changed COMMENT does not. The
// second matters as much as the first — a hash that expires on every doc edit
// is a hash somebody deletes.
func TestAnAllowlistEntryIsAClaimAboutABodyNotAName(t *testing.T) {
	hashOf := func(src string) string {
		t.Helper()
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "zz_gate_hash_probe.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing the synthetic hash probe: %v", err)
		}
		idx := gateIndexFiles(t, map[string]*ast.File{"zz_gate_hash_probe.go": file}, fset)
		h := idx.gateBodyHash("ExemptLooking")
		if h == "" {
			t.Fatal("gateBodyHash returned nothing for the probe; the hash cannot be trusted")
		}
		return h
	}

	original := hashOf(gateAllowlistHashProbeSource)

	if got := hashOf(gateAllowlistHashProbeRewritten); got == original {
		t.Errorf("rewriting the BODY of an allowlisted function did not change its hash "+
			"(both %s). Attack 16 is open: an exemption written about one implementation "+
			"would be inherited by another.", got)
	}
	if got := hashOf(gateAllowlistHashProbeRecommented); got != original {
		t.Errorf("rewriting only a COMMENT changed the body hash (%s -> %s). Every doc edit "+
			"would expire an exemption, which is how the mechanism gets deleted instead of "+
			"maintained.", original, got)
	}

	// And the live allowlist must actually carry hashes: an entry with an
	// empty or placeholder body hash is a name-only claim wearing the costume.
	for key, ex := range gateUngatedAllowlist() {
		if strings.TrimSpace(ex.body) == "" {
			t.Errorf("gateUngatedAllowlist[%q] has no body hash; it is a claim about a name",
				key)
		}
		if strings.Trim(ex.body, "0") == "" {
			t.Errorf("gateUngatedAllowlist[%q] has placeholder body hash %q; record the real "+
				"one", key, ex.body)
		}
	}
}

// TestReadabilityAnsweringEntryPointsAreProbed keeps the behavioural table
// honest for the entry points the reachability analysis cannot speak to: the
// ones that return a SEAL rather than results.
//
// HalfSeal and AuditSeal ARE the readability answer — HalfSeal.Readable is the
// gate as a bool — so a new exported function returning one is a new way to
// answer "may this half be read", and it must be probed against the
// no-half-is-readable scenarios rather than merely reviewed.
//
// This is a coverage check on gateAuditedEntryPoints, not a leak check; the
// leak check is TestResultReachingEntryPointsAreGated above.
func TestReadabilityAnsweringEntryPointsAreProbed(t *testing.T) {
	audited := map[string]bool{}
	for _, e := range gateAuditedEntryPoints() {
		if (e.probe == nil) == (e.exempt == "") {
			t.Errorf("entry %q must have exactly one of probe and exempt", e.name)
		}
		if audited[e.name] {
			t.Errorf("entry %q is listed twice", e.name)
		}
		audited[e.name] = true
	}

	idx := gateParseSource(t)
	seal := map[string]bool{"HalfSeal": true, "AuditSeal": true}

	found := 0
	for _, key := range idx.exportedEntryPoints() {
		fn := idx.decl[key]
		if fn.Type.Results == nil {
			continue
		}
		answers := false
		for _, res := range fn.Type.Results.List {
			if seal[gateBaseTypeName(res.Type)] {
				answers = true
			}
		}
		if !answers {
			continue
		}
		found++
		if !audited[key] {
			t.Errorf("%s (%s) hands out a seal, which IS the readability answer, but is not in "+
				"gateAuditedEntryPoints. Add a probe asserting it refuses every scenario in "+
				"gateScenarios, or an `exempt` reason saying why it cannot answer wrongly.",
				key, idx.file[key])
		}
	}
	if found == 0 {
		t.Fatal("no exported entry point returns a HalfSeal or an AuditSeal, which cannot be " +
			"true of this package; the scan is broken")
	}
	t.Logf("seal-returning entry points: %d found, all probed", found)
}

// gateBaseTypeName reduces a type expression to the identifier a caller would
// name: *T, []T, map[K]T and pkg.T all reduce to T.
func gateBaseTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return gateBaseTypeName(t.X)
	case *ast.ArrayType:
		return gateBaseTypeName(t.Elt)
	case *ast.MapType:
		return gateBaseTypeName(t.Value)
	case *ast.Ellipsis:
		return gateBaseTypeName(t.Elt)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 M1 — an expired audit is not readable, and says so distinctly
// ---------------------------------------------------------------------------

// readOrder and ManifestFromLog computed readability as
// IsReadableHalfStatus(status) ALONE, ignoring l.Properties.State, so an
// EXPIRED audit was fully readable: nine cards, six of them actionable,
// against a claim window that had already closed. The handoff rows behind
// those cards are subject to ReclaimExpired, so the agent's work would have
// had nowhere legal to land.
//
// The manifest must still REPORT the expired half and its result count, for
// the same reason it reports an unsealed one, so "expired" and "empty" stay
// distinguishable.
func TestExpiredAuditYieldsNoCardsAndSaysWhy(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) { l.Properties.State = StateExpired })
	rd := rpReader(t, l)

	cards, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	if len(cards) != 0 {
		t.Errorf("an expired audit produced %d task cards; the claim window has closed and "+
			"ReclaimExpired owns the handoff rows behind them", len(cards))
	}

	m, err := rd.BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if len(m.Cards) != 0 {
		t.Errorf("the manifest listed %d card refs for an expired audit", len(m.Cards))
	}
	if m.Index.Counts.Total != 0 {
		t.Errorf("counts.total = %d, want 0", m.Index.Counts.Total)
	}
	for _, h := range m.Halves {
		if h.Readable {
			t.Errorf("half %s reports readable on an expired audit; sealing.go's HalfSeal.Readable "+
				"says false for the same (status, state) pair, and two exported readiness paths "+
				"giving two answers is a gate that is only advisory", h.Half)
		}
		if h.Status != HalfStatusSealed {
			t.Errorf("half %s reports status %q; the fixture sealed both halves and expiry "+
				"must not rewrite what happened", h.Half, h.Status)
		}
		// "expired" and "empty" must not arrive as the same observation.
		if h.Results == 0 {
			t.Errorf("half %s reports 0 results; the withheld results must still be counted", h.Half)
		}
		if !strings.Contains(h.ReadRefusal, "claim timeout") {
			t.Errorf("half %s refusal is %q, want the expiry reason and not the unsealed one",
				h.Half, h.ReadRefusal)
		}
	}

	// The unsealed refusal is a DIFFERENT sentence, so a consumer can tell
	// "this half never sealed" from "the audit expired holding a sealed half"
	// without joining Status against State itself.
	unsealed := rpFixture(t, func(l *SARIFLog) {
		l.Runs[1].Properties.Status = HalfStatusRunning
		l.Runs[1].Properties.SealedAt = nil
		l.Properties.State = StateSastSealed
		l.Properties.DastStatus = DastStatusRunning
	})
	um, err := rpReader(t, unsealed).BuildManifest(rpAuditID)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	for _, h := range um.Halves {
		if h.Half != HalfDast {
			continue
		}
		if strings.Contains(h.ReadRefusal, "claim timeout") {
			t.Errorf("an unsealed half reports the expiry refusal %q", h.ReadRefusal)
		}
		if h.ReadRefusal == "" {
			t.Error("an unsealed half reports no refusal reason at all")
		}
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 M3 (consequence 2) — a spill is never a dangling reference
// ---------------------------------------------------------------------------

// NewReader left Reader.Blobs nil, so the spilled bytes existed only in
// Manifest.Blobs, which is `json:"-"`. A caller that marshalled the manifest
// and dropped the struct — the obvious thing to do with a projection — shipped
// a Tier-0 manifest whose most load-bearing content, the materialised read
// order, was a `sha256:` reference to bytes nobody held.
func TestSpilledBlobsSurviveDroppingTheManifest(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		for i := 0; i < 400; i++ {
			l.Runs[0].Results = append(l.Runs[0].Results, rpSastResult(
				fmt.Sprintf("sast:9%03d", i), float64(500-i),
				EvidenceClassSastStaticOnly, VerdictTruePositive, true,
				fmt.Sprintf("app/pkg%02d/module%03d.py", i%20, i), byte(i)))
		}
	})

	rd := NewReader(RecordMap{rpAuditID: l})
	if rd.Blobs == nil {
		t.Fatal("NewReader left Reader.Blobs nil; every spill it produces is a reference to " +
			"bytes that live only in a struct the caller was told not to serialise")
	}

	// Everything a caller keeps: the marshalled manifest and the Reader. The
	// Manifest struct itself is deliberately not retained past this point.
	refs := map[string]int{}
	raw := func() []byte {
		m, err := rd.BuildManifest(rpAuditID)
		if err != nil {
			t.Fatalf("BuildManifest: %v", err)
		}
		if len(m.Spills) == 0 {
			t.Fatal("a 409-finding record must spill something for this test to mean anything")
		}
		for _, s := range m.Spills {
			refs[s.Ref] = s.Bytes
		}
		return rpMarshal(t, m)
	}()

	var shipped Manifest
	if err := json.Unmarshal(raw, &shipped); err != nil {
		t.Fatalf("the shipped manifest does not round-trip: %v", err)
	}
	if len(shipped.Blobs) != 0 {
		t.Error("the spilled bytes came back through the serialised manifest; the spill did nothing")
	}

	retained := rd.RetainedBlobs()
	for _, s := range shipped.Spills {
		blob, ok := retained[s.Ref]
		if !ok {
			t.Fatalf("spill %s references blob %s, which the Reader did not retain: "+
				"the shipped manifest carries a dangling reference", s.Field, s.Ref)
		}
		if BlobRef(blob) != s.Ref {
			t.Errorf("retained blob for %s does not hash to its own reference", s.Field)
		}
		if len(blob) != s.Bytes {
			t.Errorf("spill %s reports %d bytes, the retained blob is %d", s.Field, s.Bytes, len(blob))
		}
	}

	// Draining is how a long-lived Reader avoids accumulating every blob it
	// ever spilled.
	drained := rd.DrainRetainedBlobs()
	if len(drained) != len(retained) {
		t.Errorf("DrainRetainedBlobs returned %d blobs, RetainedBlobs had %d", len(drained), len(retained))
	}
	if len(rd.RetainedBlobs()) != 0 {
		t.Error("DrainRetainedBlobs did not clear the retainer")
	}

	// A caller with real Tier-2 storage replaces the sink, and then the Reader
	// retains nothing it did not write.
	written := map[string][]byte{}
	own := NewReader(RecordMap{rpAuditID: l})
	own.Blobs = func(ref string, content []byte) error {
		written[ref] = content
		return nil
	}
	if _, err := own.BuildManifest(rpAuditID); err != nil {
		t.Fatalf("BuildManifest with a caller-supplied sink: %v", err)
	}
	if len(written) == 0 {
		t.Error("a caller-supplied BlobSink was never called")
	}
	if len(own.RetainedBlobs()) != 0 {
		t.Error("the Reader retained blobs the caller was already persisting")
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 m1 — a borrowed locus is labelled, and does not carry the action
// ---------------------------------------------------------------------------

// Both members of one cluster were independently actionable and pointed at the
// same line, so one defect produced two patch tasks writing into two different
// `fixes` arrays and charging the budget twice. The DAST member also presented
// its SAST peer's file and line as its own locus, which is inference reported
// as observation.
func TestBorrowedLocusIsLabelledAndWithholdsTheAction(t *testing.T) {
	l := rpFixture(t, nil)
	rd := rpReader(t, l)
	cards, err := rd.BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	byID := map[string]TaskCard{}
	for _, c := range cards {
		byID[c.FindingID] = c
	}
	sast, dast := byID["sast:0001"], byID["dast:0101"]

	// The card stays self-contained: the DAST member still SEES the file and
	// the line, because an agent reading it needs to know where the defect is.
	if dast.Locus.Path != "app/db.py" || dast.Static == nil {
		t.Fatalf("the DAST card lost the peer's static evidence: locus=%+v static=%v",
			dast.Locus, dast.Static != nil)
	}
	// ...but it is labelled as the peer's observation, not this finding's.
	if dast.Locus.BorrowedFrom != "sast:0001" {
		t.Errorf("dast card locus.borrowedFrom = %q, want %q: a DAST probe did not observe "+
			"app/db.py:412, the correlation concluded it, and a card that does not say so "+
			"presents inference as observation", dast.Locus.BorrowedFrom, "sast:0001")
	}
	if sast.Locus.BorrowedFrom != "" {
		t.Errorf("the SAST card claims a borrowed locus (%q); it observed its own",
			sast.Locus.BorrowedFrom)
	}

	// Exactly one member of the cluster carries the patch task.
	if !sast.Actionable {
		t.Error("the SAST member observed the line and must carry the action")
	}
	if dast.Actionable {
		t.Error("both cluster members are actionable: one defect, two patch tasks, two handoff " +
			"rows charged against the budget R.11's reservation is dividing")
	}
	if len(dast.ActionBlockers) == 0 {
		t.Fatal("the withheld card gives no reason; 'not actionable' is never unexplained")
	}
	if !strings.Contains(strings.Join(dast.ActionBlockers, " "), "sast:0001") {
		t.Errorf("the blocker does not name the peer that carries the action: %q", dast.ActionBlockers)
	}

	// Withholding is the ONE legal direction of divergence, so it is not a
	// disagreement with the record.
	for i := range l.Runs[1].Results {
		if l.Runs[1].Results[i].Properties.FindingID != "dast:0101" {
			continue
		}
		if err := dast.CheckAgainstRecord(&l.Runs[1].Results[i]); err != nil {
			t.Errorf("withholding an action the record allows must not be reported as a "+
				"disagreement: %v", err)
		}
	}

	// An UNCLUSTERED DAST finding observed nothing to borrow and is unaffected.
	if lone := byID["dast:0102"]; lone.Locus.BorrowedFrom != "" || !lone.Actionable {
		t.Errorf("an unclustered DAST card was withheld too: borrowedFrom=%q actionable=%t",
			lone.Locus.BorrowedFrom, lone.Actionable)
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 m2 — the card does not take `verified` on trust
// ---------------------------------------------------------------------------

// `verified` is an S7 gate of the same class as the host gate, and the host
// gate is enforced a third time on the card precisely because the card is what
// the agent receives. `verified` was copied across without re-checking the
// signals, so a malformed record put an unearned verification in front of the
// agent and CheckAgainstRecord — whose stated job is to name every
// contradiction — stayed silent.
func TestCardDoesNotTakeCorrelationVerifiedOnTrust(t *testing.T) {
	l := rpFixtureLog()
	co := l.Runs[0].Results[0].Properties.Correlation
	co.Signals = []SignalWeight{
		{Name: CorrelationSignalCweMatch, Weight: 0.5, Detail: "CWE-89"},
		{Name: CorrelationSignalParameterName, Weight: 0.5, Detail: "username"},
	}
	// Two signals and not CWE-only, so the link itself is legal; what is not
	// legal is claiming verification off them.
	if err := l.Validate(); err == nil {
		t.Fatal("the fixture must be a record contract.go REJECTS; if Validate() accepts it, " +
			"this test is no longer exercising the malformed-producer path")
	}
	if err := MaskRecord(l); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}

	cards, err := NewReader(RecordMap{rpAuditID: l}).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	var card *TaskCard
	for i := range cards {
		if cards[i].FindingID == "sast:0001" {
			card = &cards[i]
		}
	}
	if card == nil || card.Correlation == nil {
		t.Fatal("the clustered card vanished")
	}
	if card.Correlation.Verified {
		t.Errorf("the card asserts verified=true off signals %v; only %q or %q earns it, and "+
			"confidence alone never qualifies (00-SPINE.md S7)",
			card.Correlation.Signals, CorrelationSignalResponseStackTrace, CorrelationSignalRerunFlip)
	}

	// And a hand-edited card that grants it is reported as a disagreement.
	card.Correlation.Verified = true
	err = card.CheckAgainstRecord(&l.Runs[0].Results[0])
	if err == nil {
		t.Fatal("CheckAgainstRecord stayed silent on an unearned verified; naming every " +
			"contradiction is its whole job")
	}
	if !strings.Contains(err.Error(), "verified") {
		t.Errorf("the disagreement does not name the field: %v", err)
	}

	// The legitimate case still passes both ways: a stack-trace signal earns it.
	good := rpFixture(t, nil)
	goodCards, err := rpReader(t, good).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	for _, c := range goodCards {
		if c.FindingID == "sast:0001" && !c.Correlation.Verified {
			t.Error("a responseStackTrace signal is present; the clamp must not withhold an earned verification")
		}
	}
}

// ---------------------------------------------------------------------------
// CRITIQUE-03 m3 — a card names peers the reader cannot fetch
// ---------------------------------------------------------------------------

// When one half has not sealed its results correctly produce no cards, but the
// other half's card still named them as peers with `verified: true`. A card is
// documented as self-contained, and that one asserted a verified link to
// evidence the read gate had not opened.
func TestCardMarksPeersTheReadGateWithheld(t *testing.T) {
	l := rpFixture(t, func(l *SARIFLog) {
		l.Runs[1].Properties.Status = HalfStatusRunning
		l.Runs[1].Properties.SealedAt = nil
		l.Properties.State = StateSastSealed
		l.Properties.DastStatus = DastStatusRunning
	})
	cards, err := rpReader(t, l).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}

	have := map[string]bool{}
	for _, c := range cards {
		have[c.FindingID] = true
	}
	var clustered *TaskCard
	for i := range cards {
		if cards[i].FindingID == "sast:0001" {
			clustered = &cards[i]
		}
	}
	if clustered == nil || clustered.Correlation == nil {
		t.Fatal("the cluster's readable member lost its correlation")
	}

	// The link is not deleted — "not linked" and "linked to something not yet
	// readable" are different facts — but the unfetchable peer is named.
	if len(clustered.Correlation.Peers) == 0 {
		t.Fatal("the link was deleted rather than marked")
	}
	if got := clustered.Correlation.PeersUnreadable; len(got) != 1 || got[0] != "dast:0101" {
		t.Errorf("peersUnreadable = %q, want [dast:0101]", got)
	}
	for _, p := range clustered.Correlation.Peers {
		if have[p] {
			continue
		}
		found := false
		for _, u := range clustered.Correlation.PeersUnreadable {
			if u == p {
				found = true
			}
		}
		if !found {
			t.Errorf("peer %q is named on a card, has no card of its own, and is not marked unreadable", p)
		}
	}
	if !strings.Contains(clustered.Correlation.Caveat, "dast:0101") {
		t.Errorf("the caveat does not say which peer cannot be fetched: %q", clustered.Correlation.Caveat)
	}

	// On a fully sealed audit every peer is fetchable and nothing is marked.
	good, err := rpReader(t, rpFixture(t, nil)).BuildTaskCards(rpAuditID)
	if err != nil {
		t.Fatalf("BuildTaskCards: %v", err)
	}
	for _, c := range good {
		if c.Correlation != nil && len(c.Correlation.PeersUnreadable) != 0 {
			t.Errorf("card %s marks peers unreadable on a fully sealed audit: %q",
				c.FindingID, c.Correlation.PeersUnreadable)
		}
	}
}
