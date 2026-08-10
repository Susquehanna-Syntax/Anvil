// drift_test.go is A.16's evidence.
//
// The two claims A.16's packet asks to be measured are measured END TO END,
// against a real migrated A.2 cache and through A.14's real write path, not
// asserted against a struct field this package filled in itself:
//
//  1. "A synthetic dataVersion: 5.9 record is PERSISTED with parse_degraded=1,
//     not dropped." Read back out of the database, including `raw_json`
//     compared byte for byte against the document that went in.
//  2. "Tombstoning a previously published row makes a query for active
//     findings referencing that advisory return it as INVALIDATED rather than
//     silently vanishing." The finding is inserted before the tombstone and
//     counted before and after.
//
// Everything else here follows the rules this project has already paid for:
//
//   - EVERY GUARD IS VERIFIED RED. The statement allowlist is run against a
//     hand-written DELETE, the reason allowlist against reasons nobody
//     listed, and the load-bearing rule against a PAIR of documents that
//     differ in exactly one key — so a green result is a difference the guard
//     produced and not a fixture that could never have failed.
//   - NO CORPUS COMES FROM THE IMPLEMENTATION. The known-version list is
//     re-stated here from A.16's packet text ("5.0/5.1/5.2 known") and
//     compared against the table; the field fixtures are hand-written CVE
//     documents; the branch table is checked against internal/ingest/delta's
//     DECODER BEHAVIOUR rather than against a copy of delta's own list.
//   - NO NETWORK, no credentials, no environment reads, and no t.Skip. A skip
//     here would hide exactly the control the packet asks for.
package drift

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const testFeedID = "cvelistv5"

var fixtureClock = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

// packetKnownVersions is A.16's packet, quoted: "5.0/5.1/5.2 known; anything
// else sets degraded=true and stores raw verbatim".
//
// It is written out HERE, from the packet, precisely so that the table in
// drift.go is compared against something other than itself. A test whose
// corpus is the implementation certified a defect on this project rather than
// catching one.
var packetKnownVersions = []string{"5.0", "5.1", "5.2"}

// cveDoc builds a CVE 5.x record as a map so a test can add, remove or rename
// exactly one key and compare the two outcomes.
func cveDoc(id, dataVersion string) map[string]any {
	return map[string]any{
		"dataType":    "CVE_RECORD",
		"dataVersion": dataVersion,
		"cveMetadata": map[string]any{
			"cveId":             id,
			"state":             "PUBLISHED",
			"assignerOrgId":     "00000000-0000-4000-8000-000000000000",
			"assignerShortName": "example",
			"datePublished":     "2026-01-01T00:00:00Z",
			"dateUpdated":       "2026-02-01T00:00:00Z",
		},
		"containers": map[string]any{
			"cna": map[string]any{
				"providerMetadata": map[string]any{
					"orgId":     "00000000-0000-4000-8000-000000000000",
					"shortName": "example",
				},
				"descriptions": []any{map[string]any{
					"lang":  "en",
					"value": "A synthetic advisory about " + id + " affecting quorumwidget.",
				}},
				"references": []any{map[string]any{"url": "https://example.invalid/adv/" + id}},
				"metrics": []any{map[string]any{"cvssV3_1": map[string]any{
					"version":      "3.1",
					"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					"baseScore":    9.8,
					"baseSeverity": "CRITICAL",
				}}},
				"affected": []any{map[string]any{
					"vendor":      "example",
					"product":     "quorumwidget",
					"packageName": "quorumwidget",
					"versions": []any{map[string]any{
						"version":     "1.0.0",
						"status":      "affected",
						"versionType": "semver",
						"lessThan":    "1.2.3",
					}},
				}},
			},
		},
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling a fixture: %v", err)
	}
	return raw
}

// cna reaches into a fixture's CNA container so a test can inject one key.
func cna(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	containers, ok := doc["containers"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no containers object")
	}
	c, ok := containers["cna"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no cna container")
	}
	return c
}

// firstAffectedVersion reaches the load-bearing subtree: the version range the
// comparator answers from.
func firstAffectedVersion(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	affected, ok := cna(t, doc)["affected"].([]any)
	if !ok || len(affected) == 0 {
		t.Fatal("fixture has no affected entries")
	}
	entry, ok := affected[0].(map[string]any)
	if !ok {
		t.Fatal("fixture's first affected entry is not an object")
	}
	versions, ok := entry["versions"].([]any)
	if !ok || len(versions) == 0 {
		t.Fatal("fixture's first affected entry has no versions")
	}
	v, ok := versions[0].(map[string]any)
	if !ok {
		t.Fatal("fixture's first version is not an object")
	}
	return v
}

// ---------------------------------------------------------------------------
// Cache fixtures
// ---------------------------------------------------------------------------

func openCache(t *testing.T) *sql.DB {
	t.Helper()
	db, err := cache.Open(t.Context(), filepath.Join(t.TempDir(), "anvil-cache.sqlite"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := cache.Migrate(t.Context(), db); err != nil {
		t.Fatalf("cache.Migrate: %v", err)
	}
	return db
}

// admittedDecision is a NON-REFUSED licence decision.
//
// It is a literal rather than a run of A.4's real gate, and that is a
// deliberate, narrow choice: this file measures A.16, and the gate has its own
// suite. What matters here is only that the decision is admitted — a refusal
// writes nothing, and a suite in which every write silently did nothing would
// look green for the worst possible reason. Decision.Refused() is asserted
// below so the fixture cannot rot into a refusal unnoticed.
func admittedDecision(t *testing.T) license.Decision {
	t.Helper()
	d := license.Decision{
		FeedID:        testFeedID,
		Tier:          config.LicenseTier0,
		Dir:           "mirror/tier0/" + testFeedID,
		EffectiveSPDX: "CC0-1.0",
		DeclaredSPDX:  "CC0-1.0",
	}
	if d.Refused() {
		t.Fatal("the fixture licence decision is a refusal; every write below would be a no-op " +
			"and this suite would be green for the wrong reason")
	}
	return d
}

func testFeed() config.FeedConfig {
	return config.FeedConfig{ID: testFeedID}
}

// applyOne writes one parsed record through A.14's real write path. There is
// deliberately no second write path in this file: a test that inserted rows
// with its own INSERT would be measuring its own SQL.
func applyOne(t *testing.T, db *sql.DB, rec Record) delta.BatchStats {
	t.Helper()
	stats, err := delta.Apply(t.Context(), db, testFeed(), admittedDecision(t),
		[]Record{rec}, fixtureClock, 0)
	if err != nil {
		t.Fatalf("delta.Apply: %v", err)
	}
	return stats
}

// parseAndApply is the whole ingest path this packet sits in: bytes in, one
// row in the cache.
func parseAndApply(t *testing.T, db *sql.DB, raw []byte) Report {
	t.Helper()
	rec, rep, err := Parse(testFeedID, raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	applyOne(t, db, rec)
	return rep
}

// insertFinding seeds a Lane A finding.
//
// It uses raw SQL because there is no sanctioned writer for `finding` yet —
// A.9 and A.10 own that table and neither exports a write path. The column
// list is copied from internal/ingest/cache's own test so the two cannot
// disagree about the shape, and `finding.id` is a LANE-LOCAL identifier and
// never a fingerprint (schema.go says so at the table).
func insertFinding(t *testing.T, db *sql.DB, id, source, sourceID string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO finding (
			id, collector, source, source_id, package, installed_version, ecosystem,
			remediable_by_agent, as_of, staleness_seconds, anvil_trust, detected_at
		) VALUES (?, ?, ?, ?, 'quorumwidget', '1.0.0', 'deb', 0, ?, 0, ?, ?)`,
		id, cache.CollectorHost, source, sourceID,
		fixtureClock.Format(time.RFC3339), string(cache.FindingTrustDefault),
		fixtureClock.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("seeding finding %q: %v", id, err)
	}
}

func scalar[T any](t *testing.T, db *sql.DB, query string, args ...any) T {
	t.Helper()
	var out T
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&out); err != nil {
		t.Fatalf("query %q: %v", condense(query), err)
	}
	return out
}

// ---------------------------------------------------------------------------
// A.16's first stop condition: an unknown dataVersion round-trips
// ---------------------------------------------------------------------------

// TestUnknownDataVersionIsPersistedDegradedAndNotDropped is the packet's
// headline validation, measured out of the database rather than out of a
// return value.
func TestUnknownDataVersionIsPersistedDegradedAndNotDropped(t *testing.T) {
	db := openCache(t)
	raw := mustJSON(t, cveDoc("CVE-2026-9999", "5.9"))

	rec, rep, err := Parse(testFeedID, raw)
	if err != nil {
		t.Fatalf("an unknown dataVersion produced an ERROR; the packet requires it to produce a "+
			"degraded record: %v", err)
	}
	if !rep.Degraded {
		t.Fatal("dataVersion 5.9 was not reported as degraded")
	}
	if !rep.Has(CodeUnknownDataVersion) {
		t.Errorf("the report does not carry %s; codes are %v", CodeUnknownDataVersion, rep.Codes)
	}
	if rep.Branch != BranchUnknown || rep.KnownVersion {
		t.Errorf("dataVersion 5.9 selected branch %q (known=%v); want the unknown branch",
			rep.Branch, rep.KnownVersion)
	}
	if rec.SourceID != "CVE-2026-9999" {
		t.Errorf("the degraded record lost its primary key: source_id = %q", rec.SourceID)
	}
	if !bytes.Equal(rec.Raw, raw) {
		t.Error("the degraded record does not carry the publisher's bytes verbatim")
	}

	applyOne(t, db, rec)

	if got := scalar[int](t, db,
		`SELECT count(*) FROM advisory WHERE source_id = 'CVE-2026-9999' AND parse_degraded = 1
		 AND data_version = '5.9'`); got != 1 {
		t.Fatalf("expected exactly one degraded row for the 5.9 record, found %d. "+
			"research/06 Risk #3: ingest raw and set parse_degraded=1 rather than dropping the record", got)
	}
	// "Round-trips WITHOUT DATA LOSS": the publisher's bytes and the version
	// ranges a comparator would answer from both survived.
	stored := scalar[[]byte](t, db, `SELECT raw_json FROM advisory WHERE source_id = 'CVE-2026-9999'`)
	if !bytes.Equal(stored, raw) {
		t.Errorf("raw_json is not byte-identical to the document that went in:\n stored %s\n input  %s",
			stored, raw)
	}
	if got := scalar[int](t, db,
		`SELECT count(*) FROM affected WHERE source_id = 'CVE-2026-9999'`); got == 0 {
		t.Error("the degraded record's version ranges were dropped; a degraded record is still a record")
	}
}

// TestKnownDataVersionsAreNotDegraded is the other half of the same claim: if
// every record came back degraded, parse_degraded would carry no information
// and the test above would pass for the wrong reason.
func TestKnownDataVersionsAreNotDegraded(t *testing.T) {
	for _, version := range packetKnownVersions {
		t.Run(version, func(t *testing.T) {
			db := openCache(t)
			id := "CVE-2026-" + strings.ReplaceAll(version, ".", "")
			raw := mustJSON(t, cveDoc(id, version))

			rep := parseAndApply(t, db, raw)
			if rep.Degraded {
				t.Fatalf("dataVersion %s was degraded: %s", version, rep)
			}
			if !rep.Clean() {
				t.Fatalf("dataVersion %s raised codes on a document built from the known key set: %s",
					version, rep)
			}
			if got := scalar[int](t, db,
				`SELECT parse_degraded FROM advisory WHERE source_id = ?`, id); got != 0 {
				t.Errorf("parse_degraded = %d for a known version", got)
			}
		})
	}
}

// TestTheBranchTableAgreesWithTheDeltaDecoder is the cross-package conformance
// test.
//
// internal/ingest/delta keeps its own knownCVEDataVersions and it is
// unexported, so the two lists cannot be compared directly. They are compared
// BEHAVIOURALLY instead: delta.Decode's own parse_degraded is read for the
// same bytes this package branches on. A divergence — delta learning 5.3 while
// this table does not, or the reverse — is a red test here, which is the only
// place the two can be observed together at all.
func TestTheBranchTableAgreesWithTheDeltaDecoder(t *testing.T) {
	versions := append([]string{}, packetKnownVersions...)
	versions = append(versions, "5.3", "5.9", "6.0", "4.0", "", "5", "5.1.0", "v5.1", " 5.1 ")

	for _, version := range versions {
		t.Run("dataVersion="+version, func(t *testing.T) {
			raw := mustJSON(t, cveDoc("CVE-2026-1000", version))
			recs, _, err := delta.Decode(testFeedID, raw)
			if err != nil {
				t.Fatalf("delta.Decode refused a well-formed CVE record: %v", err)
			}
			if len(recs) != 1 {
				t.Fatalf("delta.Decode returned %d records for one document", len(recs))
			}
			deltaSaysDegraded := recs[0].ParseDegraded
			driftSaysKnown := BranchFor(version).Known()
			if deltaSaysDegraded == driftSaysKnown {
				t.Fatalf("the two version tables disagree about %q: delta degraded=%v, "+
					"drift known=%v. One of the two lists has moved; they describe the same fact "+
					"and a silent divergence changes what gets flagged incomplete.",
					version, deltaSaysDegraded, driftSaysKnown)
			}
		})
	}
}

// TestKnownVersionsAreExactlyThePacketsThree compares the table against A.16's
// packet rather than against itself.
func TestKnownVersionsAreExactlyThePacketsThree(t *testing.T) {
	got := KnownVersions()
	if !reflect.DeepEqual(got, packetKnownVersions) {
		t.Fatalf("KnownVersions() = %v; A.16's packet names %v", got, packetKnownVersions)
	}
	for _, v := range packetKnownVersions {
		if !BranchFor(v).Known() {
			t.Errorf("%q is named as known in the packet and is not in the table", v)
		}
	}
}

// TestNoPrefixOrFuzzyRuleOnDataVersion holds the one rule that makes the
// branch meaningful: "5.3 looks close enough to 5.2" is how a partial parse
// becomes silent.
func TestNoPrefixOrFuzzyRuleOnDataVersion(t *testing.T) {
	unknown := []string{"5", "5.", "5.1.0", "5.10", "5.11", "v5.1", "V5.1", "5.1-beta", "05.1", "", "  "}
	for _, v := range unknown {
		if BranchFor(v).Known() {
			t.Errorf("BranchFor(%q) reports a known branch; only an EXACT match on a listed "+
				"version may be known", v)
		}
	}
	// Surrounding whitespace IS trimmed, and that is deliberate: a feed that
	// pads its value has not changed its schema.
	for _, v := range []string{" 5.1", "5.1 ", "\t5.1\n"} {
		if BranchFor(v) != BranchCVE51 {
			t.Errorf("BranchFor(%q) = %q; padding is not a schema change", v, BranchFor(v))
		}
	}
}

// TestVersionOrderIsNumericPerComponent guards newestBranch against the day
// CVE reaches a two-digit minor. Lexically "5.10" < "5.2", which would silently
// pick the wrong profile for every unknown version.
func TestVersionOrderIsNumericPerComponent(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"5.2", "5.10", -1},
		{"5.10", "5.2", 1},
		{"5.1", "5.1", 0},
		{"5.0", "5.1", -1},
		{"6.0", "5.99", 1},
		{"5.1", "5.1.1", -1},
		{"x", "5.0", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if got := newestBranch(); got != BranchCVE52 {
		t.Errorf("newestBranch() = %q; the newest known version is 5.2", got)
	}

	// The ordering is exercised against a list THIS BUILD'S TABLE DOES NOT
	// CONTAIN. With only 5.0, 5.1 and 5.2 known, lexical and numeric sorting
	// agree, so a test that only looked at KnownVersions() would pass against
	// a lexical implementation and go on passing until the day CVE ships a
	// two-digit minor — at which point newestBranch would quietly select the
	// wrong profile for every unknown version.
	if got := sortVersions([]string{"5.10", "5.2", "5.1", "6.0", "5.9"}); !reflect.DeepEqual(
		got, []string{"5.1", "5.2", "5.9", "5.10", "6.0"}) {
		t.Fatalf("sortVersions = %v; want numeric-per-component order. Lexically \"5.10\" sorts "+
			"before \"5.2\", which would make the newest known profile the wrong one.", got)
	}
	if got := sortVersions(append([]string{}, KnownVersions()...)); !reflect.DeepEqual(got, KnownVersions()) {
		t.Errorf("KnownVersions() is not in the order sortVersions produces: %v", KnownVersions())
	}
}

// ---------------------------------------------------------------------------
// Which fields were not understood
// ---------------------------------------------------------------------------

// TestAnUnknownFieldInALoadBearingPathDegradesAKnownVersion is the within-
// version drift case: the feed does not bump its version, it just starts
// carrying something new where the version ranges live.
//
// IT IS RUN AS A PAIR. The control is the same document without the injected
// key and must come back clean, so a green result is the difference the guard
// found rather than a fixture that could never have been clean.
func TestAnUnknownFieldInALoadBearingPathDegradesAKnownVersion(t *testing.T) {
	control := cveDoc("CVE-2026-1111", "5.1")
	if _, rep, err := Parse(testFeedID, mustJSON(t, control)); err != nil || !rep.Clean() {
		t.Fatalf("the CONTROL document is not clean, so this test could not have failed: %s (err %v)",
			rep, err)
	}

	drifted := cveDoc("CVE-2026-1111", "5.1")
	firstAffectedVersion(t, drifted)["rangeSemanticsV2"] = "closed-open"

	rec, rep, err := Parse(testFeedID, mustJSON(t, drifted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !rep.Degraded {
		t.Fatal("an unrecognised key inside affected[].versions[] did not degrade the record. " +
			"That subtree is the version range Lane A's answer is made of (spine S1); a field " +
			"nobody understands there is a range that may not mean what the comparator read.")
	}
	if !rep.Has(CodeUnknownFieldLoadBearing) {
		t.Errorf("codes = %v; want %s", rep.Codes, CodeUnknownFieldLoadBearing)
	}
	want := "/containers/cna/affected[]/versions[]/rangeSemanticsV2"
	if !contains(rep.DegradingFields, want) {
		t.Errorf("DegradingFields = %v; want it to name %q — a degraded flag that does not say "+
			"WHICH field is a status nobody can act on", rep.DegradingFields, want)
	}
	if !rec.ParseDegraded {
		t.Error("the record's parse_degraded does not match the report")
	}
}

// TestAnUnknownFieldOutsideALoadBearingPathIsReportedNotDegraded is the other
// side of the same rule. Degrading every record that carries a new prose field
// would make parse_degraded mean "this is a CVE record", and a flag that is
// always set is a flag nobody reads.
func TestAnUnknownFieldOutsideALoadBearingPathIsReportedNotDegraded(t *testing.T) {
	doc := cveDoc("CVE-2026-2222", "5.1")
	cna(t, doc)["x_generatorNotes"] = "produced by a tool nobody told us about"

	_, rep, err := Parse(testFeedID, mustJSON(t, doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Degraded {
		t.Fatalf("a new key in a non-load-bearing path degraded the record: %s", rep)
	}
	want := "/containers/cna/x_generatorNotes"
	if !contains(rep.UnknownFields, want) {
		t.Fatalf("UnknownFields = %v; want it to name %q. An `x_` prefix is NOT an exemption: "+
			"the CVE format permits vendor extensions, and a parser that stopped looking at them "+
			"would have a documented place to hide drift.", rep.UnknownFields, want)
	}
	if contains(rep.DegradingFields, want) {
		t.Error("a non-load-bearing field was listed as degrading")
	}
	if !rep.Has(CodeUnknownField) {
		t.Errorf("codes = %v; want %s", rep.Codes, CodeUnknownField)
	}
}

// TestAnUnknownFieldInCVEMetadataDegrades covers the other load-bearing
// subtree: identity and retraction.
func TestAnUnknownFieldInCVEMetadataDegrades(t *testing.T) {
	doc := cveDoc("CVE-2026-3333", "5.1")
	meta, ok := doc["cveMetadata"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no cveMetadata")
	}
	meta["supersededBy"] = "CVE-2026-4444"

	_, rep, err := Parse(testFeedID, mustJSON(t, doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !rep.Degraded || !contains(rep.DegradingFields, "/cveMetadata/supersededBy") {
		t.Fatalf("an unrecognised key in /cveMetadata did not degrade: %s", rep)
	}
}

// TestTheLoadBearingPrefixMatchIsSegmentAware verifies the guard against the
// near-miss that has defeated three guards on this project: a plain
// strings.HasPrefix would call "/cveMetadataExtra" load-bearing.
//
// The naive answer is computed here and asserted to DIFFER, so the test fails
// if the implementation is ever simplified back into it.
func TestTheLoadBearingPrefixMatchIsSegmentAware(t *testing.T) {
	nearMisses := []string{
		"/cveMetadataExtra",
		"/cveMetadata2",
		"/containers/cna/affectedProducts",
		"/containers/cna/affected2[]/thing",
	}
	for _, p := range nearMisses {
		if isLoadBearing(p) {
			t.Errorf("isLoadBearing(%q) = true; a sibling key that merely starts with the same "+
				"letters is not the same subtree", p)
		}
		naive := false
		for _, prefix := range loadBearingPrefixes {
			base := strings.TrimSuffix(prefix, "[]")
			if strings.HasPrefix(p, base) {
				naive = true
			}
		}
		if !naive {
			t.Errorf("%q is not a near-miss at all, so it verifies nothing; pick a fixture a "+
				"naive prefix match would have accepted", p)
		}
	}
	hits := []string{
		"/cveMetadata",
		"/cveMetadata/cveId",
		"/containers/cna/affected[]",
		"/containers/cna/affected[]/versions[]/lessThan",
		"/containers/adp[]/affected[]/vendor",
	}
	for _, p := range hits {
		if !isLoadBearing(p) {
			t.Errorf("isLoadBearing(%q) = false; that path IS a load-bearing subtree", p)
		}
	}
}

// TestUnknownFieldsAreCappedAndTruncationIsItselfDegrading: a report is a log
// line, and a document is attacker-adjacent input.
func TestUnknownFieldsAreCappedAndTruncationIsItselfDegrading(t *testing.T) {
	doc := cveDoc("CVE-2026-5555", "5.1")
	container := cna(t, doc)
	for i := 0; i < MaxReportedFields*4; i++ {
		container[fmt.Sprintf("unlisted_%03d", i)] = i
	}

	_, rep, err := Parse(testFeedID, mustJSON(t, doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.UnknownFields) > MaxReportedFields {
		t.Errorf("UnknownFields has %d entries; the cap is %d", len(rep.UnknownFields), MaxReportedFields)
	}
	if !rep.Truncated {
		t.Fatal("the field list was capped and Truncated was not set; a short list must never be " +
			"mistaken for a clean one")
	}
	if !rep.Degraded || !rep.Has(CodeFieldsTruncated) {
		t.Fatalf("truncation did not degrade the record: %s. An incomplete answer about whether "+
			"anything was missed is not an answer.", rep)
	}
}

// TestAKeyChangingTypeIsDrift: a field that was an object and is now an array
// is a schema change, and it is one nothing else in this pipeline would notice.
func TestAKeyChangingTypeIsDrift(t *testing.T) {
	doc := cveDoc("CVE-2026-6666", "5.1")
	cna(t, doc)["title"] = []any{"now", "an", "array"}

	_, rep, err := Parse(testFeedID, mustJSON(t, doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !contains(rep.UnknownFields, "/containers/cna/title[]") {
		t.Fatalf("a scalar key that became an array was not reported: %s", rep)
	}
}

// ---------------------------------------------------------------------------
// Never dropped, even when nothing decodes
// ---------------------------------------------------------------------------

// TestAnUndecodableDocumentIsPreservedNotDropped covers the case the packet's
// forbidden action is really about: not "a version we do not know" but "bytes
// we cannot parse at all". Those are the ones a parser is most tempted to skip.
func TestAnUndecodableDocumentIsPreservedNotDropped(t *testing.T) {
	db := openCache(t)
	// dataType is not CVE_RECORD and the document is in no shape delta
	// recognises, so delta.Decode refuses it outright.
	raw := mustJSON(t, map[string]any{
		"dataType":    "CVE_RECORD_V6",
		"dataVersion": "6.0",
		"cveMetadata": map[string]any{"cveId": "CVE-2026-7777", "state": "PUBLISHED"},
		"payload":     map[string]any{"somethingEntirelyNew": true},
	})

	if _, _, err := delta.Decode(testFeedID, raw); err == nil {
		t.Fatal("delta.Decode accepted the fixture, so this test does not exercise the fallback " +
			"path at all; pick a document the decoder genuinely refuses")
	}

	rec, rep, err := Parse(testFeedID, raw)
	if err != nil {
		t.Fatalf("an undecodable document produced an error instead of a degraded record: %v", err)
	}
	if !rep.Has(CodeUndecodable) || !rep.Degraded {
		t.Fatalf("the fallback record was not reported as degraded: %s", rep)
	}
	if rep.DecodeError == "" {
		t.Error("the report does not carry the decoder's refusal; 'it did not parse' without a " +
			"reason is not something an operator can act on")
	}
	applyOne(t, db, rec)

	if got := scalar[int](t, db,
		`SELECT count(*) FROM advisory WHERE source_id = 'CVE-2026-7777' AND parse_degraded = 1`); got != 1 {
		t.Fatalf("the undecodable document was not persisted (%d rows). The bytes are the whole "+
			"point: a later build that understands the shape can re-parse them, and a dropped "+
			"record can never be recovered.", got)
	}
	stored := scalar[[]byte](t, db, `SELECT raw_json FROM advisory WHERE source_id = 'CVE-2026-7777'`)
	if !bytes.Equal(stored, raw) {
		t.Error("the fallback did not store the publisher's bytes verbatim")
	}
}

// TestADocumentWithNoPrimaryKeyIsRefusedLoudly is the one case that is not a
// degraded record, and it must not be a silent drop either.
func TestADocumentWithNoPrimaryKeyIsRefusedLoudly(t *testing.T) {
	raw := mustJSON(t, map[string]any{
		"dataType":    "SOMETHING_ELSE",
		"dataVersion": "9.9",
		"payload":     map[string]any{"no": "identifier anywhere"},
	})
	_, _, err := Parse(testFeedID, raw)
	if !errors.Is(err, ErrNoPrimaryKey) {
		t.Fatalf("err = %v; want ErrNoPrimaryKey. The cache is keyed on (source, source_id) and a "+
			"row without one cannot be written, re-found or re-opened, so this has to be an error "+
			"the caller sees.", err)
	}
	if !errors.Is(err, ErrDrift) {
		t.Error("the refusal is not tagged with ErrDrift, so a caller cannot tell it from a " +
			"database failure")
	}
}

// TestParseRefusesADocumentThatIsNotOneObject: an array of advisories is a
// real feed shape, and taking its first element silently would drop the rest.
func TestParseRefusesADocumentThatIsNotOneObject(t *testing.T) {
	for name, raw := range map[string]string{
		"array":  `[{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1"}}]`,
		"string": `"just a string"`,
		"empty":  ``,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse(testFeedID, []byte(raw)); !errors.Is(err, ErrNotAnObject) {
				t.Fatalf("err = %v; want ErrNotAnObject", err)
			}
		})
	}
}

// TestTheRecordAndTheReportNeverDisagreeAboutDegradation. A record whose flag
// and whose explanation disagree is worse than either alone: one of the two is
// what an operator reads and the other is what the comparator trusts.
func TestTheRecordAndTheReportNeverDisagreeAboutDegradation(t *testing.T) {
	clean := cveDoc("CVE-2026-8001", "5.1")

	unknownVersion := cveDoc("CVE-2026-8002", "5.9")

	loadBearing := cveDoc("CVE-2026-8003", "5.1")
	firstAffectedVersion(t, loadBearing)["newRangeKey"] = "x"

	cosmetic := cveDoc("CVE-2026-8004", "5.1")
	cna(t, cosmetic)["newProseKey"] = "x"

	for name, doc := range map[string]map[string]any{
		"clean":                clean,
		"unknown-version":      unknownVersion,
		"load-bearing-drift":   loadBearing,
		"non-load-bearing":     cosmetic,
		"unknown-version-both": mergeDoc(cveDoc("CVE-2026-8005", "7.7"), "extraTopLevel", "x"),
	} {
		t.Run(name, func(t *testing.T) {
			rec, rep, err := Parse(testFeedID, mustJSON(t, doc))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if rec.ParseDegraded != rep.Degraded {
				t.Fatalf("record.ParseDegraded = %v but report.Degraded = %v (%s)",
					rec.ParseDegraded, rep.Degraded, rep)
			}
			if rep.Degraded && len(rep.Codes) == 0 {
				t.Fatal("a degraded record with no code says it is incomplete without saying why")
			}
			if rep.Degraded && rep.String() == "" {
				t.Fatal("Report.String() is empty on a degraded record")
			}
		})
	}
}

func mergeDoc(doc map[string]any, key string, value any) map[string]any {
	doc[key] = value
	return doc
}

// TestParseVersionedAgreesWithParse holds the two entry points together. The
// narrow one is the packet's signature and the wide one is what an ingest path
// should call; they must not be able to disagree about the same bytes.
func TestParseVersionedAgreesWithParse(t *testing.T) {
	for _, version := range []string{"5.1", "5.9"} {
		t.Run(version, func(t *testing.T) {
			raw := mustJSON(t, cveDoc("CVE-2026-4242", version))

			narrow, degraded := ParseVersioned(raw)
			wide, rep, err := Parse(testFeedID, raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if degraded != rep.Degraded {
				t.Fatalf("ParseVersioned says degraded=%v, Parse says %v", degraded, rep.Degraded)
			}
			if narrow.Source != "" {
				t.Errorf("ParseVersioned stamped a Source (%q); bytes do not know which feed "+
					"delivered them", narrow.Source)
			}
			// Stamping the feed id is the only difference between the two.
			narrow.Source = testFeedID
			if !reflect.DeepEqual(narrow, wide) {
				t.Fatalf("the two entry points produced different records for the same bytes:\n"+
					" narrow %+v\n wide   %+v", narrow, wide)
			}
		})
	}
}

// TestParseVersionedOnAKeylessDocumentReturnsARecordTheWritePathRefuses. The
// narrow signature cannot return an error, so the failure has to arrive
// somewhere a caller cannot ignore.
func TestParseVersionedOnAKeylessDocumentReturnsARecordTheWritePathRefuses(t *testing.T) {
	db := openCache(t)
	raw := []byte(`{"dataVersion":"9.9","payload":{"no":"identifier"}}`)

	rec, degraded := ParseVersioned(raw)
	if !degraded {
		t.Fatal("a document that could not be parsed at all came back not degraded")
	}
	if !bytes.Equal(rec.Raw, raw) {
		t.Error("the returned record does not carry the publisher's bytes")
	}
	_, err := delta.Apply(t.Context(), db, testFeed(), admittedDecision(t),
		[]Record{rec}, fixtureClock, 0)
	if err == nil {
		t.Fatal("delta.Apply accepted a record with no primary key; the refusal is what makes " +
			"ParseVersioned's error-free signature safe")
	}
}

func contains(list []string, want string) bool {
	for _, got := range list {
		if got == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Tombstones
// ---------------------------------------------------------------------------

// seedPublished writes one published advisory and one finding that rests on
// it, and returns the advisory's rowid.
func seedPublished(t *testing.T, db *sql.DB, id string) int64 {
	t.Helper()
	rep := parseAndApply(t, db, mustJSON(t, cveDoc(id, "5.1")))
	if rep.Degraded {
		t.Fatalf("the seed advisory came back degraded: %s", rep)
	}
	insertFinding(t, db, "finding-"+id, testFeedID, id)
	return scalar[int64](t, db, `SELECT rowid FROM advisory WHERE source = ? AND source_id = ?`,
		testFeedID, id)
}

func newTombstoner(t *testing.T, db *sql.DB) *Tombstoner {
	t.Helper()
	ts, err := NewTombstoner(db, func() time.Time { return fixtureClock })
	if err != nil {
		t.Fatalf("NewTombstoner: %v", err)
	}
	return ts
}

// TestTombstoneFlipsDependentFindingVisibility is A.16's second stop
// condition, and the reason exit criterion 22 exists at all.
func TestTombstoneFlipsDependentFindingVisibility(t *testing.T) {
	db := openCache(t)
	const id = "CVE-2026-1234"
	seedPublished(t, db, id)

	before, err := FindingsReferencing(t.Context(), db, testFeedID, id)
	if err != nil {
		t.Fatalf("FindingsReferencing: %v", err)
	}
	if len(before) != 1 || before[0].Invalidated {
		t.Fatalf("before the tombstone: %d findings, invalidated=%v; want one live finding",
			len(before), len(before) > 0 && before[0].Invalidated)
	}

	res, err := newTombstoner(t, db).Tombstone(t.Context(), testFeedID, id, string(ReasonWithdrawn))
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if res.State != cache.AdvisoryWithdrawn || res.PreviousState != cache.AdvisoryPublished {
		t.Errorf("state went %q -> %q; want %q -> %q",
			res.PreviousState, res.State, cache.AdvisoryPublished, cache.AdvisoryWithdrawn)
	}
	if res.InvalidatedFindings != 1 {
		t.Errorf("InvalidatedFindings = %d, want 1", res.InvalidatedFindings)
	}

	after, err := FindingsReferencing(t.Context(), db, testFeedID, id)
	if err != nil {
		t.Fatalf("FindingsReferencing: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("after the tombstone the finding VANISHED (%d rows). research/06 Risk #4 and "+
			"exit criterion 22: a prior finding must be re-openable and invalidated, which it "+
			"cannot be if the query stops returning it.", len(after))
	}
	if !after[0].Invalidated {
		t.Fatal("the finding is still reported as live although its advisory was withdrawn")
	}
	if after[0].AdvisoryState != cache.AdvisoryWithdrawn || after[0].TombstonedAt == "" {
		t.Errorf("the invalidated finding does not carry the retraction: state=%q tombstoned_at=%q",
			after[0].AdvisoryState, after[0].TombstonedAt)
	}
	if after[0].FindingID != "finding-"+id {
		t.Errorf("FindingID = %q; the finding's identity must survive invalidation", after[0].FindingID)
	}

	all, err := InvalidatedFindings(t.Context(), db)
	if err != nil {
		t.Fatalf("InvalidatedFindings: %v", err)
	}
	if len(all) != 1 || all[0].FindingID != "finding-"+id {
		t.Fatalf("the re-open work list does not contain the invalidated finding: %+v", all)
	}
}

// TestTombstoneNeverDeletesARow is the forbidden action, measured.
func TestTombstoneNeverDeletesARow(t *testing.T) {
	db := openCache(t)
	const id = "CVE-2026-2345"
	rowid := seedPublished(t, db, id)
	rawBefore := scalar[[]byte](t, db, `SELECT raw_json FROM advisory WHERE source_id = ?`, id)
	affectedBefore := scalar[int](t, db, `SELECT count(*) FROM affected WHERE source_id = ?`, id)
	aliasBefore := scalar[int](t, db, `SELECT count(*) FROM cve_alias WHERE source_id = ?`, id)
	if affectedBefore == 0 || aliasBefore == 0 {
		t.Fatal("the seed advisory has no affected or alias rows, so their survival proves nothing")
	}

	res, err := newTombstoner(t, db).Tombstone(t.Context(), testFeedID, id, string(ReasonRejected))
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}

	if got := scalar[int](t, db, `SELECT count(*) FROM advisory WHERE source_id = ?`, id); got != 1 {
		t.Fatalf("the advisory row is gone (%d rows). A withdrawn advisory is TOMBSTONED, never "+
			"deleted: a finding that referenced it must still find it.", got)
	}
	state := scalar[string](t, db, `SELECT state FROM advisory WHERE source_id = ?`, id)
	stamp := scalar[string](t, db, `SELECT ifnull(tombstoned_at, '') FROM advisory WHERE source_id = ?`, id)
	if state != cache.AdvisoryRejected || stamp == "" {
		t.Errorf("state=%q tombstoned_at=%q; the schema pairs a non-published state with a "+
			"non-null timestamp", state, stamp)
	}
	if got := scalar[int64](t, db, `SELECT rowid FROM advisory WHERE source_id = ?`, id); got != rowid {
		t.Errorf("the rowid moved from %d to %d; an INSERT OR REPLACE would do that and would "+
			"orphan the FTS entry with no error", rowid, got)
	}
	if res.RowID != rowid {
		t.Errorf("TombstoneResult.RowID = %d, want %d", res.RowID, rowid)
	}
	if got := scalar[[]byte](t, db, `SELECT raw_json FROM advisory WHERE source_id = ?`, id); !bytes.Equal(got, rawBefore) {
		t.Error("raw_json changed during a tombstone; the column holds the publisher's bytes verbatim")
	}
	if got := scalar[int](t, db, `SELECT count(*) FROM affected WHERE source_id = ?`, id); got != affectedBefore {
		t.Errorf("affected rows went from %d to %d", affectedBefore, got)
	}
	if got := scalar[int](t, db, `SELECT count(*) FROM cve_alias WHERE source_id = ?`, id); got != aliasBefore {
		t.Errorf("cve_alias rows went from %d to %d", aliasBefore, got)
	}
	if got := scalar[int](t, db, `SELECT count(*) FROM finding WHERE source_id = ?`, id); got != 1 {
		t.Errorf("the dependent finding was removed (%d rows)", got)
	}
}

// TestTheRowidGuardFiresWhenARowWouldMove exercises the one check in this
// package that the public API cannot reach.
//
// The rowid cannot move today: the write is ON CONFLICT DO UPDATE and the
// statement allowlist admits nothing else. The check exists against the day
// somebody reaches for INSERT OR REPLACE, which fails exactly this way and
// fails SILENTLY — the row is re-inserted under a new rowid and its FTS entry
// is orphaned with no error anywhere. A defensive check nothing ever fires is
// a check nobody knows works, so this test lies to the writer about the rowid
// it read and requires the refusal.
func TestTheRowidGuardFiresWhenARowWouldMove(t *testing.T) {
	db := openCache(t)
	const id = "CVE-2026-9001"
	seedPublished(t, db, id)
	ts := newTombstoner(t, db)

	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	row, err := ts.readRow(t.Context(), tx, testFeedID, id)
	if err != nil {
		t.Fatalf("readRow: %v", err)
	}
	row.rowid++ // the row the writer thinks it read is not the row it will write

	_, _, err = ts.writeTombstonedRow(t.Context(), tx, testFeedID, id,
		cache.AdvisoryWithdrawn, fixtureClock.Format(time.RFC3339), row)
	if err == nil {
		t.Fatal("the writer accepted a rowid that had moved; that is the INSERT OR REPLACE " +
			"failure mode, and its whole danger is that it is silent")
	}
	if !strings.Contains(err.Error(), "orphan") {
		t.Errorf("the refusal does not say what goes wrong: %v", err)
	}
}

// TestTombstoneRemovesTheAdvisoryFromTheSearchIndex: exit criterion 22 seen
// from the FTS side. The row stays addressable; its text stops matching.
func TestTombstoneRemovesTheAdvisoryFromTheSearchIndex(t *testing.T) {
	db := openCache(t)
	const id = "CVE-2026-3456"
	seedPublished(t, db, id)

	if got := scalar[int](t, db,
		`SELECT count(*) FROM advisory_fts WHERE advisory_fts MATCH 'quorumwidget'`); got != 1 {
		t.Fatalf("the seed advisory is not in the index (%d hits), so its removal proves nothing", got)
	}
	if _, err := newTombstoner(t, db).Tombstone(t.Context(), testFeedID, id, string(ReasonWithdrawn)); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if got := scalar[int](t, db,
		`SELECT count(*) FROM advisory_fts WHERE advisory_fts MATCH 'quorumwidget'`); got != 0 {
		t.Errorf("a withdrawn advisory still matches a search (%d hits)", got)
	}
	if got := scalar[int](t, db, `SELECT count(*) FROM advisory WHERE source_id = ?`, id); got != 1 {
		t.Errorf("the advisory row went with its index entry (%d rows)", got)
	}
}

// TestTombstoneIsIdempotentAndKeepsTheFirstRetractionTime. A nightly
// reconcile re-runs this; a second call must not make a year-old withdrawal
// look like today's news.
func TestTombstoneIsIdempotentAndKeepsTheFirstRetractionTime(t *testing.T) {
	db := openCache(t)
	const id = "CVE-2026-4567"
	seedPublished(t, db, id)

	first, err := NewTombstoner(db, func() time.Time { return fixtureClock })
	if err != nil {
		t.Fatalf("NewTombstoner: %v", err)
	}
	res1, err := first.Tombstone(t.Context(), testFeedID, id, string(ReasonWithdrawn))
	if err != nil {
		t.Fatalf("first Tombstone: %v", err)
	}
	if res1.AlreadyTombstoned {
		t.Error("the first tombstone reported the row as already tombstoned")
	}

	later := fixtureClock.Add(365 * 24 * time.Hour)
	second, err := NewTombstoner(db, func() time.Time { return later })
	if err != nil {
		t.Fatalf("NewTombstoner: %v", err)
	}
	res2, err := second.Tombstone(t.Context(), testFeedID, id, string(ReasonWithdrawn))
	if err != nil {
		t.Fatalf("second Tombstone: %v", err)
	}
	if !res2.AlreadyTombstoned {
		t.Error("the second tombstone did not report the row as already tombstoned")
	}
	if res2.TombstonedAt != res1.TombstonedAt {
		t.Errorf("the retraction time moved from %q to %q on a repeat call",
			res1.TombstonedAt, res2.TombstonedAt)
	}
	stored := scalar[string](t, db, `SELECT tombstoned_at FROM advisory WHERE source_id = ?`, id)
	if stored != res1.TombstonedAt {
		t.Errorf("tombstoned_at in the database is %q; the first retraction recorded %q",
			stored, res1.TombstonedAt)
	}

	// A state CHANGE is still applied, and still does not move the clock.
	res3, err := second.Tombstone(t.Context(), testFeedID, id, string(ReasonRejected))
	if err != nil {
		t.Fatalf("withdrawn -> rejected: %v", err)
	}
	if res3.State != cache.AdvisoryRejected {
		t.Errorf("state = %q, want %q", res3.State, cache.AdvisoryRejected)
	}
	if res3.TombstonedAt != res1.TombstonedAt {
		t.Errorf("a state change moved the retraction time to %q", res3.TombstonedAt)
	}
	if got := scalar[string](t, db, `SELECT state FROM advisory WHERE source_id = ?`, id); got != cache.AdvisoryRejected {
		t.Errorf("stored state = %q, want %q", got, cache.AdvisoryRejected)
	}
}

// TestTombstoningAnAdvisoryTheCacheDoesNotHoldIsRefused. "Applied to nothing"
// and "applied successfully" are different facts.
func TestTombstoningAnAdvisoryTheCacheDoesNotHoldIsRefused(t *testing.T) {
	db := openCache(t)
	_, err := newTombstoner(t, db).Tombstone(t.Context(), testFeedID, "CVE-2026-0000", string(ReasonWithdrawn))
	if !errors.Is(err, ErrNoSuchAdvisory) {
		t.Fatalf("err = %v; want ErrNoSuchAdvisory", err)
	}
}

// TestTombstoneRefusesAnIncompleteKey.
func TestTombstoneRefusesAnIncompleteKey(t *testing.T) {
	db := openCache(t)
	ts := newTombstoner(t, db)
	for name, key := range map[string][2]string{
		"no source":    {"", "CVE-2026-1"},
		"no source id": {testFeedID, ""},
		"whitespace":   {"  ", "  "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ts.Tombstone(t.Context(), key[0], key[1], string(ReasonWithdrawn)); !errors.Is(err, ErrBadKey) {
				t.Fatalf("err = %v; want ErrBadKey", err)
			}
		})
	}
}

// TestNewTombstonerRefusesWithoutACache.
func TestNewTombstonerRefusesWithoutACache(t *testing.T) {
	if _, err := NewTombstoner(nil, nil); !errors.Is(err, ErrNoCache) {
		t.Fatalf("err = %v; want ErrNoCache", err)
	}
}

// ---------------------------------------------------------------------------
// The two allowlists, verified RED
// ---------------------------------------------------------------------------

// TestTheReasonAllowlistRefusesWhatItDoesNotKnow. There is deliberately no
// default, because the default would be 'published' — the state that means NOT
// tombstoned.
func TestTheReasonAllowlistRefusesWhatItDoesNotKnow(t *testing.T) {
	refused := []string{
		"", "  ", "deleted", "removed", "disputed", "WITHDRAWN", "Withdrawn",
		"withdrawn ", " withdrawn", "withdrawn\n", "published", "retracted",
		"withdrawn; drop table advisory",
	}
	for _, r := range refused {
		if _, err := StateForReason(r); !errors.Is(err, ErrReasonNotAllowed) {
			t.Errorf("StateForReason(%q) was accepted; only an exact member of the allowlist may be", r)
		}
	}
	for _, r := range Reasons() {
		state, err := StateForReason(string(r))
		if err != nil {
			t.Fatalf("StateForReason(%q): %v", r, err)
		}
		switch state {
		case cache.AdvisoryWithdrawn, cache.AdvisoryRejected:
		case cache.AdvisoryPublished:
			t.Errorf("reason %q maps to %q, which is the state that means NOT tombstoned", r, state)
		default:
			t.Errorf("reason %q maps to %q, which is not a state the schema admits", r, state)
		}
	}
}

// TestPoisonedIsRecordedAsWithdrawnAndTheReasonSurvives. research/06 Risk #4
// names poisoned advisories separately from withdrawn ones; the schema's three
// states cannot, so the distinction lives on the result.
func TestPoisonedIsRecordedAsWithdrawnAndTheReasonSurvives(t *testing.T) {
	db := openCache(t)
	const id = "CVE-2026-5678"
	seedPublished(t, db, id)

	res, err := newTombstoner(t, db).Tombstone(t.Context(), testFeedID, id, string(ReasonPoisoned))
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if res.State != cache.AdvisoryWithdrawn {
		t.Errorf("state = %q, want %q", res.State, cache.AdvisoryWithdrawn)
	}
	if res.Reason != ReasonPoisoned {
		t.Errorf("Reason = %q; the reason as given must survive the mapping to a schema state", res.Reason)
	}
}

// TestTheStatementAllowlistRefusesADelete is the guard, VERIFIED RED against
// the statement it exists to stop.
func TestTheStatementAllowlistRefusesADelete(t *testing.T) {
	forbidden := []string{
		`DELETE FROM advisory WHERE source = ? AND source_id = ?`,
		`delete from advisory`,
		`DELETE FROM finding WHERE source_id = ?`,
		`DELETE FROM affected WHERE source_id = ?`,
		`DROP TABLE advisory_fts`,
		`INSERT INTO advisory_fts(advisory_fts) VALUES('rebuild')`,
		`UPDATE advisory SET state = 'withdrawn'`,
		strings.TrimSpace(selectAdvisoryRowSQL) + " LIMIT 1",
	}
	for _, q := range forbidden {
		if err := checkStatement(q); !errors.Is(err, ErrStatementNotAllowed) {
			t.Errorf("checkStatement(%q) = %v; want ErrStatementNotAllowed", condense(q), err)
		}
	}
	// And the members really are members, or the guard above would pass by
	// refusing everything.
	for q := range allowedStatements {
		if err := checkStatement(q); err != nil {
			t.Errorf("checkStatement refused its own allowlist member %q: %v", condense(q), err)
		}
	}
}

// TestTheStatementAllowlistCarriesNoRowRemoval closes the other route: not
// "somebody ran a DELETE" but "somebody ADDED one to the allowlist".
//
// advisory_fts is exempt by name and only by name: its DELETE is scoped to a
// rowid, removes an index entry rather than a record, and is required — a
// withdrawn advisory must stop matching a search.
func TestTheStatementAllowlistCarriesNoRowRemoval(t *testing.T) {
	if len(allowedStatements) == 0 {
		t.Fatal("the allowlist is empty, so this scan verifies nothing")
	}
	for q, reason := range allowedStatements {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("allowlist member %q has no reason; an allowlist without reasons is not one",
				condense(q))
		}
		flat := strings.ToLower(condense(q))
		if !strings.Contains(flat, "delete") && !strings.Contains(flat, "drop") {
			continue
		}
		if flat == strings.ToLower(condense(cache.DeleteAdvisoryFTSSQL)) {
			continue
		}
		t.Errorf("allowlist member %q removes rows. A withdrawn or REJECTED advisory is "+
			"TOMBSTONED, never deleted (A.2 exit criterion 22).", condense(q))
	}
}

// TestEveryStatementThisPackageRunsIsOnTheAllowlist walks this package's own
// source and requires every SQL-shaped string constant to be an allowlist
// member.
//
// It is the complement of checkStatement: the gate proves that what reaches
// the driver was checked, and this proves nobody added a statement that
// bypasses the gate by not being a constant it knows about.
func TestEveryStatementThisPackageRunsIsOnTheAllowlist(t *testing.T) {
	for _, q := range []string{
		selectAdvisoryRowSQL,
		selectFindingsForAdvisorySQL,
		selectInvalidatedFindingsSQL,
		cache.UpsertAdvisorySQL,
		cache.DeleteAdvisoryFTSSQL,
	} {
		if err := checkStatement(q); err != nil {
			t.Errorf("a statement this package executes is not allowlisted: %v", err)
		}
	}
	if _, ok := allowedStatements[strings.TrimSpace(cache.UpsertAdvisorySQL)]; !ok {
		t.Fatal("the shared advisory write shape is not on the allowlist, so the tombstone would " +
			"have to compose its own UPDATE — which is the second write shape " +
			"internal/ingest/cache/schema.go exports the first one to prevent")
	}
}

// ---------------------------------------------------------------------------
// Cross-cutting: this package writes through A.14 and invents no vocabulary
// ---------------------------------------------------------------------------

// TestDriftRecordIsDeltaRecord holds the alias. A parallel record type would
// be a parallel write path a week later, and the two would drift.
func TestDriftRecordIsDeltaRecord(t *testing.T) {
	var r Record
	var d delta.Record
	if reflect.TypeOf(r) != reflect.TypeOf(d) {
		t.Fatalf("drift.Record is %v and delta.Record is %v; they must be the same type",
			reflect.TypeOf(r), reflect.TypeOf(d))
	}
}

// TestAdvisoryStatesComeFromTheCachePackage: the states this package writes
// are internal/ingest/cache's constants, and the schema's own CHECK is the
// arbiter. A bare string literal for an enum value is how ten cross-area
// defects happened on this project.
func TestAdvisoryStatesComeFromTheCachePackage(t *testing.T) {
	literals, err := cache.CheckLiterals("advisory_state")
	if err != nil {
		t.Fatalf("cache.CheckLiterals: %v", err)
	}
	legal := map[string]bool{}
	for _, l := range literals {
		legal[l] = true
	}
	if len(legal) != 3 {
		t.Fatalf("the schema's advisory_state CHECK admits %d values (%v); this package was "+
			"written against three", len(legal), literals)
	}
	for _, r := range Reasons() {
		state, err := StateForReason(string(r))
		if err != nil {
			t.Fatalf("StateForReason(%q): %v", r, err)
		}
		if !legal[state] {
			t.Errorf("reason %q writes state %q, which the schema's CHECK does not admit (%v)",
				r, state, literals)
		}
	}

	// The one state literal this package embeds in SQL is bound to the same
	// constant. A bare literal inside a query string is invisible to the Go
	// compiler and is how an enum value drifts from its owner.
	want := "'" + cache.AdvisoryPublished + "'"
	if !strings.Contains(selectInvalidatedFindingsSQL, want) {
		t.Errorf("the invalidated-findings query does not compare against %s; its literal has "+
			"drifted from internal/ingest/cache's constant:\n%s", want, condense(selectInvalidatedFindingsSQL))
	}
}

// TestADocumentWithTrailingContentIsRefused: two concatenated advisories parse
// as "the first one" to a streaming decoder, and "the first one" is a dropped
// record wearing a successful parse.
func TestADocumentWithTrailingContentIsRefused(t *testing.T) {
	first := mustJSON(t, cveDoc("CVE-2026-9101", "5.1"))
	second := mustJSON(t, cveDoc("CVE-2026-9102", "5.1"))
	joined := append(append([]byte{}, first...), second...)

	if _, _, err := Parse(testFeedID, joined); !errors.Is(err, ErrNotAnObject) {
		t.Fatalf("err = %v; want ErrNotAnObject", err)
	}
}

// TestTheDegradingCodeTableDefaultsToDegrading. A code added later and
// forgotten must degrade, not sail through.
func TestTheDegradingCodeTableDefaultsToDegrading(t *testing.T) {
	if !Code("a-code-nobody-listed").Degrading() {
		t.Fatal("an unlisted code does not degrade; the default has to be the safe one, because " +
			"the unsafe one is invisible")
	}
	if CodeUnknownField.Degrading() {
		t.Error("CodeUnknownField degrades; a flag that is always set is a flag nobody reads")
	}
	for _, c := range []Code{CodeUnknownDataVersion, CodeMissingDataVersion,
		CodeUnknownFieldLoadBearing, CodeUndecodable, CodeDecoderDegraded, CodeFieldsTruncated} {
		if !c.Degrading() {
			t.Errorf("%s does not degrade", c)
		}
	}
}

// TestAMissingDataVersionIsTreatedAsUnknown. A document that will not say what
// it is has not earned the benefit of the doubt.
func TestAMissingDataVersionIsTreatedAsUnknown(t *testing.T) {
	doc := cveDoc("CVE-2026-6789", "5.1")
	delete(doc, "dataVersion")

	rec, rep, err := Parse(testFeedID, mustJSON(t, doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !rep.Degraded || !rep.Has(CodeMissingDataVersion) {
		t.Fatalf("a record with no dataVersion was not degraded: %s", rep)
	}
	if !rec.ParseDegraded {
		t.Error("the record's flag disagrees with the report")
	}
}

// TestReportStringNamesTheFieldsItDegradedOn. "Degraded" without "which" is a
// status nobody can act on.
func TestReportStringNamesTheFieldsItDegradedOn(t *testing.T) {
	doc := cveDoc("CVE-2026-7890", "5.1")
	firstAffectedVersion(t, doc)["someNewRangeKey"] = "x"

	_, rep, err := Parse(testFeedID, mustJSON(t, doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	line := rep.String()
	for _, want := range []string{"DEGRADED", "someNewRangeKey", string(CodeUnknownFieldLoadBearing)} {
		if !strings.Contains(line, want) {
			t.Errorf("Report.String() does not mention %q:\n%s", want, line)
		}
	}
}

// TestOversizedDocumentsAreRefusedOnWhatArrived.
func TestOversizedDocumentsAreRefusedOnWhatArrived(t *testing.T) {
	raw := bytes.Repeat([]byte("a"), delta.MaxDocumentBytes+1)
	if _, _, err := Parse(testFeedID, raw); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("err = %v; want ErrDocumentTooLarge", err)
	}
}

// TestFindingsReferencingRefusesWithoutACache.
func TestFindingsReferencingRefusesWithoutACache(t *testing.T) {
	if _, err := FindingsReferencing(context.Background(), nil, "s", "i"); !errors.Is(err, ErrNoCache) {
		t.Fatalf("err = %v; want ErrNoCache", err)
	}
	if _, err := InvalidatedFindings(context.Background(), nil); !errors.Is(err, ErrNoCache) {
		t.Fatalf("err = %v; want ErrNoCache", err)
	}
}

// TestFindingsAreOrderedAndComplete. A read path that returns rows in an
// arbitrary order makes a diff between two runs unreadable, which is how a
// missing row stops being noticed.
func TestFindingsAreOrderedAndComplete(t *testing.T) {
	db := openCache(t)
	const id = "CVE-2026-8899"
	parseAndApply(t, db, mustJSON(t, cveDoc(id, "5.1")))
	for _, n := range []string{"c", "a", "b"} {
		insertFinding(t, db, "finding-"+n, testFeedID, id)
	}

	got, err := FindingsReferencing(t.Context(), db, testFeedID, id)
	if err != nil {
		t.Fatalf("FindingsReferencing: %v", err)
	}
	ids := make([]string, 0, len(got))
	for _, f := range got {
		ids = append(ids, f.FindingID)
	}
	want := []string{"finding-a", "finding-b", "finding-c"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("findings = %v, want %v", ids, want)
	}
	if !sort.StringsAreSorted(ids) {
		t.Error("the result is not ordered")
	}
}
