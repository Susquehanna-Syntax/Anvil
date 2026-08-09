// Tests for the Lane A ingestion cache (step A.2).
//
// The load-bearing one is TestDeltaBatchIsRowScoped: it drives 200 synthetic
// advisories through the real upsert statements, updates 5 of them, and proves
// two things at once — that `advisory_fts` reflects the update (no stale terms
// survive), and that no statement reaching the DRIVER creates, drops or
// rebuilds a virtual table. The second half is an observation of a real SQL
// trace, not an assertion about code someone read, because "no code path may
// rebuild the FTS index" is a claim about every future writer as well as this
// one.
//
// Nothing here reaches the network, and nothing here opens or imports
// internal/store.

package cache

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// ---------------------------------------------------------------------------
// A tracing driver, so "no code path rebuilds the FTS index" is observed
// ---------------------------------------------------------------------------

const traceDriverName = "sqlite-anvil-cache-trace"

// sqlTrace records every statement handed to the driver layer.
type sqlTrace struct {
	mu    sync.Mutex
	stmts []string
}

func (l *sqlTrace) record(q string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stmts = append(l.stmts, q)
}

func (l *sqlTrace) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stmts = nil
}

func (l *sqlTrace) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.stmts...)
}

var trace = &sqlTrace{}

type traceDriver struct{ base driver.Driver }

func (d traceDriver) Open(name string) (driver.Conn, error) {
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return traceConn{Conn: c}, nil
}

// traceConn forwards every statement-carrying method to the real connection
// after recording the SQL. It implements every optional interface
// database/sql probes for, so no call can slip past by falling back to a path
// this wrapper does not cover.
type traceConn struct{ driver.Conn }

func (c traceConn) Prepare(query string) (driver.Stmt, error) {
	trace.record(query)
	return c.Conn.Prepare(query)
}

func (c traceConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	trace.record(query)
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, query)
	}
	return c.Conn.Prepare(query)
}

func (c traceConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	trace.record(query)
	e, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return e.ExecContext(ctx, query, args)
}

func (c traceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	trace.record(query)
	q, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return q.QueryContext(ctx, query, args)
}

func (c traceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Conn.Begin()
}

func (c traceConn) ResetSession(ctx context.Context) error {
	if r, ok := c.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c traceConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func init() {
	// sql.Open resolves the driver immediately and connects lazily, so this
	// neither creates a file nor opens a connection.
	probe, err := sql.Open("sqlite", "file:anvil-cache-driver-probe?mode=memory")
	if err != nil {
		panic("cache_test: cannot resolve the sqlite driver: " + err.Error())
	}
	base := probe.Driver()
	_ = probe.Close()
	sql.Register(traceDriverName, traceDriver{base: base})
}

// useTraceDriver points this package's Open at the tracing driver for the
// duration of one test.
func useTraceDriver(t *testing.T) {
	t.Helper()
	prev := driverName
	driverName = traceDriverName
	trace.reset()
	t.Cleanup(func() {
		driverName = prev
		trace.reset()
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func cachePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "anvil-cache.sqlite")
}

func openCache(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func openMigrated(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := cachePath(t)
	db := openCache(t, path)
	if _, err := Migrate(t.Context(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db, path
}

// insertAdvisory writes one advisory through the package's own upsert
// statement and returns its rowid — the key advisory_fts is addressed by.
func insertAdvisory(t *testing.T, db *sql.DB, source, sourceID string, mutate func(a *advisoryRow)) int64 {
	t.Helper()
	a := advisoryRow{
		source:      source,
		sourceID:    sourceID,
		state:       AdvisoryPublished,
		licenseSPDX: "CC0-1.0",
		licenseTier: int(config.LicenseTier0),
		trust:       string(AdvisoryTrustDefault),
		asOf:        time.Unix(0, 0).UTC().Format(time.RFC3339),
		rawJSON:     []byte(`{}`),
	}
	if mutate != nil {
		mutate(&a)
	}
	rowid, err := a.exec(t.Context(), db)
	if err != nil {
		t.Fatalf("upsert advisory (%s, %s): %v", source, sourceID, err)
	}
	return rowid
}

type advisoryRow struct {
	source       string
	sourceID     string
	cveID        any
	state        string
	tombstonedAt any
	kev          int
	licenseSPDX  any
	licenseNote  any
	licenseTier  int
	trust        string
	asOf         string
	staleness    int
	parseDegrade int
	rawJSON      []byte
}

func (a advisoryRow) exec(ctx context.Context, db *sql.DB) (int64, error) {
	var rowid int64
	err := db.QueryRowContext(ctx, UpsertAdvisorySQL,
		a.source, a.sourceID, a.cveID, nil, nil, a.state, a.tombstonedAt,
		nil, nil, nil, nil, nil, a.kev,
		a.licenseSPDX, a.licenseNote, a.licenseTier, a.trust,
		a.asOf, a.staleness, a.parseDegrade, nil, a.rawJSON,
	).Scan(&rowid)
	return rowid, err
}

func indexAdvisoryText(t *testing.T, db *sql.DB, rowid int64, description, refs string) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), UpsertAdvisoryFTSSQL, rowid, description, refs); err != nil {
		t.Fatalf("indexing advisory rowid %d: %v", rowid, err)
	}
}

func ftsHits(t *testing.T, db *sql.DB, match string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM advisory_fts WHERE advisory_fts MATCH ?`, match).Scan(&n); err != nil {
		t.Fatalf("MATCH %q: %v", match, err)
	}
	return n
}

func columnsOf(t *testing.T, db *sql.DB, table string) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "SELECT name, type FROM pragma_table_info(?)", table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			t.Fatalf("scanning pragma_table_info(%s): %v", table, err)
		}
		out[name] = typ
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating pragma_table_info(%s): %v", table, err)
	}
	return out
}

func columnDefault(t *testing.T, db *sql.DB, table, column string) string {
	t.Helper()
	var dflt sql.NullString
	err := db.QueryRowContext(t.Context(),
		"SELECT dflt_value FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&dflt)
	if err != nil {
		t.Fatalf("default of %s.%s: %v", table, column, err)
	}
	return strings.Trim(dflt.String, "'")
}

// ---------------------------------------------------------------------------
// Schema shape
// ---------------------------------------------------------------------------

// TestSchemaCreatesTheTablesTheExpectedOutputNames pins the table set A.2's
// "Expected output schema" enumerates. A table quietly renamed or dropped
// breaks a sibling step that cannot see this file.
func TestSchemaCreatesTheTablesTheExpectedOutputNames(t *testing.T) {
	want := []string{
		"feed_state", "advisory", "cve_alias", "affected",
		"advisory_fts", "license_dir_manifest", "finding",
	}
	got := Tables()
	if len(got) != len(want) {
		t.Fatalf("Tables() = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Tables()[%d] = %q, want %q (full list %v)", i, got[i], want[i], got)
		}
	}

	db, _ := openMigrated(t)
	for _, table := range want {
		var n int
		if err := db.QueryRowContext(t.Context(),
			"SELECT count(*) FROM sqlite_schema WHERE name = ?", table).Scan(&n); err != nil {
			t.Fatalf("looking for %s: %v", table, err)
		}
		if n == 0 {
			t.Errorf("%s is in the DDL but not in the migrated file", table)
		}
	}
}

// TestFTS5ModuleIsInUse is A.2's stop condition: "sqlite_master shows fts5
// module in use". It reads the committed DDL back out of the file rather than
// trusting the constant, because a migration that silently degraded the
// virtual table to something else would still leave the constant intact.
func TestFTS5ModuleIsInUse(t *testing.T) {
	db, _ := openMigrated(t)

	var ddl string
	err := db.QueryRowContext(t.Context(),
		"SELECT sql FROM sqlite_master WHERE name = 'advisory_fts'").Scan(&ddl)
	if err != nil {
		t.Fatalf("reading advisory_fts DDL from sqlite_master: %v", err)
	}
	lower := strings.ToLower(ddl)
	if !strings.Contains(lower, "using fts5") {
		t.Fatalf("advisory_fts is not an fts5 table: %s", ddl)
	}
	if !strings.Contains(lower, "porter unicode61") {
		t.Errorf("advisory_fts lost its porter unicode61 tokenizer: %s", ddl)
	}
	if !strings.Contains(lower, "content=''") {
		t.Errorf("advisory_fts is no longer contentless, so it duplicates raw_json: %s", ddl)
	}
	if !strings.Contains(lower, "contentless_delete=1") {
		t.Errorf("advisory_fts lost contentless_delete=1; row-scoped replacement silently leaves "+
			"stale terms in the index (see TestContentlessDeleteIsWhatMakesUpdatesVisible): %s", ddl)
	}

	// The shadow tables are the module actually being in use, not just named.
	var shadows int
	if err := db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM sqlite_master WHERE name LIKE 'advisory_fts_%'").Scan(&shadows); err != nil {
		t.Fatalf("counting fts5 shadow tables: %v", err)
	}
	if shadows == 0 {
		t.Fatal("advisory_fts has no shadow tables; the fts5 module is not backing it")
	}
}

// TestAdvisoryCarriesEverySpineColumn is A.2's stop condition on columns.
//
// READING RECORDED: the stop condition says "every advisory-carrying table has
// license_spdx, license_manual_note, license_tier, anvil_trust, as_of,
// staleness_seconds, parse_degraded". `advisory` is the only table that
// carries advisory CONTENT; `affected` and `cve_alias` carry ranges and
// aliases keyed to it by foreign key, and the plan's own DDL gives them none
// of these columns. Duplicating a licence tier onto every child row would
// create a second, drifting answer to a question the parent already answers.
// `finding` is Lane A's own output and carries the S6 subset the plan's DDL
// specifies for it, which is checked separately below.
func TestAdvisoryCarriesEverySpineColumn(t *testing.T) {
	db, _ := openMigrated(t)

	cols := columnsOf(t, db, "advisory")
	for _, want := range []string{
		"license_spdx", "license_manual_note", "license_tier",
		"anvil_trust", "as_of", "staleness_seconds", "parse_degraded",
	} {
		if _, ok := cols[want]; !ok {
			t.Errorf("advisory is missing the required column %q (spine S6/S8)", want)
		}
	}

	findingCols := columnsOf(t, db, "finding")
	for _, want := range []string{"anvil_trust", "as_of", "staleness_seconds", "remediable_by_agent"} {
		if _, ok := findingCols[want]; !ok {
			t.Errorf("finding is missing the required column %q (spine S6)", want)
		}
	}
}

// TestPrimaryKeyIsSourceAndSourceIDNotCVE guards research/06 Risk #2: a
// cvelistV5 outage must be survivable by swapping to EUVD/OSV/GHSA without
// touching detector code, which is impossible if the CVE ID is the key.
func TestPrimaryKeyIsSourceAndSourceIDNotCVE(t *testing.T) {
	db, _ := openMigrated(t)

	rows, err := db.QueryContext(t.Context(),
		"SELECT name FROM pragma_table_info('advisory') WHERE pk > 0 ORDER BY pk")
	if err != nil {
		t.Fatalf("reading advisory primary key: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var pk []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scanning primary key: %v", err)
		}
		pk = append(pk, name)
	}
	want := []string{"source", "source_id"}
	if len(pk) != len(want) || pk[0] != want[0] || pk[1] != want[1] {
		t.Fatalf("advisory primary key is %v, want %v (research/06 Risk #2)", pk, want)
	}

	// Two sources describing one CVE must coexist. If cve_id were the key,
	// the second insert would fail.
	insertAdvisory(t, db, "cvelistv5", "CVE-2023-32681", func(a *advisoryRow) { a.cveID = "CVE-2023-32681" })
	insertAdvisory(t, db, "redhat-csaf", "RHSA-2023:4520", func(a *advisoryRow) { a.cveID = "CVE-2023-32681" })

	var n int
	if err := db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM advisory WHERE cve_id = ?", "CVE-2023-32681").Scan(&n); err != nil {
		t.Fatalf("counting advisories for one CVE: %v", err)
	}
	if n != 2 {
		t.Fatalf("two sources describing one CVE produced %d rows, want 2", n)
	}
}

// ---------------------------------------------------------------------------
// Vocabulary drift against the areas that own it
// ---------------------------------------------------------------------------

// TestTrustVocabularyMatchesRecord is the reconciliation
// plan/IMPLEMENTATION-PLAN.md §6 says nothing was ever assigned to do: area 40
// owns `anvil/trust` and this schema consumes it. If internal/record adds or
// renames a value, this test goes red instead of a NOT NULL CHECK rejecting a
// legal token at 3am during a delta sync.
func TestTrustVocabularyMatchesRecord(t *testing.T) {
	// finding may carry any of the three record values.
	got, err := CheckLiterals("finding_anvil_trust")
	if err != nil {
		t.Fatalf("CheckLiterals(finding_anvil_trust): %v", err)
	}
	var want []string
	for _, v := range record.TrustValues() {
		want = append(want, string(v))
	}
	sort.Strings(got)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if strings.Join(got, "|") != strings.Join(sortedWant, "|") {
		t.Fatalf("finding.anvil_trust admits %v, but record.TrustValues() is %v", got, want)
	}

	// advisory may carry only the values legal for a string that originated
	// OUTSIDE Anvil. record.Trust.LegalForExternalString is the authority.
	gotAdvisory, err := CheckLiterals("advisory_anvil_trust")
	if err != nil {
		t.Fatalf("CheckLiterals(advisory_anvil_trust): %v", err)
	}
	var wantAdvisory []string
	for _, v := range record.TrustValues() {
		if v.LegalForExternalString() {
			wantAdvisory = append(wantAdvisory, string(v))
		}
	}
	sort.Strings(gotAdvisory)
	sort.Strings(wantAdvisory)
	if strings.Join(gotAdvisory, "|") != strings.Join(wantAdvisory, "|") {
		t.Fatalf("advisory.anvil_trust admits %v, but record.Trust.LegalForExternalString admits %v",
			gotAdvisory, wantAdvisory)
	}

	// Every value must be one internal/record recognises, and every default
	// must be the Go constant this package exposes.
	for _, v := range append(append([]string{}, got...), gotAdvisory...) {
		if err := record.ValidateTrust(v); err != nil {
			t.Errorf("the schema admits anvil_trust=%q, which internal/record rejects: %v", v, err)
		}
	}

	db, _ := openMigrated(t)
	if got := columnDefault(t, db, "advisory", "anvil_trust"); got != string(AdvisoryTrustDefault) {
		t.Errorf("advisory.anvil_trust defaults to %q, want %q", got, AdvisoryTrustDefault)
	}
	if got := columnDefault(t, db, "finding", "anvil_trust"); got != string(FindingTrustDefault) {
		t.Errorf("finding.anvil_trust defaults to %q, want %q", got, FindingTrustDefault)
	}
}

// TestAdvisoryRefusesAnvilGeneratedTrust is the mistake internal/record
// documents area B committing, applied here: advisory text is verbatim
// publisher prose, so stamping it `anvil_generated` would disable the
// prompt-injection containment check on exactly the strings that most need it
// (spine S7).
func TestAdvisoryRefusesAnvilGeneratedTrust(t *testing.T) {
	db, _ := openMigrated(t)

	a := advisoryRow{
		source: "osv", sourceID: "GHSA-xxxx", state: AdvisoryPublished,
		licenseSPDX: "CC-BY-4.0", licenseTier: int(config.LicenseTier1),
		trust:   string(record.TrustAnvilGenerated),
		asOf:    time.Unix(0, 0).UTC().Format(time.RFC3339),
		rawJSON: []byte(`{}`),
	}
	if _, err := a.exec(t.Context(), db); err == nil {
		t.Fatal("an advisory row was accepted with anvil_trust='anvil_generated'; " +
			"record.Trust.LegalForExternalString says that is illegal for external strings")
	}
}

// TestLicenseTierVocabularyMatchesConfig reconciles the tier domain with A.1,
// which is where a feed's tier is actually declared.
func TestLicenseTierVocabularyMatchesConfig(t *testing.T) {
	var want []string
	for _, tier := range config.LicenseTierValues() {
		want = append(want, strconv.Itoa(tier.Int()))
	}
	numeric := regexp.MustCompile(`\d+`)

	for _, name := range []string{
		"feed_state_license_tier", "advisory_license_tier", "license_dir_manifest_tier",
	} {
		expr, err := CheckConstraint(name)
		if err != nil {
			t.Fatalf("CheckConstraint(%s): %v", name, err)
		}
		got := numeric.FindAllString(expr, -1)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s admits tiers %v, but config.LicenseTierValues() is %v", name, got, want)
		}
	}
}

// TestCollectorVocabularyIsExhaustive keeps the Go constants and the SQL CHECK
// from drifting; A.9 and A.10 write these values.
func TestCollectorVocabularyIsExhaustive(t *testing.T) {
	got, err := CheckLiterals("finding_collector")
	if err != nil {
		t.Fatalf("CheckLiterals(finding_collector): %v", err)
	}
	want := []string{CollectorHost, CollectorRepoSCA}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("finding.collector admits %v, want %v", got, want)
	}
}

// TestAdvisoryStateVocabularyIsExhaustive does the same for the tombstone
// states A.16 writes.
func TestAdvisoryStateVocabularyIsExhaustive(t *testing.T) {
	got, err := CheckLiterals("advisory_state")
	if err != nil {
		t.Fatalf("CheckLiterals(advisory_state): %v", err)
	}
	want := []string{AdvisoryPublished, AdvisoryWithdrawn, AdvisoryRejected}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("advisory.state admits %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Exit criteria the schema enforces rather than documents
// ---------------------------------------------------------------------------

// TestEveryAdvisoryDeclaresALicence is exit criterion 11.
func TestEveryAdvisoryDeclaresALicence(t *testing.T) {
	db, _ := openMigrated(t)

	both := advisoryRow{
		source: "alpine", sourceID: "CVE-2024-0001", state: AdvisoryPublished,
		licenseTier: int(config.LicenseTier2),
		trust:       string(AdvisoryTrustDefault),
		asOf:        time.Unix(0, 0).UTC().Format(time.RFC3339),
		rawJSON:     []byte(`{}`),
	}
	if _, err := both.exec(t.Context(), db); err == nil {
		t.Fatal("an advisory row with neither license_spdx nor license_manual_note was accepted")
	}

	// Whitespace is not a declaration.
	blank := both
	blank.licenseNote = "   "
	if _, err := blank.exec(t.Context(), db); err == nil {
		t.Fatal("an advisory row whose license_manual_note is whitespace was accepted")
	}

	// The CISA KEV shape spine S8 exists for: NOASSERTION at the API layer,
	// CC0 per the publisher's README, admitted through the manual note.
	kev := both
	kev.licenseSPDX = config.LicenseNoAssertion
	kev.licenseNote = "This work is in the public domain within the United States."
	kev.licenseTier = int(config.LicenseTier0)
	if _, err := kev.exec(t.Context(), db); err != nil {
		t.Fatalf("the CISA-KEV-shaped row (NOASSERTION + manual note) was rejected: %v", err)
	}
}

// TestHostFindingsCanNeverBeRemediable is exit criterion 21, which demands
// "no code path, flag, or config key capable of overriding it". A CHECK
// constraint is the only place that claim can be made true rather than
// asserted.
func TestHostFindingsCanNeverBeRemediable(t *testing.T) {
	db, _ := openMigrated(t)
	insertAdvisory(t, db, "ubuntu", "USN-1234-1", nil)

	insertFinding := func(collector string, remediable int) error {
		_, err := db.ExecContext(t.Context(), `
			INSERT INTO finding (
				id, collector, source, source_id, package, installed_version, ecosystem,
				remediable_by_agent, as_of, staleness_seconds, anvil_trust, detected_at
			) VALUES (?, ?, 'ubuntu', 'USN-1234-1', 'openssl', '1.1.1f', 'deb', ?, ?, 0, ?, ?)`,
			collector+"-"+strconv.Itoa(remediable), collector, remediable,
			time.Unix(0, 0).UTC().Format(time.RFC3339),
			string(FindingTrustDefault),
			time.Unix(0, 0).UTC().Format(time.RFC3339))
		return err
	}

	if err := insertFinding(CollectorHost, 0); err != nil {
		t.Fatalf("a non-remediable host finding was rejected: %v", err)
	}
	if err := insertFinding(CollectorHost, 1); err == nil {
		t.Fatal("a host-collector finding was accepted with remediable_by_agent = 1; " +
			"exit criterion 21 requires that to be unreachable")
	}
	if err := insertFinding(CollectorRepoSCA, 1); err != nil {
		t.Fatalf("a remediable repo-sca finding was rejected: %v", err)
	}
}

// TestWithdrawnAdvisoriesMustBeTombstoned is exit criterion 22's structural
// half: a non-published state without a tombstone timestamp loses the "when"
// A.16 needs to invalidate dependent findings.
func TestWithdrawnAdvisoriesMustBeTombstoned(t *testing.T) {
	db, _ := openMigrated(t)

	base := advisoryRow{
		source: "ghsa", sourceID: "GHSA-aaaa-bbbb-cccc", state: AdvisoryWithdrawn,
		licenseSPDX: "CC-BY-4.0", licenseTier: int(config.LicenseTier1),
		trust:   string(AdvisoryTrustDefault),
		asOf:    time.Unix(0, 0).UTC().Format(time.RFC3339),
		rawJSON: []byte(`{}`),
	}
	if _, err := base.exec(t.Context(), db); err == nil {
		t.Fatal("a withdrawn advisory was accepted with tombstoned_at NULL")
	}
	base.tombstonedAt = time.Unix(0, 0).UTC().Format(time.RFC3339)
	if _, err := base.exec(t.Context(), db); err != nil {
		t.Fatalf("a properly tombstoned withdrawn advisory was rejected: %v", err)
	}

	// A published advisory must not carry a tombstone: that would be a row
	// claiming to be both live and retracted.
	live := base
	live.sourceID = "GHSA-dddd-eeee-ffff"
	live.state = AdvisoryPublished
	if _, err := live.exec(t.Context(), db); err == nil {
		t.Fatal("a published advisory was accepted with a non-null tombstoned_at")
	}
}

// TestForeignKeysAreEnforced proves the DSN pragma actually took. Without it,
// an `affected` range can outlive the advisory that justified it and the
// comparator matches against nothing.
func TestForeignKeysAreEnforced(t *testing.T) {
	db, _ := openMigrated(t)

	_, err := db.ExecContext(t.Context(), `
		INSERT INTO affected (source, source_id, ecosystem, package, distro_backport)
		VALUES ('cvelistv5', 'CVE-9999-0001', 'deb', 'openssl', 0)`)
	if err == nil {
		t.Fatal("an affected row was accepted for an advisory that does not exist")
	}

	insertAdvisory(t, db, "cvelistv5", "CVE-9999-0001", nil)
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO affected (source, source_id, ecosystem, package, distro_backport)
		VALUES ('cvelistv5', 'CVE-9999-0001', 'deb', 'openssl', 1)`); err != nil {
		t.Fatalf("a valid affected row was rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The delta path — A.2's headline validation
// ---------------------------------------------------------------------------

// TestDeltaBatchIsRowScoped inserts 200 synthetic advisories, updates 5, and
// asserts (a) advisory_fts reflects every update with no stale term left
// behind, and (b) the SQL trace of the batch contains no CREATE or DROP of a
// virtual table and no FTS5 'rebuild' command.
//
// The trace is taken at the driver layer, so it also covers any statement
// database/sql synthesises on the caller's behalf.
func TestDeltaBatchIsRowScoped(t *testing.T) {
	useTraceDriver(t)
	db, _ := openMigrated(t)

	const rows = 200
	const updated = 5

	rowids := make([]int64, rows)
	for i := range rows {
		id := fmt.Sprintf("CVE-2026-%04d", i)
		rowids[i] = insertAdvisory(t, db, "cvelistv5", id, func(a *advisoryRow) {
			a.cveID = id
		})
		indexAdvisoryText(t, db, rowids[i],
			fmt.Sprintf("advisory %d concerns tokenalpha%04d in a vulnerable component", i, i),
			fmt.Sprintf("https://example.invalid/a/%04d", i))
	}

	var indexed int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM advisory_fts").Scan(&indexed); err != nil {
		t.Fatalf("counting advisory_fts rows: %v", err)
	}
	if indexed != rows {
		t.Fatalf("advisory_fts holds %d rows after %d inserts", indexed, rows)
	}

	// Everything above is setup. The trace that matters is the delta batch.
	trace.reset()

	for i := range updated {
		id := fmt.Sprintf("CVE-2026-%04d", i)
		rowid := insertAdvisory(t, db, "cvelistv5", id, func(a *advisoryRow) {
			a.cveID = id
			a.staleness = 42
		})
		if rowid != rowids[i] {
			t.Fatalf("upserting %s moved its rowid from %d to %d; the FTS entry is now orphaned. "+
				"UpsertAdvisorySQL must be ON CONFLICT DO UPDATE, never INSERT OR REPLACE",
				id, rowids[i], rowid)
		}
		indexAdvisoryText(t, db, rowid,
			fmt.Sprintf("advisory %d concerns tokenbeta%04d in a vulnerable component", i, i),
			fmt.Sprintf("https://example.invalid/a/%04d", i))
	}

	batch := trace.snapshot()

	// (a) the index reflects the update, and nothing stale survives.
	for i := range updated {
		if got := ftsHits(t, db, fmt.Sprintf("tokenalpha%04d", i)); got != 0 {
			t.Errorf("row %d still matches its OLD term tokenalpha%04d (%d hits); the FTS index was "+
				"not row-scoped-replaced", i, i, got)
		}
		if got := ftsHits(t, db, fmt.Sprintf("tokenbeta%04d", i)); got != 1 {
			t.Errorf("row %d does not match its NEW term tokenbeta%04d (%d hits)", i, i, got)
		}
	}
	for i := updated; i < rows; i++ {
		if got := ftsHits(t, db, fmt.Sprintf("tokenalpha%04d", i)); got != 1 {
			t.Errorf("untouched row %d lost its term tokenalpha%04d (%d hits)", i, i, got)
		}
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM advisory_fts").Scan(&indexed); err != nil {
		t.Fatalf("counting advisory_fts rows after the delta: %v", err)
	}
	if indexed != rows {
		t.Fatalf("advisory_fts holds %d rows after a %d-row update; a replace duplicated or dropped rows",
			indexed, rows)
	}

	// (b) the trace contains no whole-table operation on the index.
	assertNoWholeTableFTSOps(t, batch)

	// The batch touched exactly the rows it was supposed to: 5 advisory
	// upserts and 5 FTS replacements, nothing else that writes.
	writes := 0
	for _, stmt := range batch {
		if strings.Contains(stmt, "INSERT INTO advisory ") || strings.Contains(stmt, "INSERT OR REPLACE INTO advisory_fts") {
			writes++
		}
	}
	if writes != 2*updated {
		t.Errorf("the delta batch issued %d row writes, want exactly %d (one upsert plus one FTS "+
			"replacement per touched advisory); trace:\n%s", writes, 2*updated, strings.Join(batch, "\n"))
	}
}

var (
	virtualTableRE = regexp.MustCompile(`(?is)\b(create|drop)\b[^;]{0,200}\bvirtual\s+table\b`)
	ftsCommandRE   = regexp.MustCompile(`(?is)'(rebuild|delete-all|optimize)'`)
)

func assertNoWholeTableFTSOps(t *testing.T, stmts []string) {
	t.Helper()
	for i, stmt := range stmts {
		if virtualTableRE.MatchString(stmt) {
			t.Errorf("statement %d creates or drops a virtual table during a delta batch: %s", i, stmt)
		}
		if strings.Contains(strings.ToLower(stmt), "advisory_fts") && ftsCommandRE.MatchString(stmt) {
			t.Errorf("statement %d issues an fts5 whole-table command against advisory_fts: %s", i, stmt)
		}
		if lower := strings.ToLower(stmt); strings.Contains(lower, "drop") && strings.Contains(lower, "advisory_fts") {
			t.Errorf("statement %d drops advisory_fts: %s", i, stmt)
		}
	}
}

// TestContentlessDeleteIsWhatMakesUpdatesVisible is the regression guard for
// the deviation schemaSQL documents. It reproduces the plan's original
// `content=”` sketch side by side with the shipped table and shows the
// difference is not cosmetic: without contentless_delete the old terms stay
// searchable forever and no error is raised.
//
// If a future maintainer "restores the DDL to match the plan", this fails and
// explains why.
func TestContentlessDeleteIsWhatMakesUpdatesVisible(t *testing.T) {
	db, _ := openMigrated(t)

	if _, err := db.ExecContext(t.Context(),
		`CREATE VIRTUAL TABLE temp.plan_sketch_fts USING fts5(description, references_text,
		   content='', tokenize='porter unicode61')`); err != nil {
		t.Fatalf("creating the plan-sketch probe table: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS temp.plan_sketch_fts") })

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO temp.plan_sketch_fts (rowid, description, references_text) VALUES (1, 'tokenalpha', 'r')`)
	exec(`INSERT OR REPLACE INTO temp.plan_sketch_fts (rowid, description, references_text) VALUES (1, 'tokenbeta', 'r')`)

	var stale int
	if err := db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM temp.plan_sketch_fts WHERE plan_sketch_fts MATCH 'tokenalpha'`).Scan(&stale); err != nil {
		t.Fatalf("MATCH against the plan-sketch probe: %v", err)
	}
	if stale == 0 {
		t.Fatal("a plain content='' fts5 table now drops old terms on INSERT OR REPLACE. " +
			"The deviation documented on schemaSQL may no longer be needed — re-verify before removing it.")
	}

	// The shipped table does not behave that way.
	rowid := insertAdvisory(t, db, "osv", "OSV-2026-1", nil)
	indexAdvisoryText(t, db, rowid, "tokenalpha", "r")
	indexAdvisoryText(t, db, rowid, "tokenbeta", "r")
	if got := ftsHits(t, db, "tokenalpha"); got != 0 {
		t.Fatalf("advisory_fts kept the stale term after a row-scoped replace (%d hits)", got)
	}
	if got := ftsHits(t, db, "tokenbeta"); got != 1 {
		t.Fatalf("advisory_fts does not carry the new term after a row-scoped replace (%d hits)", got)
	}
}

// TestDeleteAdvisoryFTSRemovesOneRow covers A.16's tombstone path: the FTS
// entry goes, the advisory row stays.
func TestDeleteAdvisoryFTSRemovesOneRow(t *testing.T) {
	db, _ := openMigrated(t)

	keep := insertAdvisory(t, db, "osv", "OSV-2026-keep", nil)
	drop := insertAdvisory(t, db, "osv", "OSV-2026-drop", nil)
	indexAdvisoryText(t, db, keep, "tokenkeep", "")
	indexAdvisoryText(t, db, drop, "tokendrop", "")

	if _, err := db.ExecContext(t.Context(), DeleteAdvisoryFTSSQL, drop); err != nil {
		t.Fatalf("DeleteAdvisoryFTSSQL: %v", err)
	}
	if got := ftsHits(t, db, "tokendrop"); got != 0 {
		t.Errorf("the deleted row still matches (%d hits)", got)
	}
	if got := ftsHits(t, db, "tokenkeep"); got != 1 {
		t.Errorf("deleting one row disturbed another (%d hits)", got)
	}
	var n int
	if err := db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM advisory WHERE source = 'osv' AND source_id = 'OSV-2026-drop'").Scan(&n); err != nil {
		t.Fatalf("counting the advisory row: %v", err)
	}
	if n != 1 {
		t.Errorf("removing an FTS entry deleted the advisory row; exit criterion 22 says tombstone, never delete")
	}
}

// ---------------------------------------------------------------------------
// feed_state — the table A.7 reads and writes
// ---------------------------------------------------------------------------

// TestFeedStateRoundTripsForTheConditionalGETPoller exercises the shape A.7
// needs: no row means "never polled", a 200 writes an etag and a watermark,
// and a 304 moves only last_ok_at.
func TestFeedStateRoundTripsForTheConditionalGETPoller(t *testing.T) {
	db, _ := openMigrated(t)

	const feedID = "cvelistv5"
	err := db.QueryRowContext(t.Context(), SelectFeedStateSQL, feedID).Scan(
		new(sql.NullString), new(sql.NullString), new(sql.NullString), new(sql.NullString),
		new(int), new(int))
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("an unpolled feed returned %v, want sql.ErrNoRows so A.7 can treat it as never polled", err)
	}

	first := time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339)
	if _, err := db.ExecContext(t.Context(), UpsertFeedStateSQL,
		feedID, `W/"abc123"`, "Wed, 21 Oct 2026 07:28:00 GMT", "2026-10-21T00:00:00Z",
		first, 0, config.LicenseTier0.Int()); err != nil {
		t.Fatalf("first feed_state write: %v", err)
	}

	// A 304: the poller re-writes the same validators and advances only
	// last_ok_at (exit criterion 3).
	second := time.Unix(1_700_003_600, 0).UTC().Format(time.RFC3339)
	if _, err := db.ExecContext(t.Context(), UpsertFeedStateSQL,
		feedID, `W/"abc123"`, "Wed, 21 Oct 2026 07:28:00 GMT", "2026-10-21T00:00:00Z",
		second, 0, config.LicenseTier0.Int()); err != nil {
		t.Fatalf("304 feed_state write: %v", err)
	}

	var etag, lastMod, watermark, lastOK string
	var failures, tier int
	if err := db.QueryRowContext(t.Context(), SelectFeedStateSQL, feedID).
		Scan(&etag, &lastMod, &watermark, &lastOK, &failures, &tier); err != nil {
		t.Fatalf("reading feed_state back: %v", err)
	}
	if etag != `W/"abc123"` {
		t.Errorf("etag round-tripped as %q; the weak-validator prefix and quotes must survive verbatim", etag)
	}
	if lastOK != second {
		t.Errorf("last_ok_at = %q, want %q", lastOK, second)
	}
	if watermark != "2026-10-21T00:00:00Z" {
		t.Errorf("watermark = %q, want it unchanged by a 304", watermark)
	}

	var count int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM feed_state").Scan(&count); err != nil {
		t.Fatalf("counting feed_state rows: %v", err)
	}
	if count != 1 {
		t.Errorf("two writes for one feed produced %d rows; the upsert is not keyed on feed_id", count)
	}

	if _, err := db.ExecContext(t.Context(), UpsertFeedStateSQL,
		"bad-tier-feed", nil, nil, nil, nil, 0, 4); err == nil {
		t.Error("feed_state accepted license_tier = 4; research/01 defines exactly four tiers")
	}
	if _, err := db.ExecContext(t.Context(), UpsertFeedStateSQL,
		"negative-failures", nil, nil, nil, nil, -1, 0); err == nil {
		t.Error("feed_state accepted a negative consecutive_failures")
	}
}

// TestFeedStateAcceptsEveryFeedIDInTheShippedConfig proves the two halves of
// A.1 and A.2 agree on the feed_id domain, which is the produce/consume edge
// between them.
func TestFeedStateAcceptsEveryFeedIDInTheShippedConfig(t *testing.T) {
	feeds, err := config.Load(filepath.Join("..", "config", "feeds.example.yaml"))
	if err != nil {
		// NOT a skip. feeds.example.yaml is CHECKED IN at a fixed relative
		// path; it is not an optional artefact and not a platform fact. A
		// skip here reports "the produce/consume edge between A.1 and A.2 was
		// verified" whenever the file moves, is renamed, or stops parsing --
		// which is the exact failure mode internal/SKIPPED-CONTROLS.md is
		// about.
		t.Fatalf("A.1's example config could not be loaded, so the feed_id domain shared by A.1 "+
			"and A.2 was NOT cross-checked: %v", err)
	}
	if len(feeds.Feeds) == 0 {
		t.Fatal("A.1's example config declares no feeds, so this test proved nothing about the " +
			"feed_id domain (internal/ingest/config's own tests also fail on an empty table)")
	}

	db, _ := openMigrated(t)
	for _, feed := range feeds.Feeds {
		if _, err := db.ExecContext(t.Context(), UpsertFeedStateSQL,
			feed.ID, nil, nil, nil, nil, 0, feed.LicenseTier.Int()); err != nil {
			t.Errorf("feed_state rejected feed %q at tier %d: %v", feed.ID, feed.LicenseTier.Int(), err)
		}
	}

	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM feed_state").Scan(&n); err != nil {
		t.Fatalf("counting feed_state rows: %v", err)
	}
	if n != len(feeds.Feeds) {
		t.Errorf("feed_state holds %d rows for %d configured feeds", n, len(feeds.Feeds))
	}
}

// ---------------------------------------------------------------------------
// Opening and migrating
// ---------------------------------------------------------------------------

// TestMigrateIsIdempotent is A.2's stop condition: "Schema created
// idempotently on an empty file and on a file already at the latest migration
// version."
func TestMigrateIsIdempotent(t *testing.T) {
	path := cachePath(t)
	db := openCache(t, path)

	latest, err := LatestVersion()
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}

	applied, err := Migrate(t.Context(), db)
	if err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if len(applied) != latest {
		t.Fatalf("first Migrate applied %v, want every version up to %d", applied, latest)
	}
	if got, err := Version(t.Context(), db); err != nil || got != latest {
		t.Fatalf("user_version = %d (err %v), want %d", got, err, latest)
	}

	applied, err = Migrate(t.Context(), db)
	if err != nil {
		t.Fatalf("second Migrate on the same handle: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("second Migrate applied %v, want nothing", applied)
	}

	// And again on a freshly opened handle, which is the real restart case.
	_ = db.Close()
	reopened := openCache(t, path)
	applied, err = Migrate(t.Context(), reopened)
	if err != nil {
		t.Fatalf("Migrate after reopening: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("Migrate after reopening applied %v, want nothing", applied)
	}
	if got, _ := Version(t.Context(), reopened); got != latest {
		t.Fatalf("user_version after reopening = %d, want %d", got, latest)
	}
}

// TestOpenRefusesNonWALTargets covers A.2's "Do not open the DB outside WAL
// mode" forbidden action at its two reachable failure points.
func TestOpenRefusesNonWALTargets(t *testing.T) {
	for _, path := range []string{":memory:", "file:x?mode=memory", "  "} {
		if _, err := DSN(path); !errors.Is(err, ErrBadPath) {
			t.Errorf("DSN(%q) = %v, want ErrBadPath", path, err)
		}
		if _, err := Open(t.Context(), path); !errors.Is(err, ErrBadPath) {
			t.Errorf("Open(%q) = %v, want ErrBadPath", path, err)
		}
	}
	if _, err := DSN("C:/tmp/what?ever.sqlite"); !errors.Is(err, ErrBadPath) {
		t.Errorf("DSN with a '?' in the path = %v, want ErrBadPath", err)
	}

	db, _ := openMigrated(t)
	if err := CheckWAL(t.Context(), db); err != nil {
		t.Fatalf("a cache opened by Open is not in WAL mode: %v", err)
	}
	var mode string
	if err := db.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("reading journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
}

// TestCheckWALRejectsARollbackJournalDatabase proves the guard is not
// vacuously true — a handle genuinely outside WAL is refused.
func TestCheckWALRejectsARollbackJournalDatabase(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "plain.sqlite"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = raw.Close() }()
	raw.SetMaxOpenConns(1)

	if err := CheckWAL(t.Context(), raw); !errors.Is(err, ErrNotWAL) {
		t.Fatalf("CheckWAL on a delete-journal database = %v, want ErrNotWAL", err)
	}
}

// TestCheckFTS5RunsOnEveryOpen documents why the guard exists: S12's claim
// that modernc.org/sqlite bundles FTS5 is graded "absence-of-evidence", and a
// dependency bump can drop a build-time feature with no signal. If this goes
// red after a bump, the bump is the bug.
func TestCheckFTS5RunsOnEveryOpen(t *testing.T) {
	db, _ := openMigrated(t)
	if err := CheckFTS5(t.Context(), db); err != nil {
		t.Fatalf("FTS5 guard failed against modernc.org/sqlite: %v", err)
	}
	// The probe leaves nothing behind in the cache file.
	var n int
	if err := db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM sqlite_schema WHERE name LIKE ?", ftsProbeTable+"%").Scan(&n); err != nil {
		t.Fatalf("looking for probe debris: %v", err)
	}
	if n != 0 {
		t.Fatalf("the FTS5 probe left %d objects in the cache file", n)
	}
}

// TestOpenDoesNotTouchAdvisoryFTS proves the startup path — which does create
// and drop an FTS5 table for its probe — never names the real index.
func TestOpenDoesNotTouchAdvisoryFTS(t *testing.T) {
	useTraceDriver(t)
	db, _ := openMigrated(t)
	trace.reset()

	if err := CheckFTS5(t.Context(), db); err != nil {
		t.Fatalf("CheckFTS5: %v", err)
	}
	for i, stmt := range trace.snapshot() {
		if strings.Contains(strings.ToLower(stmt), "advisory_fts") {
			t.Errorf("startup statement %d names advisory_fts: %s", i, stmt)
		}
	}
}

// TestLedgerRefusesAnEditedMigration is the third load-bearing property: a
// checksum mismatch is a refusal, never a re-run and never a skip.
func TestLedgerRefusesAnEditedMigration(t *testing.T) {
	path := cachePath(t)
	db := openCache(t, path)
	if _, err := Migrate(t.Context(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if _, err := db.ExecContext(t.Context(),
		"UPDATE "+ledgerTable+" SET checksum = ? WHERE version = 1", strings.Repeat("0", 64)); err != nil {
		t.Fatalf("tampering with the ledger: %v", err)
	}
	if _, err := Migrate(t.Context(), db); !errors.Is(err, ErrMigrationLedger) {
		t.Fatalf("Migrate over a tampered ledger = %v, want ErrMigrationLedger", err)
	}
}

// TestLedgerRefusesANewerCache covers the downgrade case: a file carrying a
// migration this binary does not have.
func TestLedgerRefusesANewerCache(t *testing.T) {
	path := cachePath(t)
	db := openCache(t, path)

	current, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	future := append(append([]Migration(nil), current...), Migration{
		Version:  len(current) + 1,
		Name:     "future",
		SQL:      "CREATE TABLE future_thing (x TEXT)",
		Checksum: strings.Repeat("a", 64),
	})
	if _, err := migrateWith(t.Context(), db, future); err != nil {
		t.Fatalf("applying a synthetic future migration: %v", err)
	}

	// Now the binary that only knows the current set opens it.
	if _, err := Migrate(t.Context(), db); !errors.Is(err, ErrMigrationLedger) {
		t.Fatalf("an older binary opening a newer cache = %v, want ErrMigrationLedger", err)
	}
}

// TestFailedMigrationLeavesTheSchemaUntouched proves the whole-migration
// transaction: a failure rolls back the DDL, the user_version and the ledger
// row together.
func TestFailedMigrationLeavesTheSchemaUntouched(t *testing.T) {
	path := cachePath(t)
	db := openCache(t, path)

	current, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	broken := append(append([]Migration(nil), current...), Migration{
		Version:  len(current) + 1,
		Name:     "broken",
		SQL:      "CREATE TABLE ok_so_far (x TEXT); THIS IS NOT SQL;",
		Checksum: strings.Repeat("b", 64),
	})
	applied, err := migrateWith(t.Context(), db, broken)
	if err == nil {
		t.Fatal("a syntactically invalid migration was applied")
	}
	if len(applied) != len(current) {
		t.Fatalf("migrateWith reported %v applied, want the %d that succeeded", applied, len(current))
	}
	if got, _ := Version(t.Context(), db); got != len(current) {
		t.Errorf("user_version = %d after a failed migration, want %d", got, len(current))
	}
	var n int
	if err := db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM sqlite_schema WHERE name = 'ok_so_far'").Scan(&n); err != nil {
		t.Fatalf("looking for partially applied DDL: %v", err)
	}
	if n != 0 {
		t.Error("the first statement of a failed migration survived; it was not applied in one transaction")
	}
}

// TestMigrationChecksumsAreStable pins the definition of "the schema this
// binary carries". A changed DDL changes the checksum, which is the intended
// sensitivity; this test exists so that change is deliberate.
func TestMigrationChecksumsAreStable(t *testing.T) {
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations are defined")
	}
	if migrations[0].Version != 1 || migrations[0].Name != "init" {
		t.Fatalf("migration 1 is %d/%q, want 1/\"init\"", migrations[0].Version, migrations[0].Name)
	}
	if migrations[0].Checksum != SchemaSHA256() {
		t.Fatalf("migration 1's checksum %s does not match SchemaSHA256() %s; they must be the same "+
			"bytes", migrations[0].Checksum, SchemaSHA256())
	}
	seen := map[int]bool{}
	for _, m := range migrations {
		if seen[m.Version] {
			t.Fatalf("migration version %d is defined twice", m.Version)
		}
		seen[m.Version] = true
		if len(m.Checksum) != 64 {
			t.Errorf("migration %d has a %d-character checksum, want 64 hex characters", m.Version, len(m.Checksum))
		}
	}
}

// TestSchemaDoesNotDeclareAnythingTheStoreOfRecordOwns is a cheap structural
// guard against the confusion this package's doc comment opens with: no table
// here may be named after one in internal/store's schema, and no fingerprint
// may be defined here.
func TestSchemaDoesNotDeclareAnythingTheStoreOfRecordOwns(t *testing.T) {
	// internal/store's tables, listed here rather than imported precisely
	// because this package must not depend on it.
	storeTables := map[string]bool{
		"scan_run": true, "audit_record": true, "finding_occurrence": true,
		"handoff": true, "schema_migration": true, "advisory_alias": true,
		"advisory_affects": true, "component": true,
	}
	for _, table := range Tables() {
		if storeTables[table] {
			t.Errorf("the cache declares %q, which belongs to internal/store's schema", table)
		}
	}
	// No column anywhere in this cache may be a second fingerprint. anvil-fp/v1
	// is defined once, in internal/record (FINGERPRINT-SPEC.md); two producers
	// emitting different digests under one name breaks regression matching
	// forever with nothing to surface it, which spine S6 names explicitly.
	db, _ := openMigrated(t)
	for _, table := range Tables() {
		for column := range columnsOf(t, db, table) {
			lower := strings.ToLower(column)
			if strings.Contains(lower, "fingerprint") || strings.Contains(lower, "anvil_fp") {
				t.Errorf("%s.%s looks like a second fingerprint; anvil-fp/v1 is owned by "+
					"internal/record and Lane A must reference it, never redefine it", table, column)
			}
		}
	}
	// finding.id is Lane-A-local by contract; assert the DDL still says so, so
	// that a later step cannot quietly start writing canonical digests there.
	if !strings.Contains(schemaSQL, "Lane A local id, NOT a canonical fingerprint") {
		t.Error("finding.id lost the comment recording that it is not a canonical fingerprint")
	}
}
