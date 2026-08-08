package store

import (
	"database/sql"
	"strconv"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// newDB applies ConnectionPragmas and then schema.sql to a fresh in-memory
// database, exactly as R.5's migration will, and returns it.
//
// MaxOpenConns is pinned to 1 because each new connection to ":memory:" is a
// different, empty database.
func newDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	for _, p := range ConnectionPragmas() {
		// journal_mode is a no-op on an in-memory database (it reports
		// "memory"), which is why the WAL guarantees themselves are R.5's to
		// verify on a real file. The rest apply normally.
		if _, err := db.Exec(p); err != nil {
			t.Fatalf("pragma %q: %v", p, err)
		}
	}
	if _, err := db.Exec(Schema()); err != nil {
		t.Fatalf("applying schema.sql: %v", err)
	}
	return db
}

const (
	// 64 lowercase hex characters, the only shape ck_*_fingerprint_hex admits.
	fpA       = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	sha256Hex = "0011223344556677889900112233445566778899001122334455667788990011"
)

// seedAll inserts exactly one FK-valid row into every table schema.sql
// creates, then selects each row back. This is R.4's mandated smoke test.
func seedAll(t *testing.T, db *sql.DB) {
	t.Helper()

	type seed struct {
		table  string
		insert string
		args   []any
		verify string
	}

	seeds := []seed{
		{
			table:  "target",
			insert: `INSERT INTO target (target_id, kind, locator) VALUES (1, 'repo', 'https://example.invalid/r.git')`,
			verify: `SELECT locator FROM target WHERE target_id = 1`,
		},
		{
			table:  "trigger_policy",
			insert: `INSERT INTO trigger_policy (policy_id, target_id, kind, spec, scan_depth) VALUES (1, 1, 'cron', '0 3 * * *', 'full')`,
			verify: `SELECT spec FROM trigger_policy WHERE policy_id = 1`,
		},
		{
			table:  "ingest_watermark",
			insert: `INSERT INTO ingest_watermark (source, cursor, etag, last_success_at) VALUES ('osv', 'c1', 'e1', '2026-08-08T00:00:00Z')`,
			verify: `SELECT cursor FROM ingest_watermark WHERE source = 'osv'`,
		},
		{
			table: "advisory",
			insert: `INSERT INTO advisory (advisory_id, source, published_at, modified_at, severity, summary, content_hash, ingested_at)
			         VALUES ('CVE-2026-0001', 'osv', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 'high', 'sqli in widget', 'h1', '2026-08-08T00:00:00Z')`,
			verify: `SELECT summary FROM advisory WHERE advisory_id = 'CVE-2026-0001'`,
		},
		{
			table:  "advisory_alias",
			insert: `INSERT INTO advisory_alias (advisory_id, alias_id) VALUES ('CVE-2026-0001', 'GHSA-aaaa-bbbb-cccc')`,
			verify: `SELECT alias_id FROM advisory_alias WHERE advisory_id = 'CVE-2026-0001'`,
		},
		{
			table: "advisory_fts",
			insert: `INSERT INTO advisory_fts (rowid, summary, details, aliases)
			         SELECT rowid, summary, '', 'CVE-2026-0001' FROM advisory WHERE advisory_id = 'CVE-2026-0001'`,
			// rowid only, not a column value: `content='advisory'` makes any
			// column read go back to `advisory`, which has no `aliases`
			// column. See the KNOWN DEFECT note above this table in
			// schema.sql. Writes and rowid-only MATCH queries are the part
			// that works, and the part R.4 pins here.
			verify: `SELECT rowid FROM advisory_fts WHERE advisory_fts MATCH 'sqli'`,
		},
		{
			table:  "component",
			insert: `INSERT INTO component (component_id, ecosystem, name, purl_base) VALUES (1, 'pypi', 'requests', 'pkg:pypi/requests')`,
			verify: `SELECT purl_base FROM component WHERE component_id = 1`,
		},
		{
			table:  "advisory_affects",
			insert: `INSERT INTO advisory_affects (advisory_id, component_id, introduced, fixed, range_kind) VALUES ('CVE-2026-0001', 1, '2.0.0', '2.31.0', 'semver')`,
			verify: `SELECT fixed FROM advisory_affects WHERE advisory_id = 'CVE-2026-0001' AND component_id = 1`,
		},
		{
			table: "scan_run",
			insert: `INSERT INTO scan_run (scan_run_id, target_id, policy_id, trigger_ref, commit_sha, started_at, status, ruleset_version)
			         VALUES (1, 1, 1, 'v1.0.0', 'deadbeef', '2026-08-08T00:00:00Z', 'ok', 'rs/1')`,
			verify: `SELECT status FROM scan_run WHERE scan_run_id = 1`,
		},
		{
			table: "audit_record",
			insert: `INSERT INTO audit_record (audit_record_id, scan_run_id, schema_version, state, sast_status, sast_sealed_at,
			                                   dast_status, dast_coverage_json, target_provenance, deadline_at, payload_sha256, created_at)
			         VALUES (1, 1, ?, 'both_sealed', 'sealed', '2026-08-08T01:00:00Z',
			                 'completed_clean', '{"probedCount":1}', 'booted_clean', '2026-08-08T08:00:00Z', ?, '2026-08-08T00:00:00Z')`,
			args:   []any{record.SchemaVersion, sha256Hex},
			verify: `SELECT state FROM audit_record WHERE audit_record_id = 1`,
		},
		{
			table: "code_location",
			insert: `INSERT INTO code_location (location_id, repo_relpath, start_line, end_line, symbol, symbol_kind, blob_sha, snippet_hash)
			         VALUES (1, 'src/app/db.py', 41, 43, 'src/app/db.py::Repo.query', 'method', 'b1', 's1')`,
			verify: `SELECT repo_relpath FROM code_location WHERE location_id = 1`,
		},
		{
			table: "finding",
			insert: `INSERT INTO finding (finding_id, target_id, fingerprint, detector, evidence_class, rule_id,
			                              remediable_by_agent, advisory_id, component_id, severity, title, state,
			                              first_seen_scan, first_seen_at)
			         VALUES (1, 1, ?, 'sast', 'sast_reachable', 'anvil.py.sqli/v3', 0, 'CVE-2026-0001', 1, 'high', 'SQL injection', 'open', 1, '2026-08-08T00:30:00Z')`,
			args:   []any{fpA},
			verify: `SELECT fingerprint FROM finding WHERE finding_id = 1`,
		},
		{
			table:  "finding_fingerprint",
			insert: `INSERT INTO finding_fingerprint (finding_id, kind, alg, value) VALUES (1, 'primary', ?, ?)`,
			args:   []any{record.FingerprintAlgV1, fpA},
			verify: `SELECT value FROM finding_fingerprint WHERE finding_id = 1 AND kind = 'primary'`,
		},
		{
			table: "finding_occurrence",
			insert: `INSERT INTO finding_occurrence (occurrence_id, finding_id, scan_run_id, location_id, confidence, message,
			                                          evidence_ref, advisory_as_of, advisory_staleness_seconds, advisory_parse_degraded)
			         VALUES (1, 1, 1, 1, 0.9, 'rule anvil.py.sqli/v3 matched', 'runs/0/results/0', '2026-08-07T00:00:00Z', 86400, 0)`,
			verify: `SELECT message FROM finding_occurrence WHERE occurrence_id = 1`,
		},
		{
			table:  "finding_state_event",
			insert: `INSERT INTO finding_state_event (event_id, finding_id, scan_run_id, from_state, to_state, cause, at) VALUES (1, 1, 1, NULL, 'open', 'first_seen', '2026-08-08T00:30:00Z')`,
			verify: `SELECT to_state FROM finding_state_event WHERE event_id = 1`,
		},
		{
			table: "fix_attempt",
			insert: `INSERT INTO fix_attempt (fix_attempt_id, finding_id, audit_record_id, agent_model_id, started_at, status, patch_ref, branch_name, pr_url)
			         VALUES (1, 1, 1, 'model/x', '2026-08-08T02:00:00Z', 'proposed', 'refs/anvil/fix/1', 'anvil/fix-1', 'https://example.invalid/pr/1')`,
			verify: `SELECT status FROM fix_attempt WHERE fix_attempt_id = 1`,
		},
		{
			table: "verification",
			insert: `INSERT INTO verification (verification_id, fix_attempt_id, kind, scan_run_id, result, details_json, verified_at)
			         VALUES (1, 1, 'rescan_dast', 1, 'pass', '{"reproFailed":true}', '2026-08-08T03:00:00Z')`,
			verify: `SELECT result FROM verification WHERE verification_id = 1`,
		},
		{
			table: "suppression",
			insert: `INSERT INTO suppression (suppression_id, target_id, match_kind, match_value, classification, justification, created_by, created_at, active)
			         VALUES (1, 1, 'fingerprint', ?, 'accepted_risk', 'compensating control', 'operator', '2026-08-08T00:00:00Z', 1)`,
			args:   []any{fpA},
			verify: `SELECT classification FROM suppression WHERE suppression_id = 1`,
		},
		{
			table:  "file_state",
			insert: `INSERT INTO file_state (target_id, repo_relpath, blob_sha, ruleset_version, last_scan_id) VALUES (1, 'src/app/db.py', 'b1', 'rs/1', 1)`,
			verify: `SELECT blob_sha FROM file_state WHERE target_id = 1 AND repo_relpath = 'src/app/db.py'`,
		},
		{
			table: "handoff",
			insert: `INSERT INTO handoff (handoff_id, finding_id, audit_record_id, fingerprint, group_id, state, consumption_class,
			                              claimed_by, lease_expires_at, attempts, max_attempts, idempotency_key, created_at, updated_at)
			         VALUES (1, 1, 1, ?, 'grp-1', 'leased', 'requires_dynamic_confirmation',
			                 'worker-1', '2026-08-08T00:20:00Z', 0, 2, ?, '2026-08-08T00:00:00Z', '2026-08-08T00:00:00Z')`,
			args:   []any{fpA, sha256Hex},
			verify: `SELECT state FROM handoff WHERE handoff_id = 1`,
		},
		{
			table:  "schema_migration",
			insert: `INSERT INTO schema_migration (version, name, checksum, applied_at) VALUES (1, '0001_init', ?, '2026-08-08T00:00:00Z')`,
			args:   []any{SchemaSHA256()},
			verify: `SELECT checksum FROM schema_migration WHERE version = 1`,
		},
	}

	seeded := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		if _, err := db.Exec(s.insert, s.args...); err != nil {
			t.Fatalf("insert into %s: %v", s.table, err)
		}
		var got string
		if err := db.QueryRow(s.verify).Scan(&got); err != nil {
			t.Fatalf("select back from %s: %v", s.table, err)
		}
		if got == "" {
			t.Errorf("%s: selected an empty value back", s.table)
		}
		seeded[s.table] = true
	}

	// The seed list is checked against the DDL rather than against itself, so
	// a table added to schema.sql without a smoke insert fails here.
	for _, table := range Tables() {
		if !seeded[table] {
			t.Errorf("table %q is created by schema.sql but never exercised by the smoke test", table)
		}
	}
	if len(seeded) != len(Tables()) {
		t.Errorf("smoke test seeds %d tables, schema.sql creates %d", len(seeded), len(Tables()))
	}
}

func TestSchemaAppliesAndSmokeInsertsRoundTrip(t *testing.T) {
	db := newDB(t)
	seedAll(t, db)

	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, want 1: the schema depends on FK enforcement", fk)
	}
}

// enumStrings widens any ~string enum slice from internal/record.
func enumStrings[T ~string](vals []T) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = string(v)
	}
	return out
}

// enumChecks maps every CHECK constraint in schema.sql that names a vocabulary
// to the internal/record function that owns it. plan/IMPLEMENTATION-PLAN.md §6
// makes internal/record the single declaration site; SQL cannot reference a Go
// constant, so this table is the seam, and this test is what keeps the seam
// honest.
var enumChecks = []struct {
	constraint string
	table      string
	column     string
	want       []string
}{
	{"ck_scan_run_status", "scan_run", "status", enumStrings(record.ScanRunStatusValues())},
	{"ck_audit_record_state", "audit_record", "state", enumStrings(record.StateValues())},
	{"ck_audit_record_sast_status", "audit_record", "sast_status", enumStrings(record.HalfStatusValues())},
	{"ck_audit_record_dast_status", "audit_record", "dast_status", enumStrings(record.DastStatusValues())},
	{"ck_audit_record_target_provenance", "audit_record", "target_provenance", enumStrings(record.TargetProvenanceValues())},
	{"ck_finding_detector", "finding", "detector", enumStrings(record.DetectorKindValues())},
	{"ck_finding_evidence_class", "finding", "evidence_class", enumStrings(record.EvidenceClassValues())},
	{"ck_finding_verdict", "finding", "verdict", enumStrings(record.VerdictValues())},
	{"ck_finding_state", "finding", "state", enumStrings(record.FindingStateValues())},
	{"ck_handoff_state", "handoff", "state", enumStrings(record.HandoffStateValues())},
	{"ck_handoff_consumption_class", "handoff", "consumption_class", enumStrings(record.ConsumptionClassValues())},
}

func TestEnumCheckConstraintsMatchContractLiteralForLiteral(t *testing.T) {
	for _, c := range enumChecks {
		got, err := EnumCheckValues(c.constraint)
		if err != nil {
			t.Errorf("%s: %v", c.constraint, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s (%s.%s): SQL admits %d literals %v, internal/record declares %d %v",
				c.constraint, c.table, c.column, len(got), got, len(c.want), c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s (%s.%s): literal %d is %q in SQL, %q in internal/record",
					c.constraint, c.table, c.column, i, got[i], c.want[i])
			}
		}
	}
}

// TestEnumCheckConstraintsEnforceContractValues proves the agreement at run
// time, not only by reading the DDL: every literal internal/record declares is
// accepted by the column, and a literal it does not declare is rejected.
func TestEnumCheckConstraintsEnforceContractValues(t *testing.T) {
	db := newDB(t)
	seedAll(t, db)

	for _, c := range enumChecks {
		update := `UPDATE ` + c.table + ` SET ` + c.column + ` = ? WHERE rowid = (SELECT MIN(rowid) FROM ` + c.table + `)`
		for _, v := range c.want {
			if _, err := db.Exec(update, v); err != nil {
				t.Errorf("%s.%s rejected %q, which internal/record declares legal: %v", c.table, c.column, v, err)
			}
		}
		if _, err := db.Exec(update, "not_a_declared_literal"); err == nil {
			t.Errorf("%s.%s accepted an undeclared literal; %s is not enforcing the vocabulary",
				c.table, c.column, c.constraint)
		}
	}
}

// TestHandoffCarriesAllThirteenDispositions is the G10 regression guard. Area
// X's `anvil_ledger` was deleted and its four extra dispositions folded into
// handoff.state; if that set ever shrinks, X.9 writes a disposition this
// column cannot hold and the ready-set index re-leases the finding forever.
func TestHandoffCarriesAllThirteenDispositions(t *testing.T) {
	got, err := EnumCheckValues("ck_handoff_state")
	if err != nil {
		t.Fatalf("ck_handoff_state: %v", err)
	}
	if len(got) != 13 {
		t.Fatalf("ck_handoff_state admits %d states %v, want the 13 of IMPLEMENTATION-PLAN.md §6", len(got), got)
	}
	for _, needed := range []record.HandoffState{
		record.HandoffStateSkippedBudget,
		record.HandoffStateFixedIncidentally,
		record.HandoffStateSplitRequired,
		record.HandoffStateWithdrawn,
		record.HandoffStateSuperseded,
	} {
		if !contains(got, string(needed)) {
			t.Errorf("ck_handoff_state is missing %q, one of the dispositions collapsed in from anvil_ledger", needed)
		}
	}
}

// TestNoSecondDispositionTable guards the S1 spine rule directly: one durable
// table carrying finding dispositions, not two.
func TestNoSecondDispositionTable(t *testing.T) {
	for _, table := range Tables() {
		if strings.Contains(table, "ledger") {
			t.Errorf("schema.sql creates %q; §6 G10 collapses every finding disposition into handoff.state", table)
		}
	}
	// No other column may admit a handoff disposition. `audit_record.state` is
	// the audit's own lifecycle and `finding.state` is the durable finding
	// lifecycle; neither is a queue disposition, and the overlap that would
	// signal a second ledger is a literal only handoff.state should carry.
	for _, c := range enumChecks {
		if c.table == "handoff" {
			continue
		}
		for _, v := range c.want {
			if v == string(record.HandoffStateSkippedBudget) || v == string(record.HandoffStateLeased) {
				t.Errorf("%s.%s admits the handoff disposition %q; dispositions live only in handoff.state", c.table, c.column, v)
			}
		}
	}
}

func TestConsumptionClassHasNoDefault(t *testing.T) {
	db := newDB(t)

	notNull, dflt := columnInfo(t, db, "handoff", "consumption_class")
	if !notNull {
		t.Error("handoff.consumption_class must be NOT NULL: the static-only vs requires-dynamic-confirmation gate has no other home in the schema")
	}
	if dflt.Valid {
		t.Errorf("handoff.consumption_class has DEFAULT %q; a default silently grants every row the permissive value, which 00-SPINE.md S7 forbids", dflt.String)
	}
}

// TestColumnDefaultsMatchContract keeps the DDL's literal defaults tied to the
// Go constants they mirror.
func TestColumnDefaultsMatchContract(t *testing.T) {
	db := newDB(t)

	cases := []struct {
		table, column, want string
	}{
		{"finding", "fingerprint_alg", "'" + record.FingerprintAlgV1 + "'"},
		{"finding", "verdict", "'" + string(record.VerdictTruePositive) + "'"},
		{"audit_record", "dast_status", "'" + string(record.DastStatusNotRun) + "'"},
		{"audit_record", "claim_timeout_seconds", strconv.Itoa(record.DefaultClaimTimeoutSeconds)},
		{"handoff", "state", "'" + string(record.HandoffStateReady) + "'"},
	}
	for _, c := range cases {
		_, dflt := columnInfo(t, db, c.table, c.column)
		if !dflt.Valid {
			t.Errorf("%s.%s has no DEFAULT, want %s", c.table, c.column, c.want)
			continue
		}
		if dflt.String != c.want {
			t.Errorf("%s.%s DEFAULT is %s, internal/record says %s", c.table, c.column, dflt.String, c.want)
		}
	}
}

// TestFingerprintColumnsEnforceContractDigestLength ties the SQL length check
// to record.FingerprintDigestHexLen. CRITIQUE-01 §9 records that the digest is
// 64 lowercase hex characters and is never truncated; a truncating writer must
// fail at the column, not silently halve the collision resistance.
func TestFingerprintColumnsEnforceContractDigestLength(t *testing.T) {
	db := newDB(t)
	seedAll(t, db)

	exact := strings.Repeat("a", record.FingerprintDigestHexLen)
	short := strings.Repeat("a", record.FingerprintDigestHexLen-1)
	long := strings.Repeat("a", record.FingerprintDigestHexLen+1)
	upper := strings.Repeat("A", record.FingerprintDigestHexLen)
	nonHex := strings.Repeat("z", record.FingerprintDigestHexLen)

	for _, table := range []string{"finding", "handoff"} {
		update := `UPDATE ` + table + ` SET fingerprint = ? WHERE rowid = 1`
		if _, err := db.Exec(update, exact); err != nil {
			t.Errorf("%s.fingerprint rejected a full %d-hex digest: %v", table, record.FingerprintDigestHexLen, err)
		}
		for name, bad := range map[string]string{"truncated": short, "over-long": long, "uppercase": upper, "non-hex": nonHex} {
			if _, err := db.Exec(update, bad); err == nil {
				t.Errorf("%s.fingerprint accepted a %s digest", table, name)
			}
		}
		// Restore for the next table's FK-valid state.
		if _, err := db.Exec(update, exact); err != nil {
			t.Fatalf("restoring %s.fingerprint: %v", table, err)
		}
	}
}

// TestHostFindingsAreNeverAgentRemediable is 00-SPINE.md S7 in the schema: the
// host agent is read-only, "no package manager in a mutating mode, not behind
// a flag."
func TestHostFindingsAreNeverAgentRemediable(t *testing.T) {
	db := newDB(t)
	seedAll(t, db)

	_, err := db.Exec(`INSERT INTO finding (finding_id, target_id, fingerprint, detector, evidence_class, rule_id,
	                                        remediable_by_agent, severity, title, state, first_seen_scan, first_seen_at)
	                   VALUES (2, 1, ?, 'host', 'host', 'anvil.host.pkg/v1', 1, 'high', 'vulnerable host package', 'open', 1, '2026-08-08T00:30:00Z')`,
		strings.Repeat("b", record.FingerprintDigestHexLen))
	if err == nil {
		t.Error("a host finding was accepted with remediable_by_agent = 1")
	}
}

// TestDurableTextCapRejectsOversizedMessage is research/07 Risk #13's named
// mitigation: a raw snippet or DAST body copied into a durable column outlives
// the payload purge forever.
func TestDurableTextCapRejectsOversizedMessage(t *testing.T) {
	db := newDB(t)
	seedAll(t, db)

	for _, column := range []string{"message", "evidence_ref"} {
		update := `UPDATE finding_occurrence SET ` + column + ` = ? WHERE occurrence_id = 1`
		if _, err := db.Exec(update, strings.Repeat("x", MaxDurableTextBytes)); err != nil {
			t.Errorf("finding_occurrence.%s rejected a value at exactly the cap: %v", column, err)
		}
		if _, err := db.Exec(update, strings.Repeat("x", MaxDurableTextBytes+1)); err == nil {
			t.Errorf("finding_occurrence.%s accepted a value one byte over the cap", column)
		}
	}

	// The same cap must hold on INSERT, not only on UPDATE.
	_, err := db.Exec(`INSERT INTO finding_occurrence (occurrence_id, finding_id, scan_run_id, message)
	                   VALUES (2, 1, 1, ?)`, strings.Repeat("x", MaxDurableTextBytes+1))
	if err == nil {
		t.Error("finding_occurrence accepted an oversized message on INSERT")
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	db := newDB(t)
	seedAll(t, db)

	_, err := db.Exec(`INSERT INTO handoff (handoff_id, finding_id, audit_record_id, fingerprint, consumption_class, created_at, updated_at)
	                   VALUES (99, 4242, 1, ?, 'static_only', '2026-08-08T00:00:00Z', '2026-08-08T00:00:00Z')`, fpA)
	if err == nil {
		t.Error("handoff accepted a row referencing a finding that does not exist")
	}
}

// TestLeasedRowMustNameItsHolder: a row in state 'leased' with no claimed_by
// is unreclaimable, because the reaper's requeue rule keys on the holder and
// the lease clock.
func TestLeasedRowMustNameItsHolder(t *testing.T) {
	db := newDB(t)
	seedAll(t, db)

	_, err := db.Exec(`UPDATE handoff SET state = 'leased', claimed_by = NULL WHERE handoff_id = 1`)
	if err == nil {
		t.Error("handoff accepted state = 'leased' with a NULL claimed_by")
	}
}

// TestSchemaCarriesNoPragma: R.5 applies this DDL inside BEGIN...COMMIT, and
// `PRAGMA journal_mode = WAL` cannot run inside a transaction. The pragmas
// live in ConnectionPragmas instead, because they are per connection anyway.
func TestSchemaCarriesNoPragma(t *testing.T) {
	if strings.Contains(strings.ToUpper(stripSQLComments(Schema())), "PRAGMA") {
		t.Error("schema.sql contains a PRAGMA statement; it cannot then be applied inside a transaction")
	}
	want := []string{"journal_mode = WAL", "foreign_keys = ON", "busy_timeout = 10000", "synchronous = NORMAL", "wal_autocheckpoint = 1000"}
	got := ConnectionPragmas()
	if len(got) != len(want) {
		t.Fatalf("ConnectionPragmas returned %d pragmas %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if !strings.Contains(got[i], want[i]) {
			t.Errorf("pragma %d is %q, want it to set %q", i, got[i], want[i])
		}
	}
}

// TestEveryResearch07TableSurvives: R.4 may not drop a research/07 table
// without logging the reason, and this schema drops none.
func TestEveryResearch07TableSurvives(t *testing.T) {
	carriedForward := []string{
		"advisory", "advisory_alias", "advisory_fts", "component", "advisory_affects",
		"target", "trigger_policy", "ingest_watermark", "scan_run", "audit_record",
		"code_location", "finding", "finding_fingerprint", "finding_occurrence",
		"finding_state_event", "fix_attempt", "verification", "suppression",
		"file_state", "schema_migration",
	}
	created := Tables()
	for _, want := range carriedForward {
		if !contains(created, want) {
			t.Errorf("research/07 table %q is missing from schema.sql", want)
		}
	}
	if !contains(created, "handoff") {
		t.Error("the handoff table is missing; S1 collapses the buffer into it")
	}
}

func TestSchemaSHA256IsStableAndFullLength(t *testing.T) {
	first := SchemaSHA256()
	if len(first) != record.FingerprintDigestHexLen {
		t.Errorf("SchemaSHA256 returned %d characters, want %d", len(first), record.FingerprintDigestHexLen)
	}
	if second := SchemaSHA256(); first != second {
		t.Errorf("SchemaSHA256 is not stable: %q then %q", first, second)
	}
}

func TestCheckConstraintReportsMissingNames(t *testing.T) {
	if _, err := CheckConstraint("ck_not_a_real_constraint"); err == nil {
		t.Error("CheckConstraint reported success for a constraint that does not exist")
	}
	if _, err := EnumCheckValues("ck_not_a_real_constraint"); err == nil {
		t.Error("EnumCheckValues reported success for a constraint that does not exist")
	}
}

// ---- helpers ----

func columnInfo(t *testing.T, db *sql.DB, table, column string) (notNull bool, dflt sql.NullString) {
	t.Helper()

	rows, err := db.Query(`SELECT name, "notnull", dflt_value FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name string
		var nn int
		var d sql.NullString
		if err := rows.Scan(&name, &nn, &d); err != nil {
			t.Fatalf("scanning pragma_table_info(%s): %v", table, err)
		}
		if name == column {
			if err := rows.Err(); err != nil {
				t.Fatalf("pragma_table_info(%s): %v", table, err)
			}
			return nn != 0, d
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	t.Fatalf("%s has no column %q", table, column)
	return false, sql.NullString{}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// stripSQLComments removes `-- ...` line comments so that a PRAGMA mentioned
// in a comment does not fail TestSchemaCarriesNoPragma.
func stripSQLComments(sqlText string) string {
	var b strings.Builder
	for _, line := range strings.Split(sqlText, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
