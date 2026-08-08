package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// openMemory returns an empty in-memory database with ConnectionPragmas
// applied. MaxOpenConns is 1 because every new connection to ":memory:" is a
// different, empty database — and because the pragmas are per connection.
func openMemory(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	applyPragmas(t, db)
	return db
}

// openOnDisk returns an empty file-backed database and its directory. The
// snapshot path has to be exercised against a real file: VACUUM INTO on a
// database that never touched a filesystem would prove nothing about the
// rollback story it replaces.
func openOnDisk(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "anvil.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	applyPragmas(t, db)
	return db, dir
}

func applyPragmas(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, p := range ConnectionPragmas() {
		if _, err := db.Exec(p); err != nil {
			t.Fatalf("pragma %q: %v", p, err)
		}
	}
}

// schemaObjects renders every object SQLite actually created, which is the
// tool-free equivalent of the packet's `sqlite3 .schema` diff — and a stricter
// one, since it compares the stored DDL text rather than a pretty-printed
// rendering of it.
func schemaObjects(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema ORDER BY type, name`)
	if err != nil {
		t.Fatalf("reading sqlite_schema: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var b strings.Builder
	for rows.Next() {
		var typ, name, tbl, ddl string
		if err := rows.Scan(&typ, &name, &tbl, &ddl); err != nil {
			t.Fatalf("scanning sqlite_schema: %v", err)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\n%s\n--\n", typ, name, tbl, ddl)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating sqlite_schema: %v", err)
	}
	return b.String()
}

func ledgerRows(t *testing.T, db *sql.DB) []appliedMigration {
	t.Helper()
	applied, err := readLedger(context.Background(), db)
	if err != nil {
		t.Fatalf("readLedger: %v", err)
	}
	return applied
}

func mustSchemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	v, err := SchemaVersion(context.Background(), db)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	return v
}

// ---------------------------------------------------------------------------
// The embedded migration set
// ---------------------------------------------------------------------------

func TestEmbeddedMigrationsAreWellFormed(t *testing.T) {
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations are embedded")
	}
	for i, m := range migrations {
		if m.Version != i+1 {
			t.Fatalf("migration %d is version %d; versions must be contiguous from 1", i, m.Version)
		}
		if len(m.Checksum) != 64 {
			t.Errorf("%s: checksum %q is not a 64-character SHA-256 hex digest", m.Filename, m.Checksum)
		}
		if strings.Contains(m.SQL, includeDirectivePrefix) {
			t.Errorf("%s: an include directive survived expansion", m.Filename)
		}
		sum := sha256.Sum256([]byte(m.SQL))
		if want := hex.EncodeToString(sum[:]); m.Checksum != want {
			t.Errorf("%s: checksum %s does not digest the expanded SQL (%s)", m.Filename, m.Checksum, want)
		}
	}

	latest, err := LatestVersion()
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if latest != migrations[len(migrations)-1].Version {
		t.Fatalf("LatestVersion = %d, want %d", latest, migrations[len(migrations)-1].Version)
	}
}

// TestInitMigrationEmbedsSchemaByteForByte is the structural half of the
// packet's byte-for-byte requirement: 0001 does not carry a copy of the DDL
// that could drift from schema.sql, it carries schema.sql's exact bytes.
func TestInitMigrationEmbedsSchemaByteForByte(t *testing.T) {
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	init := migrations[0]
	if init.Name != "init" || init.Filename != "0001_init.sql" {
		t.Fatalf("migration 1 is %q (%s), want init (0001_init.sql)", init.Name, init.Filename)
	}
	if !strings.Contains(init.SQL, Schema()) {
		t.Fatal("0001_init.sql does not contain schema.sql verbatim after expansion")
	}
	// Anything outside the included schema must be comment, so the migration
	// cannot quietly add DDL that schema.sql does not describe.
	extra := strings.ReplaceAll(init.SQL, Schema(), "")
	for i, line := range strings.Split(extra, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			t.Fatalf("0001_init.sql line %d adds DDL outside schema.sql: %q", i+1, trimmed)
		}
	}
}

func TestIncludeExpansion(t *testing.T) {
	got, err := expandIncludes("test.sql", "-- header\n"+includeDirectivePrefix+"schema.sql\n-- footer\n")
	if err != nil {
		t.Fatalf("expandIncludes: %v", err)
	}
	if want := "-- header\n" + Schema() + "-- footer\n"; got != want {
		t.Fatalf("expansion did not splice schema.sql in place:\n%q", got[:min(len(got), 200)])
	}

	if _, err := expandIncludes("test.sql", includeDirectivePrefix+"secrets.sql\n"); err == nil {
		t.Fatal("expandIncludes accepted an include target other than schema.sql")
	}
}

// ---------------------------------------------------------------------------
// Applying migrations
// ---------------------------------------------------------------------------

// TestMigrateBuildsExactlyR4Schema is the packet's schema-equivalence evidence
// item: a database built by the migration runner and a database built by
// applying schema.sql directly must be indistinguishable, object for object.
func TestMigrateBuildsExactlyR4Schema(t *testing.T) {
	migrated := openMemory(t)
	applied, err := Migrate(context.Background(), migrated, "")
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(applied) != 1 || applied[0] != 1 {
		t.Fatalf("Migrate applied %v, want [1]", applied)
	}

	direct := openMemory(t)
	if _, err := direct.Exec(Schema()); err != nil {
		t.Fatalf("applying schema.sql directly: %v", err)
	}

	if got, want := schemaObjects(t, migrated), schemaObjects(t, direct); got != want {
		t.Fatalf("migrated schema differs from schema.sql applied directly:\n--- migrated ---\n%s\n--- direct ---\n%s", got, want)
	}

	if v := mustSchemaVersion(t, migrated); v != 1 {
		t.Fatalf("PRAGMA user_version = %d after migrating, want 1", v)
	}

	rows := ledgerRows(t, migrated)
	if len(rows) != 1 {
		t.Fatalf("schema_migration has %d rows, want 1", len(rows))
	}
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	if rows[0].Version != 1 || rows[0].Name != "init" || rows[0].Checksum != migrations[0].Checksum {
		t.Fatalf("ledger row %+v does not describe %s", rows[0], migrations[0].Filename)
	}
	if rows[0].AppliedAt == "" {
		t.Fatal("ledger row has no applied_at timestamp")
	}
}

func TestMigrateIsANoOpWhenCurrent(t *testing.T) {
	db := openMemory(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, db, ""); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	before := ledgerRows(t, db)
	schemaBefore := schemaObjects(t, db)

	applied, err := Migrate(ctx, db, "")
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("re-running Migrate applied %v, want nothing", applied)
	}
	after := ledgerRows(t, db)
	if len(after) != len(before) || after[0].AppliedAt != before[0].AppliedAt {
		t.Fatalf("re-running Migrate rewrote the ledger: %+v -> %+v", before, after)
	}
	if schemaObjects(t, db) != schemaBefore {
		t.Fatal("re-running Migrate changed the schema")
	}
}

// TestMigrateAppliesInNumberedOrderInsideTransactions injects later versions,
// which is the only way to test ordering and transactionality while 0001 is
// the only real migration. The alternative is finding out during the first
// upgrade a user ever performs.
func TestMigrateAppliesInNumberedOrderInsideTransactions(t *testing.T) {
	db, dir := openOnDisk(t)
	ctx := context.Background()

	migrations := withSynthetic(t,
		synthetic(2, "second", "CREATE TABLE second_step (x INTEGER);"),
		synthetic(3, "third", "CREATE TABLE third_step (y INTEGER REFERENCES second_step(x));"),
	)

	applied, err := migrateWith(ctx, db, migrations, dir)
	if err != nil {
		t.Fatalf("migrateWith: %v", err)
	}
	if len(applied) != 3 || applied[0] != 1 || applied[1] != 2 || applied[2] != 3 {
		t.Fatalf("applied %v, want [1 2 3] in order", applied)
	}
	if v := mustSchemaVersion(t, db); v != 3 {
		t.Fatalf("user_version = %d, want 3", v)
	}
	if rows := ledgerRows(t, db); len(rows) != 3 {
		t.Fatalf("ledger has %d rows, want 3", len(rows))
	}
	// third_step references second_step; it could not have been created first.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name IN ('second_step','third_step')`).Scan(&n); err != nil {
		t.Fatalf("counting new tables: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected both synthetic tables, found %d", n)
	}
}

// TestFailedMigrationLeavesSchemaUntouched is why each migration runs inside
// BEGIN ... COMMIT with the user_version bump in the same transaction.
func TestFailedMigrationLeavesSchemaUntouched(t *testing.T) {
	db := openMemory(t)
	ctx := context.Background()

	migrations := withSynthetic(t, synthetic(2, "broken",
		"CREATE TABLE half_applied (x INTEGER);\nCREATE TABLE half_applied (x INTEGER);"))

	applied, err := migrateWith(ctx, db, migrations, t.TempDir())
	if err == nil {
		t.Fatal("a migration with invalid DDL was accepted")
	}
	if len(applied) != 1 || applied[0] != 1 {
		t.Fatalf("applied %v, want [1] — 0001 succeeded and 0002 must not count", applied)
	}
	if v := mustSchemaVersion(t, db); v != 1 {
		t.Fatalf("user_version = %d after a failed migration, want 1", v)
	}
	if rows := ledgerRows(t, db); len(rows) != 1 {
		t.Fatalf("ledger has %d rows after a failed migration, want 1", len(rows))
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name = 'half_applied'`).Scan(&n); err != nil {
		t.Fatalf("looking for the rolled-back table: %v", err)
	}
	if n != 0 {
		t.Fatal("half_applied survived a rolled-back migration")
	}
}

// ---------------------------------------------------------------------------
// The ledger refuses to guess
// ---------------------------------------------------------------------------

// TestMigrateRefusesEditedMigration is the packet's stop condition: "a
// hand-edited migration file with a mismatched checksum causes migrate.go to
// refuse to start". The ledger row is edited rather than the embedded file
// because the embedded file cannot be edited at run time; the comparison
// migrate.go performs is the same one either way.
func TestMigrateRefusesEditedMigration(t *testing.T) {
	db := openMemory(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, db, ""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const tampered = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := db.Exec(`UPDATE schema_migration SET checksum = ? WHERE version = 1`, tampered); err != nil {
		t.Fatalf("tampering with the ledger: %v", err)
	}

	_, err := Migrate(ctx, db, "")
	if err == nil {
		t.Fatal("Migrate started against a database whose migration checksum does not match")
	}
	if !errors.Is(err, ErrMigrationLedger) {
		t.Fatalf("error does not wrap ErrMigrationLedger: %v", err)
	}
	for _, want := range []string{"0001_init.sql", tampered, "Refusing to start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message omits %q: %v", want, err)
		}
	}
}

func TestMigrateRefusesADowngrade(t *testing.T) {
	db := openMemory(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, db, ""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Simulate an older binary opening a store a newer one migrated.
	if _, err := db.Exec(
		`INSERT INTO schema_migration (version, name, checksum, applied_at) VALUES (2, 'future', 'x', '2026-01-01T00:00:00Z')`,
	); err != nil {
		t.Fatalf("seeding a future migration: %v", err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 2`); err != nil {
		t.Fatalf("bumping user_version: %v", err)
	}

	_, err := Migrate(ctx, db, "")
	if !errors.Is(err, ErrMigrationLedger) {
		t.Fatalf("Migrate accepted a newer store, got %v", err)
	}
	if !strings.Contains(err.Error(), "forward-only") {
		t.Errorf("error does not explain that downgrades are unsupported: %v", err)
	}
}

func TestMigrateRefusesUserVersionLedgerDisagreement(t *testing.T) {
	db := openMemory(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, db, ""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 9`); err != nil {
		t.Fatalf("bumping user_version: %v", err)
	}
	if _, err := Migrate(ctx, db, ""); !errors.Is(err, ErrMigrationLedger) {
		t.Fatalf("Migrate accepted user_version 9 with one applied migration, got %v", err)
	}
}

func TestMigrateRefusesAPopulatedDatabaseWithNoLedger(t *testing.T) {
	db := openMemory(t)
	if _, err := db.Exec(`PRAGMA user_version = 4`); err != nil {
		t.Fatalf("bumping user_version: %v", err)
	}
	_, err := Migrate(context.Background(), db, "")
	if !errors.Is(err, ErrMigrationLedger) {
		t.Fatalf("Migrate accepted a foreign database with no schema_migration table, got %v", err)
	}
}

func TestMigrateRefusesAGapInTheLedger(t *testing.T) {
	db := openMemory(t)
	ctx := context.Background()
	migrations := withSynthetic(t,
		synthetic(2, "second", "CREATE TABLE second_step (x INTEGER);"),
		synthetic(3, "third", "CREATE TABLE third_step (y INTEGER);"),
	)
	if _, err := migrateWith(ctx, db, migrations, t.TempDir()); err != nil {
		t.Fatalf("migrateWith: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM schema_migration WHERE version = 2`); err != nil {
		t.Fatalf("punching a hole in the ledger: %v", err)
	}
	if _, err := migrateWith(ctx, db, migrations, t.TempDir()); !errors.Is(err, ErrMigrationLedger) {
		t.Fatalf("Migrate accepted a ledger with a gap, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Forward-only means the snapshot is mandatory
// ---------------------------------------------------------------------------

func TestMigrateRefusesToUpgradeWithoutASnapshotDirectory(t *testing.T) {
	db, _ := openOnDisk(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, db, ""); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}

	migrations := withSynthetic(t, synthetic(2, "second", "CREATE TABLE second_step (x INTEGER);"))
	_, err := migrateWith(ctx, db, migrations, "")
	if !errors.Is(err, ErrSnapshotRequired) {
		t.Fatalf("Migrate upgraded a populated database with no snapshot directory, got %v", err)
	}
	if !strings.Contains(err.Error(), "forward-only") {
		t.Errorf("error does not explain why the snapshot is mandatory: %v", err)
	}
	if v := mustSchemaVersion(t, db); v != 1 {
		t.Fatalf("a refused upgrade changed user_version to %d", v)
	}
}

// TestSnapshotIsTakenBeforeAnUpgrade proves the replacement for down
// migrations actually exists on disk and is a readable database at the
// pre-upgrade version — an unopenable file would be a rollback path in name
// only.
func TestSnapshotIsTakenBeforeAnUpgrade(t *testing.T) {
	db, dir := openOnDisk(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, db, ""); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}

	snapDir := filepath.Join(dir, "snapshots")
	migrations := withSynthetic(t, synthetic(2, "second", "CREATE TABLE second_step (x INTEGER);"))
	if _, err := migrateWith(ctx, db, migrations, snapDir); err != nil {
		t.Fatalf("migrateWith: %v", err)
	}

	snap := filepath.Join(snapDir, "anvil-pre-v1.db")
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("no pre-migration snapshot at %s: %v", snap, err)
	}

	restored, err := sql.Open("sqlite", snap)
	if err != nil {
		t.Fatalf("reopening the snapshot: %v", err)
	}
	defer func() { _ = restored.Close() }()
	restored.SetMaxOpenConns(1)

	if v := mustSchemaVersion(t, restored); v != 1 {
		t.Fatalf("snapshot is at user_version %d, want the pre-upgrade version 1", v)
	}
	var n int
	if err := restored.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name = 'second_step'`).Scan(&n); err != nil {
		t.Fatalf("querying the snapshot: %v", err)
	}
	if n != 0 {
		t.Fatal("the snapshot contains the migration it was supposed to precede")
	}
}

func TestSnapshotRefusesToOverwriteAnExistingFile(t *testing.T) {
	db, dir := openOnDisk(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, db, ""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	dest := filepath.Join(dir, "snap.db")
	if err := Snapshot(ctx, db, dest); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := Snapshot(ctx, db, dest); err == nil {
		t.Fatal("Snapshot overwrote an existing snapshot")
	}

	// snapshotPath must therefore never hand back a name that is already
	// taken, or a retried upgrade would fail on its own previous snapshot.
	first, err := snapshotPath(dir, 1)
	if err != nil {
		t.Fatalf("snapshotPath: %v", err)
	}
	if err := os.WriteFile(first, []byte("occupied"), 0o600); err != nil {
		t.Fatalf("occupying the snapshot name: %v", err)
	}
	second, err := snapshotPath(dir, 1)
	if err != nil {
		t.Fatalf("snapshotPath: %v", err)
	}
	if second == first {
		t.Fatalf("snapshotPath returned the occupied name %q twice", first)
	}
}

func TestSnapshotRejectsEmptyArguments(t *testing.T) {
	db := openMemory(t)
	if err := Snapshot(context.Background(), db, "  "); err == nil {
		t.Fatal("Snapshot accepted an empty destination")
	}
	if err := Snapshot(context.Background(), nil, "x.db"); err == nil {
		t.Fatal("Snapshot accepted a nil database")
	}
}

func TestMigrateRejectsNilDatabase(t *testing.T) {
	if _, err := Migrate(context.Background(), nil, ""); err == nil {
		t.Fatal("Migrate accepted a nil database handle")
	}
}

// ---------------------------------------------------------------------------
// Synthetic migrations
// ---------------------------------------------------------------------------

func synthetic(version int, name, body string) Migration {
	sum := sha256.Sum256([]byte(body))
	return Migration{
		Version:  version,
		Name:     name,
		Filename: fmt.Sprintf("%04d_%s.sql", version, name),
		SQL:      body,
		Checksum: hex.EncodeToString(sum[:]),
	}
}

// withSynthetic appends test-only migrations after the real embedded set.
func withSynthetic(t *testing.T, extra ...Migration) []Migration {
	t.Helper()
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	return append(migrations, extra...)
}
