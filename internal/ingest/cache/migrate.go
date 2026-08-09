// Opening and migrating the Lane A ingestion cache (step A.2).
//
// Three properties are load-bearing here and each has a test in
// cache_test.go:
//
//  1. The cache is only ever opened in WAL mode. Open builds the DSN, then
//     PROVES `PRAGMA journal_mode` came back `wal` and refuses the handle
//     otherwise. A poller writing while the comparator reads is the normal
//     case for this file, and rollback-journal mode serialises them; more to
//     the point, A.2's Forbidden actions say "Do not open the DB outside WAL
//     mode", and a DSN parameter that silently failed to apply would satisfy
//     the letter of that while breaking it in fact.
//
//  2. Migrations are forward-only, numbered, and applied inside one
//     transaction each together with the `PRAGMA user_version` bump and the
//     ledger row — so a failure leaves the schema exactly as it was rather
//     than half-applied. Every applied migration's checksum is re-verified at
//     open against the checksum this binary carries; a mismatch is a refusal,
//     never a re-run and never a skip.
//
//  3. FTS5 is proved by USE, not by a version number. plan/00-SPINE.md S12
//     calls modernc.org/sqlite's FTS5 support "orchestrator-verified", but a
//     dependency bump can drop a build-time feature with no signal at all.
//     CheckFTS5 creates a real FTS5 table, writes a real row and runs a real
//     MATCH, on every Open.
//
// WHAT IS DELIBERATELY ABSENT: the pre-migration `VACUUM INTO` snapshot gate
// that internal/store's Migrate enforces. That gate exists because the store
// of record cannot be rebuilt — losing it loses evidence. This cache is a
// rederivable projection of public feeds: A.8's bootstrap reconstructs it, so
// demanding a snapshot of it would only teach operators to pass a junk
// directory. The asymmetry is deliberate and is the practical difference
// between the two databases.

package cache

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// driverName is the database/sql driver the cache opens through. It is a
// variable rather than a constant so cache_test.go can substitute a tracing
// driver that records every statement reaching the driver layer — which is
// how exit criterion 8's "zero DROP/CREATE VIRTUAL TABLE statements" is
// checked as an observation rather than as an assertion about code nobody
// read.
var driverName = "sqlite"

// ledgerTable is this cache's migration ledger. It is deliberately NOT called
// `schema_migration`: that name belongs to internal/store's ledger, and two
// tables with one name in two databases is how someone eventually points the
// wrong migrator at the wrong file.
const ledgerTable = "cache_migration"

const ledgerDDL = `
CREATE TABLE IF NOT EXISTS ` + ledgerTable + ` (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  checksum   TEXT NOT NULL,
  applied_at TEXT NOT NULL
)`

// ErrMigrationLedger reports that the cache file's migration history and this
// binary's migrations disagree. It is always a refusal to proceed: either
// guess about what to do next produces a schema nobody can describe.
var ErrMigrationLedger = errors.New("cache: migration ledger mismatch")

// ErrNoFTS5 reports that the SQLite build behind the *sql.DB cannot create or
// query an FTS5 virtual table. `advisory_fts` needs it, and so does every
// retrieval path that reads this cache.
var ErrNoFTS5 = errors.New("cache: SQLite FTS5 is unavailable")

// ErrNotWAL reports that the opened database is not in WAL journal mode.
var ErrNotWAL = errors.New("cache: database is not in WAL mode")

// ErrBadPath reports a cache path this package refuses to open at all.
var ErrBadPath = errors.New("cache: unusable database path")

// Migration is one numbered, forward-only migration of the cache schema.
type Migration struct {
	// Version is the migration number; versions are contiguous from 1.
	Version int
	// Name is the descriptive part, e.g. "init".
	Name string
	// SQL is the text executed inside the migration's transaction.
	SQL string
	// Checksum is the lowercase hex SHA-256 of SQL. This is the value
	// written to and re-verified against the ledger.
	Checksum string
}

// migrationDefs is the forward-only migration list. There are no down
// migrations; the rollback story for a rederivable cache is "delete the file
// and re-bootstrap", which is exactly why no snapshot gate is needed.
//
// Adding a migration means appending a new entry with the next version. NEVER
// edit an existing entry's SQL: the checksum in every deployed cache file was
// computed from those bytes, and changing them turns every existing file into
// a refusal at open.
var migrationDefs = []struct {
	version int
	name    string
	sql     string
}{
	{version: 1, name: "init", sql: schemaSQL},
}

var loadMigrations = sync.OnceValues(func() ([]Migration, error) {
	if len(migrationDefs) == 0 {
		return nil, errors.New("cache: no migrations are defined; the cache cannot be created")
	}
	out := make([]Migration, 0, len(migrationDefs))
	for i, d := range migrationDefs {
		if want := i + 1; d.version != want {
			return nil, fmt.Errorf("cache: migration versions must be contiguous from 1; "+
				"expected %d at position %d but found %d (%q)", want, i+1, d.version, d.name)
		}
		if strings.TrimSpace(d.name) == "" {
			return nil, fmt.Errorf("cache: migration %d has no name", d.version)
		}
		if strings.TrimSpace(d.sql) == "" {
			return nil, fmt.Errorf("cache: migration %d (%q) has no SQL", d.version, d.name)
		}
		sum := sha256.Sum256([]byte(d.sql))
		out = append(out, Migration{
			Version:  d.version,
			Name:     d.name,
			SQL:      d.sql,
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	return out, nil
})

// Migrations returns every migration in ascending version order.
func Migrations() ([]Migration, error) {
	migrations, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	return append([]Migration(nil), migrations...), nil
}

// LatestVersion returns the highest migration version — the schema version a
// fully migrated cache reports through Version.
func LatestVersion() (int, error) {
	migrations, err := loadMigrations()
	if err != nil {
		return 0, err
	}
	return migrations[len(migrations)-1].Version, nil
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

// connectionPragmas are the per-connection settings the cache needs, in the
// order they are applied. They go in the DSN rather than being executed on one
// handle because they are per CONNECTION, not per database file, and
// database/sql opens connections whenever it feels like it — `foreign_keys`
// above all, which SQLite leaves OFF by default and which this schema's
// composite foreign keys depend on.
//
// `synchronous = NORMAL` is the documented standard WAL pairing: crash-safe
// for the database file, accepting the loss of the most recent commits on
// power loss. For a rederivable advisory cache that trade is obviously right —
// the lost commits are re-fetched on the next poll.
func connectionPragmas() []string {
	return []string{
		"journal_mode(WAL)",
		"foreign_keys(1)",
		"busy_timeout(10000)",
		"synchronous(NORMAL)",
	}
}

// DSN builds the modernc.org/sqlite data-source name for a cache file.
//
// It refuses an in-memory database. That is not squeamishness: `:memory:` and
// `mode=memory` cannot be put into WAL journal mode at all, so an in-memory
// cache would quietly violate A.2's "do not open the DB outside WAL mode" and
// would also drop the file the whole design is built around shipping —
// research/06 §5 ships the cache as a single `anvil-cache.sqlite` "so it can
// itself be distributed, mirrored, or snapshotted without a build step".
// Tests use a temporary file, which is what a WAL-mode test must do anyway.
func DSN(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("%w: the cache needs a file path", ErrBadPath)
	}
	if isMemoryPath(trimmed) {
		return "", fmt.Errorf("%w: %q is an in-memory database, which cannot be put into WAL "+
			"journal mode; the cache is a single file on disk by design", ErrBadPath, path)
	}
	// The driver splits the DSN on the first '?' and reads a fragment after
	// '#'. A path containing either would silently truncate into a different
	// file, or drop the pragmas, so it is refused by name rather than
	// escaped into something the driver may or may not unescape.
	if i := strings.IndexAny(trimmed, "?#"); i >= 0 {
		return "", fmt.Errorf("%w: %q contains %q at byte %d; the SQLite DSN reserves both characters "+
			"and a path carrying one cannot be expressed unambiguously", ErrBadPath, path, trimmed[i:i+1], i)
	}

	q := make(url.Values)
	for _, p := range connectionPragmas() {
		q.Add("_pragma", p)
	}
	return "file:" + filepath.ToSlash(trimmed) + "?" + q.Encode(), nil
}

func isMemoryPath(path string) bool {
	lower := strings.ToLower(path)
	return lower == ":memory:" || strings.Contains(lower, "mode=memory")
}

// Open opens the cache file at path, applies the connection pragmas, and runs
// both startup guards before returning the handle: it proves the database is
// in WAL mode with foreign keys on, and it proves FTS5 works by using it.
//
// Open does NOT migrate. Callers run Migrate explicitly, so that a process
// which only reads an already-current cache never needs write permission on
// the schema.
//
// A returned error leaves no handle open.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	dsn, err := DSN(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("cache: opening %q: %w", path, err)
	}
	if err := afterOpen(ctx, db, path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func afterOpen(ctx context.Context, db *sql.DB, path string) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("cache: connecting to %q: %w", path, err)
	}
	if err := CheckWAL(ctx, db); err != nil {
		return err
	}
	if err := checkForeignKeys(ctx, db); err != nil {
		return err
	}
	return CheckFTS5(ctx, db)
}

// CheckWAL refuses a handle whose database is not in WAL journal mode.
//
// The DSN asks for WAL, but asking is not the same as getting: SQLite silently
// leaves the journal mode unchanged when it cannot honour the request — an
// in-memory database, or a file on a filesystem that cannot do the shared-
// memory mapping WAL needs. The guard is the difference between "we configured
// WAL" and "this database is in WAL".
func CheckWAL(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("cache: CheckWAL needs a database handle")
	}
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("cache: reading PRAGMA journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("%w: journal_mode is %q. The cache is polled and read concurrently, and "+
			"A.2 forbids opening it outside WAL mode", ErrNotWAL, mode)
	}
	return nil
}

func checkForeignKeys(ctx context.Context, db *sql.DB) error {
	var on int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&on); err != nil {
		return fmt.Errorf("cache: reading PRAGMA foreign_keys: %w", err)
	}
	if on != 1 {
		return errors.New("cache: PRAGMA foreign_keys is OFF. Every child table in this schema " +
			"references advisory(source, source_id); without enforcement an affected range can " +
			"outlive the advisory that justified it and the comparator will match against nothing")
	}
	return nil
}

// ftsProbeTable is the name CheckFTS5 uses for its throwaway probe. It lives
// in the `temp` schema and is dropped immediately, so it never appears in the
// cache file. It is NOT `advisory_fts`, and nothing in this package ever
// drops that table — cache_test.go traces the driver to prove it.
const ftsProbeTable = "anvil_cache_fts5_probe"

// ftsProbeMatchSQL queries the probe table.
//
// The left operand of MATCH is the BARE table name even though the table lives
// in the temp schema. Verified on modernc.org/sqlite v1.56.0: both
// "temp.tbl MATCH ?" and "tbl AS alias ... alias MATCH ?" fail with
// "no such column", because fts5 resolves that operand as a column reference
// and neither a qualified name nor an alias is one.
const ftsProbeMatchSQL = "SELECT count(*) FROM temp." + ftsProbeTable +
	" WHERE " + ftsProbeTable + " MATCH 'probe'"

// CheckFTS5 proves the SQLite build behind db can create, populate and query
// an FTS5 virtual table.
//
// It runs at every Open rather than once at build time because that is the
// only thing that catches a dependency bump silently dropping the feature.
// The probe table is created in `temp`, so a failure cannot leave debris in
// the cache file and a success does not modify it either.
func CheckFTS5(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("cache: CheckFTS5 needs a database handle")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("cache: acquiring a connection for the FTS5 guard: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// The probe must run on ONE connection: a temp table is private to the
	// connection that created it.
	_, _ = conn.ExecContext(ctx, "DROP TABLE IF EXISTS temp."+ftsProbeTable)
	create := "CREATE VIRTUAL TABLE temp." + ftsProbeTable +
		" USING fts5(probe, content='', contentless_delete=1, tokenize='porter unicode61')"
	if _, err := conn.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("%w: creating a probe FTS5 table failed. plan/00-SPINE.md S12 depends on "+
			"modernc.org/sqlite bundling FTS5; if this build does not, the advisory index cannot "+
			"exist and no retrieval path over this cache works: %w", ErrNoFTS5, err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, "DROP TABLE IF EXISTS temp."+ftsProbeTable) }()

	if _, err := conn.ExecContext(ctx,
		"INSERT INTO temp."+ftsProbeTable+" (rowid, probe) VALUES (1, 'anvil fts5 probe')"); err != nil {
		return fmt.Errorf("%w: inserting into a probe FTS5 table failed: %w", ErrNoFTS5, err)
	}
	var hits int
	if err := conn.QueryRowContext(ctx, ftsProbeMatchSQL).Scan(&hits); err != nil {
		return fmt.Errorf("%w: MATCH against a probe FTS5 table failed: %w", ErrNoFTS5, err)
	}
	if hits != 1 {
		return fmt.Errorf("%w: a probe FTS5 table accepted a row but MATCH returned %d hits, want 1. "+
			"The module loads but does not index", ErrNoFTS5, hits)
	}
	// contentless_delete is what makes the plan's row-scoped upsert contract
	// hold; a build without it would replace rows while leaving their old
	// terms searchable forever, with no error to notice.
	if _, err := conn.ExecContext(ctx,
		"INSERT OR REPLACE INTO temp."+ftsProbeTable+" (rowid, probe) VALUES (1, 'anvil fts5 replaced')"); err != nil {
		return fmt.Errorf("%w: replacing a row in a probe FTS5 table failed: %w", ErrNoFTS5, err)
	}
	if err := conn.QueryRowContext(ctx, ftsProbeMatchSQL).Scan(&hits); err != nil {
		return fmt.Errorf("%w: MATCH after replace failed: %w", ErrNoFTS5, err)
	}
	if hits != 0 {
		return fmt.Errorf("%w: this SQLite build does not honour contentless_delete: after replacing a "+
			"row, its old terms still MATCH (%d hits, want 0). Every delta sync would accumulate "+
			"phantom hits silently", ErrNoFTS5, hits)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Migrating
// ---------------------------------------------------------------------------

// Migrate brings db up to the latest schema version and returns the versions
// it applied, in order. A cache already at the latest version returns nil and
// touches nothing, so calling Migrate on every start is correct and cheap.
//
// It is idempotent on an empty file and on a file already at the latest
// version, which is A.2's stop condition.
func Migrate(ctx context.Context, db *sql.DB) ([]int, error) {
	migrations, err := Migrations()
	if err != nil {
		return nil, err
	}
	return migrateWith(ctx, db, migrations)
}

// migrateWith is Migrate over an explicit migration list. It exists so
// cache_test.go can exercise ordering, mid-sequence failure and ledger
// tampering against synthetic later versions: those paths cannot otherwise be
// tested while version 1 is the only migration, and leaving them untested
// until the first real version 2 means discovering them during an upgrade.
func migrateWith(ctx context.Context, db *sql.DB, migrations []Migration) ([]int, error) {
	if db == nil {
		return nil, errors.New("cache: Migrate needs a database handle")
	}
	if err := CheckWAL(ctx, db); err != nil {
		return nil, err
	}
	if err := CheckFTS5(ctx, db); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, ledgerDDL); err != nil {
		return nil, fmt.Errorf("cache: creating the %s ledger: %w", ledgerTable, err)
	}

	applied, err := verifyLedger(ctx, db, migrations)
	if err != nil {
		return nil, err
	}
	pending := migrations[len(applied):]
	if len(pending) == 0 {
		return nil, nil
	}

	appliedNow := make([]int, 0, len(pending))
	for _, m := range pending {
		if err := applyOne(ctx, db, m); err != nil {
			return appliedNow, err
		}
		appliedNow = append(appliedNow, m.Version)
	}
	return appliedNow, nil
}

// appliedMigration is one ledger row.
type appliedMigration struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt string
}

// verifyLedger proves the ledger and `PRAGMA user_version` agree with each
// other and with this binary's migrations, and returns the applied migrations
// in version order.
//
// Every disagreement is fatal. The three named below are the ones that
// actually happen to a self-hosted tool: a hand-edited schema, a downgraded
// binary, and a file touched by something that is not this code.
func verifyLedger(ctx context.Context, db *sql.DB, migrations []Migration) ([]appliedMigration, error) {
	userVersion, err := Version(ctx, db)
	if err != nil {
		return nil, err
	}
	applied, err := readLedger(ctx, db)
	if err != nil {
		return nil, err
	}
	if len(applied) == 0 {
		if userVersion != 0 {
			return nil, fmt.Errorf("%w: PRAGMA user_version is %d but %s is empty. This file has a "+
				"schema no migration in this binary produced; refusing to guess which ones it has",
				ErrMigrationLedger, userVersion, ledgerTable)
		}
		return nil, nil
	}

	byVersion := make(map[int]Migration, len(migrations))
	for _, m := range migrations {
		byVersion[m.Version] = m
	}
	for i, row := range applied {
		if want := i + 1; row.Version != want {
			return nil, fmt.Errorf("%w: %s jumps from version %d to %d. The history has a gap, so "+
				"the schema in this file cannot be reconstructed from this binary's migrations",
				ErrMigrationLedger, ledgerTable, want-1, row.Version)
		}
		def, ok := byVersion[row.Version]
		if !ok {
			return nil, fmt.Errorf("%w: this cache has applied migration %d (%q) which this binary does "+
				"not contain. This is an older Anvil opening a newer cache; migrations are forward-only. "+
				"Run the newer binary, or delete the cache file and re-bootstrap it",
				ErrMigrationLedger, row.Version, row.Name)
		}
		if row.Name != def.Name {
			return nil, fmt.Errorf("%w: migration %d was applied as %q but this binary calls it %q",
				ErrMigrationLedger, row.Version, row.Name, def.Name)
		}
		if row.Checksum != def.Checksum {
			return nil, fmt.Errorf("%w: migration %d (%q) no longer matches what was applied to this cache "+
				"(ledger recorded %s, this binary carries %s). Either the migration was edited after the "+
				"fact or this binary's schema differs from the one that built this file. Re-running it "+
				"would apply DDL twice and skipping it would run queries against a schema that was never "+
				"applied, so this is a refusal; delete the cache file and re-bootstrap",
				ErrMigrationLedger, row.Version, row.Name, row.Checksum, def.Checksum)
		}
	}
	if maxApplied := applied[len(applied)-1].Version; userVersion != maxApplied {
		return nil, fmt.Errorf("%w: PRAGMA user_version is %d but the highest applied migration is %d. "+
			"They are written in one transaction, so this means the file was modified outside Anvil",
			ErrMigrationLedger, userVersion, maxApplied)
	}
	return applied, nil
}

// applyOne runs one migration inside one transaction, together with the
// user_version bump and the ledger row. SQLite DDL is transactional, so a
// failure anywhere in here leaves the schema exactly as it was.
func applyOne(ctx context.Context, db *sql.DB, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cache: migration %d (%q): BEGIN failed: %w", m.Version, m.Name, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("cache: migration %d (%q) failed and was rolled back; the schema is unchanged: %w",
			m.Version, m.Name, err)
	}
	// PRAGMA takes no bound parameters, so the version is formatted in. It is
	// an int from this package's own migration list, not caller input.
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(m.Version)); err != nil {
		return fmt.Errorf("cache: migration %d (%q): bumping user_version failed and was rolled back: %w",
			m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO "+ledgerTable+" (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
		m.Version, m.Name, m.Checksum, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("cache: migration %d (%q): recording the ledger row failed and was rolled back: %w",
			m.Version, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cache: migration %d (%q): COMMIT failed; the schema is unchanged: %w",
			m.Version, m.Name, err)
	}
	committed = true
	return nil
}

// Version returns the cache's `PRAGMA user_version`, which is 0 for a file no
// migration has touched.
func Version(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("cache: reading PRAGMA user_version: %w", err)
	}
	return v, nil
}

func readLedger(ctx context.Context, db *sql.DB) ([]appliedMigration, error) {
	var n int
	err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?", ledgerTable).Scan(&n)
	if err != nil {
		return nil, fmt.Errorf("cache: looking for the %s ledger: %w", ledgerTable, err)
	}
	if n == 0 {
		return nil, nil
	}

	rows, err := db.QueryContext(ctx,
		"SELECT version, name, checksum, applied_at FROM "+ledgerTable+" ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("cache: reading %s: %w", ledgerTable, err)
	}
	defer func() { _ = rows.Close() }()

	var applied []appliedMigration
	for rows.Next() {
		var a appliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, fmt.Errorf("cache: scanning %s: %w", ledgerTable, err)
		}
		applied = append(applied, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cache: iterating %s: %w", ledgerTable, err)
	}
	return applied, nil
}
