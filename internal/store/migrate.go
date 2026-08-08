// Forward-only numbered migrations with a checksummed ledger (step R.5).
//
// research/07-database-design.md §7: "numbered forward-only SQL +
// `PRAGMA user_version` + a checksummed ledger". No Alembic, no goose, no
// sqlx-cli, nothing for a self-hoster to install — plan/00-SPINE.md S12 makes
// this Go-only, and the migrations are embedded in the binary.
//
// Three properties are load-bearing and each has a test:
//
//  1. Each migration runs inside BEGIN ... COMMIT and bumps `user_version` in
//     the SAME transaction, so a failure leaves the schema untouched rather
//     than half-applied.
//  2. Every applied migration's checksum is re-verified at startup against the
//     embedded text. A mismatch is a refusal, not a re-run and not a skip: it
//     means the database was built by a different definition of the schema
//     than the one this binary carries, and either guess about what to do next
//     corrupts the store of record.
//  3. Forward-only. There are no down migrations. The rollback story is
//     `VACUUM INTO 'anvil-pre-v{N}.db'` taken before the first migration
//     touches an existing database.

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const migrationsDir = "migrations"

// includeDirectivePrefix introduces the one preprocessor directive a migration
// file may contain. See migrations/0001_init.sql for why it exists: schema.sql
// is a frozen interface with exactly one copy in this repository, and a
// migration references it rather than duplicating it.
const includeDirectivePrefix = "-- @anvil:include "

// ErrMigrationLedger reports that the database's migration history and this
// binary's embedded migrations disagree. It is always a refusal to proceed.
var ErrMigrationLedger = errors.New("store: migration ledger mismatch")

// ErrSnapshotRequired reports that migrating an already-populated database was
// attempted without somewhere to put the pre-migration snapshot.
var ErrSnapshotRequired = errors.New("store: pre-migration snapshot directory required")

var migrationFilenameRE = regexp.MustCompile(`^(\d{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// Migration is one numbered, embedded, forward-only migration.
type Migration struct {
	// Version is the number in the filename; versions are contiguous from 1.
	Version int
	// Name is the descriptive part of the filename, e.g. "init".
	Name string
	// Filename is the name as embedded, e.g. "0001_init.sql".
	Filename string
	// SQL is the fully expanded text that will be executed: the file's bytes
	// with every include directive replaced by the included content.
	SQL string
	// Checksum is the lowercase hex SHA-256 of SQL. This is the value written
	// to and re-verified against schema_migration.checksum.
	Checksum string
}

var loadMigrations = sync.OnceValues(func() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("store: reading embedded migrations: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("store: %s/%s is a directory; migrations are flat", migrationsDir, e.Name())
		}
		m := migrationFilenameRE.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("store: migration filename %q does not match NNNN_lower_snake_name.sql", e.Name())
		}
		version, err := strconv.Atoi(m[1])
		if err != nil { // unreachable: the regexp already proved four digits
			return nil, fmt.Errorf("store: migration %q has an unparseable version: %w", e.Name(), err)
		}
		raw, err := migrationFS.ReadFile(path.Join(migrationsDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("store: reading migration %q: %w", e.Name(), err)
		}
		expanded, err := expandIncludes(e.Name(), string(raw))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(expanded))
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     m[2],
			Filename: e.Name(),
			SQL:      expanded,
			Checksum: hex.EncodeToString(sum[:]),
		})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for i, mig := range migrations {
		if want := i + 1; mig.Version != want {
			return nil, fmt.Errorf("store: migration versions must be contiguous from 0001; "+
				"expected %04d at position %d but found %q", want, i+1, mig.Filename)
		}
	}
	if len(migrations) == 0 {
		return nil, errors.New("store: no migrations are embedded; the store cannot be created")
	}
	return migrations, nil
})

// Migrations returns every embedded migration in ascending version order.
//
// It fails rather than returning a partial list if the filenames are malformed
// or the numbering has a gap or duplicate, because "migrate what parses" is
// how a store ends up at a version nobody can describe.
func Migrations() ([]Migration, error) {
	migrations, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	return append([]Migration(nil), migrations...), nil
}

// expandIncludes replaces each `-- @anvil:include <file>` line with the
// content of the named file. Today the only legal target is schema.sql, whose
// bytes come from the string ddl.go embeds — so there is exactly one copy of
// the schema in the repository and the migration cannot drift from it.
func expandIncludes(filename, src string) (string, error) {
	if !strings.Contains(src, includeDirectivePrefix) {
		return src, nil
	}

	var out strings.Builder
	out.Grow(len(src) + len(schemaSQL))
	rest := src
	lineNo := 0
	for len(rest) > 0 {
		line := rest
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			rest = ""
		}
		lineNo++

		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, includeDirectivePrefix) {
			out.WriteString(line)
			continue
		}
		target := strings.TrimSpace(strings.TrimPrefix(trimmed, includeDirectivePrefix))
		if target != "schema.sql" {
			return "", fmt.Errorf("store: %s line %d includes %q; the only includable file is schema.sql",
				filename, lineNo, target)
		}
		out.WriteString(Schema())
		if !strings.HasSuffix(Schema(), "\n") {
			out.WriteString("\n")
		}
	}
	return out.String(), nil
}

// appliedMigration is one row of the schema_migration ledger.
type appliedMigration struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt string
}

// Migrate brings db up to the latest embedded schema version and returns the
// versions it applied, in order. An already-current database returns an empty
// slice and touches nothing.
//
// snapshotDir is where the `VACUUM INTO 'anvil-pre-v{N}.db'` pre-migration
// snapshot is written. It may be empty ONLY when the database has no applied
// migrations — a fresh database has nothing to lose, so demanding a snapshot
// of it would just teach callers to pass a junk directory. Upgrading a
// populated database without one is refused: research/07-database-design.md §7
// makes the snapshot the entire replacement for down migrations, so skipping
// it means the upgrade has no rollback path at all.
//
// CheckFTS5 runs first, on the same handle. plan/40-record-and-storage.md
// requires the guards before any other store operation, and applying
// schema.sql is a store operation — its advisory_fts table would otherwise
// fail deep inside the transaction with a driver-level error instead of the
// guard's explanation.
func Migrate(ctx context.Context, db *sql.DB, snapshotDir string) ([]int, error) {
	migrations, err := Migrations()
	if err != nil {
		return nil, err
	}
	return migrateWith(ctx, db, migrations, snapshotDir)
}

// migrateWith is Migrate over an explicit migration list. It exists so
// migrate_test.go can exercise ordering, mid-sequence failure and the snapshot
// rule against synthetic later versions: those paths cannot otherwise be
// tested while 0001 is the only embedded migration, and leaving them untested
// until the first real 0002 means discovering them during an upgrade.
func migrateWith(ctx context.Context, db *sql.DB, migrations []Migration, snapshotDir string) ([]int, error) {
	if db == nil {
		return nil, errors.New("store: Migrate needs a database handle")
	}
	if err := CheckFTS5Context(ctx, db); err != nil {
		return nil, err
	}

	applied, err := verifyLedger(ctx, db, migrations)
	if err != nil {
		return nil, err
	}

	pending := migrations[len(applied):]
	if len(pending) == 0 {
		return nil, nil
	}

	if len(applied) > 0 {
		if strings.TrimSpace(snapshotDir) == "" {
			return nil, fmt.Errorf("%w: this database is at schema version %d and %d migration(s) are "+
				"pending. Migrations are forward-only and there are no down migrations "+
				"(research/07-database-design.md §7), so a VACUUM INTO snapshot is the only rollback "+
				"path; pass a directory to write it to", ErrSnapshotRequired, len(applied), len(pending))
		}
		dest, err := snapshotPath(snapshotDir, len(applied))
		if err != nil {
			return nil, err
		}
		if err := Snapshot(ctx, db, dest); err != nil {
			return nil, err
		}
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

// verifyLedger reads schema_migration and PRAGMA user_version and proves they
// agree with each other and with the embedded migrations. It returns the
// applied migrations in version order.
//
// Every disagreement here is fatal. The three it names are the ones
// research/07 §7 says actually happen to self-hosted tools: a hand-edited
// migration, a downgraded binary, and a database that was interrupted or
// touched by something that is not this code.
func verifyLedger(ctx context.Context, db *sql.DB, migrations []Migration) ([]appliedMigration, error) {
	userVersion, err := SchemaVersion(ctx, db)
	if err != nil {
		return nil, err
	}

	hasLedger, err := tableExists(ctx, db, "schema_migration")
	if err != nil {
		return nil, err
	}
	if !hasLedger {
		if userVersion != 0 {
			return nil, fmt.Errorf("%w: PRAGMA user_version is %d but there is no schema_migration table. "+
				"This database was not created by Anvil, or its ledger was dropped; refusing to guess which "+
				"migrations it has", ErrMigrationLedger, userVersion)
		}
		return nil, nil
	}

	applied, err := readLedger(ctx, db)
	if err != nil {
		return nil, err
	}
	if len(applied) == 0 {
		if userVersion != 0 {
			return nil, fmt.Errorf("%w: PRAGMA user_version is %d but schema_migration is empty",
				ErrMigrationLedger, userVersion)
		}
		return nil, nil
	}

	byVersion := make(map[int]Migration, len(migrations))
	for _, m := range migrations {
		byVersion[m.Version] = m
	}

	for i, row := range applied {
		if want := i + 1; row.Version != want {
			return nil, fmt.Errorf("%w: schema_migration jumps from version %d to %d. The history has a "+
				"gap, so the schema in this file cannot be reconstructed from the migrations in this binary",
				ErrMigrationLedger, want-1, row.Version)
		}
		embedded, ok := byVersion[row.Version]
		if !ok {
			return nil, fmt.Errorf("%w: the database has applied migration %04d (%q) which this binary does "+
				"not contain. This is an older Anvil opening a newer store; migrations are forward-only, so "+
				"downgrading is not supported. Run the newer binary, or restore an anvil-pre-v*.db snapshot",
				ErrMigrationLedger, row.Version, row.Name)
		}
		if row.Name != embedded.Name {
			return nil, fmt.Errorf("%w: migration %04d was applied as %q but this binary calls it %q",
				ErrMigrationLedger, row.Version, row.Name, embedded.Name)
		}
		if row.Checksum != embedded.Checksum {
			return nil, fmt.Errorf("%w: migration %s no longer matches what was applied to this database "+
				"(ledger recorded %s, this binary carries %s). Either the migration file or schema.sql was "+
				"edited after the fact, or this binary's schema differs from the one that built this store. "+
				"Refusing to start: re-running it would apply DDL twice and skipping it would run against a "+
				"schema that was never applied",
				ErrMigrationLedger, embedded.Filename, row.Checksum, embedded.Checksum)
		}
	}

	if maxApplied := applied[len(applied)-1].Version; userVersion != maxApplied {
		return nil, fmt.Errorf("%w: PRAGMA user_version is %d but the highest applied migration is %d. "+
			"They are written in one transaction, so this means the file was modified outside Anvil",
			ErrMigrationLedger, userVersion, maxApplied)
	}
	return applied, nil
}

// applyOne runs a single migration inside one transaction, together with the
// user_version bump and the ledger row.
//
// SQLite DDL is transactional, so a failure anywhere in here leaves the schema
// exactly as it was — which is the reason this is one transaction and not
// three statements.
func applyOne(ctx context.Context, db *sql.DB, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: migration %s: BEGIN failed: %w", m.Filename, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("store: migration %s failed and was rolled back; the schema is unchanged: %w", m.Filename, err)
	}

	// PRAGMA takes no bound parameters, so the version is formatted in. It is
	// an int parsed from a \d{4} filename match, not caller input.
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(m.Version)); err != nil {
		return fmt.Errorf("store: migration %s: bumping user_version failed and was rolled back: %w", m.Filename, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migration (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.Version, m.Name, m.Checksum, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("store: migration %s: recording the ledger row failed and was rolled back: %w", m.Filename, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: migration %s: COMMIT failed; the schema is unchanged: %w", m.Filename, err)
	}
	committed = true
	return nil
}

// Snapshot writes a consistent copy of the whole database to dest using
// `VACUUM INTO`, which research/07-database-design.md §7 makes the substitute
// for down migrations.
//
// dest must not already exist: SQLite refuses to overwrite, and so does this —
// silently replacing the only pre-upgrade copy of a store would be the worst
// possible way to be helpful.
func Snapshot(ctx context.Context, db *sql.DB, dest string) error {
	if db == nil {
		return errors.New("store: Snapshot needs a database handle")
	}
	if strings.TrimSpace(dest) == "" {
		return errors.New("store: Snapshot needs a destination path")
	}
	// VACUUM cannot run inside a transaction, so this goes to db directly. The
	// path is a SQL string literal because SQLite does not bind parameters in
	// VACUUM INTO; doubling embedded quotes is the whole escaping rule for a
	// SQLite string literal.
	quoted := "'" + strings.ReplaceAll(dest, "'", "''") + "'"
	if _, err := db.ExecContext(ctx, "VACUUM INTO "+quoted); err != nil {
		return fmt.Errorf("store: pre-migration snapshot to %q failed; refusing to migrate without one: %w", dest, err)
	}
	return nil
}

// snapshotPath builds research/07's `anvil-pre-v{N}.db` name inside dir,
// creating dir if needed. If that name is taken — a second upgrade attempt
// after a failure — a timestamp is appended rather than clobbering the
// existing snapshot.
func snapshotPath(dir string, currentVersion int) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("store: creating snapshot directory %q: %w", dir, err)
	}
	base := filepath.Join(dir, fmt.Sprintf("anvil-pre-v%d.db", currentVersion))
	if _, err := os.Lstat(base); errors.Is(err, fs.ErrNotExist) {
		return base, nil
	}
	return filepath.Join(dir, fmt.Sprintf("anvil-pre-v%d-%d.db", currentVersion, time.Now().UTC().UnixNano())), nil
}

// SchemaVersion returns the database's PRAGMA user_version, which is 0 for a
// database no migration has touched.
func SchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("store: reading PRAGMA user_version: %w", err)
	}
	return v, nil
}

// LatestVersion returns the highest embedded migration version — the schema
// version a fully migrated database will report.
func LatestVersion() (int, error) {
	migrations, err := loadMigrations()
	if err != nil {
		return 0, err
	}
	return migrations[len(migrations)-1].Version, nil
}

func tableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, name).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: looking for table %q: %w", name, err)
	}
	return n > 0, nil
}

func readLedger(ctx context.Context, db *sql.DB) ([]appliedMigration, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT version, name, checksum, applied_at FROM schema_migration ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("store: reading schema_migration: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var applied []appliedMigration
	for rows.Next() {
		var a appliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, fmt.Errorf("store: scanning schema_migration: %w", err)
		}
		applied = append(applied, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating schema_migration: %w", err)
	}
	return applied, nil
}
