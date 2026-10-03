// This file opens the store of record for a process: one file, every
// connection carrying ConnectionPragmas, both startup guards run, and the
// schema migrated, in the order plan/design/record-and-store.md puts them.
//
// ConnectionPragmas existed before this file, but nothing applied them to a
// real handle: `foreign_keys` is per connection and OFF by default, so a
// process that opened the store with a bare sql.Open would have written to a
// schema whose foreign keys were decoration. The cache solved the same problem
// with a DSN that carries the pragmas, and Open does the same.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// Open opens (creating if absent) the store at path, checks it, and migrates
// it to the latest schema. snapshotDir receives the pre-migration snapshot
// when an existing store is upgraded; see Migrate.
func Open(ctx context.Context, path, snapshotDir string) (*sql.DB, error) {
	p := strings.TrimSpace(path)
	if p == "" || p == ":memory:" || strings.HasPrefix(p, "file::memory:") {
		return nil, fmt.Errorf("store: %q is not a file; the store is one file on disk in WAL mode", path)
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return nil, fmt.Errorf("store: %q contains %q, which the SQLite DSN reserves", path, p[i:i+1])
	}
	q := make(url.Values)
	for _, pragma := range ConnectionPragmas() {
		q.Add("_pragma", strings.TrimPrefix(pragma, "PRAGMA "))
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("store: opening %q: %w", path, err)
	}
	if err := afterOpen(ctx, db, p, snapshotDir); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func afterOpen(ctx context.Context, db *sql.DB, path, snapshotDir string) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("store: connecting to %q: %w", path, err)
	}
	if err := CheckStartup(filepath.Dir(path), db); err != nil {
		return err
	}
	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		return fmt.Errorf("store: reading foreign_keys: %w", err)
	}
	if fk != 1 {
		return errors.New("store: foreign_keys is OFF on this connection; the schema depends on it")
	}
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("store: reading journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("store: journal_mode is %q, not WAL", mode)
	}
	if _, err := Migrate(ctx, db, snapshotDir); err != nil {
		return err
	}
	return nil
}
