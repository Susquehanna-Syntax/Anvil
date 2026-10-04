package store

import (
	"context"
	"testing"
)

// TestRecallCandidatesKeepsNotRunApartFromNone holds migration 0002: NULL is
// "Lane B did not run", 0 is "it ran and matched nothing", and a negative
// count is refused by the column's CHECK.
func TestRecallCandidatesKeepsNotRunApartFromNone(t *testing.T) {
	db := openMemory(t)
	if _, err := Migrate(context.Background(), db, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO target (target_id, kind, locator) VALUES (1, 'repo', 'repo:x')`); err != nil {
		t.Fatal(err)
	}
	insert := func(v any) error {
		_, err := db.Exec(`INSERT INTO scan_run (target_id, started_at, status, ruleset_version, recall_candidates)
VALUES (1, '2026-10-03T00:00:00Z', 'ok', 'r', ?)`, v)
		return err
	}
	for _, ok := range []any{nil, 0, 225} {
		if err := insert(ok); err != nil {
			t.Errorf("recall_candidates %v refused: %v", ok, err)
		}
	}
	if err := insert(-1); err == nil {
		t.Error("a negative candidate count was stored")
	}
	var nulls, zeros int
	if err := db.QueryRow(`SELECT sum(recall_candidates IS NULL), sum(recall_candidates = 0) FROM scan_run`).Scan(&nulls, &zeros); err != nil {
		t.Fatal(err)
	}
	if nulls != 1 || zeros != 1 {
		t.Fatalf("NULL and 0 did not stay apart: %d NULL, %d zero", nulls, zeros)
	}
}
