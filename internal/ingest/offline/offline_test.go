package offline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
)

const fixture = "../../../testdata/lanea-fixture"

func openCache(t *testing.T) func() int {
	t.Helper()
	ctx := context.Background()
	db, err := cache.Open(ctx, filepath.Join(t.TempDir(), "anvil-cache.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := cache.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM advisory`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	imp = func(dir string) (Report, error) { return Import(ctx, db, dir) }
	return count
}

var imp func(string) (Report, error)

func TestTheFixtureImports(t *testing.T) {
	count := openCache(t)
	rep, err := imp(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Feeds) != 1 || rep.Feeds[0].Refused != "" || rep.Feeds[0].Documents != 5 || count() != 5 {
		t.Fatalf("import: %+v, %d advisories", rep, count())
	}
}

// A feed whose licence body no longer matches its pinned digest imports
// nothing: the offline path runs the same licence gate as the live one.
func TestATamperedLicenceBodyImportsNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(dir, "mirror", "tier0", "debian-osv-fixture", "LICENSE.full.txt")
	if err := os.WriteFile(body, []byte("not the text that was pinned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	count := openCache(t)
	rep, err := imp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Feeds) != 1 || rep.Feeds[0].Refused == "" || rep.Feeds[0].Documents != 0 {
		t.Fatalf("a feed with a tampered licence body was not refused: %+v", rep.Feeds)
	}
	if n := count(); n != 0 {
		t.Fatalf("%d advisories imported from a refused feed", n)
	}
}

func TestASnapshotWithNoCaptureTimeIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SnapshotFile), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openCache(t)
	if _, err := imp(dir); err == nil {
		t.Fatal("a snapshot with no asOf imported; its data age would read as fresh")
	}
}
