package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// ---------------------------------------------------------------------------
// Guard 1 — CheckNetworkMount
// ---------------------------------------------------------------------------

// TestCheckNetworkMountRefusesInjectedNetworkFilesystems is the R.5 packet's
// "CheckNetworkMount fails against an injected fake network filesystem type"
// evidence item. The probe is the seam; no NFS server is involved.
func TestCheckNetworkMountRefusesInjectedNetworkFilesystems(t *testing.T) {
	refused := []string{
		"nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs",
		"lustre", "afs", "davfs", "vboxsf", "virtiofs", "unc",
		"fuse.sshfs", "fuse.davfs", "fuse.s3fs", "fuse.rclone",
		"NFS4", " cifs ", // case and whitespace must not smuggle a mount past
	}
	for _, fsType := range refused {
		t.Run(strings.TrimSpace(fsType), func(t *testing.T) {
			probe := func(string) (string, error) { return fsType, nil }
			err := checkNetworkMountWith("/srv/anvil", probe)
			if err == nil {
				t.Fatalf("CheckNetworkMount accepted a %q data directory", fsType)
			}
			if !errors.Is(err, ErrNetworkMount) {
				t.Fatalf("error does not wrap ErrNetworkMount: %v", err)
			}
			// "Fails loudly" means the operator can act on the message: it has
			// to name the path and say what to do.
			for _, want := range []string{"/srv/anvil", "write-ahead log", "local storage"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error message omits %q: %v", want, err)
				}
			}
		})
	}
}

func TestCheckNetworkMountAcceptsLocalFilesystems(t *testing.T) {
	// fuseblk and fuse.gocryptfs are local; refusing them would be a false
	// positive that pushes users to delete the guard.
	for _, fsType := range []string{"ext4", "xfs", "btrfs", "zfs", "apfs", "ntfs", "overlay", "tmpfs", "fuseblk", "fuse.gocryptfs"} {
		probe := func(string) (string, error) { return fsType, nil }
		if err := checkNetworkMountWith("/srv/anvil", probe); err != nil {
			t.Errorf("CheckNetworkMount refused local filesystem %q: %v", fsType, err)
		}
	}
}

func TestCheckNetworkMountPassesWhenTypeIsUndeterminable(t *testing.T) {
	probe := func(string) (string, error) { return "", nil }
	if err := checkNetworkMountWith("/srv/anvil", probe); err != nil {
		t.Fatalf("an undeterminable filesystem type must not block startup: %v", err)
	}
}

// TestCheckNetworkMountSurfacesProbeFailures pins the difference between "this
// host has no mount table" (pass) and "this host has one and it could not be
// read" (fail). The second is the case where staying quiet would hide exactly
// what the guard is for.
func TestCheckNetworkMountSurfacesProbeFailures(t *testing.T) {
	sentinel := errors.New("mount table is unreadable")
	probe := func(string) (string, error) { return "", sentinel }
	err := checkNetworkMountWith("/srv/anvil", probe)
	if !errors.Is(err, sentinel) {
		t.Fatalf("probe failure was swallowed: %v", err)
	}
}

func TestCheckNetworkMountRejectsEmptyPath(t *testing.T) {
	if err := CheckNetworkMount("   "); !errors.Is(err, ErrNetworkMount) {
		t.Fatalf("empty data directory should be refused, got %v", err)
	}
}

// TestCheckNetworkMountOnRealHostAcceptsTempDir exercises the real probe end
// to end. A temp directory is local on every machine this is expected to run
// on, so a refusal here means the probe misreads its own host.
func TestCheckNetworkMountOnRealHostAcceptsTempDir(t *testing.T) {
	if err := CheckNetworkMount(t.TempDir()); err != nil {
		t.Fatalf("real probe refused a local temp directory: %v", err)
	}
	// A directory that does not exist yet must resolve through its nearest
	// existing ancestor: the data directory is created after this guard runs.
	if err := CheckNetworkMount(filepath.Join(t.TempDir(), "anvil", "data")); err != nil {
		t.Fatalf("real probe refused a not-yet-created data directory: %v", err)
	}
}

func TestUNCPathDetection(t *testing.T) {
	unc := []string{`\\nas\anvil`, `\\nas\anvil\data`, `//nas/anvil`}
	for _, p := range unc {
		if !isUNCPath(p) {
			t.Errorf("isUNCPath(%q) = false, want true", p)
		}
	}
	notUNC := []string{`C:\anvil`, `/srv/anvil`, `\\?\C:\anvil`, `\\.\PIPE\x`, `\\nas`, `\\nas\`, ``}
	for _, p := range notUNC {
		if isUNCPath(p) {
			t.Errorf("isUNCPath(%q) = true, want false", p)
		}
	}
}

func TestMountTableParsing(t *testing.T) {
	mountinfo := "36 35 98:0 / /srv rw,noatime shared:1 - ext4 /dev/root rw\n" +
		"41 36 0:41 / /srv/anvil\\040data rw - nfs4 nas:/export/anvil rw\n" +
		"42 36 0:42 / /srv/anvilx rw - ext4 /dev/sdb rw\n"
	var got []mountEntry
	for _, line := range strings.Split(strings.TrimSuffix(mountinfo, "\n"), "\n") {
		e, ok := parseMountinfoLine(line)
		if !ok {
			t.Fatalf("failed to parse mountinfo line %q", line)
		}
		got = append(got, e)
	}
	if got[1].point != "/srv/anvil data" || got[1].fsType != "nfs4" {
		t.Fatalf("octal-escaped mount point mis-parsed: %+v", got[1])
	}

	// /proc/mounts has a different field order; both feed the same lookup.
	e, ok := parseProcMountsLine(`nas:/export /srv/anvil\040data nfs4 rw,relatime 0 0`)
	if !ok || e.point != "/srv/anvil data" || e.fsType != "nfs4" {
		t.Fatalf("/proc/mounts line mis-parsed: %+v ok=%v", e, ok)
	}

	// A mountinfo line with no "-" separator is malformed, not a mount.
	if _, ok := parseMountinfoLine("36 35 98:0 / /srv rw ext4 /dev/root rw"); ok {
		t.Fatal("a mountinfo line without the optional-fields separator must not parse")
	}
}

// TestLongestMountPointWins is the whole reason the mount table is sorted:
// a share mounted under the root filesystem must not be reported as the root
// filesystem's type.
func TestLongestMountPointWins(t *testing.T) {
	if pathHasPrefix("/srv/anvil", "/srv/anvilx/data") {
		t.Fatal("/srv/anvil must not match /srv/anvilx/data — whole path elements only")
	}
	if !pathHasPrefix("/srv/anvil", "/srv/anvil") {
		t.Fatal("a mount point is a prefix of itself")
	}
	if !pathHasPrefix("/", "/srv/anvil") {
		t.Fatal("the root filesystem contains everything")
	}
}

// ---------------------------------------------------------------------------
// Guard 2 — CheckFTS5
// ---------------------------------------------------------------------------

// TestCheckFTS5PassesAgainstTheRealDriver is the positive control. It is also
// the check the R.5 packet actually cares about at run time: if a future
// modernc.org/sqlite bump drops FTS5, this test goes red in CI on the same
// commit that bumps the dependency.
func TestCheckFTS5PassesAgainstTheRealDriver(t *testing.T) {
	db := openMemory(t)
	if err := CheckFTS5(db); err != nil {
		t.Fatalf("FTS5 guard failed against modernc.org/sqlite: %v", err)
	}
	// Repeat runs must not collide on the probe table name, and must leave no
	// trace behind on the pooled connection.
	if err := CheckFTS5(db); err != nil {
		t.Fatalf("second FTS5 probe failed: %v", err)
	}
	var leftovers int
	err := db.QueryRow(`SELECT count(*) FROM temp.sqlite_schema WHERE name LIKE 'anvil_fts5_probe%'`).Scan(&leftovers)
	if err != nil {
		t.Fatalf("counting temp objects: %v", err)
	}
	if leftovers != 0 {
		t.Fatalf("FTS5 probe left %d temp objects behind", leftovers)
	}
}

func TestCheckFTS5RejectsNilHandle(t *testing.T) {
	if err := CheckFTS5(nil); !errors.Is(err, ErrNoFTS5) {
		t.Fatalf("nil handle should be refused with ErrNoFTS5, got %v", err)
	}
}

// TestCheckFTS5FailsLoudlyWithoutFTS5 stands in for the packet's "build tag
// that disables FTS5". modernc.org/sqlite exposes no such tag — its FTS5 is
// compiled in unconditionally — so the absent capability is injected at the
// database/sql driver layer instead, which exercises the identical code path
// in CheckFTS5 including the error it produces.
func TestCheckFTS5FailsLoudlyWithoutFTS5(t *testing.T) {
	db, err := sql.Open(driverNoFTS5, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	err = CheckFTS5(db)
	if err == nil {
		t.Fatal("CheckFTS5 passed against a driver with no fts5 module")
	}
	if !errors.Is(err, ErrNoFTS5) {
		t.Fatalf("error does not wrap ErrNoFTS5: %v", err)
	}
	for _, want := range []string{"CREATE VIRTUAL TABLE", "no such module: fts5", "advisory_fts"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message omits %q: %v", want, err)
		}
	}
}

// TestCheckFTS5FailsWhenMatchSilentlyIndexesNothing is the "not silently" half
// of the packet's requirement, and the reason this guard runs a real MATCH
// rather than stopping at a successful CREATE. A build that accepts the DDL
// and indexes nothing would pass a syntax-only probe and then return zero
// advisories forever.
func TestCheckFTS5FailsWhenMatchSilentlyIndexesNothing(t *testing.T) {
	db, err := sql.Open(driverSilentFTS5, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	err = CheckFTS5(db)
	if err == nil {
		t.Fatal("CheckFTS5 passed against a driver whose FTS5 indexes nothing")
	}
	if !errors.Is(err, ErrNoFTS5) {
		t.Fatalf("error does not wrap ErrNoFTS5: %v", err)
	}
	if !strings.Contains(err.Error(), "returned 0 rows") {
		t.Errorf("error message does not say what went wrong: %v", err)
	}
}

func TestCheckStartupRunsBothGuards(t *testing.T) {
	// A refused mount short-circuits before the database is touched.
	if err := CheckStartup("", nil); !errors.Is(err, ErrNetworkMount) {
		t.Fatalf("CheckStartup should fail on the mount guard first, got %v", err)
	}
	// A good directory still has to clear the FTS5 guard.
	if err := CheckStartup(t.TempDir(), nil); !errors.Is(err, ErrNoFTS5) {
		t.Fatalf("CheckStartup should reach the FTS5 guard, got %v", err)
	}
	if err := CheckStartup(t.TempDir(), openMemory(t)); err != nil {
		t.Fatalf("CheckStartup failed on a healthy local store: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test fixtures: two database/sql drivers with broken FTS5
// ---------------------------------------------------------------------------

const (
	driverNoFTS5     = "anvil-test-no-fts5"
	driverSilentFTS5 = "anvil-test-silent-fts5"
)

func init() {
	sql.Register(driverNoFTS5, fakeDriver{silent: false})
	sql.Register(driverSilentFTS5, fakeDriver{silent: true})
}

// fakeDriver is the smallest database/sql driver that can answer CheckFTS5's
// three statements. silent=false rejects the CREATE the way a SQLite build
// without the fts5 module does; silent=true accepts everything and then
// matches nothing.
type fakeDriver struct{ silent bool }

func (d fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{silent: d.silent}, nil }

type fakeConn struct{ silent bool }

func (c fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("fake driver: Prepare is not implemented; use the context methods")
}
func (c fakeConn) Close() error              { return nil }
func (c fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("fake driver: no transactions") }

func (c fakeConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if !c.silent && strings.Contains(query, "USING fts5") {
		return nil, errors.New("no such module: fts5")
	}
	return driver.RowsAffected(0), nil
}

func (c fakeConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "MATCH") {
		return &fakeRows{cols: []string{"count(*)"}, vals: [][]driver.Value{{int64(0)}}}, nil
	}
	return &fakeRows{cols: []string{"x"}}, nil
}

type fakeRows struct {
	cols []string
	vals [][]driver.Value
	next int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.next >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.next])
	r.next++
	return nil
}
