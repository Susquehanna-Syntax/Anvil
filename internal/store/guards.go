// Startup guards for the Anvil store (step R.5).
//
// plan/40-record-and-storage.md, "Startup guards (R.5), both mandatory":
// refuse to start if the data directory is on a network-mounted filesystem,
// and refuse to start if an FTS5 smoke-test virtual table cannot be created.
// Both must run before any other store operation; CheckStartup runs them in
// the required order and Migrate calls CheckFTS5 itself so that a caller who
// builds its own *sql.DB cannot skip it.
//
// Neither guard trusts a version number, a build tag, or a claim in a
// document. plan/00-SPINE.md S12 calls modernc.org/sqlite's FTS5 support
// "orchestrator-verified", but the research trail behind that
// (plan/spine-c-language.md C5-C7) grades its own evidence B,
// "absence-of-evidence, not evidence-of-absence". A dependency bump can drop a
// build-time feature without any signal at all, and the only thing that
// catches that is executing the feature at every process start. So CheckFTS5
// creates a real FTS5 table, writes a real row, and runs a real MATCH.

package store

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
)

// ErrNetworkMount reports that the data directory is on a filesystem where
// SQLite's write-ahead log is documented not to work.
//
// research/07-database-design.md Risk #4: "WAL does not work over a network
// filesystem", and homelab users routinely put data directories on NFS or SMB.
// The failure is silent corruption of the store of record, not an error at
// mount time, which is why this is a refusal and not a warning.
var ErrNetworkMount = errors.New("store: data directory is on a network filesystem")

// ErrNoFTS5 reports that the SQLite build behind the *sql.DB cannot create or
// query an FTS5 virtual table. schema.sql's advisory_fts table needs it.
var ErrNoFTS5 = errors.New("store: SQLite FTS5 is unavailable")

// CheckStartup runs both mandatory guards in the order the store needs them,
// and is the single call a process should make before any other store
// operation.
//
// The mount check comes first because it is answerable from the filesystem
// alone: if it fails there is no reason to have opened a database at all.
func CheckStartup(dataDir string, db *sql.DB) error {
	if err := CheckNetworkMount(dataDir); err != nil {
		return err
	}
	return CheckFTS5(db)
}

// ---------------------------------------------------------------------------
// Guard 1 — network-mounted data directory
// ---------------------------------------------------------------------------

// networkFilesystemTypes is the set of filesystem type names that mean "this
// data lives on another host". A type in this set is a hard refusal.
//
// The set is deliberately explicit rather than a heuristic: guessing from the
// mount source would refuse loopback-mounted images and other perfectly local
// setups, and a false refusal at startup is as user-hostile as a missed one is
// dangerous.
var networkFilesystemTypes = map[string]bool{
	"9p":        true, // Plan 9 / virtio-9p, the usual VM share
	"afpfs":     true,
	"afs":       true,
	"beegfs":    true,
	"ceph":      true,
	"cifs":      true,
	"coda":      true,
	"davfs":     true,
	"gfs2":      true,
	"glusterfs": true,
	"lustre":    true,
	"ncpfs":     true,
	"nfs":       true,
	"nfs4":      true,
	"ocfs2":     true,
	"orangefs":  true,
	"pvfs2":     true,
	"smb2":      true,
	"smb3":      true,
	"smbfs":     true,
	"unc":       true, // synthesised below for a Windows \\server\share path
	"vboxsf":    true,
	"virtiofs":  true,
}

// networkFUSEBackends covers FUSE mounts, whose type is reported as
// "fuse.<backend>". The FUSE layer itself is local; the backend is what
// decides.
var networkFUSEBackends = map[string]bool{
	"cephfs":     true,
	"davfs":      true,
	"glusterfs":  true,
	"gvfsd-fuse": true,
	"rclone":     true,
	"s3fs":       true,
	"sshfs":      true,
}

// fsTypeProbe reports the filesystem type backing path, or "" when the host
// gives no way to tell. It is a variable-shaped seam so guards_test.go can
// inject a fake network filesystem type without needing a real NFS server.
type fsTypeProbe func(path string) (string, error)

// CheckNetworkMount refuses a data directory that sits on a network
// filesystem.
//
// KNOWN LIMIT, stated plainly because a guard that overstates its coverage is
// worse than one that does not exist. Filesystem type detection here is pure
// Go with no cgo and no build-tagged files (plan/00-SPINE.md S12), which means
// it reads /proc/self/mountinfo (falling back to /proc/mounts). On Linux —
// Anvil's deployment target — that is authoritative. On Windows it detects a
// UNC path but CANNOT see that a mapped drive letter such as Z: points at a
// share, because that needs GetDriveTypeW and therefore a windows-only source
// file this step does not own. On any host where the type cannot be
// determined the guard passes: refusing every path we cannot classify would
// make Anvil unstartable on Windows and macOS, and a guard nobody can get past
// gets deleted. Treat a positive result as reliable and a negative one as
// "not proven local".
func CheckNetworkMount(path string) error {
	return checkNetworkMountWith(path, probeFilesystemType)
}

func checkNetworkMountWith(path string, probe fsTypeProbe) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: no data directory was given", ErrNetworkMount)
	}
	fsType, err := probe(path)
	if err != nil {
		// The host offered a mount table and it could not be read or parsed.
		// That is not "unknown", it is broken, and staying quiet about it is
		// exactly the silence this guard exists to prevent.
		return fmt.Errorf("store: cannot determine the filesystem type of data directory %q: %w", path, err)
	}
	if fsType == "" {
		return nil // undeterminable; see the CheckNetworkMount doc comment
	}
	if !isNetworkFilesystemType(fsType) {
		return nil
	}
	return fmt.Errorf("%w: %q is on a %q filesystem. SQLite's write-ahead log "+
		"does not work over a network filesystem, so leaving it here risks silent "+
		"corruption of the store of record rather than an error you would notice "+
		"(research/07-database-design.md Risk #4). Move the Anvil data directory to "+
		"local storage, or mount local storage at this path",
		ErrNetworkMount, path, fsType)
}

func isNetworkFilesystemType(fsType string) bool {
	fsType = strings.ToLower(strings.TrimSpace(fsType))
	if networkFilesystemTypes[fsType] {
		return true
	}
	if backend, ok := strings.CutPrefix(fsType, "fuse."); ok {
		return networkFUSEBackends[backend]
	}
	return false
}

// probeFilesystemType is the real probe: a UNC check on Windows, then the
// Linux mount table.
func probeFilesystemType(path string) (string, error) {
	if runtime.GOOS == "windows" && isUNCPath(path) {
		return "unc", nil
	}
	return mountTableFilesystemType(path)
}

// isUNCPath reports whether path names a Windows network share directly, as
// \\server\share\... — the one network location Windows exposes without a
// syscall.
func isUNCPath(path string) bool {
	p := strings.ReplaceAll(path, "/", `\`)
	if !strings.HasPrefix(p, `\\`) {
		return false
	}
	if strings.HasPrefix(p, `\\?\`) || strings.HasPrefix(p, `\\.\`) {
		return false // device / extended-length namespace, not a share
	}
	rest := strings.Trim(p[2:], `\`)
	host, share, ok := strings.Cut(rest, `\`)
	return ok && host != "" && strings.TrimLeft(share, `\`) != ""
}

// mountTableFilesystemType returns the type of the most specific mount point
// containing path, or "" if this host publishes no mount table.
func mountTableFilesystemType(path string) (string, error) {
	target, err := resolveForMountLookup(path)
	if err != nil {
		return "", err
	}

	mounts, err := readMountTable()
	if err != nil {
		return "", err
	}
	if len(mounts) == 0 {
		return "", nil
	}

	// Longest matching mount point wins: /mnt/nas is more specific than /, and
	// a data directory under it is on the share, not on the root filesystem.
	sort.SliceStable(mounts, func(i, j int) bool {
		return len(mounts[i].point) > len(mounts[j].point)
	})
	for _, m := range mounts {
		if pathHasPrefix(m.point, target) {
			return m.fsType, nil
		}
	}
	return "", nil
}

// resolveForMountLookup makes path absolute and resolves it against the
// nearest ancestor that actually exists, because the data directory is
// routinely created after this guard runs.
func resolveForMountLookup(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", path, err)
	}
	existing := abs
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return filepath.Clean(abs), nil
		}
		existing = parent
	}
	// A symlink can cross a mount boundary; the mount that matters is the one
	// holding the real directory. Best effort — an unresolvable link is not a
	// reason to refuse startup.
	if resolved, err := filepath.EvalSymlinks(existing); err == nil {
		suffix := strings.TrimPrefix(abs, existing)
		return filepath.Clean(resolved + suffix), nil
	}
	return filepath.Clean(abs), nil
}

type mountEntry struct {
	point  string
	fsType string
}

// readMountTable parses /proc/self/mountinfo, falling back to /proc/mounts.
//
// mountinfo is preferred because its mount-point field is unambiguous even
// when a filesystem is bind-mounted or has a non-root subtree mounted, both of
// which /proc/mounts renders confusingly.
func readMountTable() ([]mountEntry, error) {
	entries, err := parseMountFile("/proc/self/mountinfo", parseMountinfoLine)
	if err == nil {
		return entries, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	entries, err = parseMountFile("/proc/mounts", parseProcMountsLine)
	if err == nil {
		return entries, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // no mount table on this host: undeterminable, not an error
	}
	return nil, err
}

func parseMountFile(name string, parse func(string) (mountEntry, bool)) ([]mountEntry, error) {
	f, err := os.Open(name) //nolint:gosec // fixed, non-user-supplied kernel path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []mountEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if e, ok := parse(scanner.Text()); ok {
			entries = append(entries, e)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return entries, nil
}

// parseMountinfoLine reads one /proc/self/mountinfo record. Layout:
//
//	ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [OPTIONAL...] - FSTYPE SOURCE SUPEROPTS
//
// The optional-fields run is variable length and terminated by a lone "-", so
// the separator has to be located rather than assumed at a fixed index.
func parseMountinfoLine(line string) (mountEntry, bool) {
	fields := strings.Fields(line)
	sep := -1
	for i, f := range fields {
		if f == "-" {
			sep = i
			break
		}
	}
	if sep < 5 || sep+1 >= len(fields) {
		return mountEntry{}, false
	}
	return mountEntry{
		point:  unescapeMountField(fields[4]),
		fsType: unescapeMountField(fields[sep+1]),
	}, true
}

// parseProcMountsLine reads one /proc/mounts record:
//
//	SOURCE MOUNTPOINT FSTYPE OPTIONS DUMP PASS
func parseProcMountsLine(line string) (mountEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return mountEntry{}, false
	}
	return mountEntry{
		point:  unescapeMountField(fields[1]),
		fsType: unescapeMountField(fields[2]),
	}, true
}

// unescapeMountField undoes the kernel's octal escaping of space (\040), tab
// (\011), newline (\012) and backslash (\134) in mount paths. Without it a
// data directory containing a space silently fails to match its own mount.
func unescapeMountField(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		var v int
		valid := true
		for _, c := range []byte(s[i+1 : i+4]) {
			if c < '0' || c > '7' {
				valid = false
				break
			}
			v = v*8 + int(c-'0')
		}
		if !valid || v > 0xff {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String()
}

// pathHasPrefix reports whether target is mountPoint or lies beneath it,
// comparing whole path elements so that /mnt/nas does not match /mnt/nasty.
func pathHasPrefix(mountPoint, target string) bool {
	mp := filepath.Clean(mountPoint)
	tg := filepath.Clean(target)
	if mp == tg {
		return true
	}
	if !strings.HasSuffix(mp, string(filepath.Separator)) {
		mp += string(filepath.Separator)
	}
	return strings.HasPrefix(tg, mp)
}

// ---------------------------------------------------------------------------
// Guard 2 — FTS5 availability
// ---------------------------------------------------------------------------

// fts5ProbeSeq keeps concurrent or repeated probes on separate table names, so
// one probe can never observe another's leftovers and report a false pass.
var fts5ProbeSeq atomic.Uint64

// CheckFTS5 verifies, by doing it, that this database can create an FTS5
// virtual table, index a row into it, and match that row back.
//
// It is deliberately not a version check, a build-tag check, or a lookup in
// pragma_compile_options: those report intent, and this guard exists to catch
// the case where intent and reality have come apart — a dependency bump that
// drops FTS5, or a driver that accepts the DDL and then indexes nothing. Both
// of those are silent failures at startup and loud, data-losing ones at first
// query against schema.sql's advisory_fts table.
//
// The probe table is created in the `temp` schema on a single pinned
// connection and dropped again, so it never touches the store file.
func CheckFTS5(db *sql.DB) error {
	return CheckFTS5Context(context.Background(), db)
}

// CheckFTS5Context is CheckFTS5 with a caller-supplied context. The
// context-free signature is the one plan/40-record-and-storage.md's R.5 packet
// specifies, so it stays; this is the form startup code with a deadline wants.
func CheckFTS5Context(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("%w: no database handle was given to the guard", ErrNoFTS5)
	}

	// One pinned connection: `temp` objects are per connection, so creating on
	// one and querying on another would test nothing and leak a table.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: FTS5 guard could not acquire a connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	table := fmt.Sprintf("anvil_fts5_probe_%d", fts5ProbeSeq.Add(1))
	drop := "DROP TABLE IF EXISTS temp." + table
	_, _ = conn.ExecContext(ctx, drop)
	defer func() { _, _ = conn.ExecContext(ctx, drop) }()

	const remedy = "Anvil's store needs FTS5 for schema.sql's advisory_fts table. " +
		"plan/00-SPINE.md S12 pins modernc.org/sqlite precisely because it bundles " +
		"FTS5; if this fails, the SQLite build behind this binary changed and the " +
		"store cannot be opened safely"

	if _, err := conn.ExecContext(ctx, "CREATE VIRTUAL TABLE temp."+table+" USING fts5(body)"); err != nil {
		return fmt.Errorf("%w: CREATE VIRTUAL TABLE ... USING fts5 was rejected: %v. %s", ErrNoFTS5, err, remedy)
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO temp."+table+"(body) VALUES ('anvil fts5 startup probe')"); err != nil {
		return fmt.Errorf("%w: the FTS5 table was created but would not accept a row: %v. %s", ErrNoFTS5, err, remedy)
	}

	var matched int
	query := "SELECT count(*) FROM temp." + table + " WHERE " + table + " MATCH 'startup'"
	if err := conn.QueryRowContext(ctx, query).Scan(&matched); err != nil {
		return fmt.Errorf("%w: the FTS5 table was created and written but MATCH failed: %v. %s", ErrNoFTS5, err, remedy)
	}
	if matched != 1 {
		return fmt.Errorf("%w: MATCH 'startup' returned %d rows, want exactly 1 — this SQLite build "+
			"accepts FTS5 syntax without indexing anything, which is the silent-failure case the guard "+
			"exists to catch. %s", ErrNoFTS5, matched, remedy)
	}
	return nil
}
