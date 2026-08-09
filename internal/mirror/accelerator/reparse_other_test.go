//go:build !windows

package accelerator

import (
	"os"
	"testing"
)

// unprivilegedLinkKind is the kind of directory link this platform lets ANY
// process create, with no privilege and no prompt.
//
// Unix has one such thing and it is the symbolic link. There is no junction
// here; the Windows/non-Windows split in this file is about which primitive the
// PLATFORM offers, not about which case is worth testing, and both sides run
// the same tests over the same guard.
const unprivilegedLinkKind = "symlink"

// mustLinkUnprivileged points link at target, and FAILS if it cannot. It never
// skips.
//
// os.Symlink needs no privilege on Unix, so a failure here is a real failure —
// a full disk, a read-only fixture, a filesystem that does not carry symlinks —
// and every one of those is something to see rather than something to pass
// over with a green tick.
func mustLinkUnprivileged(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("this host could not create a symlink %s -> %s: %v.\n"+
			"An unprivileged symlink into the share-alike quarantine is the bypass under "+
			"test; if it cannot be built here, the guard has gone unexamined rather than "+
			"been proven.", link, target, err)
	}
	return unprivilegedLinkKind
}
