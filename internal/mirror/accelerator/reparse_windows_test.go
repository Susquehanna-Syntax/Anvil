//go:build windows

package accelerator

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// unprivilegedLinkKind is the kind of directory link this platform lets ANY
// process create, with no privilege and no prompt.
//
// On Windows that is the junction, and naming it here is the point of this
// file. The pre-existing helper prefers a symlink and falls back to a junction,
// so on a Windows host with Developer Mode enabled the junction is never
// exercised — and the junction is the case that broke, because it is the one
// that needs no privilege. A guard whose only Windows coverage depends on the
// host having Developer Mode is a guard covered by accident.
const unprivilegedLinkKind = "junction"

// mustLinkUnprivileged points link at target using unprivilegedLinkKind, and
// FAILS if it cannot. It never skips.
//
// The claim under test is "an unprivileged process can aim the cache root at
// the share-alike quarantine". If this host cannot create the link, that claim
// has not been refuted — it has gone unexamined, and the difference between
// those two is the whole reason A-1 survived review.
func mustLinkUnprivileged(t *testing.T, target, link string) string {
	t.Helper()
	if err := createDirectoryJunction(link, target); err != nil {
		t.Fatalf("this Windows host could not create a directory junction %s -> %s: %v.\n"+
			"A junction needs no privilege, so this is not a host limitation to skip past: "+
			"either the guard is being left unchecked on the platform whose bypass shipped, "+
			"or something about this host must be written down with evidence.", link, target, err)
	}
	return unprivilegedLinkKind
}

// Windows reparse-point constants. They are spelled out here because package
// syscall does not export them and this repository adds no dependency —
// golang.org/x/sys included — to reach four integers.
const (
	fsctlSetReparsePoint     = 0x000900A4
	ioReparseTagMountPoint   = 0xA0000003
	fileFlagOpenReparsePoint = 0x00200000
	fileFlagBackupSemantics  = 0x02000000
)

// createDirectoryJunction creates link as a directory junction pointing at
// target, in pure Go.
//
// It does NOT shell out to `mklink /J`. mklink is a cmd.exe builtin, so
// exercising the guard through it makes a security test depend on a shell being
// present and on cmd's own path parsing. Setting the reparse point directly is
// what mklink itself does: create an empty directory, then FSCTL_SET_REPARSE_
// POINT a REPARSE_DATA_BUFFER carrying IO_REPARSE_TAG_MOUNT_POINT onto it. No
// privilege is required for either step, which is exactly the property that
// makes the junction worth guarding against.
//
// The buffer is:
//
//	uint32 ReparseTag
//	uint16 ReparseDataLength   // bytes after this header's 8
//	uint16 Reserved
//	uint16 SubstituteNameOffset, SubstituteNameLength
//	uint16 PrintNameOffset,      PrintNameLength
//	[]uint16 PathBuffer          // substitute name, then print name
//
// Lengths exclude the terminating NUL of each name; the NULs are still written,
// because the object manager expects them.
func createDirectoryJunction(link, target string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if err := os.Mkdir(link, 0o755); err != nil {
		return err
	}
	// \??\ is the NT object-manager prefix the substitute name must carry; the
	// print name is the Win32 path a user sees in `dir`.
	substitute, err := syscall.UTF16FromString(`\??\` + abs)
	if err != nil {
		return err
	}
	printName, err := syscall.UTF16FromString(abs)
	if err != nil {
		return err
	}

	paths := make([]byte, 0, 2*(len(substitute)+len(printName)))
	for _, u := range substitute {
		paths = binary.LittleEndian.AppendUint16(paths, u)
	}
	for _, u := range printName {
		paths = binary.LittleEndian.AppendUint16(paths, u)
	}

	const headerBytes, nameFieldBytes = 8, 8
	buf := make([]byte, headerBytes+nameFieldBytes+len(paths))
	binary.LittleEndian.PutUint32(buf[0:], ioReparseTagMountPoint)
	binary.LittleEndian.PutUint16(buf[4:], uint16(nameFieldBytes+len(paths)))
	binary.LittleEndian.PutUint16(buf[6:], 0)
	binary.LittleEndian.PutUint16(buf[8:], 0)
	binary.LittleEndian.PutUint16(buf[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(buf[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(buf[14:], uint16(2*(len(printName)-1)))
	copy(buf[headerBytes+nameFieldBytes:], paths)

	name, err := syscall.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	// FILE_FLAG_BACKUP_SEMANTICS is what lets CreateFile open a DIRECTORY at
	// all; FILE_FLAG_OPEN_REPARSE_POINT opens the link itself rather than
	// following it.
	h, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING,
		fileFlagBackupSemantics|fileFlagOpenReparsePoint, 0)
	if err != nil {
		return fmt.Errorf("opening %s to set a reparse point: %w", link, err)
	}
	defer func() { _ = syscall.CloseHandle(h) }()

	var returned uint32
	if err := syscall.DeviceIoControl(h, fsctlSetReparsePoint,
		&buf[0], uint32(len(buf)), nil, 0, &returned, nil); err != nil {
		return fmt.Errorf("FSCTL_SET_REPARSE_POINT on %s: %w", link, err)
	}
	return nil
}
