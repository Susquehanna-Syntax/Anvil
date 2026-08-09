package accelerator

// Reparse-point resolution for the write-path guard.
//
// # WHY THIS FILE EXISTS RATHER THAN A CALL TO filepath.EvalSymlinks
//
// The guard's whole job is to prove that the bytes this package downloads
// cannot land in mirror/tier2, the share-alike quarantine. It does that by
// comparing PATHS. A path comparison is only a filesystem statement if the path
// being compared is the one the filesystem will actually open, so the guard has
// to resolve indirection before it compares.
//
// filepath.EvalSymlinks does not resolve all of the indirection Windows offers.
// Windows has two kinds of directory reparse point:
//
//	SYMLINK (mklink /D)   — os.Lstat reports os.ModeSymlink.
//	                        Creating one needs SeCreateSymbolicLinkPrivilege:
//	                        an administrator, or Developer Mode.
//	JUNCTION (mklink /J)  — os.Lstat reports os.ModeIrregular, NOT ModeSymlink.
//	                        CREATING ONE NEEDS NO PRIVILEGE AT ALL. Any user,
//	                        any shell, no prompt.
//
// filepath.EvalSymlinks keys off os.ModeSymlink, so it walks straight through a
// junction and returns the path AS WRITTEN, with a nil error. Verified on
// go1.26.5 windows/amd64: a junction named .cache pointing at mirror/tier2
// resolved to itself, so both halves of guardCacheRoot were handed a path that
// looked like an ordinary cache root, the guard passed, and WarmStartWith wrote
// accelerator-manifest.json and trivy-db.tar.gz INTO THE QUARANTINE and returned
// nil. That is blocker A-1.
//
// The unprivileged kind is the one that was not resolved. That inverts the usual
// severity argument — this is not an attack that needs an administrator, it is
// the one an ordinary user, or a careless `mklink /J` in a build script, can set
// up by accident.
//
// So this file resolves BOTH kinds, by mode and by os.Readlink, which does
// understand IO_REPARSE_TAG_MOUNT_POINT. It is written in portable Go against
// os and path/filepath only — no cgo, no golang.org/x/sys, no syscall, no build
// tags — so on Linux and macOS it behaves exactly as symlink resolution always
// did, and the CI run and the Windows dev host execute the same code on the same
// question. (Only the test that BUILDS a junction is platform-specific, in
// reparse_windows_test.go, and it reaches package syscall rather than adding a
// dependency.)

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxReparseHops bounds how many links one resolution may follow before it is
// declared a loop. A cycle of junctions is trivial to build and would otherwise
// spin forever inside a guard, which turns a security control into a hang.
const maxReparseHops = 64

// resolveReparsePoints returns abs with every reparse point in its existing
// prefix — symlink or junction — followed to its destination.
//
// Components below the deepest existing ancestor are re-appended verbatim,
// because the cache root usually does not exist on a first run and
// filepath.EvalSymlinks fails outright on a path that is not there yet. Those
// components are still guarded as text by the caller; they cannot be resolved
// because there is nothing yet to resolve.
//
// The returned path contains no reparse points in its existing prefix, so it is
// the path the filesystem will actually open — which is the only path worth
// comparing against the quarantine.
func resolveReparsePoints(abs string) (string, error) {
	vol := filepath.VolumeName(abs)
	resolved := vol + string(filepath.Separator)
	queue := pathParts(abs[len(vol):])
	hops := 0

	for len(queue) > 0 {
		comp := queue[0]
		queue = queue[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			// Lexically safe: everything already in `resolved` has been
			// resolved, so its parent is a real parent and not a link's.
			resolved = filepath.Dir(resolved)
			continue
		}

		candidate := filepath.Join(resolved, comp)
		fi, err := os.Lstat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Nothing at or below this component exists, so nothing below
				// can be a link. Re-append the remainder verbatim.
				return filepath.Join(append([]string{candidate}, queue...)...), nil
			}
			return "", err
		}

		target, isLink, err := reparseTarget(candidate, fi)
		if err != nil {
			return "", err
		}
		if !isLink {
			resolved = candidate
			continue
		}

		hops++
		if hops > maxReparseHops {
			return "", fmt.Errorf("more than %d links followed while resolving %q; "+
				"this is a link loop", maxReparseHops, abs)
		}

		// An absolute target restarts resolution at its own root; a relative one
		// continues from the directory holding the link. Either way the target's
		// components go to the FRONT of the queue, so anything the caller asked
		// for below the link is resolved relative to where the link actually
		// points.
		if tvol := filepath.VolumeName(target); tvol != "" || rooted(target) {
			base := tvol
			if base == "" {
				base = filepath.VolumeName(resolved)
			}
			resolved = base + string(filepath.Separator)
			queue = append(pathParts(target[len(tvol):]), queue...)
			continue
		}
		queue = append(pathParts(target), queue...)
	}
	return resolved, nil
}

// reparseTarget reports the destination of a path that is a link, and whether it
// is one at all.
//
// The mode test is deliberately wider than os.ModeSymlink. Go reports a Windows
// junction as os.ModeIrregular, and a guard that only asks about ModeSymlink is
// asking about the kind of link that needs a privilege while ignoring the kind
// that does not.
//
// The two modes are then treated differently on a Readlink failure, because they
// mean different things:
//
//   - ModeSymlink and Readlink fails: something is wrong with a link we KNOW is
//     a link. Refuse, rather than silently treat it as an ordinary directory —
//     "the guard could not tell" must never resolve to "the guard allows it".
//   - ModeIrregular and Readlink fails: it was not a reparse point. Unix sockets,
//     devices and Windows AppExecLink placeholders all land here. Not a link,
//     and nothing to follow.
func reparseTarget(p string, fi os.FileInfo) (string, bool, error) {
	mode := fi.Mode()
	symlink := mode&os.ModeSymlink != 0
	if !symlink && mode&os.ModeIrregular == 0 {
		return "", false, nil
	}
	target, err := os.Readlink(p)
	if err != nil {
		if symlink {
			return "", false, fmt.Errorf("cannot read the link at %q: %w", p, err)
		}
		return "", false, nil
	}
	if strings.TrimSpace(target) == "" {
		if symlink {
			return "", false, fmt.Errorf("the link at %q has an empty target", p)
		}
		return "", false, nil
	}
	return target, true, nil
}

// pathParts splits on BOTH separators. Windows accepts either, so a guard that
// split on one would treat "a/b" as a single component on a host that opens it
// as two.
func pathParts(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
}

// rooted reports whether p begins at a volume root without naming the volume —
// "\mirror\tier2". filepath.IsAbs is false for that spelling on Windows, and
// treating it as relative would resolve it somewhere it does not point.
func rooted(p string) bool {
	return p != "" && (p[0] == '/' || p[0] == '\\')
}
