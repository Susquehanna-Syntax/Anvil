package accelerator

// Tests for blocker A-1: a Windows directory junction defeated the quarantine
// path check, and the one test that would have caught it SKIPPED on the host
// where it mattered.
//
// Two things are established here, and they are different things:
//
//  1. The guard refuses a cache root that merely POINTS into the share-alike
//     quarantine, whichever link primitive the platform offers — and on Windows
//     it is checked with the UNPRIVILEGED primitive specifically, because that
//     is the one an ordinary process can build.
//  2. The check is made AT WRITE TIME, not only at configure time. A directory
//     can be swapped for a link between the two, and a check that only ever ran
//     at the earlier moment is a statement about the past.
//
// Nothing in this file skips. mustLinkUnprivileged fails instead, on every
// platform, for the reason TestNoTestInThisPackageSkips states at the bottom.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// quarantineSpellings are the ways a link can name the share-alike quarantine.
// They are the spellings the guard folds: a subdirectory of it, the tier root
// itself, a case variant, and a Win32 trailing dot.
var quarantineSpellings = map[string]string{
	"direct":       filepath.Join("mirror", "tier2", "ubuntu"),
	"tier root":    filepath.Join("mirror", "tier2"),
	"case varied":  filepath.Join("MIRROR", "Tier2", "ubuntu"),
	"trailing dot": filepath.Join("mirror", "tier2."),
}

// linkedCacheRoot builds a tree with a quarantine in it and a cache root that
// is a LINK into that quarantine, and returns both paths.
func linkedCacheRoot(t *testing.T, target string) (cacheRoot, quarantine string) {
	t.Helper()
	root := t.TempDir()
	quarantine = filepath.Join(root, target)
	if err := os.MkdirAll(quarantine, 0o755); err != nil {
		// Not a skip: this is the test's OWN fixture, and a fixture that
		// cannot be built is a failure to look at, not a case to pass over.
		t.Fatalf("creating the quarantine fixture %s: %v", target, err)
	}
	linkParent := filepath.Join(root, "internal", "mirror", "accelerator")
	if err := os.MkdirAll(linkParent, 0o755); err != nil {
		t.Fatal(err)
	}
	cacheRoot = filepath.Join(linkParent, ".cache")
	mustLinkUnprivileged(t, quarantine, cacheRoot)
	return cacheRoot, quarantine
}

// TestAnUnprivilegedLinkedCacheRootIntoTheQuarantineIsRefused is A-1 at the
// guard.
//
// It differs from the symlink test beside it in one deliberate way: on Windows
// it forces the JUNCTION, rather than preferring a symlink and falling back.
// A symlink needs SeCreateSymbolicLinkPrivilege and a junction needs nothing,
// so on a developer-mode host the fallback path never runs — and the primitive
// that never ran is the one that walked through the quarantine.
func TestAnUnprivilegedLinkedCacheRootIntoTheQuarantineIsRefused(t *testing.T) {
	for name, target := range quarantineSpellings {
		t.Run(name, func(t *testing.T) {
			cacheRoot, _ := linkedCacheRoot(t, target)
			if _, err := guardCacheRoot(cacheRoot); !errors.Is(err, ErrLicenceTierWrite) {
				t.Fatalf("a .cache %s into %s was accepted: %v", unprivilegedLinkKind, target, err)
			}
		})
	}
}

// TestALinkedANCESTOROfTheCacheRootIsRefused covers the case the leaf test does
// not: the cache root itself is an ordinary directory, and something ABOVE it
// is the link.
//
// This is the shape a relocation script produces by accident — junction the
// tooling directory somewhere else and leave the leaf alone — so it is the one
// most likely to happen without anybody deciding to attack anything.
func TestALinkedANCESTOROfTheCacheRootIsRefused(t *testing.T) {
	root := t.TempDir()
	quarantine := filepath.Join(root, "mirror", "tier2")
	if err := os.MkdirAll(quarantine, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "internal", "mirror"), 0o755); err != nil {
		t.Fatal(err)
	}
	// internal/mirror/accelerator is the LINK; .cache below it is a plain name.
	mustLinkUnprivileged(t, quarantine, filepath.Join(root, "internal", "mirror", "accelerator"))

	cacheRoot := filepath.Join(root, "internal", "mirror", "accelerator", ".cache")
	if _, err := guardCacheRoot(cacheRoot); !errors.Is(err, ErrLicenceTierWrite) {
		t.Fatalf("a cache root under a linked ancestor was accepted: %v", err)
	}
}

// TestWarmStartThroughALinkedCacheRootWritesNothingIntoTheQuarantine is the
// same claim end to end, and it is the form the blocker was reported in:
// WarmStartWith returned nil and left accelerator-manifest.json and
// trivy-db.tar.gz inside mirror/tier2.
//
// Three things are asserted, because a refusal that still pulled, or that still
// wrote, would be no refusal at all:
//
//   - the error is ErrLicenceTierWrite, not a generic failure;
//   - the registry was never contacted, so no shared rate-limit budget was
//     spent discovering a configuration defect;
//   - not one file is reachable under the quarantine by any route.
func TestWarmStartThroughALinkedCacheRootWritesNothingIntoTheQuarantine(t *testing.T) {
	for name, target := range quarantineSpellings {
		t.Run(name, func(t *testing.T) {
			cacheRoot, quarantine := linkedCacheRoot(t, target)

			reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
			cfg := trivyOnlyConfig(reg, cacheRoot)

			if err := WarmStartWith(context.Background(), cfg); !errors.Is(err, ErrLicenceTierWrite) {
				t.Fatalf("a warm start through a .cache %s into %s returned %v; want ErrLicenceTierWrite",
					unprivilegedLinkKind, target, err)
			}
			if reg.hitCount() != 0 {
				t.Fatal("a refused cache root still triggered a network pull")
			}
			assertNoFilesUnder(t, quarantine)
		})
	}
}

// TestTheCacheRootIsReVerifiedAtWriteTime is the second half of A-1, and the
// half a fix to the resolver alone would not deliver.
//
// guardCacheRoot runs once, before the network. Then a manifest GET, a blob GET
// and up to a gigabyte of transfer happen. Only after all of that does anything
// get written. Between those two moments an unprivileged process — or a build
// script relocating a cache — can remove the directory and put a junction of the
// same name in its place, and a guard that ran only at the first moment has
// nothing to say about the second.
//
// The control case runs first on purpose. A test that only proves a refusal can
// pass because the write never worked at all.
func TestTheCacheRootIsReVerifiedAtWriteTime(t *testing.T) {
	root := t.TempDir()
	quarantine := filepath.Join(root, "mirror", "tier2", "ubuntu")
	if err := os.MkdirAll(quarantine, 0o755); err != nil {
		t.Fatal(err)
	}
	cacheRoot := filepath.Join(root, "internal", "mirror", "accelerator", ".cache")

	// Configure time: an ordinary, legal, entirely unremarkable cache root.
	guarded, err := guardCacheRoot(cacheRoot)
	if err != nil {
		t.Fatalf("a legitimate cache root was refused: %v", err)
	}

	// Control: the write works when nothing has changed underneath it.
	if err := writeFileAtomic(guarded, ManifestFileName, []byte("{}\n")); err != nil {
		t.Fatalf("writing to a legitimate cache root failed, so the refusal below "+
			"would prove nothing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(guarded, ManifestFileName)); err != nil {
		t.Fatalf("the control write did not land: %v", err)
	}

	// Time passes. The directory is swapped for a link into the quarantine,
	// with no privilege and no prompt.
	if err := os.Remove(filepath.Join(guarded, ManifestFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(guarded); err != nil {
		t.Fatalf("removing the real cache directory: %v", err)
	}
	mustLinkUnprivileged(t, quarantine, guarded)

	// Write time: the SAME root value that was accepted above must now be
	// refused, because what it names has changed.
	err = writeFileAtomic(guarded, ManifestFileName, []byte("{}\n"))
	if !errors.Is(err, ErrLicenceTierWrite) {
		t.Fatalf("a cache root swapped for a %s into the quarantine after the configure-time "+
			"check was still written to: %v", unprivilegedLinkKind, err)
	}
	assertNoFilesUnder(t, quarantine)
}

// TestReparseResolutionFollowsWhatTheFilesystemFollows is the unit-level claim
// underneath all of the above: resolveReparsePoints returns the path the
// operating system will actually open.
func TestReparseResolutionFollowsWhatTheFilesystemFollows(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	mustLinkUnprivileged(t, real, link)

	t.Run("the link itself", func(t *testing.T) {
		got, err := resolveReparsePoints(link)
		if err != nil {
			t.Fatal(err)
		}
		assertSamePath(t, got, real)
	})

	t.Run("a name that does not exist yet below a link", func(t *testing.T) {
		// The cache root does not exist on a first run, so this is the ordinary
		// case and not an edge one. The tail is re-appended to the RESOLVED
		// prefix, which is what makes the guard's comparison a real one.
		got, err := resolveReparsePoints(filepath.Join(link, "a", "b"))
		if err != nil {
			t.Fatal(err)
		}
		assertSamePath(t, got, filepath.Join(real, "a", "b"))
	})

	t.Run("a plain path is returned unchanged", func(t *testing.T) {
		got, err := resolveReparsePoints(real)
		if err != nil {
			t.Fatal(err)
		}
		assertSamePath(t, got, real)
	})
}

// TestALinkLoopIsRefusedRatherThanFollowedForever records that the guard
// terminates. A cycle of links is trivial to create, and a security check that
// hangs has failed open in the only way that matters to whoever is waiting.
func TestALinkLoopIsRefusedRatherThanFollowedForever(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	mustLinkUnprivileged(t, b, a)
	mustLinkUnprivileged(t, a, b)

	if _, err := resolveReparsePoints(filepath.Join(a, ".cache")); err == nil {
		t.Fatal("a link loop resolved without error")
	}
	if _, err := guardCacheRoot(filepath.Join(a, "mirror", "accelerator", ".cache")); !errors.Is(err, ErrBadCacheDir) {
		t.Fatalf("a cache root behind a link loop was not refused as a bad cache dir: %v", err)
	}
}

func assertSamePath(t *testing.T, got, want string) {
	t.Helper()
	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(want)) {
		t.Fatalf("resolved to %q; want %q", got, want)
	}
}

// TestNoTestInThisPackageSkips is the fix for the thing that mattered more than
// A-1 itself.
//
// TestSymlinkedCacheRootIntoTheQuarantineIsRefused reported SKIP four times on
// the Windows dev host and the package still printed
//
//	ok  github.com/Susquehanna-Syntax/Anvil/internal/mirror/accelerator
//
// `ok` is what a reviewer reads. So the one test standing between a junction and
// the share-alike quarantine was absent exactly where the bypass was reachable,
// and its absence was rendered as success. A skip that hides a security control
// is worse than a failure, because a failure is read.
//
// This package therefore has no skips at all, and this test is what keeps it
// that way. The rule is enforced on the SOURCE rather than on a test run,
// because a conditional skip that happens not to fire on the machine running CI
// is precisely the defect being prevented — asking "did anything skip today?"
// would have reported clean on Linux while the Windows host went uncovered.
//
// If a genuine platform limitation ever needs recording, the honest form is a
// test that FAILS with the evidence, or a case that does not exist on that
// platform via a build tag — see reparse_windows_test.go and
// reparse_other_test.go, which express the same case with each platform's own
// unprivileged link primitive and neither of which can silently do nothing.
func TestNoTestInThisPackageSkips(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var found []string
	scanned := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		// Parsed with build tags IGNORED. A skip hidden behind //go:build
		// windows is the exact shape of the defect, so it must be visible from
		// whichever platform runs this test.
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Skip", "Skipf", "SkipNow":
				found = append(found, fset.Position(call.Pos()).String())
			}
			return true
		})
	}

	if scanned == 0 {
		t.Fatal("no _test.go files were scanned; this check has stopped checking anything")
	}
	if len(found) != 0 {
		t.Fatalf("%d skip(s) in this package's tests, at %s.\n"+
			"A skip here reports `ok` for a security control that did not run — which is how "+
			"a Windows directory junction reached the share-alike quarantine. Make the case "+
			"RUN, or make it FAIL with the evidence for why this platform cannot express it.",
			len(found), strings.Join(found, ", "))
	}
}
