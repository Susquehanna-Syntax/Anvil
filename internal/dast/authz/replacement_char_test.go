package authz

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// replacementChar is U+FFFD, the REPLACEMENT CHARACTER, encoded as the three
// bytes EF BF BD.
//
// It is written as an ESCAPE and never as a literal, so that this file is not
// itself an instance of the thing it searches for — a scanner that matches its
// own source is a scanner that can only fail — and so that a reader can see
// what is being searched for instead of their editor rendering it as the same
// black diamond it renders every other occurrence as.
const replacementChar = "\uFFFD"

// TestNoReplacementCharactersInTheTree scans the source tree for U+FFFD.
//
// # WHY A UTF-8 VALIDITY SWEEP CANNOT DO THIS, WHICH IS THE WHOLE POINT
//
// A previous round reported "every .go and .md file decodes as valid UTF-8"
// and concluded from it that the tree was clean. That statement was TRUE and
// it was IRRELEVANT: EF BF BD — the encoding of U+FFFD — IS ITSELF VALID
// UTF-8. A validity sweep is structurally incapable of seeing this damage, so
// it returned a green result over four replacement characters sitting in
// production source where em-dashes belonged (phase4_disclosure.go, in the
// GateAudit doc comments). The check was not wrong about its own question; it
// was being used to answer a different one.
//
// So this scans for THE CODEPOINT, in the bytes, and for nothing else. The
// premise is asserted rather than assumed: the planted buffer below is checked
// to be valid UTF-8 AND to contain the character, in the same breath.
//
// # Why U+FFFD in a source file is worth a test at all
//
// Because it is the residue of a lossy decode and it is silent. Some editor or
// pipeline read a byte sequence it could not decode and substituted the
// replacement character; the file still compiles, still passes gofmt, still
// round-trips through every tool in this repository, and the original
// character is gone. In a comment it costs legibility. In a string literal
// that reaches an audit row or a refusal message it costs the exact text
// somebody will grep for later. There is no case in which one belongs in this
// tree on purpose, so there is no allowlist.
//
// # WHY THE FILE SET COMES FROM git ls-files AND NOT FROM A LIST OF DIRECTORIES
//
// Because the first version of this test listed four directories — internal/,
// .github/, cmd/ and test/ — and four directories is a set somebody has to
// remember to extend. Measured by the round-4 verifier against that version: a
// U+FFFD planted at the end of README.md and again at the end of
// THIRD-PARTY-LICENSES.md — both TRACKED, both SHIPPED — and the guard
// reported the tree clean. It walked 151 files of the repository's 236 tracked
// ones. That is the same shape as the defect this test was written to close: a
// check that cannot see the damage is not a check.
//
// So the set is now every file git tracks, with no extension filter either. A
// new top-level file, a new directory, a new .py or .toml or .golden is
// covered because it is TRACKED, not because somebody remembered to add it
// here. TestTheScanSeesAPlantedCharacterAnywhereGitTracksIt is the guard on
// that, and it plants the verifier's two characters.
func TestNoReplacementCharactersInTheTree(t *testing.T) {
	// THE DETECTOR'S OWN CONTROL, first, so that a green result below cannot
	// mean "the matcher never matches".
	planted := []byte("an em dash was here: " + replacementChar + " and text after it")
	if !bytes.Contains(planted, []byte(replacementChar)) {
		t.Fatal("the detector does not find a planted U+FFFD, so the scan below proves " +
			"nothing")
	}
	if !utf8.Valid(planted) {
		t.Fatal("the planted buffer does not decode as valid UTF-8. If this ever fails " +
			"then the premise of this test is wrong and a validity sweep WOULD have " +
			"caught the damage")
	}

	root := repoRoot(t)
	files := trackedFiles(t, root)
	hits, cov, err := scanTrackedFiles(root, files)
	if err != nil {
		t.Fatalf("scanning the tracked tree under %s: %v", root, err)
	}
	if err := cov.verify(); err != nil {
		t.Fatalf("the scan cannot be trusted, so its clean result is not accepted: %v", err)
	}
	t.Logf("scanned %d of %d tracked files under %s; %d of them outside internal/, "+
		".github/, cmd/ and test/", cov.scanned, cov.total, root, cov.outsideTheOldWalk)

	for _, h := range hits {
		t.Errorf("%s:%d holds U+FFFD (EF BF BD) at byte offset %d. That is the "+
			"REPLACEMENT CHARACTER, the residue of a lossy decode — most often an "+
			"em-dash, a quotation mark or a non-breaking space some editor could "+
			"not decode. It is VALID UTF-8, so a UTF-8 validity sweep reports this "+
			"file clean; that is precisely why this test scans for the codepoint. "+
			"Put back the character that was lost.",
			h.rel, h.line, h.offset)
	}
}

// TestTheScanSeesAPlantedCharacterAnywhereGitTracksIt is the round-4
// verifier's attack, run as a test.
//
// The verifier planted a U+FFFD at the end of README.md and at the end of
// THIRD-PARTY-LICENSES.md — both tracked, both shipped, both outside every
// directory the previous version of this scan walked — and the guard reported
// the tree clean. Here the same two files, in the same two positions, in a
// throwaway git repository so that nothing in the real working tree is
// touched, and the scan is required to report BOTH.
//
// The synthetic repository is built large enough to clear the anti-vacuity
// floor and to contain the known file, so the whole guard runs — floor,
// witnesses and relation — rather than just the matcher.
func TestTheScanSeesAPlantedCharacterAnywhereGitTracksIt(t *testing.T) {
	root := syntheticRepo(t)

	files := trackedFiles(t, root)
	hits, cov, err := scanTrackedFiles(root, files)
	if err != nil {
		t.Fatalf("scanning the synthetic repository: %v", err)
	}
	if err := cov.verify(); err != nil {
		t.Fatalf("the synthetic repository does not satisfy the coverage rules, so this "+
			"test would be measuring the fixture rather than the scan: %v", err)
	}

	got := map[string]bool{}
	for _, h := range hits {
		got[h.rel] = true
		for _, prefix := range oldWalkPrefixes {
			if strings.HasPrefix(h.rel, prefix) {
				t.Fatalf("the planted hit %s is inside %s. The fixture is wrong: the "+
					"whole point is that these files are OUTSIDE the directories the "+
					"previous scan walked", h.rel, prefix)
			}
		}
	}
	for _, w := range theTopLevelWitnesses {
		if !got[w] {
			t.Fatalf("a U+FFFD planted at the end of %s was NOT reported. That is the "+
				"exact measurement the round-4 verifier made against the previous "+
				"version of this scan, and it is what this test exists to fail on. "+
				"Reported: %v", w, hits)
		}
	}
	if len(hits) != len(theTopLevelWitnesses) {
		t.Fatalf("%d hits reported for %d planted characters: %v",
			len(hits), len(theTopLevelWitnesses), hits)
	}
}

// TestTheScanRefusesToReportCleanFromABrokenWalk is the anti-vacuity floor and
// the witness rule, each broken on purpose.
//
// A guard that has never failed has not been tested, and verify() is the half
// of this scan that decides whether a clean result MEANS anything. Both of its
// rules are exercised here against coverage that a broken walk would produce.
func TestTheScanRefusesToReportCleanFromABrokenWalk(t *testing.T) {
	full := func() scanCoverage {
		c := scanCoverage{
			total:             300,
			scanned:           300,
			outsideTheOldWalk: 40,
			seen:              map[string]bool{theKnownFile: true},
		}
		for _, w := range theTopLevelWitnesses {
			c.seen[w] = true
		}
		return c
	}
	if err := full().verify(); err != nil {
		t.Fatalf("healthy coverage was rejected, so the failures below prove nothing: %v", err)
	}

	// (1) A walk that returned almost nothing.
	starved := full()
	starved.scanned = minimumTrackedFilesScanned - 1
	err := starved.verify()
	if err == nil {
		t.Fatalf("a scan that read %d files reported itself trustworthy; the floor is %d",
			starved.scanned, minimumTrackedFilesScanned)
	}
	if !strings.Contains(err.Error(), "floor") {
		t.Fatalf("the floor's refusal does not mention the floor: %v", err)
	}

	// (2) A walk that is large but shaped like the old one: it never reached
	// the top-level files. This is the defect itself, and the floor CANNOT see
	// it — 151 files cleared the floor comfortably.
	for _, w := range theTopLevelWitnesses {
		blind := full()
		delete(blind.seen, w)
		blind.outsideTheOldWalk = 0
		err := blind.verify()
		if err == nil {
			t.Fatalf("a scan that never reached %s reported itself trustworthy. That is "+
				"the round-4 finding exactly", w)
		}
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("the refusal does not name the file that was missed (%s): %v", w, err)
		}
	}

	// (3) And the relation on its own: every witness seen, yet nothing else
	// outside the four old directories. That is a set being driven by
	// directories with the witnesses bolted on.
	narrow := full()
	narrow.outsideTheOldWalk = 1
	if err := narrow.verify(); err == nil {
		t.Fatal("a scan reaching only one file outside internal/, .github/, cmd/ and " +
			"test/ reported itself trustworthy")
	}
}

// syntheticRepo builds a throwaway git repository that satisfies every rule
// verify() imposes, with a U+FFFD planted at the END of each top-level
// witness — the verifier's exact placement.
//
// It exists so that the attack is run against real `git ls-files` output and a
// real filesystem WITHOUT modifying the working tree the developer is sitting
// in. A test that plants characters in the actual README and restores them
// afterwards is a test that leaves the tree dirty the one time it panics.
func syntheticRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
	}

	// The known file, so the scan's "did you reach the known case" rule is
	// satisfied by the fixture rather than waived.
	write(theKnownFile, "package authz\n\n// clean, an em dash — right here\n")

	// Enough tracked files to clear the floor, all clean.
	for i := 0; i < minimumTrackedFilesScanned+20; i++ {
		write(fmt.Sprintf("internal/filler/f%03d.go", i), "package filler\n")
	}
	// And enough OUTSIDE the four old directories to satisfy the relation.
	for i := 0; i < 5; i++ {
		write(fmt.Sprintf("docs/note%d.md", i), "clean\n")
	}

	// THE ATTACK: the character at the very end of each witness, which is
	// where the verifier put it.
	for _, w := range theTopLevelWitnesses {
		write(w, "# "+w+"\n\nsome shipped prose\n"+replacementChar)
	}

	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s in the synthetic repository: %v\n%s",
				strings.Join(args, " "), err, out)
		}
	}
	run("init")
	// -A rather than a path list: the fixture must be tracked the same way the
	// real repository is, or `git ls-files` is answering a different question.
	run("add", "-A")
	return root
}

// replacementHit is one occurrence, located well enough to fix.
type replacementHit struct {
	rel    string
	line   int
	offset int
}

// theKnownFile is the file the four original replacement characters were in.
// The scan is required to reach it, so that a clean result means the scan ran.
const theKnownFile = "internal/dast/authz/phase4_disclosure.go"

// theTopLevelWitnesses are tracked, shipped files that sit OUTSIDE every
// directory the previous version of this scan walked.
//
// They are named individually and by identity, not counted, because the defect
// being guarded is precisely "the set of directories drifted away from the set
// of files". A count cannot see that; these two can. They are the exact files
// the round-4 verifier planted a U+FFFD in to show the old scan reporting the
// tree clean.
var theTopLevelWitnesses = []string{"README.md", "THIRD-PARTY-LICENSES.md"}

// oldWalkPrefixes are the four directories the previous version of this scan
// walked. Nothing is excluded by them; they are here only so the scan can
// count how far past them it reached.
var oldWalkPrefixes = []string{"internal/", ".github/", "cmd/", "test/"}

// minimumTrackedFilesScanned is the anti-vacuity floor.
//
// The repository tracks 236 files as this is written (measured:
// `git ls-files | wc -l` on branch feat/phase4-dast-kernel). The floor is far
// below that and far above anything a broken walk produces, so it fires on
// "the walk returned almost nothing" without firing on ordinary churn.
//
// It is a floor and it is NOT the whole guard. The defect it was added
// alongside cleared a floor of this size with room to spare: the old walk read
// 151 files and still could not see README.md. The witnesses are what catch a
// scan that is large and wrongly shaped.
const minimumTrackedFilesScanned = 150

// scanCoverage is what the scan touched, kept so that verify() can decide
// whether a clean result means anything.
type scanCoverage struct {
	total             int
	scanned           int
	missing           int
	outsideTheOldWalk int
	seen              map[string]bool
}

// verify reports why this scan's result cannot be trusted, or nil.
//
// It returns an ERROR rather than calling t.Fatal so that its own rules can be
// broken and observed in a test — see
// TestTheScanRefusesToReportCleanFromABrokenWalk. A guard whose failure path
// cannot be reached from a test is a guard nobody has watched fail.
func (c scanCoverage) verify() error {
	if c.scanned < minimumTrackedFilesScanned {
		return fmt.Errorf("the scan read %d of %d tracked files (%d listed but absent "+
			"from disk); the floor is %d. That is too few for this repository, so a "+
			"clean result would mean nothing",
			c.scanned, c.total, c.missing, minimumTrackedFilesScanned)
	}
	if !c.seen[theKnownFile] {
		return fmt.Errorf("the scan did not reach %s, which is the file the four known "+
			"replacement characters were in. A survey that cannot reach the known case "+
			"is not a survey", theKnownFile)
	}
	// PIN THE RELATION, NOT ONLY THE VALUES. A scan that quietly reverts to
	// walking internal/, .github/, cmd/ and test/ clears the floor and reaches
	// the known file. It cannot clear these two.
	for _, w := range theTopLevelWitnesses {
		if !c.seen[w] {
			return fmt.Errorf("the scan did not reach the tracked, shipped file %s. It "+
				"sits outside internal/, .github/, cmd/ and test/, which is exactly "+
				"where the previous version of this scan could not see — a U+FFFD "+
				"planted there was reported as a clean tree", w)
		}
	}
	if c.outsideTheOldWalk < len(theTopLevelWitnesses) {
		return fmt.Errorf("only %d scanned files sit outside internal/, .github/, cmd/ "+
			"and test/. The file set is being driven by directories again",
			c.outsideTheOldWalk)
	}
	return nil
}

// scanTrackedFiles reads every path in files, relative to root, and returns
// every occurrence of U+FFFD alongside what it managed to cover.
//
// There is NO EXTENSION FILTER. Every one of the 236 files this repository
// tracks is text — measured: no tracked file contains a NUL byte — so
// filtering by extension could only remove coverage, and an extension list is
// one more list somebody has to remember to extend.
func scanTrackedFiles(root string, files []string) ([]replacementHit, scanCoverage, error) {
	cov := scanCoverage{total: len(files), seen: make(map[string]bool, len(files))}
	var hits []replacementHit

	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Tracked but not on disk: a staged deletion, or a sparse
				// checkout. Counted, not ignored — the floor is what fires if
				// this is happening at any scale.
				cov.missing++
				continue
			}
			return nil, cov, fmt.Errorf("reading tracked file %s: %w", rel, err)
		}
		cov.scanned++
		cov.seen[rel] = true

		inOldWalk := false
		for _, prefix := range oldWalkPrefixes {
			if strings.HasPrefix(rel, prefix) {
				inOldWalk = true
				break
			}
		}
		if !inOldWalk {
			cov.outsideTheOldWalk++
		}

		if i := bytes.Index(raw, []byte(replacementChar)); i >= 0 {
			hits = append(hits, replacementHit{
				rel:    rel,
				line:   1 + bytes.Count(raw[:i], []byte("\n")),
				offset: i,
			})
		}
	}
	return hits, cov, nil
}

// trackedFiles returns every path `git ls-files` reports, relative to root and
// slash-separated.
//
// It FAILS rather than falling back to a directory walk when git cannot
// answer. A fallback would be a different, weaker check wearing this one's
// name, and the failure it would hide — "this scan no longer knows what the
// repository ships" — is the exact failure this test exists to prevent. What
// settles a failure here is running the suite inside a git checkout with git
// on PATH, which is what CI does and what every development checkout is.
//
// -z is not decoration: it removes the quoting `git ls-files` applies to paths
// with unusual bytes, so a file whose name needs quoting is scanned rather
// than silently looked for under a name that does not exist.
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		detail := ""
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			detail = ": " + strings.TrimSpace(string(ee.Stderr))
		}
		t.Fatalf("`git ls-files` failed in %s, so this scan cannot learn which files the "+
			"repository ships and refuses to guess: %v%s", root, err, detail)
	}
	var files []string
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel != "" {
			files = append(files, rel)
		}
	}
	if len(files) == 0 {
		t.Fatalf("`git ls-files` listed no files in %s", root)
	}
	return files
}

// repoRoot walks up from the test's working directory until it finds go.mod.
//
// It FAILS rather than defaulting to anything: a guard that silently scans the
// wrong directory reports a clean tree it never looked at.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving the working directory: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.mod found walking up from the test's working directory, so this "+
		"scan cannot locate the repository root and refuses to scan an arbitrary "+
		"directory instead. Stopped at %s", dir)
	return ""
}
