package policy

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The fixture repository
// ---------------------------------------------------------------------------
//
// One linear history, built by real git, covering every branch of the walk:
//
//	c1  v1.0.0              root commit -- nothing before it
//	c2  v1.1.0              minor
//	c3  v1.1.1              patch
//	c4  v2.0.0              major
//	c5  nightly-2026-08-09  NOT a semantic version -- must be stepped over
//	c6  v2.1.0              minor, computed across the nightly tag
//	c7  v2.1.1-rc.1         prerelease
//	c8  v2.1.1              patch, computed across its own release candidate
//
// The packet requires v1.0.0 -> v1.1.0 -> v1.1.1 -> v2.0.0; the rest exists
// because those four alone never exercise the two skip rules, and a walk whose
// skips are untested is a walk that will be deleted by the next refactor.

type fixtureStep struct {
	tag  string
	note string
}

var fixtureHistory = []fixtureStep{
	{"v1.0.0", "root"},
	{"v1.1.0", ""},
	{"v1.1.1", ""},
	{"v2.0.0", ""},
	{"nightly-2026-08-09", "not a semantic version"},
	{"v2.1.0", ""},
	{"v2.1.1-rc.1", ""},
	{"v2.1.1", ""},
}

// requireGit skips the test when git is not on PATH. Everything else in this
// file is a real git invocation, so there is nothing to fall back to.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH; O.7's behaviour is defined only in terms of real git")
	}
}

// fixtureEnv is os.Environ() with git's configuration neutralised, so the
// fixture is the same repository on every developer's machine. A global
// commit.gpgsign, a global user.name, or a system-wide template would
// otherwise leak into it. Go's exec deduplicates the environment keeping the
// LAST occurrence, so appending is an override.
func fixtureEnv(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	return append(os.Environ(),
		"HOME="+home,
		"USERPROFILE="+home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, "no-such-gitconfig"),
		"GIT_CONFIG_SYSTEM="+filepath.Join(home, "no-such-gitconfig"),
		"GIT_AUTHOR_NAME=Anvil Fixture",
		"GIT_AUTHOR_EMAIL=fixture@anvil.invalid",
		"GIT_COMMITTER_NAME=Anvil Fixture",
		"GIT_COMMITTER_EMAIL=fixture@anvil.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
		"GIT_TERMINAL_PROMPT=0",
	)
}

func git(t *testing.T, env []string, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (in %s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newFixtureRepo builds the history above and returns its path.
func newFixtureRepo(t *testing.T) string {
	t.Helper()
	requireGit(t)

	env := fixtureEnv(t)
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("creating the fixture directory: %v", err)
	}

	git(t, env, repo, "-c", "init.defaultBranch=main", "init", "--quiet")
	for i, step := range fixtureHistory {
		git(t, env, repo, "commit", "--allow-empty", "--quiet",
			"-m", fmt.Sprintf("commit %d for %s", i+1, step.tag))
		git(t, env, repo, "tag", step.tag)
	}
	return repo
}

// fileURL renders a local path as the file:// URL git needs for a clone that
// honours --depth. `git clone --depth` against a bare path is silently ignored
// ("--depth is ignored in local clones"), which would produce a NON-shallow
// fixture and a test that passes for the wrong reason.
func fileURL(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed // C:/... -> /C:/...
	}
	return "file://" + strings.ReplaceAll(slashed, " ", "%20")
}

// newShallowClone clones the fixture truncated to depth commits, checked out at
// tag.
func newShallowClone(t *testing.T, src, tag string, depth int) string {
	t.Helper()
	env := fixtureEnv(t)
	dst := filepath.Join(t.TempDir(), "shallow")
	git(t, env, "", "clone", "--quiet",
		"--depth", strconv.Itoa(depth), "--branch", tag,
		fileURL(src), dst)
	return dst
}

// ---------------------------------------------------------------------------
// The required scenario: a real tag sequence, every bump classified
// ---------------------------------------------------------------------------

func TestComputeSemverBump_TagSequence(t *testing.T) {
	repo := newFixtureRepo(t)

	cases := []struct {
		tag  string
		want BumpKind
		why  string
	}{
		{"v1.1.0", BumpMinor, "v1.0.0 -> v1.1.0"},
		{"v1.1.1", BumpPatch, "v1.1.0 -> v1.1.1"},
		{"v2.0.0", BumpMajor, "v1.1.1 -> v2.0.0"},
		{"v2.1.0", BumpMinor, "v2.0.0 -> v2.1.0, stepping over the nightly tag"},
		{"v2.1.1-rc.1", BumpPrerelease, "a prerelease tag classifies itself"},
		{"v2.1.1", BumpPatch, "v2.1.0 -> v2.1.1, stepping over its own rc"},
	}

	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			got, err := ComputeSemverBump(repo, tc.tag)
			if err != nil {
				t.Fatalf("ComputeSemverBump(%q) = error %v; want %q (%s)", tc.tag, err, tc.want, tc.why)
			}
			if got != tc.want {
				t.Errorf("ComputeSemverBump(%q) = %q, want %q (%s)", tc.tag, got, tc.want, tc.why)
			}
			if !got.Valid() {
				t.Errorf("ComputeSemverBump(%q) returned %q, which is not in BumpKindValues() = %v",
					tc.tag, got, BumpKindValues())
			}
		})
	}
}

// The first tag in a repository has nothing before it. That must be
// ErrNoPreviousTag and must NOT be ErrShallowCheckout: this repository's
// history is complete, and reporting a misconfigured checkout here would make
// the real sentinel meaningless.
func TestComputeSemverBump_FirstTagHasNoPrevious(t *testing.T) {
	repo := newFixtureRepo(t)

	_, err := ComputeSemverBump(repo, "v1.0.0")
	if !errors.Is(err, ErrNoPreviousTag) {
		t.Fatalf("ComputeSemverBump(v1.0.0) = %v; want ErrNoPreviousTag", err)
	}
	if errors.Is(err, ErrShallowCheckout) {
		t.Errorf("a complete repository's first tag reported ErrShallowCheckout: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The required scenario: a shallow checkout, reported specifically
// ---------------------------------------------------------------------------

func TestComputeSemverBump_ShallowCheckout(t *testing.T) {
	repo := newFixtureRepo(t)

	for _, depth := range []int{1, 3} {
		t.Run(fmt.Sprintf("depth-%d", depth), func(t *testing.T) {
			clone := newShallowClone(t, repo, "v2.1.1", depth)

			// Prove the fixture really is shallow before asserting on it: a
			// clone that quietly ignored --depth would make this test pass
			// while testing nothing.
			env := fixtureEnv(t)
			if got := git(t, env, clone, "rev-parse", "--is-shallow-repository"); got != "true" {
				t.Fatalf("the fixture clone is not shallow (rev-parse said %q); "+
					"--depth was ignored, so this test would prove nothing", got)
			}

			// Document whether `git describe` would have answered anyway. At
			// depth 3 it typically does, which is exactly the hole in the
			// post-hoc heuristic: an implementation that only checked
			// .git/shallow AFTER a describe failure would return a bump here.
			cmd := exec.Command("git", "describe", "--tags", "--abbrev=0", "v2.1.1^")
			cmd.Dir = clone
			cmd.Env = env
			if out, err := cmd.Output(); err == nil {
				t.Logf("at depth %d `git describe` still answers %q; "+
					"the up-front shallow check is what rejects it",
					depth, strings.TrimSpace(string(out)))
			} else {
				t.Logf("at depth %d `git describe` fails outright: %v", depth, err)
			}

			got, err := ComputeSemverBump(clone, "v2.1.1")
			if !errors.Is(err, ErrShallowCheckout) {
				t.Fatalf("ComputeSemverBump on a depth-%d clone = (%q, %v); want ErrShallowCheckout",
					depth, got, err)
			}
			if errors.Is(err, ErrNoPreviousTag) {
				t.Errorf("a shallow checkout was reported as ErrNoPreviousTag, "+
					"which is the confusion the two sentinels exist to prevent: %v", err)
			}
			if got != BumpNone {
				t.Errorf("a rejected computation returned the bump %q; want BumpNone", got)
			}

			// The message must name the fix. This is the whole point of the
			// sentinel: an operator reading a CI log has to learn what to
			// change without reading Anvil's source.
			for _, want := range []string{"fetch-depth: 0", "fetch-tags: true"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("ErrShallowCheckout message does not mention %q; got: %v", want, err)
				}
			}
		})
	}
}

// A shallow checkout is rejected even for a prerelease tag, whose classification
// needs no history at all. The contract is uniform on purpose: "on a shallow
// checkout, ComputeSemverBump never returns a bump" is a rule an operator can
// hold in their head, and a per-tag-kind exception is not.
func TestComputeSemverBump_ShallowRejectedEvenWhenHistoryIsNotNeeded(t *testing.T) {
	repo := newFixtureRepo(t)
	clone := newShallowClone(t, repo, "v2.1.1-rc.1", 1)

	if _, err := ComputeSemverBump(clone, "v2.1.1-rc.1"); !errors.Is(err, ErrShallowCheckout) {
		t.Fatalf("prerelease tag on a shallow clone = %v; want ErrShallowCheckout", err)
	}
}

// ---------------------------------------------------------------------------
// The other error paths, each distinguishable from the others
// ---------------------------------------------------------------------------

func TestComputeSemverBump_ErrorPaths(t *testing.T) {
	repo := newFixtureRepo(t)
	notARepo := t.TempDir()

	cases := []struct {
		name string
		path string
		tag  string
		want error
	}{
		{"not a semantic version", repo, "nightly-2026-08-09", ErrNotSemver},
		{"two-component tag", repo, "v2.1", ErrNotSemver},
		{"leading zero", repo, "v01.2.3", ErrNotSemver},
		{"empty tag", repo, "", ErrNotSemver},
		{"unknown tag", repo, "v9.9.9", ErrTagNotFound},
		{"not a repository", notARepo, "v1.0.0", ErrGit},
		{"no repository path", "", "v1.0.0", ErrGit},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ComputeSemverBump(tc.path, tc.tag)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ComputeSemverBump(%q, %q) = (%q, %v); want %v", tc.path, tc.tag, got, err, tc.want)
			}
			if got != BumpNone {
				t.Errorf("a failed computation returned the bump %q; want BumpNone", got)
			}
			// "git error" with no detail is the failure mode the packet
			// forbids; every error here must say something specific.
			if len(err.Error()) < len(tc.want.Error())+8 {
				t.Errorf("error is not specific enough to act on: %v", err)
			}
		})
	}
}

// A tag that exists but is not a semantic version must fail on the TAG, not on
// the repository: ErrNotSemver is raised before git is consulted at all, so the
// same message appears whether or not the tag was ever pushed.
func TestComputeSemverBump_NonSemverTagFailsBeforeGit(t *testing.T) {
	_, err := ComputeSemverBump(filepath.Join(t.TempDir(), "does-not-exist"), "nightly-2026-08-09")
	if !errors.Is(err, ErrNotSemver) {
		t.Fatalf("got %v; want ErrNotSemver regardless of the repository", err)
	}
}

// ---------------------------------------------------------------------------
// parseSemver
// ---------------------------------------------------------------------------

func TestParseSemver(t *testing.T) {
	ok := []struct {
		tag  string
		want semver
	}{
		{"v1.2.3", semver{major: 1, minor: 2, patch: 3}},
		{"1.2.3", semver{major: 1, minor: 2, patch: 3}},
		{"v0.0.0", semver{}},
		{"v10.20.30", semver{major: 10, minor: 20, patch: 30}},
		{"v1.2.3-rc.1", semver{major: 1, minor: 2, patch: 3, prerelease: "rc.1"}},
		{"v1.2.3-0.build-7", semver{major: 1, minor: 2, patch: 3, prerelease: "0.build-7"}},
		{"v1.2.3+meta", semver{major: 1, minor: 2, patch: 3, build: "meta"}},
		{"v1.2.3-rc.1+meta.001", semver{major: 1, minor: 2, patch: 3, prerelease: "rc.1", build: "meta.001"}},
		{"v18446744073709551615.0.0", semver{major: 18446744073709551615}},
	}
	for _, tc := range ok {
		t.Run(tc.tag, func(t *testing.T) {
			got, err := parseSemver(tc.tag)
			if err != nil {
				t.Fatalf("parseSemver(%q) = %v", tc.tag, err)
			}
			if got != tc.want {
				t.Errorf("parseSemver(%q) = %+v, want %+v", tc.tag, got, tc.want)
			}
		})
	}

	bad := []string{
		"",
		"v",
		"v1",
		"v1.2",
		"v1.2.3.4",
		"V1.2.3",                    // uppercase prefix is a second spelling; rejected
		"release-1.2.3",             // not a version tag at all
		"v01.2.3",                   // leading zero (semver 2.0.0 section 2)
		"v1.02.3",                   //
		"v1.2.03",                   //
		"v1.2.-3",                   //
		"v1.2.3-",                   // empty prerelease
		"v1.2.3+",                   // empty build metadata
		"v1.2.3-rc..1",              // empty identifier
		"v1.2.3-rc.01",              // numeric prerelease identifier with a leading zero
		"v1.2.3-rc$1",               // illegal character
		"v1.2.3+meta$1",             //
		"v1.2.x",                    //
		"v 1.2.3",                   //
		"v18446744073709551616.0.0", // does not fit in uint64
	}
	for _, tag := range bad {
		t.Run("reject "+strconv.Quote(tag), func(t *testing.T) {
			got, err := parseSemver(tag)
			if err == nil {
				t.Fatalf("parseSemver(%q) = %+v, want an error", tag, got)
			}
			if !errors.Is(err, ErrNotSemver) {
				t.Errorf("parseSemver(%q) = %v; want ErrNotSemver", tag, err)
			}
			if !strings.Contains(err.Error(), strconv.Quote(tag)) {
				t.Errorf("the error does not quote the offending tag: %v", err)
			}
		})
	}
}

// Build metadata carries no precedence (semver 2.0.0 section 10), so it must
// not reach the classification. Two tags differing only in build metadata have
// the same core and the walk steps over them.
func TestClassifyCore(t *testing.T) {
	v := func(tag string) semver {
		t.Helper()
		s, err := parseSemver(tag)
		if err != nil {
			t.Fatalf("fixture %q: %v", tag, err)
		}
		return s
	}

	cases := []struct {
		prev, next string
		want       BumpKind
	}{
		{"v1.0.0", "v2.0.0", BumpMajor},
		{"v1.9.9", "v2.0.0", BumpMajor},
		{"v2.0.0", "v1.0.0", BumpMajor}, // most significant CHANGED component; no ordering claim
		{"v1.0.0", "v1.1.0", BumpMinor},
		{"v1.0.9", "v1.1.0", BumpMinor},
		{"v1.1.0", "v1.1.1", BumpPatch},
		{"v1.1.1", "v1.1.1", BumpNone},
		{"v1.1.1+a", "v1.1.1+b", BumpNone},
		{"v1.1.1-rc.1", "v1.1.1", BumpNone}, // same core: keep walking
	}
	for _, tc := range cases {
		t.Run(tc.prev+"->"+tc.next, func(t *testing.T) {
			if got := classifyCore(v(tc.prev), v(tc.next)); got != tc.want {
				t.Errorf("classifyCore(%s, %s) = %q, want %q", tc.prev, tc.next, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The enum this file consumes and must never fork
// ---------------------------------------------------------------------------

// TestSemverFileDeclaresNoSecondBumpVocabulary mirrors
// TestFrozenEnumsAreNotForked for O.7's half of the package.
//
// schemas/policy.schema.json owns the semverBump enum and engine.go is its one
// Go image. A bump literal in semver.go's CODE would be a second definition of
// it -- the defect class plan/IMPLEMENTATION-PLAN.md section 6 closed ten
// instances of. Prose may name the tokens, so this walks the AST rather than
// grepping.
func TestSemverFileDeclaresNoSecondBumpVocabulary(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "semver.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing semver.go: %v", err)
	}

	banned := map[string]bool{}
	for _, kind := range BumpKindValues() {
		banned[string(kind)] = true
	}

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if banned[val] {
			t.Errorf("semver.go line %d contains the bump literal %q; bump tokens are the "+
				"BumpKind constants in engine.go, never a second list here",
				fset.Position(lit.Pos()).Line, val)
		}
		return true
	})
}

// Whatever ComputeSemverBump returns on success is a token the schema declares.
// Asserted over the whole fixture rather than case by case so a future bump
// kind cannot be introduced here without the schema learning about it.
func TestComputeSemverBump_ReturnsOnlySchemaTokens(t *testing.T) {
	repo := newFixtureRepo(t)

	for _, step := range fixtureHistory {
		got, err := ComputeSemverBump(repo, step.tag)
		if err != nil {
			continue // the root tag and the nightly tag have no bump, by design
		}
		if !slices.Contains(BumpKindValues(), got) {
			t.Errorf("ComputeSemverBump(%q) = %q, which is not one of %v",
				step.tag, got, BumpKindValues())
		}
	}
}

// The computed bump is what a policy rule matches against, so the two halves of
// this package have to agree end to end: a rule gated on major must fire for the
// tag ComputeSemverBump calls a major bump, and must not fire for the others.
func TestComputeSemverBump_FeedsTheEngine(t *testing.T) {
	repo := newFixtureRepo(t)

	p := Policy{
		Version: SchemaVersion,
		ScanRules: []ScanRule{{
			Name:            "major-release-full",
			MatchRefs:       []string{"refs/tags/v*"},
			MatchSemverBump: []BumpKind{BumpMajor},
			Settings:        Settings{Depth: DepthFull},
		}},
	}

	fired := map[string]bool{}
	for _, step := range fixtureHistory {
		bump, err := ComputeSemverBump(repo, step.tag)
		if err != nil && !errors.Is(err, ErrNoPreviousTag) && !errors.Is(err, ErrNotSemver) {
			t.Fatalf("ComputeSemverBump(%q): %v", step.tag, err)
		}
		res, err := Evaluate(p, TriggerContext{
			Event:      "push",
			Ref:        "refs/tags/" + step.tag,
			SemverBump: bump,
		})
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", step.tag, err)
		}
		fired[step.tag] = len(res.Matched) == 1
	}

	for _, step := range fixtureHistory {
		want := step.tag == "v2.0.0"
		if fired[step.tag] != want {
			t.Errorf("the major-gated rule fired=%v for %q; want %v", fired[step.tag], step.tag, want)
		}
	}
}
