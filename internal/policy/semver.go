// semver.go is step O.7: computing the semantic-version bump that a git tag
// represents, so that a policy rule's `matchSemverBump` key has something
// TRUSTWORTHY to match against.
//
// ---------------------------------------------------------------------------
// WHY THIS IS COMPUTED AND NOT READ
// ---------------------------------------------------------------------------
//
// research/09-orchestration-and-github-actions.md Recommendation 2:
//
//	"`matchSemverBump` must be computed by Anvil, not read from the event:
//	 GitHub's payload has no 'previous tag'. Anvil derives it with
//	 `git describe --tags --abbrev=0 <tag>^` and therefore the Action must set
//	 `actions/checkout` `fetch-depth: 0` and `fetch-tags: true`. This is a real
//	 operational footgun worth documenting loudly."
//
// So there is no field to read. A `push` event on `refs/tags/v2.0.0` says the
// tag exists; it does not say what came before it, and "what came before it" is
// the entire content of a bump kind. Nothing in this file consults an event
// payload, and nothing in it accepts a caller-supplied bump.
//
// ---------------------------------------------------------------------------
// THE FOOTGUN, AND WHY THIS FILE IS STRICTER THAN THE HEURISTIC IT WAS GIVEN
// ---------------------------------------------------------------------------
//
// O.7's packet suggests detecting the shallow-checkout footgun AFTER the fact:
// treat a `git describe` failure as ErrShallowCheckout when `.git/shallow`
// exists. That heuristic has a hole, and the hole is the dangerous direction.
//
// A shallow checkout does not necessarily make `git describe` FAIL. `--depth 3`
// on the fixture in semver_test.go still reaches `v1.1.1`, so a post-hoc check
// would answer "major" for `v2.0.0` and never fire the sentinel. The next
// release, cut after four quiet commits, would fall off the end of the same
// depth-3 window and answer "no previous tag" -- or, worse, find an older tag
// and answer "minor" for a major release. The depth of the checkout would be
// silently deciding whether a major release gets its full SAST+DAST scan.
//
// Truncated history can only ever REMOVE candidate tags, never invent a nearer
// one, so a shallow answer is either right or too old -- and "too old" is
// indistinguishable from right at the call site. This file therefore refuses to
// answer at all on a shallow checkout: ComputeSemverBump checks shallowness
// FIRST, before it looks at tags, and returns ErrShallowCheckout unconditionally.
// A loud, deterministic error on every shallow run is the behaviour that gets
// `fetch-depth: 0` added to the workflow; a plausible-looking answer is not.
//
// ---------------------------------------------------------------------------
// SCOPE: THIS IS SEMVER, AND SEMVER ONLY
// ---------------------------------------------------------------------------
//
// parseSemver implements https://semver.org 2.0.0 and NOTHING ELSE. It is
// deliberately unexported, because the one thing that must not happen to it is
// being borrowed as a general version comparator.
//
// It is NOT a Debian version comparator (epochs, `~`, and the alternating
// digit/non-digit ordering of `deb-version(7)` are a different algorithm and a
// different order). It is NOT an RPM comparator (`rpmvercmp`, epoch/version/
// release triples, `tilde` and `caret` markers). It is NOT a Maven version
// comparator or range parser (`[1.0,2.0)`, qualifier ordering, `-SNAPSHOT`).
// It is NOT NuGet, Python PEP 440, or Go's `+incompatible`. Using this code to
// decide whether a package version falls inside a CVE's affected range would
// produce silently wrong matches, which is the worst failure mode a vulnerability
// scanner has. Those ecosystems need their own comparators, owned and tested
// separately, and this file does not provide them.
//
// What this file matches is a GIT TAG in a repository Anvil is scanning, against
// the semver vocabulary the policy schema already froze. That is the whole scope.

package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrShallowCheckout reports that the repository's history is truncated,
	// so no statement about the previous tag can be trusted. It is the
	// sentinel for the documented operational footgun and it is returned
	// whenever the repository is shallow -- including when `git describe`
	// would have produced a plausible answer. See this file's header for why
	// answering anyway is the unsafe direction.
	//
	// The fix is always the same and the message says it: the Action must
	// check out with `fetch-depth: 0` and `fetch-tags: true`.
	ErrShallowCheckout = errors.New("policy: shallow checkout: cannot compute a semver bump")

	// ErrNoPreviousTag reports that the history is complete but carries no
	// earlier version tag to compare against -- the ordinary case for a
	// repository's first release. It is a normal outcome, not a failure, and
	// the caller decides what an unclassifiable tag means. It is DISTINCT
	// from ErrShallowCheckout on purpose: "there is nothing before this tag"
	// and "we cannot see what is before this tag" call for opposite
	// responses, and collapsing them is how a misconfigured checkout gets
	// mistaken for a first release forever.
	ErrNoPreviousTag = errors.New("policy: no previous version tag")

	// ErrNotSemver reports a tag that is not a semantic version. The policy
	// schema's `matchSemverBump` vocabulary is semver's, so a tag outside it
	// has no bump kind -- not a defaulted one.
	ErrNotSemver = errors.New("policy: tag is not a semantic version")

	// ErrTagNotFound reports that the named tag does not resolve to a commit
	// in the repository. Separated from ErrNoPreviousTag so a typo in the
	// caller's ref does not masquerade as a first release.
	ErrTagNotFound = errors.New("policy: tag not found in repository")

	// ErrGit reports that git itself could not be run or failed for a reason
	// this file does not model. The underlying stderr is wrapped in, never
	// discarded: "git error" with no text is the failure mode O.7's packet
	// forbids.
	ErrGit = errors.New("policy: git invocation failed")
)

// ---------------------------------------------------------------------------
// Tunables, both of which are guards rather than budgets
// ---------------------------------------------------------------------------

// gitTimeout bounds a single git invocation so a wedged git cannot hang the
// daemon that called us.
//
// DERIVATION: this is NOT a performance budget and nothing should be tuned
// against it. Every command this file runs (`rev-parse`, `describe`) is local
// and reads only the object database and refs; on the largest repositories in
// public use these are sub-second. 30s is chosen to sit orders of magnitude
// above any plausible local latency so that expiry means "git is stuck", never
// "this repository is big". If it ever fires on a healthy repository, the
// correct response is to investigate the hang, not to raise the number.
const gitTimeout = 30 * time.Second

// maxTagWalk bounds the walk back through tags that carry no version signal
// (see ComputeSemverBump). It exists so a repository that tags every commit
// with a non-version name cannot turn one policy evaluation into an unbounded
// series of git invocations.
//
// DERIVATION: not measured, and deliberately generous. A release lineage needs
// one step; the walk only takes another when it meets a tag that is not a
// semantic version or that carries the same version core as the new tag. 256
// consecutive such tags is already a pathological repository, and the error
// returned at the bound says so rather than pretending there is no previous tag.
const maxTagWalk = 256

// ---------------------------------------------------------------------------
// ComputeSemverBump
// ---------------------------------------------------------------------------

// ComputeSemverBump reports which kind of version bump newTag represents in the
// git repository rooted at repoPath.
//
// The returned BumpKind is the type engine.go owns -- schemas/policy.schema.json
// #/$defs/semverBump's one Go image. This file declares no second enum and
// returns no token that is not in BumpKindValues().
//
// THE RULE, STATED NORMATIVELY
//
//  1. newTag must parse as a semantic version (an optional leading `v`, then
//     semver 2.0.0). Otherwise ErrNotSemver.
//  2. If the repository is shallow, ErrShallowCheckout -- always, before any
//     tag is looked at. See this file's header.
//  3. If newTag carries a PRERELEASE identifier (`v2.0.0-rc.1`), the bump is
//     BumpPrerelease. A prerelease tag is by definition not a release; whatever
//     core version it names, that version has not shipped. This needs no
//     history and consults none.
//  4. Otherwise walk back from newTag with
//     `git describe --tags --abbrev=0 <rev>^`, exactly the command research/09
//     specifies, and classify newTag against the first tag found that carries a
//     DIFFERENT version core:
//     - major differs -> BumpMajor
//     - else minor differs -> BumpMinor
//     - else patch differs -> BumpPatch
//
// Step 4 skips two kinds of tag, and skipping is the whole reason it is a walk
// and not a single command:
//
//   - A tag that is not a semantic version. `git describe --tags` matches every
//     tag, including `nightly-2026-08-09`. Erroring on one would mean a routine
//     nightly tag silently stops release scans; classifying against one is
//     impossible. It carries no version signal, so it is stepped over.
//   - A tag whose version CORE (major.minor.patch) equals newTag's. `v2.0.0-rc.1`
//     immediately before `v2.0.0` is the standard release-candidate flow, and it
//     says nothing about the size of the bump. Stopping there would leave a real
//     major release unclassifiable; stepping over it finds `v1.9.3` and answers
//     BumpMajor, which is the answer the operator means.
//
// If the walk runs out of tags, ErrNoPreviousTag. If it exceeds maxTagWalk, an
// error wrapping ErrNoPreviousTag that says so.
//
// WHAT THIS DOES NOT CLAIM. The bump names the most significant core component
// that CHANGED between the two tags. It does not assert that newTag is greater
// than the tag it was compared with: a tag placed on a descendant of a higher
// version (a mis-cut release) is classified by the same rule, and detecting
// non-monotonic tagging is a different job with a different owner.
//
// ECOSYSTEM SCOPE. Semver only. Debian, RPM, Maven, PEP 440 and NuGet version
// ordering are different algorithms and none of them is implemented here -- see
// this file's header before reaching for parseSemver.
func ComputeSemverBump(repoPath, newTag string) (BumpKind, error) {
	if repoPath == "" {
		return BumpNone, fmt.Errorf("%w: no repository path given", ErrGit)
	}
	if newTag == "" {
		return BumpNone, fmt.Errorf("%w: no tag given", ErrNotSemver)
	}

	next, err := parseSemver(newTag)
	if err != nil {
		return BumpNone, err
	}

	// Step 2 -- before any tag is consulted, so the answer never depends on
	// how deep the checkout happened to be.
	shallow, err := isShallowRepository(repoPath)
	if err != nil {
		return BumpNone, err
	}
	if shallow {
		return BumpNone, fmt.Errorf(
			"%w: %s has truncated history, so the tag before %q cannot be determined. "+
				"actions/checkout must set `fetch-depth: 0` and `fetch-tags: true` "+
				"(research/09-orchestration-and-github-actions.md Recommendation 2)",
			ErrShallowCheckout, repoPath, newTag)
	}

	// Step 3 -- a prerelease tag classifies itself.
	if next.prerelease != "" {
		return BumpPrerelease, nil
	}

	// Step 4 -- the walk. newTag is verified to exist first so that a failure
	// of `<rev>^` below can only mean "rev is the root commit", and a typo'd
	// ref reports itself rather than looking like a first release.
	if err := verifyRev(repoPath, newTag); err != nil {
		return BumpNone, err
	}

	rev := newTag
	for i := 0; i < maxTagWalk; i++ {
		prevTag, err := describePreviousTag(repoPath, rev)
		if err != nil {
			return BumpNone, err
		}

		prev, perr := parseSemver(prevTag)
		if perr != nil {
			rev = prevTag // not a version tag: no signal, step over it
			continue
		}
		kind := classifyCore(prev, next)
		if kind == BumpNone {
			rev = prevTag // same core (e.g. the rc of this very release)
			continue
		}
		return kind, nil
	}

	return BumpNone, fmt.Errorf(
		"%w: walked back %d tags from %q without finding one that carries a different "+
			"version core; refusing to walk further",
		ErrNoPreviousTag, maxTagWalk, newTag)
}

// classifyCore returns the bump kind implied by the two version cores, or
// BumpNone when the cores are identical.
//
// BumpNone is not a fifth bump kind (engine.go says so where it is declared);
// here it is the "these two tags carry the same version, keep looking" signal,
// which is why this function and the walk above are written as one pair.
func classifyCore(prev, next semver) BumpKind {
	switch {
	case prev.major != next.major:
		return BumpMajor
	case prev.minor != next.minor:
		return BumpMinor
	case prev.patch != next.patch:
		return BumpPatch
	default:
		return BumpNone
	}
}

// ---------------------------------------------------------------------------
// git plumbing
// ---------------------------------------------------------------------------

// isShallowRepository reports whether repoPath's history is truncated.
//
// Two mechanisms, in order, because the first is authoritative and the second
// is what O.7's packet names:
//
//  1. `git rev-parse --is-shallow-repository`, which git answers correctly for
//     worktrees, submodules and separate git dirs alike.
//  2. failing that (an ancient git that does not know the option), locate the
//     git directory with `git rev-parse --git-dir` and probe for the `shallow`
//     file inside it -- the `.git/shallow` heuristic, generalised so it also
//     works when `.git` is a FILE pointing elsewhere, which is exactly what a
//     worktree or a submodule checkout looks like.
//
// If neither can be answered, the error is returned rather than defaulting.
// Defaulting to "not shallow" would resurrect the footgun this file exists to
// close, and defaulting to "shallow" would fail every scan on an unrelated git
// problem.
func isShallowRepository(repoPath string) (bool, error) {
	out, stderr, err := runGit(repoPath, "rev-parse", "--is-shallow-repository")
	if err == nil {
		switch out {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		// Some very old gits echo the option back instead of answering. Fall
		// through to the file probe rather than guessing from unknown text.
	}

	gitDir, stderr2, err2 := runGit(repoPath, "rev-parse", "--git-dir")
	if err2 != nil {
		// Report the FIRST failure, which is the more specific one, and keep
		// both stderrs: this is also the path a non-repository takes.
		if err != nil {
			return false, gitError(err, "rev-parse --is-shallow-repository", repoPath, stderr)
		}
		return false, gitError(err2, "rev-parse --git-dir", repoPath, stderr2)
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(repoPath, gitDir)
	}
	if _, statErr := os.Stat(filepath.Join(gitDir, "shallow")); statErr == nil {
		return true, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("%w: probing %s for a shallow marker: %v",
			ErrGit, gitDir, statErr)
	}
	return false, nil
}

// verifyRev checks that rev names a commit. `^{commit}` is peeled explicitly so
// an annotated tag object resolves the same way a lightweight one does.
func verifyRev(repoPath, rev string) error {
	_, stderr, err := runGit(repoPath, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err == nil {
		return nil
	}
	if _, ok := exitStatus(err); ok {
		return fmt.Errorf("%w: %q does not resolve to a commit in %s", ErrTagNotFound, rev, repoPath)
	}
	return gitError(err, "rev-parse --verify "+rev, repoPath, stderr)
}

// noPreviousTagMarkers are the stderr fragments git uses when the question
// "what is the nearest tag before this revision?" has no answer, as opposed to
// git failing.
//
// These are matched case-insensitively against stderr. Matching on message text
// is not something to do casually, so the fallback is the safe one: anything
// unrecognised becomes ErrGit WITH the stderr attached, never a silent
// "no previous tag".
var noPreviousTagMarkers = []string{
	"no names found",       // no tags anywhere in the repository
	"no tags can describe", // tags exist, none is an ancestor
	"cannot describe",      // older phrasings of both
	"unknown revision",     // `<root>^` -- there is no earlier commit
	"ambiguous argument",   // same, phrased differently
	"not a valid object name",
}

// describePreviousTag runs the command research/09 specifies:
//
//	git describe --tags --abbrev=0 <rev>^
//
// `--tags` so lightweight tags count, `--abbrev=0` so the bare tag name comes
// back rather than a `tag-N-gsha` description, and `<rev>^` so the tag on rev
// itself is excluded.
func describePreviousTag(repoPath, rev string) (string, error) {
	out, stderr, err := runGit(repoPath, "describe", "--tags", "--abbrev=0", rev+"^")
	if err == nil {
		if out == "" {
			return "", fmt.Errorf("%w: `git describe` before %q returned nothing", ErrNoPreviousTag, rev)
		}
		return out, nil
	}
	if _, ok := exitStatus(err); ok {
		lower := strings.ToLower(stderr)
		for _, marker := range noPreviousTagMarkers {
			if strings.Contains(lower, marker) {
				return "", fmt.Errorf(
					"%w: nothing tagged before %q in %s. If this is not the repository's first "+
						"version tag, the checkout may not have fetched tags: actions/checkout "+
						"needs `fetch-tags: true` (git said: %s)",
					ErrNoPreviousTag, rev, repoPath, oneLine(stderr))
			}
		}
	}
	return "", gitError(err, "describe --tags --abbrev=0 "+rev+"^", repoPath, stderr)
}

// runGit runs one git command against repoPath and returns trimmed stdout,
// trimmed stderr, and the process error.
//
// The environment is inherited so the caller's git configuration applies, with
// three additions:
//
//   - git must never block on a credential prompt (this runs in a daemon);
//   - it must not take the index lock for what are read-only queries;
//   - its messages must be in the C locale. describePreviousTag distinguishes
//     "there is no earlier tag" from "git failed" by reading stderr, and git
//     built with NLS translates those sentences. Under a German or Japanese
//     LANG the markers would stop matching and an ordinary first release would
//     be reported as ErrGit. That is a loud, correct-category-wrong error
//     rather than a wrong answer, but pinning the locale removes it entirely.
//     LANGUAGE is cleared too because GNU gettext lets it override LC_ALL.
func runGit(repoPath string, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()

	full := append([]string{"-C", repoPath}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"LC_ALL=C",
		"LANGUAGE=",
	)

	err = cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = fmt.Errorf("git %s: %w after %s", strings.Join(args, " "), ctxErr, gitTimeout)
	}
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), err
}

// exitStatus reports the process exit code when err is git exiting non-zero,
// and false when git could not be run at all (missing binary, timeout, ...).
// The distinction matters: "git said no" and "there is no git" are different
// diagnoses and this file must not merge them.
func exitStatus(err error) (int, bool) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
}

// gitError wraps a git failure with the command, the repository and git's own
// stderr. O.7's packet forbids a bare "git error"; this is why the stderr is
// carried all the way out.
func gitError(err error, what, repoPath, stderr string) error {
	if stderr == "" {
		return fmt.Errorf("%w: `git %s` in %s: %v", ErrGit, what, repoPath, err)
	}
	return fmt.Errorf("%w: `git %s` in %s: %v: %s", ErrGit, what, repoPath, err, oneLine(stderr))
}

// oneLine flattens git's multi-line stderr so an error stays greppable in a log.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ---------------------------------------------------------------------------
// semver 2.0.0, and nothing else
// ---------------------------------------------------------------------------

// semver is a parsed semantic version. Unexported on purpose -- see this file's
// header: exporting it would invite it to be used as a package-ecosystem
// version comparator, which it is not.
type semver struct {
	major, minor, patch uint64
	prerelease          string // without the leading '-'; "" when absent
	build               string // without the leading '+'; "" when absent
}

// parseSemver parses a git tag as a semantic version.
//
// The dialect, stated so it is a contract and not an accident:
//
//   - an optional leading `v`, lowercase only, because that is git's tagging
//     convention and accepting a second spelling means two spellings of the
//     same tag can disagree. `1.2.3` and `v1.2.3` both parse; `V1.2.3` does not.
//   - `MAJOR.MINOR.PATCH`, all three REQUIRED. `v1.2` is not a semantic version
//     and is not silently widened to `v1.2.0`: the walk in ComputeSemverBump
//     steps over tags it cannot parse, so a repository using two-component tags
//     gets ErrNoPreviousTag rather than a fabricated patch component.
//   - numeric identifiers carry NO leading zeroes and no sign (semver 2.0.0 §2),
//     so `v01.0.0` is rejected. This is what makes the parse total-order-safe:
//     `01` and `1` cannot both exist as distinct tags meaning the same version.
//   - an optional `-prerelease`, dot-separated identifiers of [0-9A-Za-z-],
//     none empty, numeric ones without leading zeroes (§9).
//   - an optional `+build`, dot-separated identifiers of [0-9A-Za-z-], none
//     empty (§10). Build metadata is PARSED and then ignored for classification,
//     exactly as the spec requires: it carries no precedence.
//
// Every rejection names what was wrong with the tag, because this error reaches
// an operator looking at a tag they just pushed.
func parseSemver(tag string) (semver, error) {
	bad := func(reason string) (semver, error) {
		return semver{}, fmt.Errorf("%w: %q: %s", ErrNotSemver, tag, reason)
	}

	rest := strings.TrimPrefix(tag, "v")

	// Split off build metadata first: '+' cannot appear in a prerelease, so
	// the leftmost '+' ends the version proper.
	var build string
	if i := strings.IndexByte(rest, '+'); i >= 0 {
		build = rest[i+1:]
		rest = rest[:i]
		if err := checkDotIdentifiers(build, false); err != nil {
			return bad("build metadata: " + err.Error())
		}
	}

	// Then the prerelease. The FIRST '-' after the core starts it.
	var prerelease string
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		prerelease = rest[i+1:]
		rest = rest[:i]
		if err := checkDotIdentifiers(prerelease, true); err != nil {
			return bad("prerelease: " + err.Error())
		}
	}

	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return bad(fmt.Sprintf("want major.minor.patch, got %d component(s) in %q", len(parts), rest))
	}
	var nums [3]uint64
	for i, name := range coreComponentNames {
		n, err := parseNumericIdentifier(parts[i])
		if err != nil {
			return bad(name + ": " + err.Error())
		}
		nums[i] = n
	}

	return semver{
		major:      nums[0],
		minor:      nums[1],
		patch:      nums[2],
		prerelease: prerelease,
		build:      build,
	}, nil
}

// coreComponentNames labels the three core components in a parse error, for an
// operator reading it against a tag they just pushed.
//
// They are spelled "... version" rather than bare "major"/"minor"/"patch"
// because those three bare words are ALSO the BumpKind tokens engine.go owns,
// and TestSemverFileDeclaresNoSecondBumpVocabulary -- correctly -- cannot tell a
// component label from a forked enum. Two vocabularies sharing three words is
// exactly the collision plan/IMPLEMENTATION-PLAN.md section 6 is about, so the
// one that is not the enum gets the longer spelling.
var coreComponentNames = [3]string{"major version", "minor version", "patch version"}

// parseNumericIdentifier parses one semver numeric identifier: digits only, no
// sign, no leading zero unless the identifier IS "0".
func parseNumericIdentifier(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%q is not a number", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%q has a leading zero", s)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q does not fit in a 64-bit unsigned integer", s)
	}
	return n, nil
}

// checkDotIdentifiers validates a dot-separated identifier list. numericRules
// applies semver §9's extra constraint on prerelease identifiers that are
// wholly numeric; build metadata (§10) has no such rule, so `+001` is legal
// build metadata and `-001` is not a legal prerelease.
func checkDotIdentifiers(s string, numericRules bool) error {
	if s == "" {
		return errors.New("empty")
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return errors.New("empty identifier")
		}
		allDigits := true
		for i := 0; i < len(id); i++ {
			c := id[i]
			switch {
			case c >= '0' && c <= '9':
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-':
				allDigits = false
			default:
				return fmt.Errorf("identifier %q contains %q, which is not [0-9A-Za-z-]", id, string(c))
			}
		}
		if numericRules && allDigits && len(id) > 1 && id[0] == '0' {
			return fmt.Errorf("numeric identifier %q has a leading zero", id)
		}
	}
	return nil
}
