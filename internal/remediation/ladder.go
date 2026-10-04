package remediation

// The validation ladder (plan node ladder). Ordered rungs, each labelled with
// what it proves and what it does not, because the failure the research
// documents as most dangerous is a gate reported as stronger evidence than it
// is: 10.3% of patches pass a full test suite and remain exploitable. A pass
// never claims more than its row. A blocking failure means no pull request:
// the patch text is kept in the report and the branch is rolled back.

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
)

// RungResult is the outcome of one rung.
type RungResult string

// The rung outcomes.
const (
	RungPass     RungResult = "pass"
	RungFail     RungResult = "fail"
	RungNotRun   RungResult = "not_run"
	RungRequired RungResult = "required" // a human step the ladder cannot take
)

// Rung is one rung's row in the report and the pull-request body.
type Rung struct {
	Name         string     `json:"name"`
	Result       RungResult `json:"result"`
	Proves       string     `json:"proves"`
	DoesNotProve string     `json:"doesNotProve"`
	Detail       string     `json:"detail,omitempty"`
	Blocking     bool       `json:"blocking"`
}

// The rung names, in ladder order.
const (
	RungAlreadyProcessed = "already_processed"
	RungAnchorsApply     = "anchors_and_apply"
	RungPaths            = "disallowed_paths"
	RungSize             = "patch_size"
	RungBuild            = "isolated_build"
	RungTests            = "existing_tests"
	RungFuzz             = "fuzz_budget"
	RungDifferential     = "differential_equivalence"
	RungRescan           = "diff_aware_rescan"
	RungHumanReview      = "human_review"
	RungProvenance       = "provenance"
	RungOpenLimit        = "open_pull_request_limit"
)

// rungText is what each rung proves and does not. It is the one place the
// claims live, so the report and the pull request cannot word them
// differently.
var rungText = map[string][2]string{
	RungAlreadyProcessed: {"no earlier attempt already committed this unit of work (its idempotency key is on no fix branch)", "anything about the patch"},
	RungAnchorsApply:     {"every edit anchored exactly once in the scanned blob and git apply --3way placed the whole diff", "that the change is correct"},
	RungPaths:            {"the patch touches only the source files its findings are in, and no build, CI, dependency, configuration or repository-control file", "that the touched code is safe"},
	RungSize:             {"the patch is small enough to review (the limit is a judgement, not a measurement)", "that a small patch is a correct one"},
	RungBuild:            {"the patched tree builds with the operator's command, with no network", "that the vulnerability is gone"},
	RungTests:            {"the repository's existing tests pass on the patched tree, with no network", "that the vulnerability is gone: patches that pass full test suites remain exploitable"},
	RungFuzz:             {"a fuzz budget ran without a new crash", "absence of the defect"},
	RungDifferential:     {"behaviour is unchanged outside the fix", "(deferred past v1; never run)"},
	RungRescan:           {"the rule that raised the finding no longer matches, and no new finding appeared in the touched files", "that the vulnerability is gone: the detector is grading its own fix, so this rung can only lower a label, never raise one"},
	RungHumanReview:      {"nothing: a maintainer must review the change", "(this rung is never waived)"},
	RungProvenance:       {"the commit carries its finding, audit and idempotency-key trailers", "authorship by signature: commits are not cryptographically signed in v1"},
	RungOpenLimit:        {"opening this pull request keeps the repository at or under the open-proposal limit", "anything about the patch"},
}

func rung(name string, r RungResult, blocking bool, detail string) Rung {
	t := rungText[name]
	return Rung{Name: name, Result: r, Proves: t[0], DoesNotProve: t[1], Detail: detail, Blocking: blocking}
}

// Ladder is one target's ladder configuration.
type Ladder struct {
	Sandbox Sandbox
	// Build and Test are the operator's commands; empty means the rung is not
	// run, which blocks: an unbuilt patch is never proposed.
	Build, Test []string
	// MaxChangedLines and MaxFiles bound the patch.
	MaxChangedLines, MaxFiles int
	// Rescan re-runs the recall tier on the patched tree's touched files and
	// returns the fingerprints it found there.
	Rescan func(ctx context.Context, root string, files []string) (map[string]bool, error)
}

// DefaultMaxChangedLines and DefaultMaxFiles are the size rung's limits.
// Judgement, not evidence: the rejection rate they cause is logged.
const (
	DefaultMaxChangedLines = 80
	DefaultMaxFiles        = 5
)

// sourceExtensions are the files the agent may patch: source in the languages
// Lane B covers. Everything else (build files, manifests, CI, configuration,
// documentation, scripts) is refused, whatever a finding says about it. An
// allowlist, because the list of files that control a build has no end.
var sourceExtensions = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hpp": true, ".hh": true,
	".go": true, ".py": true, ".java": true, ".scala": true, ".cs": true,
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true,
}

// buildScriptNames are source files that a build, a test runner or a package
// manager executes or reads as configuration. Compared in lower case.
var buildScriptNames = map[string]bool{
	"setup.py": true, "conftest.py": true, "noxfile.py": true, "fabfile.py": true, "manage.py": true,
	"sconstruct": true, "sconscript": true, "gulpfile.js": true, "gruntfile.js": true, "jakefile.js": true,
	"build.go": true, "mage.go": true, "magefile.go": true,
}

// disallowedPath reports why a path may never be patched by the agent, or "".
// The agent edits first-party source; it never edits what builds, tests, ships
// or controls the repository, even when a finding sits in such a file.
func disallowedPath(p string) string {
	if err := SafePath(p); err != nil {
		return "not a plain repository path"
	}
	lower := strings.ToLower(p)
	base := path.Base(lower)
	for _, seg := range strings.Split(lower, "/") {
		if strings.HasPrefix(seg, ".") {
			return "inside a hidden directory or a dot-file (repository control, CI, editor or tool configuration)"
		}
	}
	if !sourceExtensions[path.Ext(base)] {
		return "not a source file in a language Lane B covers"
	}
	if buildScriptNames[base] || strings.Contains(base, ".config.") || strings.HasPrefix(base, "webpack.") ||
		strings.HasPrefix(base, "rollup.") || strings.HasPrefix(base, "vite.") || strings.HasPrefix(base, "jest.") ||
		strings.HasPrefix(base, "babel.") || strings.HasPrefix(base, "eslint") {
		return "a build, test or tool script"
	}
	return ""
}

// Patch is a candidate patch, applied and staged in the clone. The ladder
// never runs anything in the clone: Export writes a fresh copy of the patched
// tree (files only, no .git) for each use, and returns how to remove it.
type Patch struct {
	Export  func(ctx context.Context) (dir string, done func(), err error)
	Files   map[string]string // path -> new content
	Base    map[string]string // path -> content at the scanned commit
	Diff    string
	Allowed map[string]bool // the files the group's findings are in
	// Fingerprints are the group's findings; BaseFingerprints every SAST
	// fingerprint the scanned audit held in the touched files.
	Fingerprints, BaseFingerprints map[string]bool
}

// changedLines counts added and removed lines in a unified diff.
func changedLines(diff string) int {
	n := 0
	for _, l := range strings.Split(diff, "\n") {
		if (strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++")) || (strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---")) {
			n++
		}
	}
	return n
}

// LadderOutcome is the ladder's verdict on a patch.
type LadderOutcome struct {
	Rungs []Rung
	// Regression is true when the rescan found a finding the base did not
	// have in the touched files.
	Regression bool
	// Found is every fingerprint the rescan found in the touched files; nil
	// when the rescan did not run.
	Found map[string]bool
}

// Blocked reports the first blocking failure, or "".
func (o LadderOutcome) Blocked() string {
	for _, r := range o.Rungs {
		if r.Blocking && r.Result == RungFail {
			return r.Name + ": " + r.Detail
		}
	}
	return ""
}

// Run climbs the rungs after anchors_and_apply, stopping at the first blocking
// failure. The build and the tests share one export of the patched tree (the
// tests may need what the build made); the rescan reads another, so nothing
// the build or the tests wrote can reach it.
func (l Ladder) Run(ctx context.Context, p Patch) LadderOutcome {
	var o LadderOutcome
	add := func(r Rung) bool {
		o.Rungs = append(o.Rungs, r)
		return !(r.Blocking && r.Result == RungFail)
	}

	var bad []string
	for f := range p.Files {
		if why := disallowedPath(f); why != "" {
			bad = append(bad, f+" ("+why+")")
		} else if !p.Allowed[f] {
			bad = append(bad, f+" (no finding in this group is in it)")
		}
	}
	if len(bad) > 0 {
		add(rung(RungPaths, RungFail, true, strings.Join(bad, ", ")))
		return o
	}
	add(rung(RungPaths, RungPass, true, ""))

	maxLines, maxFiles := l.MaxChangedLines, l.MaxFiles
	if maxLines <= 0 {
		maxLines = DefaultMaxChangedLines
	}
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFiles
	}
	n := changedLines(p.Diff)
	if n > maxLines || len(p.Files) > maxFiles {
		add(rung(RungSize, RungFail, true, fmt.Sprintf("%d changed lines in %d files; limits %d and %d", n, len(p.Files), maxLines, maxFiles)))
		return o
	}
	add(rung(RungSize, RungPass, true, fmt.Sprintf("%d changed lines in %d file(s)", n, len(p.Files))))

	if p.Export == nil {
		add(rung(RungBuild, RungFail, true, "no export of the patched tree"))
		return o
	}
	buildDir, done, err := p.Export(ctx)
	if err != nil {
		add(rung(RungBuild, RungFail, true, "exporting the patched tree: "+err.Error()))
		return o
	}
	defer done()
	for _, step := range []struct {
		name string
		argv []string
	}{{RungBuild, l.Build}, {RungTests, l.Test}} {
		if len(step.argv) == 0 {
			add(rung(step.name, RungFail, true, "no command is configured for this target, and an unchecked patch is never proposed"))
			return o
		}
		res, err := l.Sandbox.Run(ctx, buildDir, step.argv)
		switch {
		case errors.Is(err, ErrNoSandbox):
			add(rung(step.name, RungFail, true, err.Error()))
			return o
		case err != nil:
			add(rung(step.name, RungFail, true, err.Error()))
			return o
		case res.Exit != 0:
			add(rung(step.name, RungFail, true, fmt.Sprintf("exit %d\n%s", res.Exit, res.Tail)))
			return o
		}
		add(rung(step.name, RungPass, true, fmt.Sprintf("exit 0 in %s", res.Elapsed.Round(1e6))))
	}

	add(rung(RungFuzz, RungNotRun, false, "no fuzz budget: the decoupled honggfuzz rung is opt-in and not built in v1"))
	add(rung(RungDifferential, RungNotRun, false, "deferred past v1"))

	if l.Rescan == nil {
		add(rung(RungRescan, RungFail, true, "no rescan is configured"))
		return o
	}
	files := make([]string, 0, len(p.Files))
	for f := range p.Files {
		files = append(files, f)
	}
	rescanDir, doneRescan, err := p.Export(ctx)
	if err != nil {
		add(rung(RungRescan, RungFail, true, "exporting the patched tree: "+err.Error()))
		return o
	}
	defer doneRescan()
	found, err := l.Rescan(ctx, rescanDir, files)
	if err != nil {
		add(rung(RungRescan, RungFail, true, "the rescan did not complete: "+err.Error()))
		return o
	}
	o.Found = found
	var still, fresh []string
	for fp := range found {
		switch {
		case p.Fingerprints[fp]:
			still = append(still, short(fp))
		case !p.BaseFingerprints[fp]:
			fresh = append(fresh, short(fp))
		}
	}
	if len(fresh) > 0 {
		o.Regression = true
		add(rung(RungRescan, RungFail, true, "new finding(s) in the touched files: "+strings.Join(fresh, ", ")))
		return o
	}
	if len(still) > 0 {
		add(rung(RungRescan, RungFail, true, "the rule still matches: "+strings.Join(still, ", ")))
		return o
	}
	add(rung(RungRescan, RungPass, true, "no rule matches at the group's findings and nothing new appeared"))
	add(rung(RungHumanReview, RungRequired, false, "a maintainer reviews every Anvil pull request; nothing merges without one"))
	return o
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
