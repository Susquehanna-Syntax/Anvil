// Package policy resolves Anvil's trigger policy from the repository it is
// scanning. Trigger policy is DATA: which events fire a scan, which refs and
// paths they apply to, which semver bumps gate a full scan, and on what
// cadence the daemon re-scans are all read from a file in the repository, never
// compiled into Anvil. plan/00-SPINE.md S1 makes that a hard constraint, and
// plan/70-orchestration-ci.md restates the review rule it implies: a literal
// such as "push" or "major" used as a match condition anywhere outside the
// parser is a defect.
//
// This file is step O.5's half of that: FINDING the policy file. Parsing it,
// evaluating its rules (O.6), and computing the semver bump its rules match
// against (O.7) are separate steps in this same package.
//
// The document shape is defined once, in schemas/policy.schema.json, and this
// package points at it by SchemaPath and SchemaID rather than restating it.
// plan/IMPLEMENTATION-PLAN.md section 6 closed ten defects that were all the
// same error -- two areas each defining the shared vocabulary from their own
// side -- so a second schema for this one file, in area D or in the GitHub
// Action (O.8), would be the eleventh. Consumers validate against that file and
// extend it there.
package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ErrNoPolicyFound reports that none of the SearchOrder candidates exists under
// the given root. It is a normal outcome, not a failure: a repository with no
// policy file is unconfigured, and the caller decides whether that means "do
// nothing" or "apply a built-in default". Test for it with errors.Is; Locate
// wraps it with the root it searched.
var ErrNoPolicyFound = errors.New("policy: no policy file found")

// Schema locations for consumers that need to validate a policy document.
// These exist so the engine (O.6), the GitHub Action (O.8) and area D's DAST
// overrides all name the SAME schema instead of each shipping their own copy.
const (
	// SchemaPath is the schema's location in the Anvil source tree,
	// relative to the repository root.
	SchemaPath = "schemas/policy.schema.json"

	// SchemaID is the schema's $id, and the value users put in a
	// `# yaml-language-server: $schema=` header. The daemon serves the same
	// document locally so schema resolution never requires internet access;
	// the .invalid TLD is deliberate -- this identifier is a name, and
	// resolving it over the network is not part of the contract.
	SchemaID = "https://anvil.invalid/schemas/policy.schema.json"
)

// searchOrder is the config-file search order, mirroring Renovate: try each
// candidate in turn and stop at the first one that exists
// (research/09-orchestration-and-github-actions.md Recommendation 2).
//
// These are FILE LOCATIONS, not trigger policy. Nothing here is an event name,
// a ref pattern, a semver bump kind or a cadence -- the four kinds of value
// O.5's packet forbids as Go constants. Every matchable value comes from
// inside whichever of these files is found.
//
// Slash-separated on purpose: these are repository-relative paths as users
// write them in documentation, converted to host separators by filepath.Join
// at the point of use, so the same list is correct on Windows.
var searchOrder = [...]string{
	".anvil/policy.yml",
	".anvil/policy.yaml",
	".anvil/policy.toml",
	"anvil.toml",
	".github/anvil.yml",
}

// SearchOrder returns the candidate paths, repository-relative and
// slash-separated, in precedence order.
//
// It exists so the GitHub Action (O.8), which runs on a runner without the
// daemon and may re-implement the lookup, can read the order from one place
// rather than re-listing it and drifting. It returns a fresh slice on every
// call: a caller that mutates the result must not be able to change where
// every other caller looks for the policy.
func SearchOrder() []string {
	out := make([]string, len(searchOrder))
	copy(out, searchOrder[:])
	return out
}

// Locate returns the path of the policy file to use for the repository rooted
// at root, joined onto root and ready to open. It tries SearchOrder in order
// and stops at the first candidate that exists as a regular file. If none
// exists it returns ErrNoPolicyFound, wrapped with the root that was searched.
//
// An empty root means the current working directory.
//
// Precedence is first-match, so a repository holding several candidates uses
// only the highest-precedence one and the others are inert. Locate does not
// warn about that -- it has one job -- but a caller that wants to surface the
// shadowing can call SearchOrder itself and stat the rest.
//
// A candidate that exists but is NOT a regular file -- a directory named
// .anvil/policy.yml, say -- is skipped, because it cannot be parsed as a
// policy document and treating it as a match would fail later with a confusing
// error. Symlinks are followed, so a symlink to a regular file is a match.
//
// Any stat error other than "does not exist" is returned, and the search STOPS
// there rather than falling through to the next candidate. That matters: if
// .anvil/policy.yml exists but is unreadable, silently continuing would run
// the repository under .github/anvil.yml -- a different policy than the one the
// user wrote, with no diagnostic. Failing loudly is the only safe behaviour for
// a file that decides whether a security scan happens at all.
//
// ENOTDIR is treated as "does not exist" rather than as an error, because it
// means the candidate definitively is not there -- some path component is a
// file. Windows reports that same situation as ErrNotExist, so folding the two
// keeps Locate's behaviour identical on both platforms instead of making a
// repository that scans on Windows fail to scan on Linux.
func Locate(root string) (string, error) {
	for _, candidate := range searchOrder {
		path := filepath.Join(root, filepath.FromSlash(candidate))

		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return "", fmt.Errorf("policy: cannot stat candidate %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		return path, nil
	}

	searched := root
	if searched == "" {
		searched = "."
	}
	return "", fmt.Errorf("%w under %q (searched %v)", ErrNoPolicyFound, searched, SearchOrder())
}
