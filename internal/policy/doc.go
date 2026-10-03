// Package policy resolves Anvil's trigger policy from the repository it is
// scanning. Trigger policy is DATA: which events fire a scan, which refs and
// paths they apply to, which semver bumps gate a full scan, and on what
// cadence the daemon re-scans are all read from a file in the repository, never
// compiled into Anvil. The spine's corrected-requirements table makes that a hard constraint, and
// plan/design/control-plane.md restates the review rule it implies: a literal
// such as "push" or "major" used as a match condition anywhere outside the
// parser is a defect.
package policy
