// Package remediation is the coding agent's side of Anvil: the consumption
// controller that turns a sealed audit's findings into proposed fixes (plan
// node consume and the rest of the remediation lane).
//
// The model only proposes. It is shown a fixed, fenced prompt and replies with
// SEARCH/REPLACE edits; the harness anchors them, synthesises a diff against the
// scanned blob, applies it with git apply --3way, runs the validation ladder,
// commits with trailers and opens a draft pull request whose body is the
// evidence. Nothing here merges, and no code path reaches a merge API.
//
// # The dispositions, and who writes each
//
// Every handoff row ends in one of the thirteen frozen handoff.state literals.
// The consumption controller writes eleven of them; the reaper writes
// 'expired' and the queue cut 'skipped_budget':
//
//	ready                  enqueued from a sealed audit, or handed back
//	leased                 an attempt in progress
//	validated              the ladder passed and the commit carries its trailers
//	failed_validation      a blocking rung of the ladder failed
//	failed_format          no anchored edit after the anchor-repair turn
//	regression_introduced  the diff-aware rescan found a finding the base did not have
//	false_positive         the triage gate judged the alarm false
//	withdrawn              report-only: the triage gate lacked context, triage may not
//	                       gate generation, or the finding is not one the agent may patch
//	split_required         the group's prompt is over the token ceiling
//	fixed_incidentally     another group's commit changed this finding's code and its
//	                       fingerprint no longer resolves
//	superseded             a newer audit re-reported the same fingerprint
//
// Each disposition is logged with its reason in remediation_log (migration
// 0003), which is the audit log the triage gate's false positives go to.
package remediation
