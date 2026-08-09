// Package scanctl is `anvil-scanctl`: the ONE named scan controller
// plan/00-SPINE.md S10 requires, holding ONE state machine with ONE owner.
// S10's reason for existing is that four research branches each specified part
// of an orchestrator (a consumption protocol with leases and ledgers, a
// correlator process, sixteen validation gates, a target-lifecycle harness),
// and "implement it as one named scan controller with one state machine and
// one owner, or it will be re-implemented inconsistently in four places."
//
// This file (step O.1) carries the package doc because it is the package's
// first file and the one every other file in it depends on. Later files in
// this package — statemachine.go (O.2), handoff.go (O.3) — must NOT add a
// second package comment.
//
// scanctl OWNS NO VOCABULARY. Every enum token it handles is a Go constant
// from internal/record, which plan/IMPLEMENTATION-PLAN.md §6 makes the single
// point where shared vocabulary is fixed: "area 40 owns every shared enum,
// because it owns the record contract, and no other area may declare one."
// Nine of the ten defects that review found were the same structural error —
// separate authors each defining the shared vocabulary from their own side.
// A bare string literal for an enum value in this package is a second
// definition and is how that recurs.
package scanctl

import (
	"errors"
	"fmt"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// THE CLOCKS — there are THREE, and this file owns exactly one of them
// ---------------------------------------------------------------------------
//
// internal/handoff/reaper.go opens with a header explaining TWO clocks and why
// conflating them is the defect plan/00-SPINE.md S1 names outright. This file
// adds the third. It does not add a fourth spelling of either of the first
// two, and every statement below is written to AGREE with the existing owner
// rather than to restate it in different words.
//
//	CLOCK 1 — THE LEASE.        handoff.lease_expires_at
//	  Owner: internal/handoff (R.7). 15-30 minutes, heartbeat-renewed.
//	  Governs ONE consumer attempt. Expiry means "the holder is presumed
//	  dead": back to 'ready' while attempts remain, terminal after that.
//	  scanctl NEVER computes it. internal/scanctl/handoff.go (O.3) is a thin
//	  adapter over R.7's protocol, per IMPLEMENTATION-PLAN.md §6 ruling G9.
//
//	CLOCK 2 — THE CLAIM TIMEOUT. audit_record.deadline_at
//	  Owner of the FORMULA: record.ComputeDeadline — `scan_run.started_at +
//	  claim_timeout_seconds`, 8h by default (record.DefaultClaimTimeoutSeconds),
//	  computed ONCE in record.Sealer.BeginAudit and never recomputed.
//	  Owner of the DUE-CHECK: record.Sealer.ExpireIfDue in memory, and
//	  handoff.Queue.ExpireClaimTimeouts against the store. This file supplies
//	  the CONFIGURED INPUTS to that formula and the resulting instant; it does
//	  not decide expiry, and deliberately exposes no predicate that would let a
//	  caller decide it here. A third due-check with no substrate of its own
//	  would be the second-definition defect again.
//	  WHO DRIVES THE STORE-SIDE SWEEP: handoff.go's Consumer.Reap /
//	  Consumer.Run, which this package now exposes precisely so the two owners
//	  are driven together. See handoff.go's "WHO DRIVES THE REAPER" section.
//
//	CLOCK 3 — THE DAST DEADLINE. audit_record.dast_deadline_seconds
//	  Owner of the FORMULA: record.ComputeDastDeadline — `scan_run.started_at +
//	  dast_deadline_seconds`, fixed at record.Sealer.BeginAudit from the
//	  configured inputs THIS file resolves. research/21 Recommendation §5
//	  requires "a configurable `dast_deadline` (suggested default 4h = half the
//	  buffer window), after which `dast.status = timed_out` and the record
//	  seals regardless. Following the owner's no-hard-coding rule for triggers,
//	  this must be config, not a constant."
//	  Owner of the DUE-CHECK: record.Sealer.SealDastIfDeadlineDue.
//
//	  THIS FILE USED TO OWN THAT DUE-CHECK AND MUST NOT AGAIN. CRITIQUE O.4
//	  blocker 2: the check ran against `Deadlines.DastDeadlineAt`, an EXPORTED
//	  field on a value the caller holds, so a tick handler could move clock 3
//	  by plain assignment — the exact thing clock 2 shrugs off, because clock 2
//	  is decided against a copy the Sealer keeps privately. Clock 3 now has the
//	  same substrate: `startedAt` and `dast_deadline_seconds` live in the
//	  Sealer, fixed at BeginAudit, and SealDastIfDeadlineDue compares against
//	  them. What THIS file carries is a DERIVED, ADVISORY instant used for
//	  scheduling and diagnostics, on a struct with no assignable field.
//
// WHAT "8 HOURS" IS. plan/00-SPINE.md S1 correction #5, verbatim: "'8 hours'
// is a claim timeout, not a deletion policy and not a confidentiality
// control." Nothing here deletes anything, nothing here is a retention
// guarantee, and nothing here is a security boundary. internal/record/SECRETS.md
// (R.9) is where the confidentiality posture lives.
//
// ONE ANCHOR, TWO OFFSETS. Clocks 2 and 3 are both anchored to
// `scan_run.started_at` and to nothing else. See the "Anchoring" section
// below; that choice is load-bearing and is the reason a late write cannot
// move either deadline.

// ---------------------------------------------------------------------------
// ANCHORING — why `scan_run.started_at` and not `audit_record.created_at`
// ---------------------------------------------------------------------------
//
// research/21 §5 writes the field as `deadline_at : created_at + 8h`, with the
// gloss "anchored to scan START, never to last write". internal/store/schema.sql
// — the frozen interface — writes it as `deadline_at = scan_run.started_at +
// claim_timeout_seconds` and ALSO carries a separate `audit_record.created_at`
// column. Those are two different columns with two different meanings, and
// this is precisely the "two areas meaning different things by the same field
// name" class IMPLEMENTATION-PLAN.md §6 was convened over.
//
// THE ANCHOR IS `scan_run.started_at`. Resolution, not a preference:
//
//   - `audit_record.created_at` is a WRITE timestamp — the moment the record
//     row is first materialised, which is at or after the scan began and can
//     be arbitrarily later on a loaded host. record.ComputeDeadline's doc
//     states R.6's forbidden action outright: "Do not compute `deadline_at`
//     from any write timestamp... Anchoring it to the last write makes the
//     timeout unbounded for a chatty scan, which quietly defeats the reaper."
//     Anchoring to created_at is a weaker form of the same mistake.
//   - `scan_run.started_at` carries the schema comment "anvil/deadline.deadlineAt
//     is computed from THIS, never last write", and record.AuditConfig.StartedAt
//     rejects the zero time for the same reason.
//   - So research/21's `created_at` and the schema's `scan_run.started_at` name
//     the SAME intended instant — "scan start" — and the schema's spelling is
//     the frozen one. This file uses the schema's spelling everywhere and does
//     not introduce a third.
//
// THE DAST DEADLINE SHARES THAT ANCHOR. It would have been plausible to anchor
// clock 3 to "when the DAST worker actually started" — when the target was
// provisioned, or when the DAST half went record.HalfStatusRunning. That is
// wrong, and the failure is concrete: a daemon that queues the DAST job behind
// five hours of other work would place a 4h DAST deadline at t=9h, past an 8h
// claim deadline at t=8h. The DAST clock would never bind, the half would
// never be forced terminal, and the audit would reach record.StateExpired
// still holding an unsealed DAST half — the exact outcome dast_deadline exists
// to prevent. It is also a write-anchored clock wearing a different hat.
//
// So `dast_deadline` is the DAST half's SHARE OF THE CLAIM WINDOW, not a
// wall-clock budget for the probing engine. An engine-level timeout (how long
// ZAP itself may run once it starts) is a different, smaller thing that
// belongs to the DAST tier, and it is not this file's.

// ---------------------------------------------------------------------------
// Constraint Resolution
// ---------------------------------------------------------------------------
//
// Three hard constraints collide with the 8-hour claim window. research/09's
// own Gaps section lists the collision as an out-of-scope lead it did not
// chase: "the 8-hour buffer retention vs the 6-hour GitHub-hosted job cap and
// 5-day self-hosted cap [S22] — a scan that outlives its buffer is a branch
// 18/24 correctness question." research/14 §6 records that two branches
// predicted the same failure independently "and neither got an answer." This
// block is the answer. Each constraint is named, then resolved.
//
// (a) THE 6-HOUR GITHUB-HOSTED JOB CAP binds the Action's own runtime ONLY.
//
//	Constraint: "Actions run limits: 6 hours max per job on GitHub-hosted
//	runners" (research/09, Rate limits and run limits; Table D "Max job time
//	| 6 hours [S22]"). The arithmetic that makes it a collision:
//	GitHubHostedJobCap (6h) < the default claim window (8h,
//	record.DefaultClaimTimeoutSeconds). A GitHub-hosted job that waited for
//	the claim window to close would be killed two hours before it did.
//	Deadlines.ExceedsGitHubHostedJobCap reports that relation for a given
//	policy; at the shipped defaults it is TRUE, and that is the point.
//
//	Resolution: thin Action, fat daemon (research/09 Recommendation §3). The
//	Action is "a trigger, not a scanner": it evaluates policy locally and
//	either runs inline delta-SAST on the runner, or fires
//	`repository_dispatch`/signed webhook at the user's daemon for anything
//	involving DAST or a full scan. THE ACTION MUST NEVER BLOCK WAITING FOR
//	SCAN COMPLETION — fire and return. Under that shape the cap binds only
//	the dispatch, which takes seconds, and the collision dissolves: the two
//	durations no longer measure the same interval.
//
//	The obvious objection is that the default DAST deadline (4h) is BELOW the
//	6h cap, so a job could in principle block for a DAST scan. It cannot, for
//	two independent reasons. First, `dast_deadline` is an upper bound on when
//	the half is FORCED terminal, not a promise of when it completes, and it is
//	measured from scan start — a dispatch that queues behind other work on the
//	user's own hardware consumes it before probing begins. Second, and
//	decisive even if the timing worked: research/21 §5 reason 1 — "Blocking
//	spends the owner's own 8-hour budget... If SAST blocks and DAST takes 6
//	hours, the coding agent gets 2 hours instead of 8." Blocking converts the
//	claim window into a scan window. The Action returns immediately whether or
//	not the cap would have permitted otherwise.
//
// (b) THE 5-DAY SELF-HOSTED JOB CAP is moot, and is never relied upon.
//
//	Constraint: "5 days max per job on self-hosted" (research/09, same
//	source; SelfHostedJobCap below). It is the one cap that comfortably
//	exceeds an 8h claim window, so it reads like an escape hatch: run the
//	whole scan inside a self-hosted job and the collision disappears.
//
//	Resolution: Anvil does not take that hatch, on grounds that have nothing
//	to do with the clock. research/09 Risk #7 quotes GitHub directly:
//	"Self-hosted runners should almost never be used for public repositories
//	on GitHub, because any user can open pull requests against the repository
//	and compromise the environment." research/09 adds that Anvil's runner is
//	"a machine holding model weights and a security-findings database — an
//	unusually attractive target." So: Anvil gates self-hosted runners on
//	public repos loudly (the shipped Action's README reproduces GitHub's
//	warning verbatim and documents restricting to private repos via runner
//	groups — that enforcement is step O.8's, not this file's), and it NEVER
//	treats a self-hosted runner as the DAST execution host regardless of
//	repository visibility. DAST executes on the user's daemon, which is a
//	separately installed artifact (plan/00-SPINE.md S9-AMENDED: `anvil-dast`,
//	with "no network probing capability compiled in" to core `anvil`).
//
//	Consequence for the clock: no Anvil deadline may ever be derived from
//	SelfHostedJobCap. The constant exists below so this resolution can be
//	stated in arithmetic and so a future reader cannot re-derive the hatch by
//	accident; it is a platform fact, not an Anvil budget.
//
// (c) A ZAP FULL SCAN OUTRUNNING THE WINDOW is bounded by `dast_deadline`.
//
//	Constraint: research/15 §"Failure mode: two engines, one buffer, eight
//	hours" — "Nuclei on a static Go binary finishes fast; a ZAP full scan
//	with AJAX spidering does not. If a scheduled ZAP full scan outruns the
//	8-hour buffer retention, the correlated artifact expires before the
//	coding agent consumes it. Anvil must bound engine wall-clock explicitly."
//	research/14 §"On B3" narrows it: "The requirement only breaks for ZAP
//	full scans, browser crawls, and fuzzing campaigns."
//
//	Resolution: clock 3. At the DAST deadline record.Sealer.SealDastIfDeadlineDue
//	seals the DAST half with record.HalfStatusTimedOut — a frozen `anvil/status` token,
//	one of the four record.TerminalHalfStatuses — regardless of how much of
//	the attack surface was covered. record.DeriveDastStatus then maps that
//	half status onto the audit-level `anvil/dastStatus`, which is
//	record.DastStatusTimedOut for a target that actually booted, and a
//	provenance-dominant value (record.DastStatusTargetBootFailed,
//	record.DastStatusTargetUnreachable, record.DastStatusSkippedNoManifest)
//	when the target never came up — the provenance rules deliberately run
//	first, so "we ran out of clock" cannot mask "there was nothing to probe".
//	Getting that precedence right is the derivation's job and this file does
//	not restate it: writing `dast_status` directly here, rather than sealing
//	the half and letting record.DeriveDastStatus run, would be a second
//	definition of a derived field that is NOT NULL in the schema.
//
//	Because the DAST deadline is a strict sub-interval of the claim window
//	(Deadlines.DastDeadlineBinds), the forced seal lands BEFORE expiry, so the
//	audit reaches record.StateBothSealed and the record is consumable — with a
//	half that says "timed out", which is honest — instead of reaching
//	record.StateExpired with the SAST half stranded. plan/00-SPINE.md S6's
//	rationale generalises here: a half that ran out of clock must be
//	distinguishable from one scanned clean, and record.DastStatusTimedOut is
//	that distinction. Note that the timed-out half is TERMINAL BUT NOT
//	READABLE: record.IsTerminalHalfStatus is true for it, record's read gate
//	stays shut on it. Whether a consumer may read any half is answered by
//	record.HalfReadGate and by nothing in this package — five previous authors
//	re-derived that predicate locally and all five got it wrong.
//
// (d) RESIDUAL RISK — THE ORPHANED CHECK RUN. OPEN. NEEDS A DESIGN SPIKE.
//
//	Not resolved here, and deliberately not assumed away.
//
//	Once (a) is applied, the triggering Action fires `repository_dispatch`
//	and returns success within seconds. Its check run then reports the
//	DISPATCH, not the scan. A DAST scan running for hours on the user's
//	daemon has NO GitHub check run tied to it at all: there is no job to
//	attach to, the workflow run is already complete, and its `GITHUB_TOKEN`
//	is revoked at job completion, so nothing on the GitHub side can even
//	update a status afterwards. A reviewer looking at a PR sees a green
//	check and concludes the scan passed, when in fact it has not started —
//	which is research/09 Risk #4's failure mode ("reviewers systematically
//	read [a blank checks list] as 'nothing to worry about'") in a second
//	costume, and Risk #4 is filed as a safety failure, not a convenience one.
//
//	The daemon must therefore INDEPENDENTLY create and update its own Checks
//	API run (or Commit Status) rather than inheriting the Action's job
//	status. Four things that spike must settle, none of which is decided:
//
//	  1. Auth. Creating a check run needs `checks: write` on a GitHub App
//	     installation token (research/09 §4 already requires the App path for
//	     fix PRs). Whether the DAST daemon holds that installation token, and
//	     what else that token can then do, is an authorization-scope question
//	     — O.11's lane, and it must not be settled by whoever needs it first.
//	  2. Which commit. research/09 Risk #12: "`repository_dispatch` runs on
//	     the default branch only... the branch must be passed in
//	     `client_payload`". So the head SHA the check run attaches to must
//	     travel in the dispatch payload and be validated on arrival; a check
//	     run created against the default-branch tip annotates the wrong
//	     commit.
//	  3. Update cadence and the stall signal. GitHub does not time out an
//	     `in_progress` check run, so a daemon that dies leaves one running
//	     forever. The sweep that closes it must be driven by THESE deadlines
//	     — Deadlines.DeadlineAt() and Deadlines.DastDeadline() — and by nothing
//	     GitHub reports.
//	  4. Rate limits against long scans, given research/09 Risk #13's
//	     1,000 req/hr/repo ceiling on any `GITHUB_TOKEN` path.
//
//	ONE INVARIANT IS NOT OPEN, and O.2 must hold it: the GitHub side is a
//	PROJECTION of the record and can never be an input to it. A stalled,
//	failed, rate-limited or rejected check-run update must not stall, block or
//	corrupt the daemon-side record — it must not become a fourth clock, and it
//	must never be able to move a deadline. That is now true BY CONSTRUCTION
//	rather than by nobody having tried: Deadlines has no exported field, both
//	instants are derived from `scan_run.started_at` at scan start, and both
//	due-checks are the Sealer's against its own private copies. A future
//	publisher handed an AuditRecord has nothing to assign to. If publishing to
//	GitHub fails entirely, the audit still seals, still expires on schedule,
//	and is still consumable locally.

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// ErrInvalidDeadlinePolicy is the sentinel every DeadlinePolicy rejection
// wraps, so callers can branch with errors.Is while recovering the specifics
// with errors.As.
var ErrInvalidDeadlinePolicy = errors.New("scanctl: invalid deadline policy")

// ErrZeroScanStart is returned when a Deadlines is asked for from the zero
// time. Both clocks are anchored to `scan_run.started_at`; a zero anchor
// would silently place the claim window in the year 1, and
// record.Sealer.BeginAudit rejects it for the same reason.
var ErrZeroScanStart = errors.New("scanctl: scan_run.started_at is the zero time")

// PolicyError reports a refused DeadlinePolicy, naming the field and the
// observed value rather than merely the offence.
type PolicyError struct {
	Field  string // "claimTimeoutSeconds" | "dastDeadlineSeconds" | "startedAt"
	Value  string // the observed value, formatted
	Reason string
	Err    error // ErrInvalidDeadlinePolicy or ErrZeroScanStart
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("scanctl: deadline policy field %s = %s is invalid: %s",
		e.Field, e.Value, e.Reason)
}

// Unwrap exposes the sentinel to errors.Is.
func (e *PolicyError) Unwrap() error { return e.Err }

// ---------------------------------------------------------------------------
// Platform facts — NOT Anvil policy, NOT timeouts
// ---------------------------------------------------------------------------

// GitHubHostedJobCap is GitHub's hard limit on a single job on a GitHub-hosted
// runner: "6 hours max per job on GitHub-hosted runners" (research/09, Rate
// limits and run limits, and Table D "Max job time | 6 hours [S22]").
//
// IT IS A PLATFORM FACT, NOT AN ANVIL BUDGET. It exists so Constraint
// Resolution (a) can be stated as arithmetic and so
// Deadlines.ExceedsGitHubHostedJobCap can be computed. Nothing in Anvil may
// use it as a timeout, a deadline, or a default: the resolution is that the
// Action never blocks, which makes the cap irrelevant to Anvil's own clocks
// rather than a number Anvil has to fit inside.
const GitHubHostedJobCap = 6 * time.Hour

// SelfHostedJobCap is GitHub's hard limit on a single job on a self-hosted
// runner: "5 days max per job on self-hosted" (research/09, same source).
//
// IT IS A PLATFORM FACT THAT ANVIL DELIBERATELY DOES NOT USE. See Constraint
// Resolution (b): the 5-day headroom would "solve" the clock collision by
// running the scan inside a self-hosted job, and Anvil refuses that shape on
// security grounds (research/09 Risk #7) independent of any deadline. This
// constant is declared so the refusal is legible and cannot be re-derived by
// accident, not so that anything can be measured against it.
const SelfHostedJobCap = 5 * 24 * time.Hour

// ---------------------------------------------------------------------------
// DeadlinePolicy — the configured inputs to both scan-scoped clocks
// ---------------------------------------------------------------------------

// DeadlinePolicy is the CONFIGURATION for clocks 2 and 3 of one audit: how
// long an unclaimed finding stays eligible, and how much of that window the
// DAST half gets before it is forced terminal.
//
// It is data, never a constant. plan/00-SPINE.md S1 makes "no hard-coded
// triggers" a hard constraint and research/21 §5 extends it to this value
// explicitly: "Following the owner's no-hard-coding rule for triggers, this
// must be config, not a constant." The zero DeadlinePolicy is meaningful and
// resolves to the documented defaults; it is not an error.
//
// WHERE THE VALUES COME FROM is not this file's business either. Trigger
// policy is `.anvil/policy.yml`, whose schema and search order are steps
// O.5/O.6; this type is the shape those values land in after parsing. Nothing
// here reads a file, names an event, or matches a ref.
type DeadlinePolicy struct {
	// ClaimTimeoutSeconds is `audit_record.claim_timeout_seconds` — clock 2.
	// Zero means record.DefaultClaimTimeoutSeconds (28800 = 8h); negative is
	// rejected, matching the schema's ck_audit_record_claim_timeout_positive
	// and record.Sealer.BeginAudit's own check.
	//
	// It is a CLAIM timeout. Not retention, not deletion, not
	// confidentiality (plan/00-SPINE.md S1 correction #5).
	ClaimTimeoutSeconds int

	// DastDeadlineSeconds is `audit_record.dast_deadline_seconds` — clock 3,
	// INDEPENDENT of clock 2 in semantics though sharing its anchor.
	//
	// Nil means "use the derived default", DefaultDastDeadlineSeconds — half
	// the resolved claim window, which is 4h at the 8h default, matching
	// research/21 §5's "suggested default 4h = half the buffer window". It is
	// derived rather than written down as 14400 so that an operator who
	// configures a 2h claim window gets a 1h DAST deadline instead of a DAST
	// clock that can never fire.
	//
	// Resolve forces this to nil when DastEnabled is false, matching
	// record.AuditConfig.DastDeadlineSeconds ("Nil when DAST is disabled").
	// Non-nil and non-positive is rejected, matching
	// ck_audit_record_dast_deadline_positive.
	DastDeadlineSeconds *int

	// DastEnabled reports whether this installation has a DAST half at all.
	// It is FALSE in the core `anvil` artifact: plan/00-SPINE.md S9-AMENDED
	// splits `anvil-dast` into a separately installed artifact with the
	// network-probing capability compiled in, so Tier S "simply does not
	// install `anvil-dast`."
	//
	// When false there is no DAST clock to run: record.Sealer.BeginAudit
	// immediately and terminally seals the DAST half as
	// record.HalfStatusSkipped / record.DastStatusNotRun, and the audit
	// reaches record.StateBothSealed the moment its SAST half seals. A DAST
	// deadline over a half that never runs would be a timer that can only
	// ever fire on nothing.
	DastEnabled bool
}

// DefaultDastDeadlineSeconds returns the DAST deadline derived from a resolved
// claim timeout: half of it, per research/21 §5's "default 4h = half the
// buffer window". At record.DefaultClaimTimeoutSeconds (28800) it returns
// 14400 — four hours.
//
// It is a FUNCTION rather than a constant on purpose. Writing 14400 down would
// silently decouple the two clocks the moment an operator changed the claim
// window, and a DAST deadline at or beyond the claim deadline never binds (see
// Deadlines.DastDeadlineBinds). The relation is the requirement; 4h is only
// what the relation evaluates to at the shipped default.
//
// The result is clamped to a minimum of 1 second because
// ck_audit_record_dast_deadline_positive requires > 0; a claim window short
// enough to hit that clamp is a test fixture, not a deployment.
func DefaultDastDeadlineSeconds(claimTimeoutSeconds int) int {
	if half := claimTimeoutSeconds / 2; half > 0 {
		return half
	}
	return 1
}

// Resolve fills in defaults, applies the DAST-disabled rule, validates, and
// returns a DeadlinePolicy whose fields are all concrete.
//
// It is the ONE place a DeadlinePolicy acquires its defaults. Resolve is
// idempotent: resolving an already-resolved policy returns it unchanged, so a
// caller that cannot remember whether it resolved may resolve again.
func (p DeadlinePolicy) Resolve() (DeadlinePolicy, error) {
	out := DeadlinePolicy{DastEnabled: p.DastEnabled}

	out.ClaimTimeoutSeconds = p.ClaimTimeoutSeconds
	if out.ClaimTimeoutSeconds == 0 {
		out.ClaimTimeoutSeconds = record.DefaultClaimTimeoutSeconds
	}
	if out.ClaimTimeoutSeconds < 0 {
		return DeadlinePolicy{}, &PolicyError{
			Field: "claimTimeoutSeconds", Value: fmt.Sprint(p.ClaimTimeoutSeconds),
			Reason: "the schema requires > 0 (ck_audit_record_claim_timeout_positive)",
			Err:    ErrInvalidDeadlinePolicy,
		}
	}

	// VALIDATED BEFORE THE DastEnabled BRANCH, not after it. CRITIQUE O.4
	// finding O4-m5: this check used to live below the early return, so a
	// policy carrying `dastDeadlineSeconds: -1` with DAST off resolved clean
	// and the config error survived — invisibly — until the day somebody
	// installed `anvil-dast`, at which point a scan that had been working
	// started failing on a line nobody had touched. A value is either legal or
	// it is not; whether this installation happens to read it today is a
	// separate question from whether it is well-formed.
	if p.DastDeadlineSeconds != nil && *p.DastDeadlineSeconds <= 0 {
		return DeadlinePolicy{}, &PolicyError{
			Field: "dastDeadlineSeconds", Value: fmt.Sprint(*p.DastDeadlineSeconds),
			Reason: "the schema requires NULL or > 0 (ck_audit_record_dast_deadline_positive)",
			Err:    ErrInvalidDeadlinePolicy,
		}
	}

	if !p.DastEnabled {
		// No DAST half exists, so there is no clock 3. Left nil, matching
		// record.AuditConfig.DastDeadlineSeconds's own contract.
		return out, nil
	}

	if p.DastDeadlineSeconds == nil {
		derived := DefaultDastDeadlineSeconds(out.ClaimTimeoutSeconds)
		out.DastDeadlineSeconds = &derived
		return out, nil
	}
	configured := *p.DastDeadlineSeconds // already checked positive above
	out.DastDeadlineSeconds = &configured
	return out, nil
}

// ClaimTimeout returns the resolved claim window as a Duration. It resolves
// first, so it is safe on a zero-valued policy; an invalid policy yields 0.
func (p DeadlinePolicy) ClaimTimeout() time.Duration {
	r, err := p.Resolve()
	if err != nil {
		return 0
	}
	return time.Duration(r.ClaimTimeoutSeconds) * time.Second
}

// DastDeadline returns the resolved DAST budget and whether there is one at
// all. ok is false when DAST is disabled — the Tier S common case — and when
// the policy is invalid.
func (p DeadlinePolicy) DastDeadline() (time.Duration, bool) {
	r, err := p.Resolve()
	if err != nil || r.DastDeadlineSeconds == nil {
		return 0, false
	}
	return time.Duration(*r.DastDeadlineSeconds) * time.Second, true
}

// AuditConfig projects this policy plus an audit identity and a scan start
// onto the record.AuditConfig that record.Sealer.BeginAudit consumes.
//
// It exists so that no caller in this package ever populates a
// record.AuditConfig field by field. That is the shape in which the deadline
// fields could drift from the ones this file computes, and R.6 owns the
// resulting `audit_record` columns.
//
// BeginAudit computes `deadline_at` itself, once, via record.ComputeDeadline.
// This method does not pass a deadline; it passes the inputs. Deadlines.At
// computes the same instant for scheduling purposes, by calling the same
// record.ComputeDeadline — there is one formula, in record, and this package
// holds no copy of it.
func (p DeadlinePolicy) AuditConfig(auditID string, startedAt time.Time) (record.AuditConfig, error) {
	r, err := p.Resolve()
	if err != nil {
		return record.AuditConfig{}, err
	}
	if startedAt.IsZero() {
		return record.AuditConfig{}, &PolicyError{
			Field: "startedAt", Value: "0001-01-01T00:00:00Z",
			Reason: "both clocks are anchored to scan_run.started_at and cannot be computed from the zero time",
			Err:    ErrZeroScanStart,
		}
	}
	return record.AuditConfig{
		AuditID:             auditID,
		StartedAt:           startedAt,
		ClaimTimeoutSeconds: r.ClaimTimeoutSeconds,
		DastEnabled:         r.DastEnabled,
		DastDeadlineSeconds: r.DastDeadlineSeconds,
	}, nil
}

// At fixes both scan-scoped clocks against one scan start. Call it ONCE, at
// scan start, alongside record.Sealer.BeginAudit; the returned Deadlines is
// immutable by construction and nothing in this package recomputes it.
func (p DeadlinePolicy) At(startedAt time.Time) (Deadlines, error) {
	r, err := p.Resolve()
	if err != nil {
		return Deadlines{}, err
	}
	if startedAt.IsZero() {
		return Deadlines{}, &PolicyError{
			Field: "startedAt", Value: "0001-01-01T00:00:00Z",
			Reason: "both clocks are anchored to scan_run.started_at and cannot be computed from the zero time",
			Err:    ErrZeroScanStart,
		}
	}

	d := Deadlines{
		startedAt:           startedAt,
		deadlineAt:          record.ComputeDeadline(startedAt, r.ClaimTimeoutSeconds),
		claimTimeoutSeconds: r.ClaimTimeoutSeconds,
	}
	// ONE FORMULA PER CLOCK, AND BOTH LIVE IN record. Clock 3's is
	// record.ComputeDastDeadline, the exact analogue of record.ComputeDeadline,
	// and the same function record.Sealer.SealDastIfDeadlineDue decides against.
	// Computing `startedAt + secs` here instead would be a second copy of a
	// formula whose whole point is that the Sealer and every derived view agree
	// to the nanosecond.
	if at, ok := record.ComputeDastDeadline(startedAt, r.DastDeadlineSeconds); ok {
		d.dastDeadlineAt = at
		d.hasDastDeadline = true
		d.dastDeadlineSeconds = *r.DastDeadlineSeconds
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// Deadlines — the two fixed instants, computed once at scan start
// ---------------------------------------------------------------------------

// Deadlines is one audit's pair of scan-scoped deadline instants, fixed at
// scan start and never recomputed.
//
// THE ONLY WAY TO CHANGE A DEADLINE IS TO START A NEW SCAN. No seal, no write,
// no publication, no consumer read and no GitHub round-trip moves either
// instant. internal/record enforces the same rule on the durable side and has a
// test named for it — TestDeadlineUnchangedByLateSeal — and
// record.Sealer.BeginAudit refuses a second BeginAudit for the same audit id
// precisely because re-beginning would recompute `deadline_at`. This type
// agrees with that rule rather than restating it.
//
// # EVERY FIELD IS UNEXPORTED, AND THAT IS THE ENFORCEMENT
//
// The previous version of this type made the claim above in a doc comment and
// then exported all five fields. CRITIQUE O.4 blocker 2 is what that cost: the
// argument offered was that Deadlines "is a value … and there is no method on
// it that mutates anything", which is true of methods and irrelevant to fields.
// A tick handler moved clock 3 with one assignment, the forced DAST seal did
// not fire, and nothing anywhere reported it.
//
// So the fields are unexported and DeadlinePolicy.At is the only producer.
// A composite literal in another package cannot set them — that is a compile
// error, not a convention — and this package's own code has no reason to. The
// accessors below are the whole surface. There are no pointer fields either, so
// two copies of a Deadlines can never share a mutable instant; the struct is
// comparable with ==.
//
// # AND THE INSTANTS STILL DO NOT DECIDE ANYTHING
//
// Unassignable is not the same as authoritative. Both instants here are DERIVED
// COPIES carried for SCHEDULING (when should the daemon next wake) and for
// DIAGNOSTICS. Neither is consulted by a due-check: clock 2's is
// record.Sealer.ExpireIfDue in memory and handoff.Queue.ExpireClaimTimeouts in
// the store, and clock 3's is record.Sealer.SealDastIfDeadlineDue. All three
// decide against the Sealer's own private `startedAt` plus the offsets
// BeginAudit fixed, which is why probe P10 could not fool clock 2 and can no
// longer fool clock 3.
type Deadlines struct {
	// startedAt is `scan_run.started_at`, the shared anchor. Kept so both
	// deadlines are auditable arithmetic rather than opaque instants.
	startedAt time.Time

	// deadlineAt is `audit_record.deadline_at` — clock 2 — as computed by
	// record.ComputeDeadline.
	deadlineAt time.Time

	// dastDeadlineAt is clock 3, as computed by record.ComputeDastDeadline.
	// hasDastDeadline is false when DAST is disabled — the Tier S common case
	// — in which case there is no DAST half to force terminal and no clock 3
	// at all. A bool rather than a *time.Time so the struct stays comparable
	// and carries nothing a copy could share.
	dastDeadlineAt  time.Time
	hasDastDeadline bool

	// claimTimeoutSeconds and dastDeadlineSeconds are the resolved offsets
	// that produced the instants above, carried so a caller writing
	// `audit_record` never has to reverse the subtraction.
	// dastDeadlineSeconds is meaningful only when hasDastDeadline.
	claimTimeoutSeconds int
	dastDeadlineSeconds int
}

// StartedAt is `scan_run.started_at`: the one anchor both clocks are measured
// from. The zero Deadlines returns the zero time, which is what an audit that
// never went through DeadlinePolicy.At has.
func (d Deadlines) StartedAt() time.Time { return d.startedAt }

// DeadlineAt is clock 2's instant, `audit_record.deadline_at`.
//
// IT IS NOT THE AUTHORITY ON EXPIRY. record.Sealer.ExpireIfDue owns that in
// memory and handoff.Queue.ExpireClaimTimeouts owns it in the store, and this
// package deliberately offers no third predicate that would let a caller decide
// expiry from this value.
func (d Deadlines) DeadlineAt() time.Time { return d.deadlineAt }

// ClaimTimeoutSeconds is the resolved offset behind DeadlineAt.
func (d Deadlines) ClaimTimeoutSeconds() int { return d.claimTimeoutSeconds }

// DastDeadlineSeconds is the resolved offset behind clock 3, and whether there
// is one. ok is false exactly when DAST is disabled for this audit.
func (d Deadlines) DastDeadlineSeconds() (int, bool) {
	if !d.hasDastDeadline {
		return 0, false
	}
	return d.dastDeadlineSeconds, true
}

// due is the single "has this instant arrived" comparison in this file.
//
// It is INCLUSIVE of the instant itself, which is the same comparison
// record.Sealer.ExpireIfDue makes (`if s.now().Before(a.deadlineAt) { return
// false }`) and the same one handoff.Queue.ExpireClaimTimeouts makes (`if
// now.Before(c.deadline) { skip }`). Writing it once here means this package
// cannot drift half a tick away from either of them.
func due(now, at time.Time) bool { return !now.Before(at) }

// DastDeadline returns clock 3's instant and whether there is one.
//
// ok is false exactly when DAST is disabled for this audit. A caller that
// treats !ok as "the deadline has not arrived yet" has inverted the meaning:
// the correct reading is "this installation has no DAST half", and
// record.Sealer.BeginAudit has already sealed that half as
// record.HalfStatusSkipped.
func (d Deadlines) DastDeadline() (time.Time, bool) {
	if !d.hasDastDeadline {
		return time.Time{}, false
	}
	return d.dastDeadlineAt, true
}

// THERE IS NO DastDeadlineElapsed, AND THERE MUST NOT BE ONE AGAIN.
//
// This type used to carry `DastDeadlineElapsed(now)` and to call it "THE ONE
// DUE-CHECK THIS PACKAGE OWNS". CRITIQUE O.4 blocker 2 found what that was
// worth: the predicate read `DastDeadlineAt`, an exported field on the caller's
// own copy, so clock 3 could be moved by assignment and the forced seal simply
// never fired — while clock 2, asked the same way, was unfoolable because
// record.Sealer.ExpireIfDue decides against a copy the Sealer keeps privately.
//
// The due-check now lives in the same place the authoritative inputs do:
// record.Sealer.SealDastIfDeadlineDue, the exact analogue of ExpireIfDue,
// deciding against the audit's own `startedAt + dast_deadline_seconds` as fixed
// at BeginAudit. It also performs the seal, so there is no window in which a
// caller has been told "due" and has not yet acted, and no second opinion about
// what "due" means.
//
// A predicate here would be a THIRD owner for a clock that has two (memory and
// store), over an input nobody re-reads. If a future author wants one, the
// question to answer first is what substrate it would decide against —
// deadlines.go has none, by design.

// DastDeadlineBinds reports whether clock 3 fires strictly before clock 2 —
// the relation that makes a timed-out DAST half land as a SEAL rather than as
// an expiry.
//
// It is TRUE at the shipped defaults (4h < 8h) and true for any policy that
// takes DefaultDastDeadlineSeconds. It is FALSE when an operator configures a
// DAST deadline at or beyond the claim window, which the schema permits
// (ck_audit_record_dast_deadline_positive checks only positivity) and which
// this package therefore does not reject.
//
// NOT REJECTING IT IS A DELIBERATE CHOICE, and this is the argument. A policy
// layer that refuses a config the frozen schema accepts becomes a second,
// stricter definition of what a legal audit is — the exact defect class
// IMPLEMENTATION-PLAN.md §6 catalogues — and the operator who set it may have
// meant it. What such a policy costs is real and should be logged, not
// silently absorbed: the DAST half will never be forced terminal, so a
// never-terminating DAST run leaves the audit in record.StateSastSealed until
// clock 2 expires it, and the SAST findings are then lost to the claim window
// rather than handed over. Callers should surface a warning; the controller
// must not fail the scan over it.
func (d Deadlines) DastDeadlineBinds() bool {
	at, ok := d.DastDeadline()
	return ok && at.Before(d.deadlineAt)
}

// ExceedsGitHubHostedJobCap reports whether the claim window is longer than
// GitHubHostedJobCap — the arithmetic behind Constraint Resolution (a).
//
// At the shipped defaults it is TRUE (8h > 6h), and that is not a
// misconfiguration to be corrected: it is the fact that forces the thin
// Action / fat daemon split. A GitHub-hosted job cannot outlive the claim
// window, so it must never try to; the Action fires and returns, and the two
// durations stop measuring the same interval.
//
// It is a DIAGNOSTIC. Nothing in Anvil may shorten a claim window to make this
// false, and nothing may branch on it to decide whether to block — the Action
// never blocks either way, for the independent reason in research/21 §5 reason
// 1 that blocking spends the owner's own claim budget.
func (d Deadlines) ExceedsGitHubHostedJobCap() bool {
	return d.deadlineAt.Sub(d.startedAt) > GitHubHostedJobCap
}

// RemainingClaimWindow reports how much of the claim window is left at now,
// clamped at zero once the window has closed.
//
// It is the budget input plan/00-SPINE.md S6's ordering rule needs — "re-cut
// the work queue on every version bump and reserve a configurable fraction
// (default 50%) of remaining budget for late DAST-confirmed arrivals" — and it
// is arithmetic, not a decision. A zero return does NOT by itself mean the
// audit has expired; record.Sealer.ExpireIfDue and
// handoff.Queue.ExpireClaimTimeouts decide that, and a live claim is never
// expired out from under its holder (research/08 §4 point 2, enforced in
// internal/handoff).
func (d Deadlines) RemainingClaimWindow(now time.Time) time.Duration {
	if remaining := d.deadlineAt.Sub(now); remaining > 0 {
		return remaining
	}
	return 0
}

// NextWake returns the earliest of the two deadline instants that has not yet
// arrived, for a daemon timer to sleep until. ok is false when both have
// arrived and there is nothing left to wait for.
//
// IT IS A SCHEDULING ANSWER, NOT A DECISION. Waking at the returned instant is
// what gives the controller the opportunity to act; what it then does is
// decided by the owners of each clock — record.Sealer.ExpireIfDue for clock 2
// and record.Sealer.SealDastIfDeadlineDue for clock 3, both driven by O.2's
// EventKindTick. A caller
// that infers "the returned instant is the DAST deadline, therefore the DAST
// half is not yet timed out" has substituted a scheduling hint for a due-check
// and will be wrong whenever the timer fires late, which on a
// resource-governed host (research/21 §E) is routine.
func (d Deadlines) NextWake(now time.Time) (time.Time, bool) {
	candidates := []time.Time{d.deadlineAt}
	if at, ok := d.DastDeadline(); ok {
		candidates = append(candidates, at)
	}

	next := time.Time{}
	found := false
	for _, at := range candidates {
		if at.IsZero() || due(now, at) {
			continue
		}
		if !found || at.Before(next) {
			next, found = at, true
		}
	}
	return next, found
}
