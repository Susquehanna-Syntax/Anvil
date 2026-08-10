// Package reconcile owns A.15: the WEEKLY FULL-BASELINE SELF-HEAL.
//
// This is step A.15 of plan/20-lane-a-ingestion-sca.md. Lane A is the
// zero-inference half of Anvil (plan/00-SPINE.md S1): CVE/OSV/GHSA describe
// vulnerable PACKAGE VERSIONS and a version comparator answers that exactly
// and for free. Nothing here infers anything, calls a model, ranks anything,
// or emits a fingerprint. Every decision below is a documented rule over two
// row sets.
//
// # Why a periodic full baseline exists at all
//
// research/06 Recommendation §3: "cvelistV5 full baseline weekly as the
// self-heal (catches anything the delta pipeline dropped)."
//
// A delta stream DRIFTS. A missed delta, a malformed record, a 200 that
// arrived truncated, a batch that failed after the cursor moved — any one of
// them leaves the cache subtly wrong FOREVER, with nothing anywhere surfacing
// it. Nothing in the incremental path can detect its own gap: the cursor is
// derived from the rows, so a row that never arrived has no cursor entry to
// look wrong. That is the same failure shape as fingerprint drift (spine S6),
// and the answer is the same one: periodically rebuild from ground truth and
// DIFF, rather than trusting the incremental path to have been complete.
//
// # This package REPORTS. A silent self-heal is indistinguishable from one
// that never ran.
//
// If the fresh baseline disagrees with the delta-built cache, that
// disagreement is a signal ABOUT THE DELTA PATH and it must be visible.
// ReconcileReport therefore carries, separately and by name: how many rows
// matched, how many the live cache was missing, how many it held at an older
// version, how many diverged at the SAME version, how many it held that ground
// truth does not have, and how many were actually written back. It also
// carries a bounded sample of the disagreeing keys, because a count tells an
// operator that the delta path is dropping records and a sample tells them
// which ones, which is the difference between an alert and a diagnosis.
//
// # The baseline is built in a SCRATCH DATABASE, never into the live cache
//
// This is the design decision the whole package rests on. A.8's Bootstrap
// writes rows; if it wrote them into the live cache, the repair would BE the
// import and there would be nothing left to diff — a self-heal that cannot
// report what it healed, which is precisely the thing this package exists to
// avoid. So the fresh baseline is imported into a throwaway cache file, the
// two row sets are merge-joined, and only then are repairs applied to the live
// cache through A.14's row-scoped write path.
//
// # What it will and will not write
//
// The repair is RESTORE-ONLY and NEVER-REGRESS:
//
//   - a key ground truth has and the live cache lacks is RESTORED. This is the
//     packet's headline case: the record the delta pipeline silently dropped.
//   - a key both hold, where ground truth's `modified` is strictly newer, is
//     RESTORED. The delta path missed an update.
//   - a key both hold at the SAME (or an unparseable) `modified` whose bytes
//     differ is RESTORED. The live row is corrupt at a version ground truth
//     can state exactly.
//   - a key both hold where THE LIVE CACHE IS NEWER is LEFT ALONE and
//     reported. A bulk artifact is cut at an instant; the delta stream is
//     legitimately ahead of it, and overwriting a newer row with the
//     baseline's older bytes would make the self-heal a data-loss event.
//   - a key only the live cache holds is REPORTED AND NEVER DELETED.
//     Withdrawn and REJECTED advisories are tombstoned rather than deleted
//     (A.2 exit criterion 22) and that is A.16's job, not this one. A row that
//     ground truth no longer carries may also simply post-date the artifact.
//
// # Nothing here composes a write shape
//
// Repairs go through delta.Apply — A.14's row-scoped upsert path, behind its
// own statement allowlist. That is deliberate: a second writer for `advisory`
// / `affected` / `advisory_fts` is exactly how a schema invariant survives in
// one writer and not the other, and delta.Record is exported for this reason
// ("A.15's reconciliation writes the same rows through the same path"). It
// also means the FTS index stays query-consistent after a repair for the same
// reason it does after a delta batch, rather than for a new reason nobody
// tested. This package therefore issues NO INSERT, REPLACE or UPDATE against
// those three tables, and no DDL of any kind: its own statement allowlist
// holds four statements, three of them SELECTs.
//
// # The two gates, unchanged
//
//   - A.4's licence gate runs FIRST, before a byte is fetched, exactly as it
//     does in A.8. A refusal ends the pass with no request made and no row
//     written. The gate is resolved HERE as well as inside Bootstrap because
//     delta.Apply takes the decision as a parameter rather than looking it up;
//     the two resolutions are cross-checked against each other afterwards and
//     a disagreement is a refusal, so "two answers to one question" is a
//     detected condition rather than a latent one.
//   - A.3's sanitizer runs inside delta.Decode on every string projected out
//     of a baseline document, and delta.Apply re-checks the whole bind set
//     with sanitize.AssertAllSanitized immediately before the parameters reach
//     the driver. raw_json is the one deliberate exception, as it is
//     everywhere else in Lane A: CVE-TOU obliges Anvil to store records
//     byte-verbatim.
//
// # A failed self-heal is LOUD
//
// A.15's packet: "Do not skip reconciliation silently on a bootstrap failure —
// a failed weekly self-heal must increment feed_state.consecutive_failures and
// surface via A.16's staleness mechanism, not fail closed and disappear." So a
// bootstrap that errored, an import that did not complete, and a baseline that
// imported zero records all increment that counter in the LIVE cache and are
// named in the report. See recordFailure for the one case that deliberately
// does not increment it, and why.
package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/bootstrap"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

const (
	// DefaultMaxSamples bounds how many disagreeing keys the report carries.
	//
	// A report is read by a person. Sixty-four keys is enough to see the shape
	// of a drift — one ecosystem, one date range, one publisher — and small
	// enough that a catastrophic diff produces a report rather than a second
	// copy of the cache. The COUNTS are never truncated; only the sample is,
	// and Truncated says so.
	DefaultMaxSamples = 64

	// DefaultRepairBatch is how many restored records are committed per
	// delta.Apply transaction. Apply is one transaction, so this is the unit
	// of work a crash can lose; every write in it is an idempotent upsert
	// keyed on (source, source_id), so re-running loses nothing but time.
	DefaultRepairBatch = 200

	// MaxRepairBatch is the ceiling on Options.RepairBatch. delta.Apply
	// refuses a batch over its own MaxBatchRecords on the grounds that a batch
	// that size is a bulk import taking the wrong door; this keeps the refusal
	// from ever being reached by a configuration mistake here.
	MaxRepairBatch = 5000
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrReconcile is satisfied by errors.Is for every refusal this package
	// raises, so a caller that only needs "did the self-heal happen" needs one
	// check.
	ErrReconcile = errors.New("reconcile: refused")

	// ErrNotConfigured reports a Healer missing something it cannot invent:
	// the live cache handle, the feed row, a working directory, or the
	// baseline factory.
	ErrNotConfigured = errors.New("reconcile: healer is not configured")

	// ErrNoBaselineMechanism reports a feed whose bootstrap_mechanism imports
	// nothing — `none` or `incremental_api`. Running a "full baseline" against
	// one of those produces an EMPTY ground truth, against which every row the
	// live cache holds looks like a row ground truth does not have. That is
	// not a drift report, it is a false alarm the size of the cache, so it is
	// refused rather than reported.
	ErrNoBaselineMechanism = errors.New("reconcile: the feed's bootstrap_mechanism imports no bulk baseline")

	// ErrEmptyBaseline reports a bootstrap that completed and wrote no rows.
	// A full baseline of a CVE feed that holds zero advisories is a broken
	// artifact, not ground truth about an empty world, and diffing against it
	// would report the entire live cache as unexplained.
	ErrEmptyBaseline = errors.New("reconcile: the fresh baseline imported no records")

	// ErrIncompleteBaseline reports a bootstrap that stopped part-way. A
	// partial import is a PREFIX of ground truth: the keys it is missing are
	// indistinguishable from keys the publisher dropped, so the "only in the
	// live cache" count would be fiction. The pass refuses to diff rather than
	// publish a number it cannot defend.
	ErrIncompleteBaseline = errors.New("reconcile: the fresh baseline did not complete")

	// ErrDecisionMismatch reports that the licence decision this package
	// resolved and the one A.8 resolved inside the bootstrap disagree about
	// the tier or the output directory. Both read the same feed row through
	// the same function, so a disagreement means the two mirrors differ — and
	// writing rows under whichever answer happened to be in hand is how an
	// unadmitted body reaches the cache.
	ErrDecisionMismatch = errors.New("reconcile: the licence gate answered differently for the same feed")

	// ErrBaselineFailed reports a bootstrap that returned an error. The wrapped
	// error is A.8's own.
	ErrBaselineFailed = errors.New("reconcile: building the fresh baseline failed")

	// ErrStatementNotAllowed reports a statement this package tried to execute
	// that is not on its allowlist. See allowedStatements.
	ErrStatementNotAllowed = errors.New("reconcile: statement is not on this package's allowlist")
)

func refuse(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %w", ErrReconcile, fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...))
}

// ---------------------------------------------------------------------------
// The statement allowlist
// ---------------------------------------------------------------------------
//
// A DENYLIST LOSES. This package names every statement it may execute and
// refuses everything else, so that a future edit reaching for a DELETE, a
// DROP, or a rebuild of advisory_fts fails at the call rather than at review.
// Three of the four are read-only; the fourth writes feed_state, whose
// parameters are a feed id, timestamps and counters Anvil itself computes.
//
// NOTE WHAT IS NOT HERE: nothing that writes `advisory`, `affected` or
// `advisory_fts`. Those writes belong to delta.Apply, behind ITS allowlist,
// which is the whole reason this package has no second write shape.

const (
	// scanAdvisorySQL streams one feed's advisory rows in key order, which is
	// what makes the diff a MERGE JOIN with bounded memory rather than two
	// 300,000-entry maps. `source` equals the feed id in both writers (A.8's
	// and A.14's decoders both bind decodeCtx.feedID), so it is the scope of
	// the comparison: the live cache holds many feeds and the baseline holds
	// exactly one.
	scanAdvisorySQL = `SELECT source_id, modified, state, raw_json FROM advisory WHERE source = ? ORDER BY source_id`

	// selectBaselineRecordSQL reads ONE record's bytes back out of the fresh
	// baseline at repair time.
	//
	// It is a single-row statement rather than an `IN (?, ?, ...)` because a
	// variable placeholder count cannot be allowlisted as exact text, and an
	// allowlist that has to accept a statement PREFIX is not an allowlist. The
	// cost is one query per restored row, which is bounded by the number of
	// records the delta path actually dropped.
	//
	// staleness_seconds comes back with it because it is the age A.8 computed
	// from the artifact's own Last-Modified. Re-deriving it here would be a
	// second answer to "how old is this data", and spine S6 requires the field
	// to mean the age of the DATA rather than the age of the write.
	selectBaselineRecordSQL = `SELECT staleness_seconds, raw_json FROM advisory WHERE source = ? AND source_id = ?`
)

var allowedStatements = map[string]string{
	strings.TrimSpace(scanAdvisorySQL): "read-only, feed-scoped, key-ordered scan of one side of the diff. " +
		"ORDER BY source_id is load-bearing: it is what lets the comparison be a streaming merge join.",
	strings.TrimSpace(selectBaselineRecordSQL): "read-only single-record read from the SCRATCH baseline, for a " +
		"record the diff decided to restore.",
	strings.TrimSpace(cache.SelectFeedStateSQL): "read-only feed_state read: the cadence input, and the current " +
		"consecutive_failures a failed pass has to increment.",
	strings.TrimSpace(cache.UpsertFeedStateSQL): "the ONLY write this package issues. It moves " +
		"consecutive_failures and nothing else: etag, last_modified, watermark and last_ok_at are read back " +
		"and written unchanged, because they belong to A.7 and A.8 and a self-heal has no business moving them.",
}

func checkStatement(q string) error {
	if _, ok := allowedStatements[strings.TrimSpace(q)]; ok {
		return nil
	}
	return refuse(ErrStatementNotAllowed,
		"this package may only execute statements on its allowlist and this one is not on it:\n\t%s\n"+
			"If it is a legitimate read, add it to allowedStatements with the reason. If it writes "+
			"advisory, affected or advisory_fts, it does NOT belong here at all: those writes go through "+
			"delta.Apply so that one write path holds the schema invariants for both A.14 and A.15.",
		strings.Join(strings.Fields(q), " "))
}

func queryAllowed(ctx context.Context, db *sql.DB, q string, args ...any) (*sql.Rows, error) {
	if err := checkStatement(q); err != nil {
		return nil, err
	}
	return db.QueryContext(ctx, q, args...)
}

func queryRowAllowed(ctx context.Context, db *sql.DB, q string, args ...any) (*sql.Row, error) {
	if err := checkStatement(q); err != nil {
		return nil, err
	}
	return db.QueryRowContext(ctx, q, args...), nil
}

func execAllowed(ctx context.Context, db *sql.DB, q string, args ...any) error {
	if err := checkStatement(q); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, q, args...)
	return err
}

// ---------------------------------------------------------------------------
// The vocabulary of a disagreement
// ---------------------------------------------------------------------------

// DisagreementKind names one way the fresh baseline and the live cache can
// disagree about a single key.
//
// These are LANE-A-LOCAL vocabulary with no counterpart in the record
// contract's six frozen enums, so declaring them here does not violate
// plan/IMPLEMENTATION-PLAN.md §6's single-owner rule — the same reasoning
// cache.CollectorHost is declared under. They exist so that a caller switches
// on a Go constant rather than on a string literal.
type DisagreementKind string

const (
	// KindMissingInLive is a key the fresh baseline has and the live cache
	// does not hold at all. This is the packet's headline case: the record the
	// delta pipeline silently dropped. It is RESTORED.
	KindMissingInLive DisagreementKind = "missing-in-live"

	// KindStaleInLive is a key both hold where ground truth's `modified` is
	// strictly newer. The delta path missed an update. It is RESTORED.
	KindStaleInLive DisagreementKind = "stale-in-live"

	// KindDivergent is a key both hold at the same — or an unparseable —
	// `modified` whose stored bytes differ. The live row is corrupt at a
	// version ground truth can state exactly. It is RESTORED.
	//
	// An unparseable timestamp on either side lands here rather than in
	// KindAheadInLive ON PURPOSE: a comparison that cannot be made must fail
	// toward the publisher's bytes, never toward keeping a row Anvil cannot
	// date.
	KindDivergent DisagreementKind = "divergent-at-same-version"

	// KindAheadInLive is a key both hold where the LIVE cache's `modified` is
	// strictly newer. The delta stream is legitimately ahead of an artifact
	// cut at an earlier instant. It is REPORTED AND LEFT ALONE: restoring it
	// would overwrite a newer record with older bytes, which would make the
	// self-heal a data-loss event.
	KindAheadInLive DisagreementKind = "ahead-in-live"

	// KindOnlyInLive is a key the live cache holds that the fresh baseline
	// does not. It is REPORTED AND NEVER DELETED — withdrawn and REJECTED
	// advisories are tombstoned rather than deleted (A.2 exit criterion 22)
	// and that is A.16's pass, and a row may also simply post-date the
	// artifact. A rising count here is a real signal and it is the operator's
	// to interpret, not this package's to act on.
	KindOnlyInLive DisagreementKind = "only-in-live"
)

// DisagreementKinds returns every kind, in report order. It exists so a test
// or a dashboard enumerates them from one place.
func DisagreementKinds() []DisagreementKind {
	return []DisagreementKind{
		KindMissingInLive, KindStaleInLive, KindDivergent, KindAheadInLive, KindOnlyInLive,
	}
}

// Valid reports whether k is one of the declared kinds.
func (k DisagreementKind) Valid() bool {
	for _, v := range DisagreementKinds() {
		if k == v {
			return true
		}
	}
	return false
}

// Repairable reports whether this kind is one the self-heal writes back.
//
// It is a property of the KIND rather than a branch inside the diff loop, so
// that the diff, the repair and the report cannot disagree about which
// disagreements get fixed.
func (k DisagreementKind) Repairable() bool {
	switch k {
	case KindMissingInLive, KindStaleInLive, KindDivergent:
		return true
	default:
		return false
	}
}

// Disagreement is one sampled key the two row sets disagree about.
type Disagreement struct {
	// SourceID is the advisory's native id within the feed. It is NOT
	// necessarily a CVE id: research/06 Risk #2 keeps the cache off CVE ids as
	// a primary key.
	SourceID string

	// Kind is what kind of disagreement it is.
	Kind DisagreementKind

	// BaselineModified and LiveModified are the two `modified` values as
	// stored, unparsed. They are carried verbatim because the interesting case
	// is usually the one where a timestamp did not parse.
	BaselineModified string
	LiveModified     string

	// Repaired is whether this key was written back. It is false for every
	// non-repairable kind, for every key in a report-only pass, and for a key
	// whose baseline record failed to decode.
	Repaired bool

	// Note carries the reason when a repairable key was not repaired.
	Note string
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

// ReconcileReport is what one self-heal found. It is returned on every path
// including the refusals, because "the licence gate said no", "the baseline
// failed to build" and "the caches agree" must not look alike to a caller
// reading a repair count.
//
// A.15's packet names the counts as {new, updated, matched,
// missing-in-live-cache}. Two of those four are ONE quantity: a key the fresh
// baseline has and the live cache does not is both "new to the live cache" and
// "missing in the live cache". This report keeps ONE field for it —
// MissingInLive — rather than two that could drift apart, and adds the counts
// the packet did not name but that a drift report is useless without: the
// direction of a mismatch (stale versus ahead), and the keys the live cache
// holds that ground truth does not. Updated is the packet's fourth name and is
// a METHOD over the two directional counts, so it cannot be set to something
// they do not add up to.
type ReconcileReport struct {
	// FeedID echoes the row this ran for, and RanAt is the pass's own clock.
	FeedID string
	RanAt  time.Time

	// Duration is measured on the injected clock, so a test with a fixed clock
	// reports zero rather than a number that varies per run.
	Duration time.Duration

	// Plan is delta.Due's answer for this feed at RanAt. BaselineDue and
	// BaselineInterval are the fields that decided whether this pass ran, and
	// they come from the feed row's baseline_interval_seconds — there is no
	// weekly constant in this package, because a cadence written as a Go
	// constant is exactly what A.1 forbids.
	Plan delta.Plan

	// Skipped is true when the baseline window has not turned over and Force
	// was not set. It is not an error and the returned error is nil.
	Skipped bool

	// Refused is true when A.4's licence gate declined the feed, and
	// RefusedBecause carries the gate's own sentence. No request was made and
	// no row was written or read.
	Refused        bool
	RefusedBecause string

	// Tier and Dir are A.4's decision as this package resolved it, and they
	// are cross-checked against the one A.8 resolved inside the bootstrap.
	Tier int
	Dir  string

	// Bootstrap is A.8's own result for the fresh baseline: what it
	// transferred, how many entries it read and how many records it wrote.
	// It is the cost side of the pass.
	Bootstrap bootstrap.BootstrapResult

	// BaselinePath is the scratch database the baseline was built in, and is
	// set only when Options.KeepBaseline asked for it to survive the pass.
	BaselinePath string

	// Failed is true when the baseline could not be built or could not be
	// trusted, and FailedBecause says which. FailureRecorded is whether
	// feed_state.consecutive_failures was successfully incremented, and
	// ConsecutiveFailures is the value after the increment — the number A.16's
	// staleness mechanism reads.
	Failed              bool
	FailedBecause       string
	FailureRecorded     bool
	ConsecutiveFailures int

	// BaselineRows and LiveRows are the two row sets' sizes, scoped to this
	// feed's `source`. Their difference is not the drift: a key can be present
	// on both sides and still disagree.
	BaselineRows int
	LiveRows     int

	// The diff, by kind. Every key on either side lands in exactly one of
	// these five, so Matched + MissingInLive + StaleInLive + Divergent +
	// AheadInLive == BaselineRows, and Matched + StaleInLive + Divergent +
	// AheadInLive + OnlyInLive == LiveRows. CheckTotals asserts both.
	Matched       int
	MissingInLive int
	StaleInLive   int
	Divergent     int
	AheadInLive   int
	OnlyInLive    int

	// Restored is advisory rows actually written back, as counted BY THE WRITE
	// PATH rather than by the loop that chose them: it is Batch.Upserts. A
	// number produced by the thing being measured is evidence; a number
	// produced by the thing doing the asking is a hope.
	Restored int

	// Batch is delta.Apply's own accounting for every repair transaction:
	// advisory upserts, row-scoped FTS writes, affected and alias rows. Its
	// FTSUpserts + FTSDeletes is the TOTAL number of statements that touched
	// advisory_fts, and there is no other one.
	Batch delta.BatchStats

	// RepairFailures counts repairable keys whose baseline record could not be
	// decoded. One malformed record in ground truth must not block restoring
	// the rest, so it is counted, sampled and carried on.
	RepairFailures int

	// Sanitize is the merged A.3 report over every baseline document decoded
	// during the repair. A non-zero count is not an error; it is the ordinary
	// state of text written by strangers.
	Sanitize sanitize.SanitizeStats

	// ReportOnly echoes the option: the pass diffed and deliberately wrote
	// nothing.
	ReportOnly bool

	// Samples is a bounded sample of disagreeing keys, in scan order, and
	// SamplesTruncated says the sample stopped before the disagreements did.
	// The COUNTS above are never truncated.
	Samples          []Disagreement
	SamplesTruncated bool

	// Note is a sentence for an operator when the outcome needs one.
	Note string
}

// Updated is A.15's packet's fourth count: keys present on both sides that the
// self-heal had to rewrite. It is derived rather than stored so that it cannot
// disagree with the two directional counts it is made of.
func (r ReconcileReport) Updated() int { return r.StaleInLive + r.Divergent }

// Disagreements is every key that was not an exact match, in either direction,
// including the ones this pass deliberately did not touch.
func (r ReconcileReport) Disagreements() int {
	return r.MissingInLive + r.StaleInLive + r.Divergent + r.AheadInLive + r.OnlyInLive
}

// Drifted reports whether the delta-built cache and ground truth disagreed
// about anything at all.
//
// It is the one boolean a daemon should alert on. A self-heal that repaired
// three records is not a success story; it is evidence that the delta path
// dropped three records and will drop more.
func (r ReconcileReport) Drifted() bool { return r.Disagreements() > 0 }

// CheckTotals verifies that every key on either side was classified into
// exactly one bucket.
//
// It is exported because it is the arithmetic that makes the report readable
// as a partition rather than as five loosely related counters, and a caller
// logging the report can assert it for free. A failure means the diff has a
// bug, not that the caches disagree.
func (r ReconcileReport) CheckTotals() error {
	if got := r.Matched + r.MissingInLive + r.StaleInLive + r.Divergent + r.AheadInLive; got != r.BaselineRows {
		return fmt.Errorf("reconcile: the baseline side of the diff accounts for %d of %d rows "+
			"(matched %d, missing-in-live %d, stale-in-live %d, divergent %d, ahead-in-live %d)",
			got, r.BaselineRows, r.Matched, r.MissingInLive, r.StaleInLive, r.Divergent, r.AheadInLive)
	}
	if got := r.Matched + r.StaleInLive + r.Divergent + r.AheadInLive + r.OnlyInLive; got != r.LiveRows {
		return fmt.Errorf("reconcile: the live side of the diff accounts for %d of %d rows "+
			"(matched %d, stale-in-live %d, divergent %d, ahead-in-live %d, only-in-live %d)",
			got, r.LiveRows, r.Matched, r.StaleInLive, r.Divergent, r.AheadInLive, r.OnlyInLive)
	}
	return nil
}

// Summary is one line for an operator's log.
//
// It always names the disagreement counts, including when they are zero: "the
// weekly self-heal ran and found nothing" is the observation that makes every
// other week's number meaningful, and a log line that appears only on drift
// cannot distinguish a healthy pipeline from a pass that stopped running.
func (r ReconcileReport) Summary() string {
	switch {
	case r.Skipped:
		return fmt.Sprintf("self-heal %s: skipped (%s)", r.FeedID, r.Note)
	case r.Refused:
		return fmt.Sprintf("self-heal %s: refused by the licence gate (%s)", r.FeedID, r.RefusedBecause)
	case r.Failed:
		return fmt.Sprintf("self-heal %s: FAILED (%s); consecutive_failures now %d",
			r.FeedID, r.FailedBecause, r.ConsecutiveFailures)
	}
	mode := "repaired"
	if r.ReportOnly {
		mode = "report-only, wrote nothing;"
	}
	return fmt.Sprintf(
		"self-heal %s: baseline %d rows, live %d rows; matched %d, missing-in-live %d, stale-in-live %d, "+
			"divergent %d, ahead-in-live %d, only-in-live %d; %s %d rows (%d repair failures)",
		r.FeedID, r.BaselineRows, r.LiveRows, r.Matched, r.MissingInLive, r.StaleInLive,
		r.Divergent, r.AheadInLive, r.OnlyInLive, mode, r.Restored, r.RepairFailures)
}

// ---------------------------------------------------------------------------
// Baseliner — A.8, as a seam
// ---------------------------------------------------------------------------

// Baseliner builds a full baseline into whatever cache it was constructed
// around. *bootstrap.Bootstrapper satisfies it.
//
// It is an interface for the same reason delta.FeedPoller is one: so that the
// daemon supplies ONE configured bootstrapper — with its HTTP client, its git
// runner, its credential lookup and its mirror — rather than this package
// constructing a second one, which would be a second implementation of A.8's
// size caps, redirect scope and credential rules.
type Baseliner interface {
	Bootstrap(ctx context.Context, feed config.FeedConfig) (bootstrap.BootstrapResult, error)
}

// BaselineFactory hands back a Baseliner bound to the SCRATCH cache handle
// this pass opened.
//
// The factory shape is what keeps the fresh baseline out of the live cache:
// the caller never gets to choose the database, because the whole design
// depends on the import landing somewhere the diff can still see it as
// separate.
type BaselineFactory func(scratch *sql.DB) (Baseliner, error)

// FromBootstrapper turns a configured A.8 bootstrapper into a BaselineFactory
// by copying it and replacing only its DB.
//
// tmpl is taken BY VALUE and copied again per call, so the caller's
// bootstrapper is never mutated and two concurrent self-heals cannot share a
// cache handle.
func FromBootstrapper(tmpl bootstrap.Bootstrapper) BaselineFactory {
	return func(scratch *sql.DB) (Baseliner, error) {
		if scratch == nil {
			return nil, refuse(ErrNotConfigured, "the baseline factory was handed a nil scratch cache")
		}
		b := tmpl
		b.DB = scratch
		return &b, nil
	}
}

// ---------------------------------------------------------------------------
// Healer
// ---------------------------------------------------------------------------

// Options configures a Healer. Live, Feed, WorkDir and Baseline are required.
type Options struct {
	// Live is the A.2 ingestion cache the delta pipeline has been writing to.
	// It is NOT internal/store: that is the audit store of record and nothing
	// here may touch it.
	Live *sql.DB

	// Feed is the row to self-heal. cvelistV5 is the worked example
	// (research/06 Recommendation §3) but nothing here is specific to it.
	Feed config.FeedConfig

	// Mirror is the filesystem A.4 reads pinned licence evidence from. Nil
	// means the process working directory, which is what a daemon wants and
	// what a test must never rely on.
	//
	// It must be the same mirror the Baseline factory's bootstrapper reads,
	// and WeeklySelfHeal cross-checks the two decisions rather than assuming
	// it.
	Mirror fs.FS

	// WorkDir is where the scratch baseline database is created. It must be a
	// real directory on disk: the baseline is the same 570 MB import A.8 does,
	// and it is not held in memory.
	WorkDir string

	// Baseline builds the fresh ground truth into the scratch cache.
	Baseline BaselineFactory

	// Now is the clock. Nil means time.Now.
	Now func() time.Time

	// MaxSamples overrides DefaultMaxSamples. Negative means zero samples.
	MaxSamples int

	// RepairBatch overrides DefaultRepairBatch.
	RepairBatch int

	// Force runs the pass even when the baseline window has not turned over.
	// It is how an operator says "self-heal this feed now", and it is the only
	// thing that overrides the feed row's cadence.
	Force bool

	// ReportOnly diffs and writes nothing. It exists so that an operator can
	// see what a self-heal WOULD do before letting it do it, and so that a
	// drift alarm can run more often than a repair.
	ReportOnly bool

	// KeepBaseline leaves the scratch database on disk and names it in the
	// report. It is for investigating a drift the counts do not explain.
	KeepBaseline bool
}

// Healer runs the weekly full-baseline self-heal for one feed.
//
// It holds no mutable state across passes and is safe for concurrent use
// across DIFFERENT feeds. Two concurrent passes over the SAME feed are not
// useful — they would each build a full baseline — but they are not unsafe,
// because every repair is an upsert keyed on (source, source_id).
type Healer struct {
	live         *sql.DB
	feed         config.FeedConfig
	mirror       fs.FS
	workDir      string
	newBaseline  BaselineFactory
	now          func() time.Time
	maxSamples   int
	repairBatch  int
	force        bool
	reportOnly   bool
	keepBaseline bool
}

// New builds a Healer, refusing anything it cannot invent.
func New(opts Options) (*Healer, error) {
	if opts.Live == nil {
		return nil, refuse(ErrNotConfigured,
			"a self-heal diffs against the live A.2 ingestion cache and needs its handle")
	}
	if strings.TrimSpace(opts.Feed.ID) == "" {
		return nil, refuse(ErrNotConfigured, "a self-heal needs the feed row it is healing")
	}
	if strings.TrimSpace(opts.WorkDir) == "" {
		return nil, refuse(ErrNotConfigured,
			"a self-heal builds the fresh baseline in a scratch database on disk and needs a directory "+
				"for it; the baseline is the same bulk import A.8 does and is not held in memory")
	}
	if opts.Baseline == nil {
		return nil, refuse(ErrNotConfigured,
			"a self-heal needs A.8's bootstrap to build ground truth. This package will not construct "+
				"one: an HTTP client, a credential lookup and a mirror built here would be a second "+
				"implementation of A.8's size caps, redirect scope and licence gate")
	}
	h := &Healer{
		live:         opts.Live,
		feed:         opts.Feed,
		mirror:       opts.Mirror,
		workDir:      opts.WorkDir,
		newBaseline:  opts.Baseline,
		now:          opts.Now,
		maxSamples:   opts.MaxSamples,
		repairBatch:  opts.RepairBatch,
		force:        opts.Force,
		reportOnly:   opts.ReportOnly,
		keepBaseline: opts.KeepBaseline,
	}
	if h.now == nil {
		h.now = time.Now
	}
	if opts.MaxSamples == 0 {
		h.maxSamples = DefaultMaxSamples
	}
	if h.maxSamples < 0 {
		h.maxSamples = 0
	}
	if h.repairBatch <= 0 {
		h.repairBatch = DefaultRepairBatch
	}
	if h.repairBatch > MaxRepairBatch {
		return nil, refuse(ErrNotConfigured,
			"RepairBatch %d exceeds %d; delta.Apply is one transaction per batch and a batch that size "+
				"is a bulk import taking the wrong door", h.repairBatch, MaxRepairBatch)
	}
	return h, nil
}

// WeeklySelfHeal is A.15's entry point: `WeeklySelfHeal(ctx) (ReconcileReport,
// error)`.
//
// THE ORDER OF WHAT FOLLOWS IS THE CONTRACT:
//
//  1. the feed row's baseline cadence is consulted   (no network, pure)
//  2. the bootstrap mechanism is checked for one that imports a baseline
//  3. A.4's LICENCE GATE runs — before a byte is fetched, so a feed with no
//     acquired licence body costs no bytes at all
//  4. a SCRATCH cache is opened and migrated
//  5. A.8 imports the full baseline INTO THE SCRATCH CACHE
//  6. the baseline is checked for being trustworthy at all: complete, and not
//     empty. A prefix of ground truth is not ground truth.
//  7. the two row sets are merge-joined in key order and classified
//  8. repairable disagreements are written back through A.14's row-scoped
//     upsert path, in batches
//
// Steps 1-3 and 6 all end the pass without writing. Step 6's failures — and a
// failure in step 5 — increment feed_state.consecutive_failures so that A.16's
// staleness mechanism sees them; see recordFailure.
//
// A non-nil error is returned WITH a populated ReconcileReport, never instead
// of one.
// The results are NAMED so that the deferred Duration write lands in the value
// the caller receives. With unnamed results the deferred assignment would
// mutate a local nobody ever reads again, and every report would carry a zero
// duration that looked like a measurement.
func (h *Healer) WeeklySelfHeal(ctx context.Context) (rep ReconcileReport, err error) {
	started := h.now().UTC()
	rep = ReconcileReport{
		FeedID:     h.feed.ID,
		RanAt:      started,
		ReportOnly: h.reportOnly,
		Tier:       license.NoTier,
	}
	defer func() { rep.Duration = h.now().UTC().Sub(started) }()

	// --- 1. Is it due? The cadence comes from the feed row and nowhere else.
	lastOK, err := h.lastSuccess(ctx)
	if err != nil {
		return rep, err
	}
	rep.Plan = delta.Due(h.feed, lastOK, started)
	if !rep.Plan.BaselineDue && !h.force {
		rep.Skipped = true
		switch {
		case !h.feed.Enabled:
			rep.Note = "the feed row is disabled; nothing about it is scheduled"
		case rep.Plan.BaselineInterval <= 0:
			rep.Note = "the feed row schedules no full-baseline self-heal " +
				"(baseline_interval_seconds is zero)"
		default:
			rep.Note = fmt.Sprintf(
				"the last success at %s falls in the same %s baseline window as %s",
				lastOK.UTC().Format(time.RFC3339), rep.Plan.BaselineInterval,
				started.Format(time.RFC3339))
		}
		return rep, nil
	}

	// --- 2. Does this feed HAVE a baseline to re-import?
	switch h.feed.BootstrapMechanism {
	case config.BootstrapBulkArchive, config.BootstrapBloblessClone:
	default:
		return rep, refuse(ErrNoBaselineMechanism,
			"feed %q declares bootstrap_mechanism %q, which imports no records. A full-baseline diff "+
				"against an empty ground truth would report every row the live cache holds as "+
				"unexplained, which is a false alarm the size of the cache",
			h.feed.ID, h.feed.BootstrapMechanism)
	}

	// --- 3. The licence gate, before a byte is fetched.
	decision, err := license.Resolve(license.FromFeed(h.feed, "", h.mirror))
	if err != nil {
		rep.Refused, rep.RefusedBecause = true, err.Error()
		return rep, fmt.Errorf("%w: feed %q: %w", ErrReconcile, h.feed.ID, err)
	}
	if decision.Refused() {
		rep.Refused = true
		rep.RefusedBecause = "the licence gate returned a refusal without an error"
		return rep, refuse(license.ErrLicenseRefused, "feed %q: %s", h.feed.ID, rep.RefusedBecause)
	}
	rep.Tier, rep.Dir = decision.Tier.Int(), decision.Dir

	// --- 4. The scratch cache. The fresh baseline never touches the live one.
	scratchDir, err := os.MkdirTemp(h.workDir, "anvil-baseline-")
	if err != nil {
		return rep, fmt.Errorf("reconcile: creating a scratch directory for feed %q: %w", h.feed.ID, err)
	}
	keep := h.keepBaseline
	defer func() {
		if !keep {
			_ = os.RemoveAll(scratchDir)
		}
	}()
	scratchPath := filepath.Join(scratchDir, "anvil-baseline.sqlite")
	if keep {
		rep.BaselinePath = scratchPath
	}
	scratch, err := cache.Open(ctx, scratchPath)
	if err != nil {
		return rep, fmt.Errorf("reconcile: opening the scratch baseline cache for feed %q: %w", h.feed.ID, err)
	}
	defer func() { _ = scratch.Close() }()
	if _, err := cache.Migrate(ctx, scratch); err != nil {
		return rep, fmt.Errorf("reconcile: migrating the scratch baseline cache for feed %q: %w", h.feed.ID, err)
	}

	// --- 5. Build ground truth.
	builder, err := h.newBaseline(scratch)
	if err != nil {
		return rep, err
	}
	if builder == nil {
		return rep, refuse(ErrNotConfigured, "the baseline factory returned no Baseliner for feed %q", h.feed.ID)
	}
	res, bootErr := builder.Bootstrap(ctx, h.feed)
	rep.Bootstrap = res

	// --- 6. Is the baseline trustworthy enough to diff against?
	switch {
	case bootErr != nil:
		return h.fail(ctx, &rep, fmt.Errorf("%w: feed %q: %w", ErrBaselineFailed, h.feed.ID, bootErr))
	case !res.Complete:
		return h.fail(ctx, &rep, refuse(ErrIncompleteBaseline,
			"feed %q: the import stopped after %d entries and %d records. A partial baseline is a PREFIX "+
				"of ground truth: the keys it is missing cannot be told apart from keys the publisher "+
				"dropped, so every 'only in the live cache' count derived from it would be fiction",
			h.feed.ID, res.EntriesRead, res.RecordsUpserted))
	case res.RecordsUpserted == 0:
		return h.fail(ctx, &rep, refuse(ErrEmptyBaseline,
			"feed %q: the import completed and wrote no records. That is a broken artifact, not ground "+
				"truth about an empty world", h.feed.ID))
	case res.Tier != decision.Tier.Int() || res.Dir != decision.Dir:
		return h.fail(ctx, &rep, refuse(ErrDecisionMismatch,
			"feed %q: this package resolved tier %d dir %q and the bootstrap resolved tier %d dir %q. "+
				"Both read the same feed row through license.Resolve, so they are reading different "+
				"mirrors, and neither answer may be used to write a row",
			h.feed.ID, decision.Tier.Int(), decision.Dir, res.Tier, res.Dir))
	}

	// --- 7. The diff.
	repairs, err := h.diff(ctx, scratch, &rep)
	if err != nil {
		return rep, err
	}
	if err := rep.CheckTotals(); err != nil {
		return rep, err
	}

	// --- 8. The repair.
	if h.reportOnly {
		rep.Note = "report-only: the disagreements above were found and deliberately not written back"
		return rep, nil
	}
	if err := h.repair(ctx, scratch, decision, repairs, started, &rep); err != nil {
		return rep, err
	}
	// The repair may already have left a note about records it could not
	// restore. It is kept: the closing sentence is context, and the thing that
	// went wrong outranks it.
	if closing := h.closingNote(rep); rep.Note == "" {
		rep.Note = closing
	} else {
		rep.Note = closing + "; " + rep.Note
	}
	return rep, nil
}

// closingNote is the sentence an operator reads when nothing went wrong, and it
// deliberately does not congratulate a pass that repaired rows.
func (h *Healer) closingNote(rep ReconcileReport) string {
	switch {
	case !rep.Drifted():
		return "the delta-built cache and the fresh baseline agree on every row"
	case rep.Restored > 0:
		return fmt.Sprintf(
			"the delta pipeline had dropped or staled %d of %d records for this feed; they were restored "+
				"from the fresh baseline. This is a defect in the delta path, not a success of the "+
				"self-heal", rep.Restored, rep.BaselineRows)
	default:
		return "the two row sets disagree but nothing was repairable: see the ahead-in-live and " +
			"only-in-live counts, which this pass reports and never acts on"
	}
}

// ---------------------------------------------------------------------------
// The diff
// ---------------------------------------------------------------------------

// sideRow is one advisory row of one side, reduced to what the comparison
// needs. raw_json is hashed and discarded as it is read, so peak memory is one
// record and not one cache.
type sideRow struct {
	sourceID string
	modified string
	digest   [sha256.Size]byte
}

// cursor is a one-row-lookahead reader over an ordered scan.
type cursor struct {
	rows  *sql.Rows
	cur   sideRow
	valid bool
	err   error
	seen  int
	// last is the previous key, kept so the scan can prove the ORDER BY it
	// depends on actually held. A merge join over an unordered scan silently
	// produces nonsense, and "the statement says ORDER BY" is not evidence
	// that the rows arrived that way.
	last string
}

func newCursor(rows *sql.Rows) *cursor {
	c := &cursor{rows: rows}
	c.advance()
	return c
}

func (c *cursor) advance() {
	if c.err != nil {
		c.valid = false
		return
	}
	if !c.rows.Next() {
		c.valid = false
		c.err = c.rows.Err()
		return
	}
	var (
		sourceID string
		modified sql.NullString
		state    sql.NullString
		raw      []byte
	)
	if err := c.rows.Scan(&sourceID, &modified, &state, &raw); err != nil {
		c.valid, c.err = false, err
		return
	}
	if c.seen > 0 && sourceID <= c.last {
		c.valid = false
		c.err = fmt.Errorf(
			"reconcile: the advisory scan returned %q after %q; the merge join depends on the "+
				"ORDER BY holding and it did not", sourceID, c.last)
		return
	}
	c.cur = sideRow{sourceID: sourceID, modified: modified.String, digest: contentDigest(state.String, modified.String, raw)}
	c.last = sourceID
	c.seen++
	c.valid = true
}

// contentDigest is the comparison key for "are these two rows the same
// record".
//
// IT IS NOT A FINGERPRINT AND MUST NEVER BE PRESENTED AS ONE. anvil-fp/v1 is
// the one fingerprint algorithm in this system, it is owned by
// internal/record, and FINGERPRINT-SPEC.md is authoritative for it (spine S6:
// two producers emitting different digests under one name breaks regression
// matching forever). This value never leaves this package, is never stored, is
// never compared against anything a record produced, and would be just as
// correct if it were any other collision-resistant hash.
//
// Fields are length-prefixed so that no concatenation of one row can be
// confused with a different concatenation of another.
func contentDigest(state, modified string, raw []byte) [sha256.Size]byte {
	h := sha256.New()
	writeField := func(b []byte) {
		var n [8]byte
		v := uint64(len(b))
		for i := 7; i >= 0; i-- {
			n[i] = byte(v)
			v >>= 8
		}
		_, _ = h.Write(n[:])
		_, _ = h.Write(b)
	}
	writeField([]byte(state))
	writeField([]byte(modified))
	writeField(raw)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// diff merge-joins the two ordered row sets and classifies every key on either
// side into exactly one bucket.
//
// It returns the source_ids to restore, in scan order. It collects KEYS and
// not records on purpose: the repair reads each record's bytes back out of the
// scratch cache afterwards, so that no cursor is open on either database while
// the live cache is being written.
func (h *Healer) diff(ctx context.Context, scratch *sql.DB, rep *ReconcileReport) ([]string, error) {
	baselineRows, err := queryAllowed(ctx, scratch, scanAdvisorySQL, h.feed.ID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: scanning the fresh baseline for feed %q: %w", h.feed.ID, err)
	}
	defer func() { _ = baselineRows.Close() }()

	liveRows, err := queryAllowed(ctx, h.live, scanAdvisorySQL, h.feed.ID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: scanning the live cache for feed %q: %w", h.feed.ID, err)
	}
	defer func() { _ = liveRows.Close() }()

	base := newCursor(baselineRows)
	live := newCursor(liveRows)

	var repairs []string
	for base.valid || live.valid {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch {
		case live.valid && (!base.valid || live.cur.sourceID < base.cur.sourceID):
			rep.LiveRows++
			rep.OnlyInLive++
			h.sample(rep, Disagreement{
				SourceID:     live.cur.sourceID,
				Kind:         KindOnlyInLive,
				LiveModified: live.cur.modified,
				Note: "ground truth does not carry this key; it is reported and never deleted " +
					"(tombstoning is A.16's pass, and the row may simply post-date the artifact)",
			})
			live.advance()

		case base.valid && (!live.valid || base.cur.sourceID < live.cur.sourceID):
			rep.BaselineRows++
			rep.MissingInLive++
			repairs = append(repairs, base.cur.sourceID)
			h.sample(rep, Disagreement{
				SourceID:         base.cur.sourceID,
				Kind:             KindMissingInLive,
				BaselineModified: base.cur.modified,
			})
			base.advance()

		default:
			rep.BaselineRows++
			rep.LiveRows++
			switch kind := classify(base.cur, live.cur); kind {
			case "":
				rep.Matched++
			case KindStaleInLive:
				rep.StaleInLive++
				repairs = append(repairs, base.cur.sourceID)
				h.sample(rep, Disagreement{
					SourceID: base.cur.sourceID, Kind: kind,
					BaselineModified: base.cur.modified, LiveModified: live.cur.modified,
				})
			case KindDivergent:
				rep.Divergent++
				repairs = append(repairs, base.cur.sourceID)
				h.sample(rep, Disagreement{
					SourceID: base.cur.sourceID, Kind: kind,
					BaselineModified: base.cur.modified, LiveModified: live.cur.modified,
					Note: "the two sides carry different bytes at the same (or an undatable) version",
				})
			case KindAheadInLive:
				rep.AheadInLive++
				h.sample(rep, Disagreement{
					SourceID: base.cur.sourceID, Kind: kind,
					BaselineModified: base.cur.modified, LiveModified: live.cur.modified,
					Note: "the live cache is newer than the artifact; restoring would overwrite a newer " +
						"record with older bytes, so this pass leaves it alone",
				})
			}
			base.advance()
			live.advance()
		}
	}
	if base.err != nil {
		return nil, fmt.Errorf("reconcile: reading the fresh baseline for feed %q: %w", h.feed.ID, base.err)
	}
	if live.err != nil {
		return nil, fmt.Errorf("reconcile: reading the live cache for feed %q: %w", h.feed.ID, live.err)
	}
	return repairs, nil
}

// classify decides what kind of disagreement one shared key has, or "" when
// the two sides carry the same record.
//
// The direction test is on the two `modified` timestamps and it is
// deliberately three-armed rather than two:
//
//   - both parse and the live one is later  -> the live cache is AHEAD. Leave
//     it alone. A bulk artifact is cut at an instant and the delta stream is
//     legitimately past it.
//   - both parse and the baseline is later  -> the live cache is STALE. The
//     delta path missed an update.
//   - anything else (equal timestamps, or one that will not parse) ->
//     DIVERGENT, and ground truth wins. A comparison that cannot be made must
//     fail toward the publisher's bytes, because keeping a row Anvil cannot
//     date over a row it fetched from the publisher is the wrong risk to take.
func classify(base, live sideRow) DisagreementKind {
	if base.digest == live.digest {
		return ""
	}
	bt, bok := parseModified(base.modified)
	lt, lok := parseModified(live.modified)
	switch {
	case bok && lok && lt.After(bt):
		return KindAheadInLive
	case bok && lok && bt.After(lt):
		return KindStaleInLive
	default:
		return KindDivergent
	}
}

// parseModified accepts the shapes advisory feeds actually emit and reports
// anything else as undatable rather than coercing it.
//
// The layout list matches internal/ingest/delta's own parseTimestamp, which is
// unexported. That duplication is deliberate and narrow: it is a shared FORMAT
// list rather than a shared judgement, and the two functions answer different
// questions — delta's fails toward re-fetching a record, this one fails toward
// restoring from ground truth. Merging them would give one policy to two
// decisions that legitimately differ.
func parseModified(s string) (time.Time, bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// sample records a disagreement in the bounded sample, and marks the report
// truncated once the bound is reached. The COUNTS are never affected.
func (h *Healer) sample(rep *ReconcileReport, d Disagreement) {
	if len(rep.Samples) >= h.maxSamples {
		rep.SamplesTruncated = true
		return
	}
	rep.Samples = append(rep.Samples, d)
}

// ---------------------------------------------------------------------------
// The repair
// ---------------------------------------------------------------------------

// repair writes the chosen records back into the live cache through
// delta.Apply, in batches.
//
// Nothing here composes a statement against `advisory`, `affected` or
// `advisory_fts`. delta.Apply owns those, behind its own allowlist, and that
// is what keeps the FTS index query-consistent after a repair for the same
// reason it is after a delta batch.
func (h *Healer) repair(
	ctx context.Context,
	scratch *sql.DB,
	decision license.Decision,
	ids []string,
	asOf time.Time,
	rep *ReconcileReport,
) error {
	if len(ids) == 0 {
		return nil
	}
	failed := map[string]string{}
	batch := make([]delta.Record, 0, h.repairBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// staleness is passed as zero because every record carries its own,
		// read from the row A.8 wrote: that is the age of the DATA the
		// artifact's Last-Modified declared, which is what spine S6's
		// staleness_seconds means. delta.Apply's per-record override wins over
		// the batch value, so the batch value is only ever a fallback nothing
		// here needs.
		stats, err := delta.Apply(ctx, h.live, h.feed, decision, batch, asOf, 0)
		rep.Batch.Merge(stats)
		rep.Restored = rep.Batch.Upserts
		batch = batch[:0]
		return err
	}

	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		recs, staleness, err := h.readBaselineRecord(ctx, scratch, id, &rep.Sanitize)
		if err != nil {
			// ONE malformed record in ground truth must not block restoring
			// the rest. It is counted, sampled, and carried past.
			failed[id] = err.Error()
			rep.RepairFailures++
			continue
		}
		for i := range recs {
			if recs[i].StalenessSeconds <= 0 {
				recs[i].StalenessSeconds = staleness
			}
			batch = append(batch, recs[i])
		}
		if len(batch) >= h.repairBatch {
			if err := flush(); err != nil {
				h.markRepairs(rep, failed)
				return err
			}
		}
	}
	if err := flush(); err != nil {
		h.markRepairs(rep, failed)
		return err
	}
	h.markRepairs(rep, failed)
	if rep.RepairFailures > 0 {
		rep.Note = fmt.Sprintf("%d baseline records could not be decoded and were not restored; "+
			"see the samples carrying a note", rep.RepairFailures)
	}
	return nil
}

// markRepairs stamps the sample entries with what actually happened to them.
func (h *Healer) markRepairs(rep *ReconcileReport, failed map[string]string) {
	for i := range rep.Samples {
		if !rep.Samples[i].Kind.Repairable() {
			continue
		}
		if why, bad := failed[rep.Samples[i].SourceID]; bad {
			rep.Samples[i].Note = "the baseline record did not decode and was not restored: " + why
			continue
		}
		rep.Samples[i].Repaired = true
	}
}

// readBaselineRecord reads one record's verbatim bytes out of the scratch
// baseline and decodes them through A.14's decoder — the same decoder the
// delta path uses, so a restored row is byte-for-byte the row a working delta
// path would have written.
//
// A decoded batch that does not contain the key we asked about is refused: a
// repair that writes rows nobody asked for is not a repair.
func (h *Healer) readBaselineRecord(
	ctx context.Context,
	scratch *sql.DB,
	id string,
	acc *sanitize.SanitizeStats,
) ([]delta.Record, int, error) {
	row, err := queryRowAllowed(ctx, scratch, selectBaselineRecordSQL, h.feed.ID, id)
	if err != nil {
		return nil, 0, err
	}
	var (
		staleness int
		raw       []byte
	)
	if err := row.Scan(&staleness, &raw); err != nil {
		return nil, 0, fmt.Errorf("reading baseline record %q: %w", id, err)
	}
	recs, stats, err := delta.Decode(h.feed.ID, raw)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding baseline record %q: %w", id, err)
	}
	found := false
	for _, r := range recs {
		if r.SourceID == id {
			found = true
			break
		}
	}
	if !found {
		return nil, 0, fmt.Errorf("the baseline document stored under %q decoded to %d record(s), none of "+
			"them that key; restoring them would write rows the diff never asked about", id, len(recs))
	}
	// The sanitizer report is merged only for documents that decoded, because
	// a document that did not decode contributed no field to any row. The
	// accumulator is a parameter rather than a field on the Healer so that a
	// pass carries no mutable state on the receiver at all.
	acc.Merge(stats)
	return recs, staleness, nil
}

// ---------------------------------------------------------------------------
// feed_state
// ---------------------------------------------------------------------------

// lastSuccess reads feed_state.last_ok_at from the LIVE cache. It is the same
// durable input delta.Due reads, and reading it from the same column is what
// keeps the two schedulers from disagreeing about when this feed last worked.
//
// A feed with no row has never been polled and everything about it is due. A
// row whose last_ok_at does not parse is treated the same way, deliberately: a
// clock we cannot read must not be allowed to postpone a self-heal forever.
func (h *Healer) lastSuccess(ctx context.Context) (time.Time, error) {
	st, ok, err := h.readFeedState(ctx)
	if err != nil || !ok || !st.lastOK.Valid {
		return time.Time{}, err
	}
	v := strings.TrimSpace(st.lastOK.String)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000000Z"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, nil
}

type feedStateRow struct {
	etag, lastModified, watermark, lastOK sql.NullString
	failures                              int
	tier                                  int
}

func (h *Healer) readFeedState(ctx context.Context) (feedStateRow, bool, error) {
	var st feedStateRow
	row, err := queryRowAllowed(ctx, h.live, cache.SelectFeedStateSQL, h.feed.ID)
	if err != nil {
		return st, false, err
	}
	switch err := row.Scan(&st.etag, &st.lastModified, &st.watermark, &st.lastOK, &st.failures, &st.tier); {
	case errors.Is(err, sql.ErrNoRows):
		return st, false, nil
	case err != nil:
		return st, false, fmt.Errorf("reconcile: reading feed_state for %q: %w", h.feed.ID, err)
	}
	return st, true, nil
}

// fail records a failed self-heal and returns the report and the error.
//
// A.15's packet: a failed weekly self-heal must increment
// feed_state.consecutive_failures and surface via A.16's staleness mechanism,
// "not fail closed and disappear". So the counter moves before the error is
// returned, and whether it moved is itself reported.
func (h *Healer) fail(ctx context.Context, rep *ReconcileReport, cause error) (ReconcileReport, error) {
	rep.Failed = true
	rep.FailedBecause = cause.Error()
	if err := h.recordFailure(ctx, rep); err != nil {
		// The self-heal failed AND the failure could not be recorded. Both are
		// reported; the original cause is the one returned, because it is the
		// one an operator has to fix first.
		rep.Note = "the failure could not be recorded in feed_state either: " + err.Error()
	}
	return *rep, cause
}

// recordFailure increments feed_state.consecutive_failures in the LIVE cache.
//
// It preserves etag, last_modified, watermark and last_ok_at exactly as read.
// Those are A.7's conditional-GET state and A.8's bootstrap cursor, and a
// self-heal has no business moving either: clearing an etag would cost a full
// re-download on the next poll, and clearing a watermark would cost A.8 its
// resume position.
//
// IT DOES NOT RESET THE COUNTER ON SUCCESS, and that is deliberate. The column
// is shared with A.7, which clears it when a poll succeeds. A self-heal that
// zeroed it would erase A.7's record of a failing poll, and a security tool
// that loses its own "this feed is not working" signal is exactly what A.16's
// staleness mechanism exists to prevent.
//
// A LICENCE REFUSAL IS NOT A FAILURE AND DOES NOT REACH HERE. A refusal means
// no publisher licence body has been acquired for this feed, which is the
// ORDINARY state of a fresh clone (see internal/ingest/license's known-limits
// note: the admission path admits nothing at all today). Counting it weekly
// would climb a failure counter on every feed in the table with nothing
// broken, which would make the counter useless for the case it exists for. The
// refusal is reported instead — loudly, on Refused and RefusedBecause, and as
// an error satisfying license.ErrLicenseRefused.
func (h *Healer) recordFailure(ctx context.Context, rep *ReconcileReport) error {
	st, ok, err := h.readFeedState(ctx)
	if err != nil {
		return err
	}
	tier := st.tier
	if !ok {
		// No row yet. license_tier is NOT NULL with a CHECK over (0,1,2,3), so
		// there is no honest value to invent when the gate never admitted this
		// feed. Say so rather than writing a tier nobody decided.
		if rep.Tier < 0 || rep.Tier > 3 {
			return fmt.Errorf("reconcile: feed %q has no feed_state row and no admitted licence tier, "+
				"so there is no row to increment and no honest tier to create one with", h.feed.ID)
		}
		tier = rep.Tier
	}
	next := st.failures + 1
	if err := execAllowed(ctx, h.live, cache.UpsertFeedStateSQL,
		h.feed.ID, nullOf(st.etag), nullOf(st.lastModified), nullOf(st.watermark), nullOf(st.lastOK),
		next, tier); err != nil {
		return fmt.Errorf("reconcile: recording a self-heal failure for %q: %w", h.feed.ID, err)
	}
	rep.FailureRecorded = true
	rep.ConsecutiveFailures = next
	return nil
}

func nullOf(v sql.NullString) any {
	if !v.Valid || strings.TrimSpace(v.String) == "" {
		return nil
	}
	return v.String
}

// SortedSamples returns the report's samples grouped by kind and then by
// source id, which is the order a human reads them in. The report itself keeps
// scan order, because scan order is what makes a clustered drift — one
// ecosystem, one date range — visible at a glance.
func SortedSamples(in []Disagreement) []Disagreement {
	out := append([]Disagreement(nil), in...)
	order := map[DisagreementKind]int{}
	for i, k := range DisagreementKinds() {
		order[k] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Kind] != order[out[j].Kind] {
			return order[out[i].Kind] < order[out[j].Kind]
		}
		return out[i].SourceID < out[j].SourceID
	})
	return out
}
