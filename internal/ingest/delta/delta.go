// Package delta is Lane A step A.14: steady-state delta ingestion.
//
// ===========================================================================
// WHAT THIS PACKAGE IS FOR
// ===========================================================================
//
// A.8 fills the cache once, from a 570 MB bulk archive. A.7 asks "did anything
// change" for the price of a conditional GET. This package is what happens
// BETWEEN those two: when a poll says something changed, it works out the
// cheapest set of bytes that describes the change, decodes them, and upserts
// exactly the rows that moved.
//
// research/06 Recommendation §3, "Steady state per feed, by value density", is
// the whole specification, and its central finding is a cost model:
//
//	"The hourly delta is CUMULATIVE SINCE THE MIDNIGHT BASELINE, not per-hour
//	incremental." Measured: 22 B at 0000Z, 25,882 B at 0100Z, 17,312,299 B at
//	2300Z. "Polling hourly and downloading each delta re-transfers everything
//	already held. Rough integral over a day: ~200 MB/day if polled hourly, vs
//	~17 MB/day if the end-of-day delta is taken once."
//
// So the cheap path is not the delta archive at all. It is `deltaLog.json` —
// "a rolling 30 days worth of CVE record modification history" — polled every
// 15 minutes, which NAMES what changed without carrying it, followed by a fetch
// of only the named records. A.14's packet makes re-downloading the cumulative
// zip on every poll a forbidden action, and PreferDeltaLog below is where that
// preference is made structural rather than advisory.
//
// ===========================================================================
// EVERY CLOCK IN THIS PACKAGE COMES FROM THE FEED TABLE
// ===========================================================================
//
// There is no cadence written in Go here and there must never be one.
// research/06 Recommendation §4: "Every cadence above lives in config, never in
// code", and internal/ingest/config carries three of them per row for exactly
// this step and A.15 — `interval_seconds`, `reconcile_interval_seconds`,
// `baseline_interval_seconds`. A.1's feeds_test.go asserts mechanically that no
// cadence literal appears in its own source; delta_test.go carries the same
// assertion against this file, because the same defect on the CONSUMING side is
// just as fatal and is easier to commit.
//
// Due() is the whole scheduler and it is a PURE FUNCTION of (feed row, last
// success, now). A daemon calls it; nothing in here sleeps, and nothing in here
// knows what a week is.
//
// ===========================================================================
// THE CURSOR IS A QUERY, NOT A COLUMN
// ===========================================================================
//
// feed_state has exactly one cursor column and A.8 already owns it: it writes a
// bootstrap Progress token into `watermark` and hands over through
// bootstrap.Handoff. A second delta cursor squeezed into the same column would
// be two writers on one value.
//
// So the delta cursor is derived from the rows themselves: CachedModified reads
// what the cache holds for one (source, source_id), and a record whose delta
// log entry is not NEWER than that is never fetched. That has a property a
// stored cursor does not — it cannot disagree with the data. A cursor that
// advanced past a failed write would drop the record permanently and silently.
//
// ===========================================================================
// WHAT CROSSES FROM FEED CONTENT INTO A REQUEST, AND WHAT DOES NOT
// ===========================================================================
//
// The deltaLog route reads a document written by strangers and then FETCHES
// THINGS IT NAMES. That is the highest-risk pattern in Lane A: a feed document
// that could choose a URL turns a scheduled background job into a request to
// wherever it likes, with the feed's own credential attached.
//
// Exactly one thing crosses that boundary, and it is a CVE identifier that
// passed IsCVEID — `CVE-` then digits, a dash, then digits, and nothing else.
// It is an ALLOWLIST of structure, not a denylist of dangerous characters:
// this project has lost three guards to a symbol, a verb or a wording nobody
// listed, and `CVE-2024-0001/../../etc/passwd` is precisely the string a
// denylist misses. The links a real deltaLog carries (`githubLink`,
// `cveOrgLink`) are PARSED AND DISCARDED — see DeltaLogEntry.
//
// Turning an identifier into a URL is the Source hook's job, for the same
// reason poller.Watermarker is an injected interface: a package that knew where
// one feed's records live would be a hard-coded feed table wearing a different
// hat.
//
// ===========================================================================
// THREE ROUTES ARE PLANNED HERE AND DELIBERATELY NOT RUN HERE
// ===========================================================================
//
// RouteReconcile, RouteBaseline and RouteGitFetch are recognised, scheduled and
// reported by Due(), and refused with a named sentinel unless a delegate is
// wired. Each refusal has a reason that is about correctness, not effort:
//
//   - RouteReconcile wants the ~17 MB end-of-day delta asset. A.8's importer
//     resolves the LARGEST archive asset of a release, which is the 570 MB
//     midnight baseline. Wiring reconcile to it would cost 570 MB/day and
//     would be the very re-download A.14's packet forbids, so this package
//     refuses rather than defaults. Choosing WHICH asset of a release is the
//     reconciliation artifact is a per-feed fact and belongs in A.1's table.
//   - RouteBaseline is A.15's weekly self-heal. Due() computes its clock
//     because the clock is in the feed row and one planner should own all
//     three; running it here would be two implementations of one pass.
//   - RouteGitFetch needs A.8's clone directory and would have to rewrite
//     A.8's watermark token afterwards — two writers on one column, which is
//     the thing the cursor design above avoids.
//
// A refusal is loud, typed and counted. It is not a silent no-op, and it is
// not a t.Skip.
package delta

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/poller"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrDelta is satisfied by every error this package originates, so a
	// caller can tell "the delta pipeline declined" from "the database
	// failed" without listing every sentinel.
	ErrDelta = errors.New("delta")

	// ErrSyncRefused is satisfied by every refusal: a decision Anvil made,
	// as opposed to something that went wrong.
	ErrSyncRefused = fmt.Errorf("%w: refused", ErrDelta)

	// ErrNoCache is a Syncer built without the A.2 ingestion cache.
	ErrNoCache = fmt.Errorf("%w: no ingestion cache", ErrSyncRefused)

	// ErrNoPoller is a Syncer built without A.7. There is no fallback path:
	// a delta sync that fetched without the poller would be a second,
	// unreviewed implementation of the conditional-GET, scope and credential
	// rules that package exists to hold.
	ErrNoPoller = fmt.Errorf("%w: no poller", ErrSyncRefused)

	// ErrNoSource is the deltaLog route with no Source hook wired. It is not
	// fatal: SyncDelta falls back to decoding the polled body, which is the
	// correct behaviour for every feed whose body IS the delta.
	ErrNoSource = fmt.Errorf("%w: no delta source", ErrSyncRefused)

	// ErrNoDeltaLog is what a Source returns to say "this feed has no delta
	// log". It is a normal answer, not a fault.
	ErrNoDeltaLog = fmt.Errorf("%w: feed has no delta log", ErrSyncRefused)

	// ErrNoReconciler is RouteReconcile with nothing wired to run it. See the
	// package comment: defaulting it to A.8's bulk importer would cost 570 MB
	// a day.
	ErrNoReconciler = fmt.Errorf("%w: no reconciler", ErrSyncRefused)

	// ErrDelegated is a route this package plans and does not run.
	ErrDelegated = fmt.Errorf("%w: route is delegated", ErrSyncRefused)

	// ErrRecordName is the CVE-identifier allowlist refusing a name a delta
	// log offered. It is the boundary between feed content and a request.
	ErrRecordName = fmt.Errorf("%w: record name", ErrSyncRefused)

	// ErrStatementNotAllowed is the SQL allowlist refusing a statement. It is
	// what stands between a delta batch and a full FTS rebuild.
	ErrStatementNotAllowed = fmt.Errorf("%w: statement not on the allowlist", ErrSyncRefused)

	// ErrUnsanitized is a record reaching the write path with a string A.3
	// would have changed.
	ErrUnsanitized = fmt.Errorf("%w: unsanitized field", ErrSyncRefused)

	// ErrBadRecord is a decoded record that cannot be written: no primary
	// key, no raw document.
	ErrBadRecord = fmt.Errorf("%w: unwritable record", ErrSyncRefused)

	// ErrUnrecognisedShape is a fetched document in no shape this package
	// decodes. SyncDelta turns it into a routing decision rather than a
	// dropped change.
	ErrUnrecognisedShape = fmt.Errorf("%w: unrecognised document shape", ErrSyncRefused)

	// ErrDocumentTooLarge, ErrArchiveTooLarge and ErrBatchTooLarge are the
	// three size bounds. Each is a refusal about what ARRIVED, never about
	// what a header claimed.
	ErrDocumentTooLarge = fmt.Errorf("%w: document too large", ErrSyncRefused)
	ErrArchiveTooLarge  = fmt.Errorf("%w: archive too large", ErrSyncRefused)
	ErrBatchTooLarge    = fmt.Errorf("%w: batch too large", ErrSyncRefused)
)

// refuse builds a refusal: a decision Anvil made.
func refuse(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Route names the transport one sync used, or would use.
//
// It is Lane-A-local vocabulary with no counterpart among the record contract's
// six frozen enums, so declaring it here does not violate the single-owner rule
// in plan/IMPLEMENTATION-PLAN.md §6. It exists so a caller switches on a
// constant rather than re-deriving the decision from a sync mechanism and a
// body it would have to sniff again.
type Route string

const (
	// RouteNone is nothing to do: the row is disabled, not due, or carries no
	// steady-state poll at all.
	RouteNone Route = "none"

	// RouteDerived is a feed whose content arrives inside another feed's
	// payload. CISA Vulnrichment is the worked example: it is delivered in
	// the CVE record's ADP container, so a separate sync would be a second
	// copy of the same bytes.
	RouteDerived Route = "derived"

	// RoutePoll is the plan-time answer for any polled feed: poll it, then
	// let the bytes decide between RouteDeltaLog and RouteFeedBody. Due()
	// never returns the other two, because which one applies is a fact about
	// the response and not about the row.
	RoutePoll Route = "poll"

	// RouteDeltaLog is the cheap path: a delta LOG names what changed, and
	// only the named records are fetched. This is the route research/06 §3
	// prescribes for cvelistV5 at 15 minutes.
	RouteDeltaLog Route = "delta_log"

	// RouteFeedBody is the polled body itself carrying the changed records —
	// KEV's catalogue, an OSV ecosystem archive. There is nothing cheaper for
	// these feeds: their publishers offer no delta mechanism.
	RouteFeedBody Route = "feed_body"

	// RouteReconcile is the periodic wider-window pass on
	// reconcile_interval_seconds. See the package comment for why it is
	// planned here and refused unless delegated.
	RouteReconcile Route = "reconcile"

	// RouteBaseline is A.15's full-baseline self-heal on
	// baseline_interval_seconds.
	RouteBaseline Route = "baseline"

	// RouteGitFetch is GHSA's incremental `git fetch` against A.8's blobless
	// clone.
	RouteGitFetch Route = "git_fetch"
)

// RouteValues returns every legal Route, in declaration order.
func RouteValues() []Route {
	return []Route{
		RouteNone, RouteDerived, RoutePoll, RouteDeltaLog,
		RouteFeedBody, RouteReconcile, RouteBaseline, RouteGitFetch,
	}
}

// Valid reports whether r is one of the declared routes.
func (r Route) Valid() bool {
	for _, v := range RouteValues() {
		if r == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Due — the whole scheduler, as a pure function
// ---------------------------------------------------------------------------

// Plan is what Due concluded about one feed at one instant.
//
// It is returned whole rather than as a bare boolean because "not due" and
// "not scheduled at all" and "disabled" are three different operational facts,
// and a feed that has gone quiet is diagnosed by which one it is.
type Plan struct {
	// FeedID echoes the row.
	FeedID string

	// Route is the transport a steady sync would use, and is one of
	// RouteNone, RouteDerived, RoutePoll or RouteGitFetch. The two
	// content-decided routes are never planned; see RoutePoll.
	Route Route

	// Due is whether the steady sync should run now.
	Due bool

	// Because is the sentence an operator reads when Due is false.
	Because string

	// Interval is the steady cadence from the feed row, and NextDueAt is when
	// the steady sync may next run. NextDueAt is the zero time when the feed
	// has never succeeded, which is also when Due is true regardless of the
	// clock.
	Interval  time.Duration
	NextDueAt time.Time

	// LastOK is feed_state.last_ok_at as read before the poll.
	LastOK time.Time

	// ReconcileDue and BaselineDue are the two wider passes. They are
	// reported rather than run; see the package comment.
	//
	// Both are WINDOW-BOUNDARY tests, not elapsed-time tests: reconcile is due
	// when `now` and `LastOK` fall in different reconcile windows. For the
	// 86,400-second reconcile interval the feed table ships, that is exactly
	// "the UTC day changed since the last successful sync", which is what
	// research/06's "end-of-day delta once daily" means and what an
	// elapsed-time test does not give — a feed polled at 23:50 and again at
	// 00:10 has elapsed 20 minutes and has crossed the day.
	ReconcileDue bool
	BaselineDue  bool

	// ReconcileInterval and BaselineInterval are the two cadences as read
	// from the feed row. Zero means the row schedules no such pass.
	ReconcileInterval time.Duration
	BaselineInterval  time.Duration
}

// Due decides what is scheduled for one feed at one instant.
//
// EVERY DURATION IN THE ANSWER COMES FROM feed. There is no default cadence, no
// minimum, no clamp and no Go constant: an operator who sets
// `interval_seconds: 86400` on a constrained host gets a daily poll, which is
// research/06 Recommendation §4's stated purpose for putting cadences in
// config at all.
//
// lastOK is feed_state.last_ok_at. The zero time means "never succeeded", and
// everything is due.
func Due(feed config.FeedConfig, lastOK, now time.Time) Plan {
	p := Plan{
		FeedID:            feed.ID,
		Route:             RouteNone,
		Interval:          feed.Interval(),
		LastOK:            lastOK,
		ReconcileInterval: feed.ReconcileInterval(),
		BaselineInterval:  feed.BaselineInterval(),
	}

	// The wider passes are computed for every row, including one that is not
	// polled at all: a bulk-only feed (sync_mechanism: none) still has a
	// baseline cadence, and that is the only thing that refreshes it.
	p.ReconcileDue = windowCrossed(lastOK, now, p.ReconcileInterval)
	p.BaselineDue = windowCrossed(lastOK, now, p.BaselineInterval)

	if !feed.Enabled {
		p.Because = "the feed row is disabled; nothing about it is scheduled"
		p.ReconcileDue, p.BaselineDue = false, false
		return p
	}

	switch feed.SyncMechanism {
	case config.SyncDerived:
		p.Route = RouteDerived
		p.Because = fmt.Sprintf(
			"the feed is derived from %q and arrives inside that feed's payload; syncing it separately "+
				"would fetch the same bytes twice", feed.DerivedFrom)
		return p

	case config.SyncNone:
		p.Because = "the feed carries no steady-state poll; only its baseline pass refreshes it"
		return p

	case config.SyncGitBloblessFetch:
		p.Route = RouteGitFetch

	default:
		p.Route = RoutePoll
	}

	if p.Interval <= 0 {
		p.Route = RouteNone
		p.Because = "the feed row declares a zero poll interval, so it has no steady-state cadence"
		return p
	}

	if lastOK.IsZero() {
		p.Due = true
		p.Because = "the feed has never recorded a successful sync"
		return p
	}

	p.NextDueAt = lastOK.Add(p.Interval)
	if now.Before(p.NextDueAt) {
		p.Because = fmt.Sprintf("the last success was at %s and the row's cadence is %s, so the next sync is at %s",
			lastOK.UTC().Format(time.RFC3339), p.Interval, p.NextDueAt.UTC().Format(time.RFC3339))
		return p
	}
	p.Due = true
	p.Because = fmt.Sprintf("the last success was at %s, which is at least the row's %s cadence ago",
		lastOK.UTC().Format(time.RFC3339), p.Interval)
	return p
}

// windowCrossed reports whether now and last fall in different windows of the
// given width.
//
// A ZERO WIDTH IS "no such pass" AND RETURNS FALSE. A zero last is "never
// succeeded" and returns true.
//
// time.Time.Truncate rounds toward the zero time, which is midnight UTC on
// 1 January year 1, so a 24-hour width gives UTC day boundaries and a
// 168-hour width gives a fixed weekly boundary. That is the property this
// wants: the pass happens once per calendar window rather than drifting later
// by however long the previous run took.
func windowCrossed(last, now time.Time, width time.Duration) bool {
	if width <= 0 {
		return false
	}
	if last.IsZero() {
		return true
	}
	return !now.UTC().Truncate(width).Equal(last.UTC().Truncate(width))
}

// ---------------------------------------------------------------------------
// The delta log
// ---------------------------------------------------------------------------

// DeltaLogEntry is one entry of a delta log: a moment, and the records that
// changed at it.
//
// THE LINK FIELDS ARE ABSENT ON PURPOSE. A real cvelistV5 deltaLog entry
// carries `githubLink` and `cveOrgLink` per record, and binding them would be
// the obvious way to fetch: the document tells you where the record lives.
// It is also an SSRF with the feed's credential attached, decided by a
// document written by strangers. encoding/json drops unknown fields, so those
// links are parsed and discarded by omission — which is stronger than dropping
// them in code, because there is no field for a later change to start using.
//
// What survives is the identifier and the claimed update time. The identifier
// is checked against IsCVEID before it reaches a Source; the time is compared
// with what the cache already holds.
type DeltaLogEntry struct {
	// FetchTime is when the publisher recorded this batch of changes.
	FetchTime string `json:"fetchTime"`

	// NumberOfChanges is the publisher's own count. It is carried for
	// diagnostics and never trusted as a length.
	NumberOfChanges int `json:"numberOfChanges"`

	New     []DeltaLogRecord `json:"new"`
	Updated []DeltaLogRecord `json:"updated"`
	Error   []DeltaLogRecord `json:"error"`
}

// DeltaLogRecord names one changed record.
type DeltaLogRecord struct {
	// CVEID is the only field that may influence a request, and only after
	// IsCVEID accepts it.
	CVEID string `json:"cveId"`

	// DateUpdated is the publisher's claimed modification time. It is
	// compared against the cache's `modified` to decide whether the record is
	// worth fetching at all, and a value in an unrecognised shape means
	// "fetch it" — see isNewer, which fails toward fetching.
	DateUpdated string `json:"dateUpdated"`
}

// MaxDeltaLogBytes bounds a delta log document. research/06 records the
// cvelistV5 log as "a rolling 30 days worth of CVE record modification
// history" and its release-notes sibling at 65 KB; 64 MiB is three orders of
// magnitude of headroom and still refuses a memory-exhaustion payload.
const MaxDeltaLogBytes = 64 << 20

// ParseDeltaLog reads a delta log document into entries.
//
// It accepts both shapes a log is published in — a bare array of entries, and
// an object with an `entries` array — because the second is what a mirror
// wrapping the first tends to produce, and refusing it would make a legitimate
// mirror unusable for no security gain. It accepts nothing else.
func ParseDeltaLog(raw []byte) ([]DeltaLogEntry, error) {
	if len(raw) > MaxDeltaLogBytes {
		return nil, refuse(ErrDocumentTooLarge,
			"a %d-byte delta log exceeds the %d-byte cap", len(raw), MaxDeltaLogBytes)
	}
	trimmed := bytes.TrimLeft(raw, " \t\r\n\ufeff")
	if len(trimmed) == 0 {
		return nil, refuse(ErrUnrecognisedShape, "the delta log document is empty")
	}

	if trimmed[0] == '[' {
		var entries []DeltaLogEntry
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, refuse(ErrUnrecognisedShape, "the delta log is not an array of entries: %v", err)
		}
		return entries, nil
	}
	if trimmed[0] == '{' {
		var wrapper struct {
			Entries []DeltaLogEntry `json:"entries"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil, refuse(ErrUnrecognisedShape, "the delta log is not an object carrying `entries`: %v", err)
		}
		if wrapper.Entries == nil {
			return nil, refuse(ErrUnrecognisedShape,
				"the delta log is a JSON object with no `entries` array; a delta log names what changed")
		}
		return wrapper.Entries, nil
	}
	return nil, refuse(ErrUnrecognisedShape, "the delta log is neither a JSON array nor a JSON object")
}

// checkRecordName is THE BOUNDARY between a document written by strangers and a
// request Anvil makes.
//
// It is an allowlist and it is deliberately narrow: `CVE-` then at least four
// digits, a dash, then at least one digit, and nothing else at all. Every
// traversal sequence, every scheme, every host, every wildcard and every
// encoding trick fails it, not because any of them is listed but because none
// of them is a CVE identifier.
//
// A rejected name is COUNTED, not silently dropped: a delta log whose names
// stopped parsing is a feed that changed shape, and the number is how an
// operator finds out before the cache quietly stops moving.
// It also requires the name to be ALREADY CANONICAL — equal to itself with
// surrounding whitespace removed. IsCVEID trims before it judges, because it
// also classifies aliases inside advisory documents where leading space is
// meaningless noise; that leniency is wrong HERE, and delta_test.go caught it:
// a guard that normalises and then accepts is not checking the string the
// caller goes on to use unless the caller applies the identical normalisation.
// Requiring the input to already be canonical removes the gap instead of
// duplicating the normalisation on both sides and hoping they stay equal.
func checkRecordName(feedID, name string) error {
	if name == strings.TrimSpace(name) && IsCVEID(name) {
		return nil
	}
	return refuse(ErrRecordName,
		"feed %q: the delta log named %q, which is not a CVE identifier. Only a name matching "+
			"CVE-<digits>-<digits> may be turned into a fetch; the log's own link fields are not read "+
			"at all, because a document written by strangers must not choose where Anvil sends a "+
			"credentialed request.",
		feedID, clip(name, 120))
}

// clip bounds a value quoted back into an error, so a hostile document cannot
// write a megabyte into a log line.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------------------------------------------------------------------
// Injected dependencies
// ---------------------------------------------------------------------------

// FeedPoller is A.7. *poller.Poller satisfies it.
//
// It is an interface so that delta_test.go can count polls and so that the
// daemon supplies one configured Poller rather than this package constructing
// an HTTP client of its own — which would be a second implementation of the
// authentication, redirect-scope and body-cap rules A.7 exists to hold.
type FeedPoller interface {
	Poll(ctx context.Context, feed config.FeedConfig) (poller.PollResult, error)
}

// Source is the FEED-SPECIFIC knowledge the deltaLog route needs and this
// package deliberately does not hold.
//
// The rationale is poller.Watermarker's, verbatim in spirit: where a feed's
// delta log lives, and where one named record lives, are facts about a FEED.
// A package that knew them would be a hard-coded feed table wearing a different
// hat, and A.1's whole design is that Lane A knows nothing about a feed that is
// not in the table.
//
// A nil Source is legal and common. It makes RouteDeltaLog unreachable and
// SyncDelta decodes the polled body instead, which is correct for every feed
// whose publisher offers no delta log — which is most of them.
type Source interface {
	// DeltaLog returns the feed's delta log document for this poll.
	//
	// It returns an error satisfying ErrNoDeltaLog when the feed has none;
	// that is a normal answer and SyncDelta falls through to the body route.
	// poll is passed so an implementation can read the release manifest, the
	// ETag or the watermark the poll just produced without making a second
	// request for them.
	DeltaLog(ctx context.Context, feed config.FeedConfig, poll poller.PollResult) ([]byte, error)

	// Record returns one advisory record verbatim.
	//
	// id has ALREADY passed checkRecordName; an implementation may rely on
	// that and must not relax it. An implementation must also apply the same
	// scope discipline A.7 applies — same host as the feed row, no cross-host
	// redirect, credentials from the row's credential_env and nowhere else.
	Record(ctx context.Context, feed config.FeedConfig, id string) ([]byte, error)
}

// Reconciler runs RouteReconcile. See the package comment for why this package
// refuses rather than defaulting the route to A.8's bulk importer.
type Reconciler interface {
	Reconcile(ctx context.Context, feed config.FeedConfig) (BatchStats, error)
}

// ---------------------------------------------------------------------------
// Syncer
// ---------------------------------------------------------------------------

// Options configures a Syncer. DB and Poller are required.
type Options struct {
	// DB is the A.2 ingestion cache, already migrated. It is NOT
	// internal/store: that is the audit store of record and nothing here may
	// touch it.
	DB *sql.DB

	// Poller is A.7. Nothing in this package makes an HTTP request except
	// through it and through Source.
	Poller FeedPoller

	// THERE IS NO Mirror FIELD, AND ITS ABSENCE IS THE POINT. A.4's licence
	// gate is resolved by A.7 BEFORE the request goes out, and the decision
	// arrives on PollResult bound to the bytes it admitted. A Mirror here
	// would let this package resolve the gate a second time, which means two
	// answers to one question and a way to write rows under a decision the
	// fetch was not made under.

	// Source is the deltaLog route's feed-specific hook. Nil disables that
	// route.
	Source Source

	// Reconcile runs RouteReconcile. Nil makes SyncReconcile a typed refusal.
	Reconcile Reconciler

	// Now is the clock. Nil means time.Now. It is injected so that a cadence
	// test asserts a boundary rather than approximately asserts one.
	Now func() time.Time
}

// Syncer performs delta syncs. It holds no per-sync mutable state and is safe
// for concurrent use across feeds; two concurrent syncs of the SAME feed are
// not useful but are not unsafe, because every write is an upsert keyed on
// (source, source_id).
type Syncer struct {
	db         *sql.DB
	poll       FeedPoller
	source     Source
	reconciler Reconciler
	now        func() time.Time
}

// SyncStats is what one SyncDelta did.
//
// It is returned even on an error, because "what did we do before it went
// wrong" is the first question an operator asks: whether the feed was polled,
// whether the licence gate refused, how many records were fetched, and whether
// anything reached the cache.
type SyncStats struct {
	// FeedID echoes the row.
	FeedID string

	// Plan is what Due concluded BEFORE the poll. Its LastOK is the value
	// that decided the schedule, which the poll then moves.
	Plan Plan

	// Route is the transport actually used. It is RouteDeltaLog or
	// RouteFeedBody for a sync that ran, and one of the others for a sync
	// that did not.
	Route Route

	// Skipped is true when nothing ran because nothing was due. It is not an
	// error and the returned error is nil.
	Skipped bool

	// Polled is whether A.7 was called, and PollStatus its typed outcome.
	Polled     bool
	PollStatus poller.Status

	// Decision is A.4's licence decision, and Refused says the gate declined.
	// A.7 resolves the gate BEFORE the request, so a refusal here means no
	// bytes were fetched at all.
	Decision       license.Decision
	Refused        bool
	RefusedBecause string

	// Delegated marks a route this package plans and does not run.
	Delegated bool

	// DeltaLogEntries, NamesSeen, NamesRejected and NamesUpToDate describe the
	// cheap path's arithmetic.
	//
	// NamesUpToDate IS THE COST MODEL. It counts records the delta log named
	// that the cache already holds at or past the log's own dateUpdated, and
	// therefore records NOT fetched. research/06's ~200 MB/day figure is what
	// happens when this number is zero because nobody looked.
	DeltaLogEntries int
	NamesSeen       int
	NamesRejected   int
	NamesUpToDate   int

	// RecordFetches is how many individual record documents were fetched, and
	// RecordBytes how many bytes those cost. BodyBytes is what the poll
	// itself transferred.
	RecordFetches int
	RecordBytes   int64
	BodyBytes     int64

	// Documents is how many documents were decoded (a body may be an archive
	// of many), and Records how many advisories came out of them.
	Documents int
	Records   int

	// Batch is what reached the cache.
	Batch BatchStats

	// Sanitize is the merged A.3 report over everything decoded. A non-zero
	// count is not an error; it is the ordinary state of text written by
	// strangers.
	Sanitize sanitize.SanitizeStats

	// AsOf is the timestamp stamped on every row this sync wrote, and
	// StalenessSeconds spine S6's age of the DATA at write time — measured
	// from the response's Last-Modified where the feed sent one, never from
	// the age of the write.
	AsOf             time.Time
	StalenessSeconds int

	// NextSyncAfter is the shortest delay before this feed may be synced
	// again. It is A.7's answer where A.7 ran, because a server that asked
	// for longer than the feed table's cadence has to be honoured.
	NextSyncAfter time.Duration

	// Note is a sentence for an operator when the outcome needs one: a route
	// refused, a body in a shape this path does not decode, a delta log the
	// Source declined to provide.
	Note string
}

// New builds a Syncer. DB and Poller are the two hard requirements: without the
// cache nothing can be written, and without A.7 nothing may be fetched.
func New(opts Options) (*Syncer, error) {
	if opts.DB == nil {
		return nil, refuse(ErrNoCache, "a delta sync writes rows and needs the A.2 ingestion cache")
	}
	if opts.Poller == nil {
		return nil, refuse(ErrNoPoller,
			"a delta sync fetches only through A.7; a client built here would be a second implementation "+
				"of its authentication, redirect-scope and body-cap rules")
	}
	s := &Syncer{
		db:         opts.DB,
		source:     opts.Source,
		reconciler: opts.Reconcile,
		poll:       opts.Poller,
		now:        opts.Now,
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// SyncDelta
// ---------------------------------------------------------------------------

// SyncDelta performs one steady-state delta sync of one feed.
//
// It is A.14's `SyncDelta(ctx, feed FeedConfig) (SyncStats, error)`; the
// dependencies that signature has no room for — the cache, the poller, the
// clock, the record source — live on the receiver so that no call site can
// supply a different one per call and no default can be reached by accident.
//
// THE ORDER OF WHAT FOLLOWS IS THE CONTRACT:
//
//  1. feed_state is read                          (no network)
//  2. Due decides what is scheduled                (pure)
//  3. A.7 polls — which resolves A.4's licence gate BEFORE the request,
//     sends the conditional headers, and refuses an off-host redirect
//  4. a 304 ends the sync having written nothing
//  5. the delta log is preferred; only records it names, and only records
//     the cache does not already hold, are fetched
//  6. every document is decoded, sanitized field by field
//  7. one row-scoped upsert per changed record
//
// Step 5 is the one A.14's packet is about. Step 3 is the one A.7's ordering
// rule is about and it is not optional: the licence gate runs before the
// request, so a feed with no acquired licence body costs no bytes at all.
//
// A non-nil error is returned WITH a populated SyncStats, never instead of one.
func (s *Syncer) SyncDelta(ctx context.Context, feed config.FeedConfig) (SyncStats, error) {
	now := s.now().UTC()
	stats := SyncStats{
		FeedID:   feed.ID,
		Route:    RouteNone,
		AsOf:     now,
		Decision: license.Decision{Tier: config.LicenseTier(license.NoTier)},
	}

	lastOK, err := s.lastSuccess(ctx, feed.ID)
	if err != nil {
		return stats, err
	}
	plan := Due(feed, lastOK, now)
	stats.Plan = plan
	stats.Route = plan.Route
	stats.NextSyncAfter = plan.Interval

	if !plan.Due {
		stats.Skipped = true
		stats.Note = plan.Because
		return stats, nil
	}

	switch plan.Route {
	case RouteGitFetch:
		stats.Delegated = true
		stats.Note = "the row's sync_mechanism is git_blobless_fetch, which fetches into A.8's clone and " +
			"would then have to rewrite A.8's watermark token; that is two writers on one column, so this " +
			"package plans the route and does not run it"
		return stats, refuse(ErrDelegated, "feed %q: %s", feed.ID, stats.Note)
	case RoutePoll:
		// fall through
	default:
		stats.Skipped = true
		stats.Note = plan.Because
		return stats, nil
	}

	// --- 3. A.7. The licence gate runs inside it, before the request. ---
	res, err := s.poll.Poll(ctx, feed)
	stats.Polled = true
	stats.PollStatus = res.Status
	stats.Decision = res.Decision
	stats.BodyBytes = res.BodyBytes
	stats.Sanitize.Merge(res.Sanitize)
	if res.NextPollAfter > 0 {
		stats.NextSyncAfter = res.NextPollAfter
	}
	if err != nil {
		if errors.Is(err, license.ErrLicenseRefused) || res.Decision.Refused() {
			stats.Refused = true
			stats.RefusedBecause = err.Error()
			stats.Note = "the licence gate declined this feed, so no bytes were fetched. " +
				"That is the ordinary state of a fresh clone: no publisher licence body has been " +
				"acquired into mirror/ yet. See " + license.AcquireCommand
		}
		return stats, err
	}
	if res.Decision.Refused() {
		stats.Refused = true
		stats.Note = "the poll returned no error but produced a refusing licence decision"
		return stats, refuse(license.ErrLicenseRefused,
			"feed %q: tier %d, dir %q", feed.ID, res.Decision.Tier.Int(), res.Decision.Dir)
	}

	// --- 4. A 304 writes nothing. Exit criterion 3: advisory, affected and
	// advisory_fts must be byte-identical after one. ---
	if res.Status != poller.StatusUpdated {
		stats.Note = fmt.Sprintf("the poll returned %q, so nothing changed and no row was written", res.Status)
		return stats, nil
	}

	stats.StalenessSeconds = stalenessSeconds(now, res.LastModified)

	// --- 5. Prefer the delta log. ---
	recs, route, note, err := s.collect(ctx, feed, res, &stats)
	stats.Route = route
	if note != "" {
		stats.Note = note
	}
	if err != nil {
		return stats, err
	}
	stats.Records = len(recs)
	if len(recs) == 0 {
		return stats, nil
	}

	// --- 7. One upsert per changed record. ---
	batch, err := Apply(ctx, s.db, feed, res.Decision, recs, now, stats.StalenessSeconds)
	stats.Batch = batch
	if err != nil {
		return stats, err
	}
	return stats, nil
}

// collect resolves the poll into decoded records, preferring the delta log.
//
// PREFERENCE IS STRUCTURAL, NOT ADVISORY. The delta log is asked for first, and
// the polled body is decoded ONLY when there is no delta log to be had — no
// Source wired, or the Source saying this feed has none. There is no size
// threshold, no "if the body is small enough", and no flag: a threshold is
// exactly how the cumulative-zip re-download A.14's packet forbids gets
// reintroduced as an optimisation.
func (s *Syncer) collect(
	ctx context.Context,
	feed config.FeedConfig,
	res poller.PollResult,
	stats *SyncStats,
) ([]Record, Route, string, error) {
	if s.source != nil {
		raw, err := s.source.DeltaLog(ctx, feed, res)
		switch {
		case err == nil:
			recs, err := s.fromDeltaLog(ctx, feed, raw, stats)
			return recs, RouteDeltaLog, "", err
		case errors.Is(err, ErrNoDeltaLog):
			// Normal. Fall through to the body.
		default:
			return nil, RouteDeltaLog, "", err
		}
	}

	recs, note, err := s.fromBody(feed, res, stats)
	return recs, RouteFeedBody, note, err
}

// fromDeltaLog is the cheap path.
//
// It reads a document that NAMES changes, checks every name against the CVE-ID
// allowlist, drops the names the cache already holds at or past the log's own
// dateUpdated, and fetches only what is left. The two counters it fills —
// NamesUpToDate and RecordFetches — are the cost model made observable.
func (s *Syncer) fromDeltaLog(
	ctx context.Context,
	feed config.FeedConfig,
	raw []byte,
	stats *SyncStats,
) ([]Record, error) {
	entries, err := ParseDeltaLog(raw)
	if err != nil {
		return nil, fmt.Errorf("feed %q: %w", feed.ID, err)
	}
	stats.DeltaLogEntries = len(entries)
	stats.RecordBytes += int64(len(raw))

	// Names are de-duplicated across entries and sorted, so that a log naming
	// the same CVE in three consecutive entries costs one fetch, and so that
	// the request order is deterministic — a test that asserts a fetch count
	// against a fixture should not depend on map iteration order.
	claimed := map[string]string{}
	var order []string
	for _, e := range entries {
		for _, group := range [][]DeltaLogRecord{e.New, e.Updated, e.Error} {
			for _, r := range group {
				stats.NamesSeen++
				if err := checkRecordName(feed.ID, r.CVEID); err != nil {
					stats.NamesRejected++
					continue
				}
				// The name is used EXACTLY as checkRecordName accepted it.
				// No trim, no case fold, no normalisation of any kind: the
				// string that was checked and the string that becomes a fetch
				// have to be the same bytes, or the check was of something
				// else.
				name := r.CVEID
				if prev, seen := claimed[name]; !seen || isNewer(r.DateUpdated, prev) {
					claimed[name] = strings.TrimSpace(r.DateUpdated)
					if !seen {
						order = append(order, name)
					}
				}
			}
		}
	}
	sort.Strings(order)

	var out []Record
	for _, name := range order {
		cached, present, err := CachedModified(ctx, s.db, feed.ID, name)
		if err != nil {
			return out, err
		}
		if present && !isNewer(claimed[name], cached) {
			// THE WHOLE POINT. The cache already holds this record at or past
			// the log's own claimed update time, so there is nothing to
			// transfer. research/06's ~200 MB/day figure is what happens when
			// this branch does not exist.
			stats.NamesUpToDate++
			continue
		}

		doc, err := s.source.Record(ctx, feed, name)
		if err != nil {
			return out, fmt.Errorf("feed %q: fetching record %s: %w", feed.ID, name, err)
		}
		stats.RecordFetches++
		stats.RecordBytes += int64(len(doc))
		stats.Documents++

		recs, sstats, err := Decode(feed.ID, doc)
		stats.Sanitize.Merge(sstats)
		if err != nil {
			return out, fmt.Errorf("feed %q: record %s: %w", feed.ID, name, err)
		}
		out = append(out, recs...)
	}
	return out, nil
}

// fromBody decodes the polled body itself.
//
// This is the correct route for every feed whose publisher offers no delta
// mechanism — KEV's catalogue, an OSV ecosystem archive — and there is nothing
// cheaper for them: research/06 records "full-file download is the only option
// OVAL documents anyway".
//
// A body in a shape this package does not decode is NOT an error that fails the
// sync. It is a ROUTING FACT, returned as a note with zero records, because the
// answer for a CSAF directory listing or an EPSS CSV is A.8's bulk path and not
// a second decoder here. Failing the sync would make a correctly-configured
// feed look broken; dropping it silently would lose the change.
func (s *Syncer) fromBody(feed config.FeedConfig, res poller.PollResult, stats *SyncStats) ([]Record, string, error) {
	body, err := res.Payload.Bytes()
	if err != nil {
		return nil, "", err
	}

	docs, err := unwrap(feed.ID, body)
	if err != nil {
		if errors.Is(err, ErrUnrecognisedShape) {
			return nil, unroutableNote(feed.ID, err), nil
		}
		return nil, "", err
	}
	stats.Documents = len(docs)
	if len(docs) > MaxBatchRecords {
		return nil, "", refuse(ErrBatchTooLarge,
			"feed %q: the polled body unpacks to %d documents, which is a bulk artifact and belongs on "+
				"A.8's resumable path rather than in a delta batch", feed.ID, len(docs))
	}

	var out []Record
	for _, d := range docs {
		recs, sstats, err := Decode(feed.ID, d)
		stats.Sanitize.Merge(sstats)
		if err != nil {
			if errors.Is(err, ErrUnrecognisedShape) {
				return nil, unroutableNote(feed.ID, err), nil
			}
			return nil, "", err
		}
		out = append(out, recs...)
	}
	return out, "", nil
}

func unroutableNote(feedID string, err error) string {
	return fmt.Sprintf(
		"feed %q polled successfully but its body is not a shape the delta decoder reads, so no row was "+
			"written and nothing was dropped silently: %v. Feeds whose steady state is a full-file "+
			"refresh (CSAF directory listings, per-branch distro secdb, the EPSS CSV) reach the cache "+
			"through A.8's bulk path.", feedID, err)
}

// ---------------------------------------------------------------------------
// SyncReconcile
// ---------------------------------------------------------------------------

// SyncReconcile runs the periodic wider-window pass on
// reconcile_interval_seconds.
//
// IT REFUSES UNLESS A Reconciler IS WIRED, and the refusal is the design. The
// artifact this pass wants is cvelistV5's ~17 MB end-of-day delta; A.8's
// importer resolves the LARGEST archive asset of a release, which is the 570 MB
// midnight baseline. Wiring this route to A.8 by default would cost 570 MB a
// day and would be precisely the re-download A.14's packet forbids — and it
// would do it silently, which is worse than doing it loudly.
//
// Choosing WHICH asset of a release is the reconciliation artifact is a
// per-feed fact, so it belongs in A.1's table beside the cadence that
// schedules it. Until it is there, this package plans the pass and declines to
// guess.
func (s *Syncer) SyncReconcile(ctx context.Context, feed config.FeedConfig) (SyncStats, error) {
	now := s.now().UTC()
	stats := SyncStats{
		FeedID:   feed.ID,
		Route:    RouteReconcile,
		AsOf:     now,
		Decision: license.Decision{Tier: config.LicenseTier(license.NoTier)},
	}
	lastOK, err := s.lastSuccess(ctx, feed.ID)
	if err != nil {
		return stats, err
	}
	stats.Plan = Due(feed, lastOK, now)

	if !stats.Plan.ReconcileDue {
		stats.Skipped = true
		if stats.Plan.ReconcileInterval <= 0 {
			stats.Note = "the feed row schedules no reconciliation pass"
		} else {
			stats.Note = fmt.Sprintf(
				"the last success at %s falls in the same %s reconciliation window as now",
				lastOK.UTC().Format(time.RFC3339), stats.Plan.ReconcileInterval)
		}
		return stats, nil
	}

	if s.reconciler == nil {
		stats.Delegated = true
		stats.Note = "the reconciliation pass is due and no Reconciler is wired. This package will not " +
			"default it to A.8's bulk importer: that importer resolves the largest asset of a release " +
			"(the 570 MB midnight baseline) rather than the ~17 MB end-of-day delta, so the default " +
			"would be a 570 MB/day re-download of data already held"
		return stats, refuse(ErrNoReconciler, "feed %q: %s", feed.ID, stats.Note)
	}

	batch, err := s.reconciler.Reconcile(ctx, feed)
	stats.Batch = batch
	return stats, err
}

// ---------------------------------------------------------------------------
// feed_state
// ---------------------------------------------------------------------------

// lastSuccess reads feed_state.last_ok_at, which is the only durable input the
// scheduler has.
//
// A feed with no row has never been polled and everything about it is due. A
// row whose last_ok_at does not parse is treated the same way, deliberately: a
// clock we cannot read must not be allowed to postpone a sync indefinitely, and
// re-syncing early costs one conditional GET.
func (s *Syncer) lastSuccess(ctx context.Context, feedID string) (time.Time, error) {
	row, err := queryRowDB(ctx, s.db, cache.SelectFeedStateSQL, feedID)
	if err != nil {
		return time.Time{}, err
	}
	var (
		etag, lastModified, watermark, lastOK sql.NullString
		failures, tier                        int
	)
	switch err := row.Scan(&etag, &lastModified, &watermark, &lastOK, &failures, &tier); {
	case err == sql.ErrNoRows:
		return time.Time{}, nil
	case err != nil:
		return time.Time{}, fmt.Errorf("delta: reading feed_state for %q: %w", feedID, err)
	}
	if !lastOK.Valid {
		return time.Time{}, nil
	}
	// A.7 and A.8 write this column in slightly different renderings of the
	// same instant, so both are accepted rather than one being declared
	// canonical from here. A value in neither shape is treated as "never
	// succeeded": a clock we cannot read must not be able to postpone a sync
	// indefinitely, and re-syncing early costs one conditional GET.
	v := strings.TrimSpace(lastOK.String)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000000Z"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, nil
}

// stalenessSeconds is the age of the DATA at write time, floored at zero.
//
// spine S6 requires as_of and staleness_seconds on every record, and
// research/06 Risk #5 is why: "never fail the scan — serve stale data with an
// as_of timestamp and a staleness_seconds field. A scan run on 3-day-old KEV
// data must say so." A publisher clock ahead of ours must not produce a
// negative age, which the cache's staleness_nonneg CHECK would refuse anyway.
func stalenessSeconds(now time.Time, lastModified string) int {
	v := strings.TrimSpace(lastModified)
	if v == "" {
		return 0
	}
	t, err := time.Parse(time.RFC1123, v)
	if err != nil {
		if t, err = time.Parse(time.RFC1123Z, v); err != nil {
			return 0
		}
	}
	if d := int(now.Sub(t).Seconds()); d > 0 {
		return d
	}
	return 0
}

// ---------------------------------------------------------------------------
// Unwrapping a polled body
// ---------------------------------------------------------------------------

// MaxUnpackedBytes bounds the total uncompressed size of one polled body.
//
// It is the decompression-bomb bound and it is measured on what ARRIVED, never
// on what a zip header claimed: a member that lies about its uncompressed size
// is stopped by the running total, not by its own metadata.
const MaxUnpackedBytes = 512 << 20

// unwrap turns a polled body into the documents inside it.
//
// A bare JSON body is one document. A zip is its members. A gzip is what it
// decompresses to. Anything else is ErrUnrecognisedShape, which SyncDelta turns
// into a routing note rather than a failure.
//
// FORMAT IS DECIDED BY THE BYTES. There is no feed-id-to-format table here for
// the same reason there is no feed-id-to-parser table in Decode: a mapping
// compiled into Go breaks the moment an operator points a row at a mirror, and
// what a body IS is a property of the body.
func unwrap(feedID string, body []byte) ([][]byte, error) {
	trimmed := bytes.TrimLeft(body, " \t\r\n\ufeff")
	if len(trimmed) == 0 {
		return nil, refuse(ErrUnrecognisedShape, "feed %q: the polled body is empty", feedID)
	}

	switch {
	case trimmed[0] == '{' || trimmed[0] == '[':
		return [][]byte{trimmed}, nil

	case bytes.HasPrefix(trimmed, []byte{0x50, 0x4b, 0x03, 0x04}), // "PK\x03\x04"
		bytes.HasPrefix(trimmed, []byte{0x50, 0x4b, 0x05, 0x06}):
		return unwrapZip(feedID, trimmed)

	case bytes.HasPrefix(trimmed, []byte{0x1f, 0x8b}):
		return unwrapGzip(feedID, trimmed)
	}
	return nil, refuse(ErrUnrecognisedShape,
		"feed %q: the polled body is neither JSON, nor a zip, nor gzip", feedID)
}

func unwrapZip(feedID string, body []byte) ([][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, refuse(ErrUnrecognisedShape, "feed %q: the body has a zip signature but does not open as one: %v", feedID, err)
	}
	var (
		out   [][]byte
		total int64
	)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("delta: feed %q: opening zip member %q: %w", feedID, clip(f.Name, 200), err)
		}
		data, err := readCapped(rc, MaxDocumentBytes)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("delta: feed %q: reading zip member %q: %w", feedID, clip(f.Name, 200), err)
		}
		total += int64(len(data))
		if total > MaxUnpackedBytes {
			return nil, refuse(ErrArchiveTooLarge,
				"feed %q: the polled body unpacks past the %d-byte cap", feedID, MaxUnpackedBytes)
		}
		trimmed := bytes.TrimLeft(data, " \t\r\n\ufeff")
		if len(trimmed) == 0 {
			continue
		}
		// A MEMBER THAT IS NOT JSON IS SKIPPED, NOT FATAL. This is the one
		// place this package skips anything, and it follows A.8's reasoning
		// exactly: an ecosystem archive is thousands of files written by
		// strangers, and a README or a checksums file must not cost the
		// advisories beside it. It is bounded to "the bytes are not a JSON
		// document at all" \u2014 a member that IS JSON and is in no shape this
		// decoder recognises still fails loudly, because that one is a
		// dropped advisory rather than a text file.
		if trimmed[0] != '{' && trimmed[0] != '[' {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil, refuse(ErrUnrecognisedShape, "feed %q: the zip holds no JSON member", feedID)
	}
	return out, nil
}

func unwrapGzip(feedID string, body []byte) ([][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, refuse(ErrUnrecognisedShape, "feed %q: the body has a gzip signature but does not open as one: %v", feedID, err)
	}
	defer func() { _ = gr.Close() }()
	data, err := readCapped(gr, MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("delta: feed %q: decompressing the body: %w", feedID, err)
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n\ufeff")
	if len(trimmed) == 0 {
		return nil, refuse(ErrUnrecognisedShape, "feed %q: the gzip decompresses to nothing", feedID)
	}
	return [][]byte{trimmed}, nil
}

// readCapped reads at most limit bytes and REFUSES at limit+1, so that a member
// lying about its size is stopped by what actually arrived.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, refuse(ErrDocumentTooLarge, "a document exceeded %d bytes while being read", limit)
	}
	return data, nil
}
