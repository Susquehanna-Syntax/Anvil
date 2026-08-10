// upsert.go is A.14's WRITE PATH: the decoded delta batch, and the row-scoped
// statements that put it in the A.2 cache.
//
// ===========================================================================
// THE ONE RULE THIS FILE EXISTS TO KEEP
// ===========================================================================
//
// A DELTA BATCH COSTS ONE UPSERT PER CHANGED ROW AND NOTHING ELSE. No DROP, no
// CREATE, no DELETE FROM advisory_fts that is not scoped to a single rowid, no
// `INSERT INTO advisory_fts(advisory_fts) VALUES('rebuild')`.
//
// internal/ingest/cache's own package comment gives the reason: "FTS5 accepts
// incremental INSERT/DELETE, so an hourly delta touching 200 records costs 200
// row upserts and NOT a rebuild. That is why no code path in Anvil may DROP or
// rebuild `advisory_fts`." A.14's packet repeats it as a forbidden action, and
// adds "regardless of batch size" — because the tempting version of this defect
// is a size threshold above which somebody decides a rebuild is cheaper.
//
// It is enforced by allowedStatements, an ALLOWLIST of the exact statement
// texts this package may hand to the driver. A denylist of forbidden verbs is
// the shape this project has already lost three guards to: `REBUILD` is not a
// verb, `advisory_fts(advisory_fts)` is not a DDL keyword, and a writer that
// composed its DROP from two concatenated fragments would defeat any pattern
// nobody thought to list. An allowlist has the opposite failure mode — a new
// statement fails loudly until somebody adds it on purpose.
//
// ===========================================================================
// WHY THIS PACKAGE HAS ITS OWN DECODER, AND WHAT THAT COSTS
// ===========================================================================
//
// internal/ingest/bootstrap decodes the same three JSON shapes and its
// decoders are unexported, so this file re-derives them. That is a REAL
// cross-area hazard of exactly the kind plan/00-SPINE.md S6 names for the
// fingerprint: two producers writing the same table from the same bytes may
// drift, and the drift shows up as A.15's weekly self-heal "restoring" rows
// forever with nothing surfacing why.
//
// It is not left to inspection. delta_test.go's
// TestDeltaAndBootstrapDecodeTheSameBytesIntoTheSameRows runs A.8's importer
// and this package's over the SAME fixture documents and compares every
// written column of `advisory`, `affected` and `cve_alias`. A divergence is a
// red test in this package, which is the only place the two can be compared at
// all. The permanent fix — one decode package both import — is reported to the
// orchestrator rather than taken here, because internal/ingest/bootstrap is
// merged and frozen and this packet may not edit it.
//
// ===========================================================================
// SANITIZE IS A PRECONDITION, AND IT IS CHECKED
// ===========================================================================
//
// Apply does not sanitize; Decode does, field by field, and Apply REFUSES a
// batch whose strings do not survive sanitize.AssertAllSanitized. That split is
// deliberate: A.15 builds Records from its own baseline read and must not be
// able to reach these statements with raw feed text just because it skipped a
// call. internal/ingest/sanitize's writer guard sees the assertion in the same
// function as the bind, which is what it can check; the assertion is what makes
// the claim true rather than merely visible.
package delta

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// The statement allowlist
// ---------------------------------------------------------------------------

// The four statements internal/ingest/cache does not export.
//
// They are byte-identical to the ones internal/ingest/bootstrap composes for
// the same tables, and that is on purpose: cache/schema.go exports the advisory
// and FTS write shapes precisely so two writers cannot disagree about them, and
// it exports nothing for `affected` or `cve_alias`. A second SHAPE here would
// be the defect that exporting the first four was meant to prevent, so these
// copy A.8's text exactly rather than improving on it. Reported to the
// orchestrator as the same gap A.8 reported.
const (
	deleteAffectedSQL = `DELETE FROM affected WHERE source = ? AND source_id = ?`

	insertAffectedSQL = `
INSERT INTO affected (source, source_id, ecosystem, package, purl, introduced, fixed, distro_backport)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	deleteAliasSQL = `DELETE FROM cve_alias WHERE source = ? AND source_id = ?`

	insertAliasSQL = `
INSERT INTO cve_alias (cve_id, source, source_id) VALUES (?, ?, ?)
ON CONFLICT (cve_id, source, source_id) DO NOTHING`
)

// selectModifiedSQL is the per-record freshness probe that makes the deltaLog
// route cheap: a record whose delta-log `dateUpdated` is not newer than what
// the cache already holds is NOT FETCHED. It is the difference between "poll
// every 15 minutes" and "download every changed record every 15 minutes".
const selectModifiedSQL = `SELECT modified FROM advisory WHERE source = ? AND source_id = ?`

// selectFTSRowidSQL reads the rowid an advisory currently occupies, which is
// the only address advisory_fts has for it. It is used on the tombstone path,
// where the FTS entry is deleted by rowid.
const selectFTSRowidSQL = `SELECT rowid FROM advisory WHERE source = ? AND source_id = ?`

// allowedStatements is THE GUARD. Every statement this package hands to the
// database driver must be a member, compared as exact text after trimming.
//
// It is a package-level var and not a function on purpose: internal/ingest/
// sanitize's writer guard walks FUNCTION bodies looking for the names of the
// cache's advisory write shapes, and a function that named them only to build
// this set would be flagged as an unsanitised writer. A var initialiser is not
// a function body, so the guard sees the real write site and not this one.
//
// The value is a human-readable reason. It is not decoration: a future reader
// deciding whether to add an entry needs to see what the existing entries had
// to justify, and "it seemed necessary" is not one of the reasons here.
var allowedStatements = map[string]string{
	strings.TrimSpace(cache.UpsertAdvisorySQL): "one advisory row, ON CONFLICT DO UPDATE, RETURNING the rowid " +
		"advisory_fts is addressed by. Never INSERT OR REPLACE: REPLACE re-inserts under a new rowid and " +
		"silently orphans the FTS entry.",
	strings.TrimSpace(cache.UpsertAdvisoryFTSSQL): "one FTS row by rowid. This is the row-scoped index write " +
		"that makes a 200-record delta cost 200 writes.",
	strings.TrimSpace(cache.DeleteAdvisoryFTSSQL): "one FTS row by rowid, for a tombstoned advisory. The " +
		"`advisory` row itself is never deleted (A.2 exit criterion 22).",
	strings.TrimSpace(deleteAffectedSQL): "the version ranges of ONE advisory. `affected` has a surrogate key " +
		"and no unique natural key, so ranges are replaced per advisory rather than merged.",
	strings.TrimSpace(insertAffectedSQL): "one version range of one advisory.",
	strings.TrimSpace(deleteAliasSQL):    "the CVE aliases of ONE advisory, replaced for the same reason.",
	strings.TrimSpace(insertAliasSQL):    "one CVE alias of one advisory.",
	strings.TrimSpace(selectModifiedSQL): "read-only freshness probe for one (source, source_id).",
	strings.TrimSpace(selectFTSRowidSQL): "read-only rowid lookup for one (source, source_id).",
	strings.TrimSpace(cache.SelectFeedStateSQL): "read-only feed_state read, used to decide what is DUE before " +
		"any poll is made.",
}

// checkStatement is the allowlist gate. Every database call in this package
// goes through it, and nothing else in this package may call the driver.
//
// The error names the statement so an operator sees WHAT was refused, and the
// message says what to do about it, because the correct response to a refusal
// here is nearly always "this statement is fine, add it deliberately" and the
// wrong response is to route around the check.
func checkStatement(q string) error {
	if _, ok := allowedStatements[strings.TrimSpace(q)]; ok {
		return nil
	}
	return refuse(ErrStatementNotAllowed,
		"this package may only execute statements on its allowlist and this one is not on it:\n\t%s\n"+
			"If it is a legitimate row-scoped write, add it to allowedStatements with the reason. "+
			"If it rebuilds, drops or re-creates advisory_fts, it is the thing A.14's packet forbids: "+
			"a delta batch costs one upsert per changed row, regardless of batch size.",
		condense(q))
}

// condense renders a statement on one line for an error message.
func condense(q string) string {
	return strings.Join(strings.Fields(q), " ")
}

// execTx runs one allowlisted statement inside a transaction.
func execTx(ctx context.Context, tx *sql.Tx, q string, args ...any) error {
	if err := checkStatement(q); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

// queryRowTx runs one allowlisted single-row query inside a transaction.
func queryRowTx(ctx context.Context, tx *sql.Tx, q string, args ...any) (*sql.Row, error) {
	if err := checkStatement(q); err != nil {
		return nil, err
	}
	return tx.QueryRowContext(ctx, q, args...), nil
}

// queryRowDB runs one allowlisted single-row query outside a transaction.
func queryRowDB(ctx context.Context, db *sql.DB, q string, args ...any) (*sql.Row, error) {
	if err := checkStatement(q); err != nil {
		return nil, err
	}
	return db.QueryRowContext(ctx, q, args...), nil
}

// ---------------------------------------------------------------------------
// The record model
// ---------------------------------------------------------------------------

// AffectedRange is one row of the cache's `affected` table: a package, an
// ecosystem, and the version window a comparator answers against.
//
// plan/00-SPINE.md S1 is why these rows are the point of Lane A at all:
// "CVE/OSV/GHSA describe vulnerable PACKAGE VERSIONS, and a version comparator
// answers that exactly and for free."
type AffectedRange struct {
	Ecosystem string
	Package   string
	PURL      string

	// Introduced and Fixed bound the vulnerable window. Either may be empty:
	// an OSV entry with a `last_affected` event and no `fixed` has no fixed
	// version, and that is a fact about the advisory, not a parse failure.
	Introduced string
	Fixed      string

	// DistroBackport marks a range that came from a vendor or distro advisory
	// rather than from upstream. research/12 §3: a distro backports a fix
	// without moving the upstream version, so an upstream range calls a
	// patched package vulnerable. This column is what A.17 needs to not do
	// that.
	DistroBackport bool
}

// Record is one decoded advisory, already sanitized, ready to bind.
//
// It is EXPORTED because A.15's reconciliation writes the same rows through
// the same path. A second write path for the same table is how a schema
// invariant survives in one writer and not the other.
type Record struct {
	// Source is the feed id and SourceID the native id within it. Together
	// they are the primary key, and it is NEVER the CVE id: research/06 Risk
	// #2 requires a cvelistV5 outage to be survivable by swapping sources,
	// and GHSA advisories frequently carry no CVE at all.
	Source   string
	SourceID string

	// CVEID is the nullable, indexed alias. Aliases carries the one-to-many.
	CVEID   string
	Aliases []string

	Published string
	Modified  string

	// State is one of cache.AdvisoryPublished / AdvisoryWithdrawn /
	// AdvisoryRejected. A non-published state MUST carry TombstonedAt, and
	// the schema's advisory_tombstone_paired CHECK refuses the row otherwise
	// — withdrawn advisories are tombstoned, never deleted, so that findings
	// that depended on them become invalidated rather than vanishing.
	State        string
	TombstonedAt string

	Severity   string
	CVSSVector string

	// CVSSScore and EPSSScore are `any` so that "no score" is SQL NULL rather
	// than 0.0. A zero CVSS base score is a real value, and a comparator that
	// cannot tell it from "absent" ranks an unscored advisory as harmless.
	CVSSScore any
	EPSSScore any
	EPSSAsOf  string

	KEV bool

	Description string
	References  []string

	Affected []AffectedRange

	// DataVersion is the record schema version the document declared, and
	// ParseDegraded is spine S6's field for "this was persisted anyway".
	// A.2 exit criterion 23: an unknown CVE dataVersion is PERSISTED with
	// parse_degraded = 1, never dropped, because silently discarding a record
	// from a newer schema is how a vulnerability disappears from a security
	// tool with no error anywhere.
	DataVersion   string
	ParseDegraded bool

	// StalenessSeconds overrides the batch-wide value when the record carries
	// its own age. Zero means "use the batch's".
	StalenessSeconds int

	// Raw is the document verbatim, stored in advisory.raw_json. It is never
	// sanitized: the column is the publisher's bytes, and CVE-TOU requires
	// records be stored byte-verbatim (research/06 §"License").
	Raw []byte
}

// ReferencesText is the `references_text` column of advisory_fts: the
// references as one newline-separated string, each element already sanitized.
func (r Record) ReferencesText() string { return strings.Join(r.References, "\n") }

// BatchStats counts what one Apply wrote. Every field counts WRITES, not net
// growth: `affected` and `cve_alias` are replaced per advisory, so a re-upsert
// of an unchanged advisory still counts its rows.
type BatchStats struct {
	// Upserts is advisory rows written, and is the number A.14's validation
	// asserts equals the batch size: 200 changed records, 200 upserts.
	Upserts int

	// FTSUpserts is row-scoped writes to advisory_fts, and FTSDeletes is
	// row-scoped deletes for tombstoned advisories. Their sum is the total
	// number of statements that touched the index — there is no other one.
	FTSUpserts int
	FTSDeletes int

	AffectedRows int
	AliasRows    int

	// Degraded counts rows persisted with parse_degraded = 1.
	Degraded int

	// Tombstoned counts rows written in a non-published state.
	Tombstoned int
}

// Merge folds o into s.
func (s *BatchStats) Merge(o BatchStats) {
	s.Upserts += o.Upserts
	s.FTSUpserts += o.FTSUpserts
	s.FTSDeletes += o.FTSDeletes
	s.AffectedRows += o.AffectedRows
	s.AliasRows += o.AliasRows
	s.Degraded += o.Degraded
	s.Tombstoned += o.Tombstoned
}

// MaxBatchRecords bounds one Apply.
//
// A delta batch is small by construction — research/06 measures the largest
// cvelistV5 hour at ~16.5 MiB of cumulative changes and the deltaLog names a
// few dozen records per fetch — and Apply is ONE TRANSACTION, so a batch that
// arrived here with hundreds of thousands of records is not a delta. It is a
// bulk import taking the wrong door, and the right answer is A.8's resumable,
// cursor-tracked path rather than a transaction that either commits a day's
// work or loses it.
const MaxBatchRecords = 50_000

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

// Apply upserts one decoded delta batch, row by row, in a single transaction.
//
// It is the whole write path. Nothing else in this package writes.
//
// THE LICENCE DECISION IS A PARAMETER AND NOT A LOOKUP. A caller has to hold
// an admitted license.Decision to reach this function at all, and the licence
// columns are bound from the DECISION rather than from the feed row's own
// claim — A.4 owns what a feed's licence is, and a writer that re-read the
// YAML would be laundering an unverified assertion into the cache. A refusal
// is refused here rather than defaulted, because Decision's zero value carries
// Tier 0, the most permissive tier this system has.
//
// asOf is stamped into every row and staleness is spine S6's staleness_seconds
// for the batch: the age of the DATA, not the age of the write.
func Apply(
	ctx context.Context,
	db *sql.DB,
	feed config.FeedConfig,
	d license.Decision,
	batch []Record,
	asOf time.Time,
	staleness int,
) (BatchStats, error) {
	var stats BatchStats
	if db == nil {
		return stats, refuse(ErrNoCache, "Apply needs the A.2 ingestion cache")
	}
	if d.Refused() {
		return stats, refuse(license.ErrLicenseRefused,
			"feed %q: the licence decision is a refusal (tier %d, dir %q), so no row may be written",
			feed.ID, d.Tier.Int(), d.Dir)
	}
	if len(batch) > MaxBatchRecords {
		return stats, refuse(ErrBatchTooLarge,
			"feed %q: %d records in one delta batch exceeds %d; a batch that size is a bulk import and "+
				"belongs on A.8's resumable path, not in one transaction",
			feed.ID, len(batch), MaxBatchRecords)
	}
	if staleness < 0 {
		staleness = 0
	}
	if len(batch) == 0 {
		return stats, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return stats, fmt.Errorf("delta: opening transaction for feed %q: %w", feed.ID, err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, rec := range batch {
		one, err := writeRecord(ctx, tx, feed, d, rec, asOf, staleness)
		if err != nil {
			return stats, err
		}
		stats.Merge(one)
	}
	if err := tx.Commit(); err != nil {
		return stats, fmt.Errorf("delta: committing %d records for feed %q: %w", len(batch), feed.ID, err)
	}
	return stats, nil
}

// writeRecord is the per-row write: one advisory upsert, one FTS write, and
// the advisory's own `affected` and `cve_alias` rows replaced.
//
// It writes exactly ONE advisory row and touches advisory_fts EXACTLY ONCE.
// That is the property A.14's validation measures, and it is a property of
// this function rather than of the loop above it.
func writeRecord(
	ctx context.Context,
	tx *sql.Tx,
	feed config.FeedConfig,
	d license.Decision,
	rec Record,
	asOf time.Time,
	staleness int,
) (BatchStats, error) {
	var stats BatchStats

	if strings.TrimSpace(rec.Source) == "" || strings.TrimSpace(rec.SourceID) == "" {
		return stats, refuse(ErrBadRecord,
			"feed %q: a record with source %q and source_id %q has no primary key",
			feed.ID, rec.Source, rec.SourceID)
	}
	if len(rec.Raw) == 0 {
		return stats, refuse(ErrBadRecord,
			"feed %q record %q: raw_json is NOT NULL and the column stores the publisher's bytes verbatim",
			feed.ID, rec.SourceID)
	}

	// A.3 IS A PRECONDITION AND THIS IS WHERE IT IS CHECKED. Every string
	// below is bound to a column; every one of them originated outside Anvil.
	// AssertAllSanitized fails on a value Sanitize would have changed, so a
	// caller that skipped the sanitizer cannot reach the bind.
	fields := map[string]string{
		"source_id":           rec.SourceID,
		"cve_id":              rec.CVEID,
		"published":           rec.Published,
		"modified":            rec.Modified,
		"tombstoned_at":       rec.TombstonedAt,
		"severity":            rec.Severity,
		"cvss_vector":         rec.CVSSVector,
		"epss_as_of":          rec.EPSSAsOf,
		"description":         rec.Description,
		"references_text":     rec.ReferencesText(),
		"data_version":        rec.DataVersion,
		"license_manual_note": d.ManualNote,
	}
	for i, a := range rec.Affected {
		fields["affected["+strconv.Itoa(i)+"].ecosystem"] = a.Ecosystem
		fields["affected["+strconv.Itoa(i)+"].package"] = a.Package
		fields["affected["+strconv.Itoa(i)+"].purl"] = a.PURL
		fields["affected["+strconv.Itoa(i)+"].introduced"] = a.Introduced
		fields["affected["+strconv.Itoa(i)+"].fixed"] = a.Fixed
	}
	for i, a := range rec.Aliases {
		fields["alias["+strconv.Itoa(i)+"]"] = a
	}
	if err := sanitize.AssertAllSanitized(fields); err != nil {
		return stats, fmt.Errorf("%w: feed %q record %q: %w", ErrUnsanitized, feed.ID, rec.SourceID, err)
	}

	state := rec.State
	if state == "" {
		state = cache.AdvisoryPublished
	}
	var tombstone any
	if state != cache.AdvisoryPublished {
		ts := rec.TombstonedAt
		if ts == "" {
			// The schema pairs a non-published state with a non-null
			// tombstone. A publisher that withdrew a record without saying
			// when still has to be recorded as withdrawn, so the batch's own
			// clock stands in — losing the "when" is better than losing the
			// withdrawal, and dropping the row is not an option at all.
			ts = asOf.UTC().Format(time.RFC3339)
		}
		tombstone = ts
		stats.Tombstoned++
	}

	rowStaleness := rec.StalenessSeconds
	if rowStaleness <= 0 {
		rowStaleness = staleness
	}

	row, err := queryRowTx(ctx, tx, cache.UpsertAdvisorySQL,
		rec.Source, rec.SourceID, nullable(rec.CVEID), nullable(rec.Published), nullable(rec.Modified),
		state, tombstone, nullable(rec.Severity), nullable(rec.CVSSVector), rec.CVSSScore,
		rec.EPSSScore, nullable(rec.EPSSAsOf), boolInt(rec.KEV),
		nullable(d.EffectiveSPDX), nullable(d.ManualNote), d.Tier.Int(),
		string(cache.AdvisoryTrustDefault),
		asOf.UTC().Format(time.RFC3339), rowStaleness, boolInt(rec.ParseDegraded),
		nullable(rec.DataVersion), rec.Raw,
	)
	if err != nil {
		return stats, err
	}
	var rowid int64
	if err := row.Scan(&rowid); err != nil {
		return stats, fmt.Errorf("delta: upserting %s/%s: %w", rec.Source, rec.SourceID, err)
	}
	stats.Upserts++
	if rec.ParseDegraded {
		stats.Degraded++
	}

	// THE INDEX IS TOUCHED ONCE, BY ROWID. A tombstoned advisory leaves the
	// index (its text must stop matching) while its `advisory` row stays, which
	// is exit criterion 22's "tombstoned, never deleted" seen from the FTS
	// side.
	if state == cache.AdvisoryPublished {
		if err := execTx(ctx, tx, cache.UpsertAdvisoryFTSSQL, rowid, rec.Description, rec.ReferencesText()); err != nil {
			return stats, fmt.Errorf("delta: indexing %s/%s: %w", rec.Source, rec.SourceID, err)
		}
		stats.FTSUpserts++
	} else {
		if err := execTx(ctx, tx, cache.DeleteAdvisoryFTSSQL, rowid); err != nil {
			return stats, fmt.Errorf("delta: unindexing tombstoned %s/%s: %w", rec.Source, rec.SourceID, err)
		}
		stats.FTSDeletes++
	}

	// Replace, never append. `affected` has a surrogate primary key and no
	// unique constraint over its natural key, so an advisory upserted twice
	// would otherwise carry every version range twice and A.17's comparator
	// would see one advisory as several.
	if err := execTx(ctx, tx, deleteAffectedSQL, rec.Source, rec.SourceID); err != nil {
		return stats, fmt.Errorf("delta: clearing affected for %s/%s: %w", rec.Source, rec.SourceID, err)
	}
	for _, a := range rec.Affected {
		if err := execTx(ctx, tx, insertAffectedSQL,
			rec.Source, rec.SourceID, a.Ecosystem, a.Package, nullable(a.PURL),
			nullable(a.Introduced), nullable(a.Fixed), boolInt(a.DistroBackport)); err != nil {
			return stats, fmt.Errorf("delta: writing affected for %s/%s: %w", rec.Source, rec.SourceID, err)
		}
		stats.AffectedRows++
	}

	if err := execTx(ctx, tx, deleteAliasSQL, rec.Source, rec.SourceID); err != nil {
		return stats, fmt.Errorf("delta: clearing cve_alias for %s/%s: %w", rec.Source, rec.SourceID, err)
	}
	for _, alias := range rec.Aliases {
		if alias == "" {
			continue
		}
		if err := execTx(ctx, tx, insertAliasSQL, alias, rec.Source, rec.SourceID); err != nil {
			return stats, fmt.Errorf("delta: writing cve_alias for %s/%s: %w", rec.Source, rec.SourceID, err)
		}
		stats.AliasRows++
	}
	return stats, nil
}

// nullable renders an empty string as SQL NULL. An empty TEXT and a NULL are
// different facts, and `advisory.cve_id IS NULL` is the one the alias design
// depends on.
func nullable(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Freshness probe — the reason the deltaLog route is cheap
// ---------------------------------------------------------------------------

// CachedModified returns the `modified` timestamp the cache currently holds for
// one advisory, and whether the row exists at all.
//
// This is A.14's cursor, and it is a QUERY rather than a stored column ON
// PURPOSE. feed_state has exactly one cursor column, `watermark`, and A.8
// already owns it: it stores a bootstrap Progress token there and A.14 reads
// the handover through bootstrap.Handoff. A second delta cursor squeezed into
// the same column would be two writers on one value, which is the failure A.8's
// own watermark doc comment describes.
//
// Deriving the cursor from the rows themselves has a property a stored cursor
// does not: it cannot disagree with the data. A record the cache is missing has
// no `modified` at all, so it is always fetched; a record the cache holds at or
// past the delta log's `dateUpdated` is never fetched. A cursor that skipped
// ahead of a failed write would silently lose the record forever.
func CachedModified(ctx context.Context, db *sql.DB, source, sourceID string) (string, bool, error) {
	row, err := queryRowDB(ctx, db, selectModifiedSQL, source, sourceID)
	if err != nil {
		return "", false, err
	}
	var modified sql.NullString
	switch err := row.Scan(&modified); {
	case err == sql.ErrNoRows:
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("delta: reading cached modified for %s/%s: %w", source, sourceID, err)
	}
	return modified.String, true, nil
}

// isNewer reports whether a delta log's claimed update time is strictly newer
// than what the cache holds.
//
// IT FAILS TOWARD FETCHING. An unparseable timestamp on either side, or an
// absent row, returns true: re-fetching a record Anvil already has costs one
// small request, and skipping a record it does not have costs a missed
// vulnerability. Those are not comparable errors and the comparison must not
// pretend they are.
func isNewer(claimed, cached string) bool {
	c, okClaimed := parseTimestamp(claimed)
	h, okCached := parseTimestamp(cached)
	if !okClaimed || !okCached {
		return true
	}
	return c.After(h)
}

// parseTimestamp accepts the two shapes advisory feeds actually emit: RFC3339
// with an offset, and RFC3339 with fractional seconds. A value in neither shape
// is reported as unparseable rather than coerced, so isNewer can fail toward
// fetching instead of toward a wrong comparison.
func parseTimestamp(s string) (time.Time, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if v, err := time.Parse(layout, t); err == nil {
			return v.UTC(), true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// MaxDocumentBytes bounds a single advisory document.
//
// It is the same order as A.8's own record cap and exists for the same reason:
// a feed that answers a record request with a gigabyte is a memory-exhaustion
// payload, and the bound has to be on what ARRIVED rather than on what a header
// claimed.
const MaxDocumentBytes = 16 << 20

// decoder is A.3 applied field by field, accumulating what was removed.
//
// The `s` method is named rather than inlined for the same reason A.8 names
// its own: internal/ingest/sanitize's writer guard resolves the package-local
// call graph by NAME, so a decoder that reaches the sanitizer through one
// method is visible to the guard, and there is exactly one place a field could
// be bound without passing through it — which is none.
type decoder struct {
	feedID string
	stats  sanitize.SanitizeStats
}

func (dc *decoder) s(raw string) string {
	clean, st := sanitize.Sanitize(raw)
	dc.stats.Merge(st)
	return clean
}

// Decode turns one fetched document into advisory records.
//
// THE FORMAT IS DECIDED BY LOOKING AT THE BYTES, never by which feed asked.
// A.1's rule — no feed fact compiled into Go — applies to a format mapping just
// as much as to a URL: a feed-id-to-parser table breaks the moment an operator
// points a row at a mirror, and what a document IS is a property of the
// document.
//
// A shape this decoder does not recognise is an ERROR and not a silent skip.
// That differs from A.8, which skips unrecognised archive members because a
// bulk archive is 300,000 files written by strangers and one bad member must
// not cost the other 299,999. A delta document is different: it was fetched
// because something said it changed, so "we do not understand it" means a
// change was dropped, and the caller needs to route the feed to a path that
// does understand it. SyncDelta does exactly that.
func Decode(feedID string, raw []byte) ([]Record, sanitize.SanitizeStats, error) {
	dc := &decoder{feedID: feedID}
	recs, err := dc.decode(raw, 0)
	return recs, dc.stats, err
}

// maxDecodeDepth bounds the array-of-documents recursion. One level of nesting
// is real (a JSON array of advisories); two is a document lying about its
// shape.
const maxDecodeDepth = 2

func (dc *decoder) decode(raw []byte, depth int) ([]Record, error) {
	if len(raw) > MaxDocumentBytes {
		return nil, refuse(ErrDocumentTooLarge,
			"feed %q: a %d-byte document exceeds the %d-byte cap", dc.feedID, len(raw), MaxDocumentBytes)
	}
	if depth > maxDecodeDepth {
		return nil, refuse(ErrUnrecognisedShape,
			"feed %q: nested arrays of documents beyond depth %d", dc.feedID, maxDecodeDepth)
	}

	// A UTF-8 BOM is written as an escape rather than as a literal: a literal
	// BOM in a Go source file is a compile error and is exactly the kind of
	// invisible character internal/ingest/invisible keeps out of this tree.
	trimmed := bytes.TrimLeft(raw, " \t\r\n\ufeff")
	if len(trimmed) == 0 {
		return nil, refuse(ErrUnrecognisedShape, "feed %q: the document is empty", dc.feedID)
	}

	head := trimmed
	if len(head) > 4096 {
		head = head[:4096]
	}

	switch {
	case trimmed[0] == '[':
		var elems []json.RawMessage
		if err := json.Unmarshal(trimmed, &elems); err != nil {
			return nil, refuse(ErrUnrecognisedShape, "feed %q: the document opens as a JSON array but does not parse as one: %v", dc.feedID, err)
		}
		var out []Record
		for _, e := range elems {
			recs, err := dc.decode(e, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, recs...)
		}
		return out, nil

	case trimmed[0] != '{':
		return nil, refuse(ErrUnrecognisedShape,
			"feed %q: the document is not JSON. CSV, XML and per-branch distro formats reach the cache "+
				"through A.8's bulk path; SyncDelta routes such a feed there rather than guessing here.",
			dc.feedID)

	case bytes.Contains(head, []byte(`"fetchTime"`)) && bytes.Contains(head, []byte(`"numberOfChanges"`)):
		return nil, refuse(ErrUnrecognisedShape,
			"feed %q: this is a delta LOG, not an advisory. It names what changed; it does not carry it. "+
				"Parse it with ParseDeltaLog and fetch the records it names.", dc.feedID)

	case bytes.Contains(head, []byte(`"vulnerabilities"`)) &&
		(bytes.Contains(head, []byte(`"catalogVersion"`)) || bytes.Contains(head, []byte(`"cveID"`))):
		return dc.decodeKEV(trimmed)

	case bytes.Contains(head, []byte(`"CVE_RECORD"`)):
		rec, ok, err := dc.decodeCVE5(trimmed)
		if err != nil || !ok {
			return nil, refuse(ErrUnrecognisedShape, "feed %q: a CVE_RECORD document did not decode: %v", dc.feedID, err)
		}
		return []Record{rec}, nil

	default:
		rec, ok, err := dc.decodeOSV(trimmed)
		if err != nil || !ok {
			return nil, refuse(ErrUnrecognisedShape,
				"feed %q: the document is a JSON object in no shape this decoder recognises "+
					"(not OSV, not CVE 5.x, not KEV): %v", dc.feedID, err)
		}
		return []Record{rec}, nil
	}
}

// --- OSV, and therefore GHSA: github/advisory-database is OSV format ---

type osvDoc struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Withdrawn     string         `json:"withdrawn"`
	Published     string         `json:"published"`
	Modified      string         `json:"modified"`
	Summary       string         `json:"summary"`
	Details       string         `json:"details"`
	Aliases       []string       `json:"aliases"`
	Related       []string       `json:"related"`
	Severity      []osvSeverity  `json:"severity"`
	References    []osvReference `json:"references"`
	Affected      []osvAffected  `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
			LastAffect string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

func (dc *decoder) decodeOSV(raw []byte) (Record, bool, error) {
	var d osvDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Record{}, false, err
	}
	if d.ID == "" {
		return Record{}, false, nil
	}

	rec := Record{
		Source:   dc.feedID,
		SourceID: dc.s(d.ID),
		State:    cache.AdvisoryPublished,
		Raw:      raw,
	}
	if d.Withdrawn != "" {
		rec.State = cache.AdvisoryWithdrawn
		rec.TombstonedAt = dc.s(d.Withdrawn)
	}
	rec.Published = dc.s(d.Published)
	rec.Modified = dc.s(d.Modified)
	rec.Description = dc.s(strings.TrimSpace(d.Summary + "\n\n" + d.Details))
	for _, s := range d.Severity {
		if strings.HasPrefix(strings.ToUpper(s.Type), "CVSS") {
			rec.CVSSVector = dc.s(s.Score)
			break
		}
	}
	for _, r := range d.References {
		if r.URL != "" {
			rec.References = append(rec.References, dc.s(r.URL))
		}
	}

	for _, a := range append(append([]string{}, d.Aliases...), d.Related...) {
		if IsCVEID(a) {
			rec.Aliases = appendUnique(rec.Aliases, dc.s(a))
		}
	}
	if IsCVEID(d.ID) {
		rec.CVEID = rec.SourceID
		rec.Aliases = appendUnique(rec.Aliases, rec.SourceID)
	} else if len(rec.Aliases) > 0 {
		rec.CVEID = rec.Aliases[0]
	}

	for _, a := range d.Affected {
		eco := dc.s(a.Package.Ecosystem)
		pkg := dc.s(a.Package.Name)
		if eco == "" || pkg == "" {
			continue
		}
		purl := dc.s(a.Package.PURL)
		backport := isDistroEcosystem(eco)
		emitted := false
		for _, rg := range a.Ranges {
			var introduced string
			for _, ev := range rg.Events {
				switch {
				case ev.Introduced != "":
					introduced = dc.s(ev.Introduced)
				case ev.Fixed != "":
					rec.Affected = append(rec.Affected, AffectedRange{
						Ecosystem: eco, Package: pkg, PURL: purl,
						Introduced: introduced, Fixed: dc.s(ev.Fixed), DistroBackport: backport,
					})
					emitted = true
				case ev.LastAffect != "":
					rec.Affected = append(rec.Affected, AffectedRange{
						Ecosystem: eco, Package: pkg, PURL: purl,
						Introduced: introduced, DistroBackport: backport,
					})
					emitted = true
				}
			}
		}
		if !emitted {
			rec.Affected = append(rec.Affected, AffectedRange{
				Ecosystem: eco, Package: pkg, PURL: purl, DistroBackport: backport,
			})
		}
	}
	return rec, true, nil
}

// isDistroEcosystem marks the ecosystems whose advisories carry BACKPORTED
// fixes. research/12 §3, the CVE-2023-32681 / RHSA-2023:4520 class: a distro
// patches without moving the upstream version, so an upstream range calls a
// fixed package vulnerable.
//
// The list matches A.8's exactly. It is duplicated for the same reason the
// decoders are, and the same conformance test covers it: a divergence changes
// `affected.distro_backport` for the same bytes depending on which importer ran.
func isDistroEcosystem(eco string) bool {
	lower := strings.ToLower(eco)
	for _, p := range []string{
		"ubuntu", "debian", "alpine", "red hat", "redhat", "rocky", "almalinux",
		"suse", "photon", "chainguard", "wolfi", "mageia",
	} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// --- CVE 5.x, the shape the deltaLog names ---

type cve5Doc struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CVEMetadata struct {
		CVEID     string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
		Rejected  string `json:"dateRejected"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cve5Container   `json:"cna"`
		ADP []cve5Container `json:"adp"`
	} `json:"containers"`
}

type cve5Container struct {
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Metrics []struct {
		CVSSv31 *cve5CVSS `json:"cvssV3_1"`
		CVSSv30 *cve5CVSS `json:"cvssV3_0"`
		CVSSv40 *cve5CVSS `json:"cvssV4_0"`
	} `json:"metrics"`
	Affected []struct {
		Vendor   string   `json:"vendor"`
		Product  string   `json:"product"`
		PackageN string   `json:"packageName"`
		Repo     string   `json:"repo"`
		CPEs     []string `json:"cpes"`
		Versions []struct {
			Version     string `json:"version"`
			LessThan    string `json:"lessThan"`
			LessOrEqual string `json:"lessThanOrEqual"`
			Status      string `json:"status"`
		} `json:"versions"`
	} `json:"affected"`
}

type cve5CVSS struct {
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// knownCVEDataVersions are the record schema versions this decoder was written
// against. An UNKNOWN one is PERSISTED with parse_degraded = 1 and never
// dropped (A.2 exit criterion 23, spine S6): silently discarding a record from
// a newer schema is how a vulnerability disappears from a security tool with no
// error anywhere.
//
// It matches A.8's list, and the conformance test is what keeps it matching.
var knownCVEDataVersions = map[string]bool{"5.0": true, "5.1": true, "5.2": true}

func (dc *decoder) decodeCVE5(raw []byte) (Record, bool, error) {
	var d cve5Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Record{}, false, err
	}
	if d.CVEMetadata.CVEID == "" {
		return Record{}, false, nil
	}

	rec := Record{
		Source:        dc.feedID,
		SourceID:      dc.s(d.CVEMetadata.CVEID),
		CVEID:         dc.s(d.CVEMetadata.CVEID),
		Published:     dc.s(d.CVEMetadata.Published),
		Modified:      dc.s(d.CVEMetadata.Updated),
		State:         cache.AdvisoryPublished,
		DataVersion:   dc.s(d.DataVersion),
		ParseDegraded: !knownCVEDataVersions[strings.TrimSpace(d.DataVersion)],
		Raw:           raw,
	}
	rec.Aliases = append(rec.Aliases, rec.CVEID)
	if strings.EqualFold(d.CVEMetadata.State, "REJECTED") {
		rec.State = cache.AdvisoryRejected
		rec.TombstonedAt = dc.s(firstNonEmpty(d.CVEMetadata.Rejected, d.CVEMetadata.Updated))
	}

	containers := append([]cve5Container{d.Containers.CNA}, d.Containers.ADP...)
	for _, c := range containers {
		for _, desc := range c.Descriptions {
			if rec.Description == "" && (desc.Lang == "" || strings.HasPrefix(strings.ToLower(desc.Lang), "en")) {
				rec.Description = dc.s(desc.Value)
			}
		}
		for _, ref := range c.References {
			if ref.URL != "" {
				rec.References = appendUnique(rec.References, dc.s(ref.URL))
			}
		}
		for _, m := range c.Metrics {
			for _, v := range []*cve5CVSS{m.CVSSv40, m.CVSSv31, m.CVSSv30} {
				if v == nil || v.VectorString == "" || rec.CVSSVector != "" {
					continue
				}
				rec.CVSSVector = dc.s(v.VectorString)
				rec.Severity = dc.s(v.BaseSeverity)
				score := v.BaseScore
				rec.CVSSScore = score
			}
		}
		for _, a := range c.Affected {
			pkg := dc.s(firstNonEmpty(a.PackageN, a.Product))
			if pkg == "" {
				continue
			}
			eco := dc.s(firstNonEmpty(a.Vendor, "cpe"))
			for _, v := range a.Versions {
				if strings.EqualFold(v.Status, "unaffected") {
					continue
				}
				rec.Affected = append(rec.Affected, AffectedRange{
					Ecosystem:  eco,
					Package:    pkg,
					Introduced: dc.s(v.Version),
					Fixed:      dc.s(firstNonEmpty(v.LessThan, v.LessOrEqual)),
				})
			}
		}
	}
	return rec, true, nil
}

// --- CISA KEV ---

// kevDoc keeps its entries as RAW MESSAGES rather than as decoded structs.
//
// That is not a style choice: `advisory.raw_json` stores the publisher's bytes
// verbatim, and re-marshalling a decoded struct would store Anvil's rendering
// of the entry instead — different key order, dropped unknown fields, and a
// different digest from the one A.8 writes for the same catalogue entry. The
// conformance test compares those bytes.
type kevDoc struct {
	CatalogVersion  string            `json:"catalogVersion"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

// decodeKEV reads the whole catalogue into memory rather than streaming it,
// which is the one place this decoder deliberately differs from A.8's.
//
// The reason is the caller. A.8 streams because it walks a 570 MB archive whose
// members it has not seen; this decoder is handed a body A.7 already read into
// memory under Options.MaxBodyBytes, so a streaming parse here would buy
// nothing and would need a second bounded reader to enforce a bound that has
// already been enforced. MaxDocumentBytes is the backstop.
func (dc *decoder) decodeKEV(raw []byte) ([]Record, error) {
	var d kevDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, refuse(ErrUnrecognisedShape, "feed %q: a KEV-shaped document did not parse: %v", dc.feedID, err)
	}
	out := make([]Record, 0, len(d.Vulnerabilities))
	for _, entryRaw := range d.Vulnerabilities {
		var e kevEntry
		if err := json.Unmarshal(entryRaw, &e); err != nil || e.CVEID == "" {
			// A single malformed catalogue entry is skipped, not fatal: the
			// KEV catalogue is one document holding every entry, and one bad
			// entry must not cost the rest. This is the one place a skip is
			// right, and it is bounded to a single element.
			continue
		}
		rec := Record{
			Source:      dc.feedID,
			SourceID:    dc.s(e.CVEID),
			CVEID:       dc.s(e.CVEID),
			Published:   dc.s(e.DateAdded),
			State:       cache.AdvisoryPublished,
			KEV:         true,
			Description: dc.s(strings.TrimSpace(e.VulnerabilityName + "\n\n" + e.ShortDescription + "\n\n" + e.RequiredAction)),
			Raw:         append([]byte(nil), entryRaw...),
		}
		rec.Aliases = append(rec.Aliases, rec.CVEID)
		if pkg := dc.s(e.Product); pkg != "" {
			rec.Affected = append(rec.Affected, AffectedRange{
				Ecosystem: dc.s(firstNonEmpty(e.VendorProject, "vendor")),
				Package:   pkg,
			})
		}
		if e.Notes != "" {
			rec.References = append(rec.References, dc.s(e.Notes))
		}
		out = append(out, rec)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

// IsCVEID is the ALLOWLIST that decides whether a string from a feed may be
// treated as a CVE identifier.
//
// It is exported because it is not only a parsing convenience: the deltaLog
// route in delta.go uses it as the ONLY thing that may cross from feed content
// into a fetch, so its strictness is a security property and not a nicety. See
// checkRecordName.
//
// The shape is CVE-<4+ digits>-<1+ digits> and nothing else. It is an allowlist
// of characters and structure, not a denylist of dangerous ones: this project
// has lost three guards to a symbol, a verb or a wording nobody listed, and
// `CVE-2024-0001/../../etc/passwd` is precisely the string a denylist misses.
func IsCVEID(s string) bool {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "CVE-") || len(t) < 8 {
		return false
	}
	rest := t[4:]
	dash := strings.Index(rest, "-")
	if dash < 4 {
		return false
	}
	for _, r := range rest[:dash] {
		if r < '0' || r > '9' {
			return false
		}
	}
	tail := rest[dash+1:]
	if tail == "" {
		return false
	}
	for _, r := range tail {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
