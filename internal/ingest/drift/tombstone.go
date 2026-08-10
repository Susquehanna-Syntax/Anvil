// tombstone.go is the other half of A.16: what happens when a publisher takes
// an advisory back.
//
// ===========================================================================
// THE ROW IS NEVER DELETED, AND THIS FILE CANNOT DELETE IT
// ===========================================================================
//
// research/06 Risk #4: "Withdrawn and poisoned advisories... Anvil must
// propagate retractions as tombstones... must be able to re-open and
// invalidate a prior finding when its advisory is withdrawn." A.2 exit
// criterion 22 says the same thing from the schema's side, and
// internal/ingest/cache enforces the pairing with a named CHECK: a state that
// is not 'published' must carry a `tombstoned_at`.
//
// A DELETE would satisfy neither. A finding that referenced the advisory would
// lose the row it points at, and "this advisory was retracted, re-open the
// finding" would become indistinguishable from "this advisory never existed" —
// which is the silent-vanishing outcome the spine's regression checking is
// specifically written against.
//
// The rule is not left to care. Every statement this package hands to the
// driver must be on allowedStatements, an ALLOWLIST of exact texts. There is
// no DELETE against `advisory` on it and no way to add one by accident: a
// statement that is not a member is refused with ErrStatementNotAllowed before
// it reaches the database. The shape is A.14's, deliberately — a denylist of
// forbidden verbs is what this project has already lost three guards to.
//
// ===========================================================================
// WHY THE WRITE GOES THROUGH cache.UpsertAdvisorySQL AND NOT THROUGH AN UPDATE
// ===========================================================================
//
// internal/ingest/cache/schema.go names this step explicitly: the advisory
// write shape is exported "because the alternative — each of A.7, A.8, A.14,
// A.15 and A.16 composing its own upsert — is how a second, subtly different
// write shape enters a schema and breaks the FTS linkage or the tombstone
// invariant with no error message."
//
// So the tombstone is a READ-MODIFY-WRITE through the shared statement: the
// row is read back, two columns are replaced, and the whole row is bound to
// the same ON CONFLICT DO UPDATE every other writer uses. It costs one extra
// SELECT and buys the property that there is exactly one statement in this
// system that writes an `advisory` row.
//
// Two consequences worth stating, because both would otherwise look like
// oversights:
//
//   - THE LICENCE COLUMNS ARE RE-BOUND FROM THE ROW, never re-derived. A
//     retraction is not a licence decision. A.4's Gate owns that, and a second
//     gate invoked from here would be an unreviewed one.
//   - THE ROWID IS PRESERVED, because ON CONFLICT DO UPDATE updates in place.
//     INSERT OR REPLACE would delete and re-insert under a NEW rowid and
//     orphan the FTS entry silently — the exact defect cache/schema.go
//     documents at the `advisory` table.
package drift

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrNoCache is a Tombstoner built without the A.2 ingestion cache.
	ErrNoCache = fmt.Errorf("%w: no ingestion cache", ErrDriftRefused)

	// ErrNoSuchAdvisory is a tombstone for a (source, source_id) the cache
	// does not hold. It is a REFUSAL and not a no-op: "the retraction was
	// applied" and "there was nothing to apply it to" are different facts, and
	// a caller that cannot tell them apart will report the second as the
	// first.
	ErrNoSuchAdvisory = fmt.Errorf("%w: no such advisory", ErrDriftRefused)

	// ErrReasonNotAllowed is the reason allowlist refusing a retraction reason
	// it does not know. See Reason.
	ErrReasonNotAllowed = fmt.Errorf("%w: retraction reason not on the allowlist", ErrDriftRefused)

	// ErrStatementNotAllowed is the SQL allowlist refusing a statement. It is
	// what stands between a retraction and a DELETE.
	ErrStatementNotAllowed = fmt.Errorf("%w: statement not on the allowlist", ErrDriftRefused)

	// ErrBadKey is an empty source or source_id.
	ErrBadKey = fmt.Errorf("%w: incomplete primary key", ErrDriftRefused)
)

// ---------------------------------------------------------------------------
// The reason allowlist
// ---------------------------------------------------------------------------

// Reason is why an advisory was retracted. It is an ALLOWLIST: a value not
// named below is refused, and no reason is ever defaulted.
//
// The default is what matters here. `advisory.state` has three legal values
// and 'published' is one of them, so a reason that fell through to a default
// would tombstone the row into the state that means NOT tombstoned — and the
// schema's advisory_tombstone_paired CHECK would then refuse the row for
// carrying a `tombstoned_at`, which reads at the call site as a database fault
// rather than as a missing case.
type Reason string

const (
	// ReasonWithdrawn is a publisher retracting an advisory: OSV's
	// `withdrawn`, a GHSA withdrawal.
	ReasonWithdrawn Reason = "withdrawn"

	// ReasonRejected is a CVE record in the REJECTED state.
	ReasonRejected Reason = "rejected"

	// ReasonPoisoned is research/06 Risk #4's other half — an advisory Anvil
	// itself distrusts rather than one the publisher pulled.
	//
	// It maps to the WITHDRAWN state, and the mapping is a fact about the
	// schema and not a judgement: `advisory.state`'s CHECK admits exactly
	// three values, A.2 is merged and frozen, and inventing a fourth here
	// would be a write the database refuses. The distinction survives on the
	// returned TombstoneResult, which carries the Reason as given.
	ReasonPoisoned Reason = "poisoned"
)

// reasonState maps each allowlisted reason to the `advisory.state` value it
// writes. The values are internal/ingest/cache's CONSTANTS and never string
// literals: a bare literal for an enum value is how ten cross-area defects
// happened on this project.
var reasonState = map[Reason]string{
	ReasonWithdrawn: cache.AdvisoryWithdrawn,
	ReasonRejected:  cache.AdvisoryRejected,
	ReasonPoisoned:  cache.AdvisoryWithdrawn,
}

// Reasons returns the allowlisted retraction reasons in a stable order.
func Reasons() []Reason {
	out := make([]Reason, 0, len(reasonState))
	for r := range reasonState {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// StateForReason resolves a retraction reason to the `advisory.state` it
// writes, or refuses.
//
// THE COMPARISON IS EXACT. No trimming, no case folding, no "withdrawn " with
// a trailing space quietly accepted: a caller passing a reason it built by
// string concatenation should find out here rather than have the value
// normalised into something it did not mean.
func StateForReason(reason string) (string, error) {
	state, ok := reasonState[Reason(reason)]
	if !ok {
		allowed := make([]string, 0, len(reasonState))
		for _, r := range Reasons() {
			allowed = append(allowed, string(r))
		}
		return "", refuse(ErrReasonNotAllowed,
			"%q is not a retraction reason this package knows; the allowlist is [%s]. "+
				"If a new retraction kind is real, add it with the advisory state it maps to — "+
				"there is deliberately no default, because the default would be 'published'.",
			clip(reason, 64), strings.Join(allowed, " "))
	}
	return state, nil
}

// ---------------------------------------------------------------------------
// The statement allowlist
// ---------------------------------------------------------------------------

// selectAdvisoryRowSQL reads back every column the shared upsert binds, plus
// the rowid advisory_fts is addressed by. It is a read: nothing here can
// change a row.
const selectAdvisoryRowSQL = `
SELECT rowid, cve_id, published, modified, state, tombstoned_at,
       severity, cvss_vector, cvss_score, epss_score, epss_as_of, kev,
       license_spdx, license_manual_note, license_tier, anvil_trust,
       as_of, staleness_seconds, parse_degraded, data_version, raw_json
FROM advisory WHERE source = ? AND source_id = ?`

// selectFindingsForAdvisorySQL is the "active findings referencing this
// advisory" query A.16's validation names.
//
// IT IS A LEFT JOIN, and that is the load-bearing detail. An inner join would
// drop a finding whose advisory row had gone missing — which is precisely the
// silent vanishing this whole file exists to prevent — so a missing advisory
// surfaces as a row with no state, marked invalidated, rather than as a
// shorter result set nobody can see the shape of.
const selectFindingsForAdvisorySQL = `
SELECT f.id, f.collector, f.source, f.source_id, f.package, f.installed_version,
       f.ecosystem, f.remediable_by_agent, f.detected_at, a.state, a.tombstoned_at
FROM finding f
LEFT JOIN advisory a ON a.source = f.source AND a.source_id = f.source_id
WHERE f.source = ? AND f.source_id = ?
ORDER BY f.id`

// selectInvalidatedFindingsSQL is the same read across the whole cache: every
// finding whose advisory is no longer published. It is the work list for the
// re-open pass the spine's regression checking requires.
const selectInvalidatedFindingsSQL = `
SELECT f.id, f.collector, f.source, f.source_id, f.package, f.installed_version,
       f.ecosystem, f.remediable_by_agent, f.detected_at, a.state, a.tombstoned_at
FROM finding f
LEFT JOIN advisory a ON a.source = f.source AND a.source_id = f.source_id
WHERE a.state IS NULL OR a.state <> 'published'
ORDER BY f.source, f.source_id, f.id`

// allowedStatements is THE GUARD. Every statement this package hands to the
// database driver must be a member, compared as exact text after trimming.
//
// THERE IS NO DELETE AGAINST `advisory` HERE AND THERE MUST NEVER BE ONE. Two
// tests in drift_test.go hold that: one runs a hand-written
// `DELETE FROM advisory ...` through this package's own exec helper and
// requires the refusal, and one scans the allowlist's KEYS for any statement
// that deletes from `advisory` or `finding`, so the guard cannot be defeated
// by adding a member rather than by routing around the check.
//
// It is a package-level var and not a function on purpose, for A.14's reason:
// internal/ingest/sanitize's writer guard walks FUNCTION bodies looking for
// the names of the cache's advisory write shapes, and a function that named
// them only to build this map would be flagged as an unsanitised writer. A var
// initialiser is not a function body, so the guard sees the real write site
// and not this one.
//
// The value is the reason the member is allowed. "It seemed necessary" is not
// one of them.
var allowedStatements = map[string]string{
	strings.TrimSpace(cache.UpsertAdvisorySQL): "the ONE shared advisory write shape, ON CONFLICT DO UPDATE, " +
		"RETURNING the rowid advisory_fts is addressed by. The tombstone is a read-modify-write through " +
		"this statement rather than an UPDATE of its own, so there is exactly one statement in this " +
		"system that writes an advisory row.",
	strings.TrimSpace(cache.DeleteAdvisoryFTSSQL): "one FTS row by rowid, for a tombstoned advisory. The " +
		"`advisory` row itself is never deleted (A.2 exit criterion 22); its TEXT stops matching, which " +
		"is the same requirement seen from the index side.",
	strings.TrimSpace(selectAdvisoryRowSQL):         "read-only: the row about to be re-bound, by primary key.",
	strings.TrimSpace(selectFindingsForAdvisorySQL): "read-only: findings referencing one advisory, with its state.",
	strings.TrimSpace(selectInvalidatedFindingsSQL): "read-only: every finding whose advisory is tombstoned.",
}

// checkStatement is the allowlist gate. Every database call in this package
// goes through it, and nothing else in this package may call the driver.
func checkStatement(q string) error {
	if _, ok := allowedStatements[strings.TrimSpace(q)]; ok {
		return nil
	}
	return refuse(ErrStatementNotAllowed,
		"this package may only execute statements on its allowlist and this one is not on it:\n\t%s\n"+
			"If it removes an `advisory` row, it is the thing A.16's packet forbids outright: a withdrawn "+
			"or REJECTED advisory is TOMBSTONED so a prior finding referencing it can be re-opened and "+
			"invalidated, and a removed row cannot be referenced at all.",
		condense(q))
}

// condense renders a statement on one line for an error message.
func condense(q string) string { return strings.Join(strings.Fields(q), " ") }

// clip bounds a value quoted back into an error message.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func execTx(ctx context.Context, tx *sql.Tx, q string, args ...any) error {
	if err := checkStatement(q); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

func queryRowTx(ctx context.Context, tx *sql.Tx, q string, args ...any) (*sql.Row, error) {
	if err := checkStatement(q); err != nil {
		return nil, err
	}
	return tx.QueryRowContext(ctx, q, args...), nil
}

func queryDB(ctx context.Context, db *sql.DB, q string, args ...any) (*sql.Rows, error) {
	if err := checkStatement(q); err != nil {
		return nil, err
	}
	return db.QueryContext(ctx, q, args...)
}

func queryTx(ctx context.Context, tx *sql.Tx, q string, args ...any) (*sql.Rows, error) {
	if err := checkStatement(q); err != nil {
		return nil, err
	}
	return tx.QueryContext(ctx, q, args...)
}

// ---------------------------------------------------------------------------
// Tombstoner
// ---------------------------------------------------------------------------

// Tombstoner applies retractions to the A.2 ingestion cache.
//
// A NOTE ON THE SHAPE, reported rather than silently applied. A.16's packet
// specifies `func Tombstone(source, sourceID string, reason string) error`.
// That signature has nowhere to put the database handle, the context or the
// clock, so implementing it literally would mean a package-level database
// global — an ambient, untestable, unclosable handle, and a worse outcome than
// the deviation. The METHOD's name and its (source, sourceID, reason)
// arguments are exactly the packet's; the receiver carries the handle and the
// clock, and the return adds a result value so a caller can see what actually
// changed instead of inferring it from a nil error.
type Tombstoner struct {
	db  *sql.DB
	now func() time.Time
}

// NewTombstoner binds a Tombstoner to the A.2 cache.
//
// now may be nil, in which case time.Now is used. A test supplies its own so
// that "the retraction timestamp did not move on the second call" is an
// assertion about the code rather than about how fast the machine ran.
func NewTombstoner(db *sql.DB, now func() time.Time) (*Tombstoner, error) {
	if db == nil {
		return nil, refuse(ErrNoCache, "a Tombstoner needs the A.2 ingestion cache")
	}
	if now == nil {
		now = time.Now
	}
	return &Tombstoner{db: db, now: now}, nil
}

// TombstoneResult is what one retraction did. Every field is an observation,
// so a caller never has to infer the outcome from a nil error.
type TombstoneResult struct {
	Source   string
	SourceID string

	// Reason is the reason as given, unmodified. It is carried because the
	// schema's three states cannot express all of them: ReasonPoisoned and
	// ReasonWithdrawn both write 'withdrawn'.
	Reason Reason

	// PreviousState is what `advisory.state` held before, and State is what it
	// holds now.
	PreviousState string
	State         string

	// TombstonedAt is the retraction timestamp now on the row. On a row that
	// was ALREADY tombstoned it is the ORIGINAL one: a retraction happened
	// when it happened, and a second call must not move the clock forward and
	// make the advisory look freshly withdrawn.
	TombstonedAt string

	// AlreadyTombstoned is true when the row was not published when it
	// arrived. The write still ran if the state changed (withdrawn -> rejected
	// is a real transition); it did not if nothing would have changed.
	AlreadyTombstoned bool

	// RowID is the `advisory` rowid, which is the only address advisory_fts
	// has for the row, and FTSDeleted records that its text was removed from
	// the index. The `advisory` row itself is never removed.
	RowID      int64
	FTSDeleted bool

	// InvalidatedFindings is how many `finding` rows now reference a
	// tombstoned advisory. They are NOT deleted and NOT hidden: they become
	// visible as invalidated, which is what lets a prior finding be re-opened.
	InvalidatedFindings int

	// Sanitized reports what A.3 removed from the values read back out of the
	// cache. It should be zero on every row this system wrote. A non-zero
	// value means something reached the cache unsanitized, which is worth
	// surfacing loudly — and worth surfacing WITHOUT blocking the retraction,
	// because refusing to record a withdrawal on account of a dirty prose
	// field would leave a retracted advisory live.
	Sanitized sanitize.SanitizeStats
}

// Tombstone marks one advisory as retracted WITHOUT deleting its row.
//
// What it does, in one transaction:
//
//  1. reads the row back by primary key, refusing if there is none;
//  2. replaces `state` and `tombstoned_at` and re-binds every other column as
//     it was, through cache.UpsertAdvisorySQL — the one shared write shape;
//  3. removes the advisory's TEXT from advisory_fts by rowid, so a retracted
//     advisory stops matching a search while its row stays addressable;
//  4. counts the findings that now reference a tombstoned advisory.
//
// It never issues a DELETE against `advisory`, `affected`, `cve_alias` or
// `finding`, and allowedStatements is what makes that a property rather than a
// promise.
func (t *Tombstoner) Tombstone(ctx context.Context, source, sourceID, reason string) (TombstoneResult, error) {
	res := TombstoneResult{Source: source, SourceID: sourceID, Reason: Reason(reason)}

	if strings.TrimSpace(source) == "" || strings.TrimSpace(sourceID) == "" {
		return res, refuse(ErrBadKey,
			"a tombstone needs both halves of the primary key; got source %q and source_id %q",
			clip(source, 64), clip(sourceID, 64))
	}
	state, err := StateForReason(reason)
	if err != nil {
		return res, err
	}
	res.State = state

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("drift: opening transaction to tombstone %s/%s: %w", source, sourceID, err)
	}
	defer func() { _ = tx.Rollback() }()

	row, err := t.readRow(ctx, tx, source, sourceID)
	if err != nil {
		return res, err
	}
	res.PreviousState = row.state
	res.RowID = row.rowid
	res.AlreadyTombstoned = row.state != cache.AdvisoryPublished

	// A retraction happened when it happened. Re-running the pass must not
	// move the timestamp forward, or a nightly reconcile would keep making a
	// year-old withdrawal look like today's news.
	stamp := strings.TrimSpace(row.tombstonedAt)
	if stamp == "" {
		stamp = t.now().UTC().Format(time.RFC3339)
	}
	res.TombstonedAt = stamp

	if res.AlreadyTombstoned && row.state == state {
		// Nothing would change. Commit nothing and say so; the finding count
		// is still reported, because that is what the caller asked about.
		n, err := countFindings(ctx, tx, source, sourceID)
		if err != nil {
			return res, err
		}
		res.InvalidatedFindings = n
		return res, nil
	}

	rowid, stats, err := t.writeTombstonedRow(ctx, tx, source, sourceID, state, stamp, row)
	res.Sanitized = stats
	if err != nil {
		return res, err
	}
	res.RowID = rowid

	if err := execTx(ctx, tx, cache.DeleteAdvisoryFTSSQL, rowid); err != nil {
		return res, fmt.Errorf("drift: unindexing tombstoned %s/%s: %w", source, sourceID, err)
	}
	res.FTSDeleted = true

	n, err := countFindings(ctx, tx, source, sourceID)
	if err != nil {
		return res, err
	}
	res.InvalidatedFindings = n

	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("drift: committing the tombstone for %s/%s: %w", source, sourceID, err)
	}
	return res, nil
}

// advisoryRow is one row read back, ready to be re-bound.
type advisoryRow struct {
	rowid            int64
	cveID            sql.NullString
	published        sql.NullString
	modified         sql.NullString
	state            string
	tombstonedAt     string
	severity         sql.NullString
	cvssVector       sql.NullString
	cvssScore        sql.NullFloat64
	epssScore        sql.NullFloat64
	epssAsOf         sql.NullString
	kev              int
	licenseSPDX      sql.NullString
	licenseNote      sql.NullString
	licenseTier      int
	anvilTrust       string
	asOf             string
	stalenessSeconds int
	parseDegraded    int
	dataVersion      sql.NullString
	rawJSON          []byte
}

// readRow reads one advisory back by primary key. It does not clean and does
// not write; see writeTombstonedRow for where A.3 runs and why it runs there.
func (t *Tombstoner) readRow(ctx context.Context, tx *sql.Tx, source, sourceID string) (advisoryRow, error) {
	var r advisoryRow
	var tombstonedAt sql.NullString

	q, err := queryRowTx(ctx, tx, selectAdvisoryRowSQL, source, sourceID)
	if err != nil {
		return r, err
	}
	err = q.Scan(&r.rowid, &r.cveID, &r.published, &r.modified, &r.state, &tombstonedAt,
		&r.severity, &r.cvssVector, &r.cvssScore, &r.epssScore, &r.epssAsOf, &r.kev,
		&r.licenseSPDX, &r.licenseNote, &r.licenseTier, &r.anvilTrust,
		&r.asOf, &r.stalenessSeconds, &r.parseDegraded, &r.dataVersion, &r.rawJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return r, refuse(ErrNoSuchAdvisory,
			"the cache holds no advisory %s/%s, so there is nothing to tombstone. This is reported "+
				"rather than treated as a no-op: a retraction applied to nothing and a retraction "+
				"applied successfully are different facts.", source, sourceID)
	case err != nil:
		return r, fmt.Errorf("drift: reading advisory %s/%s: %w", source, sourceID, err)
	}
	r.tombstonedAt = tombstonedAt.String
	return r, nil
}

// writeTombstonedRow re-binds the row with its state and tombstone replaced.
//
// A.3 RUNS IN THIS FUNCTION, in the same body as the bind, and not one call
// further up. That is deliberate and it is the shape A.14 chose for the same
// reason: internal/ingest/sanitize's writer guard resolves the package-local
// call graph by NAME and can therefore check "the function that binds is the
// function that cleans". A sanitiser two frames away is a claim the guard
// cannot verify, and a claim nothing verifies is the state this project has
// already paid to leave.
//
// SANITIZE RATHER THAN ASSERT, and the direction matters. AssertAllSanitized
// would REFUSE the tombstone on a row that reached the cache dirty, leaving a
// retracted advisory live because some prose field carried a zero-width
// character. Sanitize cleans the value, lets the retraction land, and reports
// what it removed on TombstoneResult.Sanitized — loud, without being able to
// block a withdrawal.
//
// `raw_json` is bound BYTE-FOR-BYTE as it was read and is NOT sanitized. It is
// the publisher's own document, CVE-TOU requires records be stored verbatim
// (research/06 "License"), and a retraction is a fact about the row rather
// than an edit to the publisher's bytes.
func (t *Tombstoner) writeTombstonedRow(
	ctx context.Context,
	tx *sql.Tx,
	source, sourceID, state, stamp string,
	r advisoryRow,
) (int64, sanitize.SanitizeStats, error) {
	var stats sanitize.SanitizeStats
	clean := func(v string) string {
		out, st := sanitize.Sanitize(v)
		stats.Merge(st)
		return out
	}
	cleanNull := func(v sql.NullString) any {
		if !v.Valid {
			return nil
		}
		return clean(v.String)
	}

	row, err := queryRowTx(ctx, tx, cache.UpsertAdvisorySQL,
		source, sourceID, cleanNull(r.cveID), cleanNull(r.published), cleanNull(r.modified),
		state, clean(stamp),
		cleanNull(r.severity), cleanNull(r.cvssVector), nullFloat(r.cvssScore), nullFloat(r.epssScore),
		cleanNull(r.epssAsOf), r.kev,
		cleanNull(r.licenseSPDX), cleanNull(r.licenseNote), r.licenseTier, clean(r.anvilTrust),
		clean(r.asOf), r.stalenessSeconds, r.parseDegraded, cleanNull(r.dataVersion), r.rawJSON)
	if err != nil {
		return 0, stats, err
	}
	var rowid int64
	if err := row.Scan(&rowid); err != nil {
		return 0, stats, fmt.Errorf("drift: writing the tombstone for %s/%s: %w", source, sourceID, err)
	}
	if rowid != r.rowid {
		// ON CONFLICT DO UPDATE updates in place, so this cannot happen. It is
		// checked because the version that CAN happen — INSERT OR REPLACE —
		// fails exactly this way and fails silently, orphaning the FTS entry
		// under the old rowid.
		return 0, stats, fmt.Errorf("drift: %s/%s moved from rowid %d to %d during a tombstone; "+
			"the FTS entry under the old rowid would be orphaned", source, sourceID, r.rowid, rowid)
	}
	return rowid, stats, nil
}

// nullFloat renders a nullable score as the `any` the shared upsert binds. A
// zero CVSS base score is a real value and must not become NULL, and "absent"
// must not become 0.0 — a comparator that cannot tell them apart ranks an
// unscored advisory as harmless.
func nullFloat(v sql.NullFloat64) any {
	if !v.Valid {
		return nil
	}
	return v.Float64
}

// ---------------------------------------------------------------------------
// The read path: findings that referenced a retracted advisory
// ---------------------------------------------------------------------------

// FindingStatus is one Lane A finding together with the current state of the
// advisory it rests on.
//
// FindingID IS NOT A FINGERPRINT. `finding.id` is a Lane-A-local identifier;
// internal/ingest/cache/schema.go says so at the table, and plan/00-SPINE.md
// S6 allows exactly one fingerprint algorithm, anvil-fp/v1, owned by
// internal/record. This field must never be presented as, derived into, or
// compared against one.
type FindingStatus struct {
	FindingID         string
	Collector         string
	Source            string
	SourceID          string
	Package           string
	InstalledVersion  string
	Ecosystem         string
	RemediableByAgent bool
	DetectedAt        string

	// AdvisoryState is `advisory.state`, or "" when no advisory row exists.
	AdvisoryState string

	// TombstonedAt is when the advisory was retracted, empty when it was not.
	TombstonedAt string

	// Invalidated is true when the finding's advisory is no longer published —
	// including the case where the advisory row is missing entirely. It is a
	// FLAG AND NOT A FILTER: the row is returned either way, because a prior
	// finding must be re-openable and invalidated rather than silently gone.
	Invalidated bool
}

// FindingsReferencing returns every finding that rests on one advisory,
// invalidated or not.
//
// This is the query A.16's validation names: after a tombstone, a finding that
// referenced the advisory comes back marked invalidated instead of
// disappearing from the result set.
func FindingsReferencing(ctx context.Context, db *sql.DB, source, sourceID string) ([]FindingStatus, error) {
	if db == nil {
		return nil, refuse(ErrNoCache, "FindingsReferencing needs the A.2 ingestion cache")
	}
	rows, err := queryDB(ctx, db, selectFindingsForAdvisorySQL, source, sourceID)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

// InvalidatedFindings returns every finding in the cache whose advisory is no
// longer published: the work list for the re-open pass the spine's regression
// checking requires.
func InvalidatedFindings(ctx context.Context, db *sql.DB) ([]FindingStatus, error) {
	if db == nil {
		return nil, refuse(ErrNoCache, "InvalidatedFindings needs the A.2 ingestion cache")
	}
	rows, err := queryDB(ctx, db, selectInvalidatedFindingsSQL)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

func scanFindings(rows *sql.Rows) ([]FindingStatus, error) {
	defer func() { _ = rows.Close() }()
	var out []FindingStatus
	for rows.Next() {
		var f FindingStatus
		var remediable int
		var state, tombstoned sql.NullString
		if err := rows.Scan(&f.FindingID, &f.Collector, &f.Source, &f.SourceID, &f.Package,
			&f.InstalledVersion, &f.Ecosystem, &remediable, &f.DetectedAt, &state, &tombstoned); err != nil {
			return nil, fmt.Errorf("drift: reading findings: %w", err)
		}
		f.RemediableByAgent = remediable != 0
		f.AdvisoryState = state.String
		f.TombstonedAt = tombstoned.String
		// A missing advisory row counts as invalidated. It should be
		// unreachable under the schema's foreign key, and if it ever happens
		// the finding must surface as unsupported rather than as healthy.
		f.Invalidated = !state.Valid || state.String != cache.AdvisoryPublished
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("drift: reading findings: %w", err)
	}
	return out, nil
}

// countFindings counts the findings resting on one advisory, inside the
// transaction that is retracting it.
func countFindings(ctx context.Context, tx *sql.Tx, source, sourceID string) (int, error) {
	rows, err := queryTx(ctx, tx, selectFindingsForAdvisorySQL, source, sourceID)
	if err != nil {
		return 0, fmt.Errorf("drift: counting findings for %s/%s: %w", source, sourceID, err)
	}
	found, err := scanFindings(rows)
	if err != nil {
		return 0, err
	}
	return len(found), nil
}
