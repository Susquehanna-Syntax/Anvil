// Tests for A.15, the weekly full-baseline self-heal.
//
// ===========================================================================
// WHAT THESE TESTS ARE FOR, AND WHAT A GREEN RUN DOES NOT PROVE
// ===========================================================================
//
// Four claims carry this package. Each has a test whose failure would be a
// real defect rather than a cosmetic one:
//
//  1. THE SELF-HEAL ACTUALLY HEALS, AND SAYS SO.
//     TestSelfHealRestoresTheRecordsTheDeltaPathDropped is A.15's named
//     validation: a live cache deliberately missing three records the fresh
//     baseline has. It drives the REAL A.8 bootstrapper over an httptest-
//     served zip, restores through A.14's real write path, and then asserts
//     both halves — the three rows are back, AND every unrelated row is
//     byte-identical including its as_of, which is what proves the repair was
//     row-scoped rather than a re-import wearing a diff's clothes.
//
//  2. IT NEVER MAKES THE CACHE WORSE. A bulk artifact is cut at an instant and
//     the delta stream is legitimately past it.
//     TestANewerLiveRowIsNeverOverwrittenByAnOlderBaseline and
//     TestARowGroundTruthLacksIsReportedAndNeverDeleted are the two directions
//     of that, and both assert on the stored bytes rather than on a counter.
//
//  3. A FAILURE IS LOUD. TestABootstrapFailureIncrementsConsecutiveFailures,
//     TestAnIncompleteBaselineIsRefusedAndCounted and
//     TestAnEmptyBaselineIsRefusedAndCounted assert the packet's forbidden
//     action directly: the counter A.16's staleness mechanism reads moves, and
//     the live cache is not touched.
//
//  4. NOTHING FULL-TABLE REACHES THE CACHE.
//     TestNoFullTableStatementReachesTheLiveCache opens the live cache through
//     a tracing driver and inspects EVERY statement that reached the driver
//     layer during a real repair. It is an observation, not an assertion about
//     code someone read.
//
// THE GUARDS ARE VERIFIED RED. TestTheStatementAllowlistIsOnTheLivePath
// removes an entry from the allowlist and proves the production path then
// fails, so the allowlist is load-bearing rather than decorative;
// TestTheMergeJoinRefusesAnUnorderedScan feeds the cursor a deliberately
// descending scan and proves it refuses instead of silently producing a
// nonsense diff.
//
// THE CORPUS IS AUTHORED HERE, NOT DERIVED FROM THE IMPLEMENTATION. The CVE
// 5.1 documents below are written in this file. The live cache is then built
// by running the REAL delta writer over a subset of them, which is how the
// production system builds it — so a divergence between A.8's decoder and
// A.14's decoder would surface here as a wall of "divergent" rows rather than
// hiding until a real self-heal ran.
//
// NO TEST HERE REACHES THE NETWORK: the one bulk archive is served by
// httptest. NO TEST USES A REAL CREDENTIAL.
//
// A green run does NOT prove the self-heal is affordable against a 300,000
// record cvelistV5 baseline; the fixtures here are tens of records. Nor does
// it prove anything about `go test -race`, which cannot run on the Windows dev
// host this was written on.
package reconcile

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/bootstrap"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"

	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// Clocks
// ---------------------------------------------------------------------------

// seedAt is when the delta pipeline is pretended to have written the live
// cache, and healAt is when the self-heal runs. They differ so that `as_of`
// alone distinguishes a row this pass rewrote from one it left alone — which
// is the assertion that makes "without disturbing unrelated rows" checkable.
var (
	seedAt = time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC)
	healAt = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// ---------------------------------------------------------------------------
// The corpus. Authored here.
// ---------------------------------------------------------------------------

// cveDoc renders one CVE 5.1 record. Everything a test needs to vary is a
// parameter, and nothing about it is read back out of the implementation.
func cveDoc(id, updated, description string) string {
	doc := map[string]any{
		"dataType":    "CVE_RECORD",
		"dataVersion": "5.1",
		"cveMetadata": map[string]any{
			"cveId":             id,
			"state":             "PUBLISHED",
			"datePublished":     "2026-01-02T00:00:00.000Z",
			"dateUpdated":       updated,
			"assignerShortName": "example",
		},
		"containers": map[string]any{
			"cna": map[string]any{
				"descriptions": []any{
					map[string]any{"lang": "en", "value": description},
				},
				"references": []any{
					map[string]any{"url": "https://example.invalid/advisory/" + id},
				},
				"affected": []any{map[string]any{
					"vendor":   "example",
					"product":  "widget",
					"versions": []any{map[string]any{"version": "1.0.0", "status": "affected"}},
				}},
			},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic("cveDoc: " + err.Error())
	}
	return string(b)
}

// corpus is n advisories with stable ids and a distinctive term per record, so
// an FTS round-trip can name exactly one of them.
func corpus(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("CVE-2026-%05d", 10000+i)
		out = append(out, cveDoc(id, "2026-03-01T00:00:00.000Z",
			fmt.Sprintf("Synthetic advisory for %s concerning marker%04d in the widget parser.", id, i)))
	}
	return out
}

func docID(t *testing.T, doc string) string {
	t.Helper()
	var d struct {
		CVEMetadata struct {
			CVEID string `json:"cveId"`
		} `json:"cveMetadata"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("reading the id back out of a fixture document: %v", err)
	}
	if d.CVEMetadata.CVEID == "" {
		t.Fatal("a fixture document carries no cveId")
	}
	return d.CVEMetadata.CVEID
}

// ---------------------------------------------------------------------------
// The licence mirror
// ---------------------------------------------------------------------------

// cc0Verbatim is the publisher licence text the synthetic mirror pins. A.4
// classifies BODIES, so a fixture that wants an admission has to supply a real
// permissive one.
const cc0Verbatim = `Creative Commons Legal Code

CC0 1.0 Universal

The person who associated a work with this deed has dedicated the work to the
public domain by waiving all rights to the work worldwide under copyright law.`

const cc0Notes = `SPDX-License-Identifier: CC0-1.0

Anvil's record: this source is public domain and carries no obligation.`

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func testFeed(id string) config.FeedConfig {
	return config.FeedConfig{
		ID:                       id,
		URL:                      "https://example.invalid/" + id,
		Enabled:                  true,
		AuthMode:                 config.AuthNone,
		SyncMechanism:            config.SyncConditionalGetETag,
		IntervalSeconds:          900,
		ReconcileIntervalSeconds: 86400,
		BaselineIntervalSeconds:  604800,
		FreshnessSLOSeconds:      86400,
		OnFailure:                config.OnFailureServeStale,
		LicenseTier:              config.LicenseTier0,
		LicenseSPDX:              "CC0-1.0",
		MirrorDir:                id,
		BootstrapMechanism:       config.BootstrapBulkArchive,
	}
}

// admittingMirror renders the mirror tree A.4 reads: a pinned manifest, the
// publisher's acquired text at the digest the pin names, and Anvil's own
// record. The gate's admission path is exacting and a mirror assembled by
// guesswork simply refuses, so this mirrors the shape A.4's own fixtures use.
func admittingMirror(t *testing.T, feeds ...config.FeedConfig) fs.FS {
	t.Helper()
	fsys := fstest.MapFS{}
	var man strings.Builder
	man.WriteString("# synthetic manifest, reconcile_test\n")
	man.WriteString("schema_version = 1\n")
	man.WriteString("generated_utc = \"2026-08-09\"\n")
	man.WriteString("generated_by = \"reconcile_test\"\n")

	notes := map[config.LicenseTier]*strings.Builder{}
	for _, f := range feeds {
		dir := f.MirrorDir
		if dir == "" {
			dir = f.ID
		}
		fmt.Fprintf(&man, "\n[[body]]\nfeed_id = %q\ntier = %d\ndir = %q\n"+
			"spdx_id = %q\ntext_url = \"https://example.invalid/LICENSE\"\n"+
			"sha256 = %q\nclaim_source = \"reconcile_test fixture\"\n",
			f.ID, f.LicenseTier.Int(), dir, f.LicenseSPDX, digestOf(cc0Verbatim))
		fsys[path.Join(license.TierDir(f.LicenseTier), dir, license.VerbatimFileName)] =
			&fstest.MapFile{Data: []byte(cc0Verbatim)}

		b, ok := notes[f.LicenseTier]
		if !ok {
			b = &strings.Builder{}
			b.WriteString("# fixture notes\n")
			notes[f.LicenseTier] = b
		}
		fmt.Fprintf(b, "\n%s\n%s\n%s\n",
			license.BodyBeginMarker(f.ID), cc0Notes, license.BodyEndMarker(f.ID))
	}
	for tier, b := range notes {
		fsys[path.Join(license.TierDir(tier), license.NotesFileName)] = &fstest.MapFile{Data: []byte(b.String())}
	}
	fsys[license.ManifestFileName] = &fstest.MapFile{Data: []byte(man.String())}
	return fsys
}

// emptyMirror pins nothing, so A.4 refuses every feed against it. It is what a
// fresh clone looks like.
func emptyMirror() fs.FS { return fstest.MapFS{} }

func admittedDecision(t *testing.T, feed config.FeedConfig, mirror fs.FS) license.Decision {
	t.Helper()
	d, err := license.Resolve(license.FromFeed(feed, "", mirror))
	if err != nil {
		t.Fatalf("the fixture mirror does not admit feed %q: %v", feed.ID, err)
	}
	if d.Refused() {
		t.Fatalf("the fixture mirror returned a refusal for feed %q with no error", feed.ID)
	}
	return d
}

// ---------------------------------------------------------------------------
// Caches
// ---------------------------------------------------------------------------

func newCacheAt(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := cache.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("opening cache %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := cache.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrating cache %s: %v", path, err)
	}
	return db
}

func newCache(t *testing.T) *sql.DB {
	t.Helper()
	return newCacheAt(t, filepath.Join(t.TempDir(), "anvil-cache.sqlite"))
}

// seedLive writes documents into a cache THROUGH THE PRODUCTION DELTA PATH.
//
// That is the point: the "delta-built cache" a self-heal diffs against has to
// be built the way the delta pipeline builds it, or the test is comparing the
// baseline against a fixture nobody's code would ever produce.
func seedLive(t *testing.T, db *sql.DB, feed config.FeedConfig, d license.Decision, docs []string, at time.Time) {
	t.Helper()
	var batch []delta.Record
	for _, doc := range docs {
		recs, _, err := delta.Decode(feed.ID, []byte(doc))
		if err != nil {
			t.Fatalf("decoding a fixture document: %v", err)
		}
		batch = append(batch, recs...)
	}
	if _, err := delta.Apply(context.Background(), db, feed, d, batch, at, 0); err != nil {
		t.Fatalf("seeding the live cache: %v", err)
	}
}

type storedRow struct {
	sourceID  string
	modified  string
	state     string
	asOf      string
	staleness int
	raw       string
}

// snapshot reads back every row of one feed. It is used to assert that
// unrelated rows were not disturbed, which a repair count cannot show.
func snapshot(t *testing.T, db *sql.DB, feedID string) map[string]storedRow {
	t.Helper()
	rows, err := db.Query(
		`SELECT source_id, modified, state, as_of, staleness_seconds, raw_json
		 FROM advisory WHERE source = ? ORDER BY source_id`, feedID)
	if err != nil {
		t.Fatalf("snapshotting %q: %v", feedID, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]storedRow{}
	for rows.Next() {
		var (
			r        storedRow
			modified sql.NullString
			raw      []byte
		)
		if err := rows.Scan(&r.sourceID, &modified, &r.state, &r.asOf, &r.staleness, &raw); err != nil {
			t.Fatalf("scanning a snapshot row: %v", err)
		}
		r.modified, r.raw = modified.String, string(raw)
		out[r.sourceID] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the snapshot: %v", err)
	}
	return out
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("counting (%s): %v", query, err)
	}
	return n
}

func failuresFor(t *testing.T, db *sql.DB, feedID string) (int, bool) {
	t.Helper()
	var n int
	err := db.QueryRow(`SELECT consecutive_failures FROM feed_state WHERE feed_id = ?`, feedID).Scan(&n)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false
	case err != nil:
		t.Fatalf("reading consecutive_failures for %q: %v", feedID, err)
	}
	return n, true
}

// ---------------------------------------------------------------------------
// A fake baseliner, for the cases a real bulk archive cannot express
// ---------------------------------------------------------------------------

// fakeBaseliner writes a chosen corpus into whatever scratch cache it is
// handed, and returns whatever BootstrapResult a test needs.
//
// It writes through delta.Apply for the same reason seedLive does: a scratch
// cache assembled by hand would not necessarily be a cache the real importer
// could produce.
type fakeBaseliner struct {
	t        *testing.T
	db       *sql.DB
	feed     config.FeedConfig
	decision license.Decision
	docs     []string
	at       time.Time

	// err, incomplete and emptyResult drive the failure paths.
	err         error
	incomplete  bool
	emptyResult bool

	// tierOverride and dirOverride drive the decision-mismatch path. A nil
	// override means "echo the decision".
	tierOverride *int
	dirOverride  *string

	calls *int
	// afterWrite runs with the scratch handle once the corpus is in, so a test
	// can plant a row the real importer would never write.
	afterWrite func(scratch *sql.DB)
}

func (f *fakeBaseliner) Bootstrap(ctx context.Context, feed config.FeedConfig) (bootstrap.BootstrapResult, error) {
	if f.calls != nil {
		*f.calls++
	}
	res := bootstrap.BootstrapResult{
		FeedID:    feed.ID,
		Mechanism: feed.BootstrapMechanism,
		Tier:      f.decision.Tier.Int(),
		Dir:       f.decision.Dir,
		Complete:  !f.incomplete,
	}
	if f.tierOverride != nil {
		res.Tier = *f.tierOverride
	}
	if f.dirOverride != nil {
		res.Dir = *f.dirOverride
	}
	if f.err != nil {
		return res, f.err
	}
	if !f.emptyResult {
		var batch []delta.Record
		for _, doc := range f.docs {
			recs, _, err := delta.Decode(feed.ID, []byte(doc))
			if err != nil {
				return res, err
			}
			batch = append(batch, recs...)
		}
		at := f.at
		if at.IsZero() {
			at = healAt
		}
		stats, err := delta.Apply(ctx, f.db, feed, f.decision, batch, at, 0)
		if err != nil {
			return res, err
		}
		res.RecordsUpserted = stats.Upserts
		res.EntriesRead = len(f.docs)
	}
	if f.afterWrite != nil {
		f.afterWrite(f.db)
		var n int
		if err := f.db.QueryRow(`SELECT count(*) FROM advisory WHERE source = ?`, feed.ID).Scan(&n); err == nil {
			res.RecordsUpserted = n
		}
	}
	return res, nil
}

// fakeFactory binds a fakeBaseliner to whatever scratch handle the healer
// opens. The prototype's db field is ignored; the scratch handle wins, which
// is the property that keeps the baseline out of the live cache.
func fakeFactory(proto fakeBaseliner) BaselineFactory {
	return func(scratch *sql.DB) (Baseliner, error) {
		f := proto
		f.db = scratch
		return &f, nil
	}
}

func newHealer(t *testing.T, opts Options) *Healer {
	t.Helper()
	if opts.WorkDir == "" {
		opts.WorkDir = t.TempDir()
	}
	if opts.Now == nil {
		opts.Now = fixedClock(healAt)
	}
	h, err := New(opts)
	if err != nil {
		t.Fatalf("building the healer: %v", err)
	}
	return h
}

// ---------------------------------------------------------------------------
// 1. The self-heal actually heals, and says so
// ---------------------------------------------------------------------------

// TestSelfHealRestoresTheRecordsTheDeltaPathDropped is A.15's named
// validation: "a synthetic 'live cache is missing 3 records the fresh baseline
// has' fixture, asserting the reconcile pass restores all 3 without disturbing
// unrelated rows."
//
// It drives the REAL A.8 bootstrapper over an httptest-served zip, so the path
// under test is the production one end to end: bulk archive -> scratch cache
// -> merge-join diff -> A.14's row-scoped upsert.
func TestSelfHealRestoresTheRecordsTheDeltaPathDropped(t *testing.T) {
	const total = 20
	const dropped = 3

	docs := corpus(total)
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	// The archive the publisher serves: ground truth, all 20 records.
	archive := buildZip(t, docs)
	srv := serveArchive(t, archive)
	feed.URL, feed.BootstrapURL = srv.URL+"/all.zip", srv.URL+"/all.zip"

	// The cache the delta pipeline built: the first three records never
	// arrived.
	live := newCache(t)
	seedLive(t, live, feed, decision, docs[dropped:], seedAt)

	missing := make([]string, 0, dropped)
	for _, d := range docs[:dropped] {
		missing = append(missing, docID(t, d))
	}
	before := snapshot(t, live, feed.ID)
	if len(before) != total-dropped {
		t.Fatalf("the fixture live cache holds %d rows, want %d", len(before), total-dropped)
	}

	h := newHealer(t, Options{
		Live:   live,
		Feed:   feed,
		Mirror: mirror,
		Baseline: FromBootstrapper(bootstrap.Bootstrapper{
			Mirror:  mirror,
			WorkDir: t.TempDir(),
			Clock:   fixedClock(healAt),
		}),
	})

	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v\nreport: %s", err, rep.Summary())
	}

	// --- The counts the packet asks for. ---
	if rep.BaselineRows != total {
		t.Errorf("the fresh baseline held %d rows, want %d", rep.BaselineRows, total)
	}
	if rep.LiveRows != total-dropped {
		t.Errorf("the live cache held %d rows, want %d", rep.LiveRows, total-dropped)
	}
	if rep.MissingInLive != dropped {
		t.Errorf("missing-in-live is %d, want %d; the diff did not see the dropped records",
			rep.MissingInLive, dropped)
	}
	if rep.Matched != total-dropped {
		t.Errorf("matched is %d, want %d", rep.Matched, total-dropped)
	}
	if rep.Updated() != 0 || rep.AheadInLive != 0 || rep.OnlyInLive != 0 {
		t.Errorf("nothing but the three drops should disagree, got updated=%d ahead=%d only-in-live=%d",
			rep.Updated(), rep.AheadInLive, rep.OnlyInLive)
	}
	if rep.Restored != dropped {
		t.Fatalf("restored %d rows, want %d. A.15's stop condition is a NON-ZERO restored count when "+
			"records were deliberately dropped beforehand", rep.Restored, dropped)
	}
	if err := rep.CheckTotals(); err != nil {
		t.Errorf("the diff does not partition the two row sets: %v", err)
	}
	if !rep.Drifted() {
		t.Error("Drifted() is false after three records were restored; the one boolean a daemon " +
			"alerts on did not fire")
	}

	// --- The three rows are actually back, and decode to the right content.
	after := snapshot(t, live, feed.ID)
	if len(after) != total {
		t.Fatalf("the live cache holds %d rows after the self-heal, want %d", len(after), total)
	}
	for i, id := range missing {
		row, ok := after[id]
		if !ok {
			t.Fatalf("%s is still missing after the self-heal", id)
		}
		if row.raw != docs[i] {
			t.Errorf("%s was restored with bytes that are not the publisher's", id)
		}
		if row.asOf != healAt.Format(time.RFC3339) {
			t.Errorf("%s carries as_of %q, want the self-heal's clock %q",
				id, row.asOf, healAt.Format(time.RFC3339))
		}
	}

	// --- NOTHING ELSE MOVED. This is the half a repair count cannot show. ---
	for id, was := range before {
		now, ok := after[id]
		if !ok {
			t.Fatalf("%s was in the live cache before the self-heal and is gone after it", id)
		}
		if now != was {
			t.Errorf("%s was rewritten by the self-heal and should not have been:\n  before %+v\n  after  %+v",
				id, was, now)
		}
	}

	// --- The write path's own accounting agrees with the report. ---
	if rep.Batch.Upserts != dropped || rep.Batch.FTSUpserts != dropped {
		t.Errorf("delta.Apply reports %d upserts and %d FTS writes, want %d of each",
			rep.Batch.Upserts, rep.Batch.FTSUpserts, dropped)
	}
	if rep.Batch.FTSDeletes != 0 {
		t.Errorf("the repair deleted %d FTS rows; nothing here is tombstoned", rep.Batch.FTSDeletes)
	}
}

// TestFTSStaysQueryConsistentAfterARepair is the round-trip half of A.14's
// exit criterion, re-asserted for this pass: a restored row is findable by
// text immediately, and a row restored OVER a stale one stops matching the
// stale text.
func TestFTSStaysQueryConsistentAfterARepair(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	// Ground truth: two records. One the live cache never got, one the live
	// cache got at an older version whose text says something different.
	fresh := cveDoc("CVE-2026-30001", "2026-04-01T00:00:00.000Z",
		"An advisory mentioning zebracrossing in the parser.")
	updated := cveDoc("CVE-2026-30002", "2026-04-01T00:00:00.000Z",
		"The corrected text mentioning pelicancrossing only.")
	stale := cveDoc("CVE-2026-30002", "2026-01-01T00:00:00.000Z",
		"The superseded text mentioning toucancrossing only.")

	live := newCache(t)
	seedLive(t, live, feed, decision, []string{stale}, seedAt)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{
			t: t, feed: feed, decision: decision, docs: []string{fresh, updated},
		}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if rep.MissingInLive != 1 || rep.StaleInLive != 1 || rep.Restored != 2 {
		t.Fatalf("want one missing, one stale, two restored; got %+v / restored %d",
			[]int{rep.MissingInLive, rep.StaleInLive}, rep.Restored)
	}

	matches := func(term string) []string {
		t.Helper()
		rows, err := live.Query(
			`SELECT a.source_id FROM advisory_fts f JOIN advisory a ON a.rowid = f.rowid
			 WHERE advisory_fts MATCH ? ORDER BY a.source_id`, term)
		if err != nil {
			t.Fatalf("MATCH %q: %v", term, err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scanning a MATCH row: %v", err)
			}
			out = append(out, id)
		}
		return out
	}

	if got := matches("zebracrossing"); len(got) != 1 || got[0] != "CVE-2026-30001" {
		t.Errorf("the restored record is not findable by text: MATCH zebracrossing gave %v", got)
	}
	if got := matches("pelicancrossing"); len(got) != 1 || got[0] != "CVE-2026-30002" {
		t.Errorf("the updated record's new text is not indexed: MATCH pelicancrossing gave %v", got)
	}
	if got := matches("toucancrossing"); len(got) != 0 {
		t.Errorf("the SUPERSEDED text still matches after the repair: MATCH toucancrossing gave %v. "+
			"That is the contentless-FTS phantom-hit failure A.2 carries contentless_delete=1 for", got)
	}
}

// ---------------------------------------------------------------------------
// 2. It never makes the cache worse
// ---------------------------------------------------------------------------

// TestANewerLiveRowIsNeverOverwrittenByAnOlderBaseline is the data-loss guard.
//
// A bulk artifact is cut at an instant. The delta stream is legitimately past
// it, and a self-heal that restored "ground truth" over a newer row would
// throw away the very update the delta path exists to deliver.
func TestANewerLiveRowIsNeverOverwrittenByAnOlderBaseline(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	old := cveDoc("CVE-2026-40001", "2026-01-01T00:00:00.000Z", "The version the weekly archive was cut with.")
	newer := cveDoc("CVE-2026-40001", "2026-06-01T00:00:00.000Z", "The version the delta stream already delivered.")

	live := newCache(t)
	seedLive(t, live, feed, decision, []string{newer}, seedAt)
	before := snapshot(t, live, feed.ID)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: []string{old}}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}

	if rep.AheadInLive != 1 {
		t.Fatalf("ahead-in-live is %d, want 1; the pass did not notice the live cache was newer", rep.AheadInLive)
	}
	if rep.Restored != 0 || rep.StaleInLive != 0 || rep.Divergent != 0 {
		t.Fatalf("the pass wrote something: restored=%d stale=%d divergent=%d", rep.Restored, rep.StaleInLive, rep.Divergent)
	}
	if got := snapshot(t, live, feed.ID); !sameSnapshot(got, before) {
		t.Errorf("the newer live row was overwritten with the archive's older bytes:\n  before %+v\n  after  %+v",
			before, got)
	}
	if !rep.Drifted() {
		t.Error("a row the archive and the cache disagree about did not register as drift")
	}
	// The disagreement is REPORTED even though nothing was done about it.
	if len(rep.Samples) != 1 || rep.Samples[0].Kind != KindAheadInLive || rep.Samples[0].Repaired {
		t.Errorf("the ahead-in-live key was not reported as an untouched disagreement: %+v", rep.Samples)
	}
}

// TestARowGroundTruthLacksIsReportedAndNeverDeleted is the other direction.
//
// A.2 exit criterion 22 tombstones withdrawn and REJECTED advisories rather
// than deleting them, and that is A.16's pass. A self-heal that deleted a row
// because this week's archive did not carry it would destroy the row a prior
// finding references.
func TestARowGroundTruthLacksIsReportedAndNeverDeleted(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	shared := cveDoc("CVE-2026-50001", "2026-03-01T00:00:00.000Z", "Carried by both sides.")
	orphan := cveDoc("CVE-2026-50002", "2026-03-01T00:00:00.000Z", "The live cache has it and the archive does not.")

	live := newCache(t)
	seedLive(t, live, feed, decision, []string{shared, orphan}, seedAt)
	before := snapshot(t, live, feed.ID)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: []string{shared}}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if rep.OnlyInLive != 1 || rep.Matched != 1 {
		t.Fatalf("want one only-in-live and one matched, got only-in-live=%d matched=%d", rep.OnlyInLive, rep.Matched)
	}
	if got := snapshot(t, live, feed.ID); !sameSnapshot(got, before) {
		t.Errorf("the self-heal changed the live cache; it should have reported and done nothing")
	}
	if got := countRows(t, live, `SELECT count(*) FROM advisory WHERE source = ?`, feed.ID); got != 2 {
		t.Errorf("the live cache holds %d rows, want 2: a row ground truth lacks was deleted", got)
	}
	if len(rep.Samples) != 1 || rep.Samples[0].Kind != KindOnlyInLive {
		t.Errorf("the only-in-live key was not sampled: %+v", rep.Samples)
	}
}

// TestDivergentBytesAtTheSameVersionAreRestoredFromGroundTruth covers the row
// that is corrupt rather than stale: the two sides claim the same version and
// carry different bytes.
func TestDivergentBytesAtTheSameVersionAreRestoredFromGroundTruth(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	truth := cveDoc("CVE-2026-60001", "2026-03-01T00:00:00.000Z", "The publisher's own description.")
	corrupt := cveDoc("CVE-2026-60001", "2026-03-01T00:00:00.000Z", "A description that lost half its text.")

	live := newCache(t)
	seedLive(t, live, feed, decision, []string{corrupt}, seedAt)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: []string{truth}}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if rep.Divergent != 1 || rep.Restored != 1 {
		t.Fatalf("want one divergent and one restored, got divergent=%d restored=%d", rep.Divergent, rep.Restored)
	}
	if got := snapshot(t, live, feed.ID)["CVE-2026-60001"].raw; got != truth {
		t.Errorf("the corrupt row was not replaced with the publisher's bytes")
	}
}

// TestAnUndatableRowFailsTowardGroundTruth pins the third arm of classify: a
// `modified` neither side can parse must not be read as "the live cache is
// ahead". Keeping a row Anvil cannot date over a row it fetched from the
// publisher is the wrong risk.
func TestAnUndatableRowFailsTowardGroundTruth(t *testing.T) {
	base := sideRow{sourceID: "CVE-2026-1", modified: "whenever", digest: contentDigest("published", "whenever", []byte("a"))}
	live := sideRow{sourceID: "CVE-2026-1", modified: "", digest: contentDigest("published", "", []byte("b"))}
	if got := classify(base, live); got != KindDivergent {
		t.Errorf("an undatable pair classified as %q, want %q", got, KindDivergent)
	}
	if !KindDivergent.Repairable() {
		t.Error("KindDivergent is not repairable, so an undatable disagreement would never be fixed")
	}

	same := contentDigest("published", "2026-01-01", []byte("a"))
	if got := classify(sideRow{digest: same}, sideRow{digest: same}); got != "" {
		t.Errorf("identical rows classified as %q, want a match", got)
	}
}

// TestEveryDisagreementKindIsClassifiedAndAccountedFor keeps the kind table
// and the repair rule from drifting apart.
func TestEveryDisagreementKindIsClassifiedAndAccountedFor(t *testing.T) {
	kinds := DisagreementKinds()
	if len(kinds) != 5 {
		t.Fatalf("DisagreementKinds returns %d kinds; the report's five buckets are the partition", len(kinds))
	}
	seen := map[DisagreementKind]bool{}
	for _, k := range kinds {
		if !k.Valid() {
			t.Errorf("%q is enumerated and not Valid", k)
		}
		if seen[k] {
			t.Errorf("%q is enumerated twice", k)
		}
		seen[k] = true
	}
	if DisagreementKind("something-else").Valid() {
		t.Error("Valid admits a kind nobody declared")
	}
	repairable := 0
	for _, k := range kinds {
		if k.Repairable() {
			repairable++
		}
	}
	if repairable != 3 {
		t.Errorf("%d kinds are repairable, want exactly three (missing, stale, divergent): the two "+
			"reported-only kinds are what stop the self-heal deleting or regressing rows", repairable)
	}
	if KindAheadInLive.Repairable() || KindOnlyInLive.Repairable() {
		t.Error("a reported-only kind is marked repairable; that is the data-loss path")
	}
}

// ---------------------------------------------------------------------------
// 3. A failure is loud
// ---------------------------------------------------------------------------

// TestABootstrapFailureIncrementsConsecutiveFailures is the packet's forbidden
// action, asserted directly: "a failed weekly self-heal must increment
// feed_state.consecutive_failures and surface via A.16's staleness mechanism,
// not fail closed and disappear."
func TestABootstrapFailureIncrementsConsecutiveFailures(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(4)
	live := newCache(t)
	seedLive(t, live, feed, decision, docs, seedAt)
	before := snapshot(t, live, feed.ID)

	boom := errors.New("the publisher returned 503 for six hours")
	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, err: boom}),
	})

	if n, ok := failuresFor(t, live, feed.ID); ok && n != 0 {
		t.Fatalf("the fixture starts with consecutive_failures = %d, want 0", n)
	}

	rep, err := h.WeeklySelfHeal(context.Background())
	if err == nil {
		t.Fatal("a bootstrap failure returned no error; the self-heal failed closed and disappeared")
	}
	if !errors.Is(err, ErrBaselineFailed) || !errors.Is(err, boom) {
		t.Errorf("the error does not carry the cause: %v", err)
	}
	if !rep.Failed || rep.FailedBecause == "" {
		t.Errorf("the report does not say the pass failed: %+v", rep)
	}
	if !rep.FailureRecorded {
		t.Fatal("the failure was not recorded in feed_state")
	}
	if rep.ConsecutiveFailures != 1 {
		t.Errorf("consecutive_failures reported as %d, want 1", rep.ConsecutiveFailures)
	}
	n, ok := failuresFor(t, live, feed.ID)
	if !ok {
		t.Fatal("no feed_state row was written at all; A.16's staleness mechanism has nothing to read")
	}
	if n != 1 {
		t.Errorf("feed_state.consecutive_failures is %d, want 1", n)
	}

	// A second failure keeps climbing. A counter that saturates at one cannot
	// distinguish a blip from an outage.
	if _, err := h.WeeklySelfHeal(context.Background()); err == nil {
		t.Fatal("the second failure returned no error")
	}
	if n, _ := failuresFor(t, live, feed.ID); n != 2 {
		t.Errorf("after two failures consecutive_failures is %d, want 2", n)
	}

	// And the cache was not touched on the way past.
	if got := snapshot(t, live, feed.ID); !sameSnapshot(got, before) {
		t.Error("a failed self-heal modified the live cache")
	}
	if !strings.Contains(rep.Summary(), "FAILED") {
		t.Errorf("the operator's one-line summary does not say the pass failed: %q", rep.Summary())
	}
}

// TestAnIncompleteBaselineIsRefusedAndCounted: a partial import is a PREFIX of
// ground truth, so its "only in the live cache" count would be fiction.
func TestAnIncompleteBaselineIsRefusedAndCounted(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(6)
	live := newCache(t)
	seedLive(t, live, feed, decision, docs, seedAt)
	before := snapshot(t, live, feed.ID)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{
			t: t, feed: feed, decision: decision, docs: docs[:2], incomplete: true,
		}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if !errors.Is(err, ErrIncompleteBaseline) {
		t.Fatalf("an incomplete baseline gave %v, want ErrIncompleteBaseline", err)
	}
	if !rep.Failed || !rep.FailureRecorded || rep.ConsecutiveFailures != 1 {
		t.Errorf("an incomplete baseline was not counted as a failure: %+v", rep)
	}
	if rep.MissingInLive != 0 || rep.OnlyInLive != 0 {
		t.Errorf("the pass diffed against a partial baseline anyway: %+v", rep)
	}
	if got := snapshot(t, live, feed.ID); !sameSnapshot(got, before) {
		t.Error("a refused self-heal modified the live cache")
	}
}

// TestAnEmptyBaselineIsRefusedAndCounted: a full baseline of a CVE feed that
// holds zero advisories is a broken artifact, not ground truth about an empty
// world. Diffing against it would report the whole cache as unexplained.
func TestAnEmptyBaselineIsRefusedAndCounted(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(5)
	live := newCache(t)
	seedLive(t, live, feed, decision, docs, seedAt)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, emptyResult: true}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if !errors.Is(err, ErrEmptyBaseline) {
		t.Fatalf("an empty baseline gave %v, want ErrEmptyBaseline", err)
	}
	if rep.OnlyInLive != 0 {
		t.Errorf("the pass reported %d rows as unexplained against an empty baseline; that is the "+
			"false alarm the size of the cache", rep.OnlyInLive)
	}
	if n, _ := failuresFor(t, live, feed.ID); n != 1 {
		t.Errorf("consecutive_failures is %d, want 1", n)
	}
	if got := countRows(t, live, `SELECT count(*) FROM advisory WHERE source = ?`, feed.ID); got != len(docs) {
		t.Errorf("the live cache holds %d rows, want %d", got, len(docs))
	}
}

// TestALicenceDecisionMismatchIsRefused: both sides call license.Resolve on
// the same feed row, so a disagreement means they are reading different
// mirrors and neither answer may be used to write a row.
func TestALicenceDecisionMismatchIsRefused(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	wrongDir := decision.Dir + "-somewhere-else"
	live := newCache(t)
	seedLive(t, live, feed, decision, corpus(2), seedAt)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{
			t: t, feed: feed, decision: decision, docs: corpus(2), dirOverride: &wrongDir,
		}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if !errors.Is(err, ErrDecisionMismatch) {
		t.Fatalf("a mismatched licence decision gave %v, want ErrDecisionMismatch", err)
	}
	if !rep.Failed || !rep.FailureRecorded {
		t.Errorf("a licence decision mismatch was not counted as a failure: %+v", rep)
	}
}

// TestTheLicenceGateRunsBeforeAnythingIsFetched. A refusal must cost no
// request, and — deliberately — must NOT climb the failure counter: no
// publisher licence body has been acquired is the ORDINARY state of a fresh
// clone, and counting it weekly would make the counter useless for the case it
// exists for.
func TestTheLicenceGateRunsBeforeAnythingIsFetched(t *testing.T) {
	feed := testFeed("cvelistv5")
	live := newCache(t)

	calls := 0
	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: emptyMirror(),
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, docs: corpus(2), calls: &calls}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err == nil {
		t.Fatal("an unadmitted feed produced no refusal")
	}
	if !errors.Is(err, license.ErrLicenseRefused) && !strings.Contains(err.Error(), "licen") {
		t.Errorf("the refusal does not come from the licence gate: %v", err)
	}
	if calls != 0 {
		t.Errorf("the baseline was built %d times despite a licence refusal; the gate must run BEFORE "+
			"a byte is fetched", calls)
	}
	if !rep.Refused || rep.RefusedBecause == "" {
		t.Errorf("the report does not name the refusal: %+v", rep)
	}
	if rep.Failed {
		t.Error("a licence refusal was recorded as a self-heal failure")
	}
	if _, ok := failuresFor(t, live, feed.ID); ok {
		t.Error("a licence refusal wrote a feed_state row; a fresh clone would climb a failure counter " +
			"on every feed in the table with nothing broken")
	}
	if rep.Tier != license.NoTier {
		t.Errorf("a refused pass reports tier %d; a refusal must never carry a valid tier, and 0 is the "+
			"most permissive tier this system has", rep.Tier)
	}
}

// TestAFeedWithNoBulkBaselineIsRefused. Running a "full baseline" against a
// mechanism that imports nothing yields an empty ground truth, against which
// the entire live cache looks unexplained.
func TestAFeedWithNoBulkBaselineIsRefused(t *testing.T) {
	for _, mech := range []config.BootstrapMechanism{config.BootstrapNone, config.BootstrapIncrementalAPI} {
		t.Run(string(mech), func(t *testing.T) {
			feed := testFeed("kev")
			feed.BootstrapMechanism = mech
			mirror := admittingMirror(t, feed)

			calls := 0
			h := newHealer(t, Options{
				Live: newCache(t), Feed: feed, Mirror: mirror,
				Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, calls: &calls}),
			})
			_, err := h.WeeklySelfHeal(context.Background())
			if !errors.Is(err, ErrNoBaselineMechanism) {
				t.Fatalf("bootstrap_mechanism %q gave %v, want ErrNoBaselineMechanism", mech, err)
			}
			if calls != 0 {
				t.Errorf("the baseline was built anyway (%d calls)", calls)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. Nothing full-table reaches the cache
// ---------------------------------------------------------------------------

// TestNoFullTableStatementReachesTheLiveCache opens the live cache through a
// tracing driver and inspects every statement that reached the driver layer
// during a repair.
//
// This is A.2's and A.14's shared rule, re-checked for this pass: FTS5 accepts
// incremental INSERT/DELETE, so a repair touching three records costs three
// row-scoped index writes and NOT a rebuild. It is checked as an observation
// of production statements, not as an assertion about code someone read.
func TestNoFullTableStatementReachesTheLiveCache(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(12)
	live := newTracedCache(t)
	seedLive(t, live, feed, decision, docs[3:], seedAt)

	trace.reset()
	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if rep.Restored != 3 {
		t.Fatalf("restored %d rows, want 3", rep.Restored)
	}

	stmts := trace.snapshot()
	if len(stmts) == 0 {
		t.Fatal("the trace captured nothing; the driver seam is inert and would pass anything")
	}

	// The forbidden shapes. This list is a DENYLIST only in its role as an
	// alarm: the structural guarantee is reconcile's own allowlist plus
	// delta.Apply's, and this is the observation that proves those two hold in
	// combination on a real run.
	forbidden := []string{
		"drop table", "drop view", "create virtual table", "create table",
		"alter table", "vacuum", "reindex", "'rebuild'",
	}
	// Every DELETE that reaches the cache must be ROW-SCOPED. A.14 legitimately
	// replaces one advisory's `affected` and `cve_alias` rows per upsert
	// (surrogate key, no unique natural key) and deletes one FTS row by rowid;
	// what must never appear is a delete whose scope is a table.
	rowScopes := []string{
		"where rowid = ?",
		"where source = ? and source_id = ?",
	}
	upserts, ftsWrites := 0, 0
	for _, q := range stmts {
		flat := strings.ToLower(strings.Join(strings.Fields(q), " "))
		for _, bad := range forbidden {
			if strings.Contains(flat, bad) {
				t.Errorf("a full-table statement reached the live cache: %q (matched %q)", flat, bad)
			}
		}
		if strings.HasPrefix(flat, "delete ") {
			scoped := false
			for _, s := range rowScopes {
				if strings.HasSuffix(flat, s) {
					scoped = true
				}
			}
			if !scoped {
				t.Errorf("a DELETE reached the live cache that is not row-scoped: %q", flat)
			}
		}
		if strings.HasPrefix(flat, "insert into advisory (") {
			upserts++
		}
		if strings.Contains(flat, "advisory_fts") &&
			(strings.HasPrefix(flat, "insert") || strings.HasPrefix(flat, "delete")) {
			ftsWrites++
		}
	}
	if upserts != 3 {
		t.Errorf("%d advisory upserts reached the driver, want exactly 3 — one per restored record", upserts)
	}
	if ftsWrites != 3 {
		t.Errorf("%d statements touched advisory_fts, want exactly 3", ftsWrites)
	}
}

// TestTheStatementAllowlistIsOnTheLivePath is the RED verification of the
// allowlist: an allowlist that has never refused anything has not been tested.
//
// It removes the scan statement from the allowlist and asserts the PRODUCTION
// path then fails — so the guard is load-bearing rather than a decorative map
// nothing consults.
func TestTheStatementAllowlistIsOnTheLivePath(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)
	docs := corpus(3)

	run := func() error {
		live := newCache(t)
		seedLive(t, live, feed, decision, docs[1:], seedAt)
		h := newHealer(t, Options{
			Live: live, Feed: feed, Mirror: mirror,
			Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs}),
		})
		_, err := h.WeeklySelfHeal(context.Background())
		return err
	}

	if err := run(); err != nil {
		t.Fatalf("the pass does not pass with the allowlist intact: %v", err)
	}

	key := strings.TrimSpace(scanAdvisorySQL)
	saved := allowedStatements[key]
	delete(allowedStatements, key)
	err := run()
	allowedStatements[key] = saved

	if !errors.Is(err, ErrStatementNotAllowed) {
		t.Fatalf("with the scan removed from the allowlist the pass returned %v; the guard is not on "+
			"the production path", err)
	}
	if err := run(); err != nil {
		t.Fatalf("the allowlist was not restored: %v", err)
	}
}

// TestTheAllowlistHoldsNoWriteAgainstTheAdvisoryTables. This package must have
// no second write path for advisory / affected / advisory_fts; those writes
// belong to delta.Apply so that one writer holds the schema invariants for
// both A.14 and A.15.
func TestTheAllowlistHoldsNoWriteAgainstTheAdvisoryTables(t *testing.T) {
	if len(allowedStatements) == 0 {
		t.Fatal("the allowlist is empty; the guard would refuse everything and the tests above would not pass")
	}
	writesFeedState := 0
	for q, reason := range allowedStatements {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("allowlist entry has no reason:\n\t%s", q)
		}
		flat := strings.ToLower(strings.Join(strings.Fields(q), " "))
		switch {
		case strings.HasPrefix(flat, "select "):
			// A read is fine whatever it names.
		case strings.HasPrefix(flat, "insert into feed_state"):
			writesFeedState++
		default:
			t.Errorf("allowlist entry is neither a SELECT nor the feed_state upsert:\n\t%s", flat)
		}
		for _, table := range []string{"advisory ", "advisory(", "advisory_fts", "affected"} {
			if strings.HasPrefix(flat, "select ") {
				continue
			}
			if strings.Contains(flat, table) {
				t.Errorf("an allowlisted write names %q; those writes belong to delta.Apply:\n\t%s", table, flat)
			}
		}
	}
	if writesFeedState != 1 {
		t.Errorf("%d allowlisted statements write feed_state, want exactly one (the failure counter)", writesFeedState)
	}
	if err := checkStatement(`DELETE FROM advisory WHERE source = ?`); !errors.Is(err, ErrStatementNotAllowed) {
		t.Errorf("the guard admitted a plausible-looking DELETE: %v", err)
	}
	if err := checkStatement(`INSERT INTO advisory_fts(advisory_fts) VALUES('rebuild')`); !errors.Is(err, ErrStatementNotAllowed) {
		t.Errorf("the guard admitted an FTS rebuild: %v", err)
	}
	for q := range allowedStatements {
		if err := checkStatement(q); err != nil {
			t.Errorf("the guard refuses its own allowlist entry: %v", err)
		}
		if err := checkStatement("  \n" + q + "\n  "); err != nil {
			t.Errorf("the guard is whitespace-sensitive in a way that would refuse a real call: %v", err)
		}
	}
}

// TestTheMergeJoinRefusesAnUnorderedScan is the RED verification of the second
// guard. A merge join over an unordered scan silently produces nonsense — every
// key looks missing on one side and unexplained on the other — and "the
// statement says ORDER BY" is not evidence that the rows arrived that way.
func TestTheMergeJoinRefusesAnUnorderedScan(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	db := newCache(t)
	seedLive(t, db, feed, decision, corpus(5), seedAt)

	// Deliberately DESCENDING, issued straight at the driver so the allowlist
	// is not the thing under test here.
	rows, err := db.QueryContext(context.Background(),
		`SELECT source_id, modified, state, raw_json FROM advisory WHERE source = ? ORDER BY source_id DESC`, feed.ID)
	if err != nil {
		t.Fatalf("querying: %v", err)
	}
	defer func() { _ = rows.Close() }()

	c := newCursor(rows)
	for c.valid {
		c.advance()
	}
	if c.err == nil {
		t.Fatal("the cursor consumed a descending scan without complaint; the merge join would have " +
			"reported every row as a disagreement in both directions")
	}
	if !strings.Contains(c.err.Error(), "ORDER BY") {
		t.Errorf("the cursor's refusal does not say what went wrong: %v", c.err)
	}

	// And the ascending scan the production path uses is accepted.
	asc, err := db.QueryContext(context.Background(), scanAdvisorySQL, feed.ID)
	if err != nil {
		t.Fatalf("querying: %v", err)
	}
	defer func() { _ = asc.Close() }()
	ok := newCursor(asc)
	seen := 0
	for ok.valid {
		seen++
		ok.advance()
	}
	if ok.err != nil {
		t.Fatalf("the ordered scan was refused: %v", ok.err)
	}
	if seen != 5 {
		t.Errorf("the cursor saw %d rows, want 5", seen)
	}
}

// ---------------------------------------------------------------------------
// Reporting, cadence and the remaining behaviour
// ---------------------------------------------------------------------------

// TestReportOnlyDiffsAndWritesNothing. A drift alarm should be able to run
// more often than a repair, and an operator should be able to see what a
// self-heal WOULD do before letting it do it.
func TestReportOnlyDiffsAndWritesNothing(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(8)
	live := newCache(t)
	seedLive(t, live, feed, decision, docs[3:], seedAt)
	before := snapshot(t, live, feed.ID)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror, ReportOnly: true,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if rep.MissingInLive != 3 {
		t.Errorf("missing-in-live is %d, want 3", rep.MissingInLive)
	}
	if rep.Restored != 0 || rep.Batch.Upserts != 0 {
		t.Errorf("a report-only pass wrote %d rows", rep.Restored)
	}
	if !rep.ReportOnly {
		t.Error("the report does not say it was report-only")
	}
	if got := snapshot(t, live, feed.ID); !sameSnapshot(got, before) {
		t.Error("a report-only pass changed the live cache")
	}
	for _, s := range rep.Samples {
		if s.Repaired {
			t.Errorf("a report-only pass marked %s as repaired", s.SourceID)
		}
	}
}

// TestTheBaselineNeverLandsInTheLiveCache. The whole design rests on the fresh
// baseline being imported somewhere else: if it landed in the live cache, the
// repair would BE the import and there would be nothing left to diff.
func TestTheBaselineNeverLandsInTheLiveCache(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)
	docs := corpus(9)

	live := newCache(t)
	seedLive(t, live, feed, decision, docs[4:], seedAt)

	var handedLive bool
	factory := func(scratch *sql.DB) (Baseliner, error) {
		if scratch == live {
			handedLive = true
		}
		return &fakeBaseliner{t: t, db: scratch, feed: feed, decision: decision, docs: docs}, nil
	}

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror, ReportOnly: true, Baseline: factory,
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if handedLive {
		t.Fatal("the baseline factory was handed the LIVE cache handle")
	}
	// Report-only, so the live cache still holds only what the delta path put
	// there — which is only observable because the baseline went elsewhere.
	if got := countRows(t, live, `SELECT count(*) FROM advisory WHERE source = ?`, feed.ID); got != 5 {
		t.Errorf("the live cache holds %d rows after a report-only pass over a 9-row baseline, want 5", got)
	}
	if rep.BaselineRows != 9 {
		t.Errorf("the baseline held %d rows, want 9", rep.BaselineRows)
	}
}

// TestTheScratchBaselineIsCleanedUpUnlessAsked. A 570 MB import per feed per
// week is not something to leave behind by accident, and it IS something an
// operator investigating a drift needs to be able to keep.
func TestTheScratchBaselineIsCleanedUpUnlessAsked(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)
	docs := corpus(3)

	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprintf("keep=%v", keep), func(t *testing.T) {
			workDir := t.TempDir()
			live := newCache(t)
			seedLive(t, live, feed, decision, docs, seedAt)
			h := newHealer(t, Options{
				Live: live, Feed: feed, Mirror: mirror, WorkDir: workDir, KeepBaseline: keep,
				Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs}),
			})
			rep, err := h.WeeklySelfHeal(context.Background())
			if err != nil {
				t.Fatalf("WeeklySelfHeal: %v", err)
			}
			entries, err := filepath.Glob(filepath.Join(workDir, "anvil-baseline-*"))
			if err != nil {
				t.Fatalf("globbing the work directory: %v", err)
			}
			switch {
			case keep && len(entries) != 1:
				t.Errorf("KeepBaseline left %d scratch directories, want 1", len(entries))
			case keep && rep.BaselinePath == "":
				t.Error("KeepBaseline did not name the scratch database in the report")
			case !keep && len(entries) != 0:
				t.Errorf("the scratch baseline was left behind: %v", entries)
			case !keep && rep.BaselinePath != "":
				t.Errorf("the report names a scratch path that was deleted: %q", rep.BaselinePath)
			}
		})
	}
}

// TestTheCadenceComesFromTheFeedRowAndForceOverridesIt. There is no weekly
// constant in this package: A.1 puts every cadence in feeds.yaml so an
// operator can dial the pipeline down on a constrained host.
func TestTheCadenceComesFromTheFeedRowAndForceOverridesIt(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)
	docs := corpus(4)

	live := newCache(t)
	seedLive(t, live, feed, decision, docs[1:], seedAt)

	// A success recorded inside the same weekly window as the clock.
	lastOK := healAt.Add(-2 * time.Hour).Format(time.RFC3339)
	if _, err := live.Exec(cache.UpsertFeedStateSQL, feed.ID, nil, nil, nil, lastOK, 0, 0); err != nil {
		t.Fatalf("seeding feed_state: %v", err)
	}

	calls := 0
	base := Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs, calls: &calls}),
	}

	rep, err := newHealer(t, base).WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if !rep.Skipped {
		t.Fatalf("the pass ran inside the same baseline window: %+v", rep.Plan)
	}
	if calls != 0 {
		t.Errorf("a skipped pass built the baseline anyway (%d calls)", calls)
	}
	if rep.Plan.BaselineInterval != 604800*time.Second {
		t.Errorf("the plan reports a %s baseline interval; it must come from the feed row",
			rep.Plan.BaselineInterval)
	}
	if rep.Note == "" || !strings.Contains(rep.Summary(), "skipped") {
		t.Errorf("a skipped pass does not say why: %q", rep.Summary())
	}

	forced := base
	forced.Force = true
	rep, err = newHealer(t, forced).WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("forced WeeklySelfHeal: %v", err)
	}
	if rep.Skipped || calls != 1 {
		t.Fatalf("Force did not override the cadence: skipped=%v calls=%d", rep.Skipped, calls)
	}
	if rep.Restored != 1 {
		t.Errorf("the forced pass restored %d rows, want 1", rep.Restored)
	}

	// A feed row with no baseline cadence schedules no self-heal at all.
	noCadence := base
	noCadence.Feed.BaselineIntervalSeconds = 0
	rep, err = newHealer(t, noCadence).WeeklySelfHeal(context.Background())
	if err != nil || !rep.Skipped {
		t.Fatalf("a zero baseline_interval_seconds did not skip: err=%v skipped=%v", err, rep.Skipped)
	}
	if !strings.Contains(rep.Note, "baseline_interval_seconds") {
		t.Errorf("the skip reason does not name the missing cadence: %q", rep.Note)
	}
}

// TestSamplesAreBoundedAndTheCountsAreNot. A report is read by a person; a
// catastrophic diff must produce a report and not a second copy of the cache.
func TestSamplesAreBoundedAndTheCountsAreNot(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(30)
	live := newCache(t)
	seedLive(t, live, feed, decision, docs[20:], seedAt)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror, MaxSamples: 4, ReportOnly: true,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if rep.MissingInLive != 20 {
		t.Errorf("missing-in-live is %d, want 20; the COUNTS must not be truncated", rep.MissingInLive)
	}
	if len(rep.Samples) != 4 {
		t.Errorf("the sample holds %d entries, want 4", len(rep.Samples))
	}
	if !rep.SamplesTruncated {
		t.Error("the report does not say the sample was truncated")
	}
	if err := rep.CheckTotals(); err != nil {
		t.Errorf("the counts do not partition the row sets: %v", err)
	}
}

// TestCheckTotalsCatchesAMiscount. CheckTotals is only worth exporting if it
// can fail, so this drives it against a report that does not add up.
func TestCheckTotalsCatchesAMiscount(t *testing.T) {
	good := ReconcileReport{BaselineRows: 5, LiveRows: 4, Matched: 3, MissingInLive: 1, StaleInLive: 1, OnlyInLive: 0}
	if err := good.CheckTotals(); err != nil {
		t.Fatalf("a consistent report was rejected: %v", err)
	}
	bad := good
	bad.Matched = 2
	if err := bad.CheckTotals(); err == nil {
		t.Error("CheckTotals accepted a report whose buckets do not account for every row")
	}
	if good.Updated() != 1 {
		t.Errorf("Updated() is %d, want stale+divergent = 1", good.Updated())
	}
	if good.Disagreements() != 2 || !good.Drifted() {
		t.Errorf("Disagreements()=%d Drifted()=%v, want 2 and true", good.Disagreements(), good.Drifted())
	}
	clean := ReconcileReport{BaselineRows: 3, LiveRows: 3, Matched: 3}
	if clean.Drifted() {
		t.Error("a report with no disagreements claims drift")
	}
	if !strings.Contains(clean.Summary(), "matched 3") {
		t.Errorf("a clean summary does not state what it found: %q", clean.Summary())
	}
}

// TestAnUndecodableBaselineRecordDoesNotBlockTheRest. One malformed record in
// ground truth must not cost the other restorations; it is counted, sampled
// and carried past.
func TestAnUndecodableBaselineRecordDoesNotBlockTheRest(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(4)
	live := newCache(t)
	seedLive(t, live, feed, decision, docs[2:], seedAt)

	// A row the real importer would never write, planted straight into the
	// scratch baseline: a key with bytes nothing can decode.
	plant := func(scratch *sql.DB) {
		var rowid int64
		err := scratch.QueryRow(cache.UpsertAdvisorySQL,
			feed.ID, "CVE-2026-99999", "CVE-2026-99999", nil, "2026-05-01T00:00:00Z",
			cache.AdvisoryPublished, nil, nil, nil, nil, nil, nil, 0,
			decision.EffectiveSPDX, nil, decision.Tier.Int(), string(cache.AdvisoryTrustDefault),
			healAt.Format(time.RFC3339), 0, 0, nil, []byte("this is not a document")).Scan(&rowid)
		if err != nil {
			t.Fatalf("planting an undecodable baseline row: %v", err)
		}
	}

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror,
		Baseline: fakeFactory(fakeBaseliner{
			t: t, feed: feed, decision: decision, docs: docs, afterWrite: plant,
		}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("one bad record aborted the whole self-heal: %v", err)
	}
	if rep.MissingInLive != 3 {
		t.Fatalf("missing-in-live is %d, want 3 (two real drops plus the planted key)", rep.MissingInLive)
	}
	if rep.RepairFailures != 1 {
		t.Errorf("repair failures is %d, want 1", rep.RepairFailures)
	}
	if rep.Restored != 2 {
		t.Errorf("restored %d rows, want 2; the two decodable drops must still be repaired", rep.Restored)
	}
	if !strings.Contains(rep.Note, "could not be decoded") {
		t.Errorf("the report does not mention the undecodable record: %q", rep.Note)
	}
	var bad *Disagreement
	for i := range rep.Samples {
		if rep.Samples[i].SourceID == "CVE-2026-99999" {
			bad = &rep.Samples[i]
		}
	}
	if bad == nil {
		t.Fatal("the undecodable key was not sampled")
	}
	if bad.Repaired || !strings.Contains(bad.Note, "did not decode") {
		t.Errorf("the sample does not say what happened to it: %+v", *bad)
	}
	if n := countRows(t, live, `SELECT count(*) FROM advisory WHERE source = ? AND source_id = ?`,
		feed.ID, "CVE-2026-99999"); n != 0 {
		t.Error("the undecodable record was written into the live cache anyway")
	}
}

// TestNewRefusesAnUnusableHealer. Every one of these is something the package
// cannot invent, and inventing any of them is how a self-heal ends up
// bootstrapping into the live cache or fetching without a licence.
func TestNewRefusesAnUnusableHealer(t *testing.T) {
	feed := testFeed("cvelistv5")
	ok := Options{Live: newCache(t), Feed: feed, WorkDir: t.TempDir(), Baseline: fakeFactory(fakeBaseliner{})}
	if _, err := New(ok); err != nil {
		t.Fatalf("a complete Options was refused: %v", err)
	}
	for name, mutate := range map[string]func(*Options){
		"no live cache":       func(o *Options) { o.Live = nil },
		"no feed":             func(o *Options) { o.Feed = config.FeedConfig{} },
		"no work directory":   func(o *Options) { o.WorkDir = "" },
		"no baseline factory": func(o *Options) { o.Baseline = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := ok
			mutate(&bad)
			if _, err := New(bad); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("New accepted %s: %v", name, err)
			}
		})
	}
	over := ok
	over.RepairBatch = MaxRepairBatch + 1
	if _, err := New(over); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("New accepted a repair batch over the cap: %v", err)
	}
	if f := FromBootstrapper(bootstrap.Bootstrapper{}); f != nil {
		if _, err := f(nil); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("FromBootstrapper accepted a nil scratch handle: %v", err)
		}
	}
}

// TestARepairBatchIsBoundedAndStillRestoresEverything drives the batching seam
// so that a self-heal larger than one transaction is exercised at all.
func TestARepairBatchIsBoundedAndStillRestoresEverything(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)

	docs := corpus(17)
	live := newCache(t)
	seedLive(t, live, feed, decision, docs[:2], seedAt)

	h := newHealer(t, Options{
		Live: live, Feed: feed, Mirror: mirror, RepairBatch: 4,
		Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs}),
	})
	rep, err := h.WeeklySelfHeal(context.Background())
	if err != nil {
		t.Fatalf("WeeklySelfHeal: %v", err)
	}
	if rep.Restored != 15 {
		t.Fatalf("restored %d rows across batches of 4, want 15", rep.Restored)
	}
	if got := countRows(t, live, `SELECT count(*) FROM advisory WHERE source = ?`, feed.ID); got != 17 {
		t.Errorf("the live cache holds %d rows, want 17", got)
	}
	if got := countRows(t, live, `SELECT count(*) FROM advisory_fts`); got != 17 {
		t.Errorf("the FTS index holds %d rows, want 17", got)
	}
}

// TestTheReportCarriesTheDurationItMeasured. The duration is written by a
// deferred assignment, which reaches the caller's value only because
// WeeklySelfHeal's results are NAMED. With unnamed results every report would
// carry a zero that looked like a measurement, and nothing else in this file
// would have noticed.
func TestTheReportCarriesTheDurationItMeasured(t *testing.T) {
	feed := testFeed("cvelistv5")
	mirror := admittingMirror(t, feed)
	decision := admittedDecision(t, feed, mirror)
	docs := corpus(3)

	// A clock that advances one second per reading, so the measured span is a
	// fixed non-zero number rather than a wall-clock race.
	var ticks int
	stepping := func() time.Time {
		ticks++
		return healAt.Add(time.Duration(ticks-1) * time.Second)
	}

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"repaired", Options{Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, docs: docs})}},
		{"failed", Options{Baseline: fakeFactory(fakeBaseliner{t: t, feed: feed, decision: decision, err: errors.New("no")})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ticks = 0
			live := newCache(t)
			seedLive(t, live, feed, decision, docs[1:], seedAt)
			o := tc.opts
			o.Live, o.Feed, o.Mirror, o.Now = live, feed, mirror, stepping
			rep, _ := newHealer(t, o).WeeklySelfHeal(context.Background())
			if rep.Duration <= 0 {
				t.Errorf("the report carries a %s duration after %d clock readings", rep.Duration, ticks)
			}
			if rep.RanAt != healAt {
				t.Errorf("RanAt is %s, want the first clock reading %s", rep.RanAt, healAt)
			}
		})
	}
}

// TestSortedSamplesGroupsByKind is small, and exists because a report an
// operator cannot read is a report that does not get read.
func TestSortedSamplesGroupsByKind(t *testing.T) {
	in := []Disagreement{
		{SourceID: "CVE-2", Kind: KindOnlyInLive},
		{SourceID: "CVE-3", Kind: KindMissingInLive},
		{SourceID: "CVE-1", Kind: KindMissingInLive},
	}
	got := SortedSamples(in)
	want := []string{"CVE-1", "CVE-3", "CVE-2"}
	for i := range want {
		if got[i].SourceID != want[i] {
			t.Fatalf("SortedSamples gave %v, want %v", ids(got), want)
		}
	}
	if in[0].SourceID != "CVE-2" {
		t.Error("SortedSamples mutated its input")
	}
}

func ids(in []Disagreement) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		out = append(out, d.SourceID)
	}
	return out
}

// TestIntegrationNotesForTheManualRun records what a green run here does NOT
// establish, so that the gap is written down rather than assumed away.
func TestIntegrationNotesForTheManualRun(t *testing.T) {
	t.Log(strings.Join([]string{
		"NOT PROVED BY THIS PACKAGE'S TESTS:",
		"  - affordability. The fixtures are tens of records; a real cvelistV5 baseline is ~300,000",
		"    records and ~570 MB, and neither the wall time of the merge join nor the disk cost of the",
		"    scratch database has been measured against one.",
		"  - go test -race. It cannot run on the Windows dev host (cgo.exe exit 2); CI runs it on Linux.",
		"  - that A.8's decoder and A.14's decoder agree about every REAL publisher document. They agree",
		"    about the synthetic CVE 5.1 documents in this file, which is what makes the 'matched' count",
		"    meaningful here; a disagreement on a real corpus would surface as a wall of 'divergent' rows",
		"    on the first real self-heal, which is a loud failure rather than a silent one.",
	}, "\n"))
}

// ---------------------------------------------------------------------------
// Helpers: the archive, the tracing driver, snapshot comparison
// ---------------------------------------------------------------------------

func buildZip(t *testing.T, docs []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, doc := range docs {
		id := docID(t, doc)
		w, err := zw.Create("cves/2026/" + id + ".json")
		if err != nil {
			t.Fatalf("creating zip member for %s: %v", id, err)
		}
		if _, err := w.Write([]byte(doc)); err != nil {
			t.Fatalf("writing zip member for %s: %v", id, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}

func serveArchive(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Last-Modified", "Sun, 09 Aug 2026 00:00:00 GMT")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sameSnapshot(a, b map[string]storedRow) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// --- the tracing driver ---

const traceDriverName = "sqlite-anvil-reconcile-trace"

type sqlTrace struct {
	mu    sync.Mutex
	stmts []string
}

func (l *sqlTrace) record(q string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stmts = append(l.stmts, q)
}

func (l *sqlTrace) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stmts = nil
}

func (l *sqlTrace) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.stmts...)
}

var trace = &sqlTrace{}

type traceDriver struct{ base driver.Driver }

func (d traceDriver) Open(name string) (driver.Conn, error) {
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return traceConn{Conn: c}, nil
}

// traceConn forwards every statement-carrying method to the real connection
// after recording the SQL. It implements every optional interface
// database/sql probes for, so no call can slip past by falling back to a path
// this wrapper does not cover.
type traceConn struct{ driver.Conn }

func (c traceConn) Prepare(query string) (driver.Stmt, error) {
	trace.record(query)
	return c.Conn.Prepare(query)
}

func (c traceConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	trace.record(query)
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, query)
	}
	return c.Conn.Prepare(query)
}

func (c traceConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	trace.record(query)
	e, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return e.ExecContext(ctx, query, args)
}

func (c traceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	trace.record(query)
	q, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return q.QueryContext(ctx, query, args)
}

func (c traceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Conn.Begin()
}

func (c traceConn) ResetSession(ctx context.Context) error {
	if r, ok := c.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c traceConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func init() {
	probe, err := sql.Open("sqlite", "file:anvil-reconcile-driver-probe?mode=memory")
	if err != nil {
		panic("reconcile_test: cannot resolve the sqlite driver: " + err.Error())
	}
	base := probe.Driver()
	_ = probe.Close()
	sql.Register(traceDriverName, traceDriver{base: base})
}

// newTracedCache opens a live cache through the tracing driver, using the
// cache package's OWN DSN so the connection pragmas are the production ones.
func newTracedCache(t *testing.T) *sql.DB {
	t.Helper()
	dsn, err := cache.DSN(filepath.Join(t.TempDir(), "anvil-cache.sqlite"))
	if err != nil {
		t.Fatalf("building the cache DSN: %v", err)
	}
	db, err := sql.Open(traceDriverName, dsn)
	if err != nil {
		t.Fatalf("opening the traced cache: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := cache.CheckWAL(context.Background(), db); err != nil {
		t.Fatalf("the traced cache is not in WAL mode: %v", err)
	}
	if _, err := cache.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrating the traced cache: %v", err)
	}
	return db
}
