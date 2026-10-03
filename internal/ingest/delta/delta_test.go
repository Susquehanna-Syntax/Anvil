// delta_test.go is A.14's evidence.
//
// The two claims A.14's packet asks to be measured are measured, not asserted:
//
//  1. "A 200-row delta batch produces exactly 200 upserts and zero full-table
//     statements." Counted from a SQL TRACE taken at the driver layer, so it
//     also covers statements database/sql synthesises on the caller's behalf,
//     and so that the number is not read back out of a struct field the code
//     under test filled in itself.
//  2. "The deltaLog.json path is used in preference to re-downloading the
//     cumulative hourly zip on every poll." Measured as bytes: the same feed is
//     synced twice with a Source and twice without one, and the two transfer
//     totals are compared against research/06's own cost model.
//
// Everything else here follows the rules this project has already paid for:
//
//   - EVERY GUARD IS VERIFIED RED. checkStatement, checkRecordName and the
//     no-cadence-literal scanner are each run against a corpus that must fail
//     them, and a green run over an empty corpus is treated as a broken test
//     rather than as a pass.
//   - NO CORPUS COMES FROM THE IMPLEMENTATION. The conformance test compares
//     this package's decoder against A.8's over the same bytes; the fixture
//     documents are written here and consumed by both.
//   - NO NETWORK. httptest only, and the licence gate's fixture mirror is an
//     fstest.MapFS. No test reads the process environment, so a machine with a
//     real ANVIL_GITHUB_TOKEN behaves identically to one without.
package delta

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
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/bootstrap"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/poller"
)

// ---------------------------------------------------------------------------
// Fixture constants
// ---------------------------------------------------------------------------

// fixtureToken is NOT a credential. It is a string chosen so a test can search
// an error or a rendered result for it; nothing anywhere accepts it. The real
// PAT is operator-provisioned, lives in the environment variable the feed row
// names, and is never read by this suite.
const fixtureToken = "not-a-real-token-0000-test-only"

// cc0Verbatim is the publisher licence body the synthetic mirror pins. A.4
// classifies BODIES, so a fixture that wants an admission has to supply one.
const cc0Verbatim = `Creative Commons Legal Code

CC0 1.0 Universal

The person who associated a work with this deed has dedicated the work to the
public domain by waiving all rights to the work worldwide under copyright law.`

const cc0Notes = `SPDX-License-Identifier: CC0-1.0

Anvil's record: this source is public domain and carries no obligation.`

var fixtureClock = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// A tracing driver, so "no full-table statement" is an observation
// ---------------------------------------------------------------------------

const traceDriverName = "sqlite-anvil-delta-trace"

func init() {
	// sql.Open resolves the driver immediately and connects lazily, so this
	// neither creates a file nor opens a connection.
	probe, err := sql.Open("sqlite", "file:anvil-delta-driver-probe?mode=memory")
	if err != nil {
		panic("delta_test: cannot resolve the sqlite driver: " + err.Error())
	}
	base := probe.Driver()
	_ = probe.Close()
	sql.Register(traceDriverName, traceDriver{base: base})
}

// ---------------------------------------------------------------------------
// Cache and mirror fixtures
// ---------------------------------------------------------------------------

// openTracedCache opens a migrated cache through the tracing driver.
//
// It does not call cache.Open, which resolves its own driver name: the trace
// has to sit under this package's statements, and the DSN is taken from
// cache.DSN so the connection pragmas (WAL, foreign_keys, busy_timeout) are the
// ones A.2 requires rather than a set assembled here.
func openTracedCache(t *testing.T) (*sql.DB, *sqlTrace) {
	t.Helper()
	dsn, err := cache.DSN(filepath.Join(t.TempDir(), "anvil-cache.sqlite"))
	if err != nil {
		t.Fatalf("cache.DSN: %v", err)
	}
	db, err := sql.Open(traceDriverName, dsn)
	if err != nil {
		t.Fatalf("opening traced cache: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tr := globalTrace
	tr.reset()
	t.Cleanup(tr.reset)
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatalf("pinging traced cache: %v", err)
	}
	if err := cache.CheckWAL(t.Context(), db); err != nil {
		t.Fatalf("the traced cache is not in WAL mode: %v", err)
	}
	if err := cache.CheckFTS5(t.Context(), db); err != nil {
		t.Fatalf("the traced cache has no FTS5: %v", err)
	}
	if _, err := cache.Migrate(t.Context(), db); err != nil {
		t.Fatalf("migrating the traced cache: %v", err)
	}
	tr.reset()
	return db, tr
}

// openPlainCache opens a migrated cache through the ordinary driver, for the
// tests that do not need a trace.
func openPlainCache(t *testing.T) *sql.DB {
	t.Helper()
	db, err := cache.Open(t.Context(), filepath.Join(t.TempDir(), "anvil-cache.sqlite"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := cache.Migrate(t.Context(), db); err != nil {
		t.Fatalf("cache.Migrate: %v", err)
	}
	return db
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// admittingMirror renders the mirror tree A.4 reads: a pinned manifest, the
// publisher's acquired text at the digest the pin names, and Anvil's own
// record.
//
// IT IS BUILT THE WAY internal/ingest/license's OWN FIXTURES ARE BUILT. The
// gate's admission path is exacting and a mirror assembled by guesswork simply
// refuses — which would make every test below pass for the wrong reason, since
// a refused feed writes nothing and a suite that only ever exercised refusal
// would look green.
func admittingMirror(t *testing.T, feeds ...config.FeedConfig) fs.FS {
	t.Helper()
	fsys := fstest.MapFS{}
	var man strings.Builder
	man.WriteString("# synthetic manifest, delta_test\n")
	man.WriteString("schema_version = 1\n")
	man.WriteString("generated_utc = \"2026-08-09\"\n")
	man.WriteString("generated_by = \"delta_test\"\n")

	notes := map[config.LicenseTier]*strings.Builder{}
	for _, f := range feeds {
		dir := f.MirrorDir
		if dir == "" {
			dir = f.ID
		}
		fmt.Fprintf(&man, "\n[[body]]\nfeed_id = %q\ntier = %d\ndir = %q\n"+
			"spdx_id = %q\ntext_url = \"https://example.invalid/LICENSE\"\n"+
			"sha256 = %q\nclaim_source = \"delta_test fixture\"\n",
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

// fixtureFeed builds one admitted, polled feed row.
//
// The cadences are PARAMETERS, never defaults with a value hidden in here: a
// helper that supplied a cadence would be the hard-coded cadence this package
// forbids, wearing a test's clothes.
func fixtureFeed(id, rawURL string, intervalSeconds, reconcileSeconds, baselineSeconds int) config.FeedConfig {
	return config.FeedConfig{
		ID:                       id,
		URL:                      rawURL,
		Enabled:                  true,
		AuthMode:                 config.AuthNone,
		SyncMechanism:            config.SyncConditionalGetETag,
		IntervalSeconds:          intervalSeconds,
		ReconcileIntervalSeconds: reconcileSeconds,
		BaselineIntervalSeconds:  baselineSeconds,
		FreshnessSLOSeconds:      intervalSeconds * 8,
		OnFailure:                config.OnFailureServeStale,
		LicenseTier:              config.LicenseTier0,
		LicenseSPDX:              "CC0-1.0",
		MirrorDir:                id,
		BootstrapMechanism:       config.BootstrapBulkArchive,
	}
}

// newTestSyncer wires a Syncer to a REAL A.7 poller pointed at an httptest
// server. Using the real poller is the point: it is what makes the licence
// gate run before the request, and a fake would let this suite pass with the
// gate bypassed.
func newTestSyncer(t *testing.T, db *sql.DB, feed config.FeedConfig, mirror fs.FS, tr http.RoundTripper, src Source, now func() time.Time) *Syncer {
	t.Helper()
	p, err := poller.New(poller.Options{
		DB:          db,
		Mirror:      mirror,
		Transport:   tr,
		Credentials: fixtureCredentials{},
		Now:         now,
	})
	if err != nil {
		t.Fatalf("poller.New: %v", err)
	}
	s, err := New(Options{DB: db, Poller: p, Source: src, Now: now})
	if err != nil {
		t.Fatalf("delta.New: %v", err)
	}
	return s
}

// fixtureCredentials answers nothing. No test in this file reads the process
// environment, so a machine that happens to carry a real feed credential
// behaves exactly like one that does not.
type fixtureCredentials struct{}

func (fixtureCredentials) Credential(string) (string, bool) { return "", false }

// ---------------------------------------------------------------------------
// Document fixtures — written HERE, consumed by both decoders
// ---------------------------------------------------------------------------

// cve5Record renders one CVE 5.x record. It is the shape a deltaLog names.
func cve5Record(id string, updated string) []byte {
	doc := map[string]any{
		"dataType":    "CVE_RECORD",
		"dataVersion": "5.1",
		"cveMetadata": map[string]any{
			"cveId":         id,
			"state":         "PUBLISHED",
			"datePublished": "2026-01-01T00:00:00Z",
			"dateUpdated":   updated,
		},
		"containers": map[string]any{
			"cna": map[string]any{
				"descriptions": []any{map[string]any{
					"lang":  "en",
					"value": "A synthetic advisory about " + id + " affecting tokenalpha" + strings.TrimPrefix(id, "CVE-"),
				}},
				"references": []any{map[string]any{"url": "https://example.invalid/adv/" + id}},
				"metrics": []any{map[string]any{"cvssV3_1": map[string]any{
					"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					"baseScore":    9.8,
					"baseSeverity": "CRITICAL",
				}}},
				"affected": []any{map[string]any{
					"vendor":      "example",
					"product":     "widget",
					"packageName": "widget",
					"versions": []any{map[string]any{
						"version":           "1.0.0",
						"lessThan":          "1.2.3",
						"status":            "affected",
						"versionType":       "semver",
						"lessThanOrEqual":   "",
						"changesUnexpected": false,
					}},
				}},
			},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

// osvRecord renders one OSV advisory, which is also GHSA's format.
func osvRecord(i int) []byte {
	doc := map[string]any{
		"schema_version": "1.6.0",
		"id":             fmt.Sprintf("GHSA-test-%06d", i),
		"aliases":        []string{fmt.Sprintf("CVE-2026-%06d", i)},
		"published":      "2026-01-01T00:00:00Z",
		"modified":       "2026-02-01T00:00:00Z",
		"summary":        fmt.Sprintf("Synthetic advisory %d", i),
		"details":        "Details of a synthetic advisory about tokengamma" + strconv.Itoa(i) + ".",
		"severity": []any{map[string]any{
			"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		}},
		"references": []any{map[string]any{"type": "ADVISORY", "url": fmt.Sprintf("https://example.invalid/a/%d", i)}},
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "PyPI", "name": fmt.Sprintf("pkg-%d", i%7)},
			"ranges": []any{map[string]any{
				"type": "ECOSYSTEM",
				"events": []any{
					map[string]any{"introduced": "0"},
					map[string]any{"fixed": fmt.Sprintf("1.%d.0", i%5)},
				},
			}},
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

// ubuntuOSVRecord is an OSV record from a DISTRO, which must come out with
// distro_backport set. research/12 §3 is the reason that column exists.
func ubuntuOSVRecord(i int) []byte {
	doc := map[string]any{
		"schema_version": "1.6.0",
		"id":             fmt.Sprintf("USN-%06d-1", i),
		"aliases":        []string{fmt.Sprintf("CVE-2025-%06d", i)},
		"published":      "2026-01-01T00:00:00Z",
		"modified":       "2026-02-01T00:00:00Z",
		"summary":        "A synthetic distro advisory",
		"details":        "The distro backported the fix without moving the upstream version.",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
			"ranges": []any{map[string]any{
				"type":   "ECOSYSTEM",
				"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "3.0.2-0ubuntu1.10"}},
			}},
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

// kevCatalogue renders a KEV-shaped document.
func kevCatalogue(ids ...string) []byte {
	vulns := make([]any, 0, len(ids))
	for _, id := range ids {
		vulns = append(vulns, map[string]any{
			"cveID":             id,
			"vendorProject":     "Example",
			"product":           "Widget",
			"vulnerabilityName": "Example Widget Remote Code Execution",
			"dateAdded":         "2026-03-01",
			"shortDescription":  "A synthetic known-exploited entry about tokendelta.",
			"requiredAction":    "Apply mitigations per vendor instructions.",
			"dueDate":           "2026-03-22",
			"notes":             "https://example.invalid/kev/" + id,
		})
	}
	b, _ := json.Marshal(map[string]any{
		"title":           "Synthetic KEV Catalog",
		"catalogVersion":  "2026.03.01",
		"count":           len(ids),
		"vulnerabilities": vulns,
	})
	return b
}

// deltaLogDocument renders a delta log naming records.
//
// IT CARRIES THE LINK FIELDS A REAL ONE CARRIES. That is deliberate: the
// security claim is that Anvil never reads them, and a fixture without them
// could not distinguish "never read" from "never present".
func deltaLogDocument(t *testing.T, fetchTime string, updated map[string]string, hostileLinkHost string) []byte {
	t.Helper()
	recs := make([]any, 0, len(updated))
	names := make([]string, 0, len(updated))
	for id := range updated {
		names = append(names, id)
	}
	sort.Strings(names)
	for _, id := range names {
		recs = append(recs, map[string]any{
			"cveId":       id,
			"cveOrgLink":  "https://" + hostileLinkHost + "/cve/" + id,
			"githubLink":  "https://" + hostileLinkHost + "/raw/" + id + ".json",
			"dateUpdated": updated[id],
		})
	}
	b, err := json.Marshal([]any{map[string]any{
		"fetchTime":       fetchTime,
		"numberOfChanges": len(recs),
		"new":             []any{},
		"updated":         recs,
		"error":           []any{},
	}})
	if err != nil {
		t.Fatalf("rendering delta log: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// A Source fixture that RECORDS every request it was asked to make
// ---------------------------------------------------------------------------

// fixtureSource is the injected feed-specific hook. It records every id it was
// handed, so a test can assert not only what was fetched but that nothing else
// was — which is how the "a feed document never chooses a URL" claim is
// checked rather than believed.
type fixtureSource struct {
	deltaLog []byte
	// docs maps a CVE id to the record document served for it.
	docs map[string][]byte
	// asked is every id Record was called with, in order.
	asked []string
	// logCalls counts DeltaLog calls.
	logCalls int
	// noLog makes DeltaLog answer ErrNoDeltaLog, the ordinary answer for a
	// feed whose publisher offers none.
	noLog bool
}

func (f *fixtureSource) DeltaLog(context.Context, config.FeedConfig, poller.PollResult) ([]byte, error) {
	f.logCalls++
	if f.noLog {
		return nil, fmt.Errorf("%w: fixture feed publishes no delta log", ErrNoDeltaLog)
	}
	return f.deltaLog, nil
}

func (f *fixtureSource) Record(_ context.Context, _ config.FeedConfig, id string) ([]byte, error) {
	f.asked = append(f.asked, id)
	doc, ok := f.docs[id]
	if !ok {
		return nil, fmt.Errorf("fixture source has no document for %q", id)
	}
	return doc, nil
}

// TestEveryRouteIsListed keeps the enum and its value list from drifting. A
// Route added without an entry in RouteValues would report Valid() == false
// about itself, which is the kind of quiet inconsistency §6's single-owner rule
// exists to prevent for the record contract's own enums.
func TestEveryRouteIsListed(t *testing.T) {
	seen := map[Route]bool{}
	for _, r := range RouteValues() {
		if !r.Valid() {
			t.Errorf("RouteValues lists %q but Valid rejects it", r)
		}
		if seen[r] {
			t.Errorf("RouteValues lists %q twice", r)
		}
		seen[r] = true
	}
	for _, r := range []Route{"", "rebuild", "Poll", "delta-log"} {
		if r.Valid() {
			t.Errorf("Valid accepted %q", r)
		}
	}
	// Every route a Plan or a SyncStats can carry must be in the list, or a
	// caller switching on it has an arm that never fires.
	for _, r := range []Route{
		RouteNone, RouteDerived, RoutePoll, RouteDeltaLog,
		RouteFeedBody, RouteReconcile, RouteBaseline, RouteGitFetch,
	} {
		if !seen[r] {
			t.Errorf("route %q is reachable but not listed by RouteValues", r)
		}
	}
}

// ---------------------------------------------------------------------------
// (a) The scheduler — every clock comes from the feed row
// ---------------------------------------------------------------------------

// TestDueTakesEveryCadenceFromTheFeedRow varies only the row's numbers and
// asserts the schedule follows them.
//
// It is the consuming half of A.1's rule. feeds_test.go proves the feed table's
// own source carries no cadence literal; this proves the consumer does not
// quietly substitute one when the row says something unusual, which is the
// defect that would make an operator's `interval_seconds: 86400` on a
// constrained host silently not happen.
func TestDueTakesEveryCadenceFromTheFeedRow(t *testing.T) {
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		interval int
		elapsed  time.Duration
		wantDue  bool
	}{
		{"one second short of a fifteen-minute row", 900, 899 * time.Second, false},
		{"exactly a fifteen-minute row", 900, 900 * time.Second, true},
		{"a one-second row polled after two seconds", 1, 2 * time.Second, true},
		{"a ninety-day row polled after a day", 7776000, 24 * time.Hour, false},
		{"a ninety-day row polled after a hundred days", 7776000, 2400 * time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			feed := fixtureFeed("f", "https://example.invalid/f", tc.interval, 0, 0)
			p := Due(feed, base, base.Add(tc.elapsed))
			if p.Due != tc.wantDue {
				t.Fatalf("Due=%v want %v (%s)", p.Due, tc.wantDue, p.Because)
			}
			if p.Interval != time.Duration(tc.interval)*time.Second {
				t.Fatalf("Interval=%s want %ds", p.Interval, tc.interval)
			}
		})
	}

	t.Run("a feed that has never succeeded is always due", func(t *testing.T) {
		feed := fixtureFeed("f", "https://example.invalid/f", 7776000, 0, 0)
		if p := Due(feed, time.Time{}, base); !p.Due {
			t.Fatalf("a feed with no recorded success is not due: %s", p.Because)
		}
	})

	t.Run("a disabled row schedules nothing at all", func(t *testing.T) {
		feed := fixtureFeed("f", "https://example.invalid/f", 900, 86400, 604800)
		feed.Enabled = false
		p := Due(feed, time.Time{}, base)
		if p.Due || p.ReconcileDue || p.BaselineDue {
			t.Fatalf("a disabled row scheduled something: %+v", p)
		}
	})

	t.Run("a derived row is never synced on its own account", func(t *testing.T) {
		feed := fixtureFeed("cisa-vulnrichment", "", 0, 0, 0)
		feed.SyncMechanism = config.SyncDerived
		feed.DerivedFrom = "cvelistv5"
		p := Due(feed, time.Time{}, base)
		if p.Route != RouteDerived || p.Due {
			t.Fatalf("a derived row planned %q due=%v; it arrives inside its carrier's payload", p.Route, p.Due)
		}
	})
}

// TestReconcileAndBaselineAreWindowBoundariesNotElapsedTime is the difference
// between "once a day" and "every 24 hours", and research/06 asks for the
// first: "cvelistV5 end-of-day delta once daily", "full baseline weekly".
//
// An elapsed-time test gets this wrong in the operationally common direction: a
// feed polled at 23:50 and again at 00:10 has elapsed twenty minutes and has
// crossed the day, so the end-of-day pass would never fire on a busy feed.
func TestReconcileAndBaselineAreWindowBoundariesNotElapsedTime(t *testing.T) {
	feed := fixtureFeed("cvelistv5", "https://example.invalid/c", 900, 86400, 604800)

	lateYesterday := time.Date(2026, 8, 9, 23, 50, 0, 0, time.UTC)
	earlyToday := time.Date(2026, 8, 10, 0, 10, 0, 0, time.UTC)
	if p := Due(feed, lateYesterday, earlyToday); !p.ReconcileDue {
		t.Fatalf("20 minutes that cross midnight did not make the daily reconcile due: %+v", p)
	}

	midday := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	lateSameDay := time.Date(2026, 8, 10, 23, 0, 0, 0, time.UTC)
	if p := Due(feed, midday, lateSameDay); p.ReconcileDue {
		t.Fatalf("11 hours inside one day made the daily reconcile due: %+v", p)
	}

	// The weekly baseline uses the same mechanism against a wider window, so
	// eleven hours must not trigger it and eight days must.
	if p := Due(feed, midday, lateSameDay); p.BaselineDue {
		t.Fatalf("11 hours made the weekly baseline due: %+v", p)
	}
	if p := Due(feed, midday, midday.Add(8*24*time.Hour)); !p.BaselineDue {
		t.Fatalf("8 days did not make the weekly baseline due: %+v", p)
	}

	// A row that schedules no such pass never has one due, whatever the clock
	// says. This is the case that would otherwise make every feed in the table
	// run a daily bulk pull.
	plain := fixtureFeed("cisa-kev", "https://example.invalid/k", 900, 0, 0)
	if p := Due(plain, midday, midday.Add(365*24*time.Hour)); p.ReconcileDue || p.BaselineDue {
		t.Fatalf("a row with no reconcile or baseline cadence scheduled one after a year: %+v", p)
	}
}

// TestNoCadenceLiteralIsWrittenInThisPackage is A.1's rule applied to the
// consumer, and it is the assertion A.14's brief names as the defect A.1 has an
// AST test against.
//
// THE SCANNER IS VERIFIED RED against synthetic source in the same run. A
// scanner that found nothing because it was looking for the wrong thing would
// be indistinguishable from a clean tree, and this repository has already
// certified a defect that way once.
func TestNoCadenceLiteralIsWrittenInThisPackage(t *testing.T) {
	// The negative control first: if this does not flag, nothing below means
	// anything.
	const probe = `package probe

import "time"

const pollEvery = 900 * time.Second

func f() time.Duration { return 86400 * time.Second }
`
	if got := scanForCadenceLiterals(t, "probe.go", probe); len(got) < 2 {
		t.Fatalf("the cadence scanner found %d findings in source that contains two; "+
			"it is not measuring what it claims: %v", len(got), got)
	}

	for _, name := range []string{"delta.go", "upsert.go"} {
		src, err := readSource(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if found := scanForCadenceLiterals(t, name, src); len(found) > 0 {
			t.Errorf("%s writes a cadence in Go:\n\t%s\n"+
				"Every cadence lives in the feed table (research/06 Recommendation item 4); a duration "+
				"compiled in here cannot be dialled down by an operator on a constrained host.",
				name, strings.Join(found, "\n\t"))
		}
	}
}

// cadenceSeconds are the values the shipped feed table uses. A literal equal to
// one of them in this package's source is a cadence by any other name.
var cadenceSeconds = map[string]bool{
	"900": true, "3600": true, "7200": true, "21600": true, "86400": true,
	"259200": true, "604800": true, "7776000": true, "15552000": true,
}

// scanForCadenceLiterals reports every place src writes a duration.
func scanForCadenceLiterals(t *testing.T, name, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	var found []string
	timeUnits := map[string]bool{
		"Nanosecond": true, "Microsecond": true, "Millisecond": true,
		"Second": true, "Minute": true, "Hour": true,
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			pkg, ok := e.X.(*ast.Ident)
			if ok && pkg.Name == "time" && timeUnits[e.Sel.Name] {
				found = append(found, fmt.Sprintf("%s: time.%s", fset.Position(e.Pos()), e.Sel.Name))
			}
		case *ast.BasicLit:
			if e.Kind == token.INT && cadenceSeconds[e.Value] {
				found = append(found, fmt.Sprintf("%s: the literal %s is a cadence in the feed table",
					fset.Position(e.Pos()), e.Value))
			}
		}
		return true
	})
	return found
}

// readSource reads one of this package's own source files. Tests run with the
// package directory as the working directory, so the name is enough.
func readSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}

// ---------------------------------------------------------------------------
// (b) The two guards, each verified RED
// ---------------------------------------------------------------------------

// TestStatementAllowlistRefusesEveryFullTableStatement is the guard behind
// A.14's forbidden action, "do not rebuild advisory_fts wholesale on any delta
// batch, regardless of batch size".
//
// It is checked in BOTH directions. A guard that refused everything would pass
// a refusal-only test and would also stop the package working, so the
// allowlisted statements are asserted to be accepted in the same run.
func TestStatementAllowlistRefusesEveryFullTableStatement(t *testing.T) {
	forbidden := []string{
		`DROP TABLE advisory_fts`,
		`DROP TABLE IF EXISTS advisory_fts`,
		`CREATE VIRTUAL TABLE advisory_fts USING fts5(description, references_text)`,
		`INSERT INTO advisory_fts(advisory_fts) VALUES('rebuild')`,
		`INSERT INTO advisory_fts(advisory_fts) VALUES('optimize')`,
		`DELETE FROM advisory_fts`,
		`DELETE FROM advisory`,
		`DELETE FROM affected`,
		`UPDATE advisory SET raw_json = ?`,
		`REPLACE INTO advisory (source, source_id) VALUES (?, ?)`,
		`ALTER TABLE advisory RENAME TO advisory_old`,
		`VACUUM`,
		// Two shapes a denylist of verbs would miss, listed to make the point
		// that this is not a denylist: neither carries DROP, REBUILD or
		// CREATE as a leading verb.
		`  insert   into   advisory_fts(advisory_fts)   values('rebuild')  `,
		`INSERT OR REPLACE INTO advisory_fts (rowid, description, references_text) VALUES (?, ?, ?), (?, ?, ?)`,
	}
	for _, q := range forbidden {
		if err := checkStatement(q); err == nil {
			t.Errorf("the allowlist accepted %q; a delta batch costs one upsert per changed row and "+
				"nothing else", condense(q))
		} else if !strings.Contains(err.Error(), "allowlist") {
			t.Errorf("the refusal of %q does not mention the allowlist: %v", condense(q), err)
		}
	}

	if len(allowedStatements) == 0 {
		t.Fatal("the allowlist is empty, so accepting nothing proves nothing")
	}
	for q, reason := range allowedStatements {
		if err := checkStatement(q); err != nil {
			t.Errorf("the allowlist refuses its own member (%s): %v", reason, err)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("an allowlist entry carries no reason:\n\t%s", condense(q))
		}
	}
}

// TestOnlyACVEIdentifierCrossesFromFeedContentIntoAFetch is the other guard.
//
// The corpus is written to defeat a DENYLIST: traversal in three encodings, a
// scheme, an authority, a null byte, a newline-smuggled header, a homoglyph
// digit, and a name that is a valid CVE id with one extra character. None of
// them is refused by being listed; all of them are refused by not being a CVE
// identifier.
func TestOnlyACVEIdentifierCrossesFromFeedContentIntoAFetch(t *testing.T) {
	hostile := []string{
		"",
		" ",
		"CVE-2024-0001/../../etc/passwd",
		"CVE-2024-0001%2f..%2f..%2fetc%2fpasswd",
		"CVE-2024-0001\\..\\..\\windows\\win.ini",
		"../CVE-2024-0001",
		"https://evil.invalid/CVE-2024-0001.json",
		"//evil.invalid/CVE-2024-0001",
		"file:///etc/passwd",
		"CVE-2024-0001\x00.json",
		"CVE-2024-0001\r\nX-Injected: 1",
		"CVE-2024-0001 ",
		"CVE-2024-0001.json",
		"CVE-2024-٠٠٠١",
		"cve-2024-0001",
		"CVE-24-0001",
		"CVE-2024-",
		"CVE-2024",
		"CVE-2024-0001-2",
		"CVE--2024-0001",
		strings.Repeat("CVE-2024-0001", 500),
	}
	for _, name := range hostile {
		if err := checkRecordName("fixture", name); err == nil {
			t.Errorf("a delta log name %q was accepted as a CVE identifier; only that identifier may "+
				"become a fetch", name)
		}
	}

	// The positive control. A guard that refused everything would pass the
	// loop above and would also stop the deltaLog route working.
	for _, name := range []string{"CVE-2024-0001", "CVE-1999-0001", "CVE-2026-1234567"} {
		if err := checkRecordName("fixture", name); err != nil {
			t.Errorf("a well-formed identifier %q was refused: %v", name, err)
		}
	}
}

// TestADeltaLogHasNowhereToPutAURL is a STRUCTURAL guard.
//
// checkRecordName stops a hostile IDENTIFIER. This stops the other half: a
// later change deciding that following the log's own `githubLink` would be
// convenient. There is no field to put it in, so the change cannot be made by
// accident — it has to add a field, and this test is what fails when it does.
func TestADeltaLogHasNowhereToPutAURL(t *testing.T) {
	want := map[string]bool{"CVEID": true, "DateUpdated": true}
	rt := reflect.TypeOf(DeltaLogRecord{})
	for i := 0; i < rt.NumField(); i++ {
		if !want[rt.Field(i).Name] {
			t.Errorf("DeltaLogRecord carries a field %q. A delta log is written by strangers; the only "+
				"thing that may cross from it into a request is a CVE identifier that passed IsCVEID.",
				rt.Field(i).Name)
		}
	}
	if rt.NumField() != len(want) {
		t.Errorf("DeltaLogRecord has %d fields, want %d", rt.NumField(), len(want))
	}
}

// ---------------------------------------------------------------------------
// (c) A.14's headline validation
// ---------------------------------------------------------------------------

// fullTablePatterns are the statement shapes that must NEVER appear in a delta
// batch's trace. Each is a rebuild of an index whose whole design premise is
// that it never needs one.
var fullTablePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)\bDROP\b`),
	regexp.MustCompile(`(?is)\bCREATE\s+VIRTUAL\s+TABLE\b`),
	regexp.MustCompile(`(?is)\bCREATE\s+TABLE\b`),
	regexp.MustCompile(`(?is)\bALTER\s+TABLE\b`),
	regexp.MustCompile(`(?is)'rebuild'`),
	regexp.MustCompile(`(?is)'optimize'`),
	regexp.MustCompile(`(?is)\bVACUUM\b`),
}

// unscopedFTSDelete matches a delete from the index; the caller then requires
// it to be scoped to one rowid. It is two steps rather than one regex because
// Go's RE2 has no lookahead, and a pattern that pretended to express "delete
// without a rowid clause" would either not compile or quietly match nothing —
// which is the shape of guard this project has already been burned by.
var unscopedFTSDelete = regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+advisory_fts\b`)

var rowidScoped = regexp.MustCompile(`(?is)\bWHERE\s+rowid\s*=\s*\?`)

// TestTwoHundredRowDeltaBatchCostsExactlyTwoHundredUpserts is the number A.14's
// packet asks for, taken from a driver-layer trace.
func TestTwoHundredRowDeltaBatchCostsExactlyTwoHundredUpserts(t *testing.T) {
	const rows = 200
	const feedID = "cvelistv5"

	srv := newFixtureServer(t, []byte(`{"assets":[]}`), "application/json")
	feed := fixtureFeed(feedID, srv.URL+"/releases/latest", 900, 86400, 604800)

	updated := map[string]string{}
	docs := map[string][]byte{}
	for i := range rows {
		id := fmt.Sprintf("CVE-2026-%04d", i)
		updated[id] = "2026-08-09T00:00:00Z"
		docs[id] = cve5Record(id, "2026-08-09T00:00:00Z")
	}
	src := &fixtureSource{
		deltaLog: deltaLogDocument(t, "2026-08-09T00:07:00Z", updated, "evil.invalid"),
		docs:     docs,
	}

	db, trace := openTracedCache(t)
	s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, src,
		func() time.Time { return fixtureClock })

	trace.reset()
	stats, err := s.SyncDelta(t.Context(), feed)
	if err != nil {
		t.Fatalf("SyncDelta: %v (note: %s)", err, stats.Note)
	}
	batchTrace := trace.snapshot()

	if stats.Route != RouteDeltaLog {
		t.Fatalf("route %q, want %q; the delta log is the cheap path and must be preferred", stats.Route, RouteDeltaLog)
	}
	if stats.Batch.Upserts != rows {
		t.Errorf("%d advisory upserts, want %d", stats.Batch.Upserts, rows)
	}
	if stats.Batch.FTSUpserts != rows {
		t.Errorf("%d advisory_fts writes, want %d", stats.Batch.FTSUpserts, rows)
	}

	// The counts above come from the code under test. These come from the
	// driver.
	upserts := countStatement(batchTrace, cache.UpsertAdvisorySQL)
	ftsWrites := countStatement(batchTrace, cache.UpsertAdvisoryFTSSQL)
	if upserts != rows {
		t.Errorf("the driver saw %d UpsertAdvisorySQL statements, want %d", upserts, rows)
	}
	if ftsWrites != rows {
		t.Errorf("the driver saw %d UpsertAdvisoryFTSSQL statements, want %d", ftsWrites, rows)
	}
	assertNoFullTableStatement(t, batchTrace)

	// And the rows are really there.
	if got := countRows(t, db, `SELECT count(*) FROM advisory WHERE source = ?`, feedID); got != rows {
		t.Errorf("%d advisory rows, want %d", got, rows)
	}
	if got := countRows(t, db, `SELECT count(*) FROM advisory_fts`); got != rows {
		t.Errorf("%d advisory_fts rows, want %d", got, rows)
	}
}

// TestFTSStaysQueryConsistentWithAdvisoryAfterABatch is A.14's stop condition.
//
// It is a ROUND TRIP: the text is written through the delta path and then read
// back through a MATCH query joined to `advisory`. It also re-runs the batch
// with changed text, because the failure this catches is not "the index is
// empty" but "the index still matches the OLD text", which is what a
// contentless FTS5 table does without contentless_delete=1 and which no row
// count would reveal.
func TestFTSStaysQueryConsistentWithAdvisoryAfterABatch(t *testing.T) {
	const feedID = "cvelistv5"
	srv := newFixtureServer(t, []byte(`{"assets":[]}`), "application/json")
	feed := fixtureFeed(feedID, srv.URL+"/releases/latest", 900, 0, 0)

	id := "CVE-2026-4242"
	first := map[string]string{id: "2026-08-09T00:00:00Z"}
	src := &fixtureSource{
		deltaLog: deltaLogDocument(t, "2026-08-09T00:07:00Z", first, "evil.invalid"),
		docs:     map[string][]byte{id: cve5Record(id, "2026-08-09T00:00:00Z")},
	}

	db := openPlainCache(t)
	clock := fixtureClock
	s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, src,
		func() time.Time { return clock })

	if _, err := s.SyncDelta(t.Context(), feed); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	// The round trip: find the row through the index, and prove the index's
	// rowid resolves to the right advisory.
	var gotID string
	err := db.QueryRowContext(t.Context(), `
		SELECT a.source_id FROM advisory_fts f
		JOIN advisory a ON a.rowid = f.rowid
		WHERE advisory_fts MATCH ?`, "tokenalpha2026*").Scan(&gotID)
	if err != nil {
		t.Fatalf("the batch's text is not queryable through advisory_fts: %v", err)
	}
	if gotID != id {
		t.Fatalf("MATCH resolved to %q, want %q", gotID, id)
	}

	// Now change the text and re-sync. The old term must stop matching.
	clock = clock.Add(2 * time.Hour)
	changed := cve5Record(id, "2026-08-10T00:00:00Z")
	changed = []byte(strings.ReplaceAll(string(changed), "tokenalpha2026-4242", "tokenomega2026"))
	src.docs[id] = changed
	src.deltaLog = deltaLogDocument(t, "2026-08-10T00:07:00Z",
		map[string]string{id: "2026-08-10T00:00:00Z"}, "evil.invalid")

	if _, err := s.SyncDelta(t.Context(), feed); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if n := ftsHits(t, db, "tokenalpha2026*"); n != 0 {
		t.Errorf("the OLD term still matches %d rows after the record changed; the index was not "+
			"row-scoped-replaced", n)
	}
	if n := ftsHits(t, db, "tokenomega2026"); n != 1 {
		t.Errorf("the NEW term matches %d rows, want 1", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM advisory WHERE source = ?`, feedID); n != 1 {
		t.Errorf("%d advisory rows after two syncs of one record, want 1; the upsert is not keyed on "+
			"(source, source_id)", n)
	}
}

// ---------------------------------------------------------------------------
// (d) The cost model
// ---------------------------------------------------------------------------

// TestTheDeltaLogIsPreferredOverRedownloadingTheCumulativeArchive is A.14's
// second named validation, and it is measured in bytes.
//
// research/06's finding is the whole reason this package exists: the hourly
// delta is CUMULATIVE since the midnight baseline, so re-downloading it every
// poll re-transfers everything already held — "~200 MB/day if polled hourly, vs
// ~17 MB/day if the end-of-day delta is taken once". The fixture reproduces the
// shape at a testable scale: a body that grows with every poll, and a delta log
// that names only what actually changed.
func TestTheDeltaLogIsPreferredOverRedownloadingTheCumulativeArchive(t *testing.T) {
	const feedID = "cvelistv5"

	// A cumulative body that grows on every poll, exactly as the real hourly
	// delta does. Each poll serves a fresh ETag so nothing 304s.
	var cumulativeBytes int64
	polls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		// Every poll carries every record seen so far — the cumulative shape.
		var docs []json.RawMessage
		for i := range polls * 4 {
			docs = append(docs, json.RawMessage(osvRecord(i)))
		}
		body, _ := json.Marshal(docs)
		cumulativeBytes += int64(len(body))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", fmt.Sprintf(`"poll-%d"`, polls))
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	feed := fixtureFeed(feedID, srv.URL+"/delta", 900, 0, 0)
	mirror := admittingMirror(t, feed)

	// --- The route WITHOUT a delta log: the body is all there is. ---
	bodyDB := openPlainCache(t)
	bodyClock := fixtureClock
	bodySyncer := newTestSyncer(t, bodyDB, feed, mirror, srv.Client().Transport, nil,
		func() time.Time { return bodyClock })

	var bodyTransfer int64
	for range 4 {
		st, err := bodySyncer.SyncDelta(t.Context(), feed)
		if err != nil {
			t.Fatalf("body-route sync: %v (%s)", err, st.Note)
		}
		if st.Route != RouteFeedBody {
			t.Fatalf("without a Source the route is %q, want %q", st.Route, RouteFeedBody)
		}
		bodyTransfer += st.BodyBytes
		bodyClock = bodyClock.Add(time.Duration(feed.IntervalSeconds) * time.Second)
	}

	// --- The route WITH a delta log: only the changed records move. ---
	changed := map[string]string{
		"CVE-2026-0001": "2026-08-09T00:00:00Z",
		"CVE-2026-0002": "2026-08-09T00:00:00Z",
		"CVE-2026-0003": "2026-08-09T00:00:00Z",
	}
	docs := map[string][]byte{}
	for id, when := range changed {
		docs[id] = cve5Record(id, when)
	}
	src := &fixtureSource{
		deltaLog: deltaLogDocument(t, "2026-08-09T00:07:00Z", changed, "evil.invalid"),
		docs:     docs,
	}

	logDB := openPlainCache(t)
	logClock := fixtureClock
	logSyncer := newTestSyncer(t, logDB, feed, mirror, srv.Client().Transport, src,
		func() time.Time { return logClock })

	var (
		logTransfer  int64
		fetchesFirst int
		fetchesLater int
	)
	for i := range 4 {
		st, err := logSyncer.SyncDelta(t.Context(), feed)
		if err != nil {
			t.Fatalf("delta-log sync %d: %v (%s)", i, err, st.Note)
		}
		if st.Route != RouteDeltaLog {
			t.Fatalf("sync %d took route %q, want %q", i, st.Route, RouteDeltaLog)
		}
		logTransfer += st.RecordBytes
		if i == 0 {
			fetchesFirst = st.RecordFetches
		} else {
			fetchesLater += st.RecordFetches
			if st.NamesUpToDate != len(changed) {
				t.Errorf("sync %d re-fetched records the cache already held: NamesUpToDate=%d want %d",
					i, st.NamesUpToDate, len(changed))
			}
		}
		logClock = logClock.Add(time.Duration(feed.IntervalSeconds) * time.Second)
	}

	if fetchesFirst != len(changed) {
		t.Errorf("the first delta-log sync fetched %d records, want %d", fetchesFirst, len(changed))
	}
	if fetchesLater != 0 {
		t.Errorf("later syncs fetched %d records although the delta log named nothing new; "+
			"the per-record freshness probe is not being consulted", fetchesLater)
	}

	// THE COST MODEL. The delta-log route must transfer strictly and
	// substantially less than re-reading a cumulative body every poll.
	if logTransfer >= bodyTransfer {
		t.Fatalf("the delta-log route transferred %d bytes and the cumulative-body route %d; "+
			"the cheap path is not cheaper", logTransfer, bodyTransfer)
	}
	if logTransfer*4 >= bodyTransfer {
		t.Errorf("the delta-log route transferred %d bytes against the body route's %d — less, but not "+
			"by the margin research/06's cost model describes (a cumulative artifact re-transfers "+
			"everything already held on every poll)", logTransfer, bodyTransfer)
	}

	// And the delta log route never touched the cumulative body at all: the
	// only thing it read from the poll was the fact that something changed.
	if src.logCalls != 4 {
		t.Errorf("the Source was asked for a delta log %d times across 4 syncs", src.logCalls)
	}
}

// TestTheDeltaLogsOwnLinksAreNeverFetched is the security half of the cheap
// path.
//
// The fixture's delta log carries `githubLink` and `cveOrgLink` pointing at a
// host Anvil must never contact, alongside identifiers that are not
// identifiers. Nothing but a well-formed CVE id may reach the Source.
func TestTheDeltaLogsOwnLinksAreNeverFetched(t *testing.T) {
	const feedID = "cvelistv5"
	srv := newFixtureServer(t, []byte(`{"assets":[]}`), "application/json")
	feed := fixtureFeed(feedID, srv.URL+"/releases/latest", 900, 0, 0)

	// A log mixing three good names with five that must never become a fetch.
	log := []any{map[string]any{
		"fetchTime":       "2026-08-09T00:07:00Z",
		"numberOfChanges": 8,
		"updated": []any{
			map[string]any{"cveId": "CVE-2026-0001", "githubLink": "https://evil.invalid/a", "dateUpdated": "2026-08-09T00:00:00Z"},
			map[string]any{"cveId": "https://evil.invalid/x.json", "dateUpdated": "2026-08-09T00:00:00Z"},
			map[string]any{"cveId": "CVE-2026-0002/../../../etc/passwd", "dateUpdated": "2026-08-09T00:00:00Z"},
			map[string]any{"cveId": "CVE-2026-0002", "githubLink": "https://evil.invalid/b", "dateUpdated": "2026-08-09T00:00:00Z"},
			map[string]any{"cveId": "//evil.invalid/c", "dateUpdated": "2026-08-09T00:00:00Z"},
			map[string]any{"cveId": "", "dateUpdated": "2026-08-09T00:00:00Z"},
			map[string]any{"cveId": "CVE-2026-0003", "cveOrgLink": "https://evil.invalid/d", "dateUpdated": "2026-08-09T00:00:00Z"},
			map[string]any{"cveId": "CVE-2026-0003.json", "dateUpdated": "2026-08-09T00:00:00Z"},
		},
	}}
	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("rendering the hostile delta log: %v", err)
	}
	src := &fixtureSource{
		deltaLog: raw,
		docs: map[string][]byte{
			"CVE-2026-0001": cve5Record("CVE-2026-0001", "2026-08-09T00:00:00Z"),
			"CVE-2026-0002": cve5Record("CVE-2026-0002", "2026-08-09T00:00:00Z"),
			"CVE-2026-0003": cve5Record("CVE-2026-0003", "2026-08-09T00:00:00Z"),
		},
	}

	db := openPlainCache(t)
	s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, src,
		func() time.Time { return fixtureClock })

	stats, err := s.SyncDelta(t.Context(), feed)
	if err != nil {
		t.Fatalf("SyncDelta: %v (%s)", err, stats.Note)
	}

	want := []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}
	if !reflect.DeepEqual(src.asked, want) {
		t.Fatalf("the Source was asked for %v, want %v", src.asked, want)
	}
	for _, asked := range src.asked {
		if strings.Contains(asked, "evil.invalid") || strings.ContainsAny(asked, "/\\:") {
			t.Fatalf("a request name %q carries something a CVE identifier cannot", asked)
		}
	}
	if stats.NamesRejected != 5 {
		t.Errorf("NamesRejected=%d, want 5; a name the guard drops must be counted, not silently "+
			"discarded — a delta log whose names stopped parsing is how a cache quietly stops moving",
			stats.NamesRejected)
	}
	if stats.NamesSeen != 8 {
		t.Errorf("NamesSeen=%d, want 8", stats.NamesSeen)
	}
}

// ---------------------------------------------------------------------------
// (e) Cross-producer conformance with A.8
// ---------------------------------------------------------------------------

// TestDeltaAndBootstrapDecodeTheSameBytesIntoTheSameRows is the guard on the
// duplication between the two importers.
//
// WHAT IT GUARDED, AND WHAT IT GUARDS NOW. It was written when
// internal/ingest/bootstrap's decoders were unexported and this package had
// re-derived them: two DECODERS for one wire format, which A.21 ended by
// extracting internal/ingest/decode (orchestrator ruling G11). Decoding is now
// one implementation and a decoder divergence is no longer expressible, so
// this test could have become tautological — a test that cannot fail is worse
// than no test.
//
// IT DID NOT. The two WRITE PATHS are still two: bootstrap's writer binds
// cache.UpsertAdvisorySQL from its own staleness, tombstone and licence-column
// derivation, and delta's writeRecord binds the same statement from its own.
// Those are the halves that can still drift, and a divergence in either still
// makes A.15's weekly self-heal restore the same rows forever with nothing
// surfacing why. Verified RED at extraction time: perturbing one bound column
// in bootstrap's writer fails this test on every row.
//
// The fixture documents are written in THIS file and handed to both importers.
// Neither writer's output is the other's expectation, and neither is compared
// against a table derived from itself.
func TestDeltaAndBootstrapDecodeTheSameBytesIntoTheSameRows(t *testing.T) {
	const feedID = "conformance"

	// A REJECTED record is in the corpus deliberately. Without one, every
	// comparison below runs over published rows only, and the two writers'
	// handling of a TOMBSTONED advisory — which is where they actually
	// diverged — is never exercised. A cross-producer fixture that contains no
	// instance of the state the producers treat differently is a fixture that
	// cannot fail.
	rejected := bytes.Replace(cve5Record("CVE-2026-0003", "2026-08-09T00:00:00Z"),
		[]byte(`"state":"PUBLISHED"`), []byte(`"state":"REJECTED"`), 1)
	if bytes.Contains(rejected, []byte(`"state":"PUBLISHED"`)) {
		t.Fatal("the rejected fixture still says PUBLISHED; the tombstone half of this test would " +
			"prove nothing")
	}

	members := []zipMember{
		{"cves/CVE-2026-0001.json", cve5Record("CVE-2026-0001", "2026-08-09T00:00:00Z")},
		{"cves/CVE-2026-0003.json", rejected},
		{"osv/GHSA-test-000001.json", osvRecord(1)},
		{"osv/USN-000002-1.json", ubuntuOSVRecord(2)},
		{"kev/known_exploited_vulnerabilities.json", kevCatalogue("CVE-2026-9001", "CVE-2026-9002")},
	}
	archive := buildZip(t, members)

	srv := newFixtureServer(t, archive, "application/zip")
	feed := fixtureFeed(feedID, srv.URL+"/all.zip", 900, 0, 0)
	feed.BootstrapURL = srv.URL + "/all.zip"
	mirror := admittingMirror(t, feed)

	// --- A.8's importer. ---
	bootDB := openPlainCache(t)
	b := &bootstrap.Bootstrapper{
		DB:      bootDB,
		Mirror:  mirror,
		WorkDir: t.TempDir(),
		HTTP:    srv.Client(),
		Clock:   func() time.Time { return fixtureClock },
		Lookup:  func(string) (string, bool) { return fixtureToken, true },
	}
	res, err := b.Bootstrap(t.Context(), feed)
	if err != nil {
		t.Fatalf("bootstrap: %v (refused: %s)", err, res.RefusedBecause)
	}
	if res.RecordsUpserted == 0 {
		t.Fatalf("A.8 imported nothing, so there is nothing to compare against")
	}

	// --- This package's write path over the same bytes. ---
	decision, err := license.Resolve(license.FromFeed(feed, "", mirror))
	if err != nil {
		t.Fatalf("resolving the fixture licence: %v", err)
	}
	deltaDB := openPlainCache(t)
	var batch []Record
	for _, m := range members {
		recs, _, err := Decode(feedID, m.body)
		if err != nil {
			t.Fatalf("delta decoding %s: %v", m.name, err)
		}
		batch = append(batch, recs...)
	}
	if _, err := Apply(t.Context(), deltaDB, feed, decision, batch, fixtureClock, 0); err != nil {
		t.Fatalf("delta Apply: %v", err)
	}

	assertSameAdvisoryRows(t, bootDB, deltaDB)
}

// assertSameAdvisoryRows compares the two caches column by column.
//
// as_of and staleness_seconds are EXCLUDED and the exclusion is stated rather
// than hidden: they record when the import ran and how old the artifact was,
// which are properties of the run and not of the document. Every column that is
// a function of the bytes is compared, including raw_json byte for byte.
func assertSameAdvisoryRows(t *testing.T, a, b *sql.DB) {
	t.Helper()
	const q = `
SELECT source, source_id, ifnull(cve_id,''), ifnull(published,''), ifnull(modified,''),
       state, ifnull(tombstoned_at,''), ifnull(severity,''), ifnull(cvss_vector,''),
       ifnull(cvss_score,-1), ifnull(epss_score,-1), ifnull(epss_as_of,''), kev,
       ifnull(license_spdx,''), ifnull(license_manual_note,''), license_tier, anvil_trust,
       parse_degraded, ifnull(data_version,''), hex(raw_json)
FROM advisory ORDER BY source, source_id`
	left := dumpRows(t, a, q)
	right := dumpRows(t, b, q)
	if len(left) == 0 {
		t.Fatal("the reference cache is empty; the comparison would pass vacuously")
	}
	if len(left) != len(right) {
		t.Fatalf("A.8 wrote %d advisory rows and A.14 wrote %d from the same documents:\nA.8:  %v\nA.14: %v",
			len(left), len(right), rowKeys(left), rowKeys(right))
	}
	for i := range left {
		if left[i] != right[i] {
			t.Errorf("advisory row %d differs between the two importers.\nA.8:  %s\nA.14: %s\n"+
				"Two producers writing one table from one document must agree; a divergence here makes "+
				"A.15's weekly self-heal restore the same rows forever with nothing surfacing why.",
				i, left[i], right[i])
		}
	}

	const affectedQ = `
SELECT source, source_id, ecosystem, package, ifnull(purl,''), ifnull(introduced,''),
       ifnull(fixed,''), distro_backport
FROM affected ORDER BY source, source_id, ecosystem, package, ifnull(introduced,''), ifnull(fixed,'')`
	la, ra := dumpRows(t, a, affectedQ), dumpRows(t, b, affectedQ)
	if !reflect.DeepEqual(la, ra) {
		t.Errorf("the two importers disagree about `affected`:\nA.8:  %v\nA.14: %v", la, ra)
	}

	// advisory_fts IS COMPARED, and it was not until A.21.
	//
	// The omission cost a real divergence: A.8's writer indexed every record
	// including tombstoned ones while A.14's de-indexed them, so a REJECTED
	// advisory stayed searchable on one path and not the other — and A.15's
	// weekly baseline re-runs A.8's path, which would have re-indexed it every
	// week forever. Three columns compared and one not is how a cross-producer
	// guard passes over the producer's actual difference.
	// The query asks whether an index ROW EXISTS, not what it contains.
	// advisory_fts is an EXTERNAL-CONTENT (contentless) FTS5 table: selecting
	// its columns returns NULL by design, so a comparison of column values
	// compares NULL to NULL and passes over any divergence at all.
	const ftsQ = `
SELECT a.source, a.source_id, a.state,
       CASE WHEN f.rowid IS NULL THEN 'not-indexed' ELSE 'indexed' END
FROM advisory a LEFT JOIN advisory_fts f ON f.rowid = a.rowid
ORDER BY a.source, a.source_id`
	lf, rf := dumpRows(t, a, ftsQ), dumpRows(t, b, ftsQ)
	if !reflect.DeepEqual(lf, rf) {
		t.Errorf("the two importers disagree about `advisory_fts`:\nA.8:  %v\nA.14: %v", lf, rf)
	}

	const aliasQ = `SELECT cve_id, source, source_id FROM cve_alias ORDER BY cve_id, source, source_id`
	lc, rc := dumpRows(t, a, aliasQ), dumpRows(t, b, aliasQ)
	if !reflect.DeepEqual(lc, rc) {
		t.Errorf("the two importers disagree about `cve_alias`:\nA.8:  %v\nA.14: %v", lc, rc)
	}
}

// ---------------------------------------------------------------------------
// (f) The refusal paths, which are the ORDINARY paths today
// ---------------------------------------------------------------------------

// TestALicenceRefusalCostsNoRequestAndWritesNoRow is A.7's ordering seen from
// A.14: the gate runs BEFORE the request, so a feed with no acquired licence
// body costs no bytes at all.
//
// This is the state of a fresh clone — internal/ingest/license currently admits
// nothing, because no publisher body has been acquired into mirror/ — so this
// is the path the daemon takes on a real machine today and it must be a clean,
// counted refusal rather than a crash or a partial write.
func TestALicenceRefusalCostsNoRequestAndWritesNoRow(t *testing.T) {
	const feedID = "cvelistv5"
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	feed := fixtureFeed(feedID, srv.URL+"/x", 900, 0, 0)
	db := openPlainCache(t)
	// An EMPTY mirror: nothing acquired, nothing pinned, nothing admitted.
	s := newTestSyncer(t, db, feed, fstest.MapFS{}, srv.Client().Transport, nil,
		func() time.Time { return fixtureClock })

	stats, err := s.SyncDelta(t.Context(), feed)
	if err == nil {
		t.Fatal("an unlicensed feed synced without error")
	}
	if !stats.Refused {
		t.Errorf("the refusal was not reported as one: %+v", stats)
	}
	if hits != 0 {
		t.Errorf("the server was contacted %d times for a feed the licence gate refuses; the gate runs "+
			"before the request precisely so that no rate-limit budget is spent on bytes that must "+
			"then be discarded", hits)
	}
	if n := countRows(t, db, `SELECT count(*) FROM advisory`); n != 0 {
		t.Errorf("%d advisory rows were written under a refused licence", n)
	}
	if stats.Note == "" {
		t.Error("a refusal carried no operator-readable note")
	}
}

// TestANotModifiedResponseWritesNothing is the A.2 cache's exit criterion 3
// seen from the delta path.
func TestANotModifiedResponseWritesNothing(t *testing.T) {
	const feedID = "cisa-kev"
	body := kevCatalogue("CVE-2026-9001")
	serve := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"kev-1"`)
		if serve == http.StatusNotModified {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	feed := fixtureFeed(feedID, srv.URL+"/kev.json", 900, 0, 0)
	db, trace := openTracedCache(t)
	clock := fixtureClock
	s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, nil,
		func() time.Time { return clock })

	if st, err := s.SyncDelta(t.Context(), feed); err != nil {
		t.Fatalf("first sync: %v (%s)", err, st.Note)
	} else if st.Batch.Upserts != 1 {
		t.Fatalf("the first sync wrote %d rows, want 1", st.Batch.Upserts)
	}

	before := snapshotAdvisories(t, db)
	serve = http.StatusNotModified
	clock = clock.Add(time.Duration(feed.IntervalSeconds) * time.Second)
	trace.reset()

	st, err := s.SyncDelta(t.Context(), feed)
	if err != nil {
		t.Fatalf("the 304 sync failed: %v (%s)", err, st.Note)
	}
	if st.PollStatus != poller.StatusNotModified {
		t.Fatalf("poll status %q, want %q", st.PollStatus, poller.StatusNotModified)
	}
	if st.Batch.Upserts != 0 || st.Batch.FTSUpserts != 0 {
		t.Errorf("a 304 wrote %d advisory and %d FTS rows", st.Batch.Upserts, st.Batch.FTSUpserts)
	}
	if after := snapshotAdvisories(t, db); !reflect.DeepEqual(before, after) {
		t.Errorf("a 304 changed `advisory`:\nbefore: %v\nafter:  %v", before, after)
	}
	if n := countStatement(trace.snapshot(), cache.UpsertAdvisorySQL); n != 0 {
		t.Errorf("the driver saw %d advisory upserts on a 304", n)
	}
}

// TestDelegatedRoutesRefuseLoudly checks the three routes this package plans
// and does not run.
//
// A route that quietly did nothing would look exactly like a route that
// succeeded, and the feed would stop moving with nothing to see. Each refusal
// must carry a named sentinel and a sentence.
func TestDelegatedRoutesRefuseLoudly(t *testing.T) {
	db := openPlainCache(t)
	srv := newFixtureServer(t, []byte(`{}`), "application/json")

	t.Run("git_blobless_fetch", func(t *testing.T) {
		feed := fixtureFeed("ghsa", "https://github.invalid/github/advisory-database", 3600, 0, 0)
		feed.SyncMechanism = config.SyncGitBloblessFetch
		feed.BootstrapMechanism = config.BootstrapBloblessClone
		s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, nil,
			func() time.Time { return fixtureClock })
		st, err := s.SyncDelta(t.Context(), feed)
		if err == nil {
			t.Fatal("the git-fetch route ran")
		}
		if !isDeltaError(err, ErrDelegated) {
			t.Errorf("the refusal does not satisfy ErrDelegated: %v", err)
		}
		if !st.Delegated || st.Note == "" {
			t.Errorf("the delegation was not reported: %+v", st)
		}
	})

	t.Run("reconcile without a Reconciler", func(t *testing.T) {
		feed := fixtureFeed("cvelistv5", srv.URL+"/r", 900, 86400, 604800)
		s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, nil,
			func() time.Time { return fixtureClock })
		st, err := s.SyncReconcile(t.Context(), feed)
		if err == nil {
			t.Fatal("a due reconciliation pass ran with nothing wired to run it")
		}
		if !isDeltaError(err, ErrNoReconciler) {
			t.Errorf("the refusal does not satisfy ErrNoReconciler: %v", err)
		}
		if !strings.Contains(st.Note, "570") {
			t.Errorf("the note does not say why the route is not defaulted to A.8's importer: %q", st.Note)
		}
	})

	t.Run("reconcile that is not due", func(t *testing.T) {
		feed := fixtureFeed("cisa-kev", srv.URL+"/k", 900, 0, 0)
		s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, nil,
			func() time.Time { return fixtureClock })
		st, err := s.SyncReconcile(t.Context(), feed)
		if err != nil {
			t.Fatalf("a row that schedules no reconciliation pass returned an error: %v", err)
		}
		if !st.Skipped {
			t.Errorf("a row with no reconcile cadence was not skipped: %+v", st)
		}
	})
}

// TestABodyInAnUnreadShapeIsARoutingNoteNotADroppedChange.
//
// CSAF directory listings, per-branch distro secdb files and the EPSS CSV all
// reach the cache through A.8's bulk path. When one of them arrives here the
// correct outcome is a stated routing fact — not a failed sync (which makes a
// correctly-configured feed look broken) and not a silent success (which loses
// the change).
func TestABodyInAnUnreadShapeIsARoutingNoteNotADroppedChange(t *testing.T) {
	const feedID = "epss"
	srv := newFixtureServer(t, []byte("#model_version:v2025.03.14\ncve,epss,percentile\nCVE-2026-0001,0.5,0.9\n"), "text/csv")
	feed := fixtureFeed(feedID, srv.URL+"/epss.csv", 86400, 0, 0)

	db := openPlainCache(t)
	s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, nil,
		func() time.Time { return fixtureClock })

	st, err := s.SyncDelta(t.Context(), feed)
	if err != nil {
		t.Fatalf("an unreadable body failed the sync rather than routing it: %v", err)
	}
	if st.Batch.Upserts != 0 {
		t.Errorf("%d rows were written from a body this path does not decode", st.Batch.Upserts)
	}
	if !strings.Contains(st.Note, "A.8") {
		t.Errorf("the note does not name the path that does handle it: %q", st.Note)
	}
}

// ---------------------------------------------------------------------------
// (g) The write path's own invariants
// ---------------------------------------------------------------------------

// TestApplyRefusesARecordThatSkippedTheSanitizer is the precondition check that
// makes A.3's obligation true for a caller this package cannot see — A.15
// builds Records from its own baseline read and reaches the same statements.
//
// It is verified in both directions in one run: the same record fails with an
// invisible character in its description and succeeds once Decode has been
// through it.
func TestApplyRefusesARecordThatSkippedTheSanitizer(t *testing.T) {
	const feedID = "cvelistv5"
	srv := newFixtureServer(t, []byte(`{}`), "application/json")
	feed := fixtureFeed(feedID, srv.URL+"/x", 900, 0, 0)
	mirror := admittingMirror(t, feed)
	decision, err := license.Resolve(license.FromFeed(feed, "", mirror))
	if err != nil {
		t.Fatalf("resolving the fixture licence: %v", err)
	}
	db := openPlainCache(t)

	// U+200B ZERO WIDTH SPACE, hand-built and never sanitized.
	dirty := Record{
		Source:      feedID,
		SourceID:    "CVE-2026-0001",
		CVEID:       "CVE-2026-0001",
		State:       cache.AdvisoryPublished,
		Description: "a description with a zero\u200bwidth space in it",
		Raw:         []byte(`{"id":"CVE-2026-0001"}`),
	}
	if _, err := Apply(t.Context(), db, feed, decision, []Record{dirty}, fixtureClock, 0); err == nil {
		t.Fatal("a record carrying an unsanitized string reached the write path")
	} else if !isDeltaError(err, ErrUnsanitized) {
		t.Errorf("the refusal does not satisfy ErrUnsanitized: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM advisory`); n != 0 {
		t.Errorf("%d rows survived a refused batch; Apply is one transaction", n)
	}

	// The positive control: the same document through Decode is accepted.
	doc := cve5Record("CVE-2026-0001", "2026-08-09T00:00:00Z")
	recs, _, err := Decode(feedID, doc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, err := Apply(t.Context(), db, feed, decision, recs, fixtureClock, 0); err != nil {
		t.Fatalf("a sanitized record was refused: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM advisory`); n != 1 {
		t.Errorf("%d rows after a clean batch, want 1", n)
	}
}

// TestApplyRefusesAnUnadmittedLicenceDecision. Decision's zero value carries
// Tier 0 — the most permissive tier this system has — so a write path that
// checked nothing would treat "nobody filled this in" as "fully permissive".
func TestApplyRefusesAnUnadmittedLicenceDecision(t *testing.T) {
	db := openPlainCache(t)
	feed := fixtureFeed("cvelistv5", "https://example.invalid/x", 900, 0, 0)
	recs, _, err := Decode(feed.ID, cve5Record("CVE-2026-0001", "2026-08-09T00:00:00Z"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, err := Apply(t.Context(), db, feed, license.Decision{}, recs, fixtureClock, 0); err == nil {
		t.Fatal("the zero licence Decision was accepted; it carries Tier 0, the most permissive tier there is")
	}
	if n := countRows(t, db, `SELECT count(*) FROM advisory`); n != 0 {
		t.Errorf("%d rows were written under a zero Decision", n)
	}
}

// TestATombstonedAdvisoryLeavesTheIndexAndKeepsItsRow is A.2 exit criterion 22
// on the delta path: a REJECTED CVE record is tombstoned, never deleted, so a
// finding that depended on it becomes invalidated rather than vanishing — and
// its text stops matching, so nothing retrieves it as live advice.
func TestATombstonedAdvisoryLeavesTheIndexAndKeepsItsRow(t *testing.T) {
	const feedID = "cvelistv5"
	srv := newFixtureServer(t, []byte(`{}`), "application/json")
	feed := fixtureFeed(feedID, srv.URL+"/x", 900, 0, 0)
	mirror := admittingMirror(t, feed)
	decision, err := license.Resolve(license.FromFeed(feed, "", mirror))
	if err != nil {
		t.Fatalf("resolving the fixture licence: %v", err)
	}
	db := openPlainCache(t)

	live := cve5Record("CVE-2026-0001", "2026-08-09T00:00:00Z")
	recs, _, err := Decode(feedID, live)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, err := Apply(t.Context(), db, feed, decision, recs, fixtureClock, 0); err != nil {
		t.Fatalf("Apply (live): %v", err)
	}
	if n := ftsHits(t, db, "tokenalpha2026*"); n != 1 {
		t.Fatalf("the live advisory matches %d rows, want 1", n)
	}

	rejected := []byte(strings.Replace(string(live), `"state":"PUBLISHED"`, `"state":"REJECTED"`, 1))
	if string(rejected) == string(live) {
		t.Fatal("the fixture's state field did not change; the test would prove nothing")
	}
	recs, _, err = Decode(feedID, rejected)
	if err != nil {
		t.Fatalf("Decode (rejected): %v", err)
	}
	st, err := Apply(t.Context(), db, feed, decision, recs, fixtureClock, 0)
	if err != nil {
		t.Fatalf("Apply (rejected): %v", err)
	}
	if st.Tombstoned != 1 || st.FTSDeletes != 1 {
		t.Errorf("tombstoned=%d ftsDeletes=%d, want 1 and 1", st.Tombstoned, st.FTSDeletes)
	}
	if n := countRows(t, db, `SELECT count(*) FROM advisory WHERE state = 'rejected' AND tombstoned_at IS NOT NULL`); n != 1 {
		t.Errorf("%d tombstoned rows, want 1; a rejected advisory is tombstoned and never deleted", n)
	}
	if n := ftsHits(t, db, "tokenalpha2026*"); n != 0 {
		t.Errorf("a tombstoned advisory still matches %d rows in the index", n)
	}
}

// TestDecodeRefusesADeltaLogHandedToItAsAnAdvisory. A delta log NAMES changes;
// it does not carry them. Decoding one as an advisory would write a row whose
// content is a list of identifiers, which is exactly the kind of quiet garbage
// a shape-sniffing decoder produces if it has no opinion about what it is
// looking at.
func TestDecodeRefusesADeltaLogHandedToItAsAnAdvisory(t *testing.T) {
	log := deltaLogDocument(t, "2026-08-09T00:07:00Z",
		map[string]string{"CVE-2026-0001": "2026-08-09T00:00:00Z"}, "example.invalid")
	// The array form decodes element-wise, so hand it the element.
	var elems []json.RawMessage
	if err := json.Unmarshal(log, &elems); err != nil {
		t.Fatalf("unmarshalling the fixture log: %v", err)
	}
	if _, _, err := Decode("cvelistv5", elems[0]); err == nil {
		t.Fatal("a delta log entry was decoded as an advisory")
	} else if !isDeltaError(err, ErrUnrecognisedShape) {
		t.Errorf("the refusal does not satisfy ErrUnrecognisedShape: %v", err)
	}
}

// TestAZipBodyIsUnpackedIntoItsMembers covers the OSV ecosystem archives, whose
// steady state is a full-file refresh because their publishers document no
// delta mechanism.
func TestAZipBodyIsUnpackedIntoItsMembers(t *testing.T) {
	const feedID = "osv-pypi"
	members := []zipMember{
		{"GHSA-test-000001.json", osvRecord(1)},
		{"GHSA-test-000002.json", osvRecord(2)},
		{"README.txt", []byte("not an advisory")},
	}
	archive := buildZip(t, members)
	srv := newFixtureServer(t, archive, "application/zip")
	feed := fixtureFeed(feedID, srv.URL+"/all.zip", 86400, 0, 0)

	db := openPlainCache(t)
	s := newTestSyncer(t, db, feed, admittingMirror(t, feed), srv.Client().Transport, nil,
		func() time.Time { return fixtureClock })

	st, err := s.SyncDelta(t.Context(), feed)
	if err != nil {
		t.Fatalf("SyncDelta over a zip body: %v (%s)", err, st.Note)
	}
	if st.Route != RouteFeedBody {
		t.Fatalf("route %q, want %q", st.Route, RouteFeedBody)
	}
	// The README is skipped and the two advisories are not. A zip that lost
	// its advisories to a text file beside them would be the silent-drop
	// failure this package exists to avoid.
	if st.Batch.Upserts != 2 {
		t.Fatalf("a two-advisory zip produced %d upserts (note: %s)", st.Batch.Upserts, st.Note)
	}
	if n := countRows(t, db, `SELECT count(*) FROM advisory WHERE source = ?`, feedID); n != 2 {
		t.Errorf("%d advisory rows, want 2", n)
	}
	// The distro-backport column is what defeats the CVE-2023-32681 /
	// RHSA-2023:4520 false-positive class, so a PyPI range must NOT carry it.
	if n := countRows(t, db, `SELECT count(*) FROM affected WHERE distro_backport = 1`); n != 0 {
		t.Errorf("%d PyPI ranges were marked distro_backport", n)
	}
}

// TestADistroOSVRecordCarriesTheBackportFlag is the other half: research/12 §3
// records that a distro backports a fix without moving the upstream version, so
// an upstream range calls a patched package vulnerable. The column only helps
// A.17 if it is actually set.
func TestADistroOSVRecordCarriesTheBackportFlag(t *testing.T) {
	// The row is a tier 0 fixture on purpose. The share-alike QUARANTINE is
	// A.4's own tested territory and needs a share-alike licence BODY to
	// exercise; what is under test here is that a distro's OSV export produces
	// a backported range whatever tier it is admitted at, because the flag is
	// a property of the ecosystem and not of the licence.
	const feedID = "ubuntu-osv-mirror"
	srv := newFixtureServer(t, []byte(`{}`), "application/json")
	feed := fixtureFeed(feedID, srv.URL+"/x", 86400, 0, 0)
	mirror := admittingMirror(t, feed)
	decision, err := license.Resolve(license.FromFeed(feed, "", mirror))
	if err != nil {
		t.Fatalf("resolving the fixture licence: %v", err)
	}

	db := openPlainCache(t)
	recs, _, err := Decode(feedID, ubuntuOSVRecord(2))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, err := Apply(t.Context(), db, feed, decision, recs, fixtureClock, 0); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM affected WHERE distro_backport = 1`); n != 1 {
		t.Errorf("%d backported ranges, want 1", n)
	}
	// The licence columns come from A.4's DECISION, never from the feed row's
	// own claim: a writer that re-read the YAML would launder an unverified
	// assertion into the cache.
	if n := countRows(t, db, `SELECT count(*) FROM advisory WHERE license_tier = ? AND license_spdx = ?`,
		decision.Tier.Int(), decision.EffectiveSPDX); n != 1 {
		t.Errorf("the advisory row does not carry the gate's tier %d and spdx %q",
			decision.Tier.Int(), decision.EffectiveSPDX)
	}
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func assertNoFullTableStatement(t *testing.T, statements []string) {
	t.Helper()
	if len(statements) == 0 {
		t.Fatal("the trace is empty, so 'no full-table statement' would pass vacuously")
	}
	for _, f := range fullTableFindings(statements) {
		t.Errorf("a delta batch issued a full-table statement:\n\t%s\n"+
			"A 200-record delta costs 200 row upserts and NOT a rebuild (internal/ingest/cache), "+
			"and A.14 forbids it regardless of batch size.", f)
	}
}

// fullTableFindings is the detector as a pure function, so its own negative
// control can call it instead of asserting through a testing.T.
func fullTableFindings(statements []string) []string {
	var out []string
	for _, q := range statements {
		one := condense(q)
		for _, re := range fullTablePatterns {
			if re.MatchString(one) {
				out = append(out, re.String()+" :: "+one)
			}
		}
		if unscopedFTSDelete.MatchString(one) && !rowidScoped.MatchString(one) {
			out = append(out, "DELETE FROM advisory_fts not scoped to one rowid :: "+one)
		}
	}
	return out
}

// TestTheFullTableDetectorActuallyDetects is the negative control.
//
// A detector that matched nothing would make every batch look clean, which is
// exactly how a guard passes for years while enforcing nothing.
func TestTheFullTableDetectorActuallyDetects(t *testing.T) {
	corpus := []string{
		`DROP TABLE advisory_fts`,
		`CREATE VIRTUAL TABLE advisory_fts USING fts5(description)`,
		`CREATE TABLE advisory (source TEXT)`,
		`ALTER TABLE advisory RENAME TO x`,
		`INSERT INTO advisory_fts(advisory_fts) VALUES('rebuild')`,
		`INSERT INTO advisory_fts(advisory_fts) VALUES('optimize')`,
		`VACUUM`,
		`DELETE FROM advisory_fts`,
		`DELETE FROM advisory_fts WHERE source = ?`,
	}
	for _, q := range corpus {
		if got := fullTableFindings([]string{q}); len(got) == 0 {
			t.Errorf("the full-table detector accepted %q", q)
		}
	}
	// And it must accept the statements a delta batch really issues, or every
	// test above would be failing for the wrong reason.
	legitimate := []string{
		cache.UpsertAdvisorySQL, cache.UpsertAdvisoryFTSSQL, cache.DeleteAdvisoryFTSSQL,
		insertAffectedSQL, deleteAffectedSQL, insertAliasSQL, deleteAliasSQL,
		selectModifiedSQL, cache.SelectFeedStateSQL, cache.UpsertFeedStateSQL,
	}
	if got := fullTableFindings(legitimate); len(got) > 0 {
		t.Errorf("the full-table detector rejects statements a delta batch legitimately issues: %v", got)
	}
}

func countStatement(statements []string, want string) int {
	n := 0
	target := strings.TrimSpace(want)
	for _, q := range statements {
		if strings.TrimSpace(q) == target {
			n++
		}
	}
	return n
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting (%s): %v", query, err)
	}
	return n
}

func ftsHits(t *testing.T, db *sql.DB, match string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM advisory_fts WHERE advisory_fts MATCH ?`, match).Scan(&n); err != nil {
		t.Fatalf("MATCH %q: %v", match, err)
	}
	return n
}

func snapshotAdvisories(t *testing.T, db *sql.DB) []string {
	t.Helper()
	return dumpRows(t, db, `
SELECT source, source_id, ifnull(cve_id,''), state, ifnull(modified,''), hex(raw_json)
FROM advisory ORDER BY source, source_id`)
}

func dumpRows(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), query)
	if err != nil {
		t.Fatalf("querying (%s): %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan: %v", err)
		}
		parts := make([]string, len(cols))
		for i, v := range vals {
			parts[i] = fmt.Sprintf("%s=%v", cols[i], v)
		}
		out = append(out, strings.Join(parts, " "))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func rowKeys(rows []string) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		fields := strings.Fields(r)
		if len(fields) >= 2 {
			out = append(out, fields[0]+" "+fields[1])
		}
	}
	return out
}

// isDeltaError reports whether err carries the given sentinel AND the
// package-wide one. Both matter: a caller that switches on ErrDelta must not
// have a refusal leak past it wearing a different sentinel.
func isDeltaError(err error, sentinel error) bool {
	return err != nil && errors.Is(err, sentinel) && errors.Is(err, ErrDelta)
}

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// sqlTrace records every statement handed to the driver layer.
//
// It is the same shape internal/ingest/cache's own test uses, and for the same
// reason: "no code path may rebuild the index" is a claim about what reaches
// SQLite, so it is checked at SQLite's door rather than by reading the code
// that was supposed to obey it.
type sqlTrace struct {
	mu         sync.Mutex
	statements []string
}

func (l *sqlTrace) record(q string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.statements = append(l.statements, q)
}

func (l *sqlTrace) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.statements = nil
}

func (l *sqlTrace) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.statements...)
}

// globalTrace is process-wide because a database/sql driver is. The tests that
// read it do not run in parallel, and each resets it immediately before the
// batch it measures.
var globalTrace = &sqlTrace{}

type traceDriver struct{ base driver.Driver }

func (d traceDriver) Open(name string) (driver.Conn, error) {
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return traceConn{Conn: c}, nil
}

// traceConn forwards every statement-carrying method to the real connection
// after recording the text.
type traceConn struct{ driver.Conn }

func (c traceConn) Prepare(query string) (driver.Stmt, error) {
	globalTrace.record(query)
	return c.Conn.Prepare(query)
}

func (c traceConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	globalTrace.record(query)
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, query)
	}
	return c.Conn.Prepare(query)
}

func (c traceConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	globalTrace.record(query)
	e, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return e.ExecContext(ctx, query, args)
}

func (c traceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	globalTrace.record(query)
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

// newFixtureServer serves one body over TLS.
//
// It sends NO ETag and NO Last-Modified, so every poll is unconditional and
// returns 200. The 304 path has its own test, which sets a validator on
// purpose; a shared helper that quietly enabled conditional requests would make
// the other tests pass by never fetching anything.
func newFixtureServer(t *testing.T, body []byte, contentType string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type zipMember struct {
	name string
	body []byte
}

func buildZip(t *testing.T, members []zipMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		w, err := zw.Create(m.name)
		if err != nil {
			t.Fatalf("creating zip member %q: %v", m.name, err)
		}
		if _, err := w.Write(m.body); err != nil {
			t.Fatalf("writing zip member %q: %v", m.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}
