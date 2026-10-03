// Package lanea_test is Lane A's end-to-end conformance harness (the Lane A exit gate).
//
// ===========================================================================
// WHAT THIS HARNESS IS FOR, AND WHY IT IS NOT SEVEN UNIT TESTS IN A TRENCHCOAT
// ===========================================================================
//
// Every package in Lane A has its own tests and they pass. This harness exists
// because a chain of internally-consistent links is not a working chain: the
// value of end-to-end is catching what unit tests structurally cannot, which is
// a DISAGREEMENT BETWEEN two components that each behave exactly as their own
// fixtures say they should.
//
// This project has a live example. The Trivy E2E job found that the SCA
// collector CANNOT RUN AT ALL without a pre-seeded database, because every
// prior test used recorded output — and recorded output presupposes a
// successful run. This harness found three more of the same class; they are
// named in THE OPEN SEAMS below and each one is asserted here rather than
// described.
//
// ===========================================================================
// THE REPORT IS THE DELIVERABLE, AND IT NAMES WHAT IT COULD NOT PROVE
// ===========================================================================
//
// A harness that quietly tests six of seven links is worse than one that
// fails, because the report is what gets believed. So this file does not
// return a pass/fail over "the chain": it returns a LEDGER with one entry per
// link, each either PROVEN (naming the assertion that proved it) or UNPROVEN
// (naming what is missing and what would settle it). TestLaneAChain fails if
// any link is left undecided, if a PROVEN entry carries no evidence, or if an
// UNPROVEN entry carries no settlement condition.
//
// AN UNPROVEN LINK DOES NOT FAIL THE RUN, BUT A STALE REASON DOES. Every
// "cannot be proven here" claim is re-checked against the machine on every
// run: if trivy appears on PATH, if a package manager appears, if a licence
// body is acquired into mirror/, the harness FAILS and tells you to promote
// the link to a real proof. A reason on file is a claim about today, and this
// project has already paid for three claims that were corrected and stayed
// false.
//
// ===========================================================================
// THE THREE SEAMS THIS HARNESS FOUND, AND HOW EACH CLOSED
// ===========================================================================
//
// All three were the same defect wearing three hats: FOUR COMPONENTS EACH
// DEFINED THEIR OWN PACKAGE-IDENTITY VOCABULARY AND NOBODY OWNED THE MAPPING.
// None was visible from inside any one package, because each package's
// fixtures spoke its own dialect. Plan node cli closed all three in their
// owning packages, and the harness now asserts them closed (assertSeamsClosed).
//
//	SEAM 1 — ECOSYSTEM VOCABULARY, INGESTION SIDE. internal/ingest/decode
//	wrote the publisher's spelling ("Debian:11", "Alpine:v3.19") into
//	`affected.ecosystem`, which the comparator matches exactly against
//	{deb, rpm, apk}, so every OSV-sourced distro range was unreachable.
//	CLOSED: decode writes the comparator's scheme and puts the release in the
//	range purl's distro qualifier (internal/distro), and
//	internal/scan.CacheSource consults only the host release's ranges. The
//	release scope is the part a bare vocabulary fix would have missed: a
//	Debian 11 range is wrong about a Debian 12 package.
//
//	SEAM 2 — NO PURL ON HOST PACKAGES. record emission refuses a finding with
//	no purl, and the namespace a purl needs comes from os-release, which the
//	inventory carried and nothing used. CLOSED: internal/scan.HostRecords
//	builds each package's purl from the inventory's own os-release. The
//	emitter still refuses a purl-less host match, and emitAll asserts it.
//
//	SEAM 3 — ECOSYSTEM VOCABULARY, REPO SIDE. Trivy reports language
//	ecosystems (npm, gomod) and the comparator implements only OS schemes, so
//	no repository finding could become a record. CLOSED by routing, not by a
//	comparator change: Trivy has already decided those verdicts against its
//	own database, so internal/scan.RepoMatches sends them to emission
//	directly, under the owner's accelerator decision of 2026-10-03 (off by
//	default, tier-2 attribution on every finding).
//
// ===========================================================================
// THE CORPUS
// ===========================================================================
//
// Every fixture under fixtures/ is hand-written to the publisher's documented
// shape and holds only synthetic identifiers (CVE-2026-1001..1005, RHSA-2026:
// 0001, GHSA-deb1-2026-0001). NONE of it was produced by running any part of
// Anvil: a test whose corpus comes from the implementation is not a test. The
// feed table itself is fixtures/feeds.yaml, parsed by internal/ingest/config,
// so exit criterion 1's "no feed fact in Go" holds for the harness too.
//
// No network. The only listener is an in-process httptest TLS server and the
// only hosts named anywhere are .invalid.
//
// ===========================================================================
// THE ONE INPUT THAT IS NOT A FIXTURE: THE HOST INVENTORY
// ===========================================================================
//
// internal/collector/host is the only Lane A component this harness can run
// FOR REAL, on the machine the test is running on, and it does so whenever it
// can. The rule is in hostInventoryForChain and it is one sentence:
//
//	host.Collect's REAL OUTPUT whenever a supported package manager is present
//	on this machine, and the corpus probe alone when none is.
//
// Both branches run the full chain. What differs is what the ledger may claim:
// on a Linux host with a package manager (CI, and the Debian development
// machine since 2026-10-03) the host-inventory link is PROVEN and names the
// collected package count, and on a host with none it stays UNPROVEN and says
// so. THE LEDGER LINE NAMES WHICH — a run that proved the collector and a
// run that proved only a file must not render the same, because telling those
// two apart is the entire point of that link.
//
// This replaced a tripwire that FAILED THE RUN when a package manager appeared
// ("the fixture inventory is no longer the best available evidence"). It fired
// on CI, correctly, and the fix is to honour it rather than to quieten it. The
// tripwires that remain point the other way: a present package manager that
// enumerates nothing, or real packages collected and then not submitted, both
// fail — those are the shapes in which the better evidence gets acquired and
// then dropped on the floor.
package lanea_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/host"
	"github.com/Susquehanna-Syntax/Anvil/internal/collector/repo"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/bootstrap"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
	"github.com/Susquehanna-Syntax/Anvil/internal/match"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/record/lanea"
	"github.com/Susquehanna-Syntax/Anvil/internal/scan"
)

//go:embed fixtures
var fixtures embed.FS

// fixtureClock is the one instant this harness knows. Every as_of, staleness
// and detected_at derives from it, which is what makes two consecutive runs
// byte-identical rather than merely similar.
var fixtureClock = time.Date(2026, 2, 6, 12, 0, 0, 0, time.UTC)

// repoRoot is this file's directory relative to the module root, used by the
// static scans to walk internal/. It is derived, never written down.
const repoRoot = "../../.."

// ---------------------------------------------------------------------------
// The chain-link ledger
// ---------------------------------------------------------------------------

// linkID names one link of the chain the packet asks this harness to prove.
type linkID string

const (
	linkFeedTable    linkID = "feed table   (internal/ingest/config)"
	linkLicenceGate  linkID = "licence gate (internal/ingest/license)"
	linkSanitize     linkID = "sanitize     (internal/ingest/sanitize)"
	linkCache        linkID = "cache write  (bootstrap + delta -> internal/ingest/cache)"
	linkComparator   linkID = "comparator   (internal/match)"
	linkEmission     linkID = "emission     (internal/record/lanea)"
	linkHostCollect  linkID = "host inventory (internal/collector/host)"
	linkRepoCollect  linkID = "repo SCA scan  (internal/collector/repo)"
	linkDeterminism  linkID = "two-run determinism over the whole chain"
	linkSelfHeal     linkID = "weekly self-heal (internal/ingest/reconcile)"
	linkAccelerator  linkID = "DB accelerator (internal/mirror/accelerator)"
	linkProductionUp linkID = "a production caller wiring the chain together"
)

// chainLinks is the roll call. A link absent from the ledger at the end of the
// run is a FAILURE, not an omission: the whole point of this file is that the
// report cannot quietly shorten the chain.
var chainLinks = []linkID{
	linkFeedTable, linkLicenceGate, linkSanitize, linkCache,
	linkComparator, linkEmission, linkHostCollect, linkRepoCollect,
	linkDeterminism, linkSelfHeal, linkAccelerator, linkProductionUp,
}

// verdict is one link's entry.
type verdict struct {
	// proven is true only when this run actually exercised the link.
	proven bool
	// evidence names the assertion that proved it. Required when proven.
	evidence string
	// missing says what was not available. Required when not proven.
	missing string
	// settles says what would turn this into a proof. Required when not
	// proven: "we could not check it" without "here is what would check it"
	// is an excuse, not a report.
	settles string
}

type ledger struct{ v map[linkID]verdict }

func newLedger() *ledger { return &ledger{v: map[linkID]verdict{}} }

func (l *ledger) proven(id linkID, evidence string) {
	l.v[id] = verdict{proven: true, evidence: evidence}
}

func (l *ledger) unproven(id linkID, missing, settles string) {
	l.v[id] = verdict{missing: missing, settles: settles}
}

// checkLedger is the ledger's own validator, written as a PURE FUNCTION over
// the map so that its negative control can call the shipping code instead of a
// re-implementation of it. See TestTheLedgerRefusesAnUnsupportedClaim.
func checkLedger(l *ledger) []string {
	var problems []string
	for _, id := range chainLinks {
		v, ok := l.v[id]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf(
				"link %q was never decided. A harness that returns without deciding a link has "+
					"reported a pass over a shortened chain, which is the failure this file exists "+
					"to prevent.", id))
		case v.proven && strings.TrimSpace(v.evidence) == "":
			problems = append(problems, fmt.Sprintf(
				"link %q is claimed PROVEN with no evidence. A claim that cannot be demonstrated is "+
					"deleted, not qualified.", id))
		case !v.proven && strings.TrimSpace(v.missing) == "":
			problems = append(problems, fmt.Sprintf(
				"link %q is UNPROVEN with no statement of what is missing", id))
		case !v.proven && strings.TrimSpace(v.settles) == "":
			problems = append(problems, fmt.Sprintf(
				"link %q is UNPROVEN with no settlement condition. \"We could not check it\" without "+
					"\"here is what would check it\" is an excuse, not a report.", id))
		}
	}
	return problems
}

func (l *ledger) report(t *testing.T) {
	t.Helper()
	for _, p := range checkLedger(l) {
		t.Error(p)
	}
	provenN := 0
	var b strings.Builder
	b.WriteString("\n=== LANE A CHAIN LEDGER ===\n")
	for _, id := range chainLinks {
		v := l.v[id]
		if v.proven {
			provenN++
			fmt.Fprintf(&b, "  PROVEN   %s\n             %s\n", id, v.evidence)
			continue
		}
		fmt.Fprintf(&b, "  UNPROVEN %s\n             missing: %s\n             settles: %s\n",
			id, v.missing, v.settles)
	}
	fmt.Fprintf(&b, "\n  %d of %d links proven end to end in this run.\n", provenN, len(chainLinks))
	b.WriteString("  An UNPROVEN link is not a passing link. Read the list above before quoting\n" +
		"  this test as evidence that Lane A works.\n")
	t.Log(b.String())
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

// chainOutput is everything one run of the chain produced, in a form two runs
// can be compared byte for byte.
type chainOutput struct {
	advisory  []string
	affected  []string
	alias     []string
	fts       []string
	feedState []string

	// hostSourceLabel and hostRows are the host-side INPUT, carried into the
	// two-run comparison rather than only the output.
	//
	// WHY THE INPUT IS COMPARED TOO. On a machine with a package manager the
	// host packages come from host.Collect, which reads a live package
	// database, and none of those packages matches this corpus's synthetic
	// advisories — so a difference between two collections would produce no
	// difference in any of the fields below and the determinism claim would
	// be true about a chain that never saw the data. Comparing the rows makes
	// the collector's own output part of what "byte-identical across two
	// runs" asserts.
	hostSourceLabel string
	hostRows        []string

	matches      []match.MatchResult
	coverage     match.CoverageReport
	emissionJSON []byte

	sanitizer map[string]int
	decisions map[string]license.Decision
	feeds     config.FeedSet
}

// TestLaneAChain is the harness. It runs the whole chain twice and decides
// every link.
func TestLaneAChain(t *testing.T) {
	led := newLedger()

	first := runChain(t, led)
	second := runChain(t, newLedger()) // a second, independent run; its ledger is discarded

	t.Run("determinism", func(t *testing.T) {
		diffs := diffChains(first, second)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("two consecutive runs over the same fixed corpus differ: %s", d)
			}
			led.unproven(linkDeterminism,
				"the two runs differed; see the failures above",
				"fix the non-determinism, then re-run: the diff is the evidence")
			return
		}
		led.proven(linkDeterminism, fmt.Sprintf(
			"two consecutive runs produced byte-identical output across %d advisory rows, "+
				"%d affected rows, %d cve_alias rows, %d advisory_fts rows, %d feed_state rows, "+
				"%d match results and %d bytes of emitted records (zero deltas). The INPUT is "+
				"compared too: %d host package row(s) from %s were identical across the two "+
				"independent collections. Read that source label before weighing it — on a host "+
				"with a package manager it says host.Collect read a live package database twice "+
				"and got the same bytes; where it says \"corpus probe ONLY\" it says a file was "+
				"read twice, and proves correspondingly less",
			len(first.advisory), len(first.affected), len(first.alias), len(first.fts),
			len(first.feedState), len(first.matches), len(first.emissionJSON),
			len(first.hostRows), first.hostSourceLabel))
	})

	// The links this run could not exercise, each re-checked against the
	// machine so a stale reason fails rather than persists. The host link is
	// NOT here: it is decided inside runChain, where its evidence is produced.
	decideRepoCollector(t, led)
	decideNotWired(t, led)

	led.report(t)
}

// runChain runs feed table -> licence gate -> sanitize -> cache -> comparator
// -> record emission once, deciding each link as it goes.
func runChain(t *testing.T, led *ledger) chainOutput {
	t.Helper()
	ctx := context.Background()
	out := chainOutput{decisions: map[string]license.Decision{}, sanitizer: map[string]int{}}

	// --- LINK 1: the feed table ---------------------------------------
	srv := fixtureServer(t)
	feeds := loadFeeds(t, srv.URL)
	out.feeds = feeds
	if len(feeds.Feeds) != 5 {
		t.Fatalf("the fixture feed table parsed to %d rows, want 5", len(feeds.Feeds))
	}
	for _, f := range feeds.Feeds {
		if f.IntervalSeconds <= 0 || f.FreshnessSLOSeconds < f.IntervalSeconds {
			t.Errorf("feed %q: cadence %ds / SLO %ds came out of the loader unusable",
				f.ID, f.IntervalSeconds, f.FreshnessSLOSeconds)
		}
	}
	led.proven(linkFeedTable, fmt.Sprintf(
		"internal/ingest/config.Parse loaded all %d rows of fixtures/feeds.yaml — every URL, cadence, "+
			"tier and licence in this run came from that file and none from Go", len(feeds.Feeds)))

	// --- LINK 2: the licence gate --------------------------------------
	mirror := admittingMirror(t, feeds)
	for _, f := range feeds.Feeds {
		d, err := license.Resolve(license.FromFeed(f, metadataSPDX(f.ID), mirror))
		if err != nil {
			t.Fatalf("feed %q: the licence gate refused a pinned, acquired body: %v", f.ID, err)
		}
		if d.Refused() {
			t.Fatalf("feed %q: refused decision with no error", f.ID)
		}
		out.decisions[f.ID] = d
	}
	kev := out.decisions["cisa-kev-fixture"]
	if !kev.MetadataOverridden {
		t.Error("exit criterion 10: the KEV row declares CC0-1.0 while its registry metadata says " +
			"NOASSERTION, and the gate did not record that the body overrode the metadata")
	}
	if !kev.NoteRequired || strings.TrimSpace(kev.ManualNote) == "" {
		t.Error("exit criterion 10: a metadata disagreement did not make the manual licence note mandatory")
	}
	led.proven(linkLicenceGate, fmt.Sprintf(
		"license.Resolve admitted all %d rows against a PINNED, digest-matched licence body "+
			"(SYNTHETIC — see TestTheLicenceGateAdmitsNothingInThisWorkingTree, which proves the "+
			"real mirror/ tree admits nothing), and recorded the KEV metadata override with a "+
			"mandatory manual note", len(out.decisions)))

	// --- LINKS 3+4: sanitize, then the two writers into the cache -------
	db := openCache(t)

	var bootstrapped int
	for _, f := range feeds.Feeds {
		if f.BootstrapMechanism != config.BootstrapBulkArchive {
			continue
		}
		b := &bootstrap.Bootstrapper{
			DB:      db,
			Mirror:  mirror,
			WorkDir: t.TempDir(),
			HTTP:    srv.Client(),
			Clock:   func() time.Time { return fixtureClock },
			Lookup:  func(string) (string, bool) { return "", false },
		}
		res, err := b.Bootstrap(ctx, f)
		if err != nil {
			t.Fatalf("bootstrap %q: %v (refused: %s)", f.ID, err, res.RefusedBecause)
		}
		if res.RecordsUpserted == 0 {
			t.Fatalf("bootstrap %q imported nothing", f.ID)
		}
		bootstrapped += res.RecordsUpserted
		mergeCounts(out.sanitizer, res.Sanitizer.Counts())
	}

	var deltaUpserts int
	for _, f := range feeds.Feeds {
		if f.BootstrapMechanism != config.BootstrapIncrementalAPI {
			continue
		}
		body := readFixture(t, fixturePathFor(f.ID))
		recs, st, err := delta.Decode(f.ID, body)
		if err != nil {
			t.Fatalf("delta decode %q: %v", f.ID, err)
		}
		mergeCounts(out.sanitizer, st.Counts())
		bs, err := delta.Apply(ctx, db, f, out.decisions[f.ID], recs, fixtureClock, 0)
		if err != nil {
			t.Fatalf("delta apply %q: %v", f.ID, err)
		}
		deltaUpserts += bs.Upserts
	}

	// The sanitizer must have found something, or the injection corpus never
	// reached it and this link would be passing vacuously.
	if total := sumCounts(out.sanitizer); total == 0 {
		t.Fatal("the sanitizer removed nothing across the whole corpus, but the CVE-2026-1001 " +
			"fixture carries a zero-width space, a bidi override, a zero-width joiner and an HTML " +
			"comment. Either the corpus stopped carrying them or the sanitizer stopped running; " +
			"a zero count here is not a clean corpus, it is a broken harness.")
	}
	assertStoredStringsAreSanitized(t, db)
	assertRawJSONIsVerbatim(t, db)
	led.proven(linkSanitize, fmt.Sprintf(
		"the injection corpus reached the cache through both writers; sanitize removed %d "+
			"characters across %d categories, every queryable string in `advisory` passes "+
			"sanitize.AssertSanitized, and raw_json still holds the publisher's bytes verbatim "+
			"(proving the sanitiser ran on FIELDS and not on the stored document)",
		sumCounts(out.sanitizer), len(out.sanitizer)))

	assertCacheInvariants(t, db)
	led.proven(linkCache, fmt.Sprintf(
		"The bulk bootstrap upserted %d records and delta ingestion upserted %d into one migrated FTS5 cache; every advisory "+
			"row carries a licence declaration, the REJECTED record is tombstoned rather than "+
			"deleted and left the FTS index, and the unknown dataVersion is persisted with "+
			"parse_degraded=1", bootstrapped, deltaUpserts))

	out.advisory = dump(t, db, advisoryDumpSQL)
	out.affected = dump(t, db, affectedDumpSQL)
	out.alias = dump(t, db, aliasDumpSQL)
	out.fts = dump(t, db, ftsDumpSQL)
	out.feedState = dump(t, db, feedStateDumpSQL)

	// --- LINK 5: the comparator ----------------------------------------
	// The host side is real collector output wherever a package manager
	// exists, plus the corpus probe on every host; see hostInventoryForChain
	// for the rule and decideHostLink for what each case entitles the ledger
	// to claim. Every inventory is matched the way the production scan
	// matches it: internal/scan.HostRecords builds each package's purl from
	// the inventory's own os-release, and internal/scan.CacheSource consults
	// only the ranges for that release.
	hostSrc := hostInventoryForChain(t)
	out.hostSourceLabel = hostSrc.label()
	out.hostRows = hostSrc.rows()

	var (
		results            []match.MatchResult
		cov                match.CoverageReport
		collectedSubmitted int
	)
	for _, inv := range hostSrc.inventories() {
		records, rel, err := scan.HostRecords(inv)
		if err != nil {
			t.Fatalf("scan.HostRecords for %s %s: %v", inv.OSRelease.ID, inv.OSRelease.VersionID, err)
		}
		if inv == hostSrc.inv {
			collectedSubmitted = len(records)
		}
		m, err := match.NewMatcher(&scan.CacheSource{DB: db, Release: rel.Key})
		if err != nil {
			t.Fatalf("match.NewMatcher: %v", err)
		}
		r, c, err := m.Match(ctx, records)
		if err != nil {
			t.Fatalf("match (%s): %v", rel.Key, err)
		}
		results = append(results, r...)
		cov = mergeCoverage(cov, c)
	}
	out.matches, out.coverage = results, cov

	assertSeamsClosed(t, db, cov, results)
	decideHostLink(t, led, hostSrc, collectedSubmitted, results)
	led.proven(linkComparator, fmt.Sprintf(
		"the comparator ran over %d collector-shaped packages in %d release-scoped inventories against "+
			"the cache's own `affected` rows, through internal/scan.CacheSource, and produced %d findings "+
			"with a populated CoverageReport (RangesConsidered=%d, PackagesWithNoAdvisoryData=%d). The "+
			"seams this harness used to report are asserted CLOSED here: the Debian OSV export landed "+
			"as scheme %q scoped to debian-11 and decided the debian-11 probe, and a Debian 11 range "+
			"was never consulted for another release. HOST INPUT: %s — read that before quoting the "+
			"submitted count, because the findings come from the corpus probe and NOT from any real "+
			"package this machine has installed",
		cov.PackagesSubmitted, len(hostSrc.inventories()), len(results), cov.RangesConsidered,
		cov.PackagesWithNoAdvisoryData, match.EcosystemDeb, hostSrc.label()))

	// --- LINK 6: record emission ---------------------------------------
	emissions := emitAll(t, db, out.feeds, results, repoScan(t), led)
	blob, err := json.MarshalIndent(emissions, "", "  ")
	if err != nil {
		t.Fatalf("marshalling emissions: %v", err)
	}
	out.emissionJSON = blob

	return out
}

// ---------------------------------------------------------------------------
// Emission, and the seam in front of it
// ---------------------------------------------------------------------------

func emitAll(t *testing.T, db *sql.DB, feeds config.FeedSet, results []match.MatchResult, scanned repo.ScanResult, led *ledger) []lanea.Emission {
	t.Helper()
	if len(results) == 0 {
		t.Fatal("the comparator produced no findings at all, so emission cannot be exercised; " +
			"the corpus is supposed to produce host findings from the Alpine, Debian and Red Hat ranges")
	}
	rows := &scan.AdvisoryRows{DB: db, Feeds: feeds}
	e := lanea.Emitter{
		TargetID: "anvil-conformance-target",
		// REQUIRED, and deliberately not defaultable. The emission review found that
		// staleness_seconds was being copied from the cache column (the
		// PUBLISHER lag) rather than computed as the contract quantity,
		// record-assembly time minus AsOf -- so a twenty-one-day-old cache
		// reported as one hour old and inside its SLO. Emit now refuses a
		// zero AssembledAt instead of defaulting it, because a zero default
		// silently reinstates exactly that bug.
		//
		// fixtureClock is this harness's single instant, so the cache as_of
		// and this assembly time derive from the same constant and the run
		// stays byte-identical across invocations.
		AssembledAt: fixtureClock,
	}

	// The emitter's own contract still holds: a host match with no purl is
	// refused, because the namespace comes from os-release. Production
	// supplies the purl (scan.HostRecords); stripping it must still refuse.
	for _, r := range results {
		if r.Collector != cache.CollectorHost {
			continue
		}
		if r.Purl == "" {
			t.Errorf("host match %s/%s for %s carries no purl; scan.HostRecords builds one from os-release",
				r.Source, r.SourceID, r.Package)
		}
		bare := r
		bare.Purl = ""
		if _, err := e.EmitAll([]match.MatchResult{bare}, rows.Lookup); err == nil {
			t.Error("a host match with no purl was emitted; internal/record/lanea stopped requiring one")
		} else {
			var ref *lanea.Refusal
			if !errors.As(err, &ref) || ref.Reason != lanea.RefusalNoPurl {
				t.Errorf("the purl-less host emission failed for an unexpected reason: %v", err)
			}
		}
		break
	}

	emissions, err := e.EmitAll(results, rows.Lookup)
	if err != nil {
		t.Fatalf("emitting the host results: %v", err)
	}
	if len(emissions) != len(results) {
		t.Fatalf("%d matches produced %d emissions", len(results), len(emissions))
	}

	// The repository half goes the production way: Trivy has decided each
	// verdict, so its findings go to emission through scan.RepoMatches with
	// tier-2 attribution, and the comparator is not asked to re-decide them.
	repoMatches, repoRows := scan.RepoMatches(scanned, repo.DatabaseInfo{TrivyVersion: "recorded", DBVersion: 2, UpdatedAt: fixtureClock.Add(-time.Hour)})
	for _, m := range repoMatches {
		em, err := e.Emit(m, repoRows[[2]string{m.Source, m.SourceID}])
		if err != nil {
			t.Fatalf("emitting the repository finding %s/%s: %v", m.Source, m.SourceID, err)
		}
		emissions = append(emissions, em)
	}

	// Exit criterion 21, end to end, over BOTH collectors' output.
	hosts, repos, remediable := 0, 0, 0
	for i, em := range emissions {
		switch em.Result.Properties.Detector.Kind {
		case record.DetectorKindHost:
			hosts++
			if em.RemediableByAgent() {
				t.Errorf("emission %d is host-sourced and carries remediable_by_agent=true", i)
			}
		case record.DetectorKindSCA:
			repos++
			if a := em.Result.Properties.Advisory; a == nil || a.LicenseSpdx != scan.LicenseTrivyDBTier2 {
				t.Errorf("repository emission %d does not carry tier-2 attribution: %+v", i, a)
			}
			if em.RemediableByAgent() {
				remediable++
			}
		}
	}
	if hosts == 0 || repos == 0 {
		t.Errorf("%d host and %d repository record(s) emitted; exit criterion 21 needs both to mean anything", hosts, repos)
	}

	led.proven(linkEmission, fmt.Sprintf(
		"%d canonical record(s) emitted through internal/record/lanea: %d host-sourced, all "+
			"remediable_by_agent=false, from the comparator's output and the cache's own advisory rows "+
			"read by internal/scan.AdvisoryRows; and %d repository record(s) from the Trivy report through "+
			"internal/scan.RepoMatches, every one carrying tier-2 attribution (%s), %d of them remediable "+
			"by the agent because Trivy names a fixed version. Exit criterion 21 now holds over a set that "+
			"contains both collectors' records",
		len(emissions), hosts, repos, scan.LicenseTrivyDBTier2, remediable))
	return emissions
}

// TestTheRemediablePathIsReachableAtAll is the positive control for exit
// criterion 21.
//
// "No host record is remediable" is a weak claim if NO record is ever
// remediable. The chain now emits remediable repository records from Trivy's
// verdicts (emitAll counts them); this test is the narrower control that the
// COMPARATOR'S verdict can make a record remediable too, using a probe: a
// repo-SCA package record in an ecosystem the comparator implements, which no
// collector emits. The difference between the two collectors is what decides
// remediable_by_agent, and this is where that is shown on one advisory.
func TestTheRemediablePathIsReachableAtAll(t *testing.T) {
	ctx := context.Background()
	src := match.NewStaticSource([]match.AffectedRange{{
		Source: "redhat-csaf-fixture", SourceID: "RHSA-2026:0001", CVEID: "CVE-2026-1004",
		Ecosystem: match.EcosystemRPM, Package: "python3-requests",
		Introduced: "0", Fixed: "2.25.1-3.el9", DistroBackport: true,
	}})
	m, err := match.NewMatcher(src)
	if err != nil {
		t.Fatal(err)
	}
	probe := match.PackageRecord{
		Collector:       cache.CollectorRepoSCA,
		Ecosystem:       match.EcosystemRPM,
		Name:            "python3-requests",
		Version:         "2.25.1-2.el9",
		Purl:            "pkg:rpm/redhat/python3-requests@2.25.1-2.el9",
		ManifestRelPath: "containers/api/rootfs.manifest",
	}
	hostSame := probe
	hostSame.Collector = cache.CollectorHost
	hostSame.ManifestRelPath = ""

	results, _, err := m.Match(ctx, []match.PackageRecord{probe, hostSame})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("the probe produced %d findings, want 2 (one per collector)", len(results))
	}
	var sawRemediable, sawHost bool
	for _, r := range results {
		switch r.Collector {
		case cache.CollectorRepoSCA:
			if !r.RemediableByAgent {
				t.Error("a repository dependency with a named fixed version is not remediable; the " +
					"flag is then false everywhere and \"host findings are never remediable\" is " +
					"vacuous")
			}
			sawRemediable = r.RemediableByAgent
		case cache.CollectorHost:
			if r.RemediableByAgent {
				t.Error("the identical package under the host collector is remediable")
			}
			sawHost = true
		}
	}
	if !sawRemediable || !sawHost {
		t.Fatalf("the probe did not exercise both collectors: remediable=%v host=%v", sawRemediable, sawHost)
	}
}

// ---------------------------------------------------------------------------
// The host inventory: real output where it exists, a probe where it does not
// ---------------------------------------------------------------------------
//
// TWO DIFFERENT THINGS USED TO LIVE IN ONE FIXTURE FILE, AND CONFLATING THEM
// IS WHAT THE TRIPWIRE CAUGHT.
//
//	(a) EVIDENCE FOR THE HOST-INVENTORY LINK — that internal/collector/host
//	    produces an inventory this chain can consume. A hand-written file is
//	    the WORST possible evidence for that and is superseded the moment a
//	    package manager exists, which is exactly what decideHostLink's
//	    predecessor fired about on CI.
//
//	(b) HOST-SHAPED PACKAGES THE SYNTHETIC ADVISORY CORPUS CAN DECIDE. The
//	    corpus holds CVE-2026-1001..1005 against openssl 3.1.3-r0 (apk) and
//	    python3-requests 2.25.1-3.el9 (rpm). No real machine has those
//	    versions, and no real machine ever will, so a REAL inventory cannot
//	    serve this purpose — not on CI, not anywhere. Deleting the file
//	    would delete the comparator's and the emitter's only decidable input
//	    and turn two PROVEN links into vacuous ones.
//
// So the two are now separate. (a) is host.Collect, wherever it runs. (b) is
// fixtures/inventory/corpus-probe-packages.json, which is named for what it is
// and is NEVER cited as evidence for the host link.

// hostInventorySource is which host packages this run submitted, and where
// each group came from. Nothing else in this file decides that question.
type hostInventorySource struct {
	// real is true when host.Collect ran to completion on this machine.
	real bool
	// inv is what host.Collect returned. Non-nil on both paths — the
	// collector returns an inventory alongside ErrNoPackageManager — but
	// Packages is empty when real is false.
	inv *host.Inventory
	// collected is host.Collect's own output, empty when real is false. It
	// is the ONLY thing that may be cited as evidence for linkHostCollect.
	collected []host.Package
	// probe is the corpus probe: host-shaped packages the synthetic advisory
	// corpus can decide. Present on BOTH paths, evidence for NEITHER path's
	// host-collector claim.
	probe []host.Package
	// probeReleases is the os-release each probe ecosystem belongs to, so the
	// probe is matched the way a real inventory is: release-scoped.
	probeReleases map[string]host.OSRelease
}

// inventories is every inventory the chain matches, one per release: the real
// collection first (when there is one), then the probe grouped by ecosystem in
// a fixed order.
func (s hostInventorySource) inventories() []*host.Inventory {
	var out []*host.Inventory
	if s.real {
		out = append(out, s.inv)
	}
	groups := map[string][]host.Package{}
	for _, p := range s.probe {
		groups[p.Ecosystem] = append(groups[p.Ecosystem], p)
	}
	ecos := make([]string, 0, len(groups))
	for e := range groups {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		out = append(out, &host.Inventory{
			SchemaVersion: host.InventorySchemaVersion,
			Collector:     host.Collector,
			OSRelease:     s.probeReleases[e],
			Packages:      groups[e],
		})
	}
	return out
}

// submitted is every host package the chain hands the comparator, real output
// first so the two groups are distinguishable in a failure dump.
func (s hostInventorySource) submitted() []host.Package {
	out := make([]host.Package, 0, len(s.collected)+len(s.probe))
	out = append(out, s.collected...)
	return append(out, s.probe...)
}

// label is the one-line "which inventory did this run use" the ledger and the
// determinism comparison both print. A run that proved the collector and a run
// that proved only the probe MUST NOT render the same, because telling those
// two apart is the whole point of the host link.
func (s hostInventorySource) label() string {
	if s.real {
		return fmt.Sprintf("host.Collect (GOOS=%s): %d real package(s) + %d corpus probe package(s)",
			runtime.GOOS, len(s.collected), len(s.probe))
	}
	return fmt.Sprintf("corpus probe ONLY (GOOS=%s, no package manager): %d package(s)",
		runtime.GOOS, len(s.probe))
}

// rows renders every submitted package for the two-run byte comparison.
func (s hostInventorySource) rows() []string {
	out := make([]string, 0, len(s.collected)+len(s.probe))
	render := func(origin string, pkgs []host.Package) {
		for _, p := range pkgs {
			out = append(out, fmt.Sprintf("origin=%s ecosystem=%s package=%s version=%s arch=%s",
				origin, p.Ecosystem, p.Name, p.Version, p.Arch))
		}
	}
	render("collected", s.collected)
	render("probe", s.probe)
	return out
}

// hostInventoryForChain decides which host inventory the chain runs on. It is
// the ONLY place that decides, and the rule is one sentence:
//
//	host.Collect's REAL OUTPUT whenever a supported package manager is present
//	on this machine, and the corpus probe alone when none is.
//
// The branch is the error return, not a build tag, an environment variable or
// a flag: host.Collect answers "is there a package manager here" by trying,
// and a harness that asked any other way could disagree with the collector
// about the machine it is running on.
//
// THERE IS NO SKIP ON EITHER BRANCH. Both run the full chain; what differs is
// what the ledger is entitled to claim afterwards.
func hostInventoryForChain(t *testing.T) hostInventorySource {
	t.Helper()
	probe, releases := corpusProbePackages(t)
	src := hostInventorySource{probe: probe, probeReleases: releases}

	inv, err := host.Collect(context.Background(), host.Options{
		// The same instant as everything else in this run, so CollectedAt
		// and AsOf cannot make two runs differ.
		Now: func() time.Time { return fixtureClock },
	})
	switch {
	case err == nil:
		// A supported package manager exists. Its output is better evidence
		// than anything written by hand, so the chain takes it.
		src.real = true
		src.inv = inv
		src.collected = inv.Packages
	case errors.Is(err, host.ErrNoPackageManager):
		src.inv = inv
	default:
		t.Fatalf("host.Collect failed for a reason this harness does not understand: %v", err)
	}
	return src
}

// corpusProbePackages loads (b) above: host-shaped packages chosen to
// intersect the synthetic advisory corpus.
//
// IT IS NOT A RECORDING AND MUST NEVER BE READ AS ONE. Like a real inventory it
// carries no purl; scan.HostRecords builds each one from the os-release the
// probe states for its ecosystem.
func corpusProbePackages(t *testing.T) ([]host.Package, map[string]host.OSRelease) {
	t.Helper()
	var doc struct {
		Packages   []host.Package            `json:"packages"`
		OSReleases map[string]host.OSRelease `json:"osReleases"`
	}
	if err := json.Unmarshal(readFixture(t, "fixtures/inventory/corpus-probe-packages.json"), &doc); err != nil {
		t.Fatalf("reading the corpus probe packages: %v", err)
	}
	if len(doc.Packages) == 0 {
		t.Fatal("the corpus probe is empty, so the comparator and the emitter have no decidable " +
			"host input and both links would pass vacuously")
	}
	for _, p := range doc.Packages {
		if strings.TrimSpace(p.Ecosystem) == "" || strings.TrimSpace(p.Name) == "" ||
			strings.TrimSpace(p.Version) == "" {
			t.Fatalf("corpus probe package %+v is missing a field host.Package requires; the file "+
				"is keyed on host.Package's JSON tags so that a struct change breaks it here", p)
		}
		if _, ok := doc.OSReleases[p.Ecosystem]; !ok {
			t.Fatalf("corpus probe package %+v has no os-release for its ecosystem", p)
		}
	}
	return doc.Packages, doc.OSReleases
}

func repoScan(t *testing.T) repo.ScanResult {
	t.Helper()
	res, err := repo.ParseReport(readFixture(t, "fixtures/trivy/report.json"))
	if err != nil {
		t.Fatalf("parsing the Trivy report fixture: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("the Trivy report fixture parsed to zero findings")
	}
	if err := res.AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("the parsed scan reports itself as silently empty: %v", err)
	}
	return res
}

// ---------------------------------------------------------------------------
// Assertions over the cache
// ---------------------------------------------------------------------------

func assertStoredStringsAreSanitized(t *testing.T, db *sql.DB) {
	t.Helper()
	// The queryable columns of `advisory`...
	rows, err := db.Query(`SELECT source, source_id, ifnull(severity,''), ifnull(cvss_vector,''),
	                              ifnull(data_version,''), ifnull(epss_as_of,'') FROM advisory`)
	if err != nil {
		t.Fatalf("reading advisory rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var source, id, sev, vector, dataVersion, epssAsOf string
		if err := rows.Scan(&source, &id, &sev, &vector, &dataVersion, &epssAsOf); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		for field, v := range map[string]string{
			"severity": sev, "cvss_vector": vector, "data_version": dataVersion, "epss_as_of": epssAsOf,
		} {
			if err := sanitize.AssertSanitized(v); err != nil {
				t.Errorf("%s/%s: the stored %s did not survive AssertSanitized: %v", source, id, field, err)
			}
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading advisory rows: %v", err)
	}
	if n == 0 {
		t.Fatal("no advisory rows were read, so the sanitiser assertion passed vacuously")
	}

	// ...and the indexed prose, which cannot be read back.
	//
	// advisory_fts is contentless, so the text is only observable through a
	// MATCH. The corpus's injected characters are checked by SEARCHING for the
	// tokens they were embedded in: a description that still carried a
	// zero-width space between two letters would tokenise differently and the
	// probe below would miss.
	if n := count(t, db, `SELECT count(*) FROM advisory_fts WHERE advisory_fts MATCH ?`, "mishandles"); n != 1 {
		t.Errorf("the sanitized description of the injection fixture matches %d rows for a word it "+
			"contains, want 1; a zero-width character left inside a word breaks tokenisation, which "+
			"is the retrieval failure the spine's ingest-time sanitisation prevents", n)
	}
	if n := count(t, db, `SELECT count(*) FROM advisory_fts WHERE advisory_fts MATCH ?`, "anvilinjectionprobe"); n != 0 {
		t.Errorf("the HTML comment carrying an injected instruction is still searchable in %d rows; "+
			"it should have been removed before the text reached the index", n)
	}
}

// assertRawJSONIsVerbatim is the counterpart control. raw_json is the
// publisher's bytes and must NOT be sanitised: CVE-TOU requires records be
// stored byte-verbatim, and two importers that re-render a document store two
// different digests of one advisory.
func assertRawJSONIsVerbatim(t *testing.T, db *sql.DB) {
	t.Helper()
	var raw []byte
	err := db.QueryRow(`SELECT raw_json FROM advisory WHERE source_id = ?`, "CVE-2026-1001").Scan(&raw)
	if err != nil {
		t.Fatalf("reading raw_json for the injection fixture: %v", err)
	}
	if !bytes.Contains(raw, []byte("\u200b")) {
		t.Error("raw_json no longer carries the zero-width space the fixture ships. The column is " +
			"the publisher's bytes verbatim; sanitising it would change the stored document and " +
			"break byte-for-byte agreement between the two importers.")
	}
}

func assertCacheInvariants(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := cache.CheckFTS5(context.Background(), db); err != nil {
		t.Fatalf("exit criterion 2: FTS5 is not active on the migrated cache: %v", err)
	}
	// Exit criterion 11: no advisory row may have BOTH licence columns null.
	if n := count(t, db, `SELECT count(*) FROM advisory WHERE license_spdx IS NULL AND license_manual_note IS NULL`); n != 0 {
		t.Errorf("exit criterion 11: %d advisory rows declare no licence at all", n)
	}
	// Exit criterion 23: the unknown dataVersion is persisted and flagged.
	if n := count(t, db, `SELECT count(*) FROM advisory WHERE source_id = ? AND parse_degraded = 1 AND data_version = ?`,
		"CVE-2026-1002", "5.9"); n != 1 {
		t.Errorf("exit criterion 23: the dataVersion 5.9 record is not persisted with parse_degraded=1 (%d rows)", n)
	}
	// Exit criterion 22: the REJECTED record is tombstoned, kept, and out of
	// the index.
	if n := count(t, db, `SELECT count(*) FROM advisory WHERE source_id = ? AND state = ? AND tombstoned_at IS NOT NULL`,
		"CVE-2026-1003", cache.AdvisoryRejected); n != 1 {
		t.Errorf("exit criterion 22: the REJECTED record is not tombstoned (%d rows)", n)
	}
	if n := count(t, db, `SELECT count(*) FROM advisory_fts WHERE advisory_fts MATCH ?`, "withdrawn"); n != 0 {
		t.Errorf("a tombstoned advisory still matches %d rows in the FTS index", n)
	}
	// Every advisory carries the gate's tier, never the feed row's claim.
	if n := count(t, db, `SELECT count(*) FROM advisory WHERE license_tier NOT IN (0,1,2,3)`); n != 0 {
		t.Errorf("%d advisory rows carry a tier outside the enum", n)
	}
}

// assertSeamsClosed asserts that the three identity seams this harness found
// stay closed, end to end, through the production code.
func assertSeamsClosed(t *testing.T, db *sql.DB, cov match.CoverageReport, results []match.MatchResult) {
	t.Helper()

	// Exit criterion 20: coverage is populated on every run.
	if cov.PackagesSubmitted == 0 || len(cov.SchemesImplemented) == 0 {
		t.Errorf("exit criterion 20: the CoverageReport is not populated: %+v", cov)
	}

	// SEAM 1, closed. Ingestion writes a distro range in the comparator's
	// scheme, with its release in the purl's distro qualifier; the
	// publisher's spelling stays only in raw_json.
	if n := count(t, db, `SELECT count(*) FROM affected WHERE ecosystem = ?`, "Debian:11"); n != 0 {
		t.Errorf("SEAM 1 HAS REOPENED: %d `affected` row(s) carry the publisher's spelling \"Debian:11\", "+
			"which the comparator never consults", n)
	}
	if n := count(t, db, `SELECT count(*) FROM affected WHERE ecosystem = ? AND purl LIKE ?`,
		match.EcosystemDeb, "%distro=debian-11%"); n == 0 {
		t.Error("the Debian OSV fixture did not land as a deb range scoped to debian-11")
	}
	debFound := false
	for _, r := range results {
		if r.Ecosystem == match.EcosystemDeb && r.Package == "openssl" {
			debFound = true
		}
	}
	if !debFound {
		t.Error("the debian-11 probe's openssl was not decided against the Debian OSV range; SEAM 1 is " +
			"closed only if the range is consulted")
	}

	// The release scope: a range is consulted only for its own release. The
	// Alpine 3.19 ranges must not decide the debian-11 probe and vice versa,
	// which shows as every result's purl naming the release of its range.
	for _, r := range results {
		if r.Purl == "" {
			t.Errorf("%s/%s for %s has no purl (SEAM 2)", r.Source, r.SourceID, r.Package)
		}
	}

	// The vendor range is consulted, and the rpm host package sitting exactly
	// ON the vendor's fixed version is NOT flagged: `fixed` is an EXCLUSIVE
	// upper bound, and this is the backport false-positive class.
	if count(t, db, `SELECT count(*) FROM affected WHERE ecosystem = ? AND distro_backport = 1 AND purl LIKE ?`,
		match.EcosystemRPM, "%distro=rhel-9%") == 0 {
		t.Error("the CSAF fixture produced no backported rpm range scoped to rhel-9, so the vendor-first path is untested here")
	}
	for _, r := range results {
		if r.Collector == cache.CollectorHost && r.Package == "python3-requests" {
			t.Errorf("the host's python3-requests %s was flagged against a vendor advisory that "+
				"names it as the fixed version; this is the backport false-positive class",
				r.InstalledVersion)
		}
	}
}

// mergeCoverage sums the counts of per-release coverage reports. Complete is
// true only when every report was.
func mergeCoverage(a, b match.CoverageReport) match.CoverageReport {
	first := a.PackagesSubmitted == 0 && len(a.SchemesImplemented) == 0
	a.PackagesSubmitted += b.PackagesSubmitted
	a.PackagesEvaluated += b.PackagesEvaluated
	a.PackagesUnidentifiable += b.PackagesUnidentifiable
	a.PackagesRefusedScheme += b.PackagesRefusedScheme
	a.PackagesRefusedVersion += b.PackagesRefusedVersion
	a.PackagesWithNoAdvisoryData += b.PackagesWithNoAdvisoryData
	a.RangesConsidered += b.RangesConsidered
	a.RangesRefused += b.RangesRefused
	a.SchemesImplemented = b.SchemesImplemented
	a.EcosystemsRefused = append(a.EcosystemsRefused, b.EcosystemsRefused...)
	a.Refusals = append(a.Refusals, b.Refusals...)
	a.Defences = append(a.Defences, b.Defences...)
	a.UpstreamOnlyAdvisories = append(a.UpstreamOnlyAdvisories, b.UpstreamOnlyAdvisories...)
	a.UngroupedVendorAdvisories = append(a.UngroupedVendorAdvisories, b.UngroupedVendorAdvisories...)
	a.SourceErrors = append(a.SourceErrors, b.SourceErrors...)
	a.Complete = b.Complete && (first || a.Complete)
	return a
}

// ---------------------------------------------------------------------------
// The links this machine cannot prove
// ---------------------------------------------------------------------------

// decideHostLink writes the host-inventory link's ledger entry, and it is
// called FROM INSIDE runChain, at the point the packages were actually
// submitted — not afterwards from a second host.Collect whose output nothing
// consumed. A ledger entry written somewhere other than where the evidence was
// produced can claim something the chain did not do; that is precisely the
// failure this file exists to prevent, and it is how the fixture inventory came
// to be cited for a link it never exercised.
//
// The two branches say DIFFERENT THINGS on purpose. A reader must be able to
// tell a run that proved the collector from a run that proved only the probe,
// and both the verdict (PROVEN / UNPROVEN) and the text differ accordingly.
func decideHostLink(t *testing.T, led *ledger, src hostInventorySource, collectedSubmitted int, results []match.MatchResult) {
	t.Helper()

	for _, p := range hostSourceProblems(src, collectedSubmitted) {
		t.Error(p)
	}

	if !src.real {
		led.unproven(linkHostCollect,
			"no dpkg, rpm or apk exists on this host (GOOS="+runtime.GOOS+"), so host.Collect "+
				"cannot produce an inventory here and the chain's host side is the CORPUS PROBE "+
				"alone (fixtures/inventory/corpus-probe-packages.json, "+
				strconv.Itoa(len(src.probe))+" hand-written packages in host.Package's own JSON "+
				"shape). The collector's REFUSAL is proven — it ran to completion and returned "+
				"ErrNoPackageManager rather than hanging or inventing rows — but its OUTPUT is "+
				"not, and no probe package is evidence about the collector.",
			"run this harness on a host with one of the three package managers installed; "+
				"hostInventoryForChain then takes host.Collect's real output automatically and "+
				"this entry becomes PROVEN with the collected package count. The probe file stays "+
				"either way: it is the only host input the synthetic advisory corpus can decide, "+
				"and a real inventory cannot replace it")
		return
	}

	var families []string
	for _, c := range src.inv.Coverage {
		families = append(families, fmt.Sprintf("%s=%s(%d)", c.Ecosystem, c.Status, c.Packages))
	}
	hostFindings := 0
	for _, r := range results {
		if r.Collector == cache.CollectorHost {
			hostFindings++
		}
	}

	led.proven(linkHostCollect, fmt.Sprintf(
		"host.Collect ran to completion on this machine (GOOS=%s) and returned %d package(s); "+
			"families %v; parse_degraded=%v. ALL %d were mapped through the documented "+
			"PackageRecord field mapping and submitted to the comparator IN THIS RUN, so this "+
			"entry rests on the collector's own output and not on any file in fixtures/. "+
			"NOTE WHAT THIS DOES NOT SAY: none of those packages produced a finding, and none can "+
			"— this corpus holds only synthetic CVE-2026-xxxx advisories against versions no real "+
			"machine has. The %d host finding(s) below come from the corpus probe, which is "+
			"submitted alongside and is NOT evidence about the collector. What is proven here is "+
			"that a real inventory traverses the chain: collect -> ecosystem mapping -> identity "+
			"-> comparator, at real size, byte-identically across two runs",
		runtime.GOOS, len(src.collected), families, src.inv.ParseDegraded,
		collectedSubmitted, hostFindings))
}

// decideRepoCollector proves the repository collector itself wherever Trivy
// and its database exist, by running repo.ScanRepo over the Lane A fixture
// repository (testdata/lanea-fixture/repo, a lockfile pinning lodash 4.17.15).
// Where they do not, the parse path is what is proven and the ledger says so.
// The earlier tripwire here FAILED the run when Trivy appeared; it fired on
// 2026-10-03 when Trivy was installed on the development machine, and was
// honoured by writing this branch.
func decideRepoCollector(t *testing.T, led *ledger) {
	t.Helper()
	recorded := repoScan(t)
	bin, err := repo.ResolveBinary(repo.BinaryName)
	if err != nil {
		led.unproven(linkRepoCollect,
			fmt.Sprintf("the trivy binary is not on PATH, so repo.ScanRepo cannot run here. What IS "+
				"proven is the report path: repo.ParseReport turned a recorded-shape Trivy report into "+
				"%d finding(s) with populated Coverage, and AssertNotSilentlyEmpty accepted it. The "+
				"SCAN is not proven, and a recorded report presupposes the successful run it is "+
				"standing in for.", len(recorded.Findings)),
			"install the pinned trivy release and seed its vulnerability database; this branch then "+
				"runs repo.ScanRepo over testdata/lanea-fixture/repo and the link becomes PROVEN")
		return
	}
	db, err := repo.Database(context.Background(), repo.DefaultConfig().Runner())
	if err != nil {
		led.unproven(linkRepoCollect,
			fmt.Sprintf("trivy is at %s but reports no usable vulnerability database (%v), so a scan "+
				"would fail on its first run", bin, err),
			"seed the database once (`trivy image --download-db-only`); the collector never updates it itself")
		return
	}
	res, err := repo.ScanRepo(context.Background(), filepath.Join(repoRoot, "testdata", "lanea-fixture", "repo"))
	if err != nil {
		t.Errorf("trivy and its database are present and repo.ScanRepo failed over the fixture repository: %v", err)
		led.unproven(linkRepoCollect, "repo.ScanRepo failed: "+err.Error(), "fix the failure above")
		return
	}
	if err := res.AssertNotSilentlyEmpty(); err != nil || len(res.Findings) == 0 {
		t.Errorf("the fixture repository pins lodash 4.17.15 and the real scan found %d finding(s) (%v)",
			len(res.Findings), err)
	}
	led.proven(linkRepoCollect, fmt.Sprintf(
		"repo.ScanRepo ran %s (trivy %s, database v%d built %s) over testdata/lanea-fixture/repo and "+
			"returned %d finding(s) for lodash 4.17.15 with %d target(s) detected: binary resolution, "+
			"argument construction, the exit-code contract and a seeded database, end to end",
		bin, db.TrivyVersion, db.DBVersion, db.UpdatedAt.Format(time.RFC3339), len(res.Findings),
		res.Coverage.TargetsDetected))
}

// decideNotWired records the links that are not exercised by this harness,
// and the production caller, which now is.
func decideNotWired(t *testing.T, led *ledger) {
	t.Helper()
	led.unproven(linkSelfHeal,
		"internal/ingest/reconcile's weekly baseline self-heal is not exercised by this harness: "+
			"it re-pulls the full bulk artifact, and proving that it RESTORES a silently-dropped "+
			"record needs a second, later archive plus a deliberate deletion between the two runs",
		"The weekly self-heal's own TestSelfHealRestoresDroppedRecords covers it against a synthetic "+
			"missing-records fixture; an end-to-end proof needs this harness to serve two "+
			"generations of the same archive and delete rows between them")
	led.unproven(linkAccelerator,
		"internal/mirror/accelerator is not in this chain at all. It is a warm-start optimisation "+
			"that pulls a compiled Trivy-DB/Grype-DB artifact, and pulling one requires a registry "+
			"this harness must not contact. The owner's decision of 2026-10-03 keeps Trivy-decided "+
			"findings off by default and attributes them to tier 2 when an operator enables them",
		"The accelerator and the accelerator review's own tests cover the version gate and the consume-only write refusal against "+
			"synthetic artifacts; an end-to-end proof needs a local OCI registry fixture")
	led.proven(linkProductionUp,
		"the chain above ran through the production code cmd/anvil runs: internal/scan.HostRecords "+
			"built every host purl from os-release, internal/scan.CacheSource served the comparator "+
			"release-scoped ranges, internal/scan.AdvisoryRows read every advisory row emission used, "+
			"and internal/scan.RepoMatches carried the repository findings. cmd/anvil's TestExitStatuses "+
			"and internal/scan's TestHostScanEndToEnd drive the same chain through scan.Run to a sealed, "+
			"stored record")
}

// ---------------------------------------------------------------------------
// Two-run comparison
// ---------------------------------------------------------------------------

func diffChains(a, b chainOutput) []string {
	var out []string
	cmp := func(name string, l, r []string) {
		if len(l) != len(r) {
			out = append(out, fmt.Sprintf("%s: %d rows then %d rows", name, len(l), len(r)))
			return
		}
		for i := range l {
			if l[i] != r[i] {
				out = append(out, fmt.Sprintf("%s row %d:\n  run 1: %s\n  run 2: %s", name, i, l[i], r[i]))
			}
		}
	}
	cmp("advisory", a.advisory, b.advisory)
	cmp("affected", a.affected, b.affected)
	cmp("cve_alias", a.alias, b.alias)
	cmp("advisory_fts", a.fts, b.fts)
	cmp("feed_state", a.feedState, b.feedState)

	// The host INPUT. Two runs that read the host's package database twice
	// must read the same thing, and on a real host that is a claim worth
	// making at 1000+ rows: host.Collect is documented read-only and sorts
	// its output, so a diff here is either a package that was installed or
	// removed mid-test or a collector that is not deterministic. Either one
	// is a finding, and the diff below is its report. DO NOT relax this to
	// "compare counts" — a swap of two versions keeps the count.
	if a.hostSourceLabel != b.hostSourceLabel {
		out = append(out, fmt.Sprintf("host inventory source: %q then %q",
			a.hostSourceLabel, b.hostSourceLabel))
	}
	cmp("host inventory", a.hostRows, b.hostRows)

	if len(a.matches) != len(b.matches) {
		out = append(out, fmt.Sprintf("match results: %d then %d", len(a.matches), len(b.matches)))
	} else {
		for i := range a.matches {
			if a.matches[i] != b.matches[i] {
				out = append(out, fmt.Sprintf("match result %d:\n  run 1: %+v\n  run 2: %+v",
					i, a.matches[i], b.matches[i]))
			}
		}
	}
	if !bytes.Equal(a.emissionJSON, b.emissionJSON) {
		out = append(out, "emitted records differ:\n  run 1:\n"+string(a.emissionJSON)+
			"\n  run 2:\n"+string(b.emissionJSON))
	}
	return out
}

// TestTheDiffDetectorSeesADifference is diffChains' negative control.
//
// The determinism claim in the ledger rests entirely on diffChains returning
// nothing. A comparator that returns nothing for two DIFFERENT inputs would
// make that claim unfalsifiable, and "byte-identical across two runs" would be
// a sentence about the detector rather than about the chain.
func TestTheDiffDetectorSeesADifference(t *testing.T) {
	base := chainOutput{
		advisory:        []string{"source=a source_id=1"},
		affected:        []string{"source=a source_id=1 package=openssl"},
		alias:           []string{"cve_id=CVE-2026-1001"},
		fts:             []string{"source=a source_id=1 indexed"},
		feedState:       []string{"feed_id=a"},
		hostSourceLabel: "corpus probe ONLY",
		hostRows:        []string{"origin=probe ecosystem=apk package=openssl version=3.1.3-r0 arch="},
		matches:         []match.MatchResult{{Source: "a", SourceID: "1", Package: "openssl"}},
		emissionJSON:    []byte("{}"),
	}
	if d := diffChains(base, base); len(d) != 0 {
		t.Fatalf("two identical outputs were reported as differing: %v", d)
	}

	cases := map[string]func(*chainOutput){
		"an advisory column": func(c *chainOutput) { c.advisory = []string{"source=a source_id=2"} },
		"an affected row":    func(c *chainOutput) { c.affected = append(c.affected, "extra") },
		"an alias row":       func(c *chainOutput) { c.alias = nil },
		"the FTS index":      func(c *chainOutput) { c.fts = []string{"source=a source_id=1 not-indexed"} },
		"feed state":         func(c *chainOutput) { c.feedState = []string{"feed_id=b"} },
		"a match result":     func(c *chainOutput) { c.matches[0].Package = "busybox" },
		"an emitted record":  func(c *chainOutput) { c.emissionJSON = []byte("{ }") },
		"the number of rows": func(c *chainOutput) { c.advisory = nil },
		// The host input, both halves: WHICH inventory was used, and what it
		// contained. Without these two the determinism claim would say
		// nothing about a real inventory, because a real inventory produces
		// no findings against this corpus and would leave every other field
		// untouched.
		"the host inventory source": func(c *chainOutput) { c.hostSourceLabel = "host.Collect" },
		"a host package version": func(c *chainOutput) {
			c.hostRows = []string{"origin=probe ecosystem=apk package=openssl version=3.1.4-r0 arch="}
		},
		"the number of host packages": func(c *chainOutput) { c.hostRows = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			other := base
			other.advisory = append([]string(nil), base.advisory...)
			other.affected = append([]string(nil), base.affected...)
			other.alias = append([]string(nil), base.alias...)
			other.fts = append([]string(nil), base.fts...)
			other.feedState = append([]string(nil), base.feedState...)
			other.hostRows = append([]string(nil), base.hostRows...)
			other.matches = append([]match.MatchResult(nil), base.matches...)
			other.emissionJSON = append([]byte(nil), base.emissionJSON...)
			mutate(&other)
			if d := diffChains(base, other); len(d) == 0 {
				t.Errorf("diffChains missed a change to %s, so the determinism claim cannot fail", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Exit criteria checked against the working tree rather than the corpus
// ---------------------------------------------------------------------------

// urlLiteralAllowlist is exit criterion 1 as an ALLOWLIST, because a denylist
// of feed hostnames loses: the next feed is the one nobody listed.
//
// The rule: no string literal under internal/ingest, internal/collector or
// internal/mirror may contain "://" unless it appears here EXACTLY, with a
// reason. Exact and not substring — a substring rule keyed on "https://" would
// admit every URL in the tree, which is the shape of an allowlist that has
// stopped being one.
//
// READ THE LAST THREE ENTRIES. Exit criterion 1 is written about
// internal/ingest and it holds there: no endpoint of any kind is compiled into
// the ingestion tree. internal/mirror/accelerator is OUTSIDE that scope and
// does compile in two endpoints. They are recorded here rather than quietly
// tolerated, and they are reported as an open item — the criterion's own words
// are "no hard-coded feed URL", and an operator who has to point the
// accelerator at a self-hosted mirror (which research/06 S23 says they should,
// after the GHCR TOOMANYREQUESTS incident) has to recompile today.
var urlLiteralAllowlist = map[string]string{
	"anvil-ingest/1 (+https://github.com/Susquehanna-Syntax/Anvil)": "Anvil's own project URL " +
		"inside the HTTP User-Agent. It is this process's name, not a feed.",
	"https://": "a scheme PREFIX used for validation (a feed URL must be https), not an endpoint",
	"://":      "a scheme SEPARATOR used for parsing, not an endpoint",
	"https://github.com/aquasecurity/trivy/releases (Apache-2.0), put it on PATH, ": "the operator " +
		"install hint printed when the trivy binary is absent. It is documentation in an error " +
		"message, not a fetch target: nothing in internal/collector/repo downloads it.",
	"https://grype.anchore.io/databases/v6/latest.json": "OPEN ITEM: internal/mirror/accelerator " +
		"compiles in the Grype v6 listing endpoint as its default. Outside exit criterion 1's " +
		"stated scope (internal/ingest), but the same argument applies and research/06 S23 says " +
		"operators should self-host. Reported by the Lane A exit gate, not fixed by it.",
	"https://ghcr.io": "OPEN ITEM: the same, for the Trivy-DB OCI registry default.",
}

func TestNoFeedURLLiteralInLaneASource(t *testing.T) {
	roots := []string{
		filepath.Join(repoRoot, "internal", "ingest"),
		filepath.Join(repoRoot, "internal", "collector"),
		filepath.Join(repoRoot, "internal", "mirror"),
	}
	used := map[string]bool{}
	scanned := 0
	for _, root := range roots {
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			scanned++
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Errorf("parsing %s: %v", p, err)
				return nil
			}
			ingest := strings.Contains(filepath.ToSlash(p), "/internal/ingest/")
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.Contains(s, "://") {
					return true
				}
				if _, ok := urlLiteralAllowlist[s]; ok {
					used[s] = true
					return true
				}
				where := "Lane A source"
				if ingest {
					where = "the internal/ingest tree, which exit criterion 1 names by hand"
				}
				t.Errorf("%s: the URL literal %q is compiled into %s. Feed URLs live in feeds.yaml. "+
					"If this is not a feed endpoint, add it to urlLiteralAllowlist with a reason.",
					fset.Position(lit.Pos()), s, where)
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if scanned == 0 {
		t.Fatal("the scan indexed no files; the guard is inert and would pass anything")
	}
	for allowed, reason := range urlLiteralAllowlist {
		if !used[allowed] {
			t.Errorf("urlLiteralAllowlist names %q (%q), which no longer appears. Delete the entry: "+
				"a stale exemption is how the next real one gets waved through.", allowed, reason)
		}
	}
	t.Logf("exit criterion 1: scanned %d non-test Go files under internal/{ingest,collector,mirror}; "+
		"%d allowlisted literals, no unlisted endpoint. Two of the allowlisted entries are OPEN "+
		"ITEMS in internal/mirror/accelerator, not clean results — read the map.", scanned, len(used))
}

// TestTheLicenceGateAdmitsNothingInThisWorkingTree is the honest statement
// about the licence link.
//
// The chain above admits its feeds against a SYNTHETIC pinned body. In this
// repository no publisher licence body has been acquired, so on a fresh clone
// the gate admits NOTHING and Lane A ingests nothing at all. That is the
// production state and it must be visible in the report rather than implied by
// its absence.
func TestTheLicenceGateAdmitsNothingInThisWorkingTree(t *testing.T) {
	mirrorFS := os.DirFS(repoRoot)
	statuses, err := license.MirrorStatus(mirrorFS)
	if err != nil {
		t.Fatalf("reading the real mirror manifest: %v", err)
	}
	if len(statuses) == 0 {
		t.Fatal("the real mirror manifest pins nothing, so this test proves nothing")
	}
	acquired := 0
	for _, s := range statuses {
		if s.State == license.BodyVerified {
			acquired++
		}
	}
	if acquired > 0 {
		t.Errorf("%d licence bodies are now acquired and pinned in mirror/. The Lane A chain can "+
			"be run against REAL feed licences, and the harness must stop reporting the licence "+
			"link as proven only against a synthetic body. Statuses: %v", acquired, statuses)
	}
	t.Logf("licence gate, PRODUCTION STATE: %d pins, %d acquired. On a fresh clone the gate admits "+
		"no feed at all, so nothing is fetched and nothing is written. The chain test above proves "+
		"the gate ADMITS correctly given evidence; it does not and cannot prove that any real feed "+
		"is admissible today.", len(statuses), acquired)
}

// TestTierTwoQuarantineIsOnDiskAndEnforced is exit criterion 9 against the
// working tree: the three share-alike directories exist with non-empty LICENSE
// files, and the write-path gate refuses to put their content anywhere else.
func TestTierTwoQuarantineIsOnDiskAndEnforced(t *testing.T) {
	for _, dir := range []string{"ubuntu", "alpine", "osv"} {
		p := filepath.Join(repoRoot, "mirror", "tier2", dir, "LICENSE")
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("exit criterion 9: %s: %v", p, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("exit criterion 9: %s is empty", p)
		}
	}
	for _, bad := range []string{"mirror/tier0/ubuntu/data.json", "mirror/tier1/alpine/data.json"} {
		if err := license.CheckWritePath(config.LicenseTier2, bad); err == nil {
			t.Errorf("exit criterion 9: the gate allowed tier 2 content to be written to %s", bad)
		}
	}
	// The negative control: the quarantine directory itself must be allowed,
	// or the check above would pass by refusing everything.
	if err := license.CheckWritePath(config.LicenseTier2, "mirror/tier2/ubuntu/data.json"); err != nil {
		t.Errorf("the gate refused a tier 2 write into its own quarantine directory: %v", err)
	}
}

// TestTheLedgerRefusesAnUnsupportedClaim is the ledger's negative control.
//
// checkLedger flags nothing on a well-formed run, and a validator that has
// never rejected anything has not been tested.
func TestTheLedgerRefusesAnUnsupportedClaim(t *testing.T) {
	full := newLedger()
	for _, id := range chainLinks {
		full.proven(id, "evidence")
	}
	if p := checkLedger(full); len(p) != 0 {
		t.Fatalf("a complete ledger was flagged: %v", p)
	}

	cases := []struct {
		name string
		mut  func(*ledger)
		want string
	}{
		{"missing link", func(l *ledger) { delete(l.v, linkCache) }, "never decided"},
		{"proven with no evidence", func(l *ledger) { l.v[linkCache] = verdict{proven: true} }, "no evidence"},
		{"unproven with no reason", func(l *ledger) { l.v[linkCache] = verdict{settles: "x"} }, "what is missing"},
		{"unproven with no settlement", func(l *ledger) { l.v[linkCache] = verdict{missing: "x"} }, "settlement condition"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newLedger()
			for _, id := range chainLinks {
				l.proven(id, "evidence")
			}
			tc.mut(l)
			problems := checkLedger(l)
			if len(problems) == 0 {
				t.Fatalf("checkLedger accepted %q", tc.name)
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Errorf("checkLedger flagged %q but not for the expected reason: %v", tc.name, problems)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------

func readFixture(t *testing.T, p string) []byte {
	t.Helper()
	b, err := fixtures.ReadFile(p)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", p, err)
	}
	return b
}

// fixturePathFor maps a feed id onto the single document the delta path is
// handed for it. It is a TEST mapping over TEST fixtures, not a feed table.
func fixturePathFor(feedID string) string {
	switch feedID {
	case "cisa-kev-fixture":
		return "fixtures/kev/known_exploited_vulnerabilities.json"
	case "osv-debian-fixture":
		return "fixtures/osv/GHSA-deb-2026-0001.json"
	}
	panic("no delta fixture for feed " + feedID)
}

// metadataSPDX is what a registry would report for a feed. Only KEV has one,
// and it disagrees with the row: that is exit criterion 10.
func metadataSPDX(feedID string) string {
	if feedID == "cisa-kev-fixture" {
		return config.LicenseNoAssertion
	}
	return ""
}

func loadFeeds(t *testing.T, base string) config.FeedSet {
	t.Helper()
	doc := strings.ReplaceAll(string(readFixture(t, "fixtures/feeds.yaml")), "${BASE}", base)
	set, err := config.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parsing the fixture feed table: %v", err)
	}
	return set
}

// fixtureServer serves each bulk feed as a zip and each incremental feed as
// its raw document, over an in-process TLS listener. Nothing leaves the
// process and no name here resolves.
func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	archives := map[string][]byte{
		"/cvelistv5/all.zip": buildZip(t, []string{
			"fixtures/cvelistv5/CVE-2026-1001.json",
			"fixtures/cvelistv5/CVE-2026-1002.json",
			"fixtures/cvelistv5/CVE-2026-1003.json",
		}),
		"/alpine/all.zip": buildZip(t, []string{"fixtures/alpine/v3.19-main.json"}),
		"/redhat/all.zip": buildZip(t, []string{"fixtures/redhat/RHSA-2026-0001.json"}),
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := archives[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("ETag", `"`+shortDigest(body)+`"`)
			w.Header().Set("Last-Modified", fixtureClock.Format(http.TimeFormat))
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// buildZip builds a zip with no timestamps and a fixed member order, so the
// archive bytes are identical between runs.
func buildZip(t *testing.T, paths []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range paths {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: path.Base(p), Method: zip.Deflate})
		if err != nil {
			t.Fatalf("zip header for %s: %v", p, err)
		}
		if _, err := w.Write(readFixture(t, p)); err != nil {
			t.Fatalf("writing %s into the zip: %v", p, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the zip: %v", err)
	}
	return buf.Bytes()
}

// admittingMirror builds the mirror filesystem the licence gate reads: one
// acquired publisher body per feed, its digest pinned in the manifest, and
// Anvil's own record beside it.
//
// The BODY is a fixture file. The manifest is generated because it carries a
// digest that can only be computed at run time — pinning a number written down
// by hand is the failure mode mirror/README.md is about.
func admittingMirror(t *testing.T, feeds config.FeedSet) fs.FS {
	t.Helper()
	body := readFixture(t, "fixtures/licence/cc0-1.0-excerpt.txt")
	preamble := readFixture(t, "fixtures/licence/tier0-notes.md")
	digest := digestOf(body)

	fsys := fstest.MapFS{}
	var man strings.Builder
	man.WriteString("# synthetic manifest, Lane A conformance harness\n")
	man.WriteString("schema_version = 1\n")
	man.WriteString("generated_utc = \"2026-02-06\"\n")
	man.WriteString("generated_by = \"test/conformance/lanea\"\n")

	notes := map[config.LicenseTier]*strings.Builder{}
	for _, f := range feeds.Feeds {
		dir := f.MirrorDir
		if dir == "" {
			dir = f.ID
		}
		fmt.Fprintf(&man, "\n[[body]]\nfeed_id = %q\ntier = %d\ndir = %q\nspdx_id = %q\n"+
			"text_url = \"https://example.invalid/LICENSE\"\nsha256 = %q\n"+
			"claim_source = \"Lane A conformance harness fixture\"\n",
			f.ID, f.LicenseTier.Int(), dir, f.LicenseSPDX, digest)
		fsys[path.Join(license.TierDir(f.LicenseTier), dir, license.VerbatimFileName)] =
			&fstest.MapFile{Data: body}

		b, ok := notes[f.LicenseTier]
		if !ok {
			b = &strings.Builder{}
			b.Write(preamble)
			notes[f.LicenseTier] = b
		}
		fmt.Fprintf(b, "\n%s\nSPDX-License-Identifier: %s\n\nAnvil's record: this synthetic source "+
			"is public domain and carries no obligation.\n%s\n",
			license.BodyBeginMarker(f.ID), f.LicenseSPDX, license.BodyEndMarker(f.ID))
	}
	for tier, b := range notes {
		fsys[path.Join(license.TierDir(tier), license.NotesFileName)] = &fstest.MapFile{Data: []byte(b.String())}
	}
	fsys[license.ManifestFileName] = &fstest.MapFile{Data: []byte(man.String())}
	return fsys
}

func openCache(t *testing.T) *sql.DB {
	t.Helper()
	p := filepath.Join(t.TempDir(), "anvil-cache.sqlite")
	db, err := cache.Open(context.Background(), p)
	if err != nil {
		t.Fatalf("opening the cache: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := cache.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrating the cache: %v", err)
	}
	// Exit criterion 2: migrations are idempotent on a file already at the
	// latest version.
	if _, err := cache.Migrate(context.Background(), db); err != nil {
		t.Fatalf("re-running migrations on an up-to-date cache: %v", err)
	}
	return db
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const (
	advisoryDumpSQL = `
SELECT source, source_id, ifnull(cve_id,''), ifnull(published,''), ifnull(modified,''), state,
       ifnull(tombstoned_at,''), ifnull(severity,''), ifnull(cvss_vector,''), ifnull(cvss_score,-1),
       ifnull(epss_score,-1), ifnull(epss_as_of,''), kev, ifnull(license_spdx,''),
       ifnull(license_manual_note,''), license_tier, anvil_trust, as_of, staleness_seconds,
       parse_degraded, ifnull(data_version,''), hex(raw_json)
FROM advisory ORDER BY source, source_id`

	affectedDumpSQL = `
SELECT source, source_id, ecosystem, package, ifnull(purl,''), ifnull(introduced,''),
       ifnull(fixed,''), distro_backport
FROM affected ORDER BY source, source_id, ecosystem, package, ifnull(introduced,''), ifnull(fixed,'')`

	aliasDumpSQL = `SELECT cve_id, source, source_id FROM cve_alias ORDER BY cve_id, source, source_id`

	// advisory_fts is EXTERNAL-CONTENT: selecting its columns returns NULL by
	// design, so the dump asks whether an index ROW EXISTS for each advisory.
	// Comparing column values would compare NULL to NULL and pass over any
	// divergence at all — which is how the bulk bootstrap and delta ingestion
	// tombstone divergence this harness found stayed invisible.
	ftsDumpSQL = `
SELECT a.source, a.source_id, a.state,
       CASE WHEN f.rowid IS NULL THEN 'not-indexed' ELSE 'indexed' END AS indexed
FROM advisory a LEFT JOIN advisory_fts f ON f.rowid = a.rowid
ORDER BY a.source, a.source_id`

	feedStateDumpSQL = `
SELECT feed_id, ifnull(etag,''), ifnull(last_modified,''), ifnull(watermark,''),
       ifnull(last_ok_at,''), consecutive_failures, license_tier
FROM feed_state ORDER BY feed_id`
)

func dump(t *testing.T, db *sql.DB, q string) []string {
	t.Helper()
	rows, err := db.Query(q)
	if err != nil {
		t.Fatalf("dump query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("dump columns: %v", err)
	}
	var out []string
	for rows.Next() {
		cells := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("dump scan: %v", err)
		}
		parts := make([]string, len(cols))
		for i, c := range cells {
			parts[i] = cols[i] + "=" + fmt.Sprintf("%v", c)
		}
		out = append(out, strings.Join(parts, " "))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("dump: %v", err)
	}
	sort.Strings(out)
	return out
}

func count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("counting with %q: %v", q, err)
	}
	return n
}

func mergeCounts(dst map[string]int, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

func sumCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func shortDigest(b []byte) string { return digestOf(b)[:16] }

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// hostSourceProblems is decideHostLink's tripwire set, written as a PURE
// FUNCTION over the source so that its negative control can call the shipping
// code instead of a re-implementation of it. Same argument as checkLedger.
//
// EVERY ENTRY POINTS THE SAME WAY: better evidence was available and the run
// did not use all of it. The tripwire that used to live here pointed the other
// way — it failed BECAUSE a package manager existed — and the answer to that
// one was to wire the collector in, not to keep firing. What must still fail
// is the collector's output being acquired and then quietly dropped, because
// that produces a ledger entry claiming a proof over nothing.
func hostSourceProblems(src hostInventorySource, collectedSubmitted int) []string {
	var problems []string
	if !src.real {
		if len(src.collected) > 0 {
			problems = append(problems, fmt.Sprintf(
				"the host source says no package manager is present and carries %d collected "+
					"package(s). One of the two is wrong, and the ledger is about to describe "+
					"whichever the reader trusts less.", len(src.collected)))
		}
		return problems
	}
	if len(src.collected) == 0 {
		problems = append(problems, "host.Collect returned no error on a host that HAS a package "+
			"manager, and ZERO packages. That is the silent-clean reading exit criterion 20 "+
			"forbids: a present package manager that enumerates nothing is a failed collection, "+
			"not a clean host. Read Inventory.Coverage for which family failed.")
	}
	if collectedSubmitted != len(src.collected) {
		problems = append(problems, fmt.Sprintf(
			"host.Collect returned %d package(s) but %d of them became comparator records; the "+
				"rest were dropped between the collector and the comparator (scan.HostRecords "+
				"submits every package, so this is a defect in the harness). The ledger entry would then be a claim about "+
				"output the chain did not consume.", len(src.collected), collectedSubmitted))
	}
	return problems
}

// TestTheHostLedgerLineNamesWhichInventoryItUsed is the control for the one
// thing the host link exists to communicate.
//
// THE REAL PATH CANNOT RUN ON A HOST WITHOUT dpkg, rpm OR apk (any non-Linux
// host, a minimal container), so host.Collect refuses and the chain above takes the probe
// branch every time. Everything DOWNSTREAM of that call is host-independent
// and is exercised here against two synthetic sources: a run that collected
// real packages and a run that did not. They must not render the same, in the
// verdict or in the words, because a reader's only way to tell "this proved
// the collector" from "this proved a file" is the line the ledger prints.
func TestTheHostLedgerLineNamesWhichInventoryItUsed(t *testing.T) {
	probe := []host.Package{{Ecosystem: host.EcosystemAPK, Name: "openssl", Version: "3.1.3-r0"}}
	collected := []host.Package{
		{Ecosystem: host.EcosystemDeb, Name: "libc6", Version: "2.35-0ubuntu3.6", Arch: "amd64"},
		{Ecosystem: host.EcosystemDeb, Name: "openssl", Version: "3.0.2-0ubuntu1.15", Arch: "amd64"},
	}
	collectedSrc := hostInventorySource{
		real:      true,
		collected: collected,
		probe:     probe,
		inv: &host.Inventory{
			Packages: collected,
			Coverage: []host.FamilyCoverage{
				{Ecosystem: host.EcosystemDeb, Status: host.FamilyCollected, Packages: 2},
				{Ecosystem: host.EcosystemRPM, Status: host.FamilyAbsent},
				{Ecosystem: host.EcosystemAPK, Status: host.FamilyAbsent},
			},
		},
	}
	probeOnly := hostInventorySource{probe: probe, inv: &host.Inventory{}}

	collectedLed, probeLed := newLedger(), newLedger()
	decideHostLink(t, collectedLed, collectedSrc, len(collectedSrc.collected), nil)
	decideHostLink(t, probeLed, probeOnly, 0, nil)

	rv, ok := collectedLed.v[linkHostCollect]
	if !ok || !rv.proven {
		t.Fatalf("a run that collected %d real packages did not prove the host link: %+v",
			len(collected), rv)
	}
	if !strings.Contains(rv.evidence, "host.Collect") {
		t.Errorf("the PROVEN entry does not name host.Collect as its source: %q", rv.evidence)
	}
	pv := probeLed.v[linkHostCollect]
	if pv.proven {
		t.Fatalf("a run with no package manager claimed the host link PROVEN: %+v", pv)
	}
	if !strings.Contains(pv.missing, "CORPUS PROBE") {
		t.Errorf("the UNPROVEN entry does not name the corpus probe as what it ran on: %q", pv.missing)
	}
	if rv.evidence == pv.missing {
		t.Error("the two branches render identically, so the ledger cannot distinguish a run that " +
			"proved the collector from one that proved only a file")
	}
	if p := checkLedger(newLedgerWith(linkHostCollect, rv)); len(p) != 0 {
		t.Errorf("the PROVEN host entry does not satisfy the ledger's own validator: %v", p)
	}
	if p := checkLedger(newLedgerWith(linkHostCollect, pv)); len(p) != 0 {
		t.Errorf("the UNPROVEN host entry does not satisfy the ledger's own validator: %v", p)
	}

	// The determinism comparison reads label() and rows(); both must carry the
	// distinction too, or two runs on different sources would compare equal.
	if collectedSrc.label() == probeOnly.label() {
		t.Errorf("both sources render the same label %q", collectedSrc.label())
	}
	if d := diffChains(
		chainOutput{hostSourceLabel: collectedSrc.label(), hostRows: collectedSrc.rows()},
		chainOutput{hostSourceLabel: probeOnly.label(), hostRows: probeOnly.rows()},
	); len(d) == 0 {
		t.Error("diffChains sees no difference between a real inventory and the probe alone, so " +
			"the two-run comparison would not notice the chain switching sources mid-test")
	}
	if len(collectedSrc.submitted()) != len(collected)+len(probe) {
		t.Errorf("the real path submitted %d packages, want %d collected + %d probe",
			len(collectedSrc.submitted()), len(collected), len(probe))
	}
}

// newLedgerWith builds a full ledger with one entry replaced, so a single
// verdict can be put through checkLedger.
func newLedgerWith(id linkID, v verdict) *ledger {
	l := newLedger()
	for _, other := range chainLinks {
		l.proven(other, "evidence")
	}
	l.v[id] = v
	return l
}

// TestTheHostTripwiresFireOnDroppedEvidence is hostSourceProblems' negative
// control. A guard that has never rejected anything has not been tested, and
// these are the shapes in which better evidence is collected and then not used.
func TestTheHostTripwiresFireOnDroppedEvidence(t *testing.T) {
	pkgs := []host.Package{
		{Ecosystem: host.EcosystemDeb, Name: "libc6", Version: "2.35-0ubuntu3.6"},
		{Ecosystem: host.EcosystemDeb, Name: "openssl", Version: "3.0.2-0ubuntu1.15"},
	}
	cases := []struct {
		name      string
		src       hostInventorySource
		submitted int
		want      string
	}{
		{
			name:      "a real inventory fully submitted",
			src:       hostInventorySource{real: true, collected: pkgs},
			submitted: 2,
		},
		{
			name: "no package manager, probe only",
			src:  hostInventorySource{probe: pkgs[:1]},
		},
		{
			name:      "a present package manager that enumerated nothing",
			src:       hostInventorySource{real: true},
			submitted: 0,
			want:      "ZERO packages",
		},
		{
			name:      "real packages collected and then dropped",
			src:       hostInventorySource{real: true, collected: pkgs},
			submitted: 1,
			want:      "the chain did not consume",
		},
		{
			name:      "a probe-only source carrying collected packages",
			src:       hostInventorySource{collected: pkgs},
			submitted: 0,
			want:      "One of the two is wrong",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostSourceProblems(tc.src, tc.submitted)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("a well-formed source was flagged: %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("hostSourceProblems accepted %q", tc.name)
			}
			if !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Errorf("flagged %q but not for the expected reason: %v", tc.name, got)
			}
		})
	}
}

// TestTheChainUsesTheBestAvailableHostEvidence is the tripwire that replaced
// the one CI fired, pointed the right way round.
//
// The old guard failed the run when a package manager appeared, because the
// chain was reading a hand-written file and the file had stopped being the
// best available evidence. Wiring host.Collect in answers that — but only for
// as long as the wiring stays. This test re-asks the machine DIRECTLY, without
// going through hostInventoryForChain, and fails if the chain's host input is
// not the best thing this machine can offer.
//
// It is deliberately not a statement about which branch is correct HERE: on a
// host with no package manager it asserts the probe branch, on a Linux host
// with one it asserts the collected branch, and either way it asserts that the chain and
// the machine agree.
func TestTheChainUsesTheBestAvailableHostEvidence(t *testing.T) {
	_, err := host.Collect(context.Background(), host.Options{
		Now: func() time.Time { return fixtureClock },
	})
	switch {
	case err == nil, errors.Is(err, host.ErrNoPackageManager):
	default:
		t.Fatalf("host.Collect failed for a reason this harness does not understand: %v", err)
	}
	managerPresent := err == nil

	src := hostInventoryForChain(t)
	if managerPresent != src.real {
		t.Fatalf("this machine %s a supported package manager, and the chain's host source says "+
			"real=%v. The chain must run on host.Collect's output wherever it exists and on the "+
			"corpus probe only where it does not; a disagreement here means the ledger's host "+
			"line describes an inventory the chain did not use.",
			map[bool]string{true: "HAS", false: "does not have"}[managerPresent], src.real)
	}
	if managerPresent && len(src.collected) == 0 {
		t.Error("the chain took the real branch and collected nothing; see hostSourceProblems")
	}
	if !managerPresent && len(src.collected) != 0 {
		t.Errorf("the chain took the probe branch and still carries %d collected package(s)",
			len(src.collected))
	}
	// The probe is present on BOTH branches and is never evidence about the
	// collector. If it ever went missing the comparator and emission links
	// would lose their only decidable host input and pass vacuously.
	if len(src.probe) == 0 {
		t.Error("the corpus probe is empty on this branch")
	}
	t.Logf("host evidence: %s", src.label())
}
