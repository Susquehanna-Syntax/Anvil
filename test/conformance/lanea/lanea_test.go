// Package lanea_test is Lane A's end-to-end conformance harness (A.21).
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
// THE OPEN SEAMS THIS HARNESS FOUND
// ===========================================================================
//
// All three are the same defect wearing three hats: FOUR COMPONENTS EACH
// DEFINE THEIR OWN PACKAGE-IDENTITY VOCABULARY AND NOBODY OWNS THE MAPPING.
// None is visible from inside any one package, because each package's fixtures
// speak its own dialect.
//
//	SEAM 1 — ECOSYSTEM VOCABULARY, INGESTION SIDE.
//	internal/ingest/decode writes the publisher's own ecosystem spelling into
//	`affected.ecosystem`: "Debian:11", "Alpine:v3.19", "PyPI", "Red Hat".
//	internal/match's ecosystemAllowlist is exact-match over {deb, rpm, apk} and
//	its comment says "the ingestion layer owns normalisation into this
//	vocabulary". The ingestion layer does not normalise. It is HALF normalised,
//	which is worse than neither: the Alpine secdb and Red Hat CSAF decoders
//	write "apk" and "rpm" and do reach the comparator, so a spot check on
//	either says the chain works, while every OSV- and CVE-5.x-sourced range —
//	which is most of the corpus — is silently unreachable.
//	PROVEN BY: TestLaneAChain/comparator, which ingests a real-shaped Debian
//	OSV export and finds it cannot be consulted for a deb host package.
//
//	SEAM 2 — NO PURL ON HOST PACKAGES.
//	internal/collector/host's Package is {ecosystem, package, version, arch}
//	and carries no purl. internal/match passes PackageRecord.Purl through
//	untouched. internal/record/lanea refuses any emission with no purl
//	(RefusalNoPurl) and says so deliberately: "this package will not
//	synthesise one — the namespace (debian vs ubuntu, redhat vs fedora) comes
//	from os-release". The host collector HAS os-release and does not build one.
//	So no host finding can be emitted today. A.19's own tests do not see it
//	because their host fixtures supply a purl.
//	PROVEN BY: TestLaneAChain/emission, which runs the real host inventory
//	shape through and captures the refusal.
//
//	SEAM 3 — ECOSYSTEM VOCABULARY, REPO SIDE.
//	internal/collector/repo's Finding.Ecosystem is Trivy's `Type` ("redhat",
//	"npm", "gomod"). Same allowlist, same mismatch, same silence.
//	PROVEN BY: TestLaneAChain/comparator.
//
// Where the harness has to cross one of these seams to exercise the links
// BEHIND it, it does so through bridgeEcosystem / bridgePurl — named,
// commented, TEST-ONLY functions. Their existence is the finding. They are not
// a fix and must not be copied into internal/.
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
				"%d match results and %d bytes of emitted records (zero deltas)",
			len(first.advisory), len(first.affected), len(first.alias), len(first.fts),
			len(first.feedState), len(first.matches), len(first.emissionJSON)))
	})

	// The links this run could not exercise, each re-checked against the
	// machine so a stale reason fails rather than persists.
	decideHostCollector(t, led)
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
		t.Error("exit criterion 10: a metadata disagreement did not make spine S8's manual note mandatory")
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
		"A.8 upserted %d records and A.14 upserted %d into one migrated FTS5 cache; every advisory "+
			"row carries a licence declaration, the REJECTED record is tombstoned rather than "+
			"deleted and left the FTS index, and the unknown dataVersion is persisted with "+
			"parse_degraded=1", bootstrapped, deltaUpserts))

	out.advisory = dump(t, db, advisoryDumpSQL)
	out.affected = dump(t, db, affectedDumpSQL)
	out.alias = dump(t, db, aliasDumpSQL)
	out.fts = dump(t, db, ftsDumpSQL)
	out.feedState = dump(t, db, feedStateDumpSQL)

	// --- LINK 5: the comparator ----------------------------------------
	inventory := hostInventory(t)
	scan := repoScan(t)
	records := append(hostPackageRecords(inventory), repoPackageRecords(scan)...)

	m, err := match.NewMatcher(&cacheSource{db: db})
	if err != nil {
		t.Fatalf("match.NewMatcher: %v", err)
	}
	results, cov, err := m.Match(ctx, records)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	out.matches, out.coverage = results, cov

	assertComparatorSeams(t, db, cov, results)
	led.proven(linkComparator, fmt.Sprintf(
		"the comparator ran over %d collector-shaped packages against the cache's own `affected` "+
			"rows and produced %d findings with a populated CoverageReport (Complete=%v, "+
			"RangesConsidered=%d, PackagesWithNoAdvisoryData=%d). SEAM 1 and SEAM 3 are asserted "+
			"here: the Debian OSV export landed with ecosystem %q and could not be consulted for a "+
			"deb host package, and the repository collector's %q findings were refused as an "+
			"unimplemented scheme (%d refused, ecosystems %v). Complete is FALSE because of that "+
			"refusal, which is the report doing its job",
		cov.PackagesSubmitted, len(results), cov.Complete, cov.RangesConsidered,
		cov.PackagesWithNoAdvisoryData, "Debian:11", "npm",
		cov.PackagesRefusedScheme, cov.EcosystemsRefused))

	// --- LINK 6: record emission ---------------------------------------
	emissions := emitAll(t, db, out.feeds, results, led)
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

func emitAll(t *testing.T, db *sql.DB, feeds config.FeedSet, results []match.MatchResult, led *ledger) []lanea.Emission {
	t.Helper()
	if len(results) == 0 {
		t.Fatal("the comparator produced no findings at all, so emission cannot be exercised; " +
			"the corpus is supposed to produce one host finding from the Alpine secdb ranges")
	}
	lookup := advisoryLookup(t, db, feeds)
	e := lanea.Emitter{
		TargetID: "anvil-conformance-target",
		// REQUIRED, and deliberately not defaultable. A.20 found that
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

	// SEAM 2, asserted rather than described: the host rows as the host
	// collector actually reports them carry no purl, and the emitter refuses.
	var hostAsCollected []match.MatchResult
	for _, r := range results {
		if r.Collector != cache.CollectorHost {
			continue
		}
		bare := r
		bare.Purl = "" // what host.Package actually supplies: nothing
		hostAsCollected = append(hostAsCollected, bare)
	}
	if len(hostAsCollected) == 0 {
		t.Fatal("no host finding to test the purl seam with")
	}
	if _, err := e.EmitAll(hostAsCollected, lookup); err == nil {
		t.Error("SEAM 2 HAS CLOSED: a host match with no purl was emitted. internal/collector/host " +
			"now supplies one, or internal/record/lanea stopped requiring one. Delete bridgePurl, " +
			"emit the real inventory, and promote the host link to PROVEN.")
	} else {
		var ref *lanea.Refusal
		if !errors.As(err, &ref) || ref.Reason != lanea.RefusalNoPurl {
			t.Errorf("the host emission failed for an unexpected reason: %v", err)
		}
	}

	emissions, err := e.EmitAll(results, lookup)
	if err != nil {
		t.Fatalf("emitting the bridged results: %v", err)
	}
	if len(emissions) != len(results) {
		t.Fatalf("%d matches produced %d emissions", len(results), len(emissions))
	}

	// Exit criterion 21, end to end.
	hosts := 0
	for i, em := range emissions {
		if em.Result.Properties.Detector.Kind != record.DetectorKindHost {
			t.Errorf("emission %d is not host-sourced, but every finding this corpus can produce "+
				"through a collector is: see the repo-SCA note in the ledger", i)
			continue
		}
		hosts++
		if em.RemediableByAgent() {
			t.Errorf("emission %d is host-sourced and carries remediable_by_agent=true", i)
		}
	}
	if hosts == 0 {
		t.Error("no host-sourced record was emitted, so exit criterion 21 passed vacuously")
	}

	led.proven(linkEmission, fmt.Sprintf(
		"%d canonical record(s) emitted through internal/record/lanea from the comparator's output "+
			"and the cache's own advisory rows, all host-sourced and all remediable_by_agent=false. "+
			"SEAM 2 is asserted here — the same matches WITHOUT the harness's bridgePurl are "+
			"refused with RefusalNoPurl, which is what the real inventory produces. NOTE WHAT THIS "+
			"DOES NOT SAY: exit criterion 21 holds here over a set that contains ONLY host records, "+
			"because no collector output can currently produce a non-host one. "+
			"TestTheRemediablePathIsReachableAtAll is the positive control that keeps the "+
			"assertion from being true only because nothing is.", len(emissions)))
	return emissions
}

// TestTheRemediablePathIsReachableAtAll is the positive control for exit
// criterion 21.
//
// "No host record is remediable" is a weak claim if NO record is ever
// remediable, and today none produced by a collector is: internal/collector/repo
// reports only lang-pkgs findings (it skips os-pkgs as A.9's territory), and
// internal/match implements deb, rpm and apk only. The two halves of the SCA
// path have disjoint domains, so no repository finding survives the comparator.
//
// The input below is therefore a PROBE and is labelled one: a repo-SCA package
// record in an ecosystem the comparator implements. No collector emits this
// shape today. The comparator still computes the verdict, so what is proven is
// real — remediable_by_agent CAN be true, and the difference between the two
// collectors is what decides it.
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

// advisoryLookup reads the `advisory` row a match was decided on.
//
// IT IS TEST-ONLY AND ITS EXISTENCE IS A FINDING. internal/record/lanea's
// AdvisoryRow mirrors the cache's columns one for one and documents that "the
// caller reads the row and fills this in" — and no caller exists. See
// linkProductionUp.
func advisoryLookup(t *testing.T, db *sql.DB, feeds config.FeedSet) func(string, string) (lanea.AdvisoryRow, bool) {
	t.Helper()
	slo := map[string]int{}
	for _, f := range feeds.Feeds {
		slo[f.ID] = f.FreshnessSLOSeconds
	}
	return func(source, sourceID string) (lanea.AdvisoryRow, bool) {
		const q = `
SELECT ifnull(cve_id,''), ifnull(license_spdx,''), ifnull(license_manual_note,''), anvil_trust,
       as_of, staleness_seconds, parse_degraded, ifnull(data_version,''),
       ifnull(cvss_vector,''), cvss_score, epss_score, ifnull(epss_as_of,''), kev
FROM advisory WHERE source = ? AND source_id = ?`
		var (
			cveID, spdx, note, trust, asOf, dataVersion, vector, epssAsOf string
			staleness, degraded, kev                                      int
			cvss, epss                                                    sql.NullFloat64
		)
		err := db.QueryRow(q, source, sourceID).Scan(&cveID, &spdx, &note, &trust, &asOf,
			&staleness, &degraded, &dataVersion, &vector, &cvss, &epss, &epssAsOf, &kev)
		if err != nil {
			return lanea.AdvisoryRow{}, false
		}
		when, err := time.Parse(time.RFC3339, asOf)
		if err != nil {
			return lanea.AdvisoryRow{}, false
		}
		row := lanea.AdvisoryRow{
			Source: source, SourceID: sourceID, CVEID: cveID,
			FeedID:              source,
			SnapshotDigest:      cache.SchemaSHA256(),
			LicenseSPDX:         spdx,
			LicenseManualNote:   note,
			Trust:               record.Trust(trust),
			AsOf:                when,
			StalenessSeconds:    staleness,
			FreshnessSLOSeconds: slo[source],
			ParseDegraded:       degraded == 1,
			DataVersion:         dataVersion,
			CVSSVector:          vector,
			KEVMember:           kev == 1,
		}
		if cvss.Valid {
			v := cvss.Float64
			row.CVSSScore = &v
		}
		if epss.Valid {
			v := epss.Float64
			row.EPSSScore = &v
		}
		return row, true
	}
}

// ---------------------------------------------------------------------------
// Collector inputs, and the two bridges the seams force
// ---------------------------------------------------------------------------

// bridgePurl builds the purl internal/collector/host does not.
//
// IT IS TEST-ONLY. SEAM 2: the emitter refuses a match with no purl and says
// explicitly that it will not synthesise one because the namespace comes from
// os-release. The host collector reads os-release and does not build the purl,
// so this function stands in for a component nobody has written. The namespace
// it picks is deliberately crude — this is not a proposed implementation, it is
// a scaffold holding the seam open long enough to test what is behind it.
func bridgePurl(p host.Package) string {
	ns := map[string]string{
		host.EcosystemDeb: "debian",
		host.EcosystemRPM: "redhat",
		host.EcosystemAPK: "alpine",
	}[p.Ecosystem]
	u := "pkg:" + p.Ecosystem + "/" + ns + "/" + p.Name + "@" + p.Version
	if p.Arch != "" {
		u += "?arch=" + p.Arch
	}
	return u
}

// bridgeEcosystem maps a collector's ecosystem string onto the comparator's
// vocabulary.
//
// IT IS TEST-ONLY. SEAM 1 and SEAM 3: internal/match's allowlist is exact-match
// over {deb, rpm, apk} and its comment says the ingestion layer owns
// normalisation into that vocabulary. Nothing does. This is the missing owner,
// written here so the links behind it can be exercised — and it handles exactly
// the strings this corpus produces, because a fuller table here would look like
// a fix.
func bridgeEcosystem(s string) (string, bool) {
	switch s {
	case match.EcosystemDeb, match.EcosystemRPM, match.EcosystemAPK:
		return s, true
	case "redhat", "Red Hat", "rocky", "almalinux":
		return match.EcosystemRPM, true
	case "debian", "Debian:11", "ubuntu":
		return match.EcosystemDeb, true
	case "alpine", "Alpine:v3.19":
		return match.EcosystemAPK, true
	}
	return "", false
}

func hostInventory(t *testing.T) []host.Package {
	t.Helper()
	var doc struct {
		Packages []host.Package `json:"packages"`
	}
	if err := json.Unmarshal(readFixture(t, "fixtures/inventory/host-packages.json"), &doc); err != nil {
		t.Fatalf("reading the host inventory fixture: %v", err)
	}
	if len(doc.Packages) == 0 {
		t.Fatal("the host inventory fixture is empty")
	}
	return doc.Packages
}

// hostPackageRecords applies the field mapping internal/match documents on
// PackageRecord — plus bridgePurl, which the mapping has no column for.
func hostPackageRecords(pkgs []host.Package) []match.PackageRecord {
	out := make([]match.PackageRecord, 0, len(pkgs))
	for _, p := range pkgs {
		eco, ok := bridgeEcosystem(p.Ecosystem)
		if !ok {
			continue
		}
		out = append(out, match.PackageRecord{
			Collector: host.Collector,
			Ecosystem: eco,
			Name:      p.Name,
			Version:   p.Version,
			Arch:      p.Arch,
			Purl:      bridgePurl(p),
		})
	}
	return out
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

// repoPackageRecords applies internal/match's documented repo.Finding mapping
// AND NOTHING ELSE — no bridgeEcosystem here, deliberately.
//
// SEAM 3 is only visible if the comparator is allowed to see what the collector
// actually reports. Trivy's `Type` for a lockfile is "npm"; the comparator
// implements deb, rpm and apk. Bridging it here would hide the refusal inside
// the harness, and the point is to make the comparator COUNT it — a refused
// package is a countable gap in CoverageReport rather than a silent zero.
func repoPackageRecords(scan repo.ScanResult) []match.PackageRecord {
	out := make([]match.PackageRecord, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		out = append(out, match.PackageRecord{
			Collector:       f.Collector,
			Ecosystem:       f.Ecosystem,
			Name:            f.PackageName,
			Version:         f.InstalledVersion,
			Purl:            f.Purl,
			ManifestRelPath: f.ManifestRelPath,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// The cache as an advisory source
// ---------------------------------------------------------------------------

// cacheSource is internal/match's AdvisorySource read straight off the A.2
// cache.
//
// IT IS TEST-ONLY AND ITS EXISTENCE IS A FINDING. internal/match defines the
// interface precisely so the comparator opens no database, and NOTHING under
// internal/ implements it against the cache — the comparator and the cache
// have never been connected outside this file. See linkProductionUp.
//
// It excludes tombstoned advisories, which is exit criterion 22 seen from the
// read side: a withdrawn advisory keeps its row and stops deciding findings.
type cacheSource struct{ db *sql.DB }

func (s *cacheSource) AffectedRanges(ctx context.Context, ecosystem, pkg string) ([]match.AffectedRange, error) {
	const q = `
SELECT a.source, a.source_id, ifnull(a.cve_id,''), af.ecosystem, af.package, ifnull(af.purl,''),
       ifnull(af.introduced,''), ifnull(af.fixed,''), af.distro_backport
FROM affected af
JOIN advisory a ON a.source = af.source AND a.source_id = af.source_id
WHERE af.ecosystem = ? AND af.package = ? AND a.state = ?
ORDER BY a.source, a.source_id, af.id`
	rows, err := s.db.QueryContext(ctx, q, ecosystem, pkg, cache.AdvisoryPublished)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []match.AffectedRange
	for rows.Next() {
		var r match.AffectedRange
		var backport int
		if err := rows.Scan(&r.Source, &r.SourceID, &r.CVEID, &r.Ecosystem, &r.Package,
			&r.Purl, &r.Introduced, &r.Fixed, &backport); err != nil {
			return nil, err
		}
		r.DistroBackport = backport == 1
		// An unbounded range is refused by the comparator, and an advisory
		// that names only a fixed version is unbounded below by construction.
		// "0" is the OSV convention for it and is what the corpus's own OSV
		// documents carry.
		if r.Introduced == "" && r.Fixed == "" && !r.AllVersions {
			continue
		}
		if r.Introduced == "" {
			r.Introduced = "0"
		}
		out = append(out, r)
	}
	return out, rows.Err()
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
			"is the retrieval failure spine S7's ingest-time sanitisation prevents", n)
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

func assertComparatorSeams(t *testing.T, db *sql.DB, cov match.CoverageReport, results []match.MatchResult) {
	t.Helper()

	// Exit criterion 20: coverage is populated on every run.
	if cov.PackagesSubmitted == 0 || len(cov.SchemesImplemented) == 0 {
		t.Errorf("exit criterion 20: the CoverageReport is not populated: %+v", cov)
	}
	if err := cov.AssertNotSilentlyClean(results); err != nil && len(results) == 0 {
		t.Errorf("a zero-finding run was not reported as an absence: %v", err)
	}

	// SEAM 1, asserted. The Debian OSV export IS in the cache, and it is NOT
	// reachable for a deb host package, because the decoder wrote the
	// publisher's ecosystem spelling into a column the comparator matches
	// exactly.
	stored := count(t, db, `SELECT count(*) FROM affected WHERE ecosystem = ?`, "Debian:11")
	if stored == 0 {
		t.Fatal("the Debian OSV fixture did not land in `affected`, so SEAM 1 cannot be asserted")
	}
	reachable := count(t, db, `SELECT count(*) FROM affected WHERE ecosystem = ?`, match.EcosystemDeb)
	if reachable != 0 {
		t.Errorf("SEAM 1 HAS CLOSED: %d rows now carry the comparator's own ecosystem vocabulary. "+
			"Something normalises. Delete bridgeEcosystem, point the harness at the real column, "+
			"and re-read this assertion.", reachable)
	}
	for _, r := range results {
		if r.Ecosystem == match.EcosystemDeb {
			t.Errorf("a deb finding was produced (%s/%s); with no normalisation owner this is "+
				"impossible and the assertion above is wrong", r.Package, r.InstalledVersion)
		}
	}

	// SEAM 3, asserted. The repository collector reports lang-pkgs findings —
	// it skips os-pkgs as A.9's territory — and the comparator implements OS
	// package schemes only. The two halves of the SCA path have DISJOINT
	// DOMAINS, so no repository finding can ever become a record. What the
	// comparator does right is refuse it COUNTABLY rather than returning a
	// quiet zero.
	if cov.PackagesRefusedScheme == 0 {
		t.Error("SEAM 3 HAS CLOSED, or the repo fixture stopped reaching the comparator: no package " +
			"was refused for an unimplemented scheme, though Trivy reported an npm dependency and " +
			"internal/match implements deb, rpm and apk only")
	}
	// The refusal must be findable BY NAME somewhere, or "1 package refused"
	// is a number an operator cannot act on.
	named := false
	for _, r := range cov.Refusals {
		if strings.Contains(r.Detail, "npm") || r.Ecosystem == "npm" {
			named = true
		}
	}
	if !named {
		t.Errorf("no entry in CoverageReport.Refusals names the ecosystem that was refused: %+v",
			cov.Refusals)
	}
	// FINDING, logged rather than failed because internal/match is outside this
	// packet's write scope: EcosystemsRefused is documented as "the list an
	// operator uses to decide what to implement next", and it is populated ONLY
	// from RefusalUnsupportedEcosystem. A record carrying a purl — which is
	// every repo-SCA finding, and what every collector is encouraged to
	// supply — is refused as RefusalUnsupportedPurlType instead, so the
	// operator-facing list is empty exactly when the input was well-formed.
	if cov.PackagesRefusedScheme > 0 && len(cov.EcosystemsRefused) == 0 {
		t.Logf("FINDING (internal/match, not fixed here): %d package(s) were refused for an "+
			"unimplemented scheme and CoverageReport.EcosystemsRefused is EMPTY, because the "+
			"refusal came through the purl path (RefusalUnsupportedPurlType) and only "+
			"RefusalUnsupportedEcosystem feeds that list. The count is visible; the thing to "+
			"implement next is not.", cov.PackagesRefusedScheme)
	}
	if cov.Complete {
		t.Error("the run refused a package and still reported Complete; Complete must be false " +
			"whenever something was refused, or \"nothing was found\" cannot be read as an answer")
	}

	// The vendor range IS consulted where the vocabulary happens to line up:
	// the Red Hat CSAF decoder writes "rpm" and the Alpine secdb decoder
	// writes "apk", so those two reach the comparator.
	if count(t, db, `SELECT count(*) FROM affected WHERE ecosystem = ? AND distro_backport = 1`, match.EcosystemRPM) == 0 {
		t.Error("the CSAF fixture produced no backported rpm range, so the vendor-first path is untested here")
	}

	// The rpm host package sits exactly ON the vendor's fixed version and must
	// NOT be flagged: `fixed` is an EXCLUSIVE upper bound.
	for _, r := range results {
		if r.Collector == cache.CollectorHost && r.Package == "python3-requests" {
			t.Errorf("the host's python3-requests %s was flagged against a vendor advisory that "+
				"names it as the fixed version; this is the backport false-positive class",
				r.InstalledVersion)
		}
	}
}

// ---------------------------------------------------------------------------
// The links this machine cannot prove
// ---------------------------------------------------------------------------

func decideHostCollector(t *testing.T, led *ledger) {
	t.Helper()
	inv, err := host.Collect(context.Background(), host.Options{
		Now: func() time.Time { return fixtureClock },
	})
	switch {
	case err == nil:
		// A package manager exists here after all. That is a better world,
		// and it means this harness must stop using a fixture inventory.
		led.proven(linkHostCollect, fmt.Sprintf(
			"host.Collect ran to completion on this machine and returned %d packages across %d "+
				"families", len(inv.Packages), len(inv.Coverage)))
		t.Errorf("a supported package manager is present on this host, so the fixture inventory " +
			"is no longer the best available evidence. Feed host.Collect's output into the chain " +
			"and delete fixtures/inventory/host-packages.json.")
	case errors.Is(err, host.ErrNoPackageManager):
		led.unproven(linkHostCollect,
			"no dpkg, rpm or apk exists on this host ("+"GOOS="+runtime.GOOS+"), so host.Collect "+
				"cannot produce an inventory here and the chain runs on a fixture inventory in "+
				"host.Package's own JSON shape. The collector's REFUSAL is proven — it ran to "+
				"completion and returned a named error rather than hanging or inventing rows — "+
				"but its output is not.",
			"run this harness on a Linux host with one of the three package managers installed; "+
				"the fixture inventory is then redundant and hostInventory should read from "+
				"host.Collect instead")
	default:
		t.Fatalf("host.Collect failed for a reason this harness does not understand: %v", err)
	}
}

func decideRepoCollector(t *testing.T, led *ledger) {
	t.Helper()
	scan := repoScan(t)
	if bin, err := repo.ResolveBinary(repo.BinaryName); err == nil {
		led.proven(linkRepoCollect, "trivy resolved at "+bin+" and the scan ran end to end")
		t.Errorf("trivy is installed at %s, so the recorded-report fixture is no longer the best "+
			"available evidence. Run repo.ScanRepo against a fixture tree and prove the collector "+
			"itself, not only its parser. The Trivy E2E job's finding — that the collector cannot "+
			"run without a pre-seeded database — is exactly what a recorded report cannot show.", bin)
		return
	}
	led.unproven(linkRepoCollect,
		fmt.Sprintf("the trivy binary is not on PATH, so repo.ScanRepo cannot run here. What IS "+
			"proven is the report path: repo.ParseReport turned a recorded-shape Trivy report into "+
			"%d finding(s) with populated Coverage, and AssertNotSilentlyEmpty accepted it. The "+
			"SCAN is not proven, and a recorded report presupposes the successful run it is "+
			"standing in for — the precise gap the Trivy E2E job found.", len(scan.Findings)),
		"install the pinned trivy release and its vulnerability database on the CI host, then call "+
			"repo.ScanRepo against a fixture repository; only that exercises binary resolution, "+
			"argument construction, the exit-code contract and the DB-absent failure mode")
}

// decideNotWired records the links that exist as packages with no caller.
func decideNotWired(t *testing.T, led *ledger) {
	t.Helper()
	led.unproven(linkSelfHeal,
		"internal/ingest/reconcile's weekly baseline self-heal is not exercised by this harness: "+
			"it re-pulls the full bulk artifact, and proving that it RESTORES a silently-dropped "+
			"record needs a second, later archive plus a deliberate deletion between the two runs",
		"A.15's own TestSelfHealRestoresDroppedRecords covers it against a synthetic "+
			"missing-records fixture; an end-to-end proof needs this harness to serve two "+
			"generations of the same archive and delete rows between them")
	led.unproven(linkAccelerator,
		"internal/mirror/accelerator is not in this chain at all. It is a warm-start optimisation "+
			"that pulls a compiled Trivy-DB/Grype-DB artifact, and pulling one requires a registry "+
			"this harness must not contact",
		"A.11/A.13's own tests cover the version gate and the consume-only write refusal against "+
			"synthetic artifacts; an end-to-end proof needs a local OCI registry fixture")
	led.unproven(linkProductionUp,
		"NOTHING UNDER internal/ WIRES THIS CHAIN TOGETHER. Two components this harness needed do "+
			"not exist in production form: an internal/match.AdvisorySource backed by the A.2 cache "+
			"(the comparator has never been connected to the cache outside this file) and a reader "+
			"that fills internal/record/lanea.AdvisoryRow from an `advisory` row (its doc says "+
			"\"the caller reads the row and fills this in\"; there is no caller). cacheSource and "+
			"advisoryLookup in this file are stand-ins written for the test",
		"implement both in internal/ — a cache-backed AdvisorySource and an AdvisoryRow reader — "+
			"and have this harness call them instead of its own copies; the diff between the two "+
			"implementations is then the thing that gets reviewed")
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
		advisory:     []string{"source=a source_id=1"},
		affected:     []string{"source=a source_id=1 package=openssl"},
		alias:        []string{"cve_id=CVE-2026-1001"},
		fts:          []string{"source=a source_id=1 indexed"},
		feedState:    []string{"feed_id=a"},
		matches:      []match.MatchResult{{Source: "a", SourceID: "1", Package: "openssl"}},
		emissionJSON: []byte("{}"),
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
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			other := base
			other.advisory = append([]string(nil), base.advisory...)
			other.affected = append([]string(nil), base.affected...)
			other.alias = append([]string(nil), base.alias...)
			other.fts = append([]string(nil), base.fts...)
			other.feedState = append([]string(nil), base.feedState...)
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
		"operators should self-host. Reported by A.21, not fixed by it.",
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
	// divergence at all — which is how the A.8/A.14 tombstone divergence this
	// harness found stayed invisible.
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
