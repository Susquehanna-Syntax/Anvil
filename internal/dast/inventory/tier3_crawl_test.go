// Tests for D.23, Tier 3: the browser-driven crawl.
//
// A crawler is the most dangerous component in the dynamic tier because every
// destination it visits after the first one was proposed by the target. So the
// suite is organised around the four ways that capability turns into a defect,
// and every one of them is driven through the REAL kernel — authz.InitiateRun,
// authz.Adjudicate, authz.NewRequestIntent, authz.GateAudit.AuditedAdmit,
// authz.Governor.ObserveResponse — with ClientSpider as the only double,
// because D.9's gate 3 forbids this package from holding a socket.
//
//	THE WALK-OFF. A link off the admitted origin, a scheme downgrade, a
//	different port, a cross-host redirect. Refused at the LINK, and the
//	fixture spider records every request it was handed so the tests assert
//	what actually left rather than what the implementation says it sends.
//
//	TERMINATION. A cyclic site, a self-referencing page, and an infinite site
//	that mints a fresh distinct path per page. Each terminates on a DIFFERENT
//	bound, and each test asserts the exact request COUNT rather than that the
//	function returned.
//
//	THE EXCLUSION LIST. Swagger UI and GraphQL playground paths are refused
//	even when the fixture's link graph offers them, and the sibling route that
//	merely shares a spelling is NOT refused.
//
//	THE NUMERATOR. Every route this tier produces is a candidate, including
//	one whose page answered 200 to a request this crawl itself made.
//
// The guard-breaking runs are recorded in the packet report, not here: a break
// that stays green is a finding about the test, and four of these were broken,
// watched go red, and restored byte for byte.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/engines"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// c23Spider is the browser seam's double. It serves a fixed link graph and
// RECORDS every CrawlRequest it was handed, so a test can assert what left the
// process rather than what the loop believes it sent.
type c23Spider struct {
	pages    map[string]CrawlPage
	def      CrawlPage
	err      error
	errPaths map[string]error
	// exact suppresses the harness's own defaulting, so a test can hand the
	// loop a status that is NOT an HTTP status. Without it the harness would
	// quietly repair the input the guard exists to reject.
	exact bool
	seen  []CrawlRequest
	calls int
}

func (s *c23Spider) FetchPage(_ context.Context, req CrawlRequest) (CrawlPage, error) {
	s.calls++
	s.seen = append(s.seen, req)
	if s.err != nil {
		return CrawlPage{}, s.err
	}
	if e, ok := s.errPaths[req.Path()]; ok {
		return CrawlPage{}, e
	}
	p, ok := s.pages[req.Path()]
	if !ok {
		p = s.def
	}
	if !s.exact {
		if p.Status == 0 {
			p.Status = 200
		}
		if p.Latency == 0 {
			p.Latency = 3 * time.Millisecond
		}
	}
	return p, nil
}

// paths returns every path the spider was actually asked for, in order.
func (s *c23Spider) paths() []string {
	out := make([]string, 0, len(s.seen))
	for _, r := range s.seen {
		out = append(out, r.Path())
	}
	return out
}

// labels returns "path@origin/hop" for every request, which is how the
// redirect tests assert that the LABEL and not only the destination is right.
func (s *c23Spider) labels() []string {
	out := make([]string, 0, len(s.seen))
	for _, r := range s.seen {
		out = append(out, fmt.Sprintf("%s@%s/%d", r.Path(), r.Origin(), r.Hop()))
	}
	return out
}

func c23Linking(graph map[string][]string) *c23Spider {
	pages := map[string]CrawlPage{}
	for p, links := range graph {
		pages[p] = CrawlPage{Status: 200, Links: links}
	}
	return &c23Spider{pages: pages, def: CrawlPage{Status: 200}}
}

// c23Robots is the robots.txt the fixture scope is narrowed with. An empty
// body determines the origin and disallows nothing, which is what most tests
// want: gate 11 has RUN, and it removed nothing.
func c23Robots(t *testing.T, body string) authz.RobotsDocument {
	t.Helper()
	return authz.RobotsDocument{
		Host:    fixtureHost,
		Port:    443,
		Outcome: authz.RobotsFetchRetrieved,
		Body:    []byte(body),
	}
}

// c23NarrowedScope builds the fixture scope with gate 11 APPLIED, which is the
// state CrawlConfig.Scope documents it expects. Without the narrowing
// Scope.PermitsPath refuses every path — see
// TestAScopeNobodyNarrowedPermitsNoPath, which asserts exactly that.
func c23NarrowedScope(t *testing.T, robotsBody string) authz.Scope {
	t.Helper()
	scope, err := initiateRun(t).Scope()
	if err != nil {
		t.Fatalf("init.Scope: %v", err)
	}
	narrowed, res := authz.NarrowScopeToRobots(scope, []authz.RobotsDocument{
		c23Robots(t, robotsBody),
	})
	if !res.Passed() {
		t.Fatalf("authz.NarrowScopeToRobots refused: %v", res.Err())
	}
	if !narrowed.Narrowed() {
		t.Fatal("gate 11 reported a pass and produced a scope it had not narrowed, so " +
			"every PermitsPath answer below would be fail-closed for the wrong reason")
	}
	return narrowed
}

type c23Opts struct {
	trigger    ScanTrigger
	seeds      []string
	maxPages   int
	maxDepth   int
	spider     ClientSpider
	robots     string
	robotsPol  *authz.RobotsPolicy
	scope      *authz.Scope
	freezeTime bool
	overrides  *authz.CapOverrides
}

// c23Config assembles a real kernel and a crawl configuration around it.
func c23Config(t *testing.T, o c23Opts) CrawlConfig {
	t.Helper()
	if o.trigger == ScanTriggerUnset {
		o.trigger = ScanTriggerScheduledFull
	}
	if o.seeds == nil {
		o.seeds = []string{"/"}
	}
	if o.maxPages == 0 {
		o.maxPages = 50
	}
	if o.maxDepth == 0 {
		o.maxDepth = 8
	}
	opts := c22KernelOpts{robots: o.robotsPol, overrides: o.overrides}
	gov, audit, _ := c22Kernel(t, opts)
	auth, _ := mintAuthorization(t)
	scope := c23NarrowedScope(t, o.robots)
	if o.scope != nil {
		scope = *o.scope
	}
	cfg := CrawlConfig{
		Trigger:       o.trigger,
		Governor:      gov,
		Audit:         audit,
		Authorization: auth,
		Target:        mustBareTarget(t),
		Scope:         scope,
		Technique:     authz.TechniqueContentDiscovery,
		Seeds:         o.seeds,
		MaxPages:      o.maxPages,
		MaxDepth:      o.maxDepth,
		Spider:        o.spider,
	}
	if !o.freezeTime {
		cfg.Clock = c22Advancing(t, time.Second)
	}
	return cfg
}

func c23Run(t *testing.T, cfg CrawlConfig, exclude ...string) CrawlResult {
	t.Helper()
	res, err := CrawlWithClientSpider(context.Background(), cfg, mustClock(t), exclude)
	if err != nil {
		t.Fatalf("CrawlWithClientSpider: %v", err)
	}
	return res
}

// c23Ledger renders the visit ledger for a failure message.
func c23Ledger(res CrawlResult) []string {
	out := make([]string, 0, len(res.Visits()))
	for _, v := range res.Visits() {
		out = append(out, fmt.Sprintf("%s -> %s", v.CanonicalPath(), v.Outcome()))
	}
	return out
}

func c23RoutePaths(res CrawlResult) []string {
	out := make([]string, 0, len(res.Routes()))
	for _, r := range res.Routes() {
		out = append(out, r.Path())
	}
	sort.Strings(out)
	return out
}

func c23OutcomeCount(res CrawlResult, o CrawlOutcome) int {
	n := 0
	for _, v := range res.Visits() {
		if v.Outcome() == o {
			n++
		}
	}
	return n
}

func c23Visit(t *testing.T, res CrawlResult, canon string) CrawlVisit {
	t.Helper()
	for _, v := range res.Visits() {
		if v.CanonicalPath() == canon {
			return v
		}
	}
	t.Fatalf("no ledger row for %q; the ledger is %v", canon, c23Ledger(res))
	return CrawlVisit{}
}

func c23HasRoute(res CrawlResult, path string) bool {
	for _, r := range res.Routes() {
		if r.Path() == path {
			return true
		}
	}
	return false
}

// ===========================================================================
// THE TRIGGER GATE — plan/50-dast.md exit gate 14, both halves
// ===========================================================================

// TestTheCrawlDoesNotExecuteOnAnIncrementalTrigger is exit gate 14's negative
// half, and it asserts SILENCE ON THE WIRE rather than an empty result: the
// spider's own call counter is the measurement, because a result with no
// routes is what a skipped crawl and a crawled-but-empty target both look
// like.
func TestTheCrawlDoesNotExecuteOnAnIncrementalTrigger(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/": {"/a", "/b", "/c"},
	})
	cfg := c23Config(t, c23Opts{trigger: ScanTriggerIncremental, spider: spider})
	res := c23Run(t, cfg)

	if res.Executed() {
		t.Fatal("the crawl reported that it executed on an incremental trigger")
	}
	if spider.calls != 0 {
		t.Fatalf("the spider was called %d time(s) on an incremental trigger; it must be "+
			"0. plan/50-dast.md D.23: this tier fires on scheduled full scans only",
			spider.calls)
	}
	if n := len(res.Routes()); n != 0 {
		t.Fatalf("a skipped crawl produced %d route(s)", n)
	}
	if n := res.Issued(); n != 0 {
		t.Fatalf("a skipped crawl issued %d request(s)", n)
	}
	if res.SkipReason() == "" {
		t.Fatal("the crawl was skipped and named no reason, which is the difference " +
			"between a decision and an omission")
	}
	// The skip must be DISTINGUISHABLE from an empty crawl by a caller who
	// runs only the standard emptiness assertion.
	err := res.AssertNotSilentlyEmpty()
	if !errors.Is(err, ErrCrawlDidNotRun) {
		t.Fatalf("AssertNotSilentlyEmpty returned %v, want ErrCrawlDidNotRun. A caller "+
			"that read Routes() without asking Executed() would shrink the coverage "+
			"denominator and report better coverage for it", err)
	}
}

// TestTheCrawlDoesExecuteOnAScheduledFullScan is exit gate 14's positive half.
// Without it the negative half is satisfied by a crawl that never runs at all.
func TestTheCrawlDoesExecuteOnAScheduledFullScan(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/":  {"/a", "/b"},
		"/a": {"/c"},
	})
	res := c23Run(t, c23Config(t, c23Opts{
		trigger: ScanTriggerScheduledFull, spider: spider,
	}))

	if !res.Executed() {
		t.Fatalf("the crawl did not execute on a scheduled full scan: %s", res.SkipReason())
	}
	if got := res.Issued(); got != 4 {
		t.Fatalf("issued=%d, want 4 (/, /a, /b, /c); the spider saw %v", got, spider.paths())
	}
	if got := res.Answered(); got != 4 {
		t.Fatalf("answered=%d, want 4", got)
	}
	want := []string{"/", "/a", "/b", "/c"}
	if got := c23RoutePaths(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes=%v, want %v", got, want)
	}
	if err := res.AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("AssertNotSilentlyEmpty: %v", err)
	}
	if err := res.AssertBudgetSufficed(); err != nil {
		t.Fatalf("AssertBudgetSufficed: %v", err)
	}
}

// TestOnlyTheScheduledFullTriggerIsEligible walks every enumerated trigger
// plus the zero value plus a token nobody enumerated, so the allowlist is
// measured as an allowlist rather than as "incremental is excluded".
func TestOnlyTheScheduledFullTriggerIsEligible(t *testing.T) {
	cases := []struct {
		trigger ScanTrigger
		want    bool
	}{
		{ScanTriggerScheduledFull, true},
		{ScanTriggerIncremental, false},
		{ScanTriggerTag, false},
		{ScanTriggerUnset, false},
		{ScanTrigger("nightly_full"), false},
		{ScanTrigger("SCHEDULED_FULL"), false},
		{ScanTrigger("scheduled_full "), false},
	}
	eligible := 0
	for _, c := range cases {
		if got := c.trigger.PermitsTier3Crawl(); got != c.want {
			t.Errorf("ScanTrigger(%q).PermitsTier3Crawl()=%v, want %v", c.trigger, got, c.want)
		}
		if c.want {
			eligible++
		}
	}
	if eligible != 1 {
		t.Fatalf("%d triggers are eligible in this table; the allowlist has exactly one "+
			"member and a table asserting otherwise is testing the wrong list", eligible)
	}

	// And the same answer end to end, not only from the predicate.
	for _, c := range cases {
		spider := c23Linking(map[string][]string{"/": {"/a"}})
		cfg := c23Config(t, c23Opts{spider: spider})
		cfg.Trigger = c.trigger // set AFTER the harness, which defaults it
		res := c23Run(t, cfg)
		if res.Executed() != c.want {
			t.Fatalf("trigger %q: Executed()=%v, want %v", c.trigger, res.Executed(), c.want)
		}
		if !c.want && spider.calls != 0 {
			t.Fatalf("trigger %q: the spider was called %d times", c.trigger, spider.calls)
		}
	}
}

// TestTheTriggerGateRunsBeforeAnythingElse. An ineligible run must not be able
// to reach the crawl by being differently broken, and an ineligible run with a
// broken configuration must report the TRIGGER, not the configuration.
func TestTheTriggerGateRunsBeforeAnythingElse(t *testing.T) {
	cfg := CrawlConfig{Trigger: ScanTriggerIncremental} // nothing else set at all
	res, err := CrawlWithClientSpider(context.Background(), cfg, mustClock(t), nil)
	if err != nil {
		t.Fatalf("a skipped crawl is not an error: %v", err)
	}
	if res.Executed() {
		t.Fatal("an unconfigured incremental crawl executed")
	}
	if !strings.Contains(res.SkipReason(), "incremental") {
		t.Fatalf("the skip reason is %q and does not name the trigger", res.SkipReason())
	}
}

// ===========================================================================
// THE EXCLUSION LIST — Swagger UI and GraphQL playgrounds
// ===========================================================================

// TestSwaggerUIAndGraphQLPlaygroundsAreExcludedEvenWhenTheLinkGraphOffersThem
// is D.23's first named validation requirement.
//
// The fixture target links to eight meta-surface paths from its front page.
// The assertion is on the exact set of paths that LEFT — the spider's own
// record — plus the exact ledger count, because a len(x)>0 check would pass an
// implementation that excluded one of the eight.
func TestSwaggerUIAndGraphQLPlaygroundsAreExcludedEvenWhenTheLinkGraphOffersThem(t *testing.T) {
	meta := []string{
		"/swagger-ui/index.html",
		"/swagger-ui.html",
		"/swagger-resources/configuration/ui",
		"/v3/api-docs",
		"/v2/api-docs/swagger-config",
		"/graphiql",
		"/graphql-playground/index.html",
		"/altair",
	}
	spider := c23Linking(map[string][]string{
		"/": append(append([]string{}, meta...), "/orders", "/orders/42"),
	})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	want := []string{"/", "/orders", "/orders/42"}
	if got := spider.paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the spider was asked for %v; want exactly %v. plan/50-dast.md D.23 "+
			"forbids crawling Swagger UI and GraphQL playground routes even when the "+
			"crawl finds them itself", got, want)
	}
	if got := c23OutcomeCount(res, CrawlOutcomeMetaSurfaceExcluded); got != len(meta) {
		t.Fatalf("%d ledger rows say meta_surface_excluded, want %d. The ledger is %v",
			got, len(meta), c23Ledger(res))
	}
	// An excluded path is meta-surface, not application surface, so it is NOT
	// in the coverage denominator either.
	for _, m := range meta {
		if c23HasRoute(res, m) {
			t.Fatalf("%s became an inventory route; it is meta-surface", m)
		}
	}
	if got, want := len(res.Routes()), 3; got != want {
		t.Fatalf("the crawl produced %d routes, want %d: %v", got, want, c23RoutePaths(res))
	}
	if err := res.AssertNoExcludedPathWasVisited(); err != nil {
		t.Fatalf("AssertNoExcludedPathWasVisited: %v", err)
	}
}

// TestTheExclusionListMatchesBySegmentAndNotBySubstring. A denylist that
// swallows an application route because it shares a spelling with a
// meta-surface one has deleted attack surface, silently, and made coverage
// look better for it.
func TestTheExclusionListMatchesBySegmentAndNotBySubstring(t *testing.T) {
	siblings := []string{
		"/api-docs-internal",
		"/swaggerhub",
		"/playgrounds",
		"/graphiql-users",
		"/openapikeys",
	}
	spider := c23Linking(map[string][]string{
		"/": append(append([]string{}, siblings...), "/api-docs", "/api-docs/v1"),
	})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	for _, s := range siblings {
		if !c23HasRoute(res, s) {
			t.Errorf("%s was excluded. It is a different route that merely shares a "+
				"prefix spelling, and a substring match deletes it from the inventory", s)
		}
	}
	for _, m := range []string{"/api-docs", "/api-docs/v1"} {
		if c23HasRoute(res, m) {
			t.Errorf("%s was crawled; the exclusion must cover the prefix itself and "+
				"everything below it", m)
		}
	}
	if got, want := len(res.Routes()), len(siblings)+1; got != want {
		t.Fatalf("routes=%d, want %d (the seed plus the five siblings): %v",
			got, want, c23RoutePaths(res))
	}
}

// TestTheOperatorExclusionListIsHonouredAndAnUnusableOneIsRefused.
func TestTheOperatorExclusionListIsHonouredAndAnUnusableOneIsRefused(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/": {"/admin", "/admin/users", "/adminish", "/public"},
	})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}), "/admin")

	want := []string{"/", "/adminish", "/public"}
	if got := spider.paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the spider was asked for %v, want %v", got, want)
	}
	if got := c23OutcomeCount(res, CrawlOutcomeMetaSurfaceExcluded); got != 2 {
		t.Fatalf("%d rows say excluded, want 2 (/admin and /admin/users): %v",
			got, c23Ledger(res))
	}

	// An exclusion Anvil cannot apply is REFUSED and not dropped: a dropped
	// exclusion and an honoured one look identical in the output.
	for _, bad := range []string{"", "admin", "../admin", strings.Repeat("/a", 4096)} {
		cfg := c23Config(t, c23Opts{spider: c23Linking(nil)})
		_, err := CrawlWithClientSpider(context.Background(), cfg, mustClock(t),
			[]string{bad})
		if !errors.Is(err, ErrRefused) {
			t.Errorf("exclusion %q was accepted (err=%v)", bad, err)
		}
	}
}

// TestAssertNoExcludedPathWasVisitedCanSeeTheDamage.
//
// The enqueue-time filter decides; the assertion reads back what left. A check
// that cannot see the damage is not a check, so this hands it a ledger in
// which an excluded path WAS fetched and requires it to go red.
func TestAssertNoExcludedPathWasVisitedCanSeeTheDamage(t *testing.T) {
	ex, err := newExclusionSet(nil)
	if err != nil {
		t.Fatalf("newExclusionSet: %v", err)
	}
	clean := CrawlResult{sealed: true, executed: true, exclusions: ex, visits: []CrawlVisit{
		{method: authz.MethodGet, canon: "/orders", outcome: CrawlOutcomeFetched,
			status: 200, sealed: true},
	}}
	if err := clean.AssertNoExcludedPathWasVisited(); err != nil {
		t.Fatalf("a clean ledger failed the assertion: %v", err)
	}

	damaged := clean
	damaged.visits = append(cloneVisits(clean.visits), CrawlVisit{
		method: authz.MethodGet, canon: "/swagger-ui/index.html",
		outcome: CrawlOutcomeFetched, status: 200, sealed: true,
	})
	if err := damaged.AssertNoExcludedPathWasVisited(); !errors.Is(err, ErrExcludedPathWasVisited) {
		t.Fatalf("the assertion returned %v for a ledger showing an excluded path was "+
			"fetched; it must return ErrExcludedPathWasVisited", err)
	}

	// And it must NOT fire on an excluded path that was merely RECORDED as
	// excluded, which is the correct outcome and the common case.
	recorded := clean
	recorded.visits = append(cloneVisits(clean.visits), CrawlVisit{
		method: authz.MethodGet, canon: "/graphiql",
		outcome: CrawlOutcomeMetaSurfaceExcluded, sealed: true,
	})
	if err := recorded.AssertNoExcludedPathWasVisited(); err != nil {
		t.Fatalf("the assertion fired on a correctly-excluded path: %v", err)
	}
}

// ===========================================================================
// TERMINATION — three sites, three different bounds, exact counts
// ===========================================================================

// TestACyclicLinkGraphTerminates. A -> B -> A is the smallest infinite crawl,
// and the visited set is what makes it finite. The assertion is the exact
// request count: a crawler that revisits once before noticing is a crawler
// that revisits n times on a bigger cycle.
func TestACyclicLinkGraphTerminates(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/a": {"/b"},
		"/b": {"/a"},
	})
	res := c23Run(t, c23Config(t, c23Opts{
		seeds: []string{"/a"}, spider: spider, maxPages: 500, maxDepth: 32,
	}))

	if got := spider.paths(); !reflect.DeepEqual(got, []string{"/a", "/b"}) {
		t.Fatalf("the spider was asked for %v; a cycle must be walked exactly once", got)
	}
	if got := res.Issued(); got != 2 {
		t.Fatalf("issued=%d, want 2", got)
	}
	if got := res.Discovered(); got != 3 {
		t.Fatalf("discovered=%d, want 3 (the seed, /b from /a, and /a again from /b). "+
			"The third one is the cycle and it must be SEEN and then not enqueued", got)
	}
	if got := res.Enqueued(); got != 2 {
		t.Fatalf("enqueued=%d, want 2", got)
	}
	// Termination must not have cost budget: the cycle was closed by identity,
	// not by running out.
	if err := res.AssertBudgetSufficed(); err != nil {
		t.Fatalf("a cyclic site exhausted a budget rather than terminating on the "+
			"visited set: %v", err)
	}
}

// TestASelfReferencingPageIsFetchedExactlyOnce. The degenerate cycle, and the
// one a depth bound alone would not catch cheaply.
func TestASelfReferencingPageIsFetchedExactlyOnce(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/loop": {"/loop", "/loop", "/loop", "./loop", "/loop#frag", "/loop?"},
	})
	res := c23Run(t, c23Config(t, c23Opts{seeds: []string{"/loop"}, spider: spider}))

	if got := spider.calls; got != 1 {
		t.Fatalf("the spider was called %d times for a self-referencing page, want 1. "+
			"Six spellings of one address are one address: the fragment does not reach "+
			"the server, \"./loop\" resolves to the same path, and an empty query is "+
			"the same request", got)
	}
	if got := len(res.Routes()); got != 1 {
		t.Fatalf("routes=%d, want 1: %v", got, c23RoutePaths(res))
	}
}

// TestAnInfiniteSiteTerminatesOnTheDepthBudget. Every page mints a fresh
// distinct path, so the visited set never saturates and the depth bound is the
// only thing that stops it.
func TestAnInfiniteSiteTerminatesOnTheDepthBudget(t *testing.T) {
	// A generator, not a table: a fixture that cannot produce the breaking
	// input is the defect. This one is genuinely unbounded.
	spider := &c23Spider{pages: map[string]CrawlPage{}, def: CrawlPage{Status: 200}}
	spider.pages = nil
	gen := &c23Generator{prefix: "/n"}
	res := c23Run(t, c23Config(t, c23Opts{
		seeds: []string{"/n0"}, spider: gen, maxPages: 10000, maxDepth: 4,
	}))

	// Depth 0 is the seed, so a depth budget of 4 admits five levels.
	if got, want := res.Issued(), 5; got != want {
		t.Fatalf("issued=%d, want %d against an infinite site with a depth budget of 4; "+
			"the spider saw %v", got, want, gen.seen)
	}
	if got := res.DeepestReached(); got != 4 {
		t.Fatalf("deepest=%d, want 4", got)
	}
	if got := c23OutcomeCount(res, CrawlOutcomeDepthExceeded); got != 1 {
		t.Fatalf("%d rows say depth_budget_exhausted, want 1: %v", got, c23Ledger(res))
	}
	// The address beyond the budget is NOT dropped. It is surface Anvil saw
	// and did not probe, and dropping it would improve coverage every time the
	// crawl ran short.
	if !c23HasRoute(res, "/n5") {
		t.Fatalf("the address past the depth budget left the inventory: %v",
			c23RoutePaths(res))
	}
	if err := res.AssertBudgetSufficed(); !errors.Is(err, ErrProbeBudgetExhausted) {
		t.Fatalf("AssertBudgetSufficed returned %v; a crawl that ran out of depth "+
			"produced a coverage FLOOR and must say so", err)
	}
}

// c23Generator is an infinite site: /nK links to /n(K+1), forever.
type c23Generator struct {
	prefix string
	seen   []string
}

func (g *c23Generator) FetchPage(_ context.Context, req CrawlRequest) (CrawlPage, error) {
	g.seen = append(g.seen, req.Path())
	n, err := strconv.Atoi(strings.TrimPrefix(req.Path(), g.prefix))
	if err != nil {
		return CrawlPage{Status: 404, Latency: time.Millisecond}, nil
	}
	return CrawlPage{
		Status:  200,
		Latency: time.Millisecond,
		Links:   []string{fmt.Sprintf("%s%d", g.prefix, n+1)},
	}, nil
}

// TestAnInfiniteSiteTerminatesOnThePageBudget, with the depth bound raised out
// of the way so only the page budget can stop it.
func TestAnInfiniteSiteTerminatesOnThePageBudget(t *testing.T) {
	gen := &c23Generator{prefix: "/n"}
	res := c23Run(t, c23Config(t, c23Opts{
		seeds: []string{"/n0"}, spider: gen, maxPages: 6, maxDepth: 32,
	}))

	if got := res.Issued(); got != 6 {
		t.Fatalf("issued=%d, want exactly the budget of 6; the spider saw %v",
			got, gen.seen)
	}
	if got := c23OutcomeCount(res, CrawlOutcomePageBudgetExhausted); got != 1 {
		t.Fatalf("%d rows say page_budget_exhausted, want 1: %v", got, c23Ledger(res))
	}
	if got, want := len(res.Routes()), 7; got != want {
		t.Fatalf("routes=%d, want %d: the six fetched addresses plus the one the budget "+
			"did not reach, which stays in the denominator: %v",
			got, want, c23RoutePaths(res))
	}
	if err := res.AssertBudgetSufficed(); !errors.Is(err, ErrProbeBudgetExhausted) {
		t.Fatalf("AssertBudgetSufficed returned %v", err)
	}
}

// TestACrawlBudgetThatIsNotConfiguredIsRefused. A Go zero must never mean
// "unlimited" for either bound.
func TestACrawlBudgetThatIsNotConfiguredIsRefused(t *testing.T) {
	for _, c := range []struct {
		name              string
		pages, depth      int
		wantSubstringPart string
	}{
		{"zero pages", 0, 4, "page budget"},
		{"negative pages", -1, 4, "page budget"},
		{"pages over the ceiling", codedMaxCrawlPages + 1, 4, "page budget"},
		{"zero depth", 10, 0, "depth budget"},
		{"depth over the ceiling", 10, codedMaxCrawlDepth + 1, "depth budget"},
	} {
		cfg := c23Config(t, c23Opts{spider: c23Linking(nil)})
		cfg.MaxPages = c.pages
		cfg.MaxDepth = c.depth
		_, err := CrawlWithClientSpider(context.Background(), cfg, mustClock(t), nil)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: err=%v, want ErrRefused", c.name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.wantSubstringPart) {
			t.Errorf("%s: the refusal does not name the budget: %v", c.name, err)
		}
		if cfg.Constructed() {
			t.Errorf("%s: Constructed() says yes and MergeAndConfirm's equivalent says "+
				"no; the two must not disagree", c.name)
		}
	}
}

// TestASeedlessCrawlIsRefused. A crawl with no seed reaches nothing and
// reports a target with no link graph; those are two different findings.
func TestASeedlessCrawlIsRefused(t *testing.T) {
	cfg := c23Config(t, c23Opts{spider: c23Linking(nil)})
	cfg.Seeds = nil
	if _, err := CrawlWithClientSpider(context.Background(), cfg, mustClock(t), nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("err=%v, want ErrRefused", err)
	}
}

// ===========================================================================
// THE WALK-OFF — gate 13, and the redirect label this file supplies
// ===========================================================================

// TestALinkOffTheAdmittedOriginIsRefusedAtTheLink.
//
// The crawler cannot construct a Target for another host — authz.NewTarget
// needs a pinned address, and a crawl resolves no names — so the walk-off is
// refused before a request exists rather than at the socket. The assertion is
// what LEFT: the spider's own record.
func TestALinkOffTheAdmittedOriginIsRefusedAtTheLink(t *testing.T) {
	offHost := []string{
		"https://evil.example.com/steal",
		"https://evil.example.com./steal",
		"https://EVIL.example.com/steal",
		"//evil.example.com/steal",
		"http://" + fixtureHost + "/downgrade",
		"https://" + fixtureHost + ":8443/otherport",
		"https://user:pass@evil.example.com/creds",
	}
	spider := c23Linking(map[string][]string{
		"/": append(append([]string{}, offHost...), "/stay"),
	})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	if got := spider.paths(); !reflect.DeepEqual(got, []string{"/", "/stay"}) {
		t.Fatalf("the spider was asked for %v; nothing off the admitted origin may leave",
			got)
	}
	if got, want := c23OutcomeCount(res, CrawlOutcomeOffHost), len(offHost); got != want {
		t.Fatalf("%d rows say link_points_off_the_admitted_origin, want %d: %v",
			got, want, c23Ledger(res))
	}
	// An off-host address is not this target's surface, so it must not enter
	// this target's denominator either.
	if got, want := len(res.Routes()), 2; got != want {
		t.Fatalf("routes=%d, want %d: %v", got, want, c23RoutePaths(res))
	}
}

// TestALinkThatIsNotARequestIsRefused: mailto:, javascript:, data: and the
// rest of what a page can legally put in an href.
func TestALinkThatIsNotARequestIsRefused(t *testing.T) {
	junk := []string{
		"mailto:security@example.com",
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
		"tel:+15550100",
		"ftp://" + fixtureHost + "/pub",
		"",
		"   ",
		strings.Repeat("/a", codedMaxLinkBytes),
		"/cafééé/\x00",
		"/:id/edit",
		"/*/edit",
	}
	spider := c23Linking(map[string][]string{"/": append(append([]string{}, junk...), "/ok")})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	if got := spider.paths(); !reflect.DeepEqual(got, []string{"/", "/ok"}) {
		t.Fatalf("the spider was asked for %v, want [/ /ok]", got)
	}
	unusable := c23OutcomeCount(res, CrawlOutcomeLinkUnusable) +
		c23OutcomeCount(res, CrawlOutcomeOffHost)
	if unusable != len(junk) {
		t.Fatalf("%d of %d junk links were recorded as unusable or off-host: %v",
			unusable, len(junk), c23Ledger(res))
	}
}

// TestABraceSegmentInALinkIsAnAddressAndNotATemplate.
//
// MEASURED, and the opposite of what the author expected: "/{id}/edit" in an
// href is percent-encoded by URL resolution to "/%7Bid%7D/edit" before D.20's
// canonicalizer ever sees it, so it is a concrete address and it is crawled.
// "/:id/edit" is NOT escaped, the canonicalizer rewrites it to "/{id}/edit",
// and it is refused — because requesting a template is requesting a path
// nobody published, and filing one spelling under another puts two rows in the
// denominator.
//
// The distinction is recorded as a test rather than left to be rediscovered.
func TestABraceSegmentInALinkIsAnAddressAndNotATemplate(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/": {"/{id}/edit", "/:id/edit"},
	})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	want := []string{"/", "/%7Bid%7D/edit"}
	if got := spider.paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the spider was asked for %v, want %v", got, want)
	}
	if c23HasRoute(res, "/{id}/edit") {
		t.Fatal("a templated path became a crawl route; D.22 would key it as a template " +
			"the crawl never requested")
	}
	if got := c23OutcomeCount(res, CrawlOutcomeLinkUnusable); got != 1 {
		t.Fatalf("%d rows say link_is_not_a_requestable_path, want 1: %v",
			got, c23Ledger(res))
	}
}

// TestARedirectIsReAdmittedAsALabelledHop is what internal/dast/engines/zap.go
// records as MISSING for a proxied ZAP, supplied here for the crawl's own
// requests.
//
// The assertion is on the LABEL, not only on the destination: a follow-up that
// arrives as `initial` at hop 0 reaches the same place and carries no depth to
// bound.
func TestARedirectIsReAdmittedAsALabelledHop(t *testing.T) {
	spider := &c23Spider{
		pages: map[string]CrawlPage{
			"/old": {Status: 302, Location: "/new"},
			"/new": {Status: 200, Links: []string{"/leaf"}},
		},
		def: CrawlPage{Status: 200},
	}
	res := c23Run(t, c23Config(t, c23Opts{seeds: []string{"/old"}, spider: spider}))

	want := []string{"/old@initial/0", "/new@redirect/1", "/leaf@initial/0"}
	if got := spider.labels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the spider saw %v, want %v. authz.RefuseAllRedirects names the owner "+
			"of the label: \"the egress layer records the hop, and a same-host hop is "+
			"re-issued as a fresh request with OriginRedirect and Hop+1\"", got, want)
	}
	if got := c23Visit(t, res, "/old").Outcome(); got != CrawlOutcomeRedirected {
		t.Fatalf("/old came out %s, want %s", got, CrawlOutcomeRedirected)
	}
	if got := c23Visit(t, res, "/new").Hop(); got != 1 {
		t.Fatalf("the ledger records /new at hop %d, want 1", got)
	}
}

// TestARedirectChainIsBoundedByTheKernelsHopBound.
//
// The bound is authz's own const, reached by LABELLING the hop, and this file
// holds no copy of it. The seventh request in the chain is refused by
// authz.NewRequestIntent before any gate runs, so the chain stops at hop 5.
func TestARedirectChainIsBoundedByTheKernelsHopBound(t *testing.T) {
	pages := map[string]CrawlPage{}
	for i := 0; i < 12; i++ {
		pages[fmt.Sprintf("/r%d", i)] = CrawlPage{
			Status: 301, Location: fmt.Sprintf("/r%d", i+1),
		}
	}
	spider := &c23Spider{pages: pages, def: CrawlPage{Status: 200}}
	res := c23Run(t, c23Config(t, c23Opts{
		seeds: []string{"/r0"}, spider: spider, maxPages: 100, maxDepth: 32,
	}))

	// /r0 at hop 0, then /r1../r5 at hops 1..5. /r6 would be hop 6.
	var maxHop int
	for _, r := range spider.seen {
		if r.Hop() > maxHop {
			maxHop = r.Hop()
		}
	}
	if maxHop != 5 {
		t.Fatalf("the deepest hop issued was %d, want 5; the spider saw %v",
			maxHop, spider.labels())
	}
	if got := spider.calls; got != 6 {
		t.Fatalf("the spider was called %d times, want 6 (/r0 plus five hops)", got)
	}
	v := c23Visit(t, res, "/r6")
	if v.Outcome() != CrawlOutcomeIntentRejected {
		t.Fatalf("/r6 came out %s, want %s -- the kernel refuses hop 6 at "+
			"NewRequestIntent", v.Outcome(), CrawlOutcomeIntentRejected)
	}
	// And the bound really is the kernel's: there is no local constant to
	// raise. The check is on IDENTIFIERS and not on the source text, because
	// this file's header discusses authz.maxRedirectHops by name in prose and
	// a substring guard would be satisfied by that comment.
	file, _ := parseOwnSource(t, "tier3_crawl.go")
	idents := 0
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		idents++
		low := strings.ToLower(id.Name)
		if strings.Contains(low, "redirecthop") || strings.Contains(low, "maxhop") {
			t.Errorf("tier3_crawl.go declares or uses the identifier %q, which means it "+
				"holds an opinion about a bound authz owns", id.Name)
		}
		return true
	})
	if idents == 0 {
		t.Fatal("the identifier scanner saw nothing, so its clean result is worthless")
	}
}

// TestACrossHostRedirectIsRefused. Gate 13 refuses a cross-host hop OUTRIGHT,
// and this file refuses it one step earlier by never resolving the name.
func TestACrossHostRedirectIsRefused(t *testing.T) {
	spider := &c23Spider{
		pages: map[string]CrawlPage{
			"/go": {Status: 302, Location: "https://evil.example.com/land"},
		},
		def: CrawlPage{Status: 200},
	}
	res := c23Run(t, c23Config(t, c23Opts{seeds: []string{"/go"}, spider: spider}))

	if got := spider.paths(); !reflect.DeepEqual(got, []string{"/go"}) {
		t.Fatalf("the spider was asked for %v; the cross-host Location must never be "+
			"requested. This is ZAP issue #2546, which gate 13 is named after", got)
	}
	if got := c23OutcomeCount(res, CrawlOutcomeOffHost); got != 1 {
		t.Fatalf("%d rows say off-host, want 1: %v", got, c23Ledger(res))
	}
}

// ===========================================================================
// THE KERNEL IS THE ONLY DECIDER
// ===========================================================================

// TestEveryRequestIsAdmittedThroughTheKernelAndAudited.
//
// The measurement is the audit sink's row COUNT, not that rows exist: a
// crawler that admitted six requests and wrote one row would pass a
// len(rows)>0 check.
func TestEveryRequestIsAdmittedThroughTheKernelAndAudited(t *testing.T) {
	gov, audit, sink := c22Kernel(t, c22KernelOpts{})
	auth, _ := mintAuthorization(t)
	spider := c23Linking(map[string][]string{
		"/": {"/a", "/b"}, "/a": {"/c"},
	})
	before := sink.n
	cfg := CrawlConfig{
		Trigger: ScanTriggerScheduledFull, Governor: gov, Audit: audit,
		Authorization: auth, Target: mustBareTarget(t), Scope: c23NarrowedScope(t, ""),
		Technique: authz.TechniqueContentDiscovery, Seeds: []string{"/"},
		MaxPages: 20, MaxDepth: 4, Spider: spider,
		Clock: c22Advancing(t, time.Second),
	}
	res := c23Run(t, cfg)

	if res.Issued() != 4 {
		t.Fatalf("issued=%d, want 4", res.Issued())
	}
	// One admission row and one observation row per issued request, at least.
	if got, want := sink.n-before, 2*res.Issued(); got < want {
		t.Fatalf("the audit sink took %d rows for %d issued requests; want at least %d "+
			"(an admission and an observation each). Gate 21 makes the write part of "+
			"the decision", got, res.Issued(), want)
	}
	for _, v := range res.Visits() {
		if v.Outcome().Issued() && v.AuditSeq() == 0 {
			t.Fatalf("%s was issued and carries audit sequence 0, so it cannot be joined "+
				"back to who authorized it", v)
		}
	}
}

// TestAScopeNobodyNarrowedPermitsNoPath is gate 11's fail-closed half.
//
// "Nobody determined this origin's robots.txt" and "robots.txt permitted this
// path" produce the same silence and opposite conclusions.
// Scope.PermitsPath's own doc records two incidents in this repository where
// the first was read as the second; this asserts the crawl gets the fail-closed
// answer.
func TestAScopeNobodyNarrowedPermitsNoPath(t *testing.T) {
	raw, err := initiateRun(t).Scope()
	if err != nil {
		t.Fatalf("init.Scope: %v", err)
	}
	if raw.Narrowed() {
		t.Fatal("the fixture scope arrived already narrowed, so this test proves nothing")
	}
	spider := c23Linking(map[string][]string{"/": {"/a", "/b"}})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider, scope: &raw}))

	if spider.calls != 0 {
		t.Fatalf("the spider was called %d times against a scope nobody narrowed; a "+
			"scope with no robots determination permits no path at all", spider.calls)
	}
	if got := c23OutcomeCount(res, CrawlOutcomeOutsideNarrowedScope); got != 1 {
		t.Fatalf("%d rows say outside_the_narrowed_scope, want 1 (the seed; nothing "+
			"below it was ever discovered): %v", got, c23Ledger(res))
	}
	// And the same configuration WITH the narrowing crawls, so the difference
	// is the narrowing and not something else about the fixture.
	spider2 := c23Linking(map[string][]string{"/": {"/a", "/b"}})
	if res2 := c23Run(t, c23Config(t, c23Opts{spider: spider2})); res2.Issued() != 3 {
		t.Fatalf("with the scope narrowed, issued=%d, want 3", res2.Issued())
	}
}

// TestGate11RemovesAPathAndTheCrawlDoesNotVisitIt.
//
// Both halves of gate 11 are in the path here: the SCOPE narrowing this file
// consults with Scope.PermitsPath, and the per-request CheckGate11RobotsDeny
// the Governor runs. The scope narrowing refuses first, which is why the
// ledger says outside_the_narrowed_scope rather than kernel_refused.
func TestGate11RemovesAPathAndTheCrawlDoesNotVisitIt(t *testing.T) {
	const body = "User-agent: *\nDisallow: /private\n"
	policy := authz.ParseRobotsTxt(fixtureHost, 443, []byte(body))
	if policy.PermitsPath("/private") {
		t.Fatal("the fixture robots.txt does not actually disallow /private")
	}
	spider := c23Linking(map[string][]string{
		"/": {"/private", "/private/keys", "/public"},
	})
	res := c23Run(t, c23Config(t, c23Opts{
		spider: spider, robots: body, robotsPol: &policy,
	}))

	if got := spider.paths(); !reflect.DeepEqual(got, []string{"/", "/public"}) {
		t.Fatalf("the spider was asked for %v; a path robots.txt removes must never "+
			"leave", got)
	}
	if got := c23OutcomeCount(res, CrawlOutcomeOutsideNarrowedScope); got != 2 {
		t.Fatalf("%d rows say outside_the_narrowed_scope, want 2: %v",
			got, c23Ledger(res))
	}
	// A path removed from SCOPE is not this crawl's surface, so it is not in
	// the crawl's inventory.
	if c23HasRoute(res, "/private") {
		t.Fatal("a path gate 11 removed from scope became a crawl route")
	}
}

// TestGate14RefusesTheCrawlOverflowWhenTheClockDoesNotAdvance. A crawl is precisely
// the workload that discovers gate 14's caps are real, and a frozen clock is
// how a run discovers it in the worst way.
func TestGate14RefusesTheCrawlOverflowWhenTheClockDoesNotAdvance(t *testing.T) {
	const n = 16
	links := make([]string, 0, n)
	for i := 0; i < n; i++ {
		links = append(links, fmt.Sprintf("/p%02d", i))
	}
	spider := c23Linking(map[string][]string{"/": links})
	res := c23Run(t, c23Config(t, c23Opts{
		spider: spider, maxPages: n + 1, freezeTime: true,
	}))

	want := authz.CodedMaxRequestsPerSecondPerHost
	if got := res.Answered(); got != want {
		t.Fatalf("answered=%d, want %d -- the token bucket holds exactly that many and "+
			"a frozen clock never refills it", got, want)
	}
	if got := c23OutcomeCount(res, CrawlOutcomeKernelRefused); got != n+1-want {
		t.Fatalf("%d rows say kernel_refused, want %d: %v", got, n+1-want, c23Ledger(res))
	}
	// Nothing is dropped: every address is still in the denominator.
	if got := len(res.Routes()); got != n+1 {
		t.Fatalf("routes=%d, want %d", got, n+1)
	}

	// The same fixture with an advancing clock reaches every address, so the
	// difference is Anvil's clock handling and nothing about the target.
	spider2 := c23Linking(map[string][]string{"/": links})
	res2 := c23Run(t, c23Config(t, c23Opts{spider: spider2, maxPages: n + 1}))
	if res2.Answered() != n+1 {
		t.Fatalf("with an advancing clock answered=%d, want %d", res2.Answered(), n+1)
	}
}

// TestTheObservationIsFedBackToTheKernel. A crawl that admits through the
// kernel and never tells the kernel what happened has no circuit breaker: gate
// 16 and gate 17 learn only from Governor.ObserveResponse.
func TestTheObservationIsFedBackToTheKernel(t *testing.T) {
	spider := &c23Spider{
		pages: map[string]CrawlPage{
			"/": {Status: 429, Links: []string{"/a", "/b", "/c"}},
		},
		def: CrawlPage{Status: 200},
	}
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	if got := c23OutcomeCount(res, CrawlOutcomeKernelRefused); got == 0 {
		t.Fatalf("a 429 on the seed refused nothing afterwards, so the observation is "+
			"not reaching gate 17: %v", c23Ledger(res))
	}
	if spider.calls != 1 {
		t.Fatalf("the spider was called %d times after a 429; the crawl must stop rather "+
			"than drive the budget into a target that is already saying no", spider.calls)
	}
}

// TestTheKernelValidatesTheCrawlPathRatherThanASecondValidator.
func TestTheKernelValidatesTheCrawlPathRatherThanASecondValidator(t *testing.T) {
	// A path the kernel refuses on its charset rule, offered as a seed.
	cfg := c23Config(t, c23Opts{
		spider: c23Linking(nil),
		seeds:  []string{"/ok", "/bad\x7f", "/bad\tspace"},
	})
	res := c23Run(t, cfg)
	if got := c23OutcomeCount(res, CrawlOutcomeLinkUnusable); got != 2 {
		t.Fatalf("%d seeds were refused, want 2: %v", got, c23Ledger(res))
	}
	if !c23HasRoute(res, "/ok") {
		t.Fatal("the legal seed was refused too, so the guard is refusing everything")
	}
}

// ===========================================================================
// THE NUMERATOR — ruling 7
// ===========================================================================

// TestEveryCrawlRouteIsACandidateEvenWhenTheTargetAnswered200.
//
// The crawl fetched these addresses and the target answered 200 to a request
// the kernel admitted. They are STILL candidates: there is one writer of
// ConfirmationConfirmed in this package and it is D.22's, because a second one
// is a second numerator.
func TestEveryCrawlRouteIsACandidateEvenWhenTheTargetAnswered200(t *testing.T) {
	spider := c23Linking(map[string][]string{"/": {"/a", "/b"}})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	if res.Answered() != 3 {
		t.Fatalf("answered=%d, want 3; without a real 200 this test proves nothing",
			res.Answered())
	}
	if len(res.Routes()) != 3 {
		t.Fatalf("routes=%d, want 3", len(res.Routes()))
	}
	for _, r := range res.Routes() {
		if r.Confirmation() != ConfirmationCandidate {
			t.Fatalf("%s %s is %q", r.Method(), r.Path(), r.Confirmation())
		}
		if r.Provenance() != record.InventoryProvenanceCrawl {
			t.Fatalf("%s %s carries provenance %q", r.Method(), r.Path(), r.Provenance())
		}
		if r.Trust() != record.TrustUntrusted {
			t.Fatalf("%s %s carries trust %q", r.Method(), r.Path(), r.Trust())
		}
	}
	if err := res.AssertEveryRouteIsACandidate(); err != nil {
		t.Fatalf("AssertEveryRouteIsACandidate: %v", err)
	}
}

// TestConfirmedIsNeverWrittenInThisTier reads the source. The identifier does
// not appear, and the scanner proves it can see identifiers that do.
func TestConfirmedIsNeverWrittenInThisTier(t *testing.T) {
	file, fset := parseOwnSource(t, "tier3_crawl.go")
	var confirmed []int
	candidates := 0
	idents := 0
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		idents++
		switch id.Name {
		case "ConfirmationConfirmed":
			confirmed = append(confirmed, fset.Position(id.Pos()).Line)
		case "ConfirmationCandidate":
			candidates++
		}
		return true
	})
	if idents == 0 {
		t.Fatal("the scanner found no identifiers at all, so it could not have found a " +
			"violation either")
	}
	if len(confirmed) != 0 {
		t.Fatalf("ConfirmationConfirmed appears at lines %v in tier3_crawl.go. Tier 3 "+
			"discovers candidates; D.22 confirms them", confirmed)
	}
	if candidates == 0 {
		t.Fatal("the scanner found zero uses of ConfirmationCandidate, which the file " +
			"certainly contains, so its negative result above is worthless")
	}
}

// TestCrawlRoutesFeedD22AndOnlyD22Confirms drives the real handoff: the crawl
// produces candidates, MergeAndConfirm probes them, and the confirmation
// carries an Observation with a gate-21 audit sequence.
func TestCrawlRoutesFeedD22AndOnlyD22Confirms(t *testing.T) {
	spider := c23Linking(map[string][]string{"/": {"/a", "/gone"}})
	crawl := c23Run(t, c23Config(t, c23Opts{spider: spider}))
	if len(crawl.Routes()) != 3 {
		t.Fatalf("the crawl produced %d routes, want 3", len(crawl.Routes()))
	}

	prober := c22Answering(200, map[string]int{"/gone": 404})
	res := c22Run(t, c22Confirming(t, prober, 10), crawl.Routes())

	if got := res.EndpointCount(); got != 3 {
		t.Fatalf("the union is %d endpoints, want 3", got)
	}
	if got := res.ConfirmedCount(); got != 2 {
		t.Fatalf("confirmed=%d, want 2 (/ and /a; /gone answered 404)", got)
	}
	mix := res.InventoryProvenanceMix()
	if mix[record.InventoryProvenanceCrawl] != 3 {
		t.Fatalf("the provenance mix is %v; every endpoint came from the crawl", mix)
	}
	if err := res.AssertEveryConfirmationHasEvidence(); err != nil {
		t.Fatalf("AssertEveryConfirmationHasEvidence: %v", err)
	}
	e := c22Endpoint(t, res, authz.MethodGet, "/a")
	obs, ok := e.Observation()
	if !ok || !obs.Recorded() || obs.AuditSeq() == 0 {
		t.Fatalf("/a is confirmed and its observation is %v", obs)
	}
}

// TestAssertEveryRouteIsACandidateCanSeeTheDamage. A guard that has never
// failed has not been tested.
func TestAssertEveryRouteIsACandidateCanSeeTheDamage(t *testing.T) {
	good, err := NewRoute(RouteFacts{
		Method: authz.MethodGet, Path: "/a", Target: mustBareTarget(t),
		Provenance: record.InventoryProvenanceCrawl, Confirmation: ConfirmationCandidate,
		Trust: record.TrustUntrusted,
	})
	if err != nil {
		t.Fatalf("NewRoute: %v", err)
	}
	clean := CrawlResult{sealed: true, executed: true, routes: []Route{good}}
	if err := clean.AssertEveryRouteIsACandidate(); err != nil {
		t.Fatalf("a clean result failed: %v", err)
	}

	// A route that claims confirmation.
	claimed, err := NewRoute(RouteFacts{
		Method: authz.MethodGet, Path: "/a", Target: mustBareTarget(t),
		Provenance: record.InventoryProvenanceCrawl, Confirmation: ConfirmationConfirmed,
		Trust: record.TrustUntrusted,
	})
	if err != nil {
		t.Fatalf("NewRoute: %v", err)
	}
	bad := CrawlResult{sealed: true, executed: true, routes: []Route{claimed}}
	if err := bad.AssertEveryRouteIsACandidate(); !errors.Is(err, ErrRouteClaimsConfirmed) {
		t.Fatalf("err=%v, want ErrRouteClaimsConfirmed", err)
	}

	// And a route whose provenance is not the crawl's.
	wrongProv, err := NewRoute(RouteFacts{
		Method: authz.MethodGet, Path: "/a", Target: mustBareTarget(t),
		Provenance: record.InventoryProvenanceRuntimeSpec, Confirmation: ConfirmationCandidate,
		Trust: record.TrustUntrusted,
	})
	if err != nil {
		t.Fatalf("NewRoute: %v", err)
	}
	bad2 := CrawlResult{sealed: true, executed: true, routes: []Route{wrongProv}}
	if err := bad2.AssertEveryRouteIsACandidate(); !errors.Is(err, ErrRefused) {
		t.Fatalf("err=%v, want ErrRefused", err)
	}
}

// ===========================================================================
// THE SEAM'S ABSENCE
// ===========================================================================

// TestTheToolAbsentPathRefusesLoudly. This host has no ZAP, so it has no
// Client Spider, and SystemClientSpider says so by CALLING D.15 rather than by
// asserting what D.15 would say.
func TestTheToolAbsentPathRefusesLoudly(t *testing.T) {
	spider, err := SystemClientSpider()
	if err == nil {
		t.Fatal("SystemClientSpider returned no error. A no-op spider that reported an " +
			"empty link graph is exactly the silent-clean failure this tier is written " +
			"against")
	}
	if spider != nil {
		t.Fatalf("SystemClientSpider returned a spider alongside an error: %v", spider)
	}
	if !errors.Is(err, ErrNoClientSpider) {
		t.Fatalf("err=%v, want ErrNoClientSpider", err)
	}
	// The refusal is D.15's own, unwrapped, so a host that GROWS a ZAP runner
	// changes this answer rather than leaving a stale string behind.
	if !errors.Is(err, engines.ErrEngineUnavailable) {
		t.Fatalf("err=%v does not unwrap to engines.ErrEngineUnavailable, so it is not "+
			"reporting what engines.SystemZapRunner actually said", err)
	}
}

// TestANilSpiderIsALoudRefusalAndNotAnEmptyLinkGraph. It must also not spend
// the kernel's rate budget or write a gate-21 row for a request that cannot
// leave: an audit log claiming requests Anvil never issued is worse than none.
func TestANilSpiderIsALoudRefusalAndNotAnEmptyLinkGraph(t *testing.T) {
	gov, audit, sink := c22Kernel(t, c22KernelOpts{})
	auth, _ := mintAuthorization(t)
	before := sink.n
	cfg := CrawlConfig{
		Trigger: ScanTriggerScheduledFull, Governor: gov, Audit: audit,
		Authorization: auth, Target: mustBareTarget(t), Scope: c23NarrowedScope(t, ""),
		Technique: authz.TechniqueContentDiscovery, Seeds: []string{"/", "/a"},
		MaxPages: 10, MaxDepth: 4,
		// Spider is nil.
	}
	res, err := CrawlWithClientSpider(context.Background(), cfg, mustClock(t), nil)
	if !errors.Is(err, ErrNoClientSpider) {
		t.Fatalf("err=%v, want ErrNoClientSpider", err)
	}
	if !res.Executed() {
		t.Fatal("the crawl was eligible and reported that it did not execute; the two " +
			"failures must stay distinguishable")
	}
	if res.Issued() != 0 {
		t.Fatalf("issued=%d with no spider", res.Issued())
	}
	if got := sink.n - before; got != 0 {
		t.Fatalf("the audit sink took %d rows for requests that could not leave the "+
			"process", got)
	}
	// The seeds are still in the inventory: their absence is a fact about
	// Anvil, and a shorter inventory would report better coverage for it.
	if got := len(res.Routes()); got != 2 {
		t.Fatalf("routes=%d, want 2: %v", got, c23RoutePaths(res))
	}
	if got := c23OutcomeCount(res, CrawlOutcomeFetchFailed); got != 2 {
		t.Fatalf("%d rows say fetch_failed, want 2: %v", got, c23Ledger(res))
	}
}

// TestASpiderThatReturnsNothingIsNotAnAnswer. Status 0 is non-404, so without
// the bound a lost response would look like a page that exists.
func TestASpiderThatReturnsNothingIsNotAnAnswer(t *testing.T) {
	for _, status := range []int{0, -1, 99, 600, 1000} {
		spider := &c23Spider{
			def:   CrawlPage{Status: status, Latency: time.Millisecond},
			exact: true,
		}
		res := c23Run(t, c23Config(t, c23Opts{spider: spider}))
		if res.Answered() != 0 {
			t.Errorf("status %d was counted as an answer", status)
		}
		if got := c23OutcomeCount(res, CrawlOutcomeFetchFailed); got != 1 {
			t.Errorf("status %d produced %d fetch_failed rows, want 1", status, got)
		}
		if err := res.AssertNotSilentlyEmpty(); !errors.Is(err, ErrCrawlFoundNothing) {
			t.Errorf("status %d: AssertNotSilentlyEmpty returned %v, want "+
				"ErrCrawlFoundNothing", status, err)
		}
	}
}

// TestASpiderErrorIsCountedAndDoesNotStopTheCrawl.
func TestASpiderErrorIsCountedAndDoesNotStopTheCrawl(t *testing.T) {
	spider := &c23Spider{err: errors.New("the browser died")}
	res := c23Run(t, c23Config(t, c23Opts{spider: spider, seeds: []string{"/a", "/b"}}))
	if got := c23OutcomeCount(res, CrawlOutcomeFetchFailed); got != 2 {
		t.Fatalf("%d rows say fetch_failed, want 2: %v", got, c23Ledger(res))
	}
	if got := len(res.Refusals()); got != 2 {
		t.Fatalf("%d refusals, want 2", got)
	}
	if err := res.AssertNotSilentlyEmpty(); !errors.Is(err, ErrCrawlFoundNothing) {
		t.Fatalf("err=%v, want ErrCrawlFoundNothing", err)
	}
}

// ===========================================================================
// SHAPE, DETERMINISM AND COPIES
// ===========================================================================

// TestTheQueryIsRequestedAndTheAddressIsNot. "/search?q=1" and "/search?q=2"
// are ONE endpoint with a parameter; two rows would inflate the denominator.
// But the crawl must still REQUEST the query, or it fetches a page the link
// did not point at.
func TestTheQueryIsRequestedAndTheAddressIsNot(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/": {"/search?q=1", "/search?q=2&lang=en", "/search"},
	})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))

	if got := spider.paths(); !reflect.DeepEqual(got, []string{"/", "/search?q=1"}) {
		t.Fatalf("the spider was asked for %v; the first spelling is requested WITH its "+
			"query and the later ones are the same address", got)
	}
	want := []string{"/", "/search"}
	if got := c23RoutePaths(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes=%v, want %v", got, want)
	}
	for _, r := range res.Routes() {
		if r.Path() != "/search" {
			continue
		}
		if len(r.Params()) != 1 || r.Params()[0].Name != "q" ||
			r.Params()[0].In != ParamInQuery {
			t.Fatalf("/search carries params %v, want exactly one query parameter \"q\"",
				r.Params())
		}
		if r.Params()[0].Typed() {
			t.Fatal("a crawl cannot know a parameter's type, and claiming one makes " +
				"Param.Typed() lie")
		}
	}
}

// TestCrawlOutputIsDeterministic. Two runs over one fixture produce one
// ledger, one route list and one refusal list.
func TestCrawlOutputIsDeterministic(t *testing.T) {
	graph := map[string][]string{
		"/":    {"/z", "/a", "/m", "/swagger-ui", "mailto:x@y"},
		"/a":   {"/a/1", "/a/2"},
		"/z":   {"/a"},
		"/a/1": {"/"},
	}
	render := func() ([]string, []string) {
		res := c23Run(t, c23Config(t, c23Opts{spider: c23Linking(graph)}))
		return c23Ledger(res), c23RoutePaths(res)
	}
	l1, r1 := render()
	l2, r2 := render()
	if !reflect.DeepEqual(l1, l2) {
		t.Fatalf("the ledger differs between runs:\n%v\n%v", l1, l2)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("the route list differs between runs:\n%v\n%v", r1, r2)
	}
	if len(l1) == 0 || len(r1) == 0 {
		t.Fatal("the fixture produced nothing, so determinism over it is vacuous")
	}
}

// TestCrawlResultAccessorsReturnDeepCopies mutates EVERY returned slice and
// the Params inside a returned Route.
//
// A test that mutates only the field where the copy is real proves nothing; a
// Route's params are a separate allocation from the Route, so they are the
// field a shallow copy leaves shared.
func TestCrawlResultAccessorsReturnDeepCopies(t *testing.T) {
	spider := c23Linking(map[string][]string{
		"/": {"/a?x=1", "/broken", "mailto:z@y"},
	})
	spider.errPaths = map[string]error{"/broken": errors.New("the browser died")}
	res := c23Run(t, c23Config(t, c23Opts{spider: spider}))
	if len(res.Routes()) == 0 || len(res.Visits()) == 0 || len(res.Refusals()) == 0 {
		t.Fatalf("the fixture left one of the three lists empty (%d routes, %d visits, "+
			"%d refusals), so mutating it would prove nothing",
			len(res.Routes()), len(res.Visits()), len(res.Refusals()))
	}

	routes := res.Routes()
	routes[0] = Route{}
	visits := res.Visits()
	visits[0] = CrawlVisit{}
	refusals := res.Refusals()
	refusals[0] = Refusal{}
	unreached := res.Unreached()
	if len(unreached) > 0 {
		unreached[0] = CrawlVisit{}
	}

	// The parameter slice inside a route, which is where a shallow copy hides.
	var target Route
	for _, r := range res.Routes() {
		if len(r.Params()) > 0 {
			target = r
			break
		}
	}
	if !target.Constructed() {
		t.Fatal("no returned route carries a parameter, so the deep half of this test " +
			"is vacuous")
	}
	ps := target.Params()
	ps[0].Name = "clobbered"
	ps[0].In = ParamInBody

	after := res.Routes()
	if !after[0].Constructed() {
		t.Fatal("Routes() shares its backing array with the result")
	}
	if !res.Visits()[0].Recorded() {
		t.Fatal("Visits() shares its backing array with the result")
	}
	if !res.Refusals()[0].Valid() {
		t.Fatal("Refusals() shares its backing array with the result")
	}
	for _, r := range res.Routes() {
		for _, p := range r.Params() {
			if p.Name == "clobbered" || p.In == ParamInBody {
				t.Fatal("a route's parameter slice is shared with the caller, so a " +
					"reader can rewrite the inventory it was handed")
			}
		}
	}
}

// TestEveryCrawlOutcomeIsRecognisedAndClassified. An outcome nobody enumerated
// would silently be neither issued nor in the inventory.
func TestEveryCrawlOutcomeIsRecognisedAndClassified(t *testing.T) {
	if len(CrawlOutcomeValues()) == 0 {
		t.Fatal("there are no outcomes")
	}
	issued := 0
	inInventory := 0
	for _, o := range CrawlOutcomeValues() {
		if !o.Recognised() {
			t.Errorf("%q is in CrawlOutcomeValues and is not Recognised", o)
		}
		if o.Issued() {
			issued++
			if !o.InInventory() {
				t.Errorf("%q means a request LEFT and yet is not in the inventory", o)
			}
		}
		if o.InInventory() {
			inInventory++
		}
	}
	if issued != 3 {
		t.Fatalf("%d outcomes mean a request was issued, want 3 (fetched, redirected, "+
			"fetch_failed)", issued)
	}
	if inInventory == 0 || inInventory == len(CrawlOutcomeValues()) {
		t.Fatalf("%d of %d outcomes are in the inventory; a partition that is empty or "+
			"total is not a partition", inInventory, len(CrawlOutcomeValues()))
	}
	// The zero value is neither.
	if CrawlOutcomeUnset.Recognised() || CrawlOutcomeUnset.Issued() ||
		CrawlOutcomeUnset.InInventory() {
		t.Fatal("the zero CrawlOutcome is classified as something")
	}
	if CrawlOutcome("invented").Recognised() {
		t.Fatal("an invented outcome is recognised")
	}
}

// TestTheZeroCrawlResultClaimsNothing.
func TestTheZeroCrawlResultClaimsNothing(t *testing.T) {
	var z CrawlResult
	if z.Constructed() || z.Executed() || len(z.Routes()) != 0 || z.Issued() != 0 {
		t.Fatal("the zero CrawlResult claims something")
	}
	if err := z.AssertNotSilentlyEmpty(); !errors.Is(err, ErrCrawlDidNotRun) {
		t.Fatalf("err=%v, want ErrCrawlDidNotRun", err)
	}
	var zv CrawlVisit
	if zv.Recorded() {
		t.Fatal("the zero CrawlVisit reports itself recorded")
	}
	var zr CrawlRequest
	if zr.Constructed() {
		t.Fatal("the zero CrawlRequest reports itself constructed")
	}
	var zc CrawlConfig
	if zc.Constructed() {
		t.Fatal("the zero CrawlConfig reports itself constructed")
	}
}

// TestACancelledCrawlDoesNotReportAPartialInventoryAsAMeasurement.
func TestACancelledCrawlDoesNotReportAPartialInventoryAsAMeasurement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := c23Config(t, c23Opts{
		spider: c23Linking(map[string][]string{"/": {"/a"}}),
		seeds:  []string{"/", "/b"},
	})
	res, err := CrawlWithClientSpider(ctx, cfg, mustClock(t), nil)
	if err != nil {
		t.Fatalf("CrawlWithClientSpider: %v", err)
	}
	if res.Issued() != 0 {
		t.Fatalf("issued=%d after cancellation", res.Issued())
	}
	if got := c23OutcomeCount(res, CrawlOutcomeCancelled); got != 2 {
		t.Fatalf("%d rows say cancelled, want 2: %v", got, c23Ledger(res))
	}
	if err := res.AssertBudgetSufficed(); !errors.Is(err, ErrProbeBudgetExhausted) {
		t.Fatalf("err=%v; a cancelled crawl is a coverage FLOOR", err)
	}
}

// TestOnePageCannotEnqueueAnUnboundedFrontier.
func TestOnePageCannotEnqueueAnUnboundedFrontier(t *testing.T) {
	links := make([]string, codedMaxLinksPerPage+50)
	for i := range links {
		links[i] = fmt.Sprintf("/l%05d", i)
	}
	spider := c23Linking(map[string][]string{"/": links})
	res := c23Run(t, c23Config(t, c23Opts{spider: spider, maxPages: 3}))

	// The seed plus the bounded link set; the 50 beyond the bound were never
	// read, and the refusal says so rather than dropping them quietly.
	if got, want := res.Discovered(), 1+codedMaxLinksPerPage; got != want {
		t.Fatalf("discovered=%d, want %d", got, want)
	}
	found := false
	for _, r := range res.Refusals() {
		if r.Reason == RefusalSpecTruncated && strings.Contains(r.Detail, "per-page bound") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the per-page link bound produced no refusal row: %v", res.Refusals())
	}
}

// ===========================================================================
// STRUCTURAL GUARDS
// ===========================================================================

func c23Source(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("tier3_crawl.go")
	if err != nil {
		t.Fatalf("reading tier3_crawl.go: %v. This guard refuses to report a pass it did "+
			"not measure.", err)
	}
	return string(src)
}

// TestTier3OpensNothing enforces an import allowlist on tier3_crawl.go,
// with a positive control proving the scanner can see an import at all.
//
// Every entry is on internal/dast/authz's inertImports (gate 3's allowlist)
// or is first-party; a crawler holding anything that can construct a socket
// would fail gate 3's own scan as well as this one.
func TestTier3OpensNothing(t *testing.T) {
	allowed := map[string]bool{
		`"context"`: true, `"errors"`: true, `"fmt"`: true, `"net/url"`: true,
		`"sort"`: true, `"strings"`: true, `"time"`: true, `"unicode/utf8"`: true,
		`"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"`:   true,
		`"github.com/Susquehanna-Syntax/Anvil/internal/dast/engines"`: true,
		`"github.com/Susquehanna-Syntax/Anvil/internal/record"`:       true,
	}
	file, _ := parseOwnSource(t, "tier3_crawl.go")
	if len(file.Imports) == 0 {
		t.Fatal("the scanner found zero imports, so it could not have found a violation")
	}
	for _, imp := range file.Imports {
		if !allowed[imp.Path.Value] {
			t.Fatalf("tier3_crawl.go imports %s, which is not on the allowlist. A crawler "+
				"may not hold anything that can construct a socket; egress goes through "+
				"ClientSpider", imp.Path.Value)
		}
	}
	if allowed[`"net/http"`] || allowed[`"net"`] {
		t.Fatal("a dialer is on the allowlist")
	}
}

// TestTheOnlyPathLiteralsInThisTierAreTheExclusionList.
//
// A crawler with a hard-coded destination is a crawler that visits somewhere
// the inventory did not name. The exclusion list is the one legitimate source
// of path literals here, so the guard is not "no path literals" — which the
// file would fail honestly — but "every path literal is in that function".
func TestTheOnlyPathLiteralsInThisTierAreTheExclusionList(t *testing.T) {
	file, fset := parseOwnSource(t, "tier3_crawl.go")
	var lo, hi int
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "metaSurfacePrefixes" {
			lo = fset.Position(fn.Pos()).Line
			hi = fset.Position(fn.End()).Line
		}
	}
	if lo == 0 {
		t.Fatal("metaSurfacePrefixes was not found, so the guard has no exempt range and " +
			"is measuring the wrong thing")
	}
	literals := 0
	inList := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		literals++
		if !strings.HasPrefix(v, "/") || len(v) <= 1 {
			return true
		}
		line := fset.Position(lit.Pos()).Line
		if line >= lo && line <= hi {
			inList++
			return true
		}
		t.Errorf("tier3_crawl.go contains the path literal %q at line %d, outside "+
			"metaSurfacePrefixes (lines %d-%d). The addresses this tier visits come "+
			"from the target's link graph and the configured seeds, never from a "+
			"constant in the crawler", v, line, lo, hi)
		return true
	})
	if literals == 0 {
		t.Fatal("the scanner found ZERO string literals, so it is measuring nothing")
	}
	if inList == 0 {
		t.Fatal("no path literal was found inside metaSurfacePrefixes, so the exempt " +
			"range is wrong and the guard is exempting nothing")
	}
}

// TestNoTestInTheTier3PacketIsSkipped. A t.Skip is how an unprovable control
// reports itself green.
func TestNoTestInTheTier3PacketIsSkipped(t *testing.T) {
	for _, name := range []string{"tier3_crawl.go", "tier3_crawl_test.go"} {
		file, _ := parseOwnSource(t, name)
		found := 0
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Skip" || sel.Sel.Name == "SkipNow" || sel.Sel.Name == "Skipf" {
				found++
			}
			return true
		})
		if found != 0 {
			t.Fatalf("%s contains %d t.Skip call(s)", name, found)
		}
	}
	// Positive control: the scanner can see one when it is there.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go",
		"package p\nimport \"testing\"\nfunc TestX(t *testing.T){ t.Skip(\"nope\") }\n", 0)
	if err != nil {
		t.Fatalf("parsing the fixture: %v", err)
	}
	seen := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Skip" {
			seen++
		}
		return true
	})
	if seen != 1 {
		t.Fatalf("the scanner saw %d skips in a fixture containing exactly one", seen)
	}
}

// TestTheCanonicalizerIsD20sAndNotASecondOne. Two canonicalizers that can
// disagree put two spellings of one address in the denominator.
func TestTheCanonicalizerIsD20sAndNotASecondOne(t *testing.T) {
	file, _ := parseOwnSource(t, "tier3_crawl.go")
	calls := map[string]int{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			calls[id.Name]++
		}
		return true
	})
	if calls["canonicalizePattern"] == 0 {
		t.Fatal("tier3_crawl.go never calls canonicalizePattern, so it is keying its " +
			"addresses on something D.22 does not key its union on")
	}
	if calls["endpointKey"] == 0 {
		t.Fatal("tier3_crawl.go never calls endpointKey, so its visited set and D.22's " +
			"union are keyed by two different functions")
	}
	if calls["kernelAcceptsPath"] == 0 {
		t.Fatal("tier3_crawl.go never calls kernelAcceptsPath, so the kernel is not the " +
			"thing validating its paths")
	}
	// And the host comparison is the kernel's, not a local one.
	src := c23Source(t)
	if !strings.Contains(src, "authz.Canonicalize(") {
		t.Fatal("tier3_crawl.go does not compare hosts through authz.Canonicalize, so it " +
			"holds a second opinion about what two hosts being equal means")
	}
}

// ===========================================================================
// NON-CANONICAL SPELLINGS — the third time this codebase has lost to one
// ===========================================================================

// c23DotSpellings is every spelling of a dot segment a link or a Location
// header can carry. Each one resolves, in a browser, to a path the fixture
// robots.txt has removed from scope.
//
// The list is the GENERATOR, and a generator that cannot produce the breaking
// input is the defect: it carries the three spellings the D.25 critic measured
// AND the ones it did not — double-encoded, mixed case, overlong, backslash
// separators, and a triple that only becomes a dot segment after two decodes.
func c23DotSpellings() []string {
	return []string{
		"/%2e%2e/admin",
		"/x/%2e%2e/admin",
		"/.%2e/admin",
		"/%2E%2E/admin",
		"/%2e./admin",
		"/x/%2e%2e/%2e%2e/admin",
		"/%252e%252e/admin",
		"/%c0%ae%c0%ae/admin",
		"/x\\..\\admin",
		"/x/..%2fadmin",
		"/%2e%2e%2fadmin",
	}
}

// TestANonCanonicalSpellingOfARemovedPathIsNeverRequested.
//
// Gate 11's narrowing removed /admin. A browser resolves every spelling in
// c23DotSpellings to /admin or to a path under it, so a crawl that requests
// any of them has walked outside the narrowed scope by spelling alone.
func TestANonCanonicalSpellingOfARemovedPathIsNeverRequested(t *testing.T) {
	const body = "User-agent: *\nDisallow: /admin\n"
	policy := authz.ParseRobotsTxt(fixtureHost, 443, []byte(body))
	if policy.PermitsPath("/admin") {
		t.Fatal("the fixture robots.txt does not actually disallow /admin, so this test " +
			"would pass against a crawler with no narrowing at all")
	}
	links := append([]string{"/admin"}, c23DotSpellings()...)
	spider := c23Linking(map[string][]string{"/": links})
	res := c23Run(t, c23Config(t, c23Opts{
		spider: spider, robots: body, robotsPol: &policy, maxPages: 200,
	}))

	if got := spider.paths(); !reflect.DeepEqual(got, []string{"/"}) {
		t.Fatalf("the spider was asked for %v, want only the seed. Every extra entry is "+
			"a spelling of a path gate 11 removed, requested because the narrowing was "+
			"matched against the literal bytes instead of the canonical form", got)
	}
	// ASSERT THE COUNT: one row per offered link, none of them silent.
	if got, want := len(res.Visits()), 1+len(links); got != want {
		t.Fatalf("the ledger has %d row(s) and %d link(s) were offered plus the seed; a "+
			"spelling that was dropped without a row is one an operator cannot audit: %v",
			got, want, c23Ledger(res))
	}
	for _, sp := range links {
		if c23HasRoute(res, sp) {
			t.Fatalf("%q became a crawl route; a spelling of a removed path is not "+
				"surface this crawl may report", sp)
		}
	}
	if c23HasRoute(res, "/admin") {
		t.Fatal("/admin became a crawl route through an encoded spelling")
	}
}

// TestANonCanonicalLocationHeaderIsNeverFollowed is the same measurement on
// the REDIRECT route, which reaches offer() through a different caller and
// with a different origin label.
func TestANonCanonicalLocationHeaderIsNeverFollowed(t *testing.T) {
	const body = "User-agent: *\nDisallow: /admin\n"
	policy := authz.ParseRobotsTxt(fixtureHost, 443, []byte(body))
	for _, loc := range c23DotSpellings() {
		spider := &c23Spider{
			pages: map[string]CrawlPage{
				"/": {Status: 302, Location: loc, Latency: time.Millisecond},
			},
			def: CrawlPage{Status: 200},
		}
		res := c23Run(t, c23Config(t, c23Opts{
			spider: spider, robots: body, robotsPol: &policy, maxPages: 200,
		}))
		if got := spider.paths(); !reflect.DeepEqual(got, []string{"/"}) {
			t.Fatalf("a Location of %q made the crawl request %v; the hop must be "+
				"canonicalized before gate 11's narrowing is matched", loc, got)
		}
		if len(res.Visits()) != 2 {
			t.Fatalf("a Location of %q produced %d ledger row(s), want 2 (the seed and "+
				"the refused hop): %v", loc, len(res.Visits()), c23Ledger(res))
		}
	}
}

// TestEachNonCanonicalSpellingIsClassifiedRatherThanMerelyDropped.
//
// "It was not requested" is two different facts and an operator needs to know
// which: a spelling Anvil RESOLVED and then found outside the narrowed scope is
// gate 11 doing its job, and a spelling Anvil REFUSED TO RESOLVE is a link
// whose canonical identity is not one value. The ledger says which, per link.
func TestEachNonCanonicalSpellingIsClassifiedRatherThanMerelyDropped(t *testing.T) {
	const body = "User-agent: *\nDisallow: /admin\n"
	policy := authz.ParseRobotsTxt(fixtureHost, 443, []byte(body))

	cases := []struct {
		link string
		want CrawlOutcome
		why  string
	}{
		{"/%2e%2e/admin", CrawlOutcomeOutsideNarrowedScope, "one decode gives \"..\""},
		{"/x/%2e%2e/admin", CrawlOutcomeOutsideNarrowedScope, "one decode gives \"..\""},
		{"/.%2e/admin", CrawlOutcomeOutsideNarrowedScope, "half-encoded \"..\""},
		{"/%2E%2E/admin", CrawlOutcomeOutsideNarrowedScope, "uppercase hex digits"},
		{"/%2e./admin", CrawlOutcomeOutsideNarrowedScope, "the other half-encoding"},
		{"/x/%2e%2e/%2e%2e/admin", CrawlOutcomeOutsideNarrowedScope, "two parents"},
		{"/%252e%252e/admin", CrawlOutcomeLinkUnusable, "doubly encoded: ambiguous"},
		{"/%c0%ae%c0%ae/admin", CrawlOutcomeLinkUnusable, "overlong: not valid UTF-8"},
		{"/x\\..\\admin", CrawlOutcomeLinkUnusable, "encoded backslash separator"},
		{"/x/..%2fadmin", CrawlOutcomeLinkUnusable, "encoded slash separator"},
		{"/%2e%2e%2fadmin", CrawlOutcomeLinkUnusable, "parent plus encoded slash"},
	}
	for _, tc := range cases {
		spider := c23Linking(map[string][]string{"/": {tc.link}})
		res := c23Run(t, c23Config(t, c23Opts{
			spider: spider, robots: body, robotsPol: &policy,
		}))
		if spider.calls != 1 {
			t.Fatalf("%q: the spider was called %d time(s), want 1 (the seed alone): %v",
				tc.link, spider.calls, spider.paths())
		}
		var got []CrawlVisit
		for _, v := range res.Visits() {
			if v.Outcome() != CrawlOutcomeFetched {
				got = append(got, v)
			}
		}
		if len(got) != 1 {
			t.Fatalf("%q: %d non-fetched ledger row(s), want exactly 1: %v",
				tc.link, len(got), c23Ledger(res))
		}
		if got[0].Outcome() != tc.want {
			t.Fatalf("%q (%s): the ledger says %q, want %q. Detail: %s",
				tc.link, tc.why, got[0].Outcome(), tc.want, got[0].Detail())
		}
	}
}

// TestCanonicalizationPreservesCoverageAndDoesNotDoubleCount.
//
// The counterweight to the refusals above, and the reason this is a
// canonicalization rather than a denylist of suspicious spellings: an encoded
// parent reference that resolves to a path the narrowing PERMITS is still
// crawled — once, at its canonical spelling, and not a second time under the
// spelling the link used.
func TestCanonicalizationPreservesCoverageAndDoesNotDoubleCount(t *testing.T) {
	const body = "User-agent: *\nDisallow: /admin\n"
	policy := authz.ParseRobotsTxt(fixtureHost, 443, []byte(body))
	spider := c23Linking(map[string][]string{
		"/": {"/x/%2e%2e/public", "/public", "/%2e/public", "/caf%c3%a9"},
	})
	res := c23Run(t, c23Config(t, c23Opts{
		spider: spider, robots: body, robotsPol: &policy,
	}))

	got := spider.paths()
	sort.Strings(got)
	want := []string{"/", "/caf%c3%a9", "/public"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the spider was asked for %v, want %v. Three spellings of /public are "+
			"ONE address, and a percent-encoded segment that is not a dot segment is an "+
			"ordinary path that must still be crawled", got, want)
	}
	if !c23HasRoute(res, "/public") {
		t.Fatalf("/public is not in the inventory: %v", c23RoutePaths(res))
	}
	if c23HasRoute(res, "/x/%2e%2e/public") {
		t.Fatal("the pre-canonical spelling became a second route, which is one endpoint " +
			"counted twice in the coverage denominator")
	}
	// ASSERT THE COUNT: four links plus the seed, and /public reached once.
	n := 0
	for _, v := range res.Visits() {
		if v.CanonicalPath() == "/public" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("/public has %d ledger row(s), want 1: %v", n, c23Ledger(res))
	}
}
