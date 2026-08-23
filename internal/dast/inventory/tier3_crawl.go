// D.23 — Tier 3: the browser-driven crawl.
//
// A CRAWLER IS THE MOST DANGEROUS COMPONENT IN THE DYNAMIC TIER, for one
// reason that is worth stating before any code: EVERY DESTINATION IT VISITS
// AFTER THE FIRST ONE WAS PROPOSED BY THE TARGET. A spec document is
// attacker-controlled bytes DESCRIBING attack surface (D.18's framing); a link
// graph is attacker-controlled bytes CHOOSING ANVIL'S NEXT REQUEST. That is a
// materially stronger capability handed to the thing being tested, and the
// whole shape of this file follows from refusing it.
//
// # Nothing here decides anything the kernel already decides
//
// The controls a crawl needs all exist. This file's job is to ROUTE THROUGH
// them, never to hold a second opinion:
//
//	scope, robots, method, technique   authz.Governor, per request, via
//	                                   GateAudit.AuditedAdmit — the same call
//	                                   D.22's probeOne makes
//	the walk-off                       gate 13 (CheckGate13Revalidate) re-runs
//	                                   gates 4, 5, 8, 9 and 10 on EVERY request
//	                                   and EVERY hop, against the destination
//	                                   the request would actually reach
//	the redirect chain                 authz's maxRedirectHops, reached by
//	                                   LABELLING the hop (see below)
//	rate, concurrency, volume, clock   gate 14's caps, which a crawl is
//	                                   precisely the workload that discovers
//	                                   are real
//	the path robots.txt removed        gate 11's narrowing, already applied to
//	                                   the Scope this file receives, consulted
//	                                   through Scope.PermitsPath — which is
//	                                   fail-closed on an origin nobody
//	                                   determined
//	the canonical identity of a path   D.20's canonicalizePattern, the ONE
//	                                   canonicalizer this package has, and the
//	                                   one D.22 keys its union on
//
// This file constructs no socket, holds no client and cannot import a package
// that could: D.9's gate 3 tier 1 makes that structural. The browser lives
// behind ClientSpider, and its absence is a loud typed refusal.
//
// # The redirect label, which is the one thing this file adds to the kernel
//
// internal/dast/engines/zap.go (D.15) records, at length, that NOTHING makes
// ZAP's own redirect following arrive at gate 13 labelled as a redirect: a
// proxy that stamps every request `initial` at Hop 0 never reaches authz's
// maxRedirectHops, and a same-host redirect chain is then bounded only by gate
// 14. authz.RefuseAllRedirects names the owner of the missing piece: "the
// egress layer records the hop, and a same-host hop is re-issued as a fresh
// request with OriginRedirect and Hop+1".
//
// THIS FILE IS THAT COMPONENT, for its own requests. crawlOne holds the 3xx it
// just received, so it is the one place that can honestly say "this next
// request is the follow-up to that one" — and it does, filling Origin and Hop
// itself. A crawl's redirect chain therefore IS bounded by maxRedirectHops,
// and hop 6 is refused by authz.NewRequestIntent before any gate runs.
// TestARedirectChainIsBoundedByTheKernelsHopBound measures it.
//
// That claim is scoped to requests THIS FILE issues. It says nothing about a
// ZAP process proxied through Anvil; U5 still owns that.
//
// # Termination is a correctness property, not a nicety
//
// A crawler that does not provably terminate on a cyclic or infinite site
// burns the whole per-target budget, and every endpoint discovered later
// reports as unreached — which is research/22's Risk #4 ("more endpoints can
// mean less coverage") arriving through a different door. Four independent
// bounds, any one of which alone terminates the loop:
//
//	1 THE VISITED SET. An address is fetched at most once. The key is
//	  endpointKey(method, canonicalizePattern(path)) — D.22's key, so "visited"
//	  here and "one endpoint" there are the same question. A cycle A->B->A
//	  therefore revisits nothing: the loop pops strictly from a frontier that
//	  only ever admits keys it has not already admitted, so the number of
//	  iterations is bounded by the number of DISTINCT keys, which is bounded
//	  by codedMaxFrontier.
//	2 MaxPages, configuration with no default, bounding requests ISSUED.
//	3 MaxDepth, configuration with no default, bounding link distance from a
//	  seed. An infinite site that generates a fresh path per page terminates on
//	  this one even if every path is distinct.
//	4 Gate 14's caps — rps, concurrency, volume per target run, wall clock per
//	  target — enforced by the Governor and never re-implemented here.
//
// Plus two bounds on the shape of one step: codedMaxLinksPerPage and
// codedMaxLinkBytes, so a single hostile page cannot enqueue an unbounded
// frontier or a 100 MB href.
//
// Nothing is dropped silently at any of those bounds. Every one produces a
// counted CrawlOutcome on a recorded address, because a link Anvil saw and did
// not visit is attack surface that exists, and dropping it quietly SHRINKS the
// denominator of endpoint_coverage — which makes coverage look better.
//
// # Confirmation, per ruling 7
//
// EVERY ROUTE THIS FILE PRODUCES IS ConfirmationCandidate, unconditionally,
// including one whose page answered 200 to a request this crawl itself made.
// There is exactly one writer of ConfirmationConfirmed in this package —
// D.22's confirmationFor — and a second one here would be a second numerator.
// The crawl hands D.22 candidates and D.22 confirms them; a link's existence
// is not evidence the endpoint responds, and neither is this file's opinion.
// AssertEveryRouteIsACandidate is the check rather than this paragraph.
//
// # The exclusion list is a DENYLIST, and denylists lose
//
// plan/50-dast.md D.23 requires Swagger UI and GraphQL playground routes to be
// excluded "even if discovered by the crawl itself". A prefix list is a
// denylist, and this build's standing rule is that a denylist loses. It is
// acceptable HERE, and only here, because of where its failure lands: a
// meta-surface page the list misses is CRAWLED, which costs budget. It is not
// a scope walk-off — gates 4, 11 and 13 bound where the crawl may go, and the
// exclusion list bounds nothing but waste. So the list failing open costs
// coverage, never containment, and every miss is a recorded visit an operator
// can read back.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/engines"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrNoClientSpider is returned when a crawl was eligible to run and no
	// browser seam is wired. It is an error and not an empty route list: a
	// crawl that found nothing because nothing could leave the process must
	// not be reportable as a target with no link graph.
	ErrNoClientSpider = errors.New("inventory: no ClientSpider is wired, so Tier 3 issued no " +
		"request and an empty crawl inventory would describe Anvil rather than the target")

	// ErrCrawlDidNotRun is what AssertNotSilentlyEmpty returns when the
	// trigger policy skipped the crawl. Skipping is CORRECT behaviour and is
	// not an error from CrawlWithClientSpider — but a caller that reads
	// Routes() without asking Executed() would see an empty Tier 3 and shrink
	// the coverage denominator, so the standard emptiness assertion returns a
	// distinguishable value rather than nil.
	ErrCrawlDidNotRun = errors.New("inventory: the Tier 3 crawl did not run; its trigger is " +
		"not on the eligibility allowlist, so this result describes the schedule and not " +
		"the target")

	// ErrCrawlFoundNothing is what AssertNotSilentlyEmpty returns when the
	// crawl RAN, issued requests and never received one answer.
	ErrCrawlFoundNothing = errors.New("inventory: the Tier 3 crawl ran and the target never " +
		"answered a single request; an empty crawl inventory here describes Anvil")

	// ErrExcludedPathWasVisited is what AssertNoExcludedPathWasVisited
	// returns. It re-derives the exclusion predicate over the RECORDED visits
	// rather than trusting the enqueue-time filter, so a bug in the filter is
	// visible in the result instead of only in the code that produced it.
	ErrExcludedPathWasVisited = errors.New("inventory: the crawl issued a request to a path " +
		"the exclusion list covers")

	// ErrRouteClaimsConfirmed is what AssertEveryRouteIsACandidate returns.
	ErrRouteClaimsConfirmed = errors.New("inventory: a crawl-discovered route claims " +
		"\"confirmed\"; only D.22 confirms an endpoint, and only on an observation")
)

// ---------------------------------------------------------------------------
// Coded bounds — every one of them a termination argument
// ---------------------------------------------------------------------------

const (
	// codedMaxCrawlPages is the sanity ceiling on CrawlConfig.MaxPages. The
	// real bound is gate 14's requests-per-target-run, which the Governor
	// enforces independently and which may bite first; whichever refuses
	// first is the one that refuses.
	codedMaxCrawlPages = 20000

	// codedMaxCrawlDepth is the sanity ceiling on CrawlConfig.MaxDepth.
	codedMaxCrawlDepth = 32

	// codedMaxLinksPerPage bounds how many hrefs ONE page may enqueue. A page
	// that emits a million links is a resource-exhaustion probe pointed back
	// at Anvil, and it is the cheapest one a target has.
	codedMaxLinksPerPage = 1024

	// codedMaxFrontier bounds the total number of distinct addresses the
	// crawl will ever hold. It is the outer termination bound: the loop pops
	// one entry per iteration and enqueues only keys it has never enqueued,
	// so it cannot iterate more times than this.
	codedMaxFrontier = 65536

	// codedMaxSeeds bounds the configured seed list. Seeds are Anvil's
	// configuration rather than target input, so this is a sanity floor.
	codedMaxSeeds = 64

	// codedMaxExclusions bounds the operator-supplied exclusion list.
	codedMaxExclusions = 256

	// codedMaxLinkBytes bounds one href lifted out of a page.
	codedMaxLinkBytes = 4096
)

// ---------------------------------------------------------------------------
// ScanTrigger — the gate that makes Tier 3 scheduled-full-scan-only
// ---------------------------------------------------------------------------

// ScanTrigger says what kind of run this is.
//
// # Why this is declared here, and what it is NOT
//
// It is NOT authz.TriggerEvent. That enum is gate 7's and answers a different
// question — WHO started the run and whether their provenance is trustworthy
// (schedule, workflow_dispatch, pull_request_target...). This one answers HOW
// DEEP the run is, which is orthogonal: a `schedule` event can start a light
// run and an operator can start a full one. plan/50-dast.md:1153 uses exactly
// this axis for `server_line_coverage` ("scheduled full scans only... `null`
// on incremental scans") and D.23's own validation asks for a run "whose
// trigger type is `incremental`". Nothing in this module declares that axis
// yet, so it is declared here and FLAGGED TO THE ORCHESTRATOR as a candidate
// for hoisting — into internal/record beside InventoryProvenance if D.26 needs
// it in the record, or into a run-orchestration packet if one lands first.
// Until then this is the one place the vocabulary is written, and the two
// gates compose rather than duplicate: gate 7 decides whether the run may
// happen at all, this decides whether Tier 3 is part of it.
//
// # The zero value is not a value
//
// ScanTriggerUnset names nothing and is refused. "Permitted" is the direction
// that costs something here — a browser crawl on the always-on path — so a
// Go zero value must never mean it.
type ScanTrigger string

const (
	// ScanTriggerUnset is the zero value and names nothing.
	ScanTriggerUnset ScanTrigger = ""

	// ScanTriggerScheduledFull is the scheduled full scan. THE ONLY VALUE ON
	// THE TIER 3 ALLOWLIST.
	ScanTriggerScheduledFull ScanTrigger = "scheduled_full"

	// ScanTriggerIncremental is the always-on path — the one D.15 and D.23
	// are both forbidden from firing on.
	ScanTriggerIncremental ScanTrigger = "incremental"

	// ScanTriggerTag is a tag-triggered scan. D.23's forbidden actions name
	// it beside `incremental`.
	ScanTriggerTag ScanTrigger = "tag"
)

// ScanTriggerValues returns every legal literal.
func ScanTriggerValues() []ScanTrigger {
	return []ScanTrigger{ScanTriggerScheduledFull, ScanTriggerIncremental, ScanTriggerTag}
}

// Recognised reports whether t is one of the enumerated triggers.
func (t ScanTrigger) Recognised() bool {
	for _, k := range ScanTriggerValues() {
		if k == t {
			return true
		}
	}
	return false
}

// tier3EligibleTriggers is the ALLOWLIST of triggers Tier 3 may run under.
//
// It is an allowlist matched by IDENTITY, and it is deliberately shorter than
// ScanTriggerValues. A trigger nobody enumerated — a new run mode added next
// quarter, or a typo — is not recognised, so it is not eligible, so the crawl
// does not fire. That is the safe direction: forgetting to add a mode here
// costs a crawl that should have run, and the result says so out loud
// (Executed() is false and SkipReason names the trigger). Forgetting to
// REMOVE one would cost a browser crawl on the always-on path.
//
// It is a function returning a fresh map so there is no package-level variable
// for anything to reassign, and no backing store a caller could write through.
func tier3EligibleTriggers() map[ScanTrigger]bool {
	return map[ScanTrigger]bool{ScanTriggerScheduledFull: true}
}

// PermitsTier3Crawl reports whether the Tier 3 browser crawl may run under t.
//
// False for the zero value, false for `incremental`, false for `tag`, and
// false for any token nobody enumerated.
func (t ScanTrigger) PermitsTier3Crawl() bool { return tier3EligibleTriggers()[t] }

// ---------------------------------------------------------------------------
// The meta-surface exclusion list
// ---------------------------------------------------------------------------

// metaSurfacePrefixes is the compiled-in exclusion seed list: Swagger UI and
// GraphQL playground routes, which plan/50-dast.md D.23 forbids crawling "even
// if discovered by the crawl itself".
//
// They are META-SURFACE, not application surface. Tier 0 already asks the
// target for the DOCUMENT behind them (`/v3/api-docs`, the introspection
// response) and lifts every route out of it in one request; crawling the
// single-page app that renders that document costs the tightest budget in the
// pipeline and adds nothing Tier 0 did not already have.
//
// # How they are matched, and why not by substring
//
// By SEGMENT BOUNDARY: a path matches a prefix when it equals it, or when it
// begins with it followed by "/". So "/api-docs" and "/api-docs/v1" are
// excluded and "/api-docs-internal" is NOT — that is a different application
// route that merely shares a spelling, and a substring match would silently
// delete it from the inventory. An allowlist matched by position rather than
// identity loses, and so does a denylist matched by accident.
//
// The comparison is case-folded. That widens the exclusion (it also catches
// "/Swagger-UI"), and widening a list whose only failure mode is wasted budget
// is the cheap direction. It also means a real route differing from a listed
// one only in case is excluded; that shows up as a recorded
// CrawlOutcomeMetaSurfaceExcluded rather than as a missing row.
//
// It is a function returning a fresh slice: an exclusion list the crawl could
// shorten at run time is not an exclusion list.
func metaSurfacePrefixes() []string {
	return []string{
		// --- OpenAPI / Swagger UI ---
		"/swagger",
		"/swagger-ui",
		"/swagger-ui.html",
		"/swagger-resources",
		"/api-docs",
		"/v2/api-docs",
		"/v3/api-docs",
		"/openapi",
		"/redoc",
		"/rapidoc",
		"/scalar",
		// --- GraphQL playgrounds and schema explorers ---
		"/graphiql",
		"/graphql-playground",
		"/graphql/console",
		"/graphql/graphiql",
		"/playground",
		"/altair",
		"/voyager",
		"/__graphql",
	}
}

// exclusionSet is the compiled-in list plus the operator's, normalized once.
type exclusionSet struct {
	prefixes []string
}

// newExclusionSet folds the operator's extra prefixes into the compiled-in
// ones. An operator prefix that is not a usable path is REFUSED rather than
// ignored: an exclusion somebody wrote and Anvil silently dropped is the
// shape of a crawl reaching something an operator believed it had excluded.
func newExclusionSet(extra []string) (exclusionSet, error) {
	if len(extra) > codedMaxExclusions {
		return exclusionSet{}, fmt.Errorf("inventory: %w: %d exclusion prefixes were "+
			"supplied and the coded bound is %d", ErrRefused, len(extra), codedMaxExclusions)
	}
	out := exclusionSet{}
	for _, p := range metaSurfacePrefixes() {
		out.prefixes = append(out.prefixes, strings.ToLower(p))
	}
	for i, p := range extra {
		if p == "" || !strings.HasPrefix(p, "/") || len(p) > maxRoutePathBytes {
			return exclusionSet{}, fmt.Errorf("inventory: %w: exclusion prefix %d is %q. "+
				"An exclusion must be an absolute path prefix beginning with \"/\" and "+
				"within %d bytes; one Anvil could not apply is refused rather than "+
				"dropped, because a dropped exclusion and an honoured one look "+
				"identical in the output",
				ErrRefused, i, redact(p), maxRoutePathBytes)
		}
		out.prefixes = append(out.prefixes, strings.ToLower(strings.TrimSuffix(p, "/")))
	}
	sort.Strings(out.prefixes)
	return out, nil
}

// covers reports whether path is excluded, and by which prefix.
func (e exclusionSet) covers(path string) (string, bool) {
	lower := strings.ToLower(path)
	for _, p := range e.prefixes {
		if p == "" {
			continue
		}
		if lower == p || strings.HasPrefix(lower, p+"/") {
			return p, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// CrawlOutcome — what happened to one address, with no default
// ---------------------------------------------------------------------------

// CrawlOutcome is what the crawl did with one address, and why.
//
// It is an enum for the reason ConfirmOutcome is one: "the crawl did not visit
// this" is several different facts, and a bool would fold "the exclusion list
// covered it", "the budget ran out" and "the kernel refused" into one silence.
// Only the first is a decision; the second is a coverage FLOOR and the third
// is a containment event.
type CrawlOutcome string

const (
	// CrawlOutcomeUnset is the zero value and names nothing.
	CrawlOutcomeUnset CrawlOutcome = ""

	// --- Anvil issued a request ---

	// CrawlOutcomeFetched: the kernel admitted it, the seam issued it and the
	// target answered. The status is on the CrawlVisit.
	CrawlOutcomeFetched CrawlOutcome = "fetched"
	// CrawlOutcomeRedirected: the target answered 3xx and Anvil re-admitted
	// the destination as a LABELLED hop (OriginRedirect, Hop+1).
	CrawlOutcomeRedirected CrawlOutcome = "redirect_re_admitted_as_a_labelled_hop"
	// CrawlOutcomeFetchFailed: the seam returned an error, or returned
	// something that is not an HTTP status. A value that is not an answer is
	// never read as one.
	CrawlOutcomeFetchFailed CrawlOutcome = "fetch_failed"

	// --- Anvil did not issue a request ---

	// CrawlOutcomeKernelRefused: the per-request gate chain refused. THE
	// CONTAINMENT OUTCOME — gate 4, 11 or 13 saying no.
	CrawlOutcomeKernelRefused CrawlOutcome = "kernel_refused_the_request"
	// CrawlOutcomeIntentRejected: the address could not be expressed as an
	// authz.RequestIntent at all. A redirect past the kernel's hop bound
	// lands here, because NewRequestIntent refuses Hop > maxRedirectHops.
	CrawlOutcomeIntentRejected CrawlOutcome = "not_a_valid_request_intent"
	// CrawlOutcomeMetaSurfaceExcluded: the exclusion list covers it.
	CrawlOutcomeMetaSurfaceExcluded CrawlOutcome = "meta_surface_excluded"
	// CrawlOutcomeOutsideNarrowedScope: Scope.PermitsPath said no. That is
	// gate 11's narrowing — a path robots.txt removed — or an origin nobody
	// determined, which is refused for being undetermined.
	CrawlOutcomeOutsideNarrowedScope CrawlOutcome = "outside_the_narrowed_scope"
	// CrawlOutcomeOffHost: the link proposes a different host, port or
	// scheme. THE WALK-OFF, refused at the link rather than at the socket.
	CrawlOutcomeOffHost CrawlOutcome = "link_points_off_the_admitted_origin"
	// CrawlOutcomeLinkUnusable: the href is not a path Anvil can request —
	// a mailto:, a javascript:, a fragment-only reference, an over-long
	// string, or a path D.20's canonicalizer rewrote (which would mean
	// requesting a template).
	CrawlOutcomeLinkUnusable CrawlOutcome = "link_is_not_a_requestable_path"
	// CrawlOutcomeDepthExceeded: the address sits deeper than MaxDepth.
	CrawlOutcomeDepthExceeded CrawlOutcome = "depth_budget_exhausted"
	// CrawlOutcomePageBudgetExhausted: MaxPages ran out before this address
	// was reached. IT STAYS IN THE INVENTORY as a candidate — this is a
	// coverage floor, not a shorter surface.
	CrawlOutcomePageBudgetExhausted CrawlOutcome = "page_budget_exhausted"
	// CrawlOutcomeFrontierFull: the coded frontier bound was reached.
	CrawlOutcomeFrontierFull CrawlOutcome = "frontier_bound_reached"
	// CrawlOutcomeCancelled: the context was cancelled or gate 14's wall
	// clock ran out before this address was reached.
	CrawlOutcomeCancelled CrawlOutcome = "run_cancelled_before_this_address"
)

// CrawlOutcomeValues returns every legal literal.
func CrawlOutcomeValues() []CrawlOutcome {
	return []CrawlOutcome{
		CrawlOutcomeFetched, CrawlOutcomeRedirected, CrawlOutcomeFetchFailed,
		CrawlOutcomeKernelRefused, CrawlOutcomeIntentRejected,
		CrawlOutcomeMetaSurfaceExcluded, CrawlOutcomeOutsideNarrowedScope,
		CrawlOutcomeOffHost, CrawlOutcomeLinkUnusable, CrawlOutcomeDepthExceeded,
		CrawlOutcomePageBudgetExhausted, CrawlOutcomeFrontierFull, CrawlOutcomeCancelled,
	}
}

// Recognised reports whether o is one of the enumerated outcomes.
func (o CrawlOutcome) Recognised() bool {
	for _, k := range CrawlOutcomeValues() {
		if k == o {
			return true
		}
	}
	return false
}

// issuedOutcomes is the set of outcomes that mean a request LEFT the process.
//
// It is an allowlist for the same reason perOperationReasons is one: a new
// outcome is not "issued" until somebody says so, and that direction
// understates what Anvil sent rather than overstating it.
func issuedOutcomes() map[CrawlOutcome]bool {
	return map[CrawlOutcome]bool{
		CrawlOutcomeFetched:     true,
		CrawlOutcomeRedirected:  true,
		CrawlOutcomeFetchFailed: true,
	}
}

// Issued reports whether this outcome means a request reached the seam.
func (o CrawlOutcome) Issued() bool { return issuedOutcomes()[o] }

// InInventory reports whether an address with this outcome is attack surface
// that belongs in the coverage denominator.
//
// The three that are NOT are the three where Anvil made a decision about the
// ADDRESS rather than about its own budget: an excluded meta-surface path, a
// path outside the narrowed scope, and a link that is not a requestable path
// at all. Everything else — including every budget exhaustion and every kernel
// refusal — is surface Anvil saw and did not probe, and it stays in.
func (o CrawlOutcome) InInventory() bool {
	switch o {
	case CrawlOutcomeMetaSurfaceExcluded, CrawlOutcomeOutsideNarrowedScope,
		CrawlOutcomeOffHost, CrawlOutcomeLinkUnusable, CrawlOutcomeUnset:
		return false
	default:
		return o.Recognised()
	}
}

// ---------------------------------------------------------------------------
// CrawlVisit — one address, and what became of it
// ---------------------------------------------------------------------------

// CrawlVisit is the record of one address the crawl considered.
//
// Every field is unexported and the only constructor is unexported and in this
// file, for the reason Observation is shaped that way: a caller who could mint
// one could make the crawl's ledger say anything.
type CrawlVisit struct {
	method   authz.Method
	path     string
	canon    string
	depth    int
	hop      int
	origin   authz.RequestOrigin
	outcome  CrawlOutcome
	status   int
	auditSeq authz.AuditSeq
	at       time.Time
	from     string
	detail   string
	sealed   bool
}

// Recorded reports whether v came from the crawl loop.
func (v CrawlVisit) Recorded() bool { return v.sealed && v.outcome.Recognised() }

// Method is the method the crawl would have used. Always GET; see crawlMethod.
func (v CrawlVisit) Method() authz.Method { return v.method }

// Path is the CONCRETE path, as the link spelled it after resolution.
func (v CrawlVisit) Path() string { return v.path }

// CanonicalPath is the path under D.20's canonicalizer — the spelling D.22
// keys its union on, and the spelling the visited set is keyed on.
func (v CrawlVisit) CanonicalPath() string { return v.canon }

// Depth is the link distance from a seed. A seed is depth 0.
func (v CrawlVisit) Depth() int { return v.depth }

// Hop is the redirect depth: 0 for an ordinary request, 1 for the first hop.
func (v CrawlVisit) Hop() int { return v.hop }

// Origin is the label this request carried to gate 13.
func (v CrawlVisit) Origin() authz.RequestOrigin { return v.origin }

// Outcome is what happened.
func (v CrawlVisit) Outcome() CrawlOutcome { return v.outcome }

// Status is the HTTP status the target returned, or 0 when nothing was issued
// or nothing answered. Zero is NOT an answer.
func (v CrawlVisit) Status() int { return v.status }

// AuditSeq is the gate-21 row this request was admitted under, or 0.
func (v CrawlVisit) AuditSeq() authz.AuditSeq { return v.auditSeq }

// At is the run-clock instant.
func (v CrawlVisit) At() time.Time { return v.at }

// From is the path whose link graph proposed this address, or "seed".
func (v CrawlVisit) From() string { return v.from }

// Detail is a short redacted explanation.
func (v CrawlVisit) Detail() string { return v.detail }

// String renders the visit for a log line.
func (v CrawlVisit) String() string {
	if !v.Recorded() {
		return "visit(none)"
	}
	return fmt.Sprintf("%s %s [depth %d hop %d %s] -> %s (status %d, from %s)",
		v.method, redact(v.canon), v.depth, v.hop, v.origin, v.outcome, v.status,
		redact(v.from))
}

func cloneVisits(in []CrawlVisit) []CrawlVisit {
	if in == nil {
		return nil
	}
	out := make([]CrawlVisit, len(in))
	copy(out, in)
	return out
}

// SortVisits orders visits deterministically: canonical path, then hop, then
// depth. Two runs over one fixture produce one ledger.
func SortVisits(vs []CrawlVisit) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if a.canon != b.canon {
			return a.canon < b.canon
		}
		if a.method != b.method {
			return a.method < b.method
		}
		if a.hop != b.hop {
			return a.hop < b.hop
		}
		return a.depth < b.depth
	})
}

// ---------------------------------------------------------------------------
// The browser seam
// ---------------------------------------------------------------------------

// CrawlRequest is one page fetch the kernel has ALREADY admitted.
//
// A composite literal in another package produces the zero value, whose
// Constructed() is false — the property SpecRequest, ConfirmRequest and
// engines.AdmittedRequest all hold, for the same reason: argument construction
// is a security boundary when the argument is a destination.
type CrawlRequest struct {
	auth      authz.Authorization
	target    authz.Target
	method    authz.Method
	path      string
	technique authz.Technique
	origin    authz.RequestOrigin
	hop       int
	seq       authz.AuditSeq
	sealed    bool
}

// Constructed reports whether r was built by the crawl loop.
func (r CrawlRequest) Constructed() bool { return r.sealed && r.target.Constructed() }

// Authorization returns the kernel token this fetch rests on. An implementor
// MUST pass it to authz.RequireAuthorization (or authz.PinnedDialAddress)
// immediately before constructing a socket.
func (r CrawlRequest) Authorization() authz.Authorization { return r.auth }

// Target returns the authorized destination, pinned address and all.
func (r CrawlRequest) Target() authz.Target { return r.target }

// Method returns the method to issue. Always GET.
func (r CrawlRequest) Method() authz.Method { return r.method }

// Path returns the concrete request path.
func (r CrawlRequest) Path() string { return r.path }

// Technique returns the technique gate 15 judged.
func (r CrawlRequest) Technique() authz.Technique { return r.technique }

// Origin returns the label gate 13 judged this request under.
func (r CrawlRequest) Origin() authz.RequestOrigin { return r.origin }

// Hop returns the redirect depth this request was admitted at.
func (r CrawlRequest) Hop() int { return r.hop }

// AuditSeq returns the gate-21 row this fetch was admitted under.
func (r CrawlRequest) AuditSeq() authz.AuditSeq { return r.seq }

// CrawlPage is what the browser got back.
//
// EVERY FIELD EXCEPT Status AND Latency IS ATTACKER-CONTROLLED INPUT THAT
// PROPOSES ANVIL'S NEXT DESTINATION. Nothing in it is trusted, nothing in it
// widens anything, and every value is re-validated against the kernel before
// it becomes a request.
type CrawlPage struct {
	// Status is the HTTP status code. A value outside [100,599] is treated as
	// "the seam returned nothing", never as an answer.
	Status int
	// Latency is how long the fetch took. It feeds gates 16 and 17.
	Latency time.Duration
	// Location is the Location header verbatim, meaningful on a 3xx. It is
	// the target choosing Anvil's next destination, which is exactly the
	// argument ZAP issue #2546 accepted; here it is re-admitted as a LABELLED
	// hop or refused.
	Location string
	// Links are the hrefs the rendered page proposed, verbatim. Bounded by
	// codedMaxLinksPerPage and codedMaxLinkBytes on the way in.
	Links []string
}

// ClientSpider is the browser seam: ZAP's CLIENT Spider, never the AJAX
// Spider.
//
// # Client Spider, and why the choice is not stylistic
//
// research/22-attack-surface-discovery.md lines 342-347 (Tier 3) records ZAP's
// own 2026 recommendation of the Client Spider over the AJAX Spider on scaling
// grounds: linear, against rapidly degrading. A crawl is the workload with the
// tightest budget in the pipeline, so a component that degrades super-linearly
// spends the budget on itself.
//
// # The obligations an implementation takes on
//
//  1. ISSUE EXACTLY ONE REQUEST, to exactly CrawlRequest.Path() on
//     CrawlRequest.Target(). Not the page's subresources, not its links, not
//     its redirect. This loop admits one address per call and the audit row
//     covers one address.
//  2. NEVER FOLLOW A REDIRECT. Return the 3xx and its Location. Anvil holds
//     the 3xx, labels the follow-up OriginRedirect at Hop+1, and re-admits it
//     through the whole gate chain — which is the ONLY way authz's
//     maxRedirectHops is ever reached. A seam that follows redirects itself
//     has silently removed the hop bound, and CrawlPage has no field in which
//     it could confess to having done so.
//  3. HONOUR THE AUTHORIZATION. Call authz.RequireAuthorization with
//     CrawlRequest.Authorization() and CrawlRequest.Target() immediately
//     before the socket exists.
//
// Obligations 1 and 2 are STATED HERE AND ENFORCED NOWHERE IN THIS FILE. They
// are contracts on the implementer, of the same kind engines.ZapRunner states
// for the ZAP process, and they are what an integration lane must prove.
type ClientSpider interface {
	FetchPage(ctx context.Context, req CrawlRequest) (CrawlPage, error)
}

// SystemClientSpider returns the browser this host can drive.
//
// IT ALWAYS RETURNS AN ERROR, ON EVERY HOST, TODAY — and the error is D.15's
// own, obtained by CALLING engines.SystemZapRunner rather than by asserting
// what it would say. The Tier 3 spider is ZAP's Client Spider; no ZAP runner
// adapter is compiled into this module, so there is no Client Spider either,
// and returning a no-op that reported an empty link graph would be exactly the
// silent-clean failure this whole tier is written against.
//
// MEASURED 2026-08-22, PowerShell, on the development host (recorded in
// internal/dast/engines/zap.go's header and in SKIPPED-CONTROLS U5): no zap.sh,
// no zap, no zap.bat, no docker. A JVM is present; ZAP is not.
//
// It never returns (nil, nil).
func SystemClientSpider() (ClientSpider, error) {
	_, err := engines.SystemZapRunner()
	if err == nil {
		return nil, fmt.Errorf("inventory: %w: engines.SystemZapRunner returned a runner "+
			"and no ClientSpider adapter is wired to it. A ZAP that can run and a Client "+
			"Spider Anvil can drive are two different things, and the second one is "+
			"missing", ErrNoClientSpider)
	}
	return nil, fmt.Errorf("%w: the Tier 3 spider is ZAP's Client Spider and ZAP is not "+
		"drivable here: %w", ErrNoClientSpider, err)
}

// ---------------------------------------------------------------------------
// CrawlConfig
// ---------------------------------------------------------------------------

// crawlMethod is the only method a link-graph crawl issues.
//
// It is a const and not configuration. A link is a proposal to READ something;
// a crawler that turned an href into a POST would be letting the target choose
// a state-changing request, and gate 12 and gate 15 would refuse it anyway —
// but they would refuse it AFTER Anvil had decided to make it, which is one
// decision too late. Forms are a different packet.
const crawlMethod = authz.MethodGet

// CrawlConfig is everything CrawlWithClientSpider needs. Nothing in it has a
// default that means "permitted", and nothing in it has a default that means
// "unlimited".
type CrawlConfig struct {
	// Trigger is what kind of run this is. Required, with no default: the
	// zero value is not on the eligibility allowlist, so a caller that forgot
	// this field gets a crawl that did not run rather than one that did.
	Trigger ScanTrigger

	// Governor is the kernel's per-request interceptor for this target.
	Governor *authz.Governor

	// Audit is gate 21's writer, coupled to the interceptor by AuditedAdmit:
	// an admission whose audit row did not land is not an admission.
	Audit *authz.GateAudit

	// Authorization is the kernel token for Target. authz.Adjudicate is the
	// only mint.
	Authorization authz.Authorization

	// Target is the admitted target. Every address the crawl visits lives on
	// it; a link proposing any other origin is refused as a walk-off.
	Target authz.Target

	// Scope is the NARROWED scope — gate 11 has already been applied to it by
	// whoever drove the run from InitiateRun to Adjudicate. The crawl asks it
	// Scope.PermitsPath before every address, which is fail-closed on an
	// origin nobody determined: a scope that was never narrowed permits no
	// path at all, so "nobody fetched robots.txt" cannot read as "robots.txt
	// permitted it".
	Scope authz.Scope

	// Technique is the declared technique for a crawl request. Required;
	// gate 15 judges it and there is no default, because a default here would
	// be a gate running against a value nobody chose.
	// TechniqueContentDiscovery is the accurate one: a crawl enumerates the
	// paths a site publishes.
	Technique authz.Technique

	// Seeds are the paths the crawl starts from. Required and non-empty: they
	// are Anvil's configuration, not target input, and a crawl with no seed
	// reaches nothing while reporting an empty link graph.
	Seeds []string

	// MaxPages bounds requests ISSUED. Required, no default; zero is refused
	// rather than read as unlimited.
	MaxPages int

	// MaxDepth bounds link distance from a seed. Required, no default. It is
	// the bound that terminates a crawl of an infinite site whose every
	// generated path is distinct, so the visited set never saturates.
	MaxDepth int

	// Spider is the browser seam. A nil Spider produces a counted outcome on
	// every address and a loud error — never a silently empty link graph.
	Spider ClientSpider

	// Clock advances the instant between requests. It is D.22's ClockSource,
	// reused rather than re-declared, and for the same reason: gate 14's
	// token bucket refills from the ELAPSED interval between the instants it
	// is handed, so a frozen clock spends the initial bucket and then refuses
	// every remaining request at ReasonRateExceeded — which is the kernel
	// behaving correctly and would cap the crawl for a reason about Anvil's
	// clock rather than about the target. Optional: absent, the run instant
	// is reused, the kernel refuses the overflow, and those addresses carry
	// CrawlOutcomeKernelRefused rather than vanishing.
	Clock ClockSource
}

// Constructed reports whether cfg carries what a crawl needs. Every clause is
// one validateCrawlConfig also checks, so a caller that asks first and a
// caller that just calls cannot disagree about whether a configuration is
// usable.
func (c CrawlConfig) Constructed() bool {
	return c.Target.Constructed() && c.Scope.Constructed() &&
		c.Governor.Constructed() && c.Audit.Constructed() &&
		authz.RequireAuthorization(c.Authorization, c.Target) == nil &&
		c.Technique.Classified() && !c.Technique.Destructive() &&
		len(c.Seeds) > 0 && len(c.Seeds) <= codedMaxSeeds &&
		c.MaxPages > 0 && c.MaxPages <= codedMaxCrawlPages &&
		c.MaxDepth > 0 && c.MaxDepth <= codedMaxCrawlDepth
}

// ---------------------------------------------------------------------------
// CrawlResult
// ---------------------------------------------------------------------------

// CrawlResult is one Tier 3 crawl over one target.
type CrawlResult struct {
	routes     []Route
	refusals   []Refusal
	visits     []CrawlVisit
	trigger    ScanTrigger
	skipReason string
	executed   bool
	discovered int
	enqueued   int
	issued     int
	answered   int
	maxPages   int
	maxDepth   int
	deepest    int
	truncated  bool
	exclusions exclusionSet
	sealed     bool
}

// Constructed reports whether r came from CrawlWithClientSpider.
func (r CrawlResult) Constructed() bool { return r.sealed }

// Executed reports whether the crawl actually ran.
//
// A caller MUST consult this before reading Routes(): a skipped crawl and a
// crawl that found nothing produce the same empty slice, and the two differ by
// everything. AssertNotSilentlyEmpty is the enforcement.
func (r CrawlResult) Executed() bool { return r.executed }

// Trigger is the trigger this crawl was offered.
func (r CrawlResult) Trigger() ScanTrigger { return r.trigger }

// SkipReason names why the crawl did not run, or "" when it did.
func (r CrawlResult) SkipReason() string { return r.skipReason }

// Routes returns a deep COPY of the crawl-discovered routes.
//
// Every one carries record.InventoryProvenanceCrawl and
// ConfirmationCandidate. They are inputs to D.22's MergeAndConfirm, which is
// the only thing that confirms anything.
func (r CrawlResult) Routes() []Route { return cloneRoutes(r.routes) }

// Refusals returns a COPY of every refusal, for D.26's denominator.
func (r CrawlResult) Refusals() []Refusal { return cloneRefusals(r.refusals) }

// Visits returns a COPY of the crawl's ledger, one row per address
// considered, sorted deterministically.
func (r CrawlResult) Visits() []CrawlVisit { return cloneVisits(r.visits) }

// Discovered is how many raw hrefs the crawl was offered, including duplicates
// and unusable ones.
func (r CrawlResult) Discovered() int { return r.discovered }

// Enqueued is how many DISTINCT addresses entered the frontier. It is the
// bound on how many times the loop iterated.
func (r CrawlResult) Enqueued() int { return r.enqueued }

// Issued is how many requests reached the seam. It can never exceed MaxPages.
func (r CrawlResult) Issued() int { return r.issued }

// Answered is how many the TARGET answered, whatever the status. It separates
// "this site has no links" from "Anvil never reached this application".
func (r CrawlResult) Answered() int { return r.answered }

// MaxPages returns the configured page budget, or 0 when the crawl was
// skipped.
func (r CrawlResult) MaxPages() int { return r.maxPages }

// MaxDepth returns the configured depth budget, or 0 when skipped.
func (r CrawlResult) MaxDepth() int { return r.maxDepth }

// DeepestReached is the greatest depth the crawl actually fetched at.
func (r CrawlResult) DeepestReached() int { return r.deepest }

// Truncated reports that the coded frontier bound was reached, so the crawl
// stopped enqueuing addresses it had already seen proposed.
func (r CrawlResult) Truncated() bool { return r.truncated }

// OutcomeMix counts the ledger by outcome.
func (r CrawlResult) OutcomeMix() map[CrawlOutcome]int {
	out := map[CrawlOutcome]int{}
	for _, v := range r.visits {
		out[v.outcome]++
	}
	return out
}

// Unreached returns every address the crawl recorded and never issued a
// request for, sorted. It is the coverage FLOOR: attack surface Anvil saw and
// did not probe.
func (r CrawlResult) Unreached() []CrawlVisit {
	var out []CrawlVisit
	for _, v := range r.visits {
		if !v.outcome.Issued() && v.outcome.InInventory() {
			out = append(out, v)
		}
	}
	SortVisits(out)
	return out
}

// AssertNotSilentlyEmpty separates the three ways an empty Tier 3 happens.
//
// A skipped crawl, a crawl with no seam, and a crawl the target never answered
// all produce zero routes, and only the first is correct. This returns a
// DIFFERENT sentinel for each so a caller cannot collapse them by accident.
func (r CrawlResult) AssertNotSilentlyEmpty() error {
	if !r.executed {
		return fmt.Errorf("%w: trigger %q; %s", ErrCrawlDidNotRun, r.trigger, r.skipReason)
	}
	if r.issued > 0 && r.answered == 0 {
		return fmt.Errorf("%w: %d request(s) were issued and none was answered",
			ErrCrawlFoundNothing, r.issued)
	}
	return nil
}

// AssertBudgetSufficed reports whether any address was left unreached because
// a BUDGET ran out rather than because Anvil decided against it.
//
// It names the same hazard D.22's AssertBudgetSufficed does — research/22's
// Risk #4, where a larger candidate list produces a smaller confirmed count —
// arriving through the crawl instead of through confirmation.
func (r CrawlResult) AssertBudgetSufficed() error {
	starved := map[CrawlOutcome]int{}
	for _, v := range r.visits {
		switch v.outcome {
		case CrawlOutcomePageBudgetExhausted, CrawlOutcomeDepthExceeded,
			CrawlOutcomeFrontierFull, CrawlOutcomeCancelled:
			starved[v.outcome]++
		}
	}
	if len(starved) == 0 {
		return nil
	}
	parts := make([]string, 0, len(starved))
	for _, o := range CrawlOutcomeValues() {
		if n := starved[o]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", o, n))
		}
	}
	return fmt.Errorf("%w: the Tier 3 crawl left addresses unreached (%s), so any coverage "+
		"computed over this crawl is a FLOOR and not a measurement",
		ErrProbeBudgetExhausted, strings.Join(parts, ", "))
}

// AssertEveryRouteIsACandidate is ruling 7, checked rather than asserted.
//
// A crawl-discovered route is a candidate even when the crawl fetched it and
// the target answered 200, because there is exactly one writer of
// ConfirmationConfirmed in this package and it is D.22's.
func (r CrawlResult) AssertEveryRouteIsACandidate() error {
	for _, rt := range r.routes {
		if rt.Confirmation() != ConfirmationCandidate {
			return fmt.Errorf("%w: %s %s carries %q",
				ErrRouteClaimsConfirmed, rt.Method(), redact(rt.Path()), rt.Confirmation())
		}
		if rt.Provenance() != record.InventoryProvenanceCrawl {
			return fmt.Errorf("inventory: %w: %s %s came from the crawl and carries "+
				"provenance %q", ErrRefused, rt.Method(), redact(rt.Path()), rt.Provenance())
		}
	}
	return nil
}

// AssertNoExcludedPathWasVisited re-derives the exclusion predicate over the
// RECORDED LEDGER.
//
// It is deliberately a second, independent look at the same property: the
// enqueue-time filter decides, and this reads back what actually left. A check
// that can only see the decision cannot see the damage — if the filter is ever
// wrong, this is what says so, from evidence, in the result an operator holds.
func (r CrawlResult) AssertNoExcludedPathWasVisited() error {
	for _, v := range r.visits {
		if !v.outcome.Issued() {
			continue
		}
		if p, hit := r.exclusions.covers(v.canon); hit {
			return fmt.Errorf("%w: %s %s was issued (%s) and prefix %q covers it",
				ErrExcludedPathWasVisited, v.method, redact(v.canon), v.outcome, redact(p))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The crawl
// ---------------------------------------------------------------------------

// frontierItem is one address waiting to be fetched.
type frontierItem struct {
	path   string
	canon  string
	depth  int
	hop    int
	origin authz.RequestOrigin
	from   string
}

// crawlState is the loop's own bookkeeping. It exists so the termination
// argument is readable in one place: `visited` only grows, `frontier` only
// receives keys absent from `visited`, and the loop pops one per iteration.
type crawlState struct {
	cfg     CrawlConfig
	exclude exclusionSet
	visited map[string]bool
	queue   []frontierItem
	now     authz.Clock
	out     *CrawlResult
}

// CrawlWithClientSpider is D.23: Tier 3, the browser-driven crawl.
//
// # Signature
//
// plan/50-dast.md D.23 writes it `CrawlWithClientSpider(target *Target,
// exclude []string) ([]Route, error)`. There is no `*Target` in this package —
// the kernel's authz.Target is the type, and it is one of a dozen things a
// crawl needs — so the target and its kernel objects arrive in a CrawlConfig,
// exactly as D.18's Config and D.22's ConfirmConfig do. `exclude` stays a
// named parameter because it is the plan's own emphasis and because an
// exclusion list is worth reading at the call site. The return is a
// CrawlResult rather than a bare []Route for the reason every tier in this
// package returns one: the refusals and the unreached addresses are part of
// the coverage denominator, and a bare slice drops them.
//
// # Order
//
//	0 the trigger gate. Not eligible -> the crawl DOES NOT RUN, and says so.
//	1 validate the configuration; refuse rather than degrade
//	2 seed the frontier
//	3 loop, while the frontier is non-empty and the budgets hold:
//	  3a pop one address; it is already canonical, in scope, not excluded,
//	     within depth, and not visited — every one of those was checked before
//	     it was enqueued, and the ledger carries a row for each that failed
//	  3b authz.NewRequestIntent, carrying the Origin and Hop THIS LOOP chose
//	  3c authz.RequireAuthorization, immediately before anything can leave
//	  3d GateAudit.AuditedAdmit — gates 12..21 and the gate-21 row
//	  3e only now does anything leave, and it leaves through ClientSpider
//	  3f Governor.ObserveResponse feeds gates 16 and 17 and releases the lease
//	  3g a 3xx becomes ONE labelled hop; a body becomes links
//	  3h every link is re-validated from scratch before it is enqueued
//	4 drain whatever is left, recording why each address was not reached
//
// Every failure at every step produces a row on the ledger. None produces a
// shorter inventory, and none produces a silent candidate.
func CrawlWithClientSpider(ctx context.Context, cfg CrawlConfig, now authz.Clock,
	exclude []string) (CrawlResult, error) {

	out := CrawlResult{sealed: true, trigger: cfg.Trigger}

	// Step 0. THE TRIGGER GATE. It runs before the configuration is validated
	// on purpose: an incremental run must not be able to reach a crawl by
	// being differently misconfigured, and "this trigger is not eligible" is
	// the answer whatever else is wrong.
	if !cfg.Trigger.PermitsTier3Crawl() {
		out.skipReason = fmt.Sprintf("trigger %q is not on the Tier 3 eligibility "+
			"allowlist %v. plan/50-dast.md D.23: the browser crawl fires on scheduled "+
			"full scans only, never on the incremental or tag-triggered path",
			redact(string(cfg.Trigger)), []ScanTrigger{ScanTriggerScheduledFull})
		return out, nil
	}

	if err := validateCrawlConfig(cfg); err != nil {
		return CrawlResult{sealed: true, trigger: cfg.Trigger}, err
	}
	ex, err := newExclusionSet(exclude)
	if err != nil {
		return CrawlResult{sealed: true, trigger: cfg.Trigger}, err
	}

	out.executed = true
	out.maxPages = cfg.MaxPages
	out.maxDepth = cfg.MaxDepth
	out.exclusions = ex

	st := &crawlState{
		cfg:     cfg,
		exclude: ex,
		visited: map[string]bool{},
		now:     now,
		out:     &out,
	}

	for _, seed := range cfg.Seeds {
		st.offer(seed, "seed", 0, 0, authz.OriginInitial)
	}

	for len(st.queue) > 0 {
		item := st.queue[0]
		st.queue = st.queue[1:]

		if err := ctx.Err(); err != nil {
			st.record(item, CrawlOutcomeCancelled, 0, 0, now, redact(err.Error()))
			continue
		}
		if out.issued >= cfg.MaxPages {
			st.record(item, CrawlOutcomePageBudgetExhausted, 0, 0, now, fmt.Sprintf(
				"the page budget of %d was spent before this address was reached; it "+
					"stays in the inventory as a candidate, because a budget is a "+
					"statement about Anvil and not about the target", cfg.MaxPages))
			continue
		}
		st.crawlOne(ctx, item, now)
	}

	SortVisits(out.visits)
	SortRoutes(out.routes)

	if cfg.Spider == nil {
		return out, fmt.Errorf("%w: %d address(es) were recorded and none was fetched",
			ErrNoClientSpider, len(out.visits))
	}
	return out, nil
}

func validateCrawlConfig(cfg CrawlConfig) error {
	if !cfg.Target.Constructed() {
		return fmt.Errorf("inventory: %w: the crawl was handed a Target authz.NewTarget "+
			"never built, so no link can be checked against an admitted origin and the "+
			"crawl names no host", ErrUnconstructed)
	}
	if !cfg.Scope.Constructed() {
		return fmt.Errorf("inventory: %w: the crawl was handed a Scope authz.NewScope never "+
			"built. The zero Scope permits no path at all, which is the correct answer and "+
			"a useless crawl; a caller that forgot to pass the NARROWED scope must find "+
			"that out here rather than in an empty inventory", ErrUnconstructed)
	}
	if !cfg.Governor.Constructed() {
		return fmt.Errorf("inventory: %w: the crawl was handed a Governor authz.NewGovernor "+
			"never built. A nil governor enforces nothing, and enforcing nothing is not "+
			"admitting everything", ErrUnconstructed)
	}
	if !cfg.Audit.Constructed() {
		return fmt.Errorf("inventory: %w: the crawl was handed a GateAudit "+
			"authz.NewGateAudit never built. Gate 21 makes the audit write part of the "+
			"decision, and a request with no audit row cannot be joined back to who "+
			"authorized it", ErrUnconstructed)
	}
	if err := authz.RequireAuthorization(cfg.Authorization, cfg.Target); err != nil {
		return fmt.Errorf("inventory: %w: %w", ErrRefused, err)
	}
	if !cfg.Technique.Classified() {
		return fmt.Errorf("inventory: %w: the crawl technique is %q, which is on neither of "+
			"gate 15's compiled-in lists. There is no default: a default here would be a "+
			"gate running against a value nobody chose",
			ErrRefused, redact(string(cfg.Technique)))
	}
	if cfg.Technique.Destructive() {
		return fmt.Errorf("inventory: %w: the crawl technique is %q, which is on gate 15's "+
			"destructive denylist. Following a site's own links is content discovery",
			ErrRefused, redact(string(cfg.Technique)))
	}
	if len(cfg.Seeds) == 0 {
		return fmt.Errorf("inventory: %w: the crawl has no seed path. A crawl with no seed "+
			"reaches nothing and reports a target with no link graph, which are two "+
			"different findings", ErrRefused)
	}
	if len(cfg.Seeds) > codedMaxSeeds {
		return fmt.Errorf("inventory: %w: %d seeds were configured and the coded bound is %d",
			ErrRefused, len(cfg.Seeds), codedMaxSeeds)
	}
	if cfg.MaxPages <= 0 || cfg.MaxPages > codedMaxCrawlPages {
		return fmt.Errorf("inventory: %w: the crawl page budget is %d and must be in 1..%d. "+
			"There is no default, and a zero that meant \"unlimited\" is the shape "+
			"research/22's Risk #4 describes", ErrRefused, cfg.MaxPages, codedMaxCrawlPages)
	}
	if cfg.MaxDepth <= 0 || cfg.MaxDepth > codedMaxCrawlDepth {
		return fmt.Errorf("inventory: %w: the crawl depth budget is %d and must be in 1..%d. "+
			"Depth is what terminates a crawl of a site that generates a fresh distinct "+
			"path per page, so a zero cannot mean \"unlimited\"",
			ErrRefused, cfg.MaxDepth, codedMaxCrawlDepth)
	}
	return nil
}

// clockFor returns the instant for the next request.
func (s *crawlState) clockFor(now authz.Clock) authz.Clock {
	if s.cfg.Clock == nil {
		return now
	}
	return s.cfg.Clock.NextInstant()
}

// record appends one ledger row, and — when the outcome says the address is
// attack surface — one candidate Route.
//
// The route is emitted for an address the crawl NEVER FETCHED as well as for
// one it did. That is the denominator decision: a link Anvil saw and could not
// reach is surface that exists, and leaving it out would make endpoint_coverage
// improve every time the crawl ran out of budget.
func (s *crawlState) record(item frontierItem, outcome CrawlOutcome, status int,
	seq authz.AuditSeq, at authz.Clock, detail string) {

	v := CrawlVisit{
		method:   crawlMethod,
		path:     item.path,
		canon:    item.canon,
		depth:    item.depth,
		hop:      item.hop,
		origin:   item.origin,
		outcome:  outcome,
		status:   status,
		auditSeq: seq,
		at:       at.Instant(),
		from:     item.from,
		detail:   detail,
		sealed:   true,
	}
	s.out.visits = append(s.out.visits, v)

	if !outcome.InInventory() {
		return
	}
	s.emitRoute(item)
}

// emitRoute turns one reached-or-reachable address into a CANDIDATE route.
func (s *crawlState) emitRoute(item frontierItem) {
	params, err := crawlQueryParams(item.path)
	if err != nil {
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.path),
			Method: string(crawlMethod),
			Reason: RefusalParamUnusable,
			Detail: redact(err.Error()),
		})
		params = nil
	}
	rt, rerr := NewRoute(RouteFacts{
		Method:     crawlMethod,
		Path:       item.canon,
		Target:     s.cfg.Target,
		Params:     params,
		Provenance: record.InventoryProvenanceCrawl,
		// UNCONDITIONAL, and it stays unconditional if this address answered
		// 200 to a request this crawl made. Ruling 7 and D.22 own the other
		// value; see AssertEveryRouteIsACandidate.
		Confirmation: ConfirmationCandidate,
		Trust:        record.TrustUntrusted,
	})
	if rerr != nil {
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.canon),
			Method: string(crawlMethod),
			Reason: RefusalRouteUnconstructible,
			Detail: redact(rerr.Error()),
		})
		return
	}
	s.out.routes = append(s.out.routes, rt)
}

// crawlOne drives ONE address through the kernel and the seam.
func (s *crawlState) crawlOne(ctx context.Context, item frontierItem, now authz.Clock) {
	// The seam is checked BEFORE the kernel is asked. An admission spends
	// gate 14's rate token, its volume budget and a gate-21 row, and spending
	// them on a request that cannot leave the process would make the audit
	// log claim Anvil issued requests it never issued.
	if s.cfg.Spider == nil {
		s.record(item, CrawlOutcomeFetchFailed, 0, 0, now,
			"no ClientSpider is wired, so nothing could leave the process. The address "+
				"stays in the inventory as a candidate: this is a fact about Anvil")
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.path),
			Method: string(crawlMethod),
			Reason: RefusalNoFetcherWired,
			Detail: "no ClientSpider is wired",
		})
		return
	}

	at := s.clockFor(now)

	intent, err := authz.NewRequestIntent(authz.RequestFacts{
		Origin:   item.origin,
		Admitted: s.cfg.Target,
		Next:     s.cfg.Target,
		Method:   crawlMethod,
		Path:     item.path,
		Hop:      item.hop,
	})
	if err != nil {
		// A redirect chain past authz's maxRedirectHops lands here, refused
		// by the kernel's own constant before any gate runs. There is no
		// local copy of that bound.
		s.record(item, CrawlOutcomeIntentRejected, 0, 0, at, redact(err.Error()))
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.path),
			Method: string(crawlMethod),
			Reason: RefusalIntentRejected,
			Detail: redact(err.Error()),
		})
		return
	}

	// Gate 3's runtime half, at the moment a socket could be constructed —
	// done again even though validateCrawlConfig already did it, because the
	// token and the target are both still in scope right here.
	if err := authz.RequireAuthorization(s.cfg.Authorization, s.cfg.Target); err != nil {
		s.record(item, CrawlOutcomeKernelRefused, 0, 0, at, redact(err.Error()))
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.path),
			Method: string(crawlMethod),
			Reason: RefusalKernelRefused,
			Detail: redact(err.Error()),
		})
		return
	}

	lease, res := s.cfg.Audit.AuditedAdmit(s.cfg.Governor, intent, s.cfg.Technique, at)
	if !res.Passed() {
		s.record(item, CrawlOutcomeKernelRefused, 0, 0, at, fmt.Sprintf(
			"the kernel refused at %s: %s", res.Gate(), redact(errText(res.Err()))))
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.path),
			Method: string(crawlMethod),
			Reason: RefusalKernelRefused,
			Detail: fmt.Sprintf("the kernel refused at %s: %s",
				res.Gate(), redact(errText(res.Err()))),
		})
		return
	}

	seq := s.cfg.Audit.LastSeq()

	req := CrawlRequest{
		auth:      s.cfg.Authorization,
		target:    s.cfg.Target,
		method:    crawlMethod,
		path:      item.path,
		technique: s.cfg.Technique,
		origin:    item.origin,
		hop:       item.hop,
		seq:       seq,
		sealed:    true,
	}

	s.out.issued++
	page, perr := s.cfg.Spider.FetchPage(ctx, req)
	if perr != nil {
		obsRes := s.cfg.Governor.ObserveConnectionError(lease, at)
		s.cfg.Audit.AuditedObservation(obsRes, s.cfg.Target, at)
		s.record(item, CrawlOutcomeFetchFailed, 0, seq, at, redact(perr.Error()))
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.path),
			Method: string(crawlMethod),
			Reason: RefusalFetchFailed,
			Detail: redact(perr.Error()),
		})
		return
	}

	// A status outside [100,599] is NOT an answer. D.22 holds the same rule
	// for the same reason: 0 is non-404, and a seam that lost the response
	// must not read as a page that exists.
	if page.Status < minStatusCode || page.Status > maxStatusCode {
		obsRes := s.cfg.Governor.ObserveConnectionError(lease, at)
		s.cfg.Audit.AuditedObservation(obsRes, s.cfg.Target, at)
		s.record(item, CrawlOutcomeFetchFailed, 0, seq, at, fmt.Sprintf(
			"the spider returned status %d, which is not an HTTP status", page.Status))
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.path),
			Method: string(crawlMethod),
			Reason: RefusalFetchFailed,
			Detail: fmt.Sprintf("the spider returned status %d, which is not an HTTP status",
				page.Status),
		})
		return
	}

	// ObserveResponse releases the lease and feeds gates 16 and 17, so a
	// target that starts degrading under a crawl trips the breaker rather
	// than being driven through the whole page budget.
	obsRes := s.cfg.Governor.ObserveResponse(lease, page.Status, page.Latency, nil, at)
	s.cfg.Audit.AuditedObservation(obsRes, s.cfg.Target, at)
	s.out.answered++
	if item.depth > s.out.deepest {
		s.out.deepest = item.depth
	}

	outcome := CrawlOutcomeFetched
	detail := ""
	if page.Status >= 300 && page.Status < 400 && strings.TrimSpace(page.Location) != "" {
		// THE LABELLED HOP. This is the one place in the module that holds a
		// 3xx and knows what its follow-up is, so it is the one place that
		// can fill Origin and Hop honestly.
		outcome = CrawlOutcomeRedirected
		detail = fmt.Sprintf("status %d; the Location was re-admitted as hop %d",
			page.Status, item.hop+1)
		s.offer(page.Location, item.path, item.depth, item.hop+1, authz.OriginRedirect)
	}
	if outcome == CrawlOutcomeFetched {
		detail = fmt.Sprintf("status %d", page.Status)
	}
	s.record(item, outcome, page.Status, seq, at, detail)

	// Links from the page. THIS IS THE UNTRUSTED HALF: every one of them is a
	// destination the TARGET proposed, and every one goes back through offer,
	// which re-validates from scratch.
	links := page.Links
	if len(links) > codedMaxLinksPerPage {
		s.out.refusals = append(s.out.refusals, Refusal{
			Path:   redact(item.canon),
			Method: string(crawlMethod),
			Reason: RefusalSpecTruncated,
			Detail: fmt.Sprintf("the page proposed %d links and the coded per-page bound "+
				"is %d; the remainder were not read", len(links), codedMaxLinksPerPage),
		})
		links = links[:codedMaxLinksPerPage]
	}
	for _, href := range links {
		s.offer(href, item.path, item.depth+1, 0, authz.OriginInitial)
	}
}

// offer is the ONLY way an address enters the frontier.
//
// It runs the whole re-validation from scratch on every href, on every hop,
// with no fast path and no memo of a previous decision about a "similar" link,
// because the input is chosen by the target and the cheapest way to defeat a
// filter is to make it look like something already approved.
//
// The order is chosen so the ledger sends a reader to the right place:
// unusable first (it is the link's fault), then off-host (the walk-off), then
// excluded (Anvil's decision), then scope (the kernel's), then the budgets
// (Anvil's own limits), then the visited set.
func (s *crawlState) offer(href, from string, depth, hop int, origin authz.RequestOrigin) {
	s.out.discovered++

	if len(href) > codedMaxLinkBytes {
		s.noteUnreachable(href, from, depth, hop, origin, CrawlOutcomeLinkUnusable,
			fmt.Sprintf("the link is %d bytes and the coded bound is %d",
				len(href), codedMaxLinkBytes))
		return
	}

	// requestPath is what would go on the wire, QUERY INCLUDED — "/search?q=1"
	// is a different request from "/search". addressPath is the same string
	// with the query removed, because "?q=1" and "?q=2" are ONE endpoint with
	// a parameter and two rows would inflate the denominator of a fraction
	// that is supposed to be auditable.
	requestPath, err := resolveLinkPath(s.cfg.Target, from, href)
	if err != nil {
		outcome := CrawlOutcomeLinkUnusable
		if errors.Is(err, errLinkOffHost) {
			outcome = CrawlOutcomeOffHost
		}
		s.noteUnreachable(href, from, depth, hop, origin, outcome, redact(err.Error()))
		return
	}
	addressPath := stripQuery(requestPath)

	// ONE canonicalizer: D.20's, the same one D.22 keys its union on. A
	// second one here could disagree, and the disagreement would be silent —
	// two spellings of one address, one of them fetched twice.
	canon, _, cerr := canonicalizePattern(addressPath)
	if cerr != nil {
		s.noteUnreachable(href, from, depth, hop, origin, CrawlOutcomeLinkUnusable,
			redact(cerr.Error()))
		return
	}
	if canon != addressPath {
		// The link's path carries placeholder-shaped segments, so its
		// canonical identity is a TEMPLATE. Requesting a template is
		// requesting a path nobody published; refuse it and say so, rather
		// than fetch one spelling and file it under another.
		s.noteUnreachable(href, from, depth, hop, origin, CrawlOutcomeLinkUnusable,
			fmt.Sprintf("the canonicalizer rewrote %q to %q, so its identity is a "+
				"template and not an address", redact(addressPath), redact(canon)))
		return
	}
	// Both spellings go through the KERNEL's own path validation: the one
	// that would be requested, and the one that becomes a Route.
	if err := kernelAcceptsPath(s.cfg.Target, crawlMethod, requestPath); err != nil {
		s.noteUnreachable(href, from, depth, hop, origin, CrawlOutcomeLinkUnusable,
			redact(err.Error()))
		return
	}
	if err := kernelAcceptsPath(s.cfg.Target, crawlMethod, canon); err != nil {
		s.noteUnreachable(href, from, depth, hop, origin, CrawlOutcomeLinkUnusable,
			redact(err.Error()))
		return
	}

	item := frontierItem{path: requestPath, canon: canon, depth: depth, hop: hop,
		origin: origin, from: from}

	if p, hit := s.exclude.covers(canon); hit {
		s.record(item, CrawlOutcomeMetaSurfaceExcluded, 0, 0, s.now, fmt.Sprintf(
			"prefix %q covers it. plan/50-dast.md D.23 forbids crawling Swagger UI and "+
				"GraphQL playground routes even when the crawl finds them itself: they "+
				"are meta-surface, Tier 0 already reads the document behind them in one "+
				"request, and crawling the app that renders it spends the tightest "+
				"budget in the pipeline", redact(p)))
		return
	}

	// Gate 11's narrowing, consulted through the kernel's own method. It is
	// fail-closed on an origin nobody determined: a scope that was never
	// narrowed permits no path, so "nobody fetched robots.txt" cannot read as
	// "robots.txt permitted this".
	if !s.cfg.Scope.PermitsPath(s.cfg.Target.Canonical(), s.cfg.Target.Port(), canon) {
		s.record(item, CrawlOutcomeOutsideNarrowedScope, 0, 0, s.now,
			"Scope.PermitsPath refused it: either no allow entry covers this origin, or "+
				"gate 11's narrowing removed this path, or no robots determination "+
				"covers the origin at all — which is refused rather than assumed "+
				"permissive")
		return
	}

	if depth > s.cfg.MaxDepth {
		s.record(item, CrawlOutcomeDepthExceeded, 0, 0, s.now, fmt.Sprintf(
			"this address is %d links from a seed and the depth budget is %d",
			depth, s.cfg.MaxDepth))
		return
	}

	key := endpointKey(crawlMethod, canon)
	if s.visited[key] {
		// The termination invariant, and the cyclic-site answer: an address
		// is admitted to the frontier at most once, so a cycle A->B->A stops
		// here. It is not recorded again — it already has a ledger row and a
		// route from the first time — and it is not a refusal, because
		// nothing was refused.
		return
	}
	if len(s.visited) >= codedMaxFrontier {
		s.out.truncated = true
		s.record(item, CrawlOutcomeFrontierFull, 0, 0, s.now, fmt.Sprintf(
			"the crawl has already admitted %d distinct addresses, which is the coded "+
				"frontier bound", codedMaxFrontier))
		return
	}

	s.visited[key] = true
	s.out.enqueued++
	s.queue = append(s.queue, item)
}

// noteUnreachable records an href that never became an address.
//
// It cannot use record(), which takes a frontierItem — there is no canonical
// path for a link that would not resolve — so it writes the row directly with
// the raw href redacted into the path field, and emits NO route: a string that
// is not a path is not attack surface.
func (s *crawlState) noteUnreachable(href, from string, depth, hop int,
	origin authz.RequestOrigin, outcome CrawlOutcome, detail string) {

	s.out.visits = append(s.out.visits, CrawlVisit{
		method:  crawlMethod,
		path:    redact(href),
		canon:   redact(href),
		depth:   depth,
		hop:     hop,
		origin:  origin,
		outcome: outcome,
		from:    from,
		detail:  detail,
		sealed:  true,
	})
}

// ---------------------------------------------------------------------------
// Link resolution — the untrusted half
// ---------------------------------------------------------------------------

// errLinkOffHost is the sentinel resolveLinkPath returns for a link that
// proposes an origin other than the admitted one.
var errLinkOffHost = errors.New("the link proposes an origin other than the admitted target")

// resolveLinkPath turns one href into a request path on the admitted target,
// or refuses it.
//
// # What it will not do
//
// It will NEVER return a path for a link naming a different host, port or
// scheme, and it constructs no second Target to reach one. That is not a
// convenience: authz.NewTarget requires a PINNED address, which means a DNS
// resolution, which is exactly the rebinding surface gate 9 exists to close.
// A crawl cannot resolve a name, so a crawl cannot leave the admitted origin,
// and the walk-off is refused at the link rather than at the socket.
//
// The host comparison goes through authz.Canonicalize — the KERNEL's
// canonicalization, gate 8's own — so an IDN, a trailing dot, a mixed-case
// host or a percent-encoded one compares the way the kernel would compare it,
// and this file holds no second opinion about what two hosts being equal
// means.
func resolveLinkPath(target authz.Target, from, href string) (string, error) {
	raw := strings.TrimSpace(href)
	if raw == "" {
		return "", errors.New("the link is empty")
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("the link does not parse as a URL: %v", err)
	}
	if ref.Scheme != "" && ref.Scheme != string(authz.SchemeHTTP) &&
		ref.Scheme != string(authz.SchemeHTTPS) {
		// mailto:, javascript:, data:, tel:, and every other scheme a page
		// can put in an href. None of them is a request Anvil makes.
		return "", fmt.Errorf("the link's scheme is %q and only http and https are "+
			"requestable", redact(ref.Scheme))
	}

	base := &url.URL{
		Scheme: string(target.Scheme()),
		Host:   target.Canonical(),
		Path:   from,
	}
	if !strings.HasPrefix(base.Path, "/") {
		base.Path = "/"
	}
	abs := base.ResolveReference(ref)

	if abs.Scheme != string(target.Scheme()) {
		return "", fmt.Errorf("%w: it names scheme %q and the admitted target is %q",
			errLinkOffHost, redact(abs.Scheme), target.Scheme())
	}
	host := abs.Hostname()
	if host == "" {
		return "", fmt.Errorf("%w: the resolved link names no host", errLinkOffHost)
	}
	canonHost, cerr := authz.Canonicalize(host)
	if cerr != nil {
		return "", fmt.Errorf("%w: the link's host is one gate 8 will not canonicalize: %v",
			errLinkOffHost, cerr)
	}
	if canonHost != target.Canonical() {
		return "", fmt.Errorf("%w: it names host %q and the admitted host is %q",
			errLinkOffHost, redact(canonHost), redact(target.Canonical()))
	}
	if port := abs.Port(); port != "" && port != fmt.Sprintf("%d", target.Port()) {
		return "", fmt.Errorf("%w: it names port %q and the admitted port is %d",
			errLinkOffHost, redact(port), target.Port())
	}

	// EscapedPath, not Path: it is the on-the-wire form, so it stays printable
	// ASCII and the kernel's charset rule judges the bytes that would actually
	// be sent rather than their decoded shadow.
	p := abs.EscapedPath()
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("the resolved path %q does not begin with \"/\"", redact(p))
	}

	// CANONICALIZE BEFORE MATCHING. url.ResolveReference above removed the dot
	// segments a link spelled LITERALLY; it left every ENCODED spelling of one
	// standing, because "%2e%2e" is an ordinary path segment to a URL resolver
	// and a parent reference to every browser. Everything downstream of here —
	// gate 11's narrowing, the exclusion list, the visited set, the kernel's
	// own path validation — is a MATCH against these bytes, so a spelling that
	// is normalized after the match is not normalized at all.
	spelled, serr := dotSegmentsSpelledPlainly(p)
	if serr != nil {
		return "", serr
	}
	if spelled != p {
		// Resolve the rewritten spelling THE SAME WAY the literal one was
		// resolved, through the same url.ResolveReference. This file adds no
		// dot-segment resolver of its own: the rewrite above only changes how
		// a parent reference is SPELLED, and the resolution stays Go's, which
		// is the one the literal route already used.
		ref, perr := url.Parse(spelled)
		if perr != nil {
			return "", fmt.Errorf("the link's canonical spelling %q does not parse: %v",
				redact(spelled), perr)
		}
		root := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}
		p = root.ResolveReference(ref).EscapedPath()
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			return "", fmt.Errorf("the canonical path %q does not begin with \"/\"",
				redact(p))
		}
	}

	// The FRAGMENT is dropped here and never travels: it does not reach the
	// server, so "/a#x" and "/a" are one request and keeping it would put a
	// byte on the wire the browser would not have sent.
	//
	// The QUERY IS KEPT. "/search?q=1" is a different request from "/search",
	// and a crawler that dropped the query would fetch a page the link did not
	// point at. It is removed later, by stripQuery, only to compute the
	// ADDRESS the route is filed under — "?id=1" and "?id=2" are one endpoint
	// with a parameter, and two rows there would inflate the denominator.
	if q := abs.RawQuery; q != "" {
		p += "?" + q
	}
	return p, nil
}

// errLinkAmbiguous is the sentinel for a link whose canonical identity is not
// one value: two conforming intermediaries would read it as two different
// paths, so Anvil requests neither.
var errLinkAmbiguous = errors.New("the link's canonical identity is ambiguous")

// dotSegmentsSpelledPlainly rewrites every ENCODED spelling of "." and ".."
// into the literal segment, and REFUSES every spelling whose canonical
// identity is not a single value.
//
// # Why this exists at all
//
// THIS IS THE THIRD TIME THIS BUILD HAS LOST TO A NON-CANONICAL SPELLING —
// gate 8 encodes the lesson, containment lost to ::ffff:169.254.169.254/128,
// and D.25 measured this crawl fetching "/%2e%2e/admin" while refusing the
// plain "/admin" that gate 11 had removed. Every browser resolves the first to
// the second. A control that matches on bytes the client will re-interpret is
// matching on the wrong bytes.
//
// # What it does NOT do
//
// It does not remove dot segments. url.URL.ResolveReference does that, in
// resolveLinkPath, for links and hops alike; this function only changes how a
// parent reference is SPELLED so that the resolver already in the path can see
// it. A second dot-segment resolver here is a second thing that can disagree
// with the first, and the disagreement would be silent.
//
// It also does not decode the path. A segment that is not a dot segment is
// returned byte-for-byte as the link spelled it, so the request that leaves is
// the request the link named and the kernel's charset rule still judges the
// bytes that would actually be sent.
//
// # The three refusals, all of them fail-closed
//
// Each is a spelling for which "what path is this" has more than one correct
// answer, so there is no canonical form to match gate 11 against:
//
//	AN ENCODED SEPARATOR ("..%2f", "%2e%2e%2fadmin", "x%5C..%5Cadmin").
//	One decode turns it into a segment boundary, and a proxy that decodes
//	before routing and an origin that decodes after disagree about how many
//	segments the path has. The backslash is included because a browser and a
//	Windows origin both treat it as a separator.
//
//	A DOUBLY-ENCODED DOT SEGMENT ("%252e%252e"). A browser decodes once, so
//	this is the ordinary segment "%2e%2e"; an origin that decodes twice reads
//	"..". Anvil cannot know which, and guessing in the permissive direction is
//	how the walk-off happens.
//
//	AN OVERLONG OR OTHERWISE INVALID ENCODING ("%c0%ae"). It decodes to bytes
//	that are not valid UTF-8, which some decoders fold to "." and others
//	reject.
//
// Every refusal lands in the ledger as CrawlOutcomeLinkUnusable with the
// reason, because a link Anvil saw and would not request is a fact about the
// target an operator gets to read.
// separatorBytes is the set of bytes a client may treat as a path
// separator: the slash, and the backslash that a browser and a Windows
// origin both fold to one. The backslash is written FIRST so this stays a
// character set and not a path literal — TestTheOnlyPathLiteralsInThisTierAreTheExclusionList
// refuses a path constant in this file, and it is right to.
const separatorBytes = "\\/"

func dotSegmentsSpelledPlainly(escapedPath string) (string, error) {
	const dot, dotDot = ".", ".."
	segs := strings.Split(escapedPath, "/")
	out := make([]string, len(segs))
	for i, seg := range segs {
		dec, derr := url.PathUnescape(seg)
		if derr != nil {
			return "", fmt.Errorf("%w: segment %q is not a valid percent-encoding: %v",
				errLinkAmbiguous, redact(seg), derr)
		}
		if strings.ContainsAny(dec, separatorBytes) {
			return "", fmt.Errorf("%w: segment %q carries an ENCODED SEPARATOR. A proxy "+
				"that decodes before routing and an origin that decodes after do not "+
				"agree on how many segments this path has, so there is no single "+
				"canonical form to match gate 11's narrowing against",
				errLinkAmbiguous, redact(seg))
		}
		if !utf8.ValidString(dec) {
			return "", fmt.Errorf("%w: segment %q decodes to bytes that are not valid "+
				"UTF-8. An overlong encoding of \".\" is folded to a dot segment by some "+
				"decoders and rejected by others", errLinkAmbiguous, redact(seg))
		}
		if again, aerr := url.PathUnescape(dec); aerr == nil && again != dec &&
			(again == dot || again == dotDot || strings.ContainsAny(again, separatorBytes)) {
			return "", fmt.Errorf("%w: segment %q is a DOUBLY-ENCODED dot segment or "+
				"separator. A browser decodes once and reads an ordinary segment; an "+
				"origin that decodes twice reads a parent reference",
				errLinkAmbiguous, redact(seg))
		}
		switch dec {
		case dot, dotDot:
			// The one rewrite: spell it the way the resolver in
			// resolveLinkPath can see it. "%2e%2e" and ".." are the same
			// request to every client that will ever issue it.
			out[i] = dec
		default:
			out[i] = seg
		}
	}
	return strings.Join(out, "/"), nil
}

// stripQuery returns the address half of a request path: everything before the
// first "?". A path with no query is returned unchanged.
//
// It is a string split and NOT a canonicalization — nothing in this file
// matches on its output without first running it through
// canonicalizePattern, which is D.20's and the package's only one.
func stripQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		if i == 0 {
			return "/"
		}
		return path[:i]
	}
	return path
}

// crawlQueryParams lifts a crawled URL's query keys into typed-position
// parameters.
//
// The TYPE is left empty and stays empty. A crawl cannot know a parameter's
// type, and inventing "string" would make Param.Typed() — the predicate
// plan/50-dast.md:610's "parameter-typed" claim is measured by — lie. Required
// is false for the same reason: a link carrying a parameter is not evidence
// the server demands it.
//
// It takes the REQUEST path — the one resolveLinkPath kept the query on — and
// is called by emitRoute, which files the route under the address half.
func crawlQueryParams(path string) ([]Param, error) {
	i := strings.IndexByte(path, '?')
	if i < 0 {
		return nil, nil
	}
	q := path[i+1:]
	values, err := url.ParseQuery(q)
	if err != nil {
		return nil, fmt.Errorf("the link's query string does not parse: %v", err)
	}
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]Param, 0, len(names))
	for _, k := range names {
		if k == "" || len(k) > maxIdentBytes {
			continue
		}
		if len(out) >= maxParamsPerRoute {
			break
		}
		out = append(out, Param{Name: k, In: ParamInQuery})
	}
	return out, nil
}
