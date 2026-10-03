// This file is Go route extraction: Tier 2, static route extraction from Go source.
//
// ===========================================================================
// WHAT TIER 2 IS
// ===========================================================================
//
// Tier 0 asked the running target to describe itself. Tier 1 read the spec
// files somebody checked into the repository. Tier 2 reads THE SOURCE, and it
// exists because the first two lie by omission: an endpoint nobody documented
// is exactly the endpoint worth probing.
//
// research/22-attack-surface-discovery.md lines 330-341 fix the method before
// this file makes any choice about it: "Do not use the SAST LLM to enumerate
// routes -- use deterministic AST tooling." A language model asked to list a
// repository's routes will produce a plausible list, and a plausible list is
// worse than a short one, because a hallucinated endpoint enters the coverage
// DENOMINATOR and can never be confirmed out of it. Everything below is a
// parser.
//
// ===========================================================================
// EVERY ROUTE THIS FILE PRODUCES IS A CANDIDATE. THERE IS NO OTHER PATH.
// ===========================================================================
//
// Go route extraction's forbidden actions: "Do not mark any Tier 2 output as
// `status: confirmed` at extraction time -- every route from this step is
// `status: candidate` until route confirmation confirms it via live probe."
//
// The enforcement is not a review convention. Every Route leaving this file
// goes through ONE function, toRoute, which writes ConfirmationCandidate as a
// constant. There is no parameter, no config field and no branch that can
// produce ConfirmationConfirmed here, and TestNoRouteFromThisTierIsEverConfirmed
// asserts it over every fixture in the suite including the hostile ones.
//
// The arithmetic is why. plan/design/dynamic-tier.md:1152 defines endpoint_coverage as
// confirmed-probed endpoints over the union of the Tier 0-2 inventory. A
// source file contains route registrations that never run -- behind a build
// tag, in dead code, in a handler wired to a mux that is never served. Marking
// those confirmed puts them in the NUMERATOR, and a scan that probed nothing
// then reports coverage. Promotion is route confirmation's job and inflating it here
// corrupts endpoint_coverage downstream.
//
// ===========================================================================
// TARGET SOURCE IS ATTACKER-AUTHORED INPUT
// ===========================================================================
//
// The repo spec reader recorded the lesson in its own header: 169.254.169.254 was a legal
// Compose service name, so a committed file could point Anvil's health check
// at the cloud metadata endpoint. A route pattern in a .go file is the same
// shape of thing, and gate 11's asymmetry applies here verbatim:
//
//	A SOURCE FILE FROM THE REPOSITORY MAY ONLY ADD DENIES, NEVER GRANTS.
//
//	MAY   add CANDIDATE routes to the inventory
//	MAY   enlarge the denominator of endpoint_coverage
//	NEVER widen scope         -- no host, scheme or port is ever read out of
//	                             source. A pattern's host part (net/http 1.22
//	                             allows "example.com/path") is DISCARDED, and
//	                             the discard is reported as a caveat rather
//	                             than done quietly.
//	NEVER grant authorization -- this file cannot mint an authz.Authorization,
//	                             holds no fetcher, and opens no socket
//	NEVER mark anything confirmed
//
// record.TrustUntrusted is stamped on every route, with no code path that can
// change it.
//
// ===========================================================================
// THIS FILE OPENS NOTHING, AND KNOWS NO REPOSITORY PATH
// ===========================================================================
//
// DEVIATION FROM the signature Go route extraction's design states, which is
// `ExtractGoRoutes(repoPath string) ([]Route, error)`. Stated, not hidden.
//
// The repo spec reader established the opposite shape for this package and gave the reason:
// plan/design/dynamic-tier.md:628-630 makes repository harvesting the SAST tier's job, and
// TestTier1KnowsNoRepositoryPathAndOpensNothing enforces it by parsing that
// file's own syntax tree. A repoPath parameter here would put os and
// path/filepath into this package, and then Tier 2 would be walking an
// attacker-controlled directory tree -- symlinks, device files, a .go file
// that is four gigabytes -- with none of the SAST tier's harvest controls.
//
// So ExtractGoRoutes keeps its name and changes its parameters: it takes
// GoSourceFile values the harvest pass already produced, each carrying a
// record.ArtifactLocation and a record.ArtifactContent, exactly as the repo spec reader's
// SpecFile does. THE INVENTORY RULING made the repo spec reader's input shape
// internal/record rather than a placeholder; this is the same shape one tier
// later. TestTier2OpensNothingAndKnowsNoRepositoryPath parses THIS file's
// syntax tree and fails on any filesystem import.
//
// ===========================================================================
// TWO MODES, AND WHY THE ONE THAT SHIPS IS THE WEAKER ONE
// ===========================================================================
//
// Go route extraction's design specifies go-apispec's pipeline: package load + type
// check -> AST traversal -> call graph from router registration to handler ->
// OpenAPI emission. That pipeline resolves things a parser cannot: a path
// built from a constant in another package, a router stored in a struct field
// and passed across four call sites, a handler registered through an
// interface.
//
// It is also golang.org/x/tools/go/packages in a type-checking mode, which
// RUNS `go list` OVER THE TARGET REPOSITORY -- module downloads, and with cgo
// the C toolchain. Against an untrusted target repository that is a
// code-execution surface, and it belongs behind network containment rather than
// in this process. third_party/go-apispec/PIN.md section 5 records the two
// measured blockers to vendoring it inside Go route extraction's write scope.
//
// So there are two modes and the seam between them is an interface:
//
//	ExtractionModeSyntactic    go/ast, go/parser, go/token. In process. Parses
//	                           source as INERT BYTES and executes nothing.
//	                           Ships today; every test below drives it.
//	ExtractionModeTypeChecked  TypeCheckedExtractor, supplied from OUTSIDE
//	                           this package. Nothing is wired today, so the
//	                           mode REFUSES LOUDLY (ErrNoTypeCheckedExtractor)
//	                           and never degrades into an empty route list.
//
// All three go/* packages are already on gate 3's inert allowlist
// (internal/dast/authz/egress_chokepoint_test.go), described there as "Go
// syntax trees" and "Go source parsing". Nothing in this file can construct a
// connection, and the guard that says so is a repository scan rather than this
// sentence.
//
// A TypeCheckedExtractor's output is re-validated by exactly the same
// toRoute path as the syntactic extractor's. It hands back raw strings; it
// cannot hand back a Route, cannot choose a Confirmation, and cannot bypass
// the kernel's path validation. A seam that could mint its own routes would be
// a way to launder a confirmed endpoint into the numerator from outside.
//
// ===========================================================================
// WHAT THE SYNTACTIC MODE CANNOT SEE, AND WHY THAT IS REPORTED RATHER THAN
// DROPPED
// ===========================================================================
//
// research/22 notes that go-apispec-style tooling cannot see reflection-based
// or computed-path routes at all. A parser sees even less. The failure mode to
// avoid is the silent one: a route the extractor could not resolve, dropped
// without trace, SHRINKS the coverage denominator and makes coverage look
// better than it is.
//
// So every gap is a CoverageCaveat, counted, returned, and folded into
// ExtractResult.DenominatorFloor:
//
//	CaveatPathNotStaticallyResolvable  r.Get(basePath+"/x", h) -- the pattern
//	                                   is not a string literal
//	CaveatRouterNotResolved            a registration on a receiver this file
//	                                   could not tie to a router
//	CaveatMethodNotEnumerated          a method-agnostic registration
//	                                   (chi Handle, gin Any, echo Any, fiber
//	                                   All): the path is real and GET is real,
//	                                   the OTHER methods were not enumerated
//	CaveatMountNotFollowed             chi Mount / Use with a non-literal
//	                                   sub-router
//	CaveatHostPatternDiscarded         a net/http 1.22 pattern carrying a host
//	CaveatFileUnparseable              a .go file that did not parse
//
// A caveat is not a Refusal. The runtime spec probe's RefusalReason vocabulary is closed and
// lives in tier0_runtime.go; the repo spec reader added none and neither does this file. A
// Refusal here means "this tier saw a concrete route and could not represent
// it"; a caveat means "this tier knows it did not see everything".
//
// ===========================================================================
// CANONICALIZATION, BECAUSE THE THREE TIERS GET UNIONED
// ===========================================================================
//
// gin spells a path parameter ":id". chi and gorilla/mux spell it "{id}". echo
// spells it ":id". fiber spells it ":id". net/http 1.22 spells it "{id}" and a
// trailing wildcard "{path...}". gorilla/mux allows a regex, "{id:[0-9]+}".
//
// Coverage reporting deduplicates the Tier 0-2 union on Route.Key(), which is method, path
// and operation. Six spellings of one endpoint are six rows in a denominator
// that is supposed to be auditable, so this file canonicalizes EVERY
// placeholder to the OpenAPI spelling "{name}" -- the spelling Tier 0 and Tier
// 1 already emit, because that is what the documents they read use. Canonical
// form is the kernel-facing one and it is produced before Route.Key() is ever
// taken, never after.
//
// TestGinAndChiSpellingsOfOneEndpointProduceOneKey is that claim measured
// across two frameworks rather than asserted here.
//
// ===========================================================================
// FRAMEWORK ATTRIBUTION IS BY IDENTITY, NEVER BY POSITION
// ===========================================================================
//
// The naive extractor greps for `.Get(` and `.GET(`. It produces routes from
// every type in the repository that happens to have a method of that name --
// a cache, a config store, an ORM.
//
// This file will not treat a call as a registration unless the receiver
// RESOLVES to a router: bound by a constructor it can see (chi.NewRouter,
// gin.Default, echo.New, fiber.New, mux.NewRouter, http.NewServeMux), by a
// declared parameter or field type (chi.Router, *gin.Engine, *echo.Echo,
// *fiber.App, *mux.Router, *http.ServeMux), or by a group/subrouter call on a
// router already bound. The framework comes from THAT binding, not from the
// method name and not from which import happens to be first in the file.
//
// A receiver that does not resolve produces CaveatRouterNotResolved, never a
// guess. Guessing is how `cache.Get("/etc/passwd")` becomes an endpoint.
//
// Sources: Go route extraction's design (lines 644-676) and the Coverage Reporting
// Contract (lines 1142-1160); research/22-attack-surface-discovery.md lines
// 330-341; third_party/go-apispec/PIN.md; internal/record/contract.go.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrNoTypeCheckedExtractor is returned when ExtractionModeTypeChecked is
	// selected and no TypeCheckedExtractor is wired.
	//
	// It is an error and not an empty result for the reason the whole package
	// exists: "the type-checked pipeline is not available on this host" and
	// "this repository registers no routes" must never produce the same
	// value. third_party/go-apispec/PIN.md section 5 records why nothing is
	// wired today.
	ErrNoTypeCheckedExtractor = errors.New("inventory: ExtractionModeTypeChecked was " +
		"selected and no TypeCheckedExtractor is wired, so the type-checked pipeline " +
		"cannot run; an empty route list here would describe Anvil, not the target")

	// ErrNothingExtracted is what ExtractResult.AssertNotSilentlyEmpty
	// returns when a Tier 2 run produced no routes AND was handed no source
	// files under a harvest that never ran.
	ErrNothingExtracted = errors.New("inventory: nothing was extracted; an empty Tier 2 " +
		"inventory here describes Anvil, not the target")
)

// ---------------------------------------------------------------------------
// Coded bounds
// ---------------------------------------------------------------------------

const (
	// maxGoSourceFileBytes bounds one harvested source file. The bytes are
	// attacker-authored and go/parser holds the whole file plus its syntax
	// tree in memory; a four-hundred-megabyte generated .go file committed to
	// a repository is a resource-exhaustion probe pointed back at Anvil, and
	// refusing it BY NAME is the difference between a reported caveat and an
	// OOM.
	maxGoSourceFileBytes = 4 << 20

	// maxGoSourceFilesPerExtract bounds how many source files one run carries.
	maxGoSourceFilesPerExtract = 65536

	// maxRoutesPerExtract bounds the route table one run may build, across
	// all files.
	maxRoutesPerExtract = 20000

	// maxRoutePathBytes bounds a route pattern lifted out of source BEFORE it
	// reaches the kernel. The kernel's own bound is 4096 and is the one that
	// decides; this is a cheap pre-filter so a megabyte-long string literal
	// never becomes an error message.
	maxRoutePathBytes = 4096

	// maxGroupNestingDepth bounds how deep router group/subrouter nesting is
	// followed. Source is attacker-authored and the walk is recursive.
	maxGroupNestingDepth = 64

	// maxRouterBindings bounds how many router variables one function body may
	// bind, so a generated file with a million assignments cannot grow the
	// scope map without limit.
	maxRouterBindings = 4096

	// maxCaveatsPerExtract bounds the caveat list. Caveats are per-site and a
	// hostile repository can manufacture them cheaply; the COUNT is what
	// DenominatorFloor uses and it keeps rising after the list stops growing.
	maxCaveatsPerExtract = 20000
)

// ---------------------------------------------------------------------------
// Framework — the six frameworks Go route extraction names, as an enum
// ---------------------------------------------------------------------------

// Framework is the Go HTTP router a route was registered with.
//
// Go route extraction's design expected output schema requires every Route to be
// tagged `framework: <chi|gin|net_http|echo|fiber|gorilla_mux>`; these literals
// are those six, spelled exactly.
//
// The zero value names nothing and is refused everywhere it matters. A route
// whose framework nobody set is not a weaker route, it is one whose extraction
// path cannot be audited -- and when route confirmation finds a candidate that never
// confirms, "which extractor produced this" is the first question.
type Framework string

const (
	// FrameworkUnset is the zero value and names nothing.
	FrameworkUnset Framework = ""
	// FrameworkChi is github.com/go-chi/chi.
	FrameworkChi Framework = "chi"
	// FrameworkGin is github.com/gin-gonic/gin.
	FrameworkGin Framework = "gin"
	// FrameworkNetHTTP is the standard library's net/http.
	FrameworkNetHTTP Framework = "net_http"
	// FrameworkEcho is github.com/labstack/echo.
	FrameworkEcho Framework = "echo"
	// FrameworkFiber is github.com/gofiber/fiber.
	FrameworkFiber Framework = "fiber"
	// FrameworkGorillaMux is github.com/gorilla/mux.
	FrameworkGorillaMux Framework = "gorilla_mux"
)

// FrameworkValues returns the six frameworks Go route extraction names, in a stable order.
func FrameworkValues() []Framework {
	return []Framework{
		FrameworkChi, FrameworkGin, FrameworkNetHTTP,
		FrameworkEcho, FrameworkFiber, FrameworkGorillaMux,
	}
}

// Valid reports whether f is one of the six.
func (f Framework) Valid() bool {
	for _, k := range FrameworkValues() {
		if k == f {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ExtractionMode — which pipeline, with no default
// ---------------------------------------------------------------------------

// ExtractionMode selects the pipeline.
//
// The zero value names nothing and ExtractGoRoutes refuses it. A Go zero value
// must never mean "permitted", and here the permissive reading -- silently
// falling back to the weaker pipeline when the caller asked for the stronger
// one -- would report a thin candidate list as though it were the type-checked
// one.
type ExtractionMode string

const (
	// ExtractionModeUnset is the zero value and names nothing.
	ExtractionModeUnset ExtractionMode = ""

	// ExtractionModeSyntactic parses source with go/parser and resolves what
	// syntax alone can resolve. In process, executes nothing, adds no module
	// to the dependency graph. This is what ships today.
	ExtractionModeSyntactic ExtractionMode = "syntactic"

	// ExtractionModeTypeChecked delegates to a TypeCheckedExtractor -- the
	// go-apispec pipeline of Go route extraction's design. Nothing is wired today, so
	// selecting it produces ErrNoTypeCheckedExtractor.
	ExtractionModeTypeChecked ExtractionMode = "type_checked"
)

// ExtractionModeValues returns every legal mode.
func ExtractionModeValues() []ExtractionMode {
	return []ExtractionMode{ExtractionModeSyntactic, ExtractionModeTypeChecked}
}

// Valid reports whether m is one of the legal modes.
func (m ExtractionMode) Valid() bool {
	for _, k := range ExtractionModeValues() {
		if k == m {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// CoverageCaveat — what this tier knows it did not see
// ---------------------------------------------------------------------------

// CaveatReason enumerates the ways static extraction comes up short.
//
// It is a separate vocabulary from RefusalReason on purpose. A Refusal means
// this tier SAW a concrete route and could not represent it -- an unallowlisted
// method, a path the kernel rejected. A caveat means this tier knows there is
// surface it did not see at all. Folding the two together would let a reader
// subtract refusals from a route count and believe the remainder was complete.
type CaveatReason string

const (
	// CaveatUnset is the zero value and names nothing.
	CaveatUnset CaveatReason = ""

	// CaveatPathNotStaticallyResolvable: the pattern argument is not a string
	// literal -- r.Get(basePath+"/x", h), r.Get(routes.Users, h), a pattern
	// built in a loop. research/22 names this class explicitly as invisible
	// to go-apispec-style tooling, and it is more invisible to a parser.
	CaveatPathNotStaticallyResolvable CaveatReason = "path_not_statically_resolvable"

	// CaveatRouterNotResolved: a call whose name matches a registration verb
	// on a receiver this file could not tie to a router. Reported rather than
	// guessed: guessing turns cache.Get("k") into an endpoint.
	CaveatRouterNotResolved CaveatReason = "router_receiver_not_resolved"

	// CaveatMethodNotEnumerated: a method-agnostic registration -- chi's
	// Handle/HandleFunc, gin's Any, echo's Any, fiber's All, a net/http
	// pattern with no method. The path is real and GET is genuinely served,
	// so one GET candidate is emitted; the other methods were NOT enumerated
	// and this caveat is how the reader knows the surface is wider.
	CaveatMethodNotEnumerated CaveatReason = "method_not_enumerated"

	// CaveatMountNotFollowed: chi Mount, gin/echo/fiber Use, or a
	// gorilla/mux PathPrefix handed a sub-router this file cannot follow to
	// its registrations.
	CaveatMountNotFollowed CaveatReason = "mounted_subrouter_not_followed"

	// CaveatHostPatternDiscarded: a net/http 1.22 pattern carrying a host
	// component ("example.com/path"). The host is DISCARDED -- gate 9 pins the
	// host and source may never widen scope -- and the discard is reported.
	CaveatHostPatternDiscarded CaveatReason = "host_component_discarded"

	// CaveatFileUnparseable: a .go file go/parser could not parse. Generated
	// code, a build-tag-only file, a truncated harvest, or a file that is not
	// Go at all.
	CaveatFileUnparseable CaveatReason = "file_did_not_parse"

	// CaveatFileTooLarge: a source file over the coded byte bound. Not parsed
	// at all, so whatever it registers is unseen surface.
	CaveatFileTooLarge CaveatReason = "file_exceeded_the_coded_cap"

	// CaveatNestingTooDeep: group/subrouter nesting past the coded depth.
	CaveatNestingTooDeep CaveatReason = "group_nesting_exceeded_the_coded_cap"

	// CaveatTruncated: the run hit maxRoutesPerExtract or
	// maxCaveatsPerExtract and stopped adding.
	CaveatTruncated CaveatReason = "extraction_hit_a_coded_bound"

	// CaveatCallerPrefixNotVisible: the router was bound from a function
	// PARAMETER or a struct FIELD, so this file can see which framework it is
	// but not what prefix the CALLER already applied to it.
	//
	//	func main()            { r := chi.NewRouter(); mount(r.Route("/api/v1", nil)) }
	//	func mount(r chi.Router) { r.Get("/users", h) }
	//
	// The path emitted here is "/users"; the application serves
	// "/api/v1/users". The route is still emitted -- it is a CANDIDATE and
	// route confirmation confirms it -- but a candidate at a path the target does not serve
	// looks like the target's fault when it fails to confirm, so the
	// incompleteness is REPORTED. Resolving it needs the call graph, which is
	// precisely what the type-checked pipeline buys.
	//
	// It does NOT raise the denominator floor: it qualifies routes already
	// counted rather than naming an additional endpoint.
	CaveatCallerPrefixNotVisible CaveatReason = "caller_prefix_not_visible"

	// CaveatNoFrameworkRecognised: the file imports no router this tier knows.
	// Emitted per FILE and not per call, and it is the honest answer to "why
	// did a repository full of handlers produce nothing".
	CaveatNoFrameworkRecognised CaveatReason = "no_recognised_framework_imported"
)

// CaveatReasonValues returns every legal caveat reason.
func CaveatReasonValues() []CaveatReason {
	return []CaveatReason{
		CaveatPathNotStaticallyResolvable, CaveatRouterNotResolved,
		CaveatMethodNotEnumerated, CaveatMountNotFollowed,
		CaveatHostPatternDiscarded, CaveatFileUnparseable, CaveatFileTooLarge,
		CaveatNestingTooDeep, CaveatTruncated, CaveatCallerPrefixNotVisible,
		CaveatNoFrameworkRecognised,
	}
}

// Recognised reports whether c is one of the enumerated reasons.
func (c CaveatReason) Recognised() bool {
	for _, k := range CaveatReasonValues() {
		if k == c {
			return true
		}
	}
	return false
}

// countsTowardDenominatorFloor is the ALLOWLIST of caveats that each name at
// least one endpoint that exists and was not extracted.
//
// It is an allowlist for the same reason readableRepoSpecFormats is: a caveat
// added to the vocabulary does not raise the floor until somebody adds it
// here, and forgetting UNDERSTATES the denominator rather than overstating
// coverage.
//
// CaveatNoFrameworkRecognised is deliberately NOT here: a file that imports no
// router usually registers no routes, and counting every such file as a hidden
// endpoint would make the floor meaningless.
func countsTowardDenominatorFloor() map[CaveatReason]bool {
	return map[CaveatReason]bool{
		CaveatPathNotStaticallyResolvable: true,
		CaveatRouterNotResolved:           true,
		CaveatMethodNotEnumerated:         true,
		CaveatMountNotFollowed:            true,
		CaveatFileUnparseable:             true,
		CaveatFileTooLarge:                true,
		CaveatNestingTooDeep:              true,
	}
}

// RaisesDenominatorFloor reports whether this caveat names at least one
// endpoint that exists and was not extracted.
func (c CaveatReason) RaisesDenominatorFloor() bool {
	return countsTowardDenominatorFloor()[c]
}

// CoverageCaveat is one thing Tier 2 knows it did not see.
//
// It is RETURNED rather than logged, for the same reason Refusal is: surface
// this tier missed is surface that exists, and dropping it silently shrinks
// the denominator of a fraction that is supposed to be auditable.
type CoverageCaveat struct {
	// Reason is the enumerated cause.
	Reason CaveatReason
	// File is the artifact URI of the source file, redacted.
	File string
	// Line is the 1-based line within that file, or 0.
	Line int
	// Framework is the router involved, or FrameworkUnset.
	Framework Framework
	// Detail is a short redacted fragment -- the unresolved receiver, the
	// registration verb -- for a human reading the report. It is untrusted
	// input that reaches a log, so it is redacted like every other such
	// string in this package.
	Detail string
}

// Valid reports whether c carries a recognised reason.
func (c CoverageCaveat) Valid() bool { return c.Reason.Recognised() }

// String renders the caveat for a log line.
func (c CoverageCaveat) String() string {
	loc := c.File
	if c.Line > 0 {
		loc = fmt.Sprintf("%s:%d", c.File, c.Line)
	}
	if c.Detail == "" {
		return fmt.Sprintf("%s at %s", c.Reason, loc)
	}
	return fmt.Sprintf("%s at %s (%s)", c.Reason, loc, c.Detail)
}

func cloneCaveats(in []CoverageCaveat) []CoverageCaveat {
	if in == nil {
		return nil
	}
	out := make([]CoverageCaveat, len(in))
	copy(out, in)
	return out
}

// SortCaveats orders caveats deterministically. Map iteration is randomized
// and an unstable report makes an unchanged repository look changed.
func SortCaveats(cs []CoverageCaveat) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].File != cs[j].File {
			return cs[i].File < cs[j].File
		}
		if cs[i].Line != cs[j].Line {
			return cs[i].Line < cs[j].Line
		}
		if cs[i].Reason != cs[j].Reason {
			return cs[i].Reason < cs[j].Reason
		}
		return cs[i].Detail < cs[j].Detail
	})
}

// ---------------------------------------------------------------------------
// GoSourceFile — one harvested source file
// ---------------------------------------------------------------------------

// GoSourceFileFacts is NewGoSourceFile's input. It mirrors the repo spec reader's
// SpecFileFacts, in internal/record's own vocabulary for naming and carrying a
// file from the target repository.
type GoSourceFileFacts struct {
	// Location names the file (SARIF section 3.4). URI is required.
	Location record.ArtifactLocation

	// Content carries the file's bytes (SARIF section 3.3). Required and
	// non-empty: an empty file that registered nothing and an empty file that
	// was never read produce the same route list, and this tier refuses to be
	// the place those become indistinguishable.
	Content record.ArtifactContent
}

// GoSourceFile is one harvested Go source file, sealed.
//
// Every field is unexported and there is exactly one constructor, for the same
// reason Route and SpecFile have one: a composite literal elsewhere would
// produce a file with no URI and no bytes, and the extract would then report a
// clean empty route list for it.
type GoSourceFile struct {
	uri       string
	uriBaseID string
	content   string
	sealed    bool
}

// NewGoSourceFile validates and seals one harvested source file.
func NewGoSourceFile(f GoSourceFileFacts) (GoSourceFile, error) {
	uri := f.Location.URI
	if uri == "" {
		return GoSourceFile{}, fmt.Errorf("inventory: %w: the harvested source file has no "+
			"artifact URI. A route with no file behind it cannot be reviewed, and route confirmation "+
			"cannot tell an operator where a candidate it failed to confirm came from",
			ErrRefused)
	}
	if len(uri) > maxSpecURIBytes {
		return GoSourceFile{}, fmt.Errorf("inventory: %w: the artifact URI is %d bytes and "+
			"the coded bound is %d", ErrRefused, len(uri), maxSpecURIBytes)
	}
	if err := printableIdentifier(uri); err != nil {
		return GoSourceFile{}, fmt.Errorf("inventory: %w: the artifact URI carries a control "+
			"byte (%v). It is repository-authored and it reaches log lines", ErrRefused, err)
	}
	if f.Content.Text == "" {
		return GoSourceFile{}, fmt.Errorf("inventory: %w: %q carries no bytes. An empty "+
			"source file and an unread source file produce the same empty route list, and "+
			"this tier refuses to be where those become indistinguishable",
			ErrRefused, redact(uri))
	}
	if len(f.Content.Text) > maxGoSourceFileBytes {
		return GoSourceFile{}, fmt.Errorf("inventory: %w: %q is %d bytes and the coded bound "+
			"is %d", ErrRefused, redact(uri), len(f.Content.Text), maxGoSourceFileBytes)
	}
	return GoSourceFile{
		uri:       uri,
		uriBaseID: f.Location.URIBaseID,
		content:   f.Content.Text,
		sealed:    true,
	}, nil
}

// Constructed reports whether f came from NewGoSourceFile.
func (f GoSourceFile) Constructed() bool { return f.sealed && f.uri != "" && f.content != "" }

// URI is the artifact URI naming this file.
func (f GoSourceFile) URI() string { return f.uri }

// Location returns the file in internal/record's vocabulary.
func (f GoSourceFile) Location() record.ArtifactLocation {
	return record.ArtifactLocation{URI: f.uri, URIBaseID: f.uriBaseID}
}

// Trust is TrustUntrusted, always. Anvil is the component that put these bytes
// in the struct, and the question record.Trust answers is who WROTE the bytes.
func (f GoSourceFile) Trust() record.Trust { return record.TrustUntrusted }

// Bytes returns a copy of the file's bytes.
func (f GoSourceFile) Bytes() []byte { return []byte(f.content) }

// ---------------------------------------------------------------------------
// ExtractedRoute — the seam's data shape, and the extractor's internal one
// ---------------------------------------------------------------------------

// ExtractedRoute is one registration site, BEFORE any validation.
//
// Method and Path are raw strings. This type deliberately cannot express a
// Confirmation, a Provenance or a Trust: everything that produces one -- the
// syntactic walker in this file and any TypeCheckedExtractor wired from
// outside -- goes through toRoute, which supplies all three as constants and
// runs the kernel's path validation. A seam that could hand back a Route would
// be a way to launder a confirmed endpoint into the coverage numerator from
// outside this package.
type ExtractedRoute struct {
	// Framework is the router this registration was found on. Required.
	Framework Framework
	// Method is the HTTP method as the source spelled it, uppercased by the
	// producer. Validated against the kernel's allowlist by toRoute.
	Method string
	// Path is the route pattern, ALREADY canonicalized to the "{name}"
	// placeholder spelling. Validated by the kernel via toRoute.
	Path string
	// Operation names the handler when the producer knows it -- a function
	// name -- so a reviewer can find it. May be empty.
	Operation string
	// Params are the path parameters the pattern declared.
	Params []Param
	// File is the artifact URI of the source file.
	File string
	// Line is the 1-based line of the registration call.
	Line int
}

// TypeCheckedExtractor is the seam to the go-apispec pipeline of
// Go route extraction's design.
//
// It is an interface, and the implementation lives OUTSIDE internal/dast, for
// the same reason SpecFetcher does: the build-time guard's gate 3 tier 1 fails the build if any
// package under internal/dast outside internal/dast/authz imports something
// that can construct a connection, with no allowlist -- and the type-checked
// pipeline runs `go list` over the target repository, which is a subprocess
// with network and toolchain reach that belongs behind network containment.
//
// Nothing implements this today. third_party/go-apispec/PIN.md section 5
// records the two measured blockers. internal/SKIPPED-CONTROLS.md is where the
// unprovable half is named; there is no t.Skip in this package.
type TypeCheckedExtractor interface {
	// ExtractTypeChecked returns one ExtractedRoute per registration the
	// type-checked pipeline resolved, plus the caveats it could not.
	//
	// It may return raw, unvalidated strings. It may not return Routes.
	ExtractTypeChecked(ctx context.Context, srcs []GoSourceFile) ([]ExtractedRoute, []CoverageCaveat, error)
}

// ---------------------------------------------------------------------------
// ExtractConfig
// ---------------------------------------------------------------------------

// ExtractConfig is ExtractGoRoutes's configuration. Nothing in it has a
// default that means "permitted".
type ExtractConfig struct {
	// Target is the kernel Target these routes live on. Required: it is what
	// makes the kernel's path validation possible, and it is what pins each
	// route to a host rather than leaving it a free-floating string.
	//
	// authz.NewTarget builds one without any authorization, because a Target
	// is gate 8/9's OUTPUT and not a permission. So this whole file is
	// exercisable today even though the admission chain refuses every target
	// at gate 11.
	Target authz.Target

	// Harvest says what the SAST pass did. Reused from the repo spec reader rather than
	// redeclared: it is the only thing that can distinguish "this repository
	// has no Go source" from "the handoff was never wired", and a second enum
	// for the same question is exactly the produce/consume break the first
	// plan's shared-vocabulary review exists to prevent.
	Harvest HarvestOutcome

	// Mode selects the pipeline. Required; the zero value is refused.
	Mode ExtractionMode

	// TypeChecked is the seam implementation. It is consulted only when Mode
	// is ExtractionModeTypeChecked, and its absence there is a loud refusal
	// rather than a fallback to the weaker mode.
	TypeChecked TypeCheckedExtractor
}

// Constructed reports whether cfg carries everything ExtractGoRoutes needs.
func (c ExtractConfig) Constructed() bool {
	return c.Target.Constructed() && c.Harvest.Valid() && c.Mode.Valid()
}

// ---------------------------------------------------------------------------
// FileExtract and ExtractResult
// ---------------------------------------------------------------------------

// FileExtract is what one source file produced.
type FileExtract struct {
	// URI is the artifact URI, redacted for display.
	URI string
	// Frameworks are the routers this file imports, sorted.
	Frameworks []Framework
	// Routes is how many candidate routes it produced.
	Routes int
	// Caveats is how many caveats it produced.
	Caveats int
	// Parsed reports whether go/parser accepted the file.
	Parsed bool
}

func cloneFileExtracts(in []FileExtract) []FileExtract {
	if in == nil {
		return nil
	}
	out := make([]FileExtract, len(in))
	for i, f := range in {
		out[i] = f
		if f.Frameworks != nil {
			fw := make([]Framework, len(f.Frameworks))
			copy(fw, f.Frameworks)
			out[i].Frameworks = fw
		}
	}
	return out
}

// ExtractResult is one Tier 2 run, sealed.
type ExtractResult struct {
	routes   []Route
	refusals []Refusal
	caveats  []CoverageCaveat
	files    []FileExtract
	byFW     map[Framework]int
	sourceOf map[string]record.ArtifactLocation
	mode     ExtractionMode
	harvest  HarvestOutcome
	offered  int
	parsed   int
	seen     int
	truncate bool
	sealed   bool
}

// Constructed reports whether r came from ExtractGoRoutes.
func (r ExtractResult) Constructed() bool { return r.sealed }

// Routes returns a deep copy of the candidate route list.
func (r ExtractResult) Routes() []Route { return cloneRoutes(r.routes) }

// Refusals returns a copy of the per-registration refusals.
func (r ExtractResult) Refusals() []Refusal { return cloneRefusals(r.refusals) }

// Caveats returns a copy of the coverage caveats.
func (r ExtractResult) Caveats() []CoverageCaveat { return cloneCaveats(r.caveats) }

// Files returns a deep copy of the per-file summary.
func (r ExtractResult) Files() []FileExtract { return cloneFileExtracts(r.files) }

// Mode is the pipeline that produced this result.
func (r ExtractResult) Mode() ExtractionMode { return r.mode }

// Harvest is what the SAST pass did, carried through so a reader of an empty
// result can tell which of the two empties it is.
func (r ExtractResult) Harvest() HarvestOutcome { return r.harvest }

// Offered is how many source files were handed in.
func (r ExtractResult) Offered() int { return r.offered }

// Parsed is how many of them go/parser accepted.
func (r ExtractResult) Parsed() int { return r.parsed }

// Seen is how many registration sites were examined, including the ones that
// became refusals and caveats rather than routes.
func (r ExtractResult) Seen() int { return r.seen }

// Truncated reports whether a coded bound stopped the run early.
func (r ExtractResult) Truncated() bool { return r.truncate }

// FrameworkMix is the per-framework candidate count -- the Tier 2 half of what
// coverage reporting aggregates. A copy; the internal map is never handed out.
func (r ExtractResult) FrameworkMix() map[Framework]int {
	out := make(map[Framework]int, len(r.byFW))
	for k, v := range r.byFW {
		out[k] = v
	}
	return out
}

// SourceOf returns the source file a route key came from, in
// internal/record's vocabulary, so a candidate route confirmation fails to confirm can be
// traced to a line a human can read.
func (r ExtractResult) SourceOf(key string) (record.ArtifactLocation, bool) {
	loc, ok := r.sourceOf[key]
	return loc, ok
}

// DenominatorFloor is the smallest honest size of this tier's contribution to
// the Tier 0-2 union: the routes actually extracted, PLUS the per-registration
// refusals, PLUS the caveats that each name at least one endpoint that exists
// and was not extracted.
//
// It is a FLOOR and not a count. A file that did not parse may hide one route
// or forty, and this tier does not know which; counting it as one is the
// direction that cannot overstate coverage.
func (r ExtractResult) DenominatorFloor() int {
	n := len(r.routes)
	for _, ref := range r.refusals {
		if ref.Reason.PerOperation() {
			n++
		}
	}
	for _, c := range r.caveats {
		if c.Reason.RaisesDenominatorFloor() {
			n++
		}
	}
	return n
}

// AssertNotSilentlyEmpty refuses the case where an empty Tier 2 inventory is a
// claim about Anvil rather than about the repository.
//
// An empty result under HarvestRan with files offered is a REPORTABLE FACT:
// this repository's Go source registers no routes this tier could see, and the
// caveats say why. An empty result under HarvestSkipped, or with no files
// offered at all, is a fact about the handoff.
func (r ExtractResult) AssertNotSilentlyEmpty() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: ExtractResult did not come from ExtractGoRoutes",
			ErrUnconstructed)
	}
	if len(r.routes) > 0 {
		return nil
	}
	if r.harvest == HarvestRan && r.offered > 0 {
		return nil
	}
	return fmt.Errorf("%w: harvest=%s, files offered=%d, routes=0. Under %s, or with no "+
		"files offered, an empty Tier 2 route list is a statement about the handoff and "+
		"not about the target",
		ErrNothingExtracted, r.harvest, r.offered, HarvestSkipped)
}

// AssertEveryRouteIsACandidate is Go route extraction's Forbidden-actions clause, executable.
//
// It is not defensive programming: it is the assertion the whole packet turns
// on, available to any caller that wants to check rather than trust, and it is
// what TestNoRouteFromThisTierIsEverConfirmed calls over every fixture.
func (r ExtractResult) AssertEveryRouteIsACandidate() error {
	for _, rt := range r.routes {
		if rt.Confirmation() != ConfirmationCandidate {
			return fmt.Errorf("inventory: %w: %s carries confirmation %q. Every Tier 2 "+
				"route is a candidate until route confirmation confirms it via live probe; a confirmed "+
				"one here enters the numerator of endpoint_coverage without anything "+
				"having been probed", ErrRefused, rt, rt.Confirmation())
		}
		if rt.Provenance() != record.InventoryProvenanceStaticExtraction {
			return fmt.Errorf("inventory: %w: %s carries provenance %q rather than %q",
				ErrRefused, rt, rt.Provenance(), record.InventoryProvenanceStaticExtraction)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ExtractGoRoutes — the entry point
// ---------------------------------------------------------------------------

// ExtractGoRoutes turns harvested Go source into CANDIDATE inventory routes.
//
// The signature deviates from Go route extraction's design
// `ExtractGoRoutes(repoPath string) ([]Route, error)`; this file's header
// records why, and the short version is that the repo spec reader already established that
// this package opens nothing and knows no repository path.
func ExtractGoRoutes(ctx context.Context, cfg ExtractConfig, srcs []GoSourceFile) (ExtractResult, error) {
	if !cfg.Target.Constructed() {
		return ExtractResult{}, fmt.Errorf("inventory: %w: ExtractConfig carries a Target "+
			"that authz.NewTarget never built, so no extracted path can be validated by "+
			"the kernel and no route would name a host", ErrUnconstructed)
	}
	if !cfg.Harvest.Valid() {
		return ExtractResult{}, fmt.Errorf("inventory: %w: harvest outcome is %q, which is "+
			"not one of %v. It is the only thing that can distinguish a repository with "+
			"no routes from a handoff that never ran, and defaulting it makes the second "+
			"look like the first", ErrRefused, redact(string(cfg.Harvest)),
			HarvestOutcomeValues())
	}
	if !cfg.Mode.Valid() {
		return ExtractResult{}, fmt.Errorf("inventory: %w: extraction mode is %q, which is "+
			"not one of %v", ErrRefused, redact(string(cfg.Mode)), ExtractionModeValues())
	}
	if len(srcs) > maxGoSourceFilesPerExtract {
		return ExtractResult{}, fmt.Errorf("inventory: %w: %d source files were offered and "+
			"the coded bound is %d", ErrRefused, len(srcs), maxGoSourceFilesPerExtract)
	}
	for i, s := range srcs {
		if !s.Constructed() {
			return ExtractResult{}, fmt.Errorf("inventory: %w: source file %d did not come "+
				"from NewGoSourceFile, so it carries no URI or no bytes", ErrUnconstructed, i)
		}
	}

	acc := &extractAccumulator{
		target:   cfg.Target,
		byFW:     map[Framework]int{},
		sourceOf: map[string]record.ArtifactLocation{},
		seenKey:  map[string]bool{},
		locOf:    map[string]record.ArtifactLocation{},
	}
	for _, s := range srcs {
		acc.locOf[s.uri] = s.Location()
	}

	switch cfg.Mode {
	case ExtractionModeSyntactic:
		extractSyntactically(acc, srcs)
	case ExtractionModeTypeChecked:
		if cfg.TypeChecked == nil {
			return ExtractResult{}, fmt.Errorf("%w (files offered: %d)",
				ErrNoTypeCheckedExtractor, len(srcs))
		}
		raw, caveats, err := cfg.TypeChecked.ExtractTypeChecked(ctx, srcs)
		if err != nil {
			return ExtractResult{}, fmt.Errorf("inventory: %w: the type-checked extractor "+
				"failed: %w", ErrRefused, err)
		}
		for _, c := range caveats {
			acc.addCaveat(c)
		}
		for _, er := range raw {
			acc.admit(er)
		}
		acc.parsed = len(srcs)
	default:
		// Unreachable: cfg.Mode.Valid() was checked above. Present so a
		// mode added to the enum without a branch here refuses rather than
		// silently producing an empty inventory.
		return ExtractResult{}, fmt.Errorf("inventory: %w: extraction mode %q is in the "+
			"enum and has no pipeline", ErrRefused, redact(string(cfg.Mode)))
	}

	SortRoutes(acc.routes)
	SortCaveats(acc.caveats)
	sort.SliceStable(acc.files, func(i, j int) bool { return acc.files[i].URI < acc.files[j].URI })

	return ExtractResult{
		routes:   acc.routes,
		refusals: acc.refusals,
		caveats:  acc.caveats,
		files:    acc.files,
		byFW:     acc.byFW,
		sourceOf: acc.sourceOf,
		mode:     cfg.Mode,
		harvest:  cfg.Harvest,
		offered:  len(srcs),
		parsed:   acc.parsed,
		seen:     acc.seen,
		truncate: acc.truncated,
		sealed:   true,
	}, nil
}

// ---------------------------------------------------------------------------
// The accumulator — the ONE path from a raw registration to a Route
// ---------------------------------------------------------------------------

type extractAccumulator struct {
	target    authz.Target
	routes    []Route
	refusals  []Refusal
	caveats   []CoverageCaveat
	files     []FileExtract
	byFW      map[Framework]int
	sourceOf  map[string]record.ArtifactLocation
	seenKey   map[string]bool
	locOf     map[string]record.ArtifactLocation
	seen      int
	parsed    int
	truncated bool
}

func (a *extractAccumulator) addCaveat(c CoverageCaveat) {
	if !c.Valid() {
		// A caveat with an unrecognised reason is a programming error in a
		// producer -- including a TypeCheckedExtractor supplied from outside.
		// It is dropped rather than trusted, and the drop itself is recorded
		// so the count never silently falls.
		c = CoverageCaveat{Reason: CaveatTruncated, File: redact(c.File), Line: c.Line,
			Detail: "a producer supplied an unrecognised caveat reason"}
	}
	c.File = redact(c.File)
	c.Detail = redact(c.Detail)
	if len(a.caveats) >= maxCaveatsPerExtract {
		a.truncated = true
		return
	}
	a.caveats = append(a.caveats, c)
}

// admit is the single funnel. Every route in every mode passes through here,
// which is why "no Tier 2 route can be confirmed" is a property of the code
// rather than of the reviewer's attention.
func (a *extractAccumulator) admit(er ExtractedRoute) {
	a.seen++
	if len(a.routes) >= maxRoutesPerExtract {
		a.truncated = true
		a.addCaveat(CoverageCaveat{
			Reason: CaveatTruncated, File: er.File, Line: er.Line,
			Framework: er.Framework, Detail: "route table hit the coded bound",
		})
		return
	}
	rt, ref, ok := a.toRoute(er)
	if !ok {
		if ref.Valid() {
			a.refusals = append(a.refusals, ref)
		}
		return
	}
	key := rt.Key()
	if a.seenKey[key] {
		a.refusals = append(a.refusals, Refusal{
			Path: redact(er.Path), Method: redact(er.Method), Reason: RefusalDuplicateRoute,
		})
		return
	}
	a.seenKey[key] = true
	a.routes = append(a.routes, rt)
	a.byFW[er.Framework]++
	if loc, ok := a.locOf[er.File]; ok {
		a.sourceOf[key] = loc
	}
}

// toRoute converts one raw registration into a Route.
//
// This is where ConfirmationCandidate, InventoryProvenanceStaticExtraction and
// TrustUntrusted are written, as constants, with no branch that can change
// them. It is also where the KERNEL validates the path, by way of NewRoute --
// this package holds no second path validator that could disagree with the
// kernel's.
func (a *extractAccumulator) toRoute(er ExtractedRoute) (Route, Refusal, bool) {
	if !er.Framework.Valid() {
		return Route{}, Refusal{
			Path: redact(er.Path), Method: redact(er.Method),
			Reason: RefusalRouteUnconstructible,
		}, false
	}
	if len(er.Path) > maxRoutePathBytes {
		return Route{}, Refusal{
			Path: redact(er.Path), Method: redact(er.Method),
			Reason: RefusalPathRejectedByKernel,
		}, false
	}
	// Uppercase and trim, because source spells methods however it likes --
	// chi's Method("get", ...) is legal Go. Then hand the result to NewRoute
	// and let the KERNEL's allowlist decide.
	//
	// There is deliberately no `m.Recognised()` check here. An earlier draft
	// had one, and breaking it left this suite GREEN: NewRoute already refuses
	// an unallowlisted method and classifyRouteError already maps that refusal
	// to RefusalMethodNotAllowlisted, so the check was a SECOND COPY of a rule
	// the kernel owns -- unreachable, undemonstrable, and free to drift away
	// from the kernel's list the day someone adds a method there. A guard that
	// cannot be made to fail has not been tested, so it was deleted rather
	// than qualified.
	m := authz.Method(strings.ToUpper(strings.TrimSpace(er.Method)))
	rt, err := NewRoute(RouteFacts{
		Method:       m,
		Path:         er.Path,
		Target:       a.target,
		Operation:    boundIdent(operationLabel(er)),
		Params:       er.Params,
		Provenance:   record.InventoryProvenanceStaticExtraction,
		Confirmation: ConfirmationCandidate,
		Trust:        record.TrustUntrusted,
	})
	if err != nil {
		return Route{}, Refusal{
			Path: redact(er.Path), Method: redact(er.Method),
			Reason: classifyRouteError(err),
		}, false
	}
	return rt, Refusal{}, true
}

// operationLabel names the operation within the path, and for Tier 2 that is
// DELIBERATELY EMPTY unless a producer supplied one.
//
// Route.Key() is method, path and operation, and coverage reporting deduplicates the
// Tier 0-2 union on it. Putting the framework or the enclosing function name
// in here would look like richer provenance and would in fact be denominator
// inflation: the same endpoint registered on a chi router and on a legacy
// net/http mux, or extracted twice under two spellings, would become two rows
// in a fraction that is supposed to be auditable. The framework travels in
// ExtractResult.FrameworkMix and the file in ExtractResult.SourceOf, neither
// of which is part of an endpoint's identity.
func operationLabel(er ExtractedRoute) string { return er.Operation }

// ---------------------------------------------------------------------------
// Framework attribution, by import identity
// ---------------------------------------------------------------------------

// frameworkModules maps a Go MODULE PATH to the framework it provides.
//
// Matching is by IDENTITY, not by substring and not by position: an import
// path matches when it equals the module path, or equals it followed by "/vN"
// for a major-version suffix, or is a subpackage of either. A prefix test
// alone would match "github.com/evil/github.com-gin-gonic-gin", and a
// substring test would match a comment.
func frameworkModules() map[string]Framework {
	return map[string]Framework{
		"net/http":                 FrameworkNetHTTP,
		"github.com/go-chi/chi":    FrameworkChi,
		"github.com/gin-gonic/gin": FrameworkGin,
		"github.com/labstack/echo": FrameworkEcho,
		"github.com/gofiber/fiber": FrameworkFiber,
		"github.com/gorilla/mux":   FrameworkGorillaMux,
	}
}

// frameworkForImport resolves one import path to a framework.
//
// A path matches when it EQUALS a module path or is a path-segment descendant
// of one ("github.com/go-chi/chi/v5", ".../v5/middleware"). The descendant test
// is on `mod + "/"`, never on `mod` alone: a bare prefix test would match
// "github.com/go-chi/chinchilla", and a substring test would match a comment.
func frameworkForImport(path string) (Framework, bool) {
	mods := frameworkModules()
	if fw, ok := mods[path]; ok {
		return fw, true
	}
	for mod, fw := range mods {
		if strings.HasPrefix(path, mod+"/") {
			return fw, true
		}
	}
	return FrameworkUnset, false
}

// isMajorVersionSegment reports whether seg is a Go major-version directory
// name: "v2", "v5", "v13".
func isMajorVersionSegment(seg string) bool {
	if len(seg) < 2 || seg[0] != 'v' {
		return false
	}
	n, err := strconv.Atoi(seg[1:])
	return err == nil && n >= 2
}

// importLocalName is the identifier a file uses to refer to an imported
// package: the alias when one is written, otherwise the LAST PATH SEGMENT that
// is not a major-version suffix.
//
// The last-segment rule is an approximation of the package clause, which a
// parser cannot read without the imported source. It is wrong for a package
// whose name differs from its directory. That is why it is only ever used to
// SEED a router binding, never to decide that an arbitrary selector is a
// route: a wrong local name yields CaveatRouterNotResolved, which is the safe
// direction.
func importLocalName(spec *ast.ImportSpec, path string) string {
	if spec.Name != nil {
		return spec.Name.Name
	}
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if !isMajorVersionSegment(segs[i]) {
			return segs[i]
		}
	}
	return path
}

// ---------------------------------------------------------------------------
// The registration verb tables, per framework
// ---------------------------------------------------------------------------

// verbKind says how a registration call names its method and its path.
type verbKind int

const (
	// verbFixedMethod: the method is in the call's NAME and the pattern is
	// argument 0. chi's Get, gin's GET, fiber's Post.
	verbFixedMethod verbKind = iota
	// verbMethodArg: the method is argument 0 and the pattern is argument 1.
	// chi's Method/MethodFunc, gin's Handle, echo's Add, fiber's Add.
	verbMethodArg
	// verbAnyMethod: the registration serves every method. The pattern is
	// argument 0. chi's Handle/HandleFunc, gin's Any, echo's Any, fiber's All.
	verbAnyMethod
	// verbGroup: the call returns a SUB-ROUTER carrying a path prefix, which
	// is argument 0. gin/echo/fiber Group, chi Route (with a func literal).
	verbGroup
	// verbMount: the call attaches a sub-router this file cannot follow.
	verbMount
	// verbNetHTTPPattern: net/http's ServeMux pattern in argument 0, which
	// since Go 1.22 may carry a method and a host.
	verbNetHTTPPattern
	// verbGorillaPath: gorilla/mux's HandleFunc/Handle/Path/PathPrefix, whose
	// method comes from a chained .Methods(...) call.
	verbGorillaPath
)

type verb struct {
	kind verbKind
	// method is the HTTP method for verbFixedMethod.
	method string
	// lexical reports whether a func-literal argument carries the prefix
	// scope -- chi's Route(pattern, func(r chi.Router){...}).
	lexical bool
}

// verbTables is the per-framework registration vocabulary.
//
// Every entry is a method NAME matched exactly. There is no prefix rule and no
// "anything starting with Handle", because an approximate table on an
// approximate receiver is how a config store becomes an API.
//
// CONNECT and TRACE are deliberately absent. The kernel's method allowlist
// (authz.Method) has seven members and neither is among them, so a route
// registered for them cannot be probed; chi's Connect/Trace therefore reach
// toRoute through verbMethodArg only if the source spells them as arguments,
// and are refused there BY NAME as RefusalMethodNotAllowlisted rather than
// vanishing.
func verbTables() map[Framework]map[string]verb {
	fixed := func(m string) verb { return verb{kind: verbFixedMethod, method: m} }
	return map[Framework]map[string]verb{
		FrameworkChi: {
			"Get": fixed("GET"), "Post": fixed("POST"), "Put": fixed("PUT"),
			"Patch": fixed("PATCH"), "Delete": fixed("DELETE"),
			"Head": fixed("HEAD"), "Options": fixed("OPTIONS"),
			"Connect": fixed("CONNECT"), "Trace": fixed("TRACE"),
			"Method": {kind: verbMethodArg}, "MethodFunc": {kind: verbMethodArg},
			"Handle": {kind: verbAnyMethod}, "HandleFunc": {kind: verbAnyMethod},
			"Route": {kind: verbGroup, lexical: true},
			"Group": {kind: verbGroup, lexical: true},
			"Mount": {kind: verbMount},
		},
		FrameworkGin: {
			"GET": fixed("GET"), "POST": fixed("POST"), "PUT": fixed("PUT"),
			"PATCH": fixed("PATCH"), "DELETE": fixed("DELETE"),
			"HEAD": fixed("HEAD"), "OPTIONS": fixed("OPTIONS"),
			"Handle":     {kind: verbMethodArg},
			"Any":        {kind: verbAnyMethod},
			"Group":      {kind: verbGroup},
			"StaticFile": fixed("GET"), "Static": fixed("GET"), "StaticFS": fixed("GET"),
		},
		FrameworkEcho: {
			"GET": fixed("GET"), "POST": fixed("POST"), "PUT": fixed("PUT"),
			"PATCH": fixed("PATCH"), "DELETE": fixed("DELETE"),
			"HEAD": fixed("HEAD"), "OPTIONS": fixed("OPTIONS"),
			"CONNECT": fixed("CONNECT"), "TRACE": fixed("TRACE"),
			"Add":    {kind: verbMethodArg},
			"Any":    {kind: verbAnyMethod},
			"Group":  {kind: verbGroup},
			"Static": fixed("GET"), "File": fixed("GET"),
		},
		FrameworkFiber: {
			"Get": fixed("GET"), "Post": fixed("POST"), "Put": fixed("PUT"),
			"Patch": fixed("PATCH"), "Delete": fixed("DELETE"),
			"Head": fixed("HEAD"), "Options": fixed("OPTIONS"),
			"Add":    {kind: verbMethodArg},
			"All":    {kind: verbAnyMethod},
			"Group":  {kind: verbGroup},
			"Mount":  {kind: verbMount},
			"Static": fixed("GET"),
		},
		FrameworkGorillaMux: {
			"HandleFunc": {kind: verbGorillaPath},
			"Handle":     {kind: verbGorillaPath},
			"Path":       {kind: verbGorillaPath},
			"PathPrefix": {kind: verbMount},
		},
		FrameworkNetHTTP: {
			"HandleFunc": {kind: verbNetHTTPPattern},
			"Handle":     {kind: verbNetHTTPPattern},
		},
	}
}

// routerConstructors maps a package-qualified constructor call to the
// framework of the router it returns: chi.NewRouter, gin.Default, echo.New.
//
// The key is the SELECTOR name; the package identifier is resolved separately
// against the file's imports, so an alias (`import gg "github.com/gin-gonic/gin"`)
// binds correctly and a local type named `gin` does not.
func routerConstructors() map[Framework]map[string]bool {
	return map[Framework]map[string]bool{
		FrameworkChi:        {"NewRouter": true, "NewMux": true},
		FrameworkGin:        {"Default": true, "New": true},
		FrameworkEcho:       {"New": true},
		FrameworkFiber:      {"New": true},
		FrameworkGorillaMux: {"NewRouter": true},
		FrameworkNetHTTP:    {"NewServeMux": true},
	}
}

// routerTypeNames maps a package-qualified TYPE name to its framework, for
// binding a router that arrives as a function parameter or a struct field:
// func routes(r chi.Router), func api(e *echo.Echo).
func routerTypeNames() map[Framework]map[string]bool {
	return map[Framework]map[string]bool{
		FrameworkChi:        {"Router": true, "Mux": true},
		FrameworkGin:        {"Engine": true, "RouterGroup": true, "IRouter": true, "IRoutes": true},
		FrameworkEcho:       {"Echo": true, "Group": true},
		FrameworkFiber:      {"App": true, "Router": true, "Group": true},
		FrameworkGorillaMux: {"Router": true},
		FrameworkNetHTTP:    {"ServeMux": true},
	}
}

// subRouterReturns names the calls that turn a router into another router
// WITHOUT adding a prefix of their own: gorilla/mux's .Subrouter(),
// .NewRoute(), .StrictSlash().
func subRouterReturns() map[string]bool {
	return map[string]bool{"Subrouter": true, "NewRoute": true, "StrictSlash": true}
}

// gorillaChainVerbs names the gorilla/mux *Route methods that may be chained
// onto a registration and RETURN THE ROUTE, so the registration call sits
// nested inside them in the syntax tree.
//
// This is the one framework in the six whose method is neither in the call
// name nor an argument to the registration call: it is on a different call
// applied to the *mux.Route the registration returned. A walker that read only
// the registration call would silently turn every gorilla route into a GET,
// which is the failure that makes a scanner's silence look like cleanliness.
func gorillaChainVerbs() map[string]bool {
	return map[string]bool{
		"Methods": true, "Queries": true, "Headers": true, "Schemes": true,
		"Name": true, "MatcherFunc": true, "HeadersRegexp": true,
		"QueriesRegexp": true, "Host": true,
	}
}

// ---------------------------------------------------------------------------
// The syntactic extractor
// ---------------------------------------------------------------------------

// routerBinding is what an identifier in scope refers to.
type routerBinding struct {
	fw     Framework
	prefix string
	// isPackage marks the seeded binding for net/http's PACKAGE identifier,
	// which is a router only because http.HandleFunc registers on
	// DefaultServeMux.
	//
	// It exists to keep that seed from masking `http.NewServeMux()`: without
	// it, the constructor resolver sees `http` already in scope, concludes the
	// package identifier is shadowed by a local variable, and declines to bind
	// -- and every net/http ServeMux in the repository silently becomes
	// CaveatRouterNotResolved. That is exactly the failure this suite caught,
	// and the fix is to distinguish a SEEDED package binding from a real local
	// one rather than to drop the shadowing check, which is what stops a local
	// variable named `gin` from being read as the gin package.
	isPackage bool
	// prefixUnknown marks a binding whose prefix this file cannot see because
	// the router arrived from outside the function -- a parameter or a struct
	// field. See CaveatCallerPrefixNotVisible.
	prefixUnknown bool
}

// fileScope is the per-file import picture.
type fileScope struct {
	// pkgFramework maps a LOCAL package identifier to its framework:
	// "chi" -> FrameworkChi, "gg" -> FrameworkGin under an alias.
	pkgFramework map[string]Framework
	// fieldFramework maps a STRUCT FIELD NAME to the framework of its
	// declared type, for the `type Server struct{ router chi.Router }` shape
	// where the registration reads `s.router.Get(...)` and the receiver `s` is
	// a value this file cannot type.
	//
	// It is keyed on the field name and populated only from fields whose
	// declared type is a known router type, so it stays identity-based: a
	// field named `router` of type *sql.DB does not enter the map.
	fieldFramework map[string]Framework
	// frameworks is the set of frameworks the file imports.
	frameworks map[Framework]bool
	uri        string
	fset       *token.FileSet
}

func extractSyntactically(acc *extractAccumulator, srcs []GoSourceFile) {
	for _, s := range srcs {
		acc.files = append(acc.files, extractOneFile(acc, s))
	}
}

func extractOneFile(acc *extractAccumulator, s GoSourceFile) FileExtract {
	fe := FileExtract{URI: redact(s.uri)}
	routesBefore, caveatsBefore := len(acc.routes), len(acc.caveats)

	fset := token.NewFileSet()
	// parser.SkipObjectResolution: this file needs positions and syntax, never
	// the deprecated object graph. It is also the cheaper mode, and the input
	// is attacker-authored.
	f, err := parser.ParseFile(fset, s.uri, s.content, parser.SkipObjectResolution)
	if err != nil {
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatFileUnparseable, File: s.uri,
			Detail: firstLineOf(err.Error()),
		})
		fe.Caveats = len(acc.caveats) - caveatsBefore
		return fe
	}
	acc.parsed++
	fe.Parsed = true

	sc := &fileScope{
		pkgFramework:   map[string]Framework{},
		fieldFramework: map[string]Framework{},
		frameworks:     map[Framework]bool{},
		uri:            s.uri,
		fset:           fset,
	}
	for _, imp := range f.Imports {
		path, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		fw, ok := frameworkForImport(path)
		if !ok {
			continue
		}
		sc.frameworks[fw] = true
		if name := importLocalName(imp, path); name != "" && name != "_" && name != "." {
			sc.pkgFramework[name] = fw
		}
	}
	for fw := range sc.frameworks {
		fe.Frameworks = append(fe.Frameworks, fw)
	}
	sort.Slice(fe.Frameworks, func(i, j int) bool { return fe.Frameworks[i] < fe.Frameworks[j] })

	if len(sc.frameworks) == 0 {
		acc.addCaveat(CoverageCaveat{Reason: CaveatNoFrameworkRecognised, File: s.uri})
		fe.Caveats = len(acc.caveats) - caveatsBefore
		return fe
	}

	// Package-level scope. net/http's package-level http.HandleFunc registers
	// on DefaultServeMux, so the package identifier itself is a router.
	pkgScope := map[string]routerBinding{}
	for name, fw := range sc.pkgFramework {
		if fw == FrameworkNetHTTP {
			pkgScope[name] = routerBinding{fw: FrameworkNetHTTP, isPackage: true}
		}
	}

	// Struct field types first: a registration written as `s.router.Get(...)`
	// needs the field's declared type, and the type declaration may sit below
	// the function that uses it.
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		bindRouterFields(sc, gd)
	}

	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			bindFromGenDecl(sc, pkgScope, d)
		case *ast.FuncDecl:
			if d.Body == nil {
				continue
			}
			scope := childScope(pkgScope)
			bindFromFuncSignature(sc, scope, d)
			walkBody(acc, sc, scope, d.Body, 0)
		}
	}

	fe.Routes = len(acc.routes) - routesBefore
	fe.Caveats = len(acc.caveats) - caveatsBefore
	return fe
}

// bindRouterFields records struct FIELD NAMES whose declared type is a router
// type, so `type Server struct{ router chi.Router }` makes `s.router` resolve.
//
// A parser cannot type the receiver `s`, so the field name plus its declared
// type is the identity available. It stays identity-based: only fields whose
// type resolves through routerTypeFramework enter the map, so a field named
// `router` of some other type does not, and its registrations become
// CaveatRouterNotResolved rather than routes on a guess.
func bindRouterFields(sc *fileScope, gd *ast.GenDecl) {
	for _, spec := range gd.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			continue
		}
		for _, field := range st.Fields.List {
			fw, ok := routerTypeFramework(sc, field.Type)
			if !ok {
				continue
			}
			for _, name := range field.Names {
				if len(sc.fieldFramework) >= maxRouterBindings {
					return
				}
				sc.fieldFramework[name.Name] = fw
			}
		}
	}
}

func childScope(parent map[string]routerBinding) map[string]routerBinding {
	out := make(map[string]routerBinding, len(parent)+4)
	for k, v := range parent {
		out[k] = v
	}
	return out
}

// bindFromGenDecl binds package-level `var r = chi.NewRouter()`.
func bindFromGenDecl(sc *fileScope, scope map[string]routerBinding, d *ast.GenDecl) {
	if d.Tok != token.VAR {
		return
	}
	for _, spec := range d.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range vs.Names {
			if i >= len(vs.Values) {
				if fw, ok := routerTypeFramework(sc, vs.Type); ok {
					bind(scope, name.Name, routerBinding{fw: fw, prefixUnknown: true})
				}
				continue
			}
			if b, ok := bindingFromExpr(sc, scope, vs.Values[i], 0); ok {
				bind(scope, name.Name, b)
			}
		}
	}
}

// bindFromFuncSignature binds a router that arrives as a parameter or a
// receiver: func routes(r chi.Router), func (s *Server) mount(e *echo.Echo).
func bindFromFuncSignature(sc *fileScope, scope map[string]routerBinding, d *ast.FuncDecl) {
	fields := []*ast.FieldList{d.Type.Params, d.Recv}
	for _, fl := range fields {
		if fl == nil {
			continue
		}
		for _, field := range fl.List {
			fw, ok := routerTypeFramework(sc, field.Type)
			if !ok {
				continue
			}
			for _, name := range field.Names {
				bind(scope, name.Name, routerBinding{fw: fw, prefixUnknown: true})
			}
		}
	}
}

// routerTypeFramework resolves a type expression to a framework when it names
// a router type: chi.Router, *gin.Engine, *echo.Echo.
func routerTypeFramework(sc *fileScope, e ast.Expr) (Framework, bool) {
	switch t := e.(type) {
	case *ast.StarExpr:
		return routerTypeFramework(sc, t.X)
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		if !ok {
			return FrameworkUnset, false
		}
		fw, ok := sc.pkgFramework[pkg.Name]
		if !ok {
			return FrameworkUnset, false
		}
		if routerTypeNames()[fw][t.Sel.Name] {
			return fw, true
		}
	}
	return FrameworkUnset, false
}

func bind(scope map[string]routerBinding, name string, b routerBinding) {
	if name == "" || name == "_" {
		return
	}
	if len(scope) >= maxRouterBindings {
		return
	}
	scope[name] = b
}

// bindingFromExpr resolves an expression to a router binding when it is one:
// chi.NewRouter(), r.Group("/api"), r.PathPrefix("/api").Subrouter().
//
// depth bounds the mutual recursion with resolveReceiver. Source is
// attacker-authored and a chain of ten thousand .Subrouter() calls is a stack
// overflow that a repository can commit.
func bindingFromExpr(sc *fileScope, scope map[string]routerBinding, e ast.Expr, depth int) (routerBinding, bool) {
	if depth > maxGroupNestingDepth {
		return routerBinding{}, false
	}
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return routerBinding{}, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return routerBinding{}, false
	}

	// A constructor: chi.NewRouter(), http.NewServeMux(). Resolved against the
	// FILE'S IMPORTS, so an alias binds correctly and a local variable that
	// happens to be named `gin` does not.
	if pkg, ok := sel.X.(*ast.Ident); ok {
		existing, bound := scope[pkg.Name]
		shadowed := bound && !existing.isPackage
		if !shadowed {
			if fw, isPkg := sc.pkgFramework[pkg.Name]; isPkg {
				if routerConstructors()[fw][sel.Sel.Name] {
					return routerBinding{fw: fw}, true
				}
			}
		}
	}

	// A chain that returns a router without adding a prefix:
	// r.PathPrefix("/api").Subrouter(), r.NewRoute().
	if subRouterReturns()[sel.Sel.Name] {
		parent, ok := resolveReceiver(sc, scope, sel.X, depth+1)
		if !ok {
			return routerBinding{}, false
		}
		return parent, true
	}

	parent, ok := resolveReceiver(sc, scope, sel.X, depth+1)
	if !ok {
		return routerBinding{}, false
	}

	// gorilla/mux's PathPrefix carries a prefix and returns a *Route that
	// .Subrouter() turns back into a router.
	if parent.fw == FrameworkGorillaMux && sel.Sel.Name == "PathPrefix" {
		pre, has := literalPathArg(call, 0)
		if !has {
			return routerBinding{}, false
		}
		return routerBinding{
			fw:            parent.fw,
			prefix:        joinPrefix(parent.prefix, pre),
			prefixUnknown: parent.prefixUnknown,
		}, true
	}

	// A group: r.Group("/api"), r.Route("/api", fn).
	v, ok := verbTables()[parent.fw][sel.Sel.Name]
	if !ok || v.kind != verbGroup {
		return routerBinding{}, false
	}
	pre, has := literalPathArg(call, 0)
	if !has {
		// A group whose prefix is computed. The sub-router is real, and every
		// route under it would be WRONG if the prefix were assumed empty, so
		// the binding is refused and the registrations under it become
		// CaveatRouterNotResolved rather than routes at the wrong paths.
		return routerBinding{}, false
	}
	return routerBinding{
		fw:            parent.fw,
		prefix:        joinPrefix(parent.prefix, pre),
		prefixUnknown: parent.prefixUnknown,
	}, true
}

// resolveReceiver resolves a call's receiver expression to a binding.
//
// Idents and single-level selectors (s.router) resolve from scope; a call
// expression resolves through bindingFromExpr, which is what makes
// r.PathPrefix("/api").Subrouter().HandleFunc(...) work in one expression.
// Anything else -- an index expression, a type assertion, a map lookup -- is
// UNRESOLVED, and unresolved means a caveat, never a guess.
func resolveReceiver(sc *fileScope, scope map[string]routerBinding, e ast.Expr, depth int) (routerBinding, bool) {
	if key, ok := receiverKey(e); ok {
		if b, found := scope[key]; found {
			return b, true
		}
	}
	// `s.router` where `router` is a struct field DECLARED as a router type.
	// The receiver `s` cannot be typed by a parser, so the field name plus its
	// declared type is the identity available; a field of any other type is
	// not in the map and does not resolve.
	if selx, ok := e.(*ast.SelectorExpr); ok {
		if _, isIdent := selx.X.(*ast.Ident); isIdent {
			if fw, known := sc.fieldFramework[selx.Sel.Name]; known {
				return routerBinding{fw: fw, prefixUnknown: true}, true
			}
		}
	}
	if _, isCall := e.(*ast.CallExpr); isCall {
		return bindingFromExpr(sc, scope, e, depth+1)
	}
	return routerBinding{}, false
}

func receiverKey(e ast.Expr) (string, bool) {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name, true
	case *ast.SelectorExpr:
		if base, ok := t.X.(*ast.Ident); ok {
			return base.Name + "." + t.Sel.Name, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// The body walk
// ---------------------------------------------------------------------------

// walkBody walks a function body in source order, binding routers as it meets
// them and admitting registrations against the bindings in scope.
//
// It is written as an explicit recursion rather than a bare ast.Inspect
// because SCOPE MATTERS: chi's Route(pattern, func(r chi.Router){...}) gives
// the inner literal its own prefix, and a flat walk would apply the outer
// prefix to the inner registrations or the inner prefix to the outer ones.
func walkBody(acc *extractAccumulator, sc *fileScope, scope map[string]routerBinding,
	body *ast.BlockStmt, depth int) {

	if body == nil {
		return
	}
	if depth > maxGroupNestingDepth {
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatNestingTooDeep, File: sc.uri, Line: sc.line(body.Pos()),
		})
		return
	}

	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) {
					break
				}
				name, ok := receiverKey(lhs)
				if !ok {
					continue
				}
				if b, ok := bindingFromExpr(sc, scope, node.Rhs[i], 0); ok {
					bind(scope, name, b)
				}
			}
			// Descend anyway: a right-hand side can carry a registration
			// (`_ = mount(r.Group("/a"))`), and a walk that stopped here
			// would lose it silently.
			for _, rhs := range node.Rhs {
				ast.Inspect(rhs, visit)
			}
			return false

		case *ast.CallExpr:
			if handleCall(acc, sc, scope, node, depth) {
				return false
			}
			return true

		case *ast.FuncLit:
			// A function literal that is NOT a group callback -- middleware,
			// a goroutine, a handler. It gets a CHILD scope so its own
			// bindings cannot leak back out to its siblings.
			walkBody(acc, sc, childScope(scope), node.Body, depth+1)
			return false
		}
		return true
	}

	for _, stmt := range body.List {
		ast.Inspect(stmt, visit)
	}
}

// unwrapGorillaChain peels a gorilla/mux fluent chain down to the registration
// call at its root, collecting the methods named along the way.
//
// The syntax tree for
//
//	r.HandleFunc("/users/{id}", h).Methods("GET", "PUT").Name("user")
//
// nests the REGISTRATION at the bottom and the modifiers above it, so the walk
// meets `.Name` first. This peels from the outside in, gathering every
// `.Methods(...)` argument, and hands back the inner `r.HandleFunc(...)` call
// together with {"GET","PUT"}.
//
// It returns ok=false when the outermost call is not a chain verb at all,
// which is every non-gorilla call in the repository.
func unwrapGorillaChain(call *ast.CallExpr) (*ast.CallExpr, []string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !gorillaChainVerbs()[sel.Sel.Name] {
		return nil, nil, false
	}
	var methods []string
	cur := call
	for i := 0; i < maxGroupNestingDepth; i++ {
		csel, ok := cur.Fun.(*ast.SelectorExpr)
		if !ok || !gorillaChainVerbs()[csel.Sel.Name] {
			break
		}
		if csel.Sel.Name == "Methods" {
			for j := range cur.Args {
				if m, has := literalStringArg(cur, j); has {
					methods = append(methods, m)
				}
			}
		}
		inner, ok := csel.X.(*ast.CallExpr)
		if !ok {
			return nil, nil, false
		}
		cur = inner
	}
	if cur == call {
		return nil, nil, false
	}
	return cur, methods, true
}

// handleCall decides whether one call expression is a route registration and,
// if so, admits it. It returns true when it consumed the node, which stops the
// walk from descending into a subtree it has already accounted for.
func handleCall(acc *extractAccumulator, sc *fileScope, scope map[string]routerBinding,
	call *ast.CallExpr, depth int) bool {

	// gorilla/mux first: the registration is NESTED inside its modifiers, so
	// the outermost node has to be recognised before the receiver is resolved.
	if inner, methods, ok := unwrapGorillaChain(call); ok {
		return handleGorillaRegistration(acc, sc, scope, inner, methods, depth)
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	line := sc.line(call.Lparen)

	b, resolved := resolveReceiver(sc, scope, sel.X, 0)
	if !resolved {
		// The receiver is not a known router. Complain only when the call
		// LOOKS like a registration under a framework this file imports and
		// carries a literal path -- otherwise every method call in the
		// repository produces a caveat and the caveat list stops meaning
		// anything, which is its own kind of blindness.
		if looksLikeRegistration(sc, sel.Sel.Name) && hasLiteralPathArg(call) {
			key, _ := receiverKey(sel.X)
			acc.addCaveat(CoverageCaveat{
				Reason: CaveatRouterNotResolved, File: sc.uri, Line: line,
				Detail: key + "." + sel.Sel.Name,
			})
		}
		return false
	}

	v, ok := verbTables()[b.fw][sel.Sel.Name]
	if !ok {
		return false
	}

	switch v.kind {
	case verbFixedMethod:
		admitPattern(acc, sc, b, call, 0, v.method, line)
		return true

	case verbMethodArg:
		m, has := literalStringArg(call, 0)
		if !has {
			acc.addCaveat(CoverageCaveat{
				Reason: CaveatMethodNotEnumerated, File: sc.uri, Line: line,
				Framework: b.fw, Detail: sel.Sel.Name + " with a computed method",
			})
			return true
		}
		admitPattern(acc, sc, b, call, 1, m, line)
		return true

	case verbAnyMethod:
		// The path is real and GET is genuinely served by all of these. The
		// OTHER methods were not enumerated, and this caveat is how a reader
		// knows the surface is wider than the one candidate emitted here.
		// Emitting all seven allowlisted methods instead would multiply the
		// coverage denominator by seven on a guess.
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatMethodNotEnumerated, File: sc.uri, Line: line,
			Framework: b.fw, Detail: sel.Sel.Name,
		})
		admitPattern(acc, sc, b, call, 0, "GET", line)
		return true

	case verbGroup:
		pre, has := literalPathArg(call, 0)
		if !has {
			acc.addCaveat(CoverageCaveat{
				Reason: CaveatPathNotStaticallyResolvable, File: sc.uri, Line: line,
				Framework: b.fw, Detail: sel.Sel.Name + " prefix",
			})
			return true
		}
		child := routerBinding{
			fw:            b.fw,
			prefix:        joinPrefix(b.prefix, pre),
			prefixUnknown: b.prefixUnknown,
		}
		// chi's Route(pattern, func(r chi.Router){...}) puts the sub-router in
		// the literal's PARAMETER. Bind it there and walk the literal with a
		// child scope, so the prefix applies inside and does not leak back out.
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.FuncLit)
			if !ok {
				continue
			}
			inner := childScope(scope)
			if lit.Type != nil && lit.Type.Params != nil {
				for _, field := range lit.Type.Params.List {
					for _, name := range field.Names {
						bind(inner, name.Name, child)
					}
				}
			}
			walkBody(acc, sc, inner, lit.Body, depth+1)
		}
		return true

	case verbMount:
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatMountNotFollowed, File: sc.uri, Line: line,
			Framework: b.fw, Detail: sel.Sel.Name,
		})
		return true

	case verbNetHTTPPattern:
		raw, has := literalStringArg(call, 0)
		if !has {
			acc.addCaveat(CoverageCaveat{
				Reason: CaveatPathNotStaticallyResolvable, File: sc.uri, Line: line,
				Framework: b.fw, Detail: sel.Sel.Name,
			})
			return true
		}
		method, host, path := splitServeMuxPattern(raw)
		if host != "" {
			// Gate 11's asymmetry, applied to source: a host written in a
			// repository may not widen scope. It is DISCARDED, and the
			// discard is reported rather than done quietly.
			acc.addCaveat(CoverageCaveat{
				Reason: CaveatHostPatternDiscarded, File: sc.uri, Line: line,
				Framework: b.fw, Detail: host,
			})
		}
		if method == "" {
			acc.addCaveat(CoverageCaveat{
				Reason: CaveatMethodNotEnumerated, File: sc.uri, Line: line,
				Framework: b.fw, Detail: "ServeMux pattern with no method",
			})
			method = "GET"
		}
		admitLiteral(acc, sc, b, path, method, line)
		return true

	case verbGorillaPath:
		// Reached only when a gorilla registration carries NO chained
		// modifier at all -- r.HandleFunc("/x", h) on its own line. The
		// chained form arrives through handleGorillaRegistration.
		return handleGorillaRegistration(acc, sc, scope, call, nil, depth)
	}
	return false
}

// handleGorillaRegistration admits a gorilla/mux registration with the methods
// its chain named, or reports that the chain named none.
func handleGorillaRegistration(acc *extractAccumulator, sc *fileScope,
	scope map[string]routerBinding, call *ast.CallExpr, methods []string, _ int) bool {

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	line := sc.line(call.Lparen)

	b, resolved := resolveReceiver(sc, scope, sel.X, 0)
	if !resolved {
		if looksLikeRegistration(sc, sel.Sel.Name) && hasLiteralPathArg(call) {
			key, _ := receiverKey(sel.X)
			acc.addCaveat(CoverageCaveat{
				Reason: CaveatRouterNotResolved, File: sc.uri, Line: line,
				Detail: key + "." + sel.Sel.Name,
			})
		}
		return false
	}
	if b.fw != FrameworkGorillaMux {
		return false
	}
	v, ok := verbTables()[b.fw][sel.Sel.Name]
	if !ok {
		return false
	}
	if v.kind == verbMount {
		// PathPrefix without a .Subrouter() this walk could follow.
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatMountNotFollowed, File: sc.uri, Line: line,
			Framework: b.fw, Detail: sel.Sel.Name,
		})
		return true
	}
	if v.kind != verbGorillaPath {
		return false
	}
	pre, has := literalPathArg(call, 0)
	if !has {
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatPathNotStaticallyResolvable, File: sc.uri, Line: line,
			Framework: b.fw, Detail: sel.Sel.Name,
		})
		return true
	}
	if len(methods) == 0 {
		// gorilla/mux without .Methods(...) matches EVERY method. Same
		// treatment as chi's Handle: one honest GET candidate plus a caveat
		// that the rest were not enumerated.
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatMethodNotEnumerated, File: sc.uri, Line: line,
			Framework: b.fw, Detail: sel.Sel.Name + " with no .Methods(...)",
		})
		methods = []string{"GET"}
	}
	for _, m := range methods {
		admitLiteral(acc, sc, b, pre, m, line)
	}
	return true
}

// looksLikeRegistration reports whether name is a registration verb in ANY
// framework this file imports. It is the filter that keeps
// CaveatRouterNotResolved from firing on every method call in the repository.
func looksLikeRegistration(sc *fileScope, name string) bool {
	tables := verbTables()
	for fw := range sc.frameworks {
		if _, ok := tables[fw][name]; ok {
			return true
		}
	}
	return false
}

func hasLiteralPathArg(call *ast.CallExpr) bool {
	if _, ok := literalPathArg(call, 0); ok {
		return true
	}
	_, ok := literalPathArg(call, 1)
	return ok
}

func admitPattern(acc *extractAccumulator, sc *fileScope, b routerBinding,
	call *ast.CallExpr, argIdx int, method string, line int) {

	pat, has := literalPathArg(call, argIdx)
	if !has {
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatPathNotStaticallyResolvable, File: sc.uri, Line: line,
			Framework: b.fw, Detail: method,
		})
		return
	}
	admitLiteral(acc, sc, b, pat, method, line)
}

func admitLiteral(acc *extractAccumulator, sc *fileScope, b routerBinding,
	pat, method string, line int) {

	full := joinPrefix(b.prefix, pat)
	canon, params, err := canonicalizePattern(full)
	if err != nil {
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatPathNotStaticallyResolvable, File: sc.uri, Line: line,
			Framework: b.fw, Detail: err.Error(),
		})
		return
	}
	if b.prefixUnknown {
		acc.addCaveat(CoverageCaveat{
			Reason: CaveatCallerPrefixNotVisible, File: sc.uri, Line: line,
			Framework: b.fw, Detail: canon,
		})
	}
	acc.admit(ExtractedRoute{
		Framework: b.fw,
		Method:    method,
		Path:      canon,
		Params:    params,
		File:      sc.uri,
		Line:      line,
	})
}
func (sc *fileScope) line(p token.Pos) int {
	if sc.fset == nil || !p.IsValid() {
		return 0
	}
	return sc.fset.Position(p).Line
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------------------------------------------------------------------------
// Literal argument reading
// ---------------------------------------------------------------------------

// literalStringArg returns argument i as a Go string literal, or reports that
// it is not one.
//
// It deliberately does NOT fold constants, concatenate `"/a" + "/b"`, or
// follow an identifier to its declaration. Each of those is a place where a
// parser starts guessing, and a guessed path is a permanent row in the
// coverage denominator. Everything it cannot read becomes
// CaveatPathNotStaticallyResolvable, which is the honest answer and the one
// the type-checked mode exists to improve on.
func literalStringArg(call *ast.CallExpr, i int) (string, bool) {
	if i < 0 || i >= len(call.Args) {
		return "", false
	}
	lit, ok := call.Args[i].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// literalPathArg is literalStringArg with the bound applied, so a megabyte
// string literal never reaches the canonicalizer or an error message.
func literalPathArg(call *ast.CallExpr, i int) (string, bool) {
	s, ok := literalStringArg(call, i)
	if !ok || len(s) > maxRoutePathBytes {
		return "", false
	}
	return s, true
}

// ---------------------------------------------------------------------------
// Pattern canonicalization
// ---------------------------------------------------------------------------

// joinPrefix concatenates a group prefix and a route pattern into one path
// with exactly one separator between them.
func joinPrefix(prefix, pat string) string {
	switch {
	case prefix == "" && pat == "":
		return "/"
	case prefix == "":
		if strings.HasPrefix(pat, "/") {
			return pat
		}
		return "/" + pat
	case pat == "" || pat == "/":
		if strings.HasPrefix(prefix, "/") {
			return strings.TrimSuffix(prefix, "/") + "/"
		}
		return "/" + strings.TrimSuffix(prefix, "/") + "/"
	}
	p := prefix
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "/")
	s := pat
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return p + s
}

// splitServeMuxPattern splits a net/http ServeMux pattern into method, host
// and path.
//
// Go 1.22 generalised the pattern to "[METHOD ][HOST]/[PATH]". A pattern with
// no method matches every method; a pattern with a host restricts to that
// host. Both are read here so the method can be reported honestly and the host
// can be DISCARDED loudly.
func splitServeMuxPattern(raw string) (method, host, path string) {
	s := strings.TrimSpace(raw)
	if i := strings.IndexByte(s, ' '); i > 0 {
		head := s[:i]
		rest := strings.TrimSpace(s[i+1:])
		if isAllUpperASCII(head) {
			method = head
			s = rest
		}
	}
	if s == "" {
		return method, "", "/"
	}
	if !strings.HasPrefix(s, "/") {
		if i := strings.IndexByte(s, '/'); i >= 0 {
			host = s[:i]
			s = s[i:]
		} else {
			host = s
			s = "/"
		}
	}
	return method, host, s
}

func isAllUpperASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// canonicalizePattern rewrites a framework's placeholder spelling into the
// OpenAPI "{name}" spelling Tier 0 and Tier 1 already emit, and returns the
// path parameters it found.
//
// The spellings, all six frameworks:
//
//	{id}            chi, gorilla/mux, net/http 1.22  -> {id}
//	{id:[0-9]+}     chi, gorilla/mux                  -> {id}
//	{id...}         net/http 1.22 trailing wildcard   -> {id}
//	:id             gin, echo, fiber                  -> {id}
//	*               chi, echo, fiber catch-all        -> {wildcard}
//	*filepath       gin catch-all                     -> {filepath}
//	+              fiber one-or-more                  -> {wildcard}
//
// This runs BEFORE Route.Key() is ever taken, so the Tier 0-2 union
// deduplicates on one spelling rather than six. It is the kernel-facing form,
// and it is produced once here rather than by a second canonicalizer somewhere
// downstream that could disagree.
func canonicalizePattern(pat string) (string, []Param, error) {
	if pat == "" {
		return "", nil, errors.New("empty pattern")
	}
	if len(pat) > maxRoutePathBytes {
		return "", nil, fmt.Errorf("pattern is %d bytes", len(pat))
	}
	segs := strings.Split(pat, "/")
	var params []Param
	seen := map[string]bool{}
	wildcards := 0

	addParam := func(name string) string {
		if name == "" {
			wildcards++
			name = "wildcard"
			if wildcards > 1 {
				name = fmt.Sprintf("wildcard%d", wildcards)
			}
		}
		if !seen[name] && len(params) < maxParamsPerRoute {
			seen[name] = true
			params = append(params, Param{
				Name:     boundIdent(name),
				In:       ParamInPath,
				Required: true,
				// Type is empty and stays empty. Syntactic extraction cannot
				// know a parameter's type; inventing "string" would make
				// Param.Typed() -- the predicate plan/design/dynamic-tier.md:610's
				// "parameter-typed" claim is measured by -- lie.
			})
		}
		return "{" + boundIdent(name) + "}"
	}

	for i, seg := range segs {
		switch {
		case seg == "":
			continue
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
			inner := seg[1 : len(seg)-1]
			// gorilla/chi regex constraint: {id:[0-9]+}
			if j := strings.IndexByte(inner, ':'); j >= 0 {
				inner = inner[:j]
			}
			// net/http 1.22 trailing wildcard: {path...}
			inner = strings.TrimSuffix(inner, "...")
			name, err := placeholderName(inner)
			if err != nil {
				return "", nil, err
			}
			segs[i] = addParam(name)
		case strings.HasPrefix(seg, ":"):
			name, err := placeholderName(seg[1:])
			if err != nil {
				return "", nil, err
			}
			segs[i] = addParam(name)
		case strings.HasPrefix(seg, "*"):
			name, err := placeholderName(seg[1:])
			if err != nil {
				return "", nil, err
			}
			segs[i] = addParam(name)
		case seg == "+":
			segs[i] = addParam("")
		}
	}
	out := strings.Join(segs, "/")
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out, params, nil
}

// placeholderName validates and returns a placeholder's name.
//
// An empty name is legal and means "an unnamed wildcard" -- chi's "/*", echo's
// "/*". A name carrying anything but ASCII letters, digits and underscore is
// REFUSED rather than sanitized: sanitizing would map two distinct
// placeholders onto one canonical name and merge two endpoints into one row.
func placeholderName(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if len(s) > maxIdentBytes {
		return "", fmt.Errorf("placeholder name is %d bytes", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_'
		if !ok {
			return "", fmt.Errorf("placeholder name carries byte 0x%02x", c)
		}
	}
	return s, nil
}
