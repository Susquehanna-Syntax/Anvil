// This file is packet D.21: Tier 2, static route extraction from the non-Go
// languages -- Express, Flask, FastAPI, Django, Spring and Rails.
//
// ===========================================================================
// THE FAILURE THIS FILE IS DESIGNED AGAINST
// ===========================================================================
//
// endpoint_coverage (plan/50-dast.md:1152) is confirmed-probed endpoints
// divided by the UNION of the Tier 0-2 inventory. A language this extractor
// does not really support does not merely miss endpoints -- it removes them
// from the DENOMINATOR, and the fraction goes UP. The metric improves exactly
// when the tool gets worse, and nothing in the number itself shows it.
//
// So the central design rule here is not coverage, it is DISTINGUISHABILITY:
//
//	"this language was scanned and had no endpoints"
//	"this language is not supported and was never scanned"
//	"this language is supported, was scanned, and no framework was recognised"
//	"this language is supported and the bytes did not lex"
//
// are FOUR different values of ScanOutcome, all four reach D.26 on
// OtherExtractResult.LanguageReports(), and TestScanOutcomesAreDistinguishable
// proves a caller can tell them apart. A zero route count on its own never
// means "clean" anywhere in this file.
//
// On top of that, OtherExtractResult.AssertDenominatorIsComplete returns an
// ERROR whenever a recognised-but-unsupported language was present in the
// offered file set. A caller that wants to publish endpoint_coverage has to
// either handle that error or ignore it in writing; it cannot arrive at a
// flattering number by accident.
//
// ===========================================================================
// WHAT IS ACTUALLY SUPPORTED -- SupportMatrix() IS THE ONE PLACE
// ===========================================================================
//
// SupportMatrix() below is the single machine-readable statement of what this
// extractor recognises and what it is blind to, per framework. It is not a
// comment: TestSupportMatrixIsBackedByAFixture fails if any entry lacks a
// hand-written fixture that produced routes, and TestSupportMatrixNamesEvery
// Framework fails if a framework is added to the enum without an entry.
//
// The languages are named by SupportedLanguages(); every other language this
// file can recognise by extension is listed in recognisedLanguages() with
// status LanguageStatusNotSupported, which is the loud form of "invisible".
//
// ===========================================================================
// THIS IS A LEXER, NOT AN AST -- SAID PLAINLY
// ===========================================================================
//
// D.20 had go/parser. This file has none: modernc.org/sqlite is the module's
// only dependency, and there is no JavaScript, Python, Java or Ruby parser in
// the standard library. What is here is a per-language LEXER (scanSource) plus
// deterministic token-shape matching over its output.
//
// That is still what research/22-attack-surface-discovery.md lines 330-341
// require -- "use deterministic AST tooling", the prohibition being on asking
// an LLM to enumerate routes -- but it is weaker than a parser, and the
// weakness is one-directional by construction:
//
//   - A shape the lexer cannot resolve becomes a CoverageCaveat, never a
//     guess. A receiver that is not a bound router produces
//     CaveatRouterNotResolved, exactly as D.20 does, because guessing is how
//     `cache.get("user:1")` becomes an endpoint.
//   - Bytes the lexer cannot lex (an unterminated string, an unterminated
//     comment, an unbalanced Ruby block) produce CaveatFileUnparseable and the
//     file's routes are DISCARDED rather than emitted at possibly-wrong paths.
//
// ===========================================================================
// EVERY ROUTE THIS FILE PRODUCES IS A CANDIDATE
// ===========================================================================
//
// plan/50-dast.md D.21's Forbidden actions: "every route here is
// `status: candidate`, never `confirmed`, at extraction time". As in D.20 the
// enforcement is structural rather than editorial: every route goes through
// ONE function, otherAccumulator.toRoute, which writes ConfirmationCandidate,
// record.InventoryProvenanceStaticExtraction and record.TrustUntrusted as
// constants with no branch that can change them, and hands the path to the
// KERNEL via NewRoute. There is no second path validator in this file.
//
// ===========================================================================
// WHAT IS REUSED FROM D.18/D.19/D.20 RATHER THAN RESTATED
// ===========================================================================
//
//	Route, NewRoute, RouteFacts, Param, SortRoutes  -- the endpoint type (D.18)
//	Refusal, RefusalReason, classifyRouteError      -- the refusal vocabulary
//	CoverageCaveat, CaveatReason, SortCaveats       -- the caveat vocabulary
//	HarvestOutcome                                  -- ran vs skipped (D.19)
//	NewGoSourceFile                                 -- harvested-file validation
//	canonicalizePattern, joinPrefix, redact         -- D.20's canonicalization
//
// Two D.20 types are Go-SPECIFIC and could not be reused, and this file may
// not modify tier2_go_extract.go to widen them:
//
//   - Framework is the six Go routers. NonGoFramework is a separate enum and
//     NonGoCaveat EMBEDS CoverageCaveat so the shared reason vocabulary, the
//     RaisesDenominatorFloor semantics and D.26's consumption are unchanged
//     while the non-Go framework still travels.
//   - No new CaveatReason is declared. CaveatReasonValues() lives in
//     tier2_go_extract.go and CoverageCaveat.Valid() consults it, so a reason
//     declared here would be born invalid. Every shortfall below maps onto an
//     existing reason, and the "language not supported" fact -- which is NOT a
//     caveat, see below -- travels as a ScanOutcome instead.
//
// WHY "LANGUAGE NOT SUPPORTED" IS NOT A CAVEAT. A CoverageCaveat that raises
// the denominator floor asserts "at least ONE endpoint exists here that was
// not extracted". An unsupported language hides an UNKNOWN number: one, or
// four hundred. Counting it as one would be the same understatement this file
// exists to prevent, dressed up as diligence. It travels as a ScanOutcome and
// as an assertion that fails, both of which say "the denominator is not
// complete" rather than "the denominator is one bigger".
//
// Sources: plan/50-dast.md D.21 (lines 677-708) and the Coverage Reporting
// Contract (lines 1142-1160); research/22-attack-surface-discovery.md lines
// 330-341 and its Risk #2; internal/dast/inventory/tier2_go_extract.go (D.20).
package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrUnsupportedLanguagePresent is what
	// OtherExtractResult.AssertDenominatorIsComplete returns when the offered
	// file set contained a language this extractor recognises and cannot
	// read.
	//
	// It is an error rather than a field so that a caller computing
	// endpoint_coverage has to make a decision about it in code. A boolean
	// nobody reads is how the denominator quietly shrinks.
	ErrUnsupportedLanguagePresent = errors.New("inventory: the offered file set contains " +
		"a language this extractor cannot read, so the Tier 2 denominator is incomplete " +
		"by an unknown amount and endpoint_coverage computed over it is an overestimate")

	// ErrNoNonGoSourceOffered is what AssertNotSilentlyEmpty returns when a
	// run produced nothing AND had nothing to work from.
	ErrNoNonGoSourceOffered = errors.New("inventory: no non-Go source reached this tier; " +
		"an empty result here describes the handoff, not the target")
)

// ---------------------------------------------------------------------------
// Coded bounds
// ---------------------------------------------------------------------------

const (
	// maxNonGoSourceFilesPerExtract bounds how many files one run carries.
	maxNonGoSourceFilesPerExtract = 65536

	// maxTokensPerFile bounds the lexer's output for one file. The bytes are
	// repository-authored and the token slice is held whole; a file of four
	// million single-character identifiers is a resource probe pointed back
	// at Anvil, and refusing it BY NAME is the difference between a reported
	// caveat and an OOM.
	maxTokensPerFile = 400000

	// maxNonGoNestingDepth bounds Express mount chains, Rails block nesting
	// and Spring class nesting. Source is attacker-authored and a mount cycle
	// (a.use("/x", b); b.use("/y", a)) is one line of JavaScript.
	maxNonGoNestingDepth = 64

	// maxRailsResourceRoutes bounds how many routes one `resources` line may
	// expand to, so a hostile routes.rb cannot multiply the table without
	// limit. Seven is the Rails default set; the bound is generous.
	maxRailsResourceRoutes = 16
)

// ---------------------------------------------------------------------------
// Language -- including the ones with no extractor
// ---------------------------------------------------------------------------

// Language is the source language of one harvested file.
//
// It deliberately enumerates languages this file CANNOT read. A language that
// is not in the vocabulary at all is a language whose files are silently
// ignored, and silence is the failure mode the packet is about.
type Language string

const (
	// LanguageUnset is the zero value and names nothing.
	LanguageUnset Language = ""

	// --- supported by this extractor ---

	// LanguageJavaScript covers JavaScript and TypeScript.
	LanguageJavaScript Language = "javascript"
	// LanguagePython is Python.
	LanguagePython Language = "python"
	// LanguageJava is Java.
	LanguageJava Language = "java"
	// LanguageRuby is Ruby.
	LanguageRuby Language = "ruby"

	// --- supported by D.20, not here ---

	// LanguageGo is Go, which tier2_go_extract.go reads.
	LanguageGo Language = "go"

	// --- recognised, no extractor exists anywhere in Anvil ---

	// LanguagePHP is PHP: Laravel, Symfony, Slim. Invisible.
	LanguagePHP Language = "php"
	// LanguageCSharp is C#: ASP.NET Core. Invisible. research/22's Risk #2
	// records that the best-funded commercial equivalent does not read it
	// either.
	LanguageCSharp Language = "csharp"
	// LanguageKotlin is Kotlin, which hosts Spring and Ktor. Invisible even
	// though the Spring ANNOTATIONS this file reads in Java appear in it.
	LanguageKotlin Language = "kotlin"
	// LanguageScala is Scala: Play, Akka HTTP. Invisible.
	LanguageScala Language = "scala"
	// LanguageRust is Rust: axum, actix-web, rocket. Invisible.
	LanguageRust Language = "rust"
	// LanguageElixir is Elixir: Phoenix. Invisible.
	LanguageElixir Language = "elixir"
	// LanguagePerl is Perl: Mojolicious, Dancer. Invisible.
	LanguagePerl Language = "perl"
	// LanguageSwift is Swift: Vapor. Invisible.
	LanguageSwift Language = "swift"
	// LanguageClojure is Clojure: ring, compojure. Invisible.
	LanguageClojure Language = "clojure"
)

// LanguageStatus says what Anvil can do with a language, as opposed to what it
// found in it.
//
// The distinction is the whole packet. A zero route count means something
// completely different under each of these.
type LanguageStatus string

const (
	// LanguageStatusUnset is the zero value and names nothing.
	LanguageStatusUnset LanguageStatus = ""

	// LanguageStatusSupported: this file has an extractor for it.
	LanguageStatusSupported LanguageStatus = "supported_by_this_extractor"

	// LanguageStatusGoExtractor: D.20 reads it, not this file. A .go file
	// offered here is not a gap, it is a routing mistake in the caller.
	LanguageStatusGoExtractor LanguageStatus = "supported_by_the_go_extractor"

	// LanguageStatusNotSupported: Anvil recognises the language and has no
	// extractor for it anywhere. Its endpoints are invisible and its files
	// make the Tier 2 denominator incomplete.
	LanguageStatusNotSupported LanguageStatus = "recognised_language_no_extractor_exists"

	// LanguageStatusUnrecognised: the file extension names no language this
	// build knows -- a README, a lockfile, a .env.
	//
	// It deliberately does NOT make the denominator incomplete. Treating
	// every unrecognised file as hidden surface would make the assertion fire
	// on every repository and a warning that always fires is not a warning.
	LanguageStatusUnrecognised LanguageStatus = "file_extension_not_recognised"
)

// LanguageStatusValues returns every legal literal.
func LanguageStatusValues() []LanguageStatus {
	return []LanguageStatus{
		LanguageStatusSupported, LanguageStatusGoExtractor,
		LanguageStatusNotSupported, LanguageStatusUnrecognised,
	}
}

// Valid reports whether s is one of the legal literals.
func (s LanguageStatus) Valid() bool {
	for _, k := range LanguageStatusValues() {
		if k == s {
			return true
		}
	}
	return false
}

// recognisedLanguages maps a lower-cased file extension (with its dot) to the
// language it names.
//
// Matching is on the EXTENSION as a whole, never a substring: a table keyed by
// substring would file "notes.python.md" as Python. The extension is lifted
// from the artifact URI, which is repository-authored, so nothing downstream
// trusts it beyond choosing which extractor to run.
func recognisedLanguages() map[string]Language {
	return map[string]Language{
		".js": LanguageJavaScript, ".mjs": LanguageJavaScript,
		".cjs": LanguageJavaScript, ".jsx": LanguageJavaScript,
		".ts": LanguageJavaScript, ".tsx": LanguageJavaScript,
		".mts": LanguageJavaScript, ".cts": LanguageJavaScript,

		".py": LanguagePython, ".pyi": LanguagePython,

		".java": LanguageJava,

		".rb": LanguageRuby, ".rake": LanguageRuby,

		".go": LanguageGo,

		".php": LanguagePHP,
		".cs":  LanguageCSharp,
		".kt":  LanguageKotlin, ".kts": LanguageKotlin,
		".scala": LanguageScala, ".sc": LanguageScala,
		".rs": LanguageRust,
		".ex": LanguageElixir, ".exs": LanguageElixir,
		".pl": LanguagePerl, ".pm": LanguagePerl,
		".swift": LanguageSwift,
		".clj":   LanguageClojure, ".cljs": LanguageClojure,
	}
}

// SupportedLanguages returns the languages this extractor can actually read,
// in a stable order. It is derived from the extractor dispatch in
// (*fileWalk).run, so a language cannot appear here without a code path.
func SupportedLanguages() []Language {
	return []Language{LanguageJavaScript, LanguagePython, LanguageJava, LanguageRuby}
}

// Status returns what Anvil can do with this language.
func (l Language) Status() LanguageStatus {
	for _, k := range SupportedLanguages() {
		if k == l {
			return LanguageStatusSupported
		}
	}
	if l == LanguageGo {
		return LanguageStatusGoExtractor
	}
	if l == LanguageUnset {
		return LanguageStatusUnrecognised
	}
	for _, k := range recognisedLanguages() {
		if k == l {
			return LanguageStatusNotSupported
		}
	}
	return LanguageStatusUnrecognised
}

// classifyURI resolves an artifact URI to a language and a status.
//
// The extension is taken from the LAST path segment only, so a directory named
// "src.py/" cannot decide the language of "src.py/README".
func classifyURI(uri string) (Language, LanguageStatus) {
	seg := uri
	if i := strings.LastIndexAny(seg, "/\\"); i >= 0 {
		seg = seg[i+1:]
	}
	dot := strings.LastIndexByte(seg, '.')
	if dot < 0 {
		return LanguageUnset, LanguageStatusUnrecognised
	}
	ext := strings.ToLower(seg[dot:])
	lang, ok := recognisedLanguages()[ext]
	if !ok {
		return LanguageUnset, LanguageStatusUnrecognised
	}
	return lang, lang.Status()
}

// ---------------------------------------------------------------------------
// NonGoFramework
// ---------------------------------------------------------------------------

// NonGoFramework is the web framework a route was registered with.
//
// It is a separate enum from D.20's Framework because that one is the six Go
// routers and tier2_go_extract.go is read-only to this packet. The zero value
// names nothing and toRoute refuses it.
type NonGoFramework string

const (
	// NonGoFrameworkUnset is the zero value and names nothing.
	NonGoFrameworkUnset NonGoFramework = ""
	// NonGoFrameworkExpress is Express on Node.
	NonGoFrameworkExpress NonGoFramework = "express"
	// NonGoFrameworkFlask is Flask.
	NonGoFrameworkFlask NonGoFramework = "flask"
	// NonGoFrameworkFastAPI is FastAPI.
	NonGoFrameworkFastAPI NonGoFramework = "fastapi"
	// NonGoFrameworkDjango is Django's URLconf.
	NonGoFrameworkDjango NonGoFramework = "django"
	// NonGoFrameworkSpring is Spring Web MVC's annotation model.
	NonGoFrameworkSpring NonGoFramework = "spring"
	// NonGoFrameworkRails is Rails' routes.rb DSL.
	NonGoFrameworkRails NonGoFramework = "rails"
)

// NonGoFrameworkValues returns the five frameworks D.21 names -- Flask and
// FastAPI counted separately, because they are different DSLs that happen to
// share a language and this file reads them with different code.
func NonGoFrameworkValues() []NonGoFramework {
	return []NonGoFramework{
		NonGoFrameworkExpress, NonGoFrameworkFlask, NonGoFrameworkFastAPI,
		NonGoFrameworkDjango, NonGoFrameworkSpring, NonGoFrameworkRails,
	}
}

// Valid reports whether f is one of the enumerated frameworks.
func (f NonGoFramework) Valid() bool {
	for _, k := range NonGoFrameworkValues() {
		if k == f {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The support matrix -- ONE place, machine-readable
// ---------------------------------------------------------------------------

// FrameworkSupport is what this extractor claims about one framework.
//
// BlindTo is the load-bearing half. plan/50-dast.md D.21's Forbidden actions
// require that reflection-based and computed-path routes are not silently
// dropped; this is where the classes of them are named, and the Caveat column
// says which CoverageCaveat a reader will actually see when one is hit.
type FrameworkSupport struct {
	// Framework is the framework this row describes.
	Framework NonGoFramework
	// Language is the language it is read in.
	Language Language
	// Recognises lists the registration shapes the extractor resolves.
	Recognises []string
	// BlindTo lists shapes it cannot resolve. Each one produces a caveat.
	BlindTo []string
	// Fixture names the hand-written fixture in
	// tier2_other_extract_test.go's frameworkFixtures table that proves this
	// row. TestSupportMatrixIsBackedByAFixture fails without it.
	Fixture string
}

// SupportMatrix is the single statement of what D.21 supports.
//
// Nothing here is claimed that a hand-written fixture did not exercise:
// TestSupportMatrixIsBackedByAFixture matches every row against the fixture
// table by Fixture name and fails if the fixture produced no routes.
func SupportMatrix() []FrameworkSupport {
	return []FrameworkSupport{
		{
			Framework: NonGoFrameworkExpress,
			Language:  LanguageJavaScript,
			Recognises: []string{
				`app/router bound from require("express"), express(), express.Router(), ` +
					`import express from "express", import { Router } from "express"`,
				`app.get/post/put/patch/delete/head/options("/literal", handler)`,
				`app.all("/literal", handler) -- emits GET, method not enumerated`,
				`router.route("/literal").get(h).post(h) chains`,
				`app.use("/prefix", router) mounts, resolved within one file`,
				`":id" and ":id?" path placeholders`,
			},
			BlindTo: []string{
				`a mount whose child router is defined in another file ` +
					`(CaveatCallerPrefixNotVisible)`,
				`app.use("/prefix", middlewareNotKnownToBeARouter) ` +
					`(CaveatMountNotFollowed)`,
				`a computed path: app.get(BASE + "/x") or a template literal ` +
					`(CaveatPathNotStaticallyResolvable)`,
				`a computed method: app[verb]("/x") (CaveatMethodNotEnumerated)`,
				`a registration on a receiver that is not a bound router ` +
					`(CaveatRouterNotResolved)`,
				`app.get("setting") with one argument is Express's SETTINGS getter, ` +
					`not a route, and is not emitted`,
			},
			Fixture: "express_basic",
		},
		{
			Framework: NonGoFrameworkFlask,
			Language:  LanguagePython,
			Recognises: []string{
				`app bound from Flask(...), blueprint bound from Blueprint(...)`,
				`@app.route("/literal") and @app.route("/literal", methods=[...])`,
				`app.add_url_rule("/literal", ..., methods=[...])`,
				`Blueprint(..., url_prefix="/p") and ` +
					`app.register_blueprint(bp, url_prefix="/p")`,
				`"<id>", "<int:id>", "<path:rest>" converters`,
			},
			BlindTo: []string{
				`a blueprint never registered in the same file ` +
					`(CaveatCallerPrefixNotVisible)`,
				`a computed rule: app.add_url_rule(build(x)) or an f-string ` +
					`(CaveatPathNotStaticallyResolvable)`,
				`a decorator on a receiver that is not a bound app or blueprint ` +
					`(CaveatRouterNotResolved)`,
				`Flask's implicit HEAD and OPTIONS handlers are NOT emitted: only ` +
					`the methods the source names are`,
				`pluggable views (MethodView / add_url_rule with view_func=cls.as_view) ` +
					`enumerate no methods (CaveatMethodNotEnumerated)`,
			},
			Fixture: "flask_basic",
		},
		{
			Framework: NonGoFrameworkFastAPI,
			Language:  LanguagePython,
			Recognises: []string{
				`app bound from FastAPI(...), router bound from APIRouter(...)`,
				`@app.get/post/put/patch/delete/head/options/trace("/literal")`,
				`@app.api_route("/literal", methods=[...])`,
				`APIRouter(prefix="/p") and app.include_router(r, prefix="/p")`,
				`"{id}" and "{rest:path}" placeholders`,
			},
			BlindTo: []string{
				`a router never included in the same file ` +
					`(CaveatCallerPrefixNotVisible)`,
				`a computed path or an f-string ` +
					`(CaveatPathNotStaticallyResolvable)`,
				`app.add_api_route(...) is not read (CaveatRouterNotResolved is not ` +
					`raised for it; it simply is not a shape this file matches)`,
				`@app.trace(...) is refused by the kernel's method allowlist and ` +
					`becomes a per-operation Refusal, not a route`,
			},
			Fixture: "fastapi_basic",
		},
		{
			Framework: NonGoFrameworkDjango,
			Language:  LanguagePython,
			Recognises: []string{
				`path("literal/", view) from django.urls`,
				`"<int:pk>", "<slug:s>", "<path:rest>" converters`,
				`include(...) as the view argument, reported as an unfollowed mount`,
			},
			BlindTo: []string{
				`METHOD: a Django URLconf names none. One GET candidate is emitted ` +
					`per path and CaveatMethodNotEnumerated says the surface is wider`,
				`PREFIX: a URLconf's paths are relative to wherever the module is ` +
					`include()d, which this file cannot see ` +
					`(CaveatCallerPrefixNotVisible, once per file)`,
				`re_path(r"^...$") is a regex, not a literal path, and is ALWAYS ` +
					`reported (CaveatPathNotStaticallyResolvable)`,
				`the included URLconf's own routes (CaveatMountNotFollowed)`,
				`DRF routers (SimpleRouter/DefaultRouter register()) are not read`,
			},
			Fixture: "django_basic",
		},
		{
			Framework: NonGoFrameworkSpring,
			Language:  LanguageJava,
			Recognises: []string{
				`@GetMapping/@PostMapping/@PutMapping/@PatchMapping/@DeleteMapping`,
				`@RequestMapping(value=..., method=RequestMethod.GET) and ` +
					`method={RequestMethod.GET, RequestMethod.POST}`,
				`a class-level @RequestMapping prefix, scoped by brace depth`,
				`multi-path annotations: @GetMapping({"/a", "/b"})`,
				`"{id}", "{id:regex}" and Spring 6's "{*rest}" placeholders`,
			},
			BlindTo: []string{
				`a path given as a constant or a property placeholder: ` +
					`@GetMapping(PATHS.USERS) or "${api.base}/x" ` +
					`(CaveatPathNotStaticallyResolvable)`,
				`@RequestMapping with no method= names no method: one GET candidate ` +
					`plus CaveatMethodNotEnumerated`,
				`functional endpoints (RouterFunctions.route()) are not read`,
				`Kotlin sources carrying the same annotations are NOT read at all ` +
					`-- LanguageKotlin is LanguageStatusNotSupported`,
				`a controller inherited from a superclass in another file ` +
					`(CaveatCallerPrefixNotVisible is not raised; it is simply unseen)`,
			},
			Fixture: "spring_basic",
		},
		{
			Framework: NonGoFrameworkRails,
			Language:  LanguageRuby,
			Recognises: []string{
				`a routes file containing Rails.application.routes.draw`,
				`get/post/put/patch/delete "path" or :symbol`,
				`match "path", via: [:get, :post]`,
				`root to: "c#a"`,
				`namespace :api do, scope "/v1" do, scope path: "/v1" do`,
				`resources :users and resource :profile, with only:/except:`,
				`member do / collection do / nested resources inside a resources block`,
				`mount Engine => "/x", reported as an unfollowed mount`,
			},
			BlindTo: []string{
				`a computed path: get ROUTE_CONST or an interpolated "#{x}" string ` +
					`(CaveatPathNotStaticallyResolvable)`,
				`via: :all names no method (CaveatMethodNotEnumerated)`,
				`the routes inside a mounted engine (CaveatMountNotFollowed)`,
				`anything inside a resources block that is not member/collection/` +
					`resources: Rails' implicit nesting rule was not verifiable on ` +
					`this host, so it is reported (CaveatMountNotFollowed) rather ` +
					`than guessed`,
				`concerns, direct, resolve and defaults are not read`,
				`nested-resource parent ids are singularised by removing a trailing ` +
					`"s": "/people/{people_id}" where Rails writes "{person_id}". The ` +
					`PATH TEMPLATE is right and the parameter NAME may be wrong`,
				`a routes file with unbalanced do/end lexes as unparseable and its ` +
					`routes are DISCARDED (CaveatFileUnparseable)`,
			},
			Fixture: "rails_basic",
		},
	}
}

// SupportMatrixString renders the matrix for a report or a log line.
func SupportMatrixString() string {
	var b strings.Builder
	for _, e := range SupportMatrix() {
		fmt.Fprintf(&b, "%s (%s), fixture %s\n", e.Framework, e.Language, e.Fixture)
		for _, r := range e.Recognises {
			fmt.Fprintf(&b, "  reads:  %s\n", r)
		}
		for _, r := range e.BlindTo {
			fmt.Fprintf(&b, "  blind:  %s\n", r)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// ScanOutcome -- the distinguishability requirement, as a value
// ---------------------------------------------------------------------------

// ScanOutcome is what happened to one file, or to one language across a run.
//
// The four values that can accompany a zero route count are all distinct, and
// that is the point of the type. A caller that sees ScanOutcomeScannedNoEndpoints
// has learned something about the TARGET; a caller that sees
// ScanOutcomeLanguageNotSupported has learned something about ANVIL. Collapsing
// them into "0 routes" is the silent-clean failure.
type ScanOutcome string

const (
	// ScanOutcomeUnset is the zero value and names nothing.
	ScanOutcomeUnset ScanOutcome = ""

	// ScanOutcomeRoutesFound: an extractor ran and produced candidates.
	ScanOutcomeRoutesFound ScanOutcome = "routes_found"

	// ScanOutcomeScannedNoEndpoints: an extractor ran, recognised a supported
	// framework, and the source registered nothing it could see. A fact about
	// the target.
	ScanOutcomeScannedNoEndpoints ScanOutcome = "scanned_no_endpoints"

	// ScanOutcomeScannedNoFrameworkRecognised: an extractor ran over readable
	// bytes and found no framework it knows. A helper module, or a framework
	// nobody wired.
	ScanOutcomeScannedNoFrameworkRecognised ScanOutcome = "scanned_no_supported_framework_found"

	// ScanOutcomeNothingParsed: the language is supported and the lexer
	// rejected the bytes. A fact about the bytes, or about the lexer.
	ScanOutcomeNothingParsed ScanOutcome = "scanned_nothing_lexed"

	// ScanOutcomeLanguageNotSupported: no extractor exists. A fact about
	// Anvil, and the one that makes the coverage denominator incomplete.
	ScanOutcomeLanguageNotSupported ScanOutcome = "language_not_supported"

	// ScanOutcomeHandledByGoExtractor: a .go file was offered to the non-Go
	// tier. D.20 reads it; this tier did not, and did not fail to.
	ScanOutcomeHandledByGoExtractor ScanOutcome = "handled_by_the_go_extractor"

	// ScanOutcomeFileTypeUnrecognised: the extension names no language.
	ScanOutcomeFileTypeUnrecognised ScanOutcome = "file_type_not_recognised"
)

// ScanOutcomeValues returns every legal literal.
func ScanOutcomeValues() []ScanOutcome {
	return []ScanOutcome{
		ScanOutcomeRoutesFound, ScanOutcomeScannedNoEndpoints,
		ScanOutcomeScannedNoFrameworkRecognised, ScanOutcomeNothingParsed,
		ScanOutcomeLanguageNotSupported, ScanOutcomeHandledByGoExtractor,
		ScanOutcomeFileTypeUnrecognised,
	}
}

// Valid reports whether o is one of the legal literals.
func (o ScanOutcome) Valid() bool {
	for _, k := range ScanOutcomeValues() {
		if k == o {
			return true
		}
	}
	return false
}

// MeansAnvilCouldNotLook reports whether this outcome describes a limit of
// ANVIL rather than a property of the target.
//
// It is the predicate AssertDenominatorIsComplete partitions on, and it is a
// method rather than a comparison at the call site so a value added to the
// enum is classified in one place.
func (o ScanOutcome) MeansAnvilCouldNotLook() bool {
	switch o {
	case ScanOutcomeLanguageNotSupported, ScanOutcomeNothingParsed:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// SourceFile
// ---------------------------------------------------------------------------

// SourceFile is one harvested non-Go source file, sealed and classified.
//
// The bytes are validated by NewGoSourceFile rather than by a second copy of
// the same checks. That constructor's rules -- a required URI, a printable
// URI, required non-empty content, a byte cap -- are about HARVESTED BYTES and
// not about Go, and a second validator here is exactly the kind of drifting
// duplicate this build has a standing rule against. Only the type's NAME is
// Go-flavoured, and the alternative was thirty copied lines that could fall
// out of step.
//
// The language is decided AT CONSTRUCTION from the URI, so no code path
// downstream can hold a SourceFile whose language nobody classified.
type SourceFile struct {
	inner  GoSourceFile
	lang   Language
	status LanguageStatus
}

// NewSourceFile validates, classifies and seals one harvested source file.
func NewSourceFile(f GoSourceFileFacts) (SourceFile, error) {
	inner, err := NewGoSourceFile(f)
	if err != nil {
		return SourceFile{}, err
	}
	lang, status := classifyURI(inner.URI())
	return SourceFile{inner: inner, lang: lang, status: status}, nil
}

// Constructed reports whether f came from NewSourceFile.
func (f SourceFile) Constructed() bool { return f.inner.Constructed() && f.status.Valid() }

// URI is the artifact URI naming this file.
func (f SourceFile) URI() string { return f.inner.URI() }

// Location returns the file in internal/record's vocabulary.
func (f SourceFile) Location() record.ArtifactLocation { return f.inner.Location() }

// Trust is TrustUntrusted, always, for the reason GoSourceFile.Trust is: the
// question record.Trust answers is who WROTE the bytes.
func (f SourceFile) Trust() record.Trust { return f.inner.Trust() }

// Bytes returns a copy of the file's bytes.
func (f SourceFile) Bytes() []byte { return f.inner.Bytes() }

// Language is the language classified from the URI at construction.
func (f SourceFile) Language() Language { return f.lang }

// Status is what Anvil can do with that language.
func (f SourceFile) Status() LanguageStatus { return f.status }

func (f SourceFile) text() string { return f.inner.content }

// ---------------------------------------------------------------------------
// The raw shape, and the reports
// ---------------------------------------------------------------------------

// ExtractedNonGoRoute is one registration site BEFORE any validation.
//
// Like D.20's ExtractedRoute it deliberately cannot express a Confirmation, a
// Provenance or a Trust: everything that produces one goes through
// otherAccumulator.toRoute, which supplies all three as constants. A shape
// that could carry a Confirmation would be a way to launder a confirmed
// endpoint into the coverage numerator.
type ExtractedNonGoRoute struct {
	// Framework is the framework this registration was found on. Required.
	Framework NonGoFramework
	// Language is the source language. Required.
	Language Language
	// Method is the HTTP method as the extractor determined it.
	Method string
	// Pattern is the route pattern in the FRAMEWORK's own placeholder
	// spelling. translatePlaceholders and canonicalizePattern are applied
	// inside admit, so there is exactly one canonicalization path.
	Pattern string
	// File is the artifact URI of the source file.
	File string
	// Line is the 1-based line of the registration.
	Line int
}

// NonGoCaveat is one CoverageCaveat plus the non-Go framework and language it
// arose in.
//
// It EMBEDS CoverageCaveat rather than redeclaring one: the reason vocabulary,
// Valid(), String() and RaisesDenominatorFloor() are D.20's and stay D.20's,
// and D.26 can take the embedded value directly. The two extra fields exist
// because CoverageCaveat.Framework is the Go-only Framework enum and this
// packet may not widen it.
type NonGoCaveat struct {
	CoverageCaveat

	// NonGoFramework is the framework involved, or NonGoFrameworkUnset.
	NonGoFramework NonGoFramework
	// Language is the source language.
	Language Language
}

func cloneNonGoCaveats(in []NonGoCaveat) []NonGoCaveat {
	if in == nil {
		return nil
	}
	out := make([]NonGoCaveat, len(in))
	copy(out, in)
	return out
}

// NonGoFileExtract is what one source file produced. Every file offered gets
// one, including the ones no extractor could touch -- that is how an
// unsupported file stays visible instead of vanishing.
type NonGoFileExtract struct {
	// URI is the artifact URI, redacted for display.
	URI string
	// Language is the classified language.
	Language Language
	// Status is what Anvil can do with that language.
	Status LanguageStatus
	// Outcome is what actually happened to this file.
	Outcome ScanOutcome
	// Frameworks are the frameworks recognised in it, sorted.
	Frameworks []NonGoFramework
	// Routes is how many candidate routes it produced.
	Routes int
	// Caveats is how many caveats it produced.
	Caveats int
	// Lexed reports whether scanSource accepted the bytes. False for a file
	// no extractor ran over.
	Lexed bool
}

func cloneFileExtractsNonGo(in []NonGoFileExtract) []NonGoFileExtract {
	if in == nil {
		return nil
	}
	out := make([]NonGoFileExtract, len(in))
	for i, f := range in {
		out[i] = f
		if f.Frameworks != nil {
			fw := make([]NonGoFramework, len(f.Frameworks))
			copy(fw, f.Frameworks)
			out[i].Frameworks = fw
		}
	}
	return out
}

// LanguageReport is one language's whole story for a run.
//
// This is the type the honesty requirement lives in. It reaches D.26 for every
// language present in the offered file set, supported or not.
type LanguageReport struct {
	// Language is the language.
	Language Language
	// Status is what Anvil can do with it.
	Status LanguageStatus
	// Outcome is the run-level outcome for it.
	Outcome ScanOutcome
	// FilesOffered is how many files of this language were handed in.
	FilesOffered int
	// FilesLexed is how many of them scanSource accepted.
	FilesLexed int
	// Routes is how many candidates they produced.
	Routes int
	// Caveats is how many caveats they produced.
	Caveats int
	// Frameworks are the frameworks recognised across them, sorted.
	Frameworks []NonGoFramework
}

func cloneLanguageReports(in []LanguageReport) []LanguageReport {
	if in == nil {
		return nil
	}
	out := make([]LanguageReport, len(in))
	for i, r := range in {
		out[i] = r
		if r.Frameworks != nil {
			fw := make([]NonGoFramework, len(r.Frameworks))
			copy(fw, r.Frameworks)
			out[i].Frameworks = fw
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Config and result
// ---------------------------------------------------------------------------

// OtherExtractConfig is ExtractNonGoRoutes's configuration. Nothing in it has
// a default that means "permitted".
type OtherExtractConfig struct {
	// Target is the kernel Target these routes live on. Required: it is what
	// makes the kernel's path validation possible and what pins each route to
	// a host rather than leaving it a free-floating string.
	Target authz.Target

	// Harvest says what the SAST pass did. Reused from D.19: it is the only
	// thing that can distinguish "this repository has no non-Go source" from
	// "the handoff was never wired".
	Harvest HarvestOutcome
}

// Constructed reports whether cfg carries everything the entry point needs.
func (c OtherExtractConfig) Constructed() bool {
	return c.Target.Constructed() && c.Harvest.Valid()
}

// OtherExtractResult is one D.21 run, sealed.
type OtherExtractResult struct {
	routes    []Route
	refusals  []Refusal
	caveats   []NonGoCaveat
	files     []NonGoFileExtract
	langs     []LanguageReport
	byFW      map[NonGoFramework]int
	sourceOf  map[string]record.ArtifactLocation
	harvest   HarvestOutcome
	offered   int
	scanned   int
	lexed     int
	seen      int
	truncated bool
	sealed    bool
}

// Constructed reports whether r came from ExtractNonGoRoutes.
func (r OtherExtractResult) Constructed() bool { return r.sealed }

// Routes returns a deep copy of the candidate route list.
func (r OtherExtractResult) Routes() []Route { return cloneRoutes(r.routes) }

// Refusals returns a copy of the per-registration refusals.
func (r OtherExtractResult) Refusals() []Refusal { return cloneRefusals(r.refusals) }

// Caveats returns a copy of the coverage caveats, with their frameworks.
func (r OtherExtractResult) Caveats() []NonGoCaveat { return cloneNonGoCaveats(r.caveats) }

// SharedCaveats returns the caveats in D.20's own type, so D.26 can pool the
// Tier 2 caveat lists from both extractors without knowing about this one.
func (r OtherExtractResult) SharedCaveats() []CoverageCaveat {
	if r.caveats == nil {
		return nil
	}
	out := make([]CoverageCaveat, len(r.caveats))
	for i, c := range r.caveats {
		out[i] = c.CoverageCaveat
	}
	return out
}

// Files returns a deep copy of the per-file summary, one entry per file
// offered.
func (r OtherExtractResult) Files() []NonGoFileExtract {
	return cloneFileExtractsNonGo(r.files)
}

// LanguageReports returns a deep copy of the per-language summary, sorted by
// language. This is where "not supported" and "scanned, nothing found" arrive
// as different values.
func (r OtherExtractResult) LanguageReports() []LanguageReport {
	return cloneLanguageReports(r.langs)
}

// LanguageReport returns the report for one language.
func (r OtherExtractResult) LanguageReport(l Language) (LanguageReport, bool) {
	for _, rep := range r.langs {
		if rep.Language == l {
			return cloneLanguageReports([]LanguageReport{rep})[0], true
		}
	}
	return LanguageReport{}, false
}

// Harvest is what the SAST pass did, carried through so a reader of an empty
// result can tell which of the two empties it is.
func (r OtherExtractResult) Harvest() HarvestOutcome { return r.harvest }

// Offered is how many source files were handed in.
func (r OtherExtractResult) Offered() int { return r.offered }

// Scanned is how many of them an extractor actually ran over.
func (r OtherExtractResult) Scanned() int { return r.scanned }

// Lexed is how many of those the lexer accepted.
func (r OtherExtractResult) Lexed() int { return r.lexed }

// Seen is how many registration sites were examined, including the ones that
// became refusals rather than routes.
func (r OtherExtractResult) Seen() int { return r.seen }

// Truncated reports whether a coded bound stopped the run early.
func (r OtherExtractResult) Truncated() bool { return r.truncated }

// FrameworkMix is the per-framework candidate count.
func (r OtherExtractResult) FrameworkMix() map[NonGoFramework]int {
	out := make(map[NonGoFramework]int, len(r.byFW))
	for k, v := range r.byFW {
		out[k] = v
	}
	return out
}

// SourceOf returns the source file a route key came from, so a candidate D.22
// fails to confirm can be traced to a line a human can read.
func (r OtherExtractResult) SourceOf(key string) (record.ArtifactLocation, bool) {
	loc, ok := r.sourceOf[key]
	return loc, ok
}

// DenominatorFloor is the smallest honest size of this tier's contribution to
// the Tier 0-2 union: routes extracted, PLUS per-operation refusals, PLUS the
// caveats that each name at least one endpoint that exists and was not
// extracted.
//
// It deliberately adds NOTHING for an unsupported language. See the file
// header: an unsupported language hides an unknown number of endpoints, and
// calling that number one would be an understatement wearing the costume of a
// measurement. UnsupportedLanguages() and AssertDenominatorIsComplete carry
// that fact instead.
func (r OtherExtractResult) DenominatorFloor() int {
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

// UnsupportedLanguages returns the languages that were PRESENT in the offered
// file set and that Anvil could not look at, sorted.
//
// "Present" is the operative word: this is not the list of languages Anvil
// cannot read in general, it is the list of ones this repository actually
// contains. A repository with no PHP is not penalised for PHP.
func (r OtherExtractResult) UnsupportedLanguages() []Language {
	var out []Language
	for _, rep := range r.langs {
		if rep.Outcome.MeansAnvilCouldNotLook() {
			out = append(out, rep.Language)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DenominatorIsComplete reports whether every offered file reached an
// extractor that could read it.
func (r OtherExtractResult) DenominatorIsComplete() bool {
	return len(r.UnsupportedLanguages()) == 0
}

// AssertDenominatorIsComplete refuses the case the whole packet is about.
//
// endpoint_coverage is confirmed-probed endpoints over the Tier 0-2 union. If
// a language in this repository has no extractor, its endpoints are missing
// from the union, the denominator is too small, and the fraction reads HIGHER
// than the truth -- the metric improving because the tool got worse.
//
// This returns an error so that D.26 cannot compute coverage over an
// incomplete denominator without a line of code saying it chose to.
func (r OtherExtractResult) AssertDenominatorIsComplete() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: OtherExtractResult did not come from "+
			"ExtractNonGoRoutes", ErrUnconstructed)
	}
	missing := r.UnsupportedLanguages()
	if len(missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(missing))
	for _, l := range missing {
		rep, _ := r.LanguageReport(l)
		names = append(names, fmt.Sprintf("%s (%d file(s), %s)",
			l, rep.FilesOffered, rep.Outcome))
	}
	return fmt.Errorf("%w: %s", ErrUnsupportedLanguagePresent, strings.Join(names, "; "))
}

// AssertNotSilentlyEmpty refuses the case where an empty result is a claim
// about Anvil rather than about the repository.
//
// An empty result under HarvestRan, with files offered that an extractor
// actually ran over, is a REPORTABLE FACT: this repository's non-Go source
// registers no routes this tier could see, and the caveats and language
// reports say why. An empty result with nothing scanned is a fact about the
// handoff or about Anvil's language coverage, and it is refused by name.
func (r OtherExtractResult) AssertNotSilentlyEmpty() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: OtherExtractResult did not come from "+
			"ExtractNonGoRoutes", ErrUnconstructed)
	}
	if len(r.routes) > 0 {
		return nil
	}
	if r.harvest == HarvestRan && r.scanned > 0 {
		return nil
	}
	return fmt.Errorf("%w: harvest=%s, files offered=%d, files an extractor ran over=%d, "+
		"routes=0. With nothing scanned, an empty non-Go route list says nothing about "+
		"the target", ErrNoNonGoSourceOffered, r.harvest, r.offered, r.scanned)
}

// AssertEveryRouteIsACandidate is D.21's Forbidden-actions clause, executable.
func (r OtherExtractResult) AssertEveryRouteIsACandidate() error {
	for _, rt := range r.routes {
		if rt.Confirmation() != ConfirmationCandidate {
			return fmt.Errorf("inventory: %w: %s carries confirmation %q. Every Tier 2 "+
				"route is a candidate until D.22 confirms it via live probe; a confirmed "+
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
// ExtractNonGoRoutes -- the entry point
// ---------------------------------------------------------------------------

// ExtractNonGoRoutes turns harvested non-Go source into CANDIDATE inventory
// routes, plus an honest account of what it could not read.
//
// The signature deviates from plan/50-dast.md D.21's
// `ExtractRoutes(repoPath string, framework Framework) ([]Route, error)` in
// three ways, all of them following D.20 rather than inventing anything:
//
//   - No repoPath. This package opens no files; D.19 established that the
//     harvest side hands bytes across, and a package under internal/dast that
//     walks a filesystem is a containment question D.11 owns.
//   - No per-framework parameter. A repository is not one framework, and
//     asking the CALLER which framework a file uses would make the caller's
//     guess the extractor's answer. The framework is decided per file from
//     what the source imports and binds.
//   - A result rather than a bare []Route. The route list is the least
//     important half of the output here; the caveats and the language reports
//     are what keep the coverage denominator honest.
//
// ctx is accepted for signature symmetry with ExtractGoRoutes and for a future
// TypeCheckedExtractor-style seam. Nothing in this file blocks, so it is
// checked once per file rather than plumbed through the lexer.
func ExtractNonGoRoutes(ctx context.Context, cfg OtherExtractConfig, srcs []SourceFile) (OtherExtractResult, error) {
	if !cfg.Target.Constructed() {
		return OtherExtractResult{}, fmt.Errorf("inventory: %w: OtherExtractConfig carries "+
			"a Target that authz.NewTarget never built, so no extracted path can be "+
			"validated by the kernel and no route would name a host", ErrUnconstructed)
	}
	if !cfg.Harvest.Valid() {
		return OtherExtractResult{}, fmt.Errorf("inventory: %w: harvest outcome is %q, "+
			"which is not one of %v. It is the only thing that can distinguish a "+
			"repository with no non-Go source from a handoff that never ran, and "+
			"defaulting it makes the second look like the first",
			ErrRefused, redact(string(cfg.Harvest)), HarvestOutcomeValues())
	}
	if len(srcs) > maxNonGoSourceFilesPerExtract {
		return OtherExtractResult{}, fmt.Errorf("inventory: %w: %d source files were "+
			"offered and the coded bound is %d", ErrRefused, len(srcs),
			maxNonGoSourceFilesPerExtract)
	}
	for i, s := range srcs {
		if !s.Constructed() {
			return OtherExtractResult{}, fmt.Errorf("inventory: %w: source file %d did not "+
				"come from NewSourceFile, so it carries no URI, no bytes or no language "+
				"classification", ErrUnconstructed, i)
		}
	}

	acc := &otherAccumulator{
		target:   cfg.Target,
		byFW:     map[NonGoFramework]int{},
		sourceOf: map[string]record.ArtifactLocation{},
		seenKey:  map[string]bool{},
		locOf:    map[string]record.ArtifactLocation{},
	}
	for _, s := range srcs {
		acc.locOf[s.URI()] = s.Location()
	}

	for _, s := range srcs {
		if err := ctx.Err(); err != nil {
			return OtherExtractResult{}, fmt.Errorf("inventory: %w: extraction was "+
				"cancelled after %d of %d files; a partial route list reported as a "+
				"complete one would understate the coverage denominator",
				err, len(acc.files), len(srcs))
		}
		acc.runFile(s)
	}

	SortRoutes(acc.routes)
	sortNonGoCaveats(acc.caveats)
	sort.SliceStable(acc.files, func(i, j int) bool { return acc.files[i].URI < acc.files[j].URI })

	return OtherExtractResult{
		routes:    acc.routes,
		refusals:  acc.refusals,
		caveats:   acc.caveats,
		files:     acc.files,
		langs:     acc.languageReports(),
		byFW:      acc.byFW,
		sourceOf:  acc.sourceOf,
		harvest:   cfg.Harvest,
		offered:   len(srcs),
		scanned:   acc.scanned,
		lexed:     acc.lexed,
		seen:      acc.seen,
		truncated: acc.truncated,
		sealed:    true,
	}, nil
}

// sortNonGoCaveats orders caveats deterministically, on the same keys
// SortCaveats uses, so the two Tier 2 extractors report in the same order.
func sortNonGoCaveats(cs []NonGoCaveat) {
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
// The accumulator -- the ONE path from a raw registration to a Route
// ---------------------------------------------------------------------------

type otherAccumulator struct {
	target    authz.Target
	routes    []Route
	refusals  []Refusal
	caveats   []NonGoCaveat
	files     []NonGoFileExtract
	byFW      map[NonGoFramework]int
	sourceOf  map[string]record.ArtifactLocation
	seenKey   map[string]bool
	locOf     map[string]record.ArtifactLocation
	scanned   int
	lexed     int
	seen      int
	truncated bool
}

// runFile is the per-file dispatch, and the place every file offered gets a
// NonGoFileExtract whether or not anything could read it.
func (a *otherAccumulator) runFile(f SourceFile) {
	fe := NonGoFileExtract{URI: redact(f.URI()), Language: f.Language(), Status: f.Status()}

	switch f.Status() {
	case LanguageStatusNotSupported:
		fe.Outcome = ScanOutcomeLanguageNotSupported
		a.files = append(a.files, fe)
		return
	case LanguageStatusGoExtractor:
		fe.Outcome = ScanOutcomeHandledByGoExtractor
		a.files = append(a.files, fe)
		return
	case LanguageStatusUnrecognised:
		fe.Outcome = ScanOutcomeFileTypeUnrecognised
		a.files = append(a.files, fe)
		return
	}

	a.scanned++
	routesBefore, caveatsBefore := len(a.routes), len(a.caveats)

	ts, err := scanSource(f.Language(), f.text())
	if err != nil {
		a.caveat(f, 0, NonGoFrameworkUnset, CaveatFileUnparseable, err.Error())
		fe.Outcome = ScanOutcomeNothingParsed
		fe.Caveats = len(a.caveats) - caveatsBefore
		a.files = append(a.files, fe)
		return
	}
	a.lexed++
	fe.Lexed = true

	w := &fileWalk{acc: a, f: f, ts: ts, fws: map[NonGoFramework]bool{}}
	w.run()

	if w.discard {
		// The file lexed but did not hold together structurally -- an
		// unbalanced Rails do/end. Its routes would carry prefixes this file
		// computed from a scope stack it knows is wrong, and a candidate at a
		// wrong path looks like the target's fault when D.22 cannot confirm
		// it. They are DROPPED and the drop is reported.
		a.caveat(f, 0, NonGoFrameworkUnset, CaveatFileUnparseable, w.discardWhy)
		fe.Outcome = ScanOutcomeNothingParsed
		fe.Frameworks = sortedFrameworks(w.fws)
		fe.Caveats = len(a.caveats) - caveatsBefore
		a.files = append(a.files, fe)
		return
	}

	for _, er := range w.out {
		a.admit(er)
	}

	fe.Frameworks = sortedFrameworks(w.fws)
	fe.Routes = len(a.routes) - routesBefore
	fe.Caveats = len(a.caveats) - caveatsBefore
	switch {
	case fe.Routes > 0:
		fe.Outcome = ScanOutcomeRoutesFound
	case len(fe.Frameworks) == 0:
		fe.Outcome = ScanOutcomeScannedNoFrameworkRecognised
	default:
		fe.Outcome = ScanOutcomeScannedNoEndpoints
	}
	a.files = append(a.files, fe)
}

func sortedFrameworks(m map[NonGoFramework]bool) []NonGoFramework {
	var out []NonGoFramework
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (a *otherAccumulator) caveat(f SourceFile, line int, fw NonGoFramework, reason CaveatReason, detail string) {
	c := CoverageCaveat{Reason: reason, File: redact(f.URI()), Line: line, Detail: redact(detail)}
	if !c.Valid() {
		// A caveat with an unrecognised reason is a programming error in this
		// file. It is rewritten rather than trusted, so the count never
		// silently falls and CoverageCaveat.Valid() stays true for everything
		// that leaves here.
		c = CoverageCaveat{Reason: CaveatTruncated, File: redact(f.URI()), Line: line,
			Detail: "an unrecognised caveat reason was produced"}
	}
	if len(a.caveats) >= maxCaveatsPerExtract {
		a.truncated = true
		return
	}
	a.caveats = append(a.caveats, NonGoCaveat{
		CoverageCaveat: c, NonGoFramework: fw, Language: f.Language(),
	})
}

// admit is the single funnel. Every route from every language passes through
// here, which is why "no D.21 route can be confirmed" is a property of the
// code rather than of the reviewer's attention.
func (a *otherAccumulator) admit(er ExtractedNonGoRoute) {
	a.seen++
	if len(a.routes) >= maxRoutesPerExtract {
		a.truncated = true
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
		// A duplicate is the SAME endpoint under a second spelling, not a
		// second endpoint. It is recorded so the count is auditable and it
		// does not become a second row in the union.
		a.refusals = append(a.refusals, Refusal{
			Path: redact(er.Pattern), Method: redact(er.Method),
			Reason: RefusalDuplicateRoute,
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
// them. It is also the ONLY place a pattern is canonicalized: the
// framework-specific placeholder SPELLING is translated first, then D.20's
// canonicalizePattern produces the kernel-facing form, then NewRoute hands the
// path to the kernel. This package holds no second path validator.
func (a *otherAccumulator) toRoute(er ExtractedNonGoRoute) (Route, Refusal, bool) {
	if !er.Framework.Valid() {
		return Route{}, Refusal{
			Path: redact(er.Pattern), Method: redact(er.Method),
			Reason: RefusalRouteUnconstructible,
		}, false
	}
	if len(er.Pattern) > maxRoutePathBytes {
		return Route{}, Refusal{
			Path: redact(er.Pattern), Method: redact(er.Method),
			Reason: RefusalPathRejectedByKernel,
		}, false
	}
	spelled, err := translatePlaceholders(er.Framework, er.Pattern)
	if err != nil {
		return Route{}, Refusal{
			Path: redact(er.Pattern), Method: redact(er.Method),
			Reason: RefusalPathRejectedByKernel,
		}, false
	}
	path, params, err := canonicalizePattern(spelled)
	if err != nil {
		return Route{}, Refusal{
			Path: redact(er.Pattern), Method: redact(er.Method),
			Reason: RefusalPathRejectedByKernel,
		}, false
	}
	// Uppercased and trimmed, because source spells methods however it likes.
	// There is deliberately no allowlist check here: NewRoute already refuses
	// an unallowlisted method and classifyRouteError maps that refusal to
	// RefusalMethodNotAllowlisted, so a check here would be a second copy of a
	// rule the kernel owns -- unreachable, and free to drift the day a method
	// is added there.
	m := authz.Method(strings.ToUpper(strings.TrimSpace(er.Method)))
	rt, err := NewRoute(RouteFacts{
		Method: m,
		Path:   path,
		Target: a.target,
		// Operation is deliberately EMPTY, for the reason D.20's
		// operationLabel gives: Route.Key() is method, path and operation and
		// D.26 deduplicates the Tier 0-2 union on it. Putting the handler name
		// or the framework in here would look like richer provenance and would
		// in fact be denominator inflation -- the same endpoint reached from
		// an Express route and a Tier 0 spec would become two rows. The
		// framework travels in FrameworkMix and the file in SourceOf, neither
		// of which is part of an endpoint's identity.
		Operation:    "",
		Params:       params,
		Provenance:   record.InventoryProvenanceStaticExtraction,
		Confirmation: ConfirmationCandidate,
		Trust:        record.TrustUntrusted,
	})
	if err != nil {
		return Route{}, Refusal{
			Path: redact(er.Pattern), Method: redact(er.Method),
			Reason: classifyRouteError(err),
		}, false
	}
	return rt, Refusal{}, true
}

// languageReports folds the per-file extracts into one row per language
// present in the offered file set.
func (a *otherAccumulator) languageReports() []LanguageReport {
	byLang := map[Language]*LanguageReport{}
	fws := map[Language]map[NonGoFramework]bool{}
	order := []Language{}
	for _, fe := range a.files {
		rep, ok := byLang[fe.Language]
		if !ok {
			rep = &LanguageReport{Language: fe.Language, Status: fe.Status}
			byLang[fe.Language] = rep
			fws[fe.Language] = map[NonGoFramework]bool{}
			order = append(order, fe.Language)
		}
		rep.FilesOffered++
		rep.Routes += fe.Routes
		rep.Caveats += fe.Caveats
		if fe.Lexed {
			rep.FilesLexed++
		}
		for _, f := range fe.Frameworks {
			fws[fe.Language][f] = true
		}
	}
	out := make([]LanguageReport, 0, len(order))
	for _, l := range order {
		rep := byLang[l]
		rep.Frameworks = sortedFrameworks(fws[l])
		rep.Outcome = languageOutcome(*rep)
		out = append(out, *rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Language < out[j].Language })
	return out
}

// languageOutcome decides the run-level outcome for one language.
//
// The order of the cases is the order of the claims a reader should be allowed
// to make, strongest first. In particular "supported, and every file of it
// failed to lex" resolves to ScanOutcomeNothingParsed and therefore to
// MeansAnvilCouldNotLook -- a language whose files Anvil could not read leaves
// the denominator just as incomplete as one it has no extractor for.
func languageOutcome(rep LanguageReport) ScanOutcome {
	switch rep.Status {
	case LanguageStatusNotSupported:
		return ScanOutcomeLanguageNotSupported
	case LanguageStatusGoExtractor:
		return ScanOutcomeHandledByGoExtractor
	case LanguageStatusUnrecognised:
		return ScanOutcomeFileTypeUnrecognised
	}
	switch {
	case rep.Routes > 0:
		return ScanOutcomeRoutesFound
	case rep.FilesLexed == 0:
		return ScanOutcomeNothingParsed
	case len(rep.Frameworks) == 0:
		return ScanOutcomeScannedNoFrameworkRecognised
	default:
		return ScanOutcomeScannedNoEndpoints
	}
}

// ---------------------------------------------------------------------------
// Placeholder spelling -> the "{name}" spelling canonicalizePattern reads
// ---------------------------------------------------------------------------

// translatePlaceholders rewrites a framework's placeholder SPELLING into the
// "{name}" form D.20's canonicalizePattern already understands.
//
// It is not a second canonicalizer and it deliberately does not act like one:
// it does not touch slashes, case, dot segments, the leading "/", or anything
// else the kernel or canonicalizePattern owns. It rewrites placeholder
// segments and nothing else, and its output goes straight into
// canonicalizePattern at the single call site in toRoute, so there is exactly
// one function producing the kernel-facing form.
//
// The spellings:
//
//	<id>, <int:id>, <path:rest>   Flask, Django   -> {id}, {id}, {rest}
//	:id, :id?                     Express, Rails  -> {id}   (canonicalizePattern
//	                                                 reads ":id"; the "?" is
//	                                                 stripped here)
//	{id}, {id:regex}              FastAPI, Spring -> handled by canonicalizePattern
//	{*rest}                       Spring 6        -> {rest}
//	*rest                         Rails glob      -> handled by canonicalizePattern
func translatePlaceholders(fw NonGoFramework, pat string) (string, error) {
	if pat == "" {
		return "", errors.New("empty pattern")
	}
	if len(pat) > maxRoutePathBytes {
		return "", fmt.Errorf("pattern is %d bytes", len(pat))
	}
	segs := strings.Split(pat, "/")
	for i, seg := range segs {
		switch {
		case strings.HasPrefix(seg, "<") && strings.HasSuffix(seg, ">"):
			// Flask and Django: <converter:name>, converter FIRST. This is
			// the reverse of chi's {name:regex}, which is exactly why the
			// translation cannot be left to canonicalizePattern -- it would
			// keep "int" and drop "id".
			inner := seg[1 : len(seg)-1]
			if j := strings.IndexByte(inner, ':'); j >= 0 {
				inner = inner[j+1:]
			}
			segs[i] = "{" + inner + "}"
		case strings.HasPrefix(seg, "{*") && strings.HasSuffix(seg, "}"):
			segs[i] = "{" + seg[2:len(seg)-1] + "}"
		case strings.HasPrefix(seg, ":") && strings.HasSuffix(seg, "?") && len(seg) > 2:
			segs[i] = seg[:len(seg)-1]
		}
	}
	return strings.Join(segs, "/"), nil
}

// ---------------------------------------------------------------------------
// The lexer
// ---------------------------------------------------------------------------

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokSymbol
	tokPunct
	tokNumber
	tokNewline
)

// tok is one lexical token.
//
// `lit` is the load-bearing field: it is false for a string whose value this
// lexer cannot know statically -- an interpolated template literal, an
// f-string, a "#{}" Ruby string, or ANY string carrying a backslash escape.
// Every extractor below treats a non-literal string as
// CaveatPathNotStaticallyResolvable rather than as a path, which is why a
// decoding bug in an escape sequence cannot become a route at the wrong path.
type tok struct {
	kind tokKind
	text string
	str  string
	lit  bool
	line int
}

type tokens []tok

func (ts tokens) at(i int) tok {
	if i < 0 || i >= len(ts) {
		return tok{kind: tokEOF}
	}
	return ts[i]
}

func (ts tokens) isPunct(i int, s string) bool {
	t := ts.at(i)
	return t.kind == tokPunct && t.text == s
}

func (ts tokens) isIdent(i int, s string) bool {
	t := ts.at(i)
	return t.kind == tokIdent && t.text == s
}

// matchClose returns the index of the bracket closing the one at open.
func (ts tokens) matchClose(open int) (int, bool) {
	o := ts.at(open)
	if o.kind != tokPunct {
		return 0, false
	}
	want, ok := map[string]string{"(": ")", "[": "]", "{": "}"}[o.text]
	if !ok {
		return 0, false
	}
	depth := 0
	for i := open; i < len(ts); i++ {
		t := ts[i]
		if t.kind != tokPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
			if depth == 0 {
				if t.text == want {
					return i, true
				}
				return 0, false
			}
		}
	}
	return 0, false
}

// span is a half-open token range.
type span struct{ lo, hi int }

// splitArgs splits the tokens between an opening bracket and its match into
// top-level comma-separated spans. Newline tokens are skipped, so an argument
// list broken across lines splits the same way as one on a single line.
func (ts tokens) splitArgs(open, close int) []span {
	var out []span
	depth := 0
	lo := open + 1
	for i := open; i < close; i++ {
		t := ts[i]
		if t.kind != tokPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ",":
			if depth == 1 {
				out = append(out, span{lo, i})
				lo = i + 1
			}
		}
	}
	if lo < close {
		out = append(out, span{lo, close})
	}
	for i := range out {
		out[i] = ts.trimSpan(out[i])
	}
	return out
}

func (ts tokens) trimSpan(s span) span {
	for s.lo < s.hi && ts[s.lo].kind == tokNewline {
		s.lo++
	}
	for s.hi > s.lo && ts[s.hi-1].kind == tokNewline {
		s.hi--
	}
	return s
}

// soleString returns the value of a span that is exactly one literal string.
//
// "Exactly one" is the check that keeps `BASE + "/x"` out of the route table:
// a span holding a string and an operator is not a static path, and the second
// return value is false for it.
func (ts tokens) soleString(s span) (string, bool) {
	s = ts.trimSpan(s)
	if s.hi-s.lo != 1 {
		return "", false
	}
	t := ts[s.lo]
	if t.kind != tokString || !t.lit {
		return "", false
	}
	return t.str, true
}

// soleIdent returns the identifier of a span that is exactly one identifier.
func (ts tokens) soleIdent(s span) (string, bool) {
	s = ts.trimSpan(s)
	if s.hi-s.lo != 1 {
		return "", false
	}
	t := ts[s.lo]
	if t.kind != tokIdent {
		return "", false
	}
	return t.text, true
}

// spanHasString reports whether a span mentions any string at all, literal or
// not. It is what distinguishes "a computed path" (worth a caveat) from "no
// path argument at all" (an ordinary middleware call, worth nothing).
func (ts tokens) spanHasString(s span) bool {
	for i := s.lo; i < s.hi; i++ {
		if ts[i].kind == tokString {
			return true
		}
	}
	return false
}

var errUnterminated = errors.New("a string, comment or heredoc was never terminated")

// scanSource lexes one source file.
//
// It emits newline tokens for Python and Ruby, whose statements are
// line-terminated, and not for JavaScript or Java, where a method chain broken
// across lines is ordinary style and a newline token would break the
// adjacency checks the extractors use.
func scanSource(lang Language, src string) (tokens, error) {
	var out tokens
	line := 1
	i, n := 0, len(src)
	wantNewlines := lang == LanguagePython || lang == LanguageRuby

	prev := func() tok {
		if len(out) == 0 {
			return tok{kind: tokEOF}
		}
		return out[len(out)-1]
	}
	emit := func(t tok) { out = append(out, t) }

	for i < n {
		if len(out) > maxTokensPerFile {
			return nil, fmt.Errorf("the file produced more than %d tokens", maxTokensPerFile)
		}
		c := src[i]

		if c == '\n' {
			if wantNewlines && prev().kind != tokNewline && len(out) > 0 {
				emit(tok{kind: tokNewline, text: "\n", line: line})
			}
			line++
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v' {
			i++
			continue
		}

		// --- comments ---
		switch lang {
		case LanguageJavaScript, LanguageJava:
			if c == '/' && i+1 < n && src[i+1] == '/' {
				for i < n && src[i] != '\n' {
					i++
				}
				continue
			}
			if c == '/' && i+1 < n && src[i+1] == '*' {
				j := strings.Index(src[i+2:], "*/")
				if j < 0 {
					return nil, fmt.Errorf("%w: block comment at line %d", errUnterminated, line)
				}
				line += strings.Count(src[i:i+2+j+2], "\n")
				i += 2 + j + 2
				continue
			}
		case LanguagePython, LanguageRuby:
			if c == '#' {
				for i < n && src[i] != '\n' {
					i++
				}
				continue
			}
		}
		if lang == LanguageRuby && c == '=' && atLineStart(src, i) && strings.HasPrefix(src[i:], "=begin") {
			j := strings.Index(src[i:], "\n=end")
			if j < 0 {
				return nil, fmt.Errorf("%w: =begin block at line %d", errUnterminated, line)
			}
			line += strings.Count(src[i:i+j+1], "\n")
			i += j + 1
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}

		// --- Ruby heredocs, before "<<" is read as an operator ---
		if lang == LanguageRuby && c == '<' && i+1 < n && src[i+1] == '<' {
			if ni, nl, ok, err := scanRubyHeredoc(src, i, line, prev()); err != nil {
				return nil, err
			} else if ok {
				i, line = ni, nl
				emit(tok{kind: tokString, str: "", lit: false, line: line})
				continue
			}
		}

		// --- Ruby percent literals ---
		if lang == LanguageRuby && c == '%' && i+1 < n {
			switch src[i+1] {
			case 'w', 'i', 'W', 'I':
				ni, nl, items, ok := scanRubyWordList(src, i, line)
				if !ok {
					return nil, fmt.Errorf("%w: %%%c list at line %d", errUnterminated, src[i+1], line)
				}
				kind := tokString
				if src[i+1] == 'i' || src[i+1] == 'I' {
					kind = tokSymbol
				}
				emit(tok{kind: tokPunct, text: "[", line: line})
				for _, w := range items {
					emit(tok{kind: kind, str: w, text: w, lit: true, line: line})
				}
				emit(tok{kind: tokPunct, text: "]", line: nl})
				i, line = ni, nl
				continue
			case 'q', 'Q', 'r':
				ni, nl, val, ok := scanRubyPercentString(src, i, line)
				if !ok {
					return nil, fmt.Errorf("%w: %%%c literal at line %d", errUnterminated, src[i+1], line)
				}
				// %r is a regex, never a static path.
				emit(tok{kind: tokString, str: val, lit: src[i+1] != 'r', line: line})
				i, line = ni, nl
				continue
			}
		}

		// --- regex literals, which must not be mistaken for division ---
		if (lang == LanguageJavaScript || lang == LanguageRuby) && c == '/' && regexCanStartHere(prev()) {
			if ni, ok := skipRegexLiteral(src, i); ok {
				emit(tok{kind: tokString, str: "", lit: false, line: line})
				i = ni
				continue
			}
		}

		// --- strings ---
		if isQuote(c) || (lang == LanguageJava && c == '"') {
			ni, nl, val, lit, err := scanQuoted(lang, src, i, line, false, false)
			if err != nil {
				return nil, err
			}
			emit(tok{kind: tokString, str: val, lit: lit, line: line})
			i, line = ni, nl
			continue
		}

		// --- Ruby symbols ---
		if lang == LanguageRuby && c == ':' && i+1 < n && isIdentStart(src[i+1]) {
			j := i + 1
			for j < n && isIdentPart(src[j]) {
				j++
			}
			emit(tok{kind: tokSymbol, text: src[i+1 : j], str: src[i+1 : j], lit: true, line: line})
			i = j
			continue
		}

		// --- identifiers, and Python string prefixes ---
		if isIdentStart(c) {
			j := i
			for j < n && isIdentPart(src[j]) {
				j++
			}
			word := src[i:j]
			if lang == LanguageRuby && j < n && (src[j] == '?' || src[j] == '!') {
				j++
				word = src[i:j]
			}
			if lang == LanguagePython && j < n && isQuote(src[j]) && isPythonStringPrefix(word) {
				raw := strings.ContainsAny(word, "rR")
				interp := strings.ContainsAny(word, "fF")
				ni, nl, val, lit, err := scanQuoted(lang, src, j, line, raw, interp)
				if err != nil {
					return nil, err
				}
				emit(tok{kind: tokString, str: val, lit: lit, line: line})
				i, line = ni, nl
				continue
			}
			emit(tok{kind: tokIdent, text: word, line: line})
			i = j
			continue
		}

		// --- numbers ---
		if c >= '0' && c <= '9' {
			j := i
			for j < n && (isIdentPart(src[j]) || src[j] == '.') {
				j++
			}
			emit(tok{kind: tokNumber, text: src[i:j], line: line})
			i = j
			continue
		}

		// --- punctuation ---
		if i+1 < n {
			two := src[i : i+2]
			switch two {
			case "=>", "::", "->", "==", "!=", "<=", ">=", "&&", "||", "+=", "?.", "**":
				emit(tok{kind: tokPunct, text: two, line: line})
				i += 2
				continue
			}
		}
		emit(tok{kind: tokPunct, text: string(c), line: line})
		i++
	}
	if wantNewlines && len(out) > 0 && out[len(out)-1].kind != tokNewline {
		out = append(out, tok{kind: tokNewline, text: "\n", line: line})
	}
	return out, nil
}

func atLineStart(src string, i int) bool { return i == 0 || src[i-1] == '\n' }

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' || c >= 0x80
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func isPythonStringPrefix(w string) bool {
	switch strings.ToLower(w) {
	case "r", "b", "u", "f", "rb", "br", "fr", "rf", "ur", "bR":
		return true
	}
	return false
}

// scanQuoted lexes one quoted string, returning the next index, the new line
// number, the decoded value and whether the value is STATICALLY KNOWN.
//
// A string is not statically known when it carries an interpolation
// ("${...}", "#{...}", an f-string) or ANY backslash escape. The escape rule
// is deliberately blunt: decoding "/" correctly is easy to get subtly
// wrong, and a subtly wrong decode becomes a route at a path the target does
// not serve. A string with an escape becomes
// CaveatPathNotStaticallyResolvable, which is the direction that cannot
// invent an endpoint.
func scanQuoted(lang Language, src string, i, line int, raw, interp bool) (int, int, string, bool, error) {
	n := len(src)
	q := src[i]
	triple := false
	if (lang == LanguagePython || lang == LanguageJava) && i+2 < n && src[i+1] == q && src[i+2] == q {
		triple = true
	}
	openLen := 1
	if triple {
		openLen = 3
	}
	j := i + openLen
	var b strings.Builder
	lit := !interp
	startLine := line
	for j < n {
		c := src[j]
		if c == '\n' {
			line++
			if !triple && lang != LanguageJavaScript && q != '`' {
				return 0, 0, "", false, fmt.Errorf("%w: string at line %d", errUnterminated, startLine)
			}
			b.WriteByte(c)
			j++
			continue
		}
		if c == '\\' && !raw {
			lit = false
			j += 2
			continue
		}
		if c == '\\' && raw {
			b.WriteByte(c)
			lit = false
			j += 2
			if j <= n {
				continue
			}
			break
		}
		if q == '`' && lang == LanguageJavaScript && c == '$' && j+1 < n && src[j+1] == '{' {
			lit = false
			depth := 0
			for j < n {
				if src[j] == '{' {
					depth++
				} else if src[j] == '}' {
					depth--
					if depth == 0 {
						j++
						break
					}
				} else if src[j] == '\n' {
					line++
				}
				j++
			}
			continue
		}
		if q == '"' && lang == LanguageRuby && c == '#' && j+1 < n && src[j+1] == '{' {
			lit = false
			depth := 0
			for j < n {
				if src[j] == '{' {
					depth++
				} else if src[j] == '}' {
					depth--
					if depth == 0 {
						j++
						break
					}
				} else if src[j] == '\n' {
					line++
				}
				j++
			}
			continue
		}
		if c == q {
			if triple {
				if j+2 < n && src[j+1] == q && src[j+2] == q {
					return j + 3, line, b.String(), lit, nil
				}
				b.WriteByte(c)
				j++
				continue
			}
			return j + 1, line, b.String(), lit, nil
		}
		b.WriteByte(c)
		j++
	}
	return 0, 0, "", false, fmt.Errorf("%w: string at line %d", errUnterminated, startLine)
}

// regexCanStartHere is the standard previous-token heuristic for telling a
// regex literal from a division operator.
//
// It matters more than it looks: a regex like /['"]/ carries an unbalanced
// quote, and lexing it as division would flip the string state for the rest of
// the file. The failure would be silent -- routes vanishing, or a comment
// becoming a path.
func regexCanStartHere(prev tok) bool {
	switch prev.kind {
	case tokEOF, tokNewline:
		return true
	case tokIdent:
		switch prev.text {
		case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
			"case", "do", "else", "yield", "await", "throw", "and", "or", "not",
			"when", "unless", "if", "while", "until", "then":
			return true
		}
		return false
	case tokPunct:
		switch prev.text {
		case "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-",
			"*", "%", "<", ">", "~", "^", "=>", "&&", "||", "==", "!=", "<=", ">=":
			return true
		}
		return false
	}
	return false
}

// skipRegexLiteral consumes a /.../flags literal. It refuses one that would
// span a newline, which is what a division operator at the end of a line looks
// like, so a misfire of the heuristic costs a mis-lexed operator rather than
// the rest of the file.
func skipRegexLiteral(src string, i int) (int, bool) {
	n := len(src)
	j := i + 1
	inClass := false
	for j < n {
		c := src[j]
		switch {
		case c == '\n':
			return 0, false
		case c == '\\':
			j += 2
			continue
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			j++
			for j < n && isIdentPart(src[j]) {
				j++
			}
			return j, true
		}
		j++
	}
	return 0, false
}

// scanRubyHeredoc consumes a <<~IDENT / <<-IDENT / <<IDENT heredoc body.
//
// The third form is only treated as a heredoc after a token that cannot end an
// expression, because "a << B" is a left shift and mis-reading it as a heredoc
// would swallow the rest of the file.
func scanRubyHeredoc(src string, i, line int, prev tok) (int, int, bool, error) {
	n := len(src)
	j := i + 2
	squiggly := false
	if j < n && (src[j] == '~' || src[j] == '-') {
		squiggly = true
		j++
	}
	if j < n && (src[j] == '\'' || src[j] == '"') {
		q := src[j]
		k := j + 1
		for k < n && src[k] != q && src[k] != '\n' {
			k++
		}
		if k >= n || src[k] != q {
			return 0, 0, false, nil
		}
		return consumeHeredocBody(src, k+1, line, src[j+1:k])
	}
	k := j
	for k < n && isIdentPart(src[k]) {
		k++
	}
	if k == j {
		return 0, 0, false, nil
	}
	tag := src[j:k]
	if !squiggly {
		if !isAllUpperASCII(strings.ReplaceAll(tag, "_", "A")) {
			return 0, 0, false, nil
		}
		switch prev.kind {
		case tokEOF, tokNewline:
		case tokPunct:
			switch prev.text {
			case "(", ",", "=", "=>", "[", "{":
			default:
				return 0, 0, false, nil
			}
		default:
			return 0, 0, false, nil
		}
	}
	return consumeHeredocBody(src, k, line, tag)
}

func consumeHeredocBody(src string, from, line int, tag string) (int, int, bool, error) {
	n := len(src)
	// The rest of the line after the heredoc marker belongs to the statement,
	// but nothing in this file reads it, so it is consumed with the body. That
	// loses at most a trailing argument on a line that already contains a
	// heredoc, and no fixture or framework shape below puts a route there.
	j := from
	for j < n && src[j] != '\n' {
		j++
	}
	lines := 0
	for j < n {
		j++
		lines++
		k := j
		for k < n && src[k] != '\n' {
			k++
		}
		if strings.TrimSpace(src[j:k]) == tag {
			return k, line + lines, true, nil
		}
		j = k
		if j >= n {
			break
		}
	}
	return 0, 0, false, fmt.Errorf("%w: heredoc <<%s at line %d", errUnterminated, tag, line)
}

func scanRubyWordList(src string, i, line int) (int, int, []string, bool) {
	n := len(src)
	if i+2 >= n {
		return 0, 0, nil, false
	}
	open := src[i+2]
	closer, ok := map[byte]byte{'[': ']', '(': ')', '{': '}', '<': '>'}[open]
	if !ok {
		return 0, 0, nil, false
	}
	j := i + 3
	start := j
	for j < n && src[j] != closer {
		j++
	}
	if j >= n {
		return 0, 0, nil, false
	}
	body := src[start:j]
	return j + 1, line + strings.Count(body, "\n"), strings.Fields(body), true
}

func scanRubyPercentString(src string, i, line int) (int, int, string, bool) {
	n := len(src)
	if i+2 >= n {
		return 0, 0, "", false
	}
	open := src[i+2]
	closer, ok := map[byte]byte{'[': ']', '(': ')', '{': '}', '<': '>', '|': '|', '!': '!'}[open]
	if !ok {
		return 0, 0, "", false
	}
	j := i + 3
	start := j
	for j < n && src[j] != closer {
		if src[j] == '\\' {
			j++
		}
		j++
	}
	if j >= n {
		return 0, 0, "", false
	}
	body := src[start:j]
	return j + 1, line + strings.Count(body, "\n"), body, true
}

// ---------------------------------------------------------------------------
// The per-file walk
// ---------------------------------------------------------------------------

type fileWalk struct {
	acc        *otherAccumulator
	f          SourceFile
	ts         tokens
	fws        map[NonGoFramework]bool
	out        []ExtractedNonGoRoute
	discard    bool
	discardWhy string
}

func (w *fileWalk) caveat(line int, fw NonGoFramework, reason CaveatReason, detail string) {
	w.acc.caveat(w.f, line, fw, reason, detail)
}

func (w *fileWalk) emit(fw NonGoFramework, method, pattern string, line int) {
	w.out = append(w.out, ExtractedNonGoRoute{
		Framework: fw, Language: w.f.Language(), Method: method,
		Pattern: pattern, File: w.f.URI(), Line: line,
	})
}

// run dispatches on the language. SupportedLanguages() is derived from this
// switch: a language listed there without a case here would report
// ScanOutcomeScannedNoFrameworkRecognised for every file, which is a claim
// about the target rather than about Anvil, so the two are kept together and
// TestSupportedLanguagesAllHaveAnExtractor checks it.
func (w *fileWalk) run() {
	switch w.f.Language() {
	case LanguageJavaScript:
		w.express()
	case LanguagePython:
		w.python()
	case LanguageJava:
		w.spring()
	case LanguageRuby:
		w.rails()
	}
}

// httpMethodForVerb maps a lower-case framework verb to an HTTP method.
//
// TRACE is included deliberately even though the kernel's allowlist does not
// carry it: a @app.trace route becomes a per-operation Refusal that COUNTS
// toward the coverage denominator, where dropping it here would make it
// disappear.
func httpMethodForVerb(v string) (string, bool) {
	switch v {
	case "get":
		return "GET", true
	case "post":
		return "POST", true
	case "put":
		return "PUT", true
	case "patch":
		return "PATCH", true
	case "delete":
		return "DELETE", true
	case "head":
		return "HEAD", true
	case "options":
		return "OPTIONS", true
	case "trace":
		return "TRACE", true
	}
	return "", false
}

// routeJoin composes a scope prefix with a route pattern.
//
// It differs from D.20's joinPrefix in exactly one case: an EMPTY pattern.
// joinPrefix("/api/users", "") returns "/api/users/", which is right for a chi
// Route group and wrong for Spring's bare @GetMapping on a mapped class and
// for Rails' `resources` index action -- both of those serve "/api/users" with
// no trailing slash, and a trailing slash is a DIFFERENT endpoint in the
// Tier 0-2 union. Every other case delegates, so there is no second joiner
// with its own opinion about slashes.
func routeJoin(prefix, pat string) string {
	if pat == "" {
		if prefix == "" {
			return "/"
		}
		return prefix
	}
	return joinPrefix(prefix, pat)
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Express
// ---------------------------------------------------------------------------

type jsRouterKind struct{ isApp bool }

type jsReg struct {
	router, method, pattern string
	line                    int
}

type jsMount struct {
	parent, child, prefix string
	line                  int
}

func (w *fileWalk) express() {
	ts := w.ts
	mods := map[string]bool{}        // idents bound to the express module
	routerCtors := map[string]bool{} // idents bound to express.Router

	for i := 0; i < len(ts); i++ {
		if ts.isIdent(i, "require") && ts.isPunct(i+1, "(") {
			if s, ok := ts.soleString(span{i + 2, i + 3}); ok && s == "express" && ts.isPunct(i+3, ")") {
				w.bindJSRequire(i, mods, routerCtors)
			}
			continue
		}
		if ts.isIdent(i, "import") {
			w.bindJSImport(i, mods, routerCtors)
		}
	}
	if len(mods) == 0 && len(routerCtors) == 0 {
		w.caveat(0, NonGoFrameworkUnset, CaveatNoFrameworkRecognised,
			"no express import was found in this file")
		return
	}
	w.fws[NonGoFrameworkExpress] = true

	routers := map[string]jsRouterKind{}
	// require("express")() binds an app directly.
	for i := 0; i < len(ts); i++ {
		if ts.isIdent(i, "require") && ts.isPunct(i+1, "(") &&
			ts.isPunct(i+3, ")") && ts.isPunct(i+4, "(") {
			if s, ok := ts.soleString(span{i + 2, i + 3}); ok && s == "express" {
				if ts.isPunct(i-1, "=") && ts.at(i-2).kind == tokIdent {
					routers[ts.at(i-2).text] = jsRouterKind{isApp: true}
				}
			}
		}
	}
	for i := 0; i < len(ts); i++ {
		if ts.at(i).kind != tokIdent || !ts.isPunct(i+1, "(") {
			continue
		}
		name := ts.at(i).text
		start, isApp, isRouter := i, false, false
		switch {
		case name == "Router" && ts.isPunct(i-1, ".") && mods[ts.at(i-2).text]:
			isRouter, start = true, i-2
		case mods[name]:
			isApp = true
		case routerCtors[name]:
			isRouter = true
		}
		if !isApp && !isRouter {
			continue
		}
		if ts.isPunct(start-1, "=") && ts.at(start-2).kind == tokIdent {
			routers[ts.at(start-2).text] = jsRouterKind{isApp: isApp}
		}
	}

	var regs []jsReg
	var mounts []jsMount
	for i := 0; i < len(ts); i++ {
		t := ts.at(i)
		if t.kind != tokIdent {
			continue
		}
		if _, ok := routers[t.text]; ok && ts.isPunct(i+1, "[") {
			w.caveat(t.line, NonGoFrameworkExpress, CaveatMethodNotEnumerated,
				"computed member access on router "+t.text)
			continue
		}
		if !(ts.isPunct(i+1, ".") && ts.at(i+2).kind == tokIdent && ts.isPunct(i+3, "(")) {
			continue
		}
		recv, verb := t.text, ts.at(i+2).text
		open := i + 3
		closeIdx, ok := ts.matchClose(open)
		if !ok {
			continue
		}
		args := ts.splitArgs(open, closeIdx)
		if _, isRouter := routers[recv]; !isRouter {
			if expressRegistrationVerb(verb) && len(args) >= 2 {
				if p, ok := ts.soleString(args[0]); ok && strings.HasPrefix(p, "/") {
					w.caveat(t.line, NonGoFrameworkExpress, CaveatRouterNotResolved,
						recv+"."+verb)
				}
			}
			continue
		}
		switch {
		case verb == "use":
			w.expressUse(recv, args, t.line, routers, &mounts)
		case verb == "route":
			closeIdx = w.expressRouteChain(recv, args, closeIdx, t.line, &regs)
		case verb == "all":
			if len(args) == 0 {
				break
			}
			if p, ok := ts.soleString(args[0]); ok && len(args) >= 2 {
				regs = append(regs, jsReg{recv, "GET", p, t.line})
				w.caveat(t.line, NonGoFrameworkExpress, CaveatMethodNotEnumerated,
					recv+".all "+p)
			} else if len(args) > 0 && ts.spanHasString(args[0]) {
				w.caveat(t.line, NonGoFrameworkExpress, CaveatPathNotStaticallyResolvable,
					recv+".all")
			}
		default:
			m, isVerb := httpMethodForVerb(verb)
			if !isVerb {
				break
			}
			// app.get("title") with ONE argument is Express's settings
			// getter, not a route. Emitting it would put a configuration key
			// in the coverage denominator forever.
			if len(args) < 2 {
				break
			}
			if p, ok := ts.soleString(args[0]); ok {
				regs = append(regs, jsReg{recv, m, p, t.line})
			} else if ts.spanHasString(args[0]) || args[0].hi > args[0].lo {
				w.caveat(t.line, NonGoFrameworkExpress, CaveatPathNotStaticallyResolvable,
					recv+"."+verb)
			}
		}
		i = closeIdx
	}

	w.emitWithPrefixes(NonGoFrameworkExpress, routers, regs, mounts)
}

func expressRegistrationVerb(v string) bool {
	if _, ok := httpMethodForVerb(v); ok {
		return v != "trace"
	}
	return v == "all" || v == "use" || v == "route"
}

func (w *fileWalk) expressUse(recv string, args []span, line int,
	routers map[string]jsRouterKind, mounts *[]jsMount) {
	ts := w.ts
	if len(args) == 0 {
		return
	}
	prefix, ok := ts.soleString(args[0])
	if !ok {
		// app.use(middleware) mounts no path and names no endpoint. Silence
		// is correct here and is not the silence this packet is about.
		return
	}
	if len(args) >= 2 {
		if child, ok := ts.soleIdent(args[1]); ok {
			if _, known := routers[child]; known {
				*mounts = append(*mounts, jsMount{recv, child, prefix, line})
				return
			}
		}
	}
	w.caveat(line, NonGoFrameworkExpress, CaveatMountNotFollowed,
		recv+".use "+prefix)
}

// expressRouteChain reads router.route("/x").get(h).post(h) and returns the
// index the outer loop should continue from.
func (w *fileWalk) expressRouteChain(recv string, args []span, closeIdx, line int, regs *[]jsReg) int {
	ts := w.ts
	if len(args) == 0 {
		return closeIdx
	}
	p, ok := ts.soleString(args[0])
	if !ok {
		w.caveat(line, NonGoFrameworkExpress, CaveatPathNotStaticallyResolvable,
			recv+".route")
		return closeIdx
	}
	j := closeIdx + 1
	for depth := 0; depth < maxNonGoNestingDepth; depth++ {
		if !(ts.isPunct(j, ".") && ts.at(j+1).kind == tokIdent && ts.isPunct(j+2, "(")) {
			break
		}
		verb := ts.at(j + 1).text
		cclose, ok := ts.matchClose(j + 2)
		if !ok {
			break
		}
		if m, isVerb := httpMethodForVerb(verb); isVerb {
			*regs = append(*regs, jsReg{recv, m, p, ts.at(j + 1).line})
		} else if verb == "all" {
			*regs = append(*regs, jsReg{recv, "GET", p, ts.at(j + 1).line})
			w.caveat(ts.at(j+1).line, NonGoFrameworkExpress, CaveatMethodNotEnumerated,
				recv+".route().all")
		}
		j = cclose
		closeIdx = cclose
		j++
	}
	return closeIdx
}

// emitWithPrefixes resolves Express mount prefixes and emits.
//
// A router that no app in this file mounts gets CaveatCallerPrefixNotVisible
// and is emitted at its bare path. The route is still a CANDIDATE and D.22
// confirms it; the caveat is there so that a candidate at a path the target
// does not serve reads as Anvil's incompleteness rather than the target's
// fault. This mirrors D.20's handling of a chi router bound from a parameter.
func (w *fileWalk) emitWithPrefixes(fw NonGoFramework, routers map[string]jsRouterKind,
	regs []jsReg, mounts []jsMount) {
	prefixes := map[string][]string{}
	for name, r := range routers {
		if r.isApp {
			prefixes[name] = []string{""}
		}
	}
	for pass := 0; ; pass++ {
		if pass >= maxNonGoNestingDepth {
			w.caveat(0, fw, CaveatNestingTooDeep,
				fmt.Sprintf("mount resolution did not settle within %d passes",
					maxNonGoNestingDepth))
			break
		}
		changed := false
		for _, m := range mounts {
			for _, base := range prefixes[m.parent] {
				np := joinPrefix(base, m.prefix)
				if !containsStr(prefixes[m.child], np) {
					prefixes[m.child] = append(prefixes[m.child], np)
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	warned := map[string]bool{}
	for _, r := range regs {
		pres := prefixes[r.router]
		if len(pres) == 0 {
			if !warned[r.router] {
				warned[r.router] = true
				w.caveat(r.line, fw, CaveatCallerPrefixNotVisible,
					"router "+r.router+" is not mounted in this file")
			}
			pres = []string{""}
		}
		sort.Strings(pres)
		for _, pre := range pres {
			w.emit(fw, r.method, joinPrefix(pre, r.pattern), r.line)
		}
	}
}

// ---------------------------------------------------------------------------
// Python: Flask, FastAPI and Django
// ---------------------------------------------------------------------------

type pyRouter struct {
	fw     NonGoFramework
	prefix string
	isApp  bool
	bound  bool // an app, or a blueprint/router registered in this file
}

func (w *fileWalk) python() {
	ts := w.ts
	// Local name -> the imported symbol it refers to. Only symbols imported
	// from a framework module are entered, so `from mypkg import path` cannot
	// turn os.path calls into Django routes.
	sym := map[string]string{}
	for i := 0; i < len(ts); i++ {
		if ts.isIdent(i, "from") {
			w.bindPythonFrom(i, sym)
		}
	}
	if len(sym) == 0 {
		w.caveat(0, NonGoFrameworkUnset, CaveatNoFrameworkRecognised,
			"no flask, fastapi or django import was found in this file")
		return
	}

	routers := map[string]*pyRouter{}
	for i := 0; i < len(ts); i++ {
		if ts.at(i).kind != tokIdent || !ts.isPunct(i+1, "(") {
			continue
		}
		canon, ok := sym[ts.at(i).text]
		if !ok {
			continue
		}
		if !ts.isPunct(i-1, "=") || ts.at(i-2).kind != tokIdent {
			continue
		}
		name := ts.at(i - 2).text
		closeIdx, ok := ts.matchClose(i + 1)
		if !ok {
			continue
		}
		args := ts.splitArgs(i+1, closeIdx)
		switch canon {
		case "Flask":
			routers[name] = &pyRouter{fw: NonGoFrameworkFlask, isApp: true, bound: true}
		case "FastAPI":
			routers[name] = &pyRouter{fw: NonGoFrameworkFastAPI, isApp: true, bound: true}
		case "Blueprint":
			p, _ := w.pyKwargString(args, "url_prefix")
			routers[name] = &pyRouter{fw: NonGoFrameworkFlask, prefix: p}
		case "APIRouter":
			p, _ := w.pyKwargString(args, "prefix")
			routers[name] = &pyRouter{fw: NonGoFrameworkFastAPI, prefix: p}
		}
	}

	// Registration of blueprints and routers, which supplies the prefix an
	// unregistered one does not have.
	for i := 0; i < len(ts); i++ {
		if !(ts.at(i).kind == tokIdent && ts.isPunct(i+1, ".") &&
			ts.at(i+2).kind == tokIdent && ts.isPunct(i+3, "(")) {
			continue
		}
		verb := ts.at(i + 2).text
		if verb != "register_blueprint" && verb != "include_router" {
			continue
		}
		parent, isParent := routers[ts.at(i).text]
		closeIdx, ok := ts.matchClose(i + 3)
		if !ok {
			continue
		}
		args := ts.splitArgs(i+3, closeIdx)
		if len(args) == 0 {
			continue
		}
		child, ok := ts.soleIdent(args[0])
		if !ok {
			continue
		}
		r, known := routers[child]
		if !known {
			w.caveat(ts.at(i).line, frameworkForPyVerb(verb), CaveatMountNotFollowed,
				ts.at(i).text+"."+verb+" of an unknown router")
			continue
		}
		outer := ""
		if isParent {
			outer = parent.prefix
		}
		if p, ok := w.pyKwargString(args, "url_prefix"); ok {
			r.prefix = joinPrefix(joinPrefix(outer, p), r.prefix)
		} else if p, ok := w.pyKwargString(args, "prefix"); ok {
			r.prefix = joinPrefix(joinPrefix(outer, p), r.prefix)
		} else if outer != "" {
			r.prefix = joinPrefix(outer, r.prefix)
		}
		r.bound = true
	}

	for _, r := range routers {
		w.fws[r.fw] = true
	}

	warned := map[NonGoFramework]bool{}
	prefixOf := func(name string) string {
		r := routers[name]
		if r == nil {
			return ""
		}
		if !r.bound && !warned[r.fw] {
			warned[r.fw] = true
			w.caveat(0, r.fw, CaveatCallerPrefixNotVisible,
				name+" is never registered in this file, so any prefix its caller "+
					"applies is invisible")
		}
		return r.prefix
	}

	// --- decorators ---
	for i := 0; i < len(ts); i++ {
		if !ts.isPunct(i, "@") {
			continue
		}
		if !(ts.at(i+1).kind == tokIdent && ts.isPunct(i+2, ".") &&
			ts.at(i+3).kind == tokIdent && ts.isPunct(i+4, "(")) {
			continue
		}
		recv, verb := ts.at(i+1).text, ts.at(i+3).text
		closeIdx, ok := ts.matchClose(i + 4)
		if !ok {
			continue
		}
		args := ts.splitArgs(i+4, closeIdx)
		r, known := routers[recv]
		if !known {
			if verb == "route" || isPyVerb(verb) {
				if len(args) > 0 {
					if p, ok := ts.soleString(args[0]); ok && strings.HasPrefix(p, "/") {
						w.caveat(ts.at(i).line, NonGoFrameworkUnset, CaveatRouterNotResolved,
							"@"+recv+"."+verb)
					}
				}
			}
			continue
		}
		w.pythonDecorator(r, prefixOf(recv), verb, args, ts.at(i).line)
		i = closeIdx
	}

	// --- flask add_url_rule ---
	for i := 0; i < len(ts); i++ {
		if !(ts.at(i).kind == tokIdent && ts.isPunct(i+1, ".") &&
			ts.isIdent(i+2, "add_url_rule") && ts.isPunct(i+3, "(")) {
			continue
		}
		r, known := routers[ts.at(i).text]
		if !known || r.fw != NonGoFrameworkFlask {
			continue
		}
		closeIdx, ok := ts.matchClose(i + 3)
		if !ok {
			continue
		}
		args := ts.splitArgs(i+3, closeIdx)
		if len(args) == 0 {
			continue
		}
		p, ok := ts.soleString(args[0])
		if !ok {
			w.caveat(ts.at(i).line, NonGoFrameworkFlask, CaveatPathNotStaticallyResolvable,
				ts.at(i).text+".add_url_rule")
			continue
		}
		full := joinPrefix(prefixOf(ts.at(i).text), p)
		methods := w.pyMethodsKwarg(args)
		if len(methods) == 0 {
			w.emit(NonGoFrameworkFlask, "GET", full, ts.at(i).line)
			w.caveat(ts.at(i).line, NonGoFrameworkFlask, CaveatMethodNotEnumerated,
				"add_url_rule "+p+" names no methods")
		} else {
			for _, m := range methods {
				w.emit(NonGoFrameworkFlask, m, full, ts.at(i).line)
			}
		}
		i = closeIdx
	}

	w.django(sym)
}

func frameworkForPyVerb(v string) NonGoFramework {
	if v == "register_blueprint" {
		return NonGoFrameworkFlask
	}
	return NonGoFrameworkFastAPI
}

func isPyVerb(v string) bool {
	_, ok := httpMethodForVerb(v)
	return ok
}

func (w *fileWalk) pythonDecorator(r *pyRouter, prefix, verb string, args []span, line int) {
	ts := w.ts
	if len(args) == 0 {
		return
	}
	p, ok := ts.soleString(args[0])
	if !ok {
		if verb == "route" || verb == "api_route" || isPyVerb(verb) {
			w.caveat(line, r.fw, CaveatPathNotStaticallyResolvable, "@"+verb)
		}
		return
	}
	full := joinPrefix(prefix, p)
	switch {
	case r.fw == NonGoFrameworkFlask && verb == "route":
		methods := w.pyMethodsKwarg(args)
		if len(methods) == 0 {
			methods = []string{"GET"}
		}
		for _, m := range methods {
			w.emit(NonGoFrameworkFlask, m, full, line)
		}
	case r.fw == NonGoFrameworkFastAPI && verb == "api_route":
		methods := w.pyMethodsKwarg(args)
		if len(methods) == 0 {
			w.emit(NonGoFrameworkFastAPI, "GET", full, line)
			w.caveat(line, NonGoFrameworkFastAPI, CaveatMethodNotEnumerated,
				"api_route "+p+" names no methods")
			return
		}
		for _, m := range methods {
			w.emit(NonGoFrameworkFastAPI, m, full, line)
		}
	case r.fw == NonGoFrameworkFastAPI:
		if m, ok := httpMethodForVerb(verb); ok {
			w.emit(NonGoFrameworkFastAPI, m, full, line)
		}
	}
}

// pyKwargString reads a `name="value"` keyword argument out of an argument
// list, requiring the value to be exactly one static string.
func (w *fileWalk) pyKwargString(args []span, name string) (string, bool) {
	ts := w.ts
	for _, a := range args {
		a = ts.trimSpan(a)
		if a.hi-a.lo < 3 {
			continue
		}
		if ts.at(a.lo).kind != tokIdent || ts.at(a.lo).text != name || !ts.isPunct(a.lo+1, "=") {
			continue
		}
		return ts.soleString(span{a.lo + 2, a.hi})
	}
	return "", false
}

// pyMethodsKwarg reads `methods=["GET", "POST"]`.
func (w *fileWalk) pyMethodsKwarg(args []span) []string {
	ts := w.ts
	for _, a := range args {
		a = ts.trimSpan(a)
		if a.hi-a.lo < 3 {
			continue
		}
		if ts.at(a.lo).kind != tokIdent || ts.at(a.lo).text != "methods" ||
			!ts.isPunct(a.lo+1, "=") {
			continue
		}
		var out []string
		for i := a.lo + 2; i < a.hi; i++ {
			if ts[i].kind == tokString && ts[i].lit {
				out = append(out, strings.ToUpper(strings.TrimSpace(ts[i].str)))
			}
		}
		return out
	}
	return nil
}

// bindPythonFrom reads `from <module> import a, b as c` and records only the
// symbols that came from a framework module.
func (w *fileWalk) bindPythonFrom(i int, sym map[string]string) {
	ts := w.ts
	j := i + 1
	var mod strings.Builder
	for j < len(ts) && (ts[j].kind == tokIdent || ts.isPunct(j, ".")) && !ts.isIdent(j, "import") {
		if ts[j].kind == tokIdent {
			mod.WriteString(ts[j].text)
		} else {
			mod.WriteByte('.')
		}
		j++
	}
	if !ts.isIdent(j, "import") {
		return
	}
	module := mod.String()
	var want map[string]string
	switch {
	case module == "flask" || strings.HasPrefix(module, "flask."):
		want = map[string]string{"Flask": "Flask", "Blueprint": "Blueprint"}
	case module == "fastapi" || strings.HasPrefix(module, "fastapi."):
		want = map[string]string{"FastAPI": "FastAPI", "APIRouter": "APIRouter"}
	case module == "django.urls" || module == "django.conf.urls":
		want = map[string]string{"path": "path", "re_path": "re_path",
			"url": "re_path", "include": "include"}
	default:
		return
	}
	j++
	if ts.isPunct(j, "(") {
		j++
	}
	for j < len(ts) && ts[j].kind != tokNewline {
		if ts[j].kind != tokIdent {
			j++
			continue
		}
		imported := ts[j].text
		local := imported
		if ts.isIdent(j+1, "as") && ts.at(j+2).kind == tokIdent {
			local = ts.at(j + 2).text
			j += 2
		}
		if canon, ok := want[imported]; ok {
			sym[local] = canon
		}
		j++
	}
}

func (w *fileWalk) django(sym map[string]string) {
	ts := w.ts
	hasDjango := false
	for _, canon := range sym {
		if canon == "path" || canon == "re_path" || canon == "include" {
			hasDjango = true
		}
	}
	if !hasDjango {
		return
	}
	w.fws[NonGoFrameworkDjango] = true
	// A URLconf's paths are relative to wherever the module is include()d and
	// this file cannot see that call site. Reported ONCE per file: it
	// qualifies routes already counted rather than naming an extra endpoint,
	// which is why CaveatCallerPrefixNotVisible does not raise the floor.
	w.caveat(0, NonGoFrameworkDjango, CaveatCallerPrefixNotVisible,
		"django URLconf paths are relative to the point where this module is included")

	for i := 0; i < len(ts); i++ {
		if ts.at(i).kind != tokIdent || !ts.isPunct(i+1, "(") {
			continue
		}
		canon, ok := sym[ts.at(i).text]
		if !ok || (canon != "path" && canon != "re_path") {
			continue
		}
		closeIdx, ok := ts.matchClose(i + 1)
		if !ok {
			continue
		}
		args := ts.splitArgs(i+1, closeIdx)
		line := ts.at(i).line
		if canon == "re_path" {
			w.caveat(line, NonGoFrameworkDjango, CaveatPathNotStaticallyResolvable,
				"re_path takes a regular expression, not a literal path")
			i = closeIdx
			continue
		}
		if len(args) == 0 {
			i = closeIdx
			continue
		}
		p, ok := ts.soleString(args[0])
		if !ok {
			w.caveat(line, NonGoFrameworkDjango, CaveatPathNotStaticallyResolvable, "path()")
			i = closeIdx
			continue
		}
		if len(args) >= 2 {
			if id, ok := ts.at(args[1].lo).textIfIdent(); ok {
				if c, ok2 := sym[id]; ok2 && c == "include" {
					w.caveat(line, NonGoFrameworkDjango, CaveatMountNotFollowed,
						"include() at "+p)
					i = closeIdx
					continue
				}
			}
		}
		w.emit(NonGoFrameworkDjango, "GET", p, line)
		w.caveat(line, NonGoFrameworkDjango, CaveatMethodNotEnumerated,
			"a django URLconf names no method for "+p)
		i = closeIdx
	}
}

func (t tok) textIfIdent() (string, bool) {
	if t.kind != tokIdent {
		return "", false
	}
	return t.text, true
}

// ---------------------------------------------------------------------------
// Spring
// ---------------------------------------------------------------------------

func (w *fileWalk) spring() {
	ts := w.ts
	spring := false
	for i := 0; i < len(ts); i++ {
		if !ts.isIdent(i, "import") {
			continue
		}
		var b strings.Builder
		for j := i + 1; j < len(ts) && (ts[j].kind == tokIdent || ts.isPunct(j, ".") ||
			ts.isPunct(j, "*")); j++ {
			if ts[j].kind == tokIdent {
				b.WriteString(ts[j].text)
			} else {
				b.WriteString(ts[j].text)
			}
		}
		p := b.String()
		if p == "org.springframework" || strings.HasPrefix(p, "org.springframework.") {
			spring = true
			break
		}
	}
	if !spring {
		w.caveat(0, NonGoFrameworkUnset, CaveatNoFrameworkRecognised,
			"no org.springframework import was found in this file")
		return
	}
	w.fws[NonGoFrameworkSpring] = true

	depth := 0
	pending := ""
	prefixAt := map[int]string{}
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		if t.kind == tokPunct && t.text == "{" {
			depth++
			if pending != "" {
				prefixAt[depth] = pending
				pending = ""
			}
			continue
		}
		if t.kind == tokPunct && t.text == "}" {
			delete(prefixAt, depth)
			if depth > 0 {
				depth--
			}
			continue
		}
		if !(t.kind == tokPunct && t.text == "@" && ts.at(i+1).kind == tokIdent) {
			continue
		}
		ann := ts.at(i + 1).text
		end := i + 1
		var args []span
		if ts.isPunct(i+2, "(") {
			c, ok := ts.matchClose(i + 2)
			if !ok {
				continue
			}
			args = ts.splitArgs(i+2, c)
			end = c
		}
		method, isMapping := springAnnotationMethod(ann)
		if !isMapping {
			i = end
			continue
		}
		paths, resolvable := w.springPaths(args)
		classLevel := springAnnotatesAClass(ts, end+1)
		if classLevel {
			if !resolvable || len(paths) == 0 {
				w.caveat(t.line, NonGoFrameworkSpring, CaveatPathNotStaticallyResolvable,
					"class-level @"+ann)
			} else {
				pending = paths[0]
			}
			i = end
			continue
		}
		if !resolvable {
			w.caveat(t.line, NonGoFrameworkSpring, CaveatPathNotStaticallyResolvable, "@"+ann)
			i = end
			continue
		}
		prefix := springPrefix(prefixAt)
		methods := []string{method}
		if ann == "RequestMapping" {
			methods = w.springMethodsArg(args)
			if len(methods) == 0 {
				methods = []string{"GET"}
				w.caveat(t.line, NonGoFrameworkSpring, CaveatMethodNotEnumerated,
					"@RequestMapping names no method")
			}
		}
		if len(paths) == 0 {
			paths = []string{""}
		}
		for _, p := range paths {
			for _, m := range methods {
				w.emit(NonGoFrameworkSpring, m, routeJoin(prefix, p), t.line)
			}
		}
		i = end
	}
}

func springPrefix(prefixAt map[int]string) string {
	if len(prefixAt) == 0 {
		return ""
	}
	depths := make([]int, 0, len(prefixAt))
	for d := range prefixAt {
		depths = append(depths, d)
	}
	sort.Ints(depths)
	out := ""
	for _, d := range depths {
		out = joinPrefix(out, prefixAt[d])
	}
	return out
}

func springAnnotationMethod(ann string) (string, bool) {
	switch ann {
	case "GetMapping":
		return "GET", true
	case "PostMapping":
		return "POST", true
	case "PutMapping":
		return "PUT", true
	case "PatchMapping":
		return "PATCH", true
	case "DeleteMapping":
		return "DELETE", true
	case "RequestMapping":
		return "GET", true
	}
	return "", false
}

// springPaths reads the path(s) out of a mapping annotation's arguments.
//
// The second return value is false when the annotation names a path this file
// cannot resolve -- a constant, a "${property}" placeholder, a concatenation.
// An annotation with NO path argument at all returns (nil, true): that is
// legal Spring and means "the class-level prefix, exactly".
func (w *fileWalk) springPaths(args []span) ([]string, bool) {
	ts := w.ts
	take := func(s span) ([]string, bool) {
		if p, ok := ts.soleString(s); ok {
			if strings.Contains(p, "${") {
				return nil, false
			}
			return []string{p}, true
		}
		s = ts.trimSpan(s)
		if ts.isPunct(s.lo, "{") {
			c, ok := ts.matchClose(s.lo)
			if !ok || c+1 != s.hi {
				return nil, false
			}
			var out []string
			for _, e := range ts.splitArgs(s.lo, c) {
				p, ok := ts.soleString(e)
				if !ok || strings.Contains(p, "${") {
					return nil, false
				}
				out = append(out, p)
			}
			return out, true
		}
		return nil, false
	}
	sawNamed := false
	for _, a := range args {
		a = ts.trimSpan(a)
		if a.hi <= a.lo {
			continue
		}
		if ts.at(a.lo).kind == tokIdent && ts.isPunct(a.lo+1, "=") {
			name := ts.at(a.lo).text
			if name == "value" || name == "path" {
				sawNamed = true
				return take(span{a.lo + 2, a.hi})
			}
			continue
		}
		return take(a)
	}
	if sawNamed {
		return nil, false
	}
	return nil, true
}

// springMethodsArg reads method=RequestMethod.GET or
// method={RequestMethod.GET, RequestMethod.POST}.
func (w *fileWalk) springMethodsArg(args []span) []string {
	ts := w.ts
	for _, a := range args {
		a = ts.trimSpan(a)
		if a.hi-a.lo < 3 {
			continue
		}
		if ts.at(a.lo).kind != tokIdent || ts.at(a.lo).text != "method" ||
			!ts.isPunct(a.lo+1, "=") {
			continue
		}
		var out []string
		for i := a.lo + 2; i < a.hi; i++ {
			if ts[i].kind != tokIdent || !ts.isPunct(i-1, ".") {
				continue
			}
			if !ts.isIdent(i-2, "RequestMethod") {
				continue
			}
			out = append(out, strings.ToUpper(ts[i].text))
		}
		return out
	}
	return nil
}

// springAnnotatesAClass reports whether the annotation ending just before j
// decorates a class rather than a method, by skipping the modifiers and other
// annotations between them.
func springAnnotatesAClass(ts tokens, j int) bool {
	for guard := 0; guard < 64 && j < len(ts); guard++ {
		t := ts.at(j)
		if t.kind == tokPunct && t.text == "@" && ts.at(j+1).kind == tokIdent {
			j += 2
			if ts.isPunct(j, "(") {
				c, ok := ts.matchClose(j)
				if !ok {
					return false
				}
				j = c + 1
			}
			continue
		}
		if t.kind != tokIdent {
			return false
		}
		switch t.text {
		case "public", "private", "protected", "static", "final", "abstract",
			"sealed", "non", "strictfp", "default", "synchronized", "native":
			j++
			continue
		case "class", "interface", "record", "enum":
			return true
		}
		return false
	}
	return false
}

// ---------------------------------------------------------------------------
// Rails
// ---------------------------------------------------------------------------

type railsScope struct {
	// prefix applies to plain verb calls inside this scope.
	prefix string
	// kind is "plain", "resources" or "resource".
	kind string
	// memberPrefix and nestedPrefix are the resources-block scopes.
	memberPrefix string
	nestedPrefix string
}

func (w *fileWalk) rails() {
	ts := w.ts
	isRoutes := false
	for i := 0; i+2 < len(ts); i++ {
		if ts.isIdent(i, "routes") && ts.isPunct(i+1, ".") && ts.isIdent(i+2, "draw") {
			isRoutes = true
			break
		}
	}
	if !isRoutes {
		w.caveat(0, NonGoFrameworkUnset, CaveatNoFrameworkRecognised,
			"no Rails.application.routes.draw block was found in this file")
		return
	}
	w.fws[NonGoFrameworkRails] = true

	stack := []railsScope{{prefix: "", kind: "plain"}}
	pending := (*railsScope)(nil)
	tooDeep := false

	cur := func() railsScope { return stack[len(stack)-1] }
	push := func(s railsScope) {
		if len(stack) >= maxNonGoNestingDepth {
			tooDeep = true
			return
		}
		stack = append(stack, s)
	}

	for i := 0; i < len(ts); i++ {
		t := ts.at(i)
		switch {
		case t.kind == tokIdent && t.text == "do":
			if pending != nil {
				push(*pending)
				pending = nil
			} else {
				push(railsScope{prefix: cur().prefix, kind: "plain"})
			}
			// Skip block parameters: do |name|
			if ts.isPunct(i+1, "|") {
				for j := i + 2; j < len(ts); j++ {
					if ts.isPunct(j, "|") {
						i = j
						break
					}
				}
			}
			continue
		case t.kind == tokIdent && t.text == "end":
			pending = nil
			if len(stack) <= 1 {
				w.discard = true
				w.discardWhy = fmt.Sprintf("an `end` at line %d closes a block that was "+
					"never opened, so every scope prefix computed from here on would be "+
					"wrong", t.line)
				return
			}
			stack = stack[:len(stack)-1]
			continue
		case t.kind != tokIdent:
			continue
		}

		args, next := w.railsArgs(i + 1)
		sc := cur()
		switch t.text {
		case "namespace":
			name, ok := w.railsFirstName(args)
			if !ok {
				w.caveat(t.line, NonGoFrameworkRails, CaveatPathNotStaticallyResolvable,
					"namespace with a non-literal name")
				i = next - 1
				continue
			}
			s := railsScope{prefix: joinPrefix(sc.prefix, name), kind: "plain"}
			pending = &s
		case "scope":
			name, ok := w.railsFirstName(args)
			if !ok {
				if p, ok2 := w.railsKwargString(args, "path"); ok2 {
					name, ok = p, true
				}
			}
			p := sc.prefix
			if ok {
				p = joinPrefix(sc.prefix, name)
			}
			s := railsScope{prefix: p, kind: "plain"}
			pending = &s
		case "constraints":
			s := railsScope{prefix: sc.prefix, kind: "plain"}
			pending = &s
		case "member":
			if sc.kind != "resources" && sc.kind != "resource" {
				break
			}
			s := railsScope{prefix: sc.memberPrefix, kind: "plain"}
			pending = &s
		case "collection":
			if sc.kind != "resources" && sc.kind != "resource" {
				break
			}
			s := railsScope{prefix: sc.prefix, kind: "plain"}
			pending = &s
		case "resources", "resource":
			base, ok := w.railsFirstName(args)
			if !ok {
				w.caveat(t.line, NonGoFrameworkRails, CaveatPathNotStaticallyResolvable,
					t.text+" with a non-literal name")
				i = next - 1
				continue
			}
			parent := sc.prefix
			if sc.kind == "resources" || sc.kind == "resource" {
				parent = sc.nestedPrefix
			}
			s := w.railsResource(t.text == "resources", parent, base, args, t.line)
			pending = &s
		case "root":
			if p, ok := w.railsKwargString(args, "to"); ok && p != "" {
				w.emit(NonGoFrameworkRails, "GET", routeJoin(sc.prefix, ""), t.line)
			} else if _, ok := w.railsFirstName(args); ok {
				w.emit(NonGoFrameworkRails, "GET", routeJoin(sc.prefix, ""), t.line)
			}
		case "mount":
			w.caveat(t.line, NonGoFrameworkRails, CaveatMountNotFollowed,
				"a mounted engine's own routes are not read")
		case "get", "post", "put", "patch", "delete", "match":
			w.railsVerb(t.text, sc, args, t.line)
		}
		// A scope directive only opens a block when a `do` follows it on the
		// same statement. `resources :users, only: [:index]` opens nothing,
		// and leaving its scope pending would attach it to whatever `do`
		// came next -- silently reprefixing an unrelated block.
		if pending != nil && !ts.isIdent(next, "do") {
			pending = nil
		}
		i = next - 1
	}

	if tooDeep {
		w.caveat(0, NonGoFrameworkRails, CaveatNestingTooDeep,
			fmt.Sprintf("routes nested deeper than the coded bound of %d",
				maxNonGoNestingDepth))
	}
	if len(stack) != 1 {
		w.discard = true
		w.discardWhy = fmt.Sprintf("%d block(s) were opened and never closed, so every "+
			"scope prefix in this file is unreliable", len(stack)-1)
	}
}

// railsArgs collects the tokens of a Ruby method call written without
// parentheses: everything up to the end of the line, or to a `do`.
func (w *fileWalk) railsArgs(from int) ([]span, int) {
	ts := w.ts
	if ts.isPunct(from, "(") {
		c, ok := ts.matchClose(from)
		if ok {
			return ts.splitArgs(from, c), c + 1
		}
	}
	j := from
	for j < len(ts) {
		t := ts[j]
		if t.kind == tokNewline {
			break
		}
		if t.kind == tokIdent && t.text == "do" {
			break
		}
		if t.kind == tokPunct {
			switch t.text {
			case "(", "[", "{":
				c, ok := ts.matchClose(j)
				if !ok {
					j++
					continue
				}
				j = c + 1
				continue
			}
		}
		j++
	}
	var out []span
	depth := 0
	lo := from
	for k := from; k < j; k++ {
		t := ts[k]
		if t.kind != tokPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ",":
			if depth == 0 {
				out = append(out, ts.trimSpan(span{lo, k}))
				lo = k + 1
			}
		}
	}
	if lo < j {
		out = append(out, ts.trimSpan(span{lo, j}))
	}
	return out, j
}

// railsFirstName reads the first positional argument as a path or a symbol.
func (w *fileWalk) railsFirstName(args []span) (string, bool) {
	ts := w.ts
	for _, a := range args {
		a = ts.trimSpan(a)
		if a.hi-a.lo != 1 {
			// A "name:" keyword argument is two tokens; skip it and keep
			// looking for a positional one.
			if a.hi-a.lo >= 2 && ts.at(a.lo).kind == tokIdent && ts.isPunct(a.lo+1, ":") {
				continue
			}
			return "", false
		}
		t := ts[a.lo]
		switch {
		case t.kind == tokSymbol:
			return t.str, true
		case t.kind == tokString && t.lit:
			return t.str, true
		default:
			return "", false
		}
	}
	return "", false
}

// railsKwargString reads `name: "value"` or `name: :value`.
func (w *fileWalk) railsKwargString(args []span, name string) (string, bool) {
	ts := w.ts
	for _, a := range args {
		a = ts.trimSpan(a)
		if a.hi-a.lo < 3 {
			continue
		}
		if !(ts.at(a.lo).kind == tokIdent && ts.at(a.lo).text == name && ts.isPunct(a.lo+1, ":")) {
			continue
		}
		v := ts.trimSpan(span{a.lo + 2, a.hi})
		if v.hi-v.lo != 1 {
			return "", false
		}
		t := ts[v.lo]
		if (t.kind == tokString && t.lit) || t.kind == tokSymbol {
			return t.str, true
		}
		return "", false
	}
	return "", false
}

// railsSymbolList reads `only: [:index, :show]` or `only: :index`.
func (w *fileWalk) railsSymbolList(args []span, name string) ([]string, bool) {
	ts := w.ts
	for _, a := range args {
		a = ts.trimSpan(a)
		if a.hi-a.lo < 3 {
			continue
		}
		if !(ts.at(a.lo).kind == tokIdent && ts.at(a.lo).text == name && ts.isPunct(a.lo+1, ":")) {
			continue
		}
		var out []string
		for i := a.lo + 2; i < a.hi; i++ {
			if ts[i].kind == tokSymbol {
				out = append(out, ts[i].str)
			}
		}
		return out, true
	}
	return nil, false
}

func (w *fileWalk) railsVerb(verb string, sc railsScope, args []span, line int) {
	if sc.kind == "resources" || sc.kind == "resource" {
		// Rails' implicit nesting rule for a bare verb inside a resources
		// block was not verifiable on this host, and a guessed prefix here
		// would put a candidate at a path the target does not serve. It is
		// REPORTED instead.
		w.caveat(line, NonGoFrameworkRails, CaveatMountNotFollowed,
			"a `"+verb+"` directly inside a resources block is not member/collection "+
				"and its implicit prefix was not resolved")
		return
	}
	name, ok := w.railsFirstName(args)
	if !ok {
		w.caveat(line, NonGoFrameworkRails, CaveatPathNotStaticallyResolvable,
			verb+" with a non-literal path")
		return
	}
	full := joinPrefix(sc.prefix, name)
	if verb != "match" {
		w.emit(NonGoFrameworkRails, strings.ToUpper(verb), full, line)
		return
	}
	via, present := w.railsSymbolList(args, "via")
	if !present || len(via) == 0 {
		w.emit(NonGoFrameworkRails, "GET", full, line)
		w.caveat(line, NonGoFrameworkRails, CaveatMethodNotEnumerated,
			"match "+name+" names no usable via: list")
		return
	}
	for _, v := range via {
		if v == "all" || v == "any" {
			w.emit(NonGoFrameworkRails, "GET", full, line)
			w.caveat(line, NonGoFrameworkRails, CaveatMethodNotEnumerated,
				"match "+name+" via: :all")
			return
		}
	}
	for _, v := range via {
		if m, ok := httpMethodForVerb(strings.ToLower(v)); ok {
			w.emit(NonGoFrameworkRails, m, full, line)
		}
	}
}

// railsAction is one route of the RESTful default set.
type railsAction struct {
	name     string
	method   string
	suffix   string
	onMember bool
}

// railsPluralActions is the seven-route default of `resources`, and
// railsSingularActions the six-route default of `resource`.
//
// They are tables rather than code so a reader can check them against the
// Rails routing guide line by line.
func railsPluralActions() []railsAction {
	return []railsAction{
		{"index", "GET", "", false},
		{"create", "POST", "", false},
		{"new", "GET", "/new", false},
		{"edit", "GET", "/edit", true},
		{"show", "GET", "", true},
		{"update", "PATCH", "", true},
		{"update", "PUT", "", true},
		{"destroy", "DELETE", "", true},
	}
}

func railsSingularActions() []railsAction {
	return []railsAction{
		{"new", "GET", "/new", false},
		{"create", "POST", "", false},
		{"show", "GET", "", false},
		{"edit", "GET", "/edit", false},
		{"update", "PATCH", "", false},
		{"update", "PUT", "", false},
		{"destroy", "DELETE", "", false},
	}
}

func (w *fileWalk) railsResource(plural bool, parent, base string, args []span, line int) railsScope {
	collection := joinPrefix(parent, base)
	member := collection
	if plural {
		member = joinPrefix(collection, "/:id")
	}
	sc := railsScope{
		prefix:       collection,
		kind:         "resource",
		memberPrefix: member,
		nestedPrefix: member,
	}
	if plural {
		sc.kind = "resources"
		sc.nestedPrefix = joinPrefix(collection, "/:"+railsSingularize(base)+"_id")
	}

	actions := railsSingularActions()
	if plural {
		actions = railsPluralActions()
	}
	if only, ok := w.railsSymbolList(args, "only"); ok {
		actions = filterRailsActions(actions, only, true)
	}
	if except, ok := w.railsSymbolList(args, "except"); ok {
		actions = filterRailsActions(actions, except, false)
	}
	if len(actions) > maxRailsResourceRoutes {
		actions = actions[:maxRailsResourceRoutes]
	}
	for _, a := range actions {
		at := collection
		if a.onMember {
			at = member
		}
		w.emit(NonGoFrameworkRails, a.method, routeJoin(at, a.suffix), line)
	}
	return sc
}

func filterRailsActions(in []railsAction, names []string, keep bool) []railsAction {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	var out []railsAction
	for _, a := range in {
		if set[a.name] == keep {
			out = append(out, a)
		}
	}
	return out
}

// railsSingularize removes a trailing "s" and nothing else.
//
// It is named in SupportMatrix's BlindTo list because it is wrong for every
// irregular plural: "/people/{people_id}" where Rails writes "{person_id}".
// The PATH TEMPLATE is right -- one placeholder segment in the right place --
// and only the parameter's NAME differs, which nothing downstream matches on.
func railsSingularize(s string) string {
	if strings.HasSuffix(s, "ies") && len(s) > 3 {
		return s[:len(s)-3] + "y"
	}
	if strings.HasSuffix(s, "s") && len(s) > 1 {
		return s[:len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// JavaScript import binding
// ---------------------------------------------------------------------------

func (w *fileWalk) bindJSRequire(i int, mods, routerCtors map[string]bool) {
	ts := w.ts
	if !ts.isPunct(i-1, "=") {
		return
	}
	if ts.at(i-2).kind == tokIdent {
		mods[ts.at(i-2).text] = true
		return
	}
	if !ts.isPunct(i-2, "}") {
		return
	}
	depth := 0
	for j := i - 2; j >= 0; j-- {
		if ts[j].kind != tokPunct {
			continue
		}
		switch ts[j].text {
		case "}":
			depth++
		case "{":
			depth--
			if depth == 0 {
				w.bindJSNamed(j, i-2, routerCtors)
				return
			}
		}
	}
}

func (w *fileWalk) bindJSImport(i int, mods, routerCtors map[string]bool) {
	ts := w.ts
	fromIdx := -1
	for j := i + 1; j < len(ts) && j < i+256; j++ {
		if ts.isIdent(j, "from") {
			fromIdx = j
			break
		}
		if ts.at(j).kind == tokString {
			// `import "express"` -- a side-effect import binds nothing.
			return
		}
	}
	if fromIdx < 0 {
		return
	}
	if s, ok := ts.soleString(span{fromIdx + 1, fromIdx + 2}); !ok || s != "express" {
		return
	}
	for j := i + 1; j < fromIdx; j++ {
		if ts.isPunct(j, "{") {
			c, ok := ts.matchClose(j)
			if !ok {
				return
			}
			w.bindJSNamed(j, c, routerCtors)
			j = c
			continue
		}
		if ts.at(j).kind == tokIdent {
			mods[ts.at(j).text] = true
		}
	}
}

// bindJSNamed reads a `{ Router }` or `{ Router: R }` destructuring clause and
// records only the name that actually refers to express's Router.
func (w *fileWalk) bindJSNamed(open, closeAt int, routerCtors map[string]bool) {
	ts := w.ts
	for _, a := range ts.splitArgs(open, closeAt) {
		a = ts.trimSpan(a)
		if a.hi <= a.lo {
			continue
		}
		if ts.at(a.lo).kind != tokIdent || ts.at(a.lo).text != "Router" {
			continue
		}
		local := "Router"
		if a.hi-a.lo >= 3 && (ts.isPunct(a.lo+1, ":") || ts.isIdent(a.lo+1, "as")) &&
			ts.at(a.lo+2).kind == tokIdent {
			local = ts.at(a.lo + 2).text
		}
		routerCtors[local] = true
	}
}
