// Tests for D.21, Tier 2 of the attack-surface inventory: static route
// extraction from Express, Flask, FastAPI, Django, Spring and Rails.
//
// ===========================================================================
// WHAT THIS SUITE IS FOR
// ===========================================================================
//
// Four claims are load-bearing for D.21, and each is measured here rather than
// asserted in a comment.
//
//  1. SIX FRAMEWORKS PRODUCE THEIR KNOWN ROUTE TABLES. Every fixture in
//     nonGoFixtures is HAND-WRITTEN source and every expected table was
//     written by reading that source, never by running the extractor and
//     pasting its output. A table generated from the code under test proves
//     only that the code is deterministic.
//
//  2. EVERY FIXTURE CARRIES AN INTENTIONALLY-INVISIBLE ROUTE AND SAYS SO.
//     plan/50-dast.md D.21's Validation clause. Each fixture contains a
//     computed path, a computed method, an unfollowable mount or a
//     method-agnostic registration, and the test asserts the matching
//     CoverageCaveat is present rather than that the route silently vanished.
//
//  3. "NOT SUPPORTED" AND "SCANNED, NOTHING FOUND" ARE DIFFERENT VALUES.
//     TestScanOutcomesAreDistinguishable walks all four of the outcomes that
//     can accompany a zero route count and fails if any two collapse.
//
//  4. AN UNSUPPORTED LANGUAGE DOES NOT QUIETLY IMPROVE endpoint_coverage.
//     TestAnUnsupportedLanguageInflatesCoverageUnlessItIsReported computes the
//     fraction the naive way and shows it RISING when a PHP file is added,
//     then shows AssertDenominatorIsComplete refusing that number.
//
// ===========================================================================
// ON BREAKING THE GUARDS
// ===========================================================================
//
// The house rule is that a guard that has never failed has not been tested.
// Every negative below is paired with a POSITIVE control in the same table or
// the same function, so a matcher that stopped matching anything at all fails
// rather than passes: the receiver-not-guessed test asserts both that
// `redis.get("/looks/like/a/path", cb)` produces no route AND that the
// identical call on a bound router does; the denominator test asserts both
// that PHP fails the assertion AND that the same file set without PHP passes
// it. What each break printed when it was run is in the packet report; a
// comment claiming a test went red is not evidence either.
package inventory

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

func otherSrc(t *testing.T, uri, body string) SourceFile {
	t.Helper()
	f, err := NewSourceFile(GoSourceFileFacts{
		Location: record.ArtifactLocation{URI: uri},
		Content:  record.ArtifactContent{Text: body},
	})
	if err != nil {
		t.Fatalf("NewSourceFile(%q): %v", uri, err)
	}
	return f
}

func otherCfg(t *testing.T) OtherExtractConfig {
	t.Helper()
	return OtherExtractConfig{Target: mustBareTarget(t), Harvest: HarvestRan}
}

func extractOther(t *testing.T, srcs ...SourceFile) OtherExtractResult {
	t.Helper()
	res, err := ExtractNonGoRoutes(context.Background(), otherCfg(t), srcs)
	if err != nil {
		t.Fatalf("ExtractNonGoRoutes: %v", err)
	}
	return res
}

func extractOne(t *testing.T, uri, body string) OtherExtractResult {
	t.Helper()
	return extractOther(t, otherSrc(t, uri, body))
}

func otherRouteTable(res OtherExtractResult) []string {
	var out []string
	for _, r := range res.Routes() {
		out = append(out, string(r.Method())+" "+r.Path())
	}
	sort.Strings(out)
	return out
}

func otherCaveatCount(res OtherExtractResult, reason CaveatReason) int {
	n := 0
	for _, c := range res.Caveats() {
		if c.Reason == reason {
			n++
		}
	}
	return n
}

func otherRefusalCount(res OtherExtractResult, reason RefusalReason) int {
	n := 0
	for _, r := range res.Refusals() {
		if r.Reason == reason {
			n++
		}
	}
	return n
}

func fileOutcome(t *testing.T, res OtherExtractResult, uri string) NonGoFileExtract {
	t.Helper()
	for _, f := range res.Files() {
		if f.URI == redact(uri) {
			return f
		}
	}
	t.Fatalf("no NonGoFileExtract for %q; got %+v", uri, res.Files())
	return NonGoFileExtract{}
}

// ---------------------------------------------------------------------------
// The six framework fixtures
// ---------------------------------------------------------------------------

type otherFixture struct {
	name string
	fw   NonGoFramework
	uri  string
	src  string
	// want is the route table, written out by reading src.
	want []string
	// invisible names the intentionally-invisible constructs in src and the
	// caveat each must produce. plan/50-dast.md D.21's Validation clause.
	invisible map[CaveatReason]string
}

func nonGoFixtures() []otherFixture {
	return []otherFixture{
		{
			name: "express_basic",
			fw:   NonGoFrameworkExpress,
			uri:  "src/routes.js",
			src: `
const express = require('express');
const { Router } = require('express');

const app = express();
const users = Router();
const admin = express.Router();

users.get('/', listUsers);
users.post('/', createUser);
users.get('/:id', showUser);
users.delete('/:id', destroyUser);
users.route('/:id/avatar').put(setAvatar).patch(patchAvatar);

admin.all('/audit', audit);

app.use('/api/users', users);
app.use('/admin', admin);
app.get('/healthz', health);

// Express's SETTINGS getter, one argument. Not a route. The key is
// deliberately one word: a key with a space in it is refused by the
// KERNEL's path rule, which would hide whether this file refused it.
app.get('etag');
// Middleware with no path. Names no endpoint.
app.use(bodyParser());

// Invisible: the path is computed.
const BASE = '/v2';
app.get(BASE + '/legacy', legacy);

// Invisible: the method is computed.
app[verbFromConfig]('/dynamic', dyn);

// Invisible: a mount whose child is not a router this file bound.
app.use('/plugins', pluginRouterFromAnotherModule);

// Not a router at all. Must never become an endpoint.
cache.get('user:1');
redis.get('/looks/like/a/path', cb);
`,
			want: []string{
				"DELETE /api/users/{id}",
				"GET /admin/audit",
				"GET /api/users/",
				"GET /api/users/{id}",
				"GET /healthz",
				"PATCH /api/users/{id}/avatar",
				"POST /api/users/",
				"PUT /api/users/{id}/avatar",
			},
			invisible: map[CaveatReason]string{
				CaveatPathNotStaticallyResolvable: "app.get(BASE + '/legacy')",
				CaveatMethodNotEnumerated:         "admin.all and app[verbFromConfig]",
				CaveatMountNotFollowed:            "app.use('/plugins', <not a bound router>)",
				CaveatRouterNotResolved:           "redis.get('/looks/like/a/path', cb)",
			},
		},
		{
			name: "flask_basic",
			fw:   NonGoFrameworkFlask,
			uri:  "app/views.py",
			src: `
from flask import Flask, Blueprint

app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix="/api")
orphan = Blueprint("orphan", __name__, url_prefix="/orphan")

@app.route("/healthz")
def healthz():
    return "ok"

@api.route("/users", methods=["GET", "POST"])
def users():
    return ""

@api.route("/users/<int:user_id>", methods=["GET", "DELETE"])
def user(user_id):
    return ""

@api.route("/files/<path:rest>")
def files(rest):
    return ""

@orphan.route("/thing")
def thing():
    return ""

app.register_blueprint(api)

# Invisible: the rule is built at runtime.
for name in EXTRA:
    app.add_url_rule(build_rule(name), view_func=make_view(name))

# Invisible: the decorated object is not an app or blueprint this file bound.
@legacy_app.route("/legacy")
def legacy():
    return ""
`,
			want: []string{
				"DELETE /api/users/{user_id}",
				"GET /api/files/{rest}",
				"GET /api/users",
				"GET /api/users/{user_id}",
				"GET /healthz",
				"GET /orphan/thing",
				"POST /api/users",
			},
			invisible: map[CaveatReason]string{
				CaveatPathNotStaticallyResolvable: "add_url_rule(build_rule(name))",
				CaveatRouterNotResolved:           "@legacy_app.route",
				CaveatCallerPrefixNotVisible:      "the orphan blueprint is never registered",
			},
		},
		{
			name: "fastapi_basic",
			fw:   NonGoFrameworkFastAPI,
			uri:  "app/api.py",
			src: `
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter(prefix="/v1")
detached = APIRouter(prefix="/detached")

@app.get("/healthz")
async def healthz():
    return {}

@router.get("/items")
async def list_items():
    return []

@router.post("/items")
async def create_item():
    return {}

@router.get("/items/{item_id}")
async def get_item(item_id: int):
    return {}

@router.get("/files/{rest:path}")
async def get_file(rest: str):
    return {}

@router.api_route("/ping", methods=["GET", "HEAD"])
async def ping():
    return {}

@detached.get("/hidden")
async def hidden():
    return {}

app.include_router(router, prefix="/api")

# Invisible to the KERNEL rather than to the lexer: TRACE is not on the
# method allowlist, so this becomes a per-operation refusal.
@app.trace("/trace-me")
async def trace_me():
    return {}

# Invisible: an f-string path.
@app.get(f"/{PREFIX}/dynamic")
async def dynamic():
    return {}
`,
			want: []string{
				"GET /api/v1/files/{rest}",
				"GET /api/v1/items",
				"GET /api/v1/items/{item_id}",
				"GET /api/v1/ping",
				"GET /detached/hidden",
				"GET /healthz",
				"HEAD /api/v1/ping",
				"POST /api/v1/items",
			},
			invisible: map[CaveatReason]string{
				CaveatPathNotStaticallyResolvable: `@app.get(f"/{PREFIX}/dynamic")`,
				CaveatCallerPrefixNotVisible:      "the detached router is never included",
			},
		},
		{
			name: "django_basic",
			fw:   NonGoFrameworkDjango,
			uri:  "project/urls.py",
			src: `
from django.urls import path, re_path, include

urlpatterns = [
    path("healthz/", views.healthz),
    path("users/", views.user_list),
    path("users/<int:pk>/", views.user_detail),
    path("files/<path:rest>", views.file_detail),
    re_path(r"^legacy/(?P<slug>[\w-]+)/$", views.legacy),
    path("blog/", include("blog.urls")),
]
`,
			want: []string{
				"GET /files/{rest}",
				"GET /healthz/",
				"GET /users/",
				"GET /users/{pk}/",
			},
			invisible: map[CaveatReason]string{
				CaveatPathNotStaticallyResolvable: "re_path takes a regex",
				CaveatMountNotFollowed:            `include("blog.urls")`,
				CaveatMethodNotEnumerated:         "a URLconf names no method",
				CaveatCallerPrefixNotVisible:      "the include() point is invisible",
			},
		},
		{
			name: "spring_basic",
			fw:   NonGoFrameworkSpring,
			uri:  "src/main/java/com/example/UserController.java",
			src: `
package com.example;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping
    public List<User> list() { return null; }

    @GetMapping("/{id}")
    public User show(@PathVariable String id) { return null; }

    @PostMapping
    public User create(@RequestBody User u) { return null; }

    @PutMapping({"/{id}", "/{id}/replace"})
    public User replace(@PathVariable String id) { return null; }

    @DeleteMapping("/{id}")
    public void destroy(@PathVariable String id) { }

    @RequestMapping(value = "/search", method = RequestMethod.GET)
    public List<User> search() { return null; }

    // Invisible: @RequestMapping with no method= names no method.
    @RequestMapping("/legacy")
    public String legacy() { return null; }

    // Invisible: the path is a constant this file cannot resolve.
    @GetMapping(Paths.REPORTS)
    public String reports() { return null; }
}
`,
			want: []string{
				"DELETE /api/users/{id}",
				"GET /api/users",
				"GET /api/users/legacy",
				"GET /api/users/search",
				"GET /api/users/{id}",
				"POST /api/users",
				"PUT /api/users/{id}",
				"PUT /api/users/{id}/replace",
			},
			invisible: map[CaveatReason]string{
				CaveatPathNotStaticallyResolvable: "@GetMapping(Paths.REPORTS)",
				CaveatMethodNotEnumerated:         "@RequestMapping with no method=",
			},
		},
		{
			name: "rails_basic",
			fw:   NonGoFrameworkRails,
			uri:  "config/routes.rb",
			src: `
Rails.application.routes.draw do
  root to: "home#index"

  get "/healthz", to: "health#show"

  namespace :api do
    resources :users, only: [:index, :show]

    resources :posts do
      member do
        post "publish"
      end
      collection do
        get "search"
      end
      resources :comments, only: [:index]
    end

    resource :profile, only: [:show, :update]
  end

  scope path: "/v2" do
    match "/legacy", via: [:get, :post]
  end

  # Invisible: a mounted engine's own routes.
  mount Sidekiq::Web => "/sidekiq"

  # Invisible: the path is a constant.
  get ADMIN_PATH, to: "admin#index"
end
`,
			want: []string{
				"DELETE /api/posts/{id}",
				"GET /",
				"GET /api/posts",
				"GET /api/posts/new",
				"GET /api/posts/search",
				"GET /api/posts/{id}",
				"GET /api/posts/{id}/edit",
				"GET /api/posts/{post_id}/comments",
				"GET /api/profile",
				"GET /api/users",
				"GET /api/users/{id}",
				"GET /healthz",
				"GET /v2/legacy",
				"PATCH /api/posts/{id}",
				"PATCH /api/profile",
				"POST /api/posts",
				"POST /api/posts/{id}/publish",
				"POST /v2/legacy",
				"PUT /api/posts/{id}",
				"PUT /api/profile",
			},
			invisible: map[CaveatReason]string{
				CaveatMountNotFollowed:            "mount Sidekiq::Web",
				CaveatPathNotStaticallyResolvable: "get ADMIN_PATH",
			},
		},
	}
}

// TestFrameworkFixturesProduceTheirKnownRouteTables is D.21's stop condition,
// executable: "Five frameworks produce candidate route lists with honest
// coverage caveats on fixtures." Six rows, because Flask and FastAPI are
// separate DSLs read by separate code.
func TestFrameworkFixturesProduceTheirKnownRouteTables(t *testing.T) {
	for _, fx := range nonGoFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			res := extractOne(t, fx.uri, fx.src)
			got := otherRouteTable(res)
			if !reflect.DeepEqual(got, fx.want) {
				t.Fatalf("route table mismatch\n got: %v\nwant: %v", got, fx.want)
			}
			if n := res.FrameworkMix()[fx.fw]; n == 0 {
				t.Fatalf("FrameworkMix has no %s routes: %v", fx.fw, res.FrameworkMix())
			}
			fe := fileOutcome(t, res, fx.uri)
			if fe.Outcome != ScanOutcomeRoutesFound {
				t.Fatalf("file outcome = %q, want %q", fe.Outcome, ScanOutcomeRoutesFound)
			}
			if err := res.AssertNotSilentlyEmpty(); err != nil {
				t.Fatalf("AssertNotSilentlyEmpty: %v", err)
			}
			if err := res.AssertDenominatorIsComplete(); err != nil {
				t.Fatalf("AssertDenominatorIsComplete on a single supported file: %v", err)
			}
		})
	}
}

// TestEveryFixtureReportsItsInvisibleRoutes is plan/50-dast.md D.21's
// Validation clause: "each test must include at least one
// intentionally-invisible route ... and assert the extractor reports a
// non-empty coverage_caveat rather than silently under-reporting."
func TestEveryFixtureReportsItsInvisibleRoutes(t *testing.T) {
	for _, fx := range nonGoFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			if len(fx.invisible) == 0 {
				t.Fatal("the fixture declares no intentionally-invisible construct, so " +
					"this test cannot prove the extractor reports one")
			}
			res := extractOne(t, fx.uri, fx.src)
			if len(res.Caveats()) == 0 {
				t.Fatal("the fixture carries invisible routes and the extractor " +
					"reported NO caveats at all -- a silently under-reported inventory")
			}
			for reason, why := range fx.invisible {
				if otherCaveatCount(res, reason) == 0 {
					t.Fatalf("no %s caveat for %s; caveats were %v",
						reason, why, res.Caveats())
				}
			}
			for _, c := range res.Caveats() {
				if !c.Valid() {
					t.Fatalf("caveat %+v is not Valid(); a caveat with an unrecognised "+
						"reason is dropped by every consumer", c)
				}
			}
		})
	}
}

// TestNoNonGoRouteIsEverConfirmed is D.21's Forbidden-actions clause.
func TestNoNonGoRouteIsEverConfirmed(t *testing.T) {
	for _, fx := range nonGoFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			res := extractOne(t, fx.uri, fx.src)
			if err := res.AssertEveryRouteIsACandidate(); err != nil {
				t.Fatalf("AssertEveryRouteIsACandidate: %v", err)
			}
			for _, r := range res.Routes() {
				if r.Confirmation() != ConfirmationCandidate {
					t.Fatalf("%s is %q", r, r.Confirmation())
				}
				if r.Provenance() != record.InventoryProvenanceStaticExtraction {
					t.Fatalf("%s carries provenance %q", r, r.Provenance())
				}
				if r.Trust() != record.TrustUntrusted {
					t.Fatalf("%s carries trust %q", r, r.Trust())
				}
				if r.Operation() != "" {
					t.Fatalf("%s carries operation %q; Route.Key() includes the "+
						"operation and D.26 deduplicates the union on it", r, r.Operation())
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The support matrix is a claim, so it is checked
// ---------------------------------------------------------------------------

// TestSupportMatrixIsBackedByAFixture enforces "do not claim a framework you
// did not test against a real hand-written fixture".
func TestSupportMatrixIsBackedByAFixture(t *testing.T) {
	byName := map[string]otherFixture{}
	for _, fx := range nonGoFixtures() {
		byName[fx.name] = fx
	}
	for _, e := range SupportMatrix() {
		fx, ok := byName[e.Fixture]
		if !ok {
			t.Fatalf("SupportMatrix claims %s with fixture %q and no such fixture exists",
				e.Framework, e.Fixture)
		}
		if fx.fw != e.Framework {
			t.Fatalf("fixture %q is for %s, not %s", e.Fixture, fx.fw, e.Framework)
		}
		if len(e.Recognises) == 0 || len(e.BlindTo) == 0 {
			t.Fatalf("%s claims support with %d recognised shapes and %d blind spots; "+
				"an extractor with no named blind spots is a claim of completeness",
				e.Framework, len(e.Recognises), len(e.BlindTo))
		}
		res := extractOne(t, fx.uri, fx.src)
		if len(res.Routes()) == 0 {
			t.Fatalf("%s is claimed in SupportMatrix and its fixture produced no routes",
				e.Framework)
		}
		if e.Language != fx.fwLanguage() {
			t.Fatalf("%s is claimed for %s and its fixture is %s",
				e.Framework, e.Language, fx.fwLanguage())
		}
	}
}

func (fx otherFixture) fwLanguage() Language {
	l, _ := classifyURI(fx.uri)
	return l
}

// TestSupportMatrixNamesEveryFramework fails if a framework is added to the
// enum without a row, which is how an untested claim gets in.
func TestSupportMatrixNamesEveryFramework(t *testing.T) {
	named := map[NonGoFramework]bool{}
	for _, e := range SupportMatrix() {
		if named[e.Framework] {
			t.Fatalf("SupportMatrix names %s twice", e.Framework)
		}
		named[e.Framework] = true
	}
	for _, f := range NonGoFrameworkValues() {
		if !named[f] {
			t.Fatalf("%s is in NonGoFrameworkValues and has no SupportMatrix row, so "+
				"nothing states what it reads or what it is blind to", f)
		}
	}
	if s := SupportMatrixString(); !strings.Contains(s, "blind:") {
		t.Fatalf("SupportMatrixString renders no blind spots:\n%s", s)
	}
}

// TestSupportedLanguagesAllHaveAnExtractor keeps SupportedLanguages() honest
// against the dispatch in (*fileWalk).run. A language listed there with no
// case would report "scanned, no framework found" for every file, which is a
// claim about the target made out of a gap in Anvil.
func TestSupportedLanguagesAllHaveAnExtractor(t *testing.T) {
	probes := map[Language]struct{ uri, src string }{
		LanguageJavaScript: {"probe.js", "const x = 1;\n"},
		LanguagePython:     {"probe.py", "x = 1\n"},
		LanguageJava:       {"Probe.java", "class Probe {}\n"},
		LanguageRuby:       {"probe.rb", "x = 1\n"},
	}
	for _, l := range SupportedLanguages() {
		p, ok := probes[l]
		if !ok {
			t.Fatalf("%s is in SupportedLanguages and this test has no probe for it", l)
		}
		if l.Status() != LanguageStatusSupported {
			t.Fatalf("%s.Status() = %q", l, l.Status())
		}
		res := extractOne(t, p.uri, p.src)
		fe := fileOutcome(t, res, p.uri)
		if fe.Language != l {
			t.Fatalf("%s classified as %s", p.uri, fe.Language)
		}
		if !fe.Lexed {
			t.Fatalf("%s did not lex, so the dispatch for %s was never reached", p.uri, l)
		}
		if fe.Outcome != ScanOutcomeScannedNoFrameworkRecognised {
			t.Fatalf("%s outcome = %q, want %q", p.uri, fe.Outcome,
				ScanOutcomeScannedNoFrameworkRecognised)
		}
	}
}

// ---------------------------------------------------------------------------
// The honesty requirement
// ---------------------------------------------------------------------------

// TestScanOutcomesAreDistinguishable is the packet's central claim: a zero
// route count NEVER means one thing.
//
// The four zero-route outcomes are produced side by side in one run and the
// test fails if any two of them collapse onto the same value.
func TestScanOutcomesAreDistinguishable(t *testing.T) {
	const flaskRoutes = `
from flask import Flask
app = Flask(__name__)

@app.route("/only")
def only():
    return ""
`
	const flaskNoRoutes = `
from flask import Flask
app = Flask(__name__)

def helper():
    return 1
`
	const noFramework = `
import os

def helper():
    return os.getcwd()
`
	const unlexable = `
x = "this string never closes
`
	res := extractOther(t,
		otherSrc(t, "a_routes.py", flaskRoutes),
		otherSrc(t, "b_empty.py", flaskNoRoutes),
		otherSrc(t, "c_helper.py", noFramework),
		otherSrc(t, "d_broken.py", unlexable),
		otherSrc(t, "e_legacy.php", "<?php Route::get('/php', 'C@a'); ?>"),
		otherSrc(t, "f_notes.md", "# notes\n"),
		otherSrc(t, "g_router.go", "package main\n"),
	)

	want := map[string]ScanOutcome{
		"a_routes.py":  ScanOutcomeRoutesFound,
		"b_empty.py":   ScanOutcomeScannedNoEndpoints,
		"c_helper.py":  ScanOutcomeScannedNoFrameworkRecognised,
		"d_broken.py":  ScanOutcomeNothingParsed,
		"e_legacy.php": ScanOutcomeLanguageNotSupported,
		"f_notes.md":   ScanOutcomeFileTypeUnrecognised,
		"g_router.go":  ScanOutcomeHandledByGoExtractor,
	}
	seen := map[ScanOutcome]string{}
	for uri, wantOut := range want {
		fe := fileOutcome(t, res, uri)
		if fe.Outcome != wantOut {
			t.Fatalf("%s outcome = %q, want %q", uri, fe.Outcome, wantOut)
		}
		if !fe.Outcome.Valid() {
			t.Fatalf("%s outcome %q is not in ScanOutcomeValues()", uri, fe.Outcome)
		}
		if other, dup := seen[fe.Outcome]; dup {
			t.Fatalf("%s and %s produced the SAME outcome %q; the two cases are "+
				"indistinguishable to any consumer", uri, other, fe.Outcome)
		}
		seen[fe.Outcome] = uri
	}
	if len(seen) != len(want) {
		t.Fatalf("%d distinct outcomes for %d distinct cases", len(seen), len(want))
	}

	// Only one of the four zero-route files describes the TARGET. The other
	// three describe Anvil, and exactly two of them make the denominator
	// incomplete.
	for _, uri := range []string{"b_empty.py", "c_helper.py"} {
		if fileOutcome(t, res, uri).Outcome.MeansAnvilCouldNotLook() {
			t.Fatalf("%s is reported as a limit of Anvil; it is a fact about the "+
				"target's source", uri)
		}
	}
	for _, uri := range []string{"d_broken.py", "e_legacy.php"} {
		if !fileOutcome(t, res, uri).Outcome.MeansAnvilCouldNotLook() {
			t.Fatalf("%s is not reported as a limit of Anvil, so its endpoints "+
				"silently leave the coverage denominator", uri)
		}
	}
}

// TestEveryScanOutcomeIsClassified fails if a value is added to the enum
// without MeansAnvilCouldNotLook being taught about it. The predicate decides
// whether the coverage denominator is honest; a value that falls through its
// default silently answers "Anvil looked fine".
func TestEveryScanOutcomeIsClassified(t *testing.T) {
	want := map[ScanOutcome]bool{
		ScanOutcomeRoutesFound:                  false,
		ScanOutcomeScannedNoEndpoints:           false,
		ScanOutcomeScannedNoFrameworkRecognised: false,
		ScanOutcomeNothingParsed:                true,
		ScanOutcomeLanguageNotSupported:         true,
		ScanOutcomeHandledByGoExtractor:         false,
		ScanOutcomeFileTypeUnrecognised:         false,
	}
	for _, o := range ScanOutcomeValues() {
		w, ok := want[o]
		if !ok {
			t.Fatalf("%q is in ScanOutcomeValues and this test does not classify it; "+
				"decide whether it makes the coverage denominator incomplete", o)
		}
		if o.MeansAnvilCouldNotLook() != w {
			t.Fatalf("%q.MeansAnvilCouldNotLook() = %v, want %v",
				o, o.MeansAnvilCouldNotLook(), w)
		}
	}
	if ScanOutcomeUnset.MeansAnvilCouldNotLook() {
		t.Fatal("the zero ScanOutcome answers the denominator question")
	}
}

// TestAnUnsupportedLanguageInflatesCoverageUnlessItIsReported is the failure
// mode the packet brief names, demonstrated end to end.
//
// The naive coverage fraction is confirmed-probed endpoints over the Tier 2
// denominator floor. Adding a PHP file to the repository ADDS attack surface
// and, because nothing here can read PHP, leaves the floor unchanged -- so the
// fraction is unchanged or better while the tool has got strictly worse
// relative to the target. The only thing that catches it is
// AssertDenominatorIsComplete, and this test shows it flipping.
func TestAnUnsupportedLanguageInflatesCoverageUnlessItIsReported(t *testing.T) {
	const flaskApp = `
from flask import Flask
app = Flask(__name__)

@app.route("/one")
def one():
    return ""

@app.route("/two")
def two():
    return ""
`
	goSet := []SourceFile{otherSrc(t, "app.py", flaskApp)}
	phpSet := append(append([]SourceFile{}, goSet...),
		otherSrc(t, "legacy/index.php", "<?php Route::get('/a', 'X'); Route::post('/b', 'Y');"))

	clean := extractOther(t, goSet...)
	withPHP := extractOther(t, phpSet...)

	if clean.DenominatorFloor() != withPHP.DenominatorFloor() {
		t.Fatalf("the PHP file changed the denominator floor (%d -> %d); this test's "+
			"premise is that it cannot", clean.DenominatorFloor(),
			withPHP.DenominatorFloor())
	}
	// The naive fraction, with a fixed numerator, does not fall. That is the
	// whole hazard: two more real endpoints exist and coverage does not move.
	naive := func(res OtherExtractResult) float64 {
		if res.DenominatorFloor() == 0 {
			return 0
		}
		return 2.0 / float64(res.DenominatorFloor())
	}
	if naive(withPHP) < naive(clean) {
		t.Fatalf("premise broken: naive coverage fell from %v to %v",
			naive(clean), naive(withPHP))
	}

	if err := clean.AssertDenominatorIsComplete(); err != nil {
		t.Fatalf("the supported-only file set failed the completeness assertion: %v", err)
	}
	err := withPHP.AssertDenominatorIsComplete()
	if err == nil {
		t.Fatal("a PHP file was present and AssertDenominatorIsComplete passed; " +
			"endpoint_coverage over this denominator is an overestimate and nothing " +
			"says so")
	}
	if !errors.Is(err, ErrUnsupportedLanguagePresent) {
		t.Fatalf("wrong sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), string(LanguagePHP)) {
		t.Fatalf("the error does not name the language: %v", err)
	}
	if got := withPHP.UnsupportedLanguages(); !reflect.DeepEqual(got, []Language{LanguagePHP}) {
		t.Fatalf("UnsupportedLanguages() = %v", got)
	}
	if withPHP.DenominatorIsComplete() {
		t.Fatal("DenominatorIsComplete() disagrees with AssertDenominatorIsComplete")
	}
	if !clean.DenominatorIsComplete() {
		t.Fatal("the supported-only set is reported as incomplete")
	}
}

// TestAnUnsupportedLanguageDoesNotFakeAFloor is the other half: the honest
// answer to "how many endpoints are in that PHP file" is "unknown", so the
// floor must not quietly assert "one".
func TestAnUnsupportedLanguageDoesNotFakeAFloor(t *testing.T) {
	res := extractOther(t,
		otherSrc(t, "a.php", "<?php $x = 1;"),
		otherSrc(t, "b.php", "<?php $y = 2;"),
		otherSrc(t, "c.cs", "class C {}"),
	)
	if res.DenominatorFloor() != 0 {
		t.Fatalf("DenominatorFloor() = %d for three unreadable files; counting an "+
			"unsupported language as one endpoint is an understatement pretending to "+
			"be a measurement", res.DenominatorFloor())
	}
	if len(res.UnsupportedLanguages()) != 2 {
		t.Fatalf("UnsupportedLanguages() = %v, want php and csharp",
			res.UnsupportedLanguages())
	}
	rep, ok := res.LanguageReport(LanguagePHP)
	if !ok {
		t.Fatal("no LanguageReport for php")
	}
	if rep.FilesOffered != 2 || rep.FilesLexed != 0 || rep.Routes != 0 {
		t.Fatalf("php report = %+v", rep)
	}
	if rep.Status != LanguageStatusNotSupported {
		t.Fatalf("php status = %q", rep.Status)
	}
}

// TestUnrecognisedFileTypesDoNotFireTheDenominatorAlarm is the paired control
// for the one above. A warning that fires on every repository is not a
// warning, so a README must not be reported as hidden attack surface.
func TestUnrecognisedFileTypesDoNotFireTheDenominatorAlarm(t *testing.T) {
	res := extractOther(t,
		otherSrc(t, "README.md", "# hello\n"),
		otherSrc(t, "package-lock.json", "{}"),
		otherSrc(t, "Makefile.txt", "all:\n"),
	)
	if err := res.AssertDenominatorIsComplete(); err != nil {
		t.Fatalf("documentation files fired the denominator alarm: %v", err)
	}
	// ... and the positive control, so a matcher that stopped classifying
	// anything fails here rather than passing.
	withPHP := extractOther(t,
		otherSrc(t, "README.md", "# hello\n"),
		otherSrc(t, "x.php", "<?php"),
	)
	if err := withPHP.AssertDenominatorIsComplete(); err == nil {
		t.Fatal("adding a PHP file did not fire the alarm, so the alarm classifies " +
			"nothing")
	}
}

// TestGoFileOfferedHereIsNotAGap: a .go file routed to the wrong extractor is
// a caller mistake, not a hole in Anvil's language coverage. D.20 reads it.
func TestGoFileOfferedHereIsNotAGap(t *testing.T) {
	res := extractOne(t, "main.go", "package main\nfunc main() {}\n")
	if err := res.AssertDenominatorIsComplete(); err != nil {
		t.Fatalf("a .go file made the denominator incomplete: %v", err)
	}
	fe := fileOutcome(t, res, "main.go")
	if fe.Outcome != ScanOutcomeHandledByGoExtractor || fe.Status != LanguageStatusGoExtractor {
		t.Fatalf("go file classified as %q/%q", fe.Outcome, fe.Status)
	}
	if fe.Lexed {
		t.Fatal("the non-Go lexer ran over a Go file")
	}
}

// ---------------------------------------------------------------------------
// Guessing, and refusing to guess
// ---------------------------------------------------------------------------

// TestRouterReceiverIsNeverGuessed is D.20's rule carried across: guessing is
// how cache.get("user:1") becomes an endpoint.
//
// The negatives are paired with a positive control on a BOUND router in the
// same file, so a matcher that stopped matching registrations at all fails.
func TestRouterReceiverIsNeverGuessed(t *testing.T) {
	const src = `
const express = require('express');
const app = express();

// The positive control: identical shape, bound receiver, must be a route.
app.get('/real', handler);

// Bound receiver, one argument: Express's settings getter, not a route.
// One word, so the kernel's path rule cannot be what refuses it.
app.get('etag');

// Unbound receiver, key-shaped argument: neither a route nor a caveat.
cache.get('user:1');

// Unbound receiver, path-shaped argument: not a route, but REPORTED.
redis.get('/looks/like/a/path', cb);
`
	res := extractOne(t, "src/app.js", src)
	if got, want := otherRouteTable(res), []string{"GET /real"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if n := otherCaveatCount(res, CaveatRouterNotResolved); n != 1 {
		t.Fatalf("%d router-not-resolved caveats, want exactly 1 (for redis.get; "+
			"cache.get('user:1') is not path-shaped and must not produce one): %v",
			n, res.Caveats())
	}
}

// TestExpressSettingsGetterIsNotAnEndpoint pins the one-argument rule on its
// own, because a configuration key in the coverage denominator can never be
// confirmed out of it.
func TestExpressSettingsGetterIsNotAnEndpoint(t *testing.T) {
	// "etag" is a real Express setting AND a legal path segment, so removing
	// the one-argument rule turns it into the endpoint "/etag". An earlier
	// draft used "view engine", whose SPACE the kernel's path rule refuses --
	// which meant this test stayed green with the rule deleted and was proving
	// the kernel's behaviour rather than this file's.
	res := extractOne(t, "s.js", "const e=require('express');const app=e();\n"+
		"app.get('etag');\napp.get('/kept', h);\n")
	if got, want := otherRouteTable(res), []string{"GET /kept"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
}

// TestTraceIsAPerOperationRefusalNotASilentDrop. TRACE is a method FastAPI
// exposes and the kernel's allowlist does not carry. Dropping it here would
// shrink the denominator; refusing it keeps it counted.
func TestTraceIsAPerOperationRefusalNotASilentDrop(t *testing.T) {
	const src = `
from fastapi import FastAPI
app = FastAPI()

@app.trace("/trace-me")
async def trace_me():
    return {}

@app.get("/kept")
async def kept():
    return {}
`
	res := extractOne(t, "api.py", src)
	if got, want := otherRouteTable(res), []string{"GET /kept"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if n := otherRefusalCount(res, RefusalMethodNotAllowlisted); n != 1 {
		t.Fatalf("%d method-not-allowlisted refusals, want 1: %v", n, res.Refusals())
	}
	if !RefusalMethodNotAllowlisted.PerOperation() {
		t.Fatal("the refusal does not count toward the denominator")
	}
	if res.DenominatorFloor() < 2 {
		t.Fatalf("DenominatorFloor() = %d; the refused TRACE operation left the "+
			"denominator", res.DenominatorFloor())
	}
}

// ---------------------------------------------------------------------------
// The lexer's own failure modes
// ---------------------------------------------------------------------------

// TestLexerSurvivesARegexCarryingAQuote. /['"]/ is a regex with an unbalanced
// quote in it. Lexing it as division would flip the string state for the rest
// of the file and routes after it would silently vanish.
//
// The route AFTER the regex is the assertion; a route before it would pass
// even with the bug.
func TestLexerSurvivesARegexCarryingAQuote(t *testing.T) {
	const src = `
const express = require('express');
const app = express();
const strip = /['"]/g;
const div = total / count / 2;
app.get('/after-the-regex', handler);
`
	res := extractOne(t, "q.js", src)
	if got, want := otherRouteTable(res), []string{"GET /after-the-regex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v; a mis-lexed regex swallowed the rest of "+
			"the file", got, want)
	}
}

// TestTemplateLiteralPathIsReportedNotDecoded. A template literal with a
// substitution is not a static path, and pretending to know its value would
// put an endpoint the target does not serve in the denominator.
func TestTemplateLiteralPathIsReportedNotDecoded(t *testing.T) {
	src := "const express = require('express');\nconst app = express();\n" +
		"app.get(`/users/${id}/posts`, h);\napp.get('/static', h);\n"
	res := extractOne(t, "t.js", src)
	if got, want := otherRouteTable(res), []string{"GET /static"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if otherCaveatCount(res, CaveatPathNotStaticallyResolvable) != 1 {
		t.Fatalf("the template literal was dropped without a caveat: %v", res.Caveats())
	}
}

// TestUnterminatedStringIsReportedNotIgnored. Bytes the lexer cannot read are
// a fact worth reporting: an empty route list from an unreadable file is
// indistinguishable from a file with no routes unless it is.
func TestUnterminatedStringIsReportedNotIgnored(t *testing.T) {
	res := extractOne(t, "broken.py", "x = \"never closed\ny = 1\n")
	if len(res.Routes()) != 0 {
		t.Fatalf("routes from an unlexable file: %v", otherRouteTable(res))
	}
	if otherCaveatCount(res, CaveatFileUnparseable) != 1 {
		t.Fatalf("no file-unparseable caveat: %v", res.Caveats())
	}
	if res.DenominatorFloor() != 1 {
		t.Fatalf("DenominatorFloor() = %d; an unreadable file hides at least one "+
			"endpoint", res.DenominatorFloor())
	}
	if err := res.AssertDenominatorIsComplete(); err == nil {
		t.Fatal("a file Anvil could not read left the denominator reported as complete")
	}
}

// TestUnbalancedRailsBlockDiscardsItsRoutes. Every prefix in a routes.rb comes
// from the do/end scope stack. If the stack is wrong, every prefix is wrong,
// and a candidate at a path the target does not serve reads as the target's
// fault when D.22 cannot confirm it. The routes are DROPPED and the drop is
// reported.
func TestUnbalancedRailsBlockDiscardsItsRoutes(t *testing.T) {
	const balanced = `
Rails.application.routes.draw do
  namespace :api do
    get "/users", to: "users#index"
  end
end
`
	const unbalanced = `
Rails.application.routes.draw do
  namespace :api do
    get "/users", to: "users#index"
end
`
	ok := extractOne(t, "config/routes.rb", balanced)
	if got, want := otherRouteTable(ok), []string{"GET /api/users"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("balanced fixture route table = %v, want %v", got, want)
	}
	bad := extractOne(t, "config/routes.rb", unbalanced)
	if len(bad.Routes()) != 0 {
		t.Fatalf("an unbalanced routes.rb still produced %v", otherRouteTable(bad))
	}
	if otherCaveatCount(bad, CaveatFileUnparseable) != 1 {
		t.Fatalf("the discard was not reported: %v", bad.Caveats())
	}
	fe := fileOutcome(t, bad, "config/routes.rb")
	if fe.Outcome != ScanOutcomeNothingParsed {
		t.Fatalf("outcome = %q, want %q", fe.Outcome, ScanOutcomeNothingParsed)
	}
}

// TestARailsEndWithNoBlockIsRefusedRatherThanUnderflowing is the other
// direction of the same stack.
func TestARailsEndWithNoBlockIsRefusedRatherThanUnderflowing(t *testing.T) {
	const src = `
Rails.application.routes.draw do
  get "/a", to: "a#a"
end
end
`
	res := extractOne(t, "config/routes.rb", src)
	if len(res.Routes()) != 0 {
		t.Fatalf("routes survived a stack underflow: %v", otherRouteTable(res))
	}
	if otherCaveatCount(res, CaveatFileUnparseable) != 1 {
		t.Fatalf("no caveat for the underflow: %v", res.Caveats())
	}
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

// TestPlaceholderSpellingsAllReachOneCanonicalForm. Six frameworks spell path
// parameters six ways and the Tier 0-2 union deduplicates on Route.Key(), so
// two spellings of one endpoint would be two rows in a fraction that is
// supposed to be auditable.
func TestPlaceholderSpellingsAllReachOneCanonicalForm(t *testing.T) {
	cases := []struct {
		fw       NonGoFramework
		pattern  string
		wantPath string
		wantParm []string
	}{
		{NonGoFrameworkFlask, "/users/<int:user_id>", "/users/{user_id}", []string{"user_id"}},
		{NonGoFrameworkFlask, "/users/<user_id>", "/users/{user_id}", []string{"user_id"}},
		{NonGoFrameworkDjango, "/files/<path:rest>", "/files/{rest}", []string{"rest"}},
		{NonGoFrameworkExpress, "/users/:id", "/users/{id}", []string{"id"}},
		{NonGoFrameworkExpress, "/users/:id?", "/users/{id}", []string{"id"}},
		{NonGoFrameworkRails, "/users/:id/edit", "/users/{id}/edit", []string{"id"}},
		{NonGoFrameworkFastAPI, "/files/{rest:path}", "/files/{rest}", []string{"rest"}},
		{NonGoFrameworkSpring, "/users/{id:[0-9]+}", "/users/{id}", []string{"id"}},
		{NonGoFrameworkSpring, "/files/{*rest}", "/files/{rest}", []string{"rest"}},
	}
	for _, c := range cases {
		spelled, err := translatePlaceholders(c.fw, c.pattern)
		if err != nil {
			t.Fatalf("translatePlaceholders(%s, %q): %v", c.fw, c.pattern, err)
		}
		got, params, err := canonicalizePattern(spelled)
		if err != nil {
			t.Fatalf("canonicalizePattern(%q): %v", spelled, err)
		}
		if got != c.wantPath {
			t.Fatalf("%s %q -> %q, want %q", c.fw, c.pattern, got, c.wantPath)
		}
		var names []string
		for _, p := range params {
			names = append(names, p.Name)
			if p.In != ParamInPath {
				t.Fatalf("%s %q: parameter %q travels in %q", c.fw, c.pattern, p.Name, p.In)
			}
			if p.Typed() {
				t.Fatalf("%s %q: parameter %q claims type %q; a lexer cannot know a "+
					"parameter's type and inventing one makes Param.Typed() lie",
					c.fw, c.pattern, p.Name, p.Type)
			}
		}
		if !reflect.DeepEqual(names, c.wantParm) {
			t.Fatalf("%s %q params = %v, want %v", c.fw, c.pattern, names, c.wantParm)
		}
	}
}

// TestTranslatePlaceholdersLeavesEverythingElseAlone. It is a SPELLING step,
// not a second canonicalizer: slashes, case and dot segments belong to
// canonicalizePattern and to the kernel.
func TestTranslatePlaceholdersLeavesEverythingElseAlone(t *testing.T) {
	for _, in := range []string{
		"users", "/Users/Mixed/Case", "/a/../b", "/trailing/", "//double//slash",
	} {
		for _, fw := range NonGoFrameworkValues() {
			got, err := translatePlaceholders(fw, in)
			if err != nil {
				t.Fatalf("translatePlaceholders(%s, %q): %v", fw, in, err)
			}
			if got != in {
				t.Fatalf("translatePlaceholders(%s, %q) = %q; it rewrote something "+
					"that is not a placeholder", fw, in, got)
			}
		}
	}
}

// TestTheKernelStillOwnsPathValidation. A dot segment is two spellings of one
// endpoint and the kernel refuses it; this file must not be quietly fixing it
// up on the way past.
func TestTheKernelStillOwnsPathValidation(t *testing.T) {
	const src = `
const express = require('express');
const app = express();
app.get('/a/../b', h);
app.get('/kept', h);
`
	res := extractOne(t, "k.js", src)
	if got, want := otherRouteTable(res), []string{"GET /kept"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if otherRefusalCount(res, RefusalPathRejectedByKernel) != 1 {
		t.Fatalf("the dot-segment path was dropped without a refusal: %v", res.Refusals())
	}
}

// ---------------------------------------------------------------------------
// Mount and prefix resolution
// ---------------------------------------------------------------------------

// TestExpressNestedMountsCompose, and TestExpressMountCycleDoesNotHang below,
// are the two halves of the mount resolver.
func TestExpressNestedMountsCompose(t *testing.T) {
	const src = `
const express = require('express');
const app = express();
const api = express.Router();
const v1 = express.Router();
const users = express.Router();

users.get('/:id', show);
v1.use('/users', users);
api.use('/v1', v1);
app.use('/api', api);
`
	res := extractOne(t, "m.js", src)
	want := []string{"GET /api/v1/users/{id}"}
	if got := otherRouteTable(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if otherCaveatCount(res, CaveatCallerPrefixNotVisible) != 0 {
		t.Fatalf("a fully mounted router was reported as prefix-unknown: %v", res.Caveats())
	}
}

func TestExpressMountCycleDoesNotHang(t *testing.T) {
	const src = `
const express = require('express');
const app = express();
const a = express.Router();
const b = express.Router();
a.use('/b', b);
b.use('/a', a);
a.get('/leaf', h);
app.use('/root', a);
`
	res := extractOne(t, "c.js", src)
	if len(res.Routes()) == 0 {
		t.Fatal("the cycle swallowed every route")
	}
	if otherCaveatCount(res, CaveatNestingTooDeep) == 0 {
		t.Fatalf("a mount cycle resolved without hitting the coded bound: %v",
			res.Caveats())
	}
	if err := res.AssertEveryRouteIsACandidate(); err != nil {
		t.Fatal(err)
	}
}

// TestAnUnmountedExpressRouterIsEmittedAndFlagged. The route is still a
// candidate -- D.22 confirms it -- but the caller's prefix is invisible, and a
// candidate at a path the target does not serve must not read as the target's
// fault.
func TestAnUnmountedExpressRouterIsEmittedAndFlagged(t *testing.T) {
	const src = `
const { Router } = require('express');
const router = Router();
router.get('/widgets', list);
module.exports = router;
`
	res := extractOne(t, "widgets.js", src)
	if got, want := otherRouteTable(res), []string{"GET /widgets"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if otherCaveatCount(res, CaveatCallerPrefixNotVisible) != 1 {
		t.Fatalf("the unknown caller prefix was not reported: %v", res.Caveats())
	}
	if CaveatCallerPrefixNotVisible.RaisesDenominatorFloor() {
		t.Fatal("caller-prefix-not-visible raises the denominator floor; it qualifies " +
			"routes already counted rather than naming an extra endpoint")
	}
}

// ---------------------------------------------------------------------------
// Result plumbing
// ---------------------------------------------------------------------------

// TestExtractNonGoRoutesRefusesUnconstructedInput. A Go zero value must never
// mean "permitted".
func TestExtractNonGoRoutesRefusesUnconstructedInput(t *testing.T) {
	good := otherSrc(t, "a.py", "x = 1\n")
	cases := []struct {
		name string
		cfg  OtherExtractConfig
		srcs []SourceFile
		want error
	}{
		{"no target", OtherExtractConfig{Harvest: HarvestRan}, nil, ErrUnconstructed},
		{"no harvest", OtherExtractConfig{Target: mustBareTarget(t)}, nil, ErrRefused},
		{"unconstructed source",
			OtherExtractConfig{Target: mustBareTarget(t), Harvest: HarvestRan},
			[]SourceFile{{}}, ErrUnconstructed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ExtractNonGoRoutes(context.Background(), c.cfg, c.srcs)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	// The positive control: the same call with everything set must succeed,
	// so a refusal that started firing on everything fails here.
	if _, err := ExtractNonGoRoutes(context.Background(), otherCfg(t),
		[]SourceFile{good}); err != nil {
		t.Fatalf("a fully constructed call was refused: %v", err)
	}
	if _, err := NewSourceFile(GoSourceFileFacts{
		Location: record.ArtifactLocation{URI: "a.py"},
	}); !errors.Is(err, ErrRefused) {
		t.Fatalf("NewSourceFile accepted a file with no bytes: %v", err)
	}
	if _, err := NewSourceFile(GoSourceFileFacts{
		Content: record.ArtifactContent{Text: "x"},
	}); !errors.Is(err, ErrRefused) {
		t.Fatalf("NewSourceFile accepted a file with no URI: %v", err)
	}
}

// TestNonGoAssertNotSilentlyEmptyDistinguishesTheTwoEmpties.
func TestNonGoAssertNotSilentlyEmptyDistinguishesTheTwoEmpties(t *testing.T) {
	// A repository whose Python was read and registers nothing: reportable.
	scanned := extractOther(t, otherSrc(t, "a.py", "from flask import Flask\napp = Flask(__name__)\n"))
	if err := scanned.AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("a scanned repository with no routes was refused: %v", err)
	}
	// Nothing was scanned at all: a fact about the handoff, refused by name.
	nothing := extractOther(t, otherSrc(t, "README.md", "# hi\n"))
	if err := nothing.AssertNotSilentlyEmpty(); !errors.Is(err, ErrNoNonGoSourceOffered) {
		t.Fatalf("err = %v, want %v", err, ErrNoNonGoSourceOffered)
	}
	// Harvest skipped, with the same file set: still refused.
	skipped, err := ExtractNonGoRoutes(context.Background(),
		OtherExtractConfig{Target: mustBareTarget(t), Harvest: HarvestSkipped},
		[]SourceFile{otherSrc(t, "a.py", "from flask import Flask\napp = Flask(__name__)\n")})
	if err != nil {
		t.Fatal(err)
	}
	if err := skipped.AssertNotSilentlyEmpty(); !errors.Is(err, ErrNoNonGoSourceOffered) {
		t.Fatalf("under HarvestSkipped err = %v", err)
	}
	if skipped.Harvest() != HarvestSkipped {
		t.Fatalf("Harvest() = %q", skipped.Harvest())
	}
	// The zero result is not a result.
	var zero OtherExtractResult
	if err := zero.AssertNotSilentlyEmpty(); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("the zero result passed: %v", err)
	}
	if err := zero.AssertDenominatorIsComplete(); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("the zero result reported a complete denominator: %v", err)
	}
	if zero.Constructed() {
		t.Fatal("the zero result is Constructed()")
	}
}

// TestResultAccessorsReturnDeepCopies.
//
// The mutations below deliberately target the fields where a shallow copy
// would NOT be caught by a naive test: the NESTED slices (Frameworks inside a
// file extract and a language report, Params inside a Route) and the maps. A
// test that only reassigned a top-level element would pass against a shallow
// copy and prove nothing.
func TestResultAccessorsReturnDeepCopies(t *testing.T) {
	res := extractOne(t, "app/views.py", nonGoFixtures()[1].src)
	if len(res.Routes()) == 0 {
		t.Fatal("the fixture produced no routes, so nothing here is exercised")
	}

	routes := res.Routes()
	for i := range routes {
		if len(routes[i].Params()) > 0 {
			ps := routes[i].params
			ps[0].Name = "CLOBBERED"
			ps[0].In = ParamInHeader
		}
		routes[i] = Route{}
	}
	fresh := res.Routes()
	if len(fresh) != len(routes) {
		t.Fatalf("route count changed: %d -> %d", len(routes), len(fresh))
	}
	for _, r := range fresh {
		if !r.Constructed() {
			t.Fatal("a route was clobbered through the copy Routes() returned")
		}
		for _, p := range r.Params() {
			if p.Name == "CLOBBERED" || p.In == ParamInHeader {
				t.Fatal("Route.Params() shares its backing array with the inventory")
			}
		}
	}

	files := res.Files()
	for i := range files {
		for j := range files[i].Frameworks {
			files[i].Frameworks[j] = NonGoFramework("CLOBBERED")
		}
		files[i].Routes = -1
	}
	for _, f := range res.Files() {
		if f.Routes == -1 {
			t.Fatal("Files() shares its slice with the result")
		}
		for _, fw := range f.Frameworks {
			if fw == "CLOBBERED" {
				t.Fatal("NonGoFileExtract.Frameworks is shared with the result")
			}
		}
	}

	langs := res.LanguageReports()
	for i := range langs {
		for j := range langs[i].Frameworks {
			langs[i].Frameworks[j] = NonGoFramework("CLOBBERED")
		}
		langs[i].Routes = -1
	}
	for _, l := range res.LanguageReports() {
		if l.Routes == -1 {
			t.Fatal("LanguageReports() shares its slice with the result")
		}
		for _, fw := range l.Frameworks {
			if fw == "CLOBBERED" {
				t.Fatal("LanguageReport.Frameworks is shared with the result")
			}
		}
	}

	rep, ok := res.LanguageReport(LanguagePython)
	if !ok {
		t.Fatal("no python language report")
	}
	for j := range rep.Frameworks {
		rep.Frameworks[j] = NonGoFramework("CLOBBERED")
	}
	again, _ := res.LanguageReport(LanguagePython)
	for _, fw := range again.Frameworks {
		if fw == "CLOBBERED" {
			t.Fatal("LanguageReport(l).Frameworks is shared with the result")
		}
	}

	mix := res.FrameworkMix()
	mix[NonGoFrameworkFlask] = -1
	mix[NonGoFramework("injected")] = 99
	if res.FrameworkMix()[NonGoFrameworkFlask] == -1 {
		t.Fatal("FrameworkMix() hands out the internal map")
	}
	if _, ok := res.FrameworkMix()[NonGoFramework("injected")]; ok {
		t.Fatal("FrameworkMix() hands out the internal map")
	}

	cav := res.Caveats()
	for i := range cav {
		cav[i].Detail = "CLOBBERED"
		cav[i].Reason = CaveatTruncated
	}
	for _, c := range res.Caveats() {
		if c.Detail == "CLOBBERED" {
			t.Fatal("Caveats() shares its slice with the result")
		}
	}
	shared := res.SharedCaveats()
	if len(shared) != len(res.Caveats()) {
		t.Fatalf("SharedCaveats() dropped %d caveats",
			len(res.Caveats())-len(shared))
	}
	for i := range shared {
		shared[i].Detail = "CLOBBERED"
	}
	for _, c := range res.Caveats() {
		if c.Detail == "CLOBBERED" {
			t.Fatal("SharedCaveats() shares its backing array with the result")
		}
	}

	refs := res.Refusals()
	for i := range refs {
		refs[i].Reason = RefusalUnset
	}
	for _, r := range res.Refusals() {
		if r.Reason == RefusalUnset {
			t.Fatal("Refusals() shares its slice with the result")
		}
	}
}

// TestDenominatorFloorCountsWhatItSays.
func TestDenominatorFloorCountsWhatItSays(t *testing.T) {
	fx := nonGoFixtures()[3] // django: routes, caveats and no refusals
	res := extractOne(t, fx.uri, fx.src)
	want := len(res.Routes())
	for _, r := range res.Refusals() {
		if r.Reason.PerOperation() {
			want++
		}
	}
	floorRaising := 0
	for _, c := range res.Caveats() {
		if c.Reason.RaisesDenominatorFloor() {
			floorRaising++
		}
	}
	want += floorRaising
	if got := res.DenominatorFloor(); got != want {
		t.Fatalf("DenominatorFloor() = %d, want %d", got, want)
	}
	if floorRaising == 0 {
		t.Fatal("the django fixture produced no floor-raising caveat, so this test " +
			"cannot tell a floor that counts them from one that does not")
	}
	if got := res.DenominatorFloor(); got <= len(res.Routes()) {
		t.Fatalf("DenominatorFloor() = %d with %d routes and %d floor-raising "+
			"caveats; the caveats vanished from the denominator",
			got, len(res.Routes()), floorRaising)
	}
}

// TestSourceOfTracesACandidateBackToItsFile. A candidate D.22 cannot confirm
// is unreviewable without it.
func TestSourceOfTracesACandidateBackToItsFile(t *testing.T) {
	res := extractOne(t, "app/views.py", nonGoFixtures()[1].src)
	for _, r := range res.Routes() {
		loc, ok := res.SourceOf(r.Key())
		if !ok {
			t.Fatalf("no source location for %s", r)
		}
		if loc.URI != "app/views.py" {
			t.Fatalf("%s traced to %q", r, loc.URI)
		}
	}
	if _, ok := res.SourceOf("GET\x00/not-a-route\x00"); ok {
		t.Fatal("SourceOf answered for a key no route carries")
	}
}

// TestDuplicateRegistrationsAreOneEndpoint. Two spellings of one endpoint must
// not become two rows in the Tier 0-2 union.
func TestDuplicateRegistrationsAreOneEndpoint(t *testing.T) {
	const src = `
const express = require('express');
const app = express();
app.get('/dup', a);
app.get('/dup', b);
`
	res := extractOne(t, "d.js", src)
	if got, want := otherRouteTable(res), []string{"GET /dup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if otherRefusalCount(res, RefusalDuplicateRoute) != 1 {
		t.Fatalf("the duplicate was dropped without a record: %v", res.Refusals())
	}
}

// TestCancelledContextDoesNotReportAPartialInventory. A partial route list
// returned as a complete one understates the denominator.
func TestCancelledContextDoesNotReportAPartialInventory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ExtractNonGoRoutes(ctx, otherCfg(t),
		[]SourceFile{otherSrc(t, "a.py", "x = 1\n")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// The positive control: the same call on a live context succeeds.
	if _, err := ExtractNonGoRoutes(context.Background(), otherCfg(t),
		[]SourceFile{otherSrc(t, "a.py", "x = 1\n")}); err != nil {
		t.Fatalf("a live context was refused: %v", err)
	}
}

// TestNonGoCaveatCarriesItsFrameworkAndStaysAValidCoverageCaveat. The embedded
// value is what D.26 consumes, so it has to keep working.
func TestNonGoCaveatCarriesItsFrameworkAndStaysAValidCoverageCaveat(t *testing.T) {
	fx := nonGoFixtures()[5] // rails
	res := extractOne(t, fx.uri, fx.src)
	seen := false
	for _, c := range res.Caveats() {
		if !c.Valid() {
			t.Fatalf("caveat %+v is not Valid()", c)
		}
		if c.Language != LanguageRuby {
			t.Fatalf("caveat %+v does not carry its language", c)
		}
		if c.NonGoFramework == NonGoFrameworkRails {
			seen = true
		}
		if c.CoverageCaveat.Framework != FrameworkUnset {
			t.Fatalf("a non-Go caveat claims the Go framework %q",
				c.CoverageCaveat.Framework)
		}
		if !strings.Contains(c.String(), string(c.Reason)) {
			t.Fatalf("CoverageCaveat.String() lost the reason: %q", c.String())
		}
	}
	if !seen {
		t.Fatalf("no caveat carried NonGoFrameworkRails: %v", res.Caveats())
	}
}

// TestAdmitRefusesARouteThatNamesNoFramework exercises the funnel directly.
//
// No code path in this package can produce an ExtractedNonGoRoute with an
// unset framework -- fileWalk.emit always passes a constant -- so breaking the
// check in toRoute left the whole suite GREEN, which is a finding about the
// suite and not a licence to delete the check: unlike D.20's deleted method
// allowlist, nothing downstream re-checks this. NewRoute never sees the
// framework, so an unset one would simply land in FrameworkMix under the empty
// key and a route would be attributed to nothing.
//
// It is reached here the only way it can be reached: at the choke point, from
// inside the package.
func TestAdmitRefusesARouteThatNamesNoFramework(t *testing.T) {
	newAcc := func() *otherAccumulator {
		return &otherAccumulator{
			target:   mustBareTarget(t),
			byFW:     map[NonGoFramework]int{},
			sourceOf: map[string]record.ArtifactLocation{},
			seenKey:  map[string]bool{},
			locOf:    map[string]record.ArtifactLocation{},
		}
	}
	// The positive control first: a funnel that refused everything would fail
	// here rather than pass the negatives below.
	acc := newAcc()
	acc.admit(ExtractedNonGoRoute{
		Framework: NonGoFrameworkExpress, Language: LanguageJavaScript,
		Method: "GET", Pattern: "/ok", File: "a.js", Line: 1,
	})
	if len(acc.routes) != 1 {
		t.Fatalf("a well-formed registration produced %d routes", len(acc.routes))
	}

	for _, fw := range []NonGoFramework{NonGoFrameworkUnset, NonGoFramework("made-up")} {
		acc := newAcc()
		acc.admit(ExtractedNonGoRoute{
			Framework: fw, Language: LanguageJavaScript,
			Method: "GET", Pattern: "/no-framework", File: "a.js", Line: 1,
		})
		if len(acc.routes) != 0 {
			t.Fatalf("framework %q produced a route; FrameworkMix would attribute it "+
				"to nothing and D.22 could not say which extractor to blame when it "+
				"fails to confirm", fw)
		}
		if len(acc.refusals) != 1 || acc.refusals[0].Reason != RefusalRouteUnconstructible {
			t.Fatalf("framework %q was dropped without a per-operation refusal: %v",
				fw, acc.refusals)
		}
		if !acc.refusals[0].Reason.PerOperation() {
			t.Fatalf("framework %q left the coverage denominator", fw)
		}
	}
}

// TestLanguageClassificationIsByWholeExtension. A table matched by substring
// would file "notes.python.md" as Python.
func TestLanguageClassificationIsByWholeExtension(t *testing.T) {
	cases := []struct {
		uri    string
		lang   Language
		status LanguageStatus
	}{
		{"src/app.js", LanguageJavaScript, LanguageStatusSupported},
		{"src/app.tsx", LanguageJavaScript, LanguageStatusSupported},
		{"a/b/views.py", LanguagePython, LanguageStatusSupported},
		{"A.java", LanguageJava, LanguageStatusSupported},
		{"config/routes.rb", LanguageRuby, LanguageStatusSupported},
		{"main.go", LanguageGo, LanguageStatusGoExtractor},
		{"index.php", LanguagePHP, LanguageStatusNotSupported},
		{"Controller.cs", LanguageCSharp, LanguageStatusNotSupported},
		{"App.kt", LanguageKotlin, LanguageStatusNotSupported},
		{"notes.python.md", LanguageUnset, LanguageStatusUnrecognised},
		{"src.py/README", LanguageUnset, LanguageStatusUnrecognised},
		{"Dockerfile", LanguageUnset, LanguageStatusUnrecognised},
		{"src/APP.PY", LanguagePython, LanguageStatusSupported},
	}
	for _, c := range cases {
		lang, status := classifyURI(c.uri)
		if lang != c.lang || status != c.status {
			t.Fatalf("classifyURI(%q) = (%q, %q), want (%q, %q)",
				c.uri, lang, status, c.lang, c.status)
		}
		if !status.Valid() {
			t.Fatalf("classifyURI(%q) produced an invalid status %q", c.uri, status)
		}
	}
	// Kotlin is the sharp one: it carries the same Spring annotations this
	// file reads in Java, and it is still not supported. Saying so is the
	// difference between a gap and a silent clean.
	if LanguageKotlin.Status() != LanguageStatusNotSupported {
		t.Fatal("kotlin is reported as supported; nothing in this file reads it")
	}
}

// TestSpringClassPrefixIsScopedByBraceDepth. Two controllers in one file must
// not share a prefix.
func TestSpringClassPrefixIsScopedByBraceDepth(t *testing.T) {
	const src = `
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/first")
class First {
    @GetMapping("/a")
    public String a() { return null; }
}

@RestController
@RequestMapping("/second")
class Second {
    @GetMapping("/b")
    public String b() { return null; }
}

@RestController
class Bare {
    @GetMapping("/c")
    public String c() { return null; }
}
`
	res := extractOne(t, "Two.java", src)
	want := []string{"GET /c", "GET /first/a", "GET /second/b"}
	if got := otherRouteTable(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
}

// TestDjangoPathAndRePathAreDifferentOutcomes. re_path takes a regex and can
// never be a literal path; path() can. Folding them together would either
// drop real endpoints or invent regex-shaped ones.
func TestDjangoPathAndRePathAreDifferentOutcomes(t *testing.T) {
	const src = `
from django.urls import path, re_path

urlpatterns = [
    path("kept/", views.kept),
    re_path(r"^dropped/$", views.dropped),
]
`
	res := extractOne(t, "urls.py", src)
	if got, want := otherRouteTable(res), []string{"GET /kept/"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	if otherCaveatCount(res, CaveatPathNotStaticallyResolvable) != 1 {
		t.Fatalf("re_path was dropped without a caveat: %v", res.Caveats())
	}
	// A file that imports `path` from somewhere else must NOT become Django.
	other := extractOne(t, "notdjango.py", "from mypkg import path\nurlpatterns = [path(\"x/\", v)]\n")
	if len(other.Routes()) != 0 {
		t.Fatalf("a non-django `path` import produced routes: %v", otherRouteTable(other))
	}
	// The sharper case, and the one that actually reaches the per-call import
	// gate: the file IS a Django URLconf -- it imports re_path from
	// django.urls, so the Django extractor runs over it -- and `path` in it is
	// a local helper of the same name. Attributing that call to Django would
	// put an endpoint the target does not serve in the denominator forever.
	//
	// The case above returns long before django() is reached, so it left the
	// gate untested; that was a finding about this test, not about the gate.
	shadowed := extractOne(t, "shadow_urls.py", strings.Join([]string{
		"from django.urls import re_path",
		"from .helpers import path",
		"",
		"urlpatterns = [",
		`    re_path(r"^kept/$", views.kept),`,
		"]",
		`extra = path("/not-a-route", 1)`,
		"",
	}, "\n"))
	if len(shadowed.Routes()) != 0 {
		t.Fatalf("a locally-defined `path` was attributed to Django: %v",
			otherRouteTable(shadowed))
	}
	if otherCaveatCount(shadowed, CaveatPathNotStaticallyResolvable) != 1 {
		t.Fatalf("the re_path in the shadowed fixture was not reported, so this probe "+
			"never reaches the django extractor at all: %v", shadowed.Caveats())
	}
}

// TestRailsResourcesExpandToTheDocumentedSevenActions pins the table a reader
// can check against the Rails routing guide.
func TestRailsResourcesExpandToTheDocumentedSevenActions(t *testing.T) {
	const src = `
Rails.application.routes.draw do
  resources :photos
end
`
	res := extractOne(t, "config/routes.rb", src)
	want := []string{
		"DELETE /photos/{id}",
		"GET /photos",
		"GET /photos/new",
		"GET /photos/{id}",
		"GET /photos/{id}/edit",
		"PATCH /photos/{id}",
		"POST /photos",
		"PUT /photos/{id}",
	}
	if got := otherRouteTable(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v", got, want)
	}
	only := extractOne(t, "config/routes.rb",
		"Rails.application.routes.draw do\n  resources :photos, only: [:index]\nend\n")
	if got, want := otherRouteTable(only), []string{"GET /photos"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("only: route table = %v, want %v", got, want)
	}
	except := extractOne(t, "config/routes.rb",
		"Rails.application.routes.draw do\n  resources :photos, except: [:destroy, :new, :edit, :create, :update]\nend\n")
	if got, want := otherRouteTable(except),
		[]string{"GET /photos", "GET /photos/{id}"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("except: route table = %v, want %v", got, want)
	}
}

// TestRailsBareVerbInsideAResourcesBlockIsReportedNotGuessed. Rails' implicit
// nesting rule for that shape was not verifiable on this host, and a guessed
// prefix would put a candidate at a path the target does not serve.
func TestRailsBareVerbInsideAResourcesBlockIsReportedNotGuessed(t *testing.T) {
	const src = `
Rails.application.routes.draw do
  resources :photos do
    get "preview"
    member do
      get "zoom"
    end
  end
end
`
	res := extractOne(t, "config/routes.rb", src)
	table := otherRouteTable(res)
	if !containsStr(table, "GET /photos/{id}/zoom") {
		t.Fatalf("the member route is missing: %v", table)
	}
	for _, r := range table {
		if strings.Contains(r, "preview") {
			t.Fatalf("a guessed prefix was applied to the bare verb: %v", table)
		}
	}
	if otherCaveatCount(res, CaveatMountNotFollowed) != 1 {
		t.Fatalf("the unresolved bare verb was dropped without a caveat: %v",
			res.Caveats())
	}
}

// TestAStaleRailsScopeDoesNotAttachToAnUnrelatedBlock.
//
// `resources :photos, only: [:index]` opens no block. If its scope stayed
// pending, the next `do` in the file -- here an unread `concern` directive --
// would inherit it, and every route inside would be silently reprefixed with
// "/photos" and treated as living inside a resources block. This was found by
// asking what the break for the pending-clear would look like; nothing in the
// suite failed without it, which was a finding about the suite.
func TestAStaleRailsScopeDoesNotAttachToAnUnrelatedBlock(t *testing.T) {
	const src = `
Rails.application.routes.draw do
  resources :photos, only: [:index]

  concern :commentable do
    get "/comments", to: "comments#index"
  end
end
`
	res := extractOne(t, "config/routes.rb", src)
	want := []string{"GET /comments", "GET /photos"}
	if got := otherRouteTable(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v; the resources scope leaked into the "+
			"following block", got, want)
	}
}

// TestRubyHeredocDoesNotSwallowTheFile. A heredoc mis-lexed as a left shift
// consumes everything after it, and the routes after it vanish silently.
func TestRubyHeredocDoesNotSwallowTheFile(t *testing.T) {
	// The body carries a LONE `end`. An earlier draft's body happened to
	// contain a matching do/end pair, so the scope stack balanced either way
	// and removing the heredoc rule left this test GREEN.
	const src = `
Rails.application.routes.draw do
  BANNER = <<~TEXT
    end
    this is prose, not a block
  TEXT

  get "/after-the-heredoc", to: "a#a"
end
`
	res := extractOne(t, "config/routes.rb", src)
	if got, want := otherRouteTable(res), []string{"GET /after-the-heredoc"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("route table = %v, want %v; the heredoc body was lexed as code",
			got, want)
	}
}

// TestOutputIsDeterministic. Map iteration is randomized and an unstable
// report makes an unchanged repository look changed, which is what
// record.PropRunRouteTableDigest would see.
func TestOutputIsDeterministic(t *testing.T) {
	var srcs []SourceFile
	for _, fx := range nonGoFixtures() {
		srcs = append(srcs, otherSrc(t, fx.uri, fx.src))
	}
	first := extractOther(t, srcs...)
	wantRoutes := otherRouteTable(first)
	var wantCaveats []string
	for _, c := range first.Caveats() {
		wantCaveats = append(wantCaveats, c.String())
	}
	for i := 0; i < 8; i++ {
		res := extractOther(t, srcs...)
		if got := otherRouteTable(res); !reflect.DeepEqual(got, wantRoutes) {
			t.Fatalf("run %d route table differs", i)
		}
		var got []string
		for _, c := range res.Caveats() {
			got = append(got, c.String())
		}
		if !reflect.DeepEqual(got, wantCaveats) {
			t.Fatalf("run %d caveat order differs:\n got %v\nwant %v", i, got, wantCaveats)
		}
		var files []string
		for _, f := range res.Files() {
			files = append(files, f.URI)
		}
		if !sort.StringsAreSorted(files) {
			t.Fatalf("run %d file list is not sorted: %v", i, files)
		}
	}
}

// TestAllFixturesTogetherStayHonest is the whole-repository case: six
// frameworks, four languages, one result.
func TestAllFixturesTogetherStayHonest(t *testing.T) {
	var srcs []SourceFile
	rows, union := 0, map[string]bool{}
	for _, fx := range nonGoFixtures() {
		srcs = append(srcs, otherSrc(t, fx.uri, fx.src))
		rows += len(fx.want)
		for _, r := range fx.want {
			union[r] = true
		}
	}
	res := extractOther(t, srcs...)
	// The expectation is the UNION, not the sum. Three fixtures serve
	// "GET /healthz" and two serve "GET /api/users"; those are one endpoint
	// each in the Tier 0-2 union, and counting them twice would inflate the
	// denominator of a fraction that is supposed to be auditable. The
	// difference is not silent -- each collapse is a RefusalDuplicateRoute.
	if len(union) >= rows {
		t.Fatalf("the six fixtures declare %d rows and %d distinct endpoints; this "+
			"test cannot tell a deduplicating union from a summing one", rows, len(union))
	}
	if len(res.Routes()) != len(union) {
		t.Fatalf("%d routes across the six fixtures, want %d distinct (from %d rows)",
			len(res.Routes()), len(union), rows)
	}
	var got []string
	for r := range union {
		got = append(got, r)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(otherRouteTable(res), got) {
		t.Fatalf("combined route table\n got: %v\nwant: %v", otherRouteTable(res), got)
	}
	if n := otherRefusalCount(res, RefusalDuplicateRoute); n != rows-len(union) {
		t.Fatalf("%d duplicate refusals for %d collapsed rows", n, rows-len(union))
	}
	if err := res.AssertEveryRouteIsACandidate(); err != nil {
		t.Fatal(err)
	}
	if err := res.AssertDenominatorIsComplete(); err != nil {
		t.Fatalf("six supported-language fixtures left the denominator incomplete: %v", err)
	}
	if err := res.AssertNotSilentlyEmpty(); err != nil {
		t.Fatal(err)
	}
	mix := res.FrameworkMix()
	for _, f := range NonGoFrameworkValues() {
		if mix[f] == 0 {
			t.Fatalf("%s contributed no routes to the combined run: %v", f, mix)
		}
	}
	langs := map[Language]bool{}
	for _, rep := range res.LanguageReports() {
		langs[rep.Language] = true
		if rep.Outcome != ScanOutcomeRoutesFound {
			t.Fatalf("%s outcome = %q", rep.Language, rep.Outcome)
		}
	}
	for _, l := range SupportedLanguages() {
		if !langs[l] {
			t.Fatalf("no language report for %s", l)
		}
	}
	if res.Scanned() != len(srcs) || res.Lexed() != len(srcs) {
		t.Fatalf("scanned=%d lexed=%d of %d offered", res.Scanned(), res.Lexed(), len(srcs))
	}
	if res.Truncated() {
		t.Fatal("a six-file run hit a coded bound")
	}
}
