// Tests for D.19, Tier 1 of the attack-surface inventory.
//
// ===========================================================================
// WHAT IS PROVEN HERE
// ===========================================================================
//
// EVERYTHING IN THIS PACKET IS PROVEN END TO END. Tier 1 issues no request, so
// none of it depends on the kernel admitting anything, none of it needs a
// SpecFetcher, and nothing in it belongs in internal/SKIPPED-CONTROLS.md.
// There is no t.Skip in this file.
//
//	all five input formats the packet names parse to Route lists — OpenAPI
//	YAML, Swagger JSON, WSDL, GraphQL SDL, and a Postman collection converted
//	to OpenAPI at ingest — in ONE ingest, which is D.19's stop condition
//	the two axes: every Tier 1 route is repo_spec + candidate + untrusted, and
//	the retag that stamps them cannot be made to launder a confirmed route
//	gate 11's asymmetry against a REPOSITORY-AUTHORED file: an OpenAPI
//	`servers` entry, a WSDL `soap:address location` and a Postman request URL
//	all pointing at 169.254.169.254 are read, recorded and IGNORED, and only
//	the path half of any of them is ever used
//	the coverage arithmetic: nothing any of the five parsers saw vanishes
//	without a row, and a refused operation still counts toward the denominator
//	the block-YAML subset: it refuses the WHOLE document on any construct
//	outside it, one construct at a time, and the tree it builds for a document
//	inside it is the same tree the equivalent JSON produces
//	that this file's implementation cannot open a file and cannot know a
//	repository path, enforced by an import allowlist and a literal scan
//	the copy discipline on every reference field, with reflection guards that
//	fail when a new one is added
//
// ===========================================================================
// THE HOST THIS WAS RUN ON
// ===========================================================================
//
// Windows 11, Go 1.26.5, from PowerShell. The race detector works from
// PowerShell on this host and fails from Git Bash with a ThreadSanitizer
// allocation error that is an address-space issue rather than a race; any
// race-detector claim in the packet report names the shell that produced it.
package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Harness
//
// mustBareTarget, mustClock and the kernel fixtures come from
// tier0_runtime_test.go: this is one package and a second Target fixture would
// be a second definition of what "the target" is, which is exactly what the
// foreign-origin tests below depend on being singular.
// ---------------------------------------------------------------------------

const t1GraphQLEndpoint = "/graphql"

func t1File(t *testing.T, uri, content string) SpecFile {
	t.Helper()
	f, err := NewSpecFile(SpecFileFacts{
		Location: record.ArtifactLocation{URI: uri},
		Content:  record.ArtifactContent{Text: content},
	})
	if err != nil {
		t.Fatalf("NewSpecFile(%q): %v", uri, err)
	}
	return f
}

func t1Config(t *testing.T) IngestConfig {
	t.Helper()
	return IngestConfig{
		Target:          mustBareTarget(t),
		Harvest:         HarvestRan,
		GraphQLEndpoint: t1GraphQLEndpoint,
	}
}

func t1Ingest(t *testing.T, uri, content string) FileResult {
	t.Helper()
	fr, err := IngestSpecFile(t1Config(t), t1File(t, uri, content))
	if err != nil {
		t.Fatalf("IngestSpecFile(%q): %v", uri, err)
	}
	if err := fr.AssertAccountedFor(); err != nil {
		t.Fatalf("%s: %v", uri, err)
	}
	return fr
}

func t1RouteKeys(rs []Route) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		op := ""
		if r.Operation() != "" {
			op = " " + r.Operation()
		}
		out = append(out, string(r.Method())+" "+r.Path()+op)
	}
	sort.Strings(out)
	return out
}

func t1Reasons(refs []Refusal) map[RefusalReason]int {
	out := map[RefusalReason]int{}
	for _, r := range refs {
		out[r.Reason]++
	}
	return out
}

func t1HasReason(refs []Refusal, want RefusalReason) bool {
	for _, r := range refs {
		if r.Reason == want {
			return true
		}
	}
	return false
}

// ===========================================================================
// THE FIVE FORMATS — D.19's STOP CONDITION
// ===========================================================================

// fixtureOpenAPIYAML exercises the block-YAML reader on the constructs a real
// openapi.yaml uses: nested mappings, sequences of mappings, a literal block
// scalar, a quoted scalar and an unquoted version string.
const fixtureOpenAPIYAML = `openapi: 3.0.3
info:
  title: Fixture Service
  version: "1.0"
  description: |
    A committed description that spans lines.
      An indented continuation.

    A second paragraph.
servers:
  - url: https://target.example.com
paths:
  /users:
    get:
      operationId: listUsers
      parameters:
        - name: limit
          in: query
          required: false
          schema:
            type: integer
        - name: X-Trace
          in: header
          schema:
            type: string
    post:
      operationId: createUser
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
  /users/{id}:
    get:
      operationId: getUser
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
`

// fixtureSwaggerJSON exercises Swagger 2's flat parameter types, its basePath
// prefixing, and an in=body parameter carrying a schema reference.
const fixtureSwaggerJSON = `{"swagger":"2.0","host":"target.example.com","basePath":"/api/v2",
 "paths":{"/orders":{
   "get":{"operationId":"listOrders",
     "parameters":[{"name":"page","in":"query","type":"integer"}]},
   "post":{"operationId":"createOrder",
     "parameters":[{"name":"payload","in":"body","schema":{"$ref":"#/definitions/Order"}}]}}}}`

// fixtureWSDL exercises the binding -> portType -> message chain and the
// address location that supplies the path.
const fixtureWSDL = `<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             xmlns:tns="urn:fixture" targetNamespace="urn:fixture">
  <message name="GetQuoteIn">
    <part name="symbol" type="xsd:string"/>
    <part name="depth" type="xsd:int"/>
  </message>
  <message name="GetQuoteOut"><part name="price" type="xsd:decimal"/></message>
  <portType name="QuotePort">
    <operation name="GetQuote">
      <input message="tns:GetQuoteIn"/>
      <output message="tns:GetQuoteOut"/>
    </operation>
    <operation name="Ping"/>
  </portType>
  <binding name="QuoteBinding" type="tns:QuotePort">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
  </binding>
  <service name="QuoteService">
    <port name="QuotePortSoap" binding="tns:QuoteBinding">
      <soap:address location="https://target.example.com/soap/quote"/>
    </port>
  </service>
</definitions>`

// fixtureGraphQLSDL exercises block descriptions, comments, argument defaults,
// list and non-null type wrappers, and a Mutation type.
const fixtureGraphQLSDL = `# A committed schema.
"""
The root query type. It contains a } brace inside this description, which must
not close the type body that follows.
"""
type Query {
  user(id: ID!, includeDrafts: Boolean = false): User
  search(term: String!, first: Int): [User!]!
}

type Mutation {
  createUser(input: CreateUserInput!): User!
  deleteUser(id: ID!): Boolean
}

input CreateUserInput {
  name: String!
  email: String
}

type User {
  id: ID!
  name: String
}
`

// fixturePostman exercises nested folders, the object and string URL shapes,
// query and header parameters, a raw body and a `:id` path variable.
const fixturePostman = `{
 "info": {"name":"Fixture",
   "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
 "item": [
  {"name":"list users","request":{"method":"GET",
    "url":{"raw":"https://target.example.com/api/users?limit=10","query":[{"key":"limit"}]},
    "header":[{"key":"X-Trace"}]}},
  {"name":"folder","item":[
    {"name":"get user","request":{"method":"GET",
      "url":{"raw":"https://target.example.com/api/users/:id"}}},
    {"name":"create user","request":{"method":"POST",
      "url":{"raw":"https://target.example.com/api/users"},
      "body":{"mode":"raw","raw":"{}"}}}
  ]}
 ]
}`

// TestAllFiveInputFormatsParseToRouteListsInOneIngest is D.19's stop
// condition, stated as one test: "All five input formats parse to Route lists;
// Postman-to-OpenAPI conversion verified against a fixture collection."
func TestAllFiveInputFormatsParseToRouteListsInOneIngest(t *testing.T) {
	files := []SpecFile{
		t1File(t, "api/openapi.yaml", fixtureOpenAPIYAML),
		t1File(t, "api/swagger.json", fixtureSwaggerJSON),
		t1File(t, "soap/quote.wsdl", fixtureWSDL),
		t1File(t, "graph/schema.graphql", fixtureGraphQLSDL),
		t1File(t, "postman/collection.json", fixturePostman),
	}
	res, err := IngestRepoSpecs(t1Config(t), files)
	if err != nil {
		t.Fatalf("IngestRepoSpecs: %v", err)
	}
	if err := res.AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("%v", err)
	}
	if res.Offered() != 5 || res.Ingested() != 5 {
		t.Fatalf("offered %d, ingested %d; all five fixtures are formats this tier reads",
			res.Offered(), res.Ingested())
	}

	wantFormats := map[SpecFormat]bool{
		FormatOpenAPI3YAML:      true,
		FormatSwagger2:          true,
		FormatWSDL:              true,
		FormatGraphQLSDL:        true,
		FormatPostmanCollection: true,
	}
	got := map[SpecFormat]bool{}
	for _, f := range res.Files() {
		got[f.Format] = true
		if len(f.Routes) == 0 {
			t.Errorf("%s parsed as %s and produced no routes; the stop condition is that "+
				"all five formats parse to Route LISTS", f.Location.URI, f.Format)
		}
	}
	if !reflect.DeepEqual(got, wantFormats) {
		t.Fatalf("the ingest classified %v and the five formats are %v", got, wantFormats)
	}

	want := []string{
		"GET /api/users list users",
		"GET /api/users/{id} get user",
		"GET /api/v2/orders listOrders",
		"GET /users listUsers",
		"GET /users/{id} getUser",
		"POST /api/users create user",
		"POST /api/v2/orders createOrder",
		"POST /graphql Mutation.createUser",
		"POST /graphql Mutation.deleteUser",
		"POST /graphql Query.search",
		"POST /graphql Query.user",
		"POST /soap/quote QuotePort.GetQuote",
		"POST /soap/quote QuotePort.Ping",
		"POST /users createUser",
	}
	if diff := t1RouteKeys(res.Routes()); !reflect.DeepEqual(diff, want) {
		t.Fatalf("the union is\n  %s\nand the five fixtures declare\n  %s",
			strings.Join(diff, "\n  "), strings.Join(want, "\n  "))
	}
	if res.Seen() != len(want) {
		t.Errorf("Seen is %d and %d routes came out with no per-operation refusals",
			res.Seen(), len(want))
	}
	if res.DenominatorFloor() != len(want) {
		t.Errorf("DenominatorFloor is %d, want %d", res.DenominatorFloor(), len(want))
	}
}

func TestOpenAPIYAMLYieldsFullyTypedRoutes(t *testing.T) {
	fr := t1Ingest(t, "openapi.yaml", fixtureOpenAPIYAML)
	if fr.Format != FormatOpenAPI3YAML {
		t.Fatalf("format is %s", fr.Format)
	}
	if len(fr.Routes) != 3 {
		t.Fatalf("got %d routes: %v", len(fr.Routes), t1RouteKeys(fr.Routes))
	}
	for _, r := range fr.Routes {
		if !r.FullyTyped() {
			t.Errorf("route %s carries an untyped parameter; the packet asks for "+
				"parameter-typed extraction and this is the predicate that measures it", r)
		}
	}
	var get Route
	for _, r := range fr.Routes {
		if r.Operation() == "listUsers" {
			get = r
		}
	}
	if !get.Constructed() {
		t.Fatal("the fixture's listUsers operation did not become a route")
	}
	want := []Param{
		{Name: "limit", In: ParamInQuery, Type: "integer"},
		{Name: "X-Trace", In: ParamInHeader, Type: "string"},
	}
	if !reflect.DeepEqual(get.Params(), want) {
		t.Fatalf("listUsers params are %#v, want %#v", get.Params(), want)
	}
}

func TestSwaggerJSONAppliesBasePathAndTypesEveryParameter(t *testing.T) {
	fr := t1Ingest(t, "swagger.json", fixtureSwaggerJSON)
	if fr.Format != FormatSwagger2 {
		t.Fatalf("format is %s", fr.Format)
	}
	got := t1RouteKeys(fr.Routes)
	want := []string{"GET /api/v2/orders listOrders", "POST /api/v2/orders createOrder"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes are %v, want %v", got, want)
	}
	for _, r := range fr.Routes {
		if !r.FullyTyped() {
			t.Errorf("route %s is not fully typed: %#v", r, r.Params())
		}
	}
}

func TestWSDLYieldsOneRoutePerOperationOnThePortsPath(t *testing.T) {
	fr := t1Ingest(t, "quote.wsdl", fixtureWSDL)
	if fr.Format != FormatWSDL {
		t.Fatalf("format is %s", fr.Format)
	}
	got := t1RouteKeys(fr.Routes)
	want := []string{"POST /soap/quote QuotePort.GetQuote", "POST /soap/quote QuotePort.Ping"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes are %v, want %v", got, want)
	}
	// One SOAP path, two operations. Counting the PORT as one endpoint would
	// make endpoint_coverage meaningless for a SOAP target: probing the single
	// path once would read as complete coverage of every operation behind it.
	for _, r := range fr.Routes {
		if r.Operation() == "QuotePort.GetQuote" {
			want := []Param{
				{Name: "symbol", In: ParamInBody, Type: "xsd:string", Required: true},
				{Name: "depth", In: ParamInBody, Type: "xsd:int", Required: true},
			}
			if !reflect.DeepEqual(r.Params(), want) {
				t.Fatalf("GetQuote params are %#v, want %#v", r.Params(), want)
			}
		}
	}
}

func TestGraphQLSDLYieldsOneRoutePerRootField(t *testing.T) {
	fr := t1Ingest(t, "schema.graphql", fixtureGraphQLSDL)
	if fr.Format != FormatGraphQLSDL {
		t.Fatalf("format is %s", fr.Format)
	}
	got := t1RouteKeys(fr.Routes)
	want := []string{
		"POST /graphql Mutation.createUser",
		"POST /graphql Mutation.deleteUser",
		"POST /graphql Query.search",
		"POST /graphql Query.user",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes are %v, want %v", got, want)
	}
	// The `}` inside the block description must not have closed the type body.
	// If it had, Query.search would be missing and this test would be the only
	// thing that noticed.
	for _, r := range fr.Routes {
		if r.Operation() != "Query.user" {
			continue
		}
		want := []Param{
			{Name: "id", In: ParamInGraphQLArgument, Type: "ID!", Required: true},
			{Name: "includeDrafts", In: ParamInGraphQLArgument, Type: "Boolean"},
		}
		if !reflect.DeepEqual(r.Params(), want) {
			t.Fatalf("Query.user args are %#v, want %#v", r.Params(), want)
		}
	}
	if len(fr.Routes) != 4 {
		t.Fatalf("got %d routes", len(fr.Routes))
	}
}

func TestPostmanIsConvertedToOpenAPIAtIngest(t *testing.T) {
	fr := t1Ingest(t, "collection.json", fixturePostman)
	if fr.Format != FormatPostmanCollection {
		t.Fatalf("format is %s", fr.Format)
	}
	got := t1RouteKeys(fr.Routes)
	want := []string{
		"GET /api/users list users",
		"GET /api/users/{id} get user",
		"POST /api/users create user",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes are %v, want %v", got, want)
	}
	for _, r := range fr.Routes {
		switch r.Operation() {
		case "get user":
			want := []Param{{Name: "id", In: ParamInPath, Required: true}}
			if !reflect.DeepEqual(r.Params(), want) {
				t.Fatalf("the `:id` segment did not become a path parameter: %#v", r.Params())
			}
			if r.FullyTyped() {
				t.Error("a Postman path variable has no declared type, so the route must " +
					"NOT report itself fully typed. Reporting otherwise would assert a " +
					"type the collection never carried")
			}
		case "create user":
			want := []Param{{Name: "requestBody", In: ParamInBody, Type: "application/json"}}
			if !reflect.DeepEqual(r.Params(), want) {
				t.Fatalf("the raw body did not become a requestBody: %#v", r.Params())
			}
		}
	}
}

// ===========================================================================
// THE TWO AXES
// ===========================================================================

// TestEveryTier1RouteIsRepoSpecCandidateUntrusted sweeps every fixture.
//
// The two axes cannot be defaulted for the reason D.18 records: a candidate
// that reads as confirmed moves into the NUMERATOR of endpoint_coverage
// (plan/50-dast.md:1152). For Tier 1 the pressure is specific — the plan text
// itself says a checked-in spec is "authoritative for what the developer
// intended" — and a six-month-old openapi.yaml is exactly the input that would
// hand Anvil a numerator full of endpoints that no longer exist.
func TestEveryTier1RouteIsRepoSpecCandidateUntrusted(t *testing.T) {
	tgt := mustBareTarget(t)
	for _, fx := range everyTier1Fixture() {
		t.Run(fx.name, func(t *testing.T) {
			fr := t1Ingest(t, fx.name, fx.content)
			if len(fr.Routes) == 0 && !fx.routeless {
				t.Fatalf("%s produced no routes at all, so this sweep asserts nothing "+
					"about it", fx.name)
			}
			for _, r := range fr.Routes {
				if r.Provenance() != record.InventoryProvenanceRepoSpec {
					t.Errorf("route %s is tagged %q and Tier 1 is repo_spec", r,
						r.Provenance())
				}
				if r.Confirmation() != ConfirmationCandidate {
					t.Errorf("route %s is %q. Confirmation is D.22's, on a non-404 "+
						"response; a checked-in spec is a claim about a service Anvil "+
						"has not touched", r, r.Confirmation())
				}
				if r.Trust() != record.TrustUntrusted {
					t.Errorf("route %s is %q. A repository wrote these bytes", r, r.Trust())
				}
				if r.Target() != tgt {
					t.Errorf("route %s moved off the pinned target", r)
				}
				if r.ServedAt() != "" {
					t.Errorf("route %s carries ServedAt %q. ServedAt is a well-known "+
						"ENDPOINT and D.18 uses it as a request path; a repository "+
						"filename there is a filename where a later packet looks for an "+
						"address", r, r.ServedAt())
				}
			}
		})
	}
}

// TestTheRetagCannotLaunderAConfirmedRoute.
//
// retagAsRepoSpec is the single place a Tier 0 route becomes a Tier 1 route,
// which makes it the single place a `confirmed` could leak into this tier. The
// input here is deliberately the most permissive route the package can build —
// runtime_spec, CONFIRMED, and TrustVerified rather than untrusted — so that a
// retag that copied any of the three would be visible.
func TestTheRetagCannotLaunderAConfirmedRoute(t *testing.T) {
	tgt := mustBareTarget(t)
	laundered, err := NewRoute(RouteFacts{
		Method: authz.MethodGet, Path: "/admin", Target: tgt,
		Operation:    "adminPanel",
		Params:       []Param{{Name: "q", In: ParamInQuery, Type: "string"}},
		Provenance:   record.InventoryProvenanceRuntimeSpec,
		Confirmation: ConfirmationConfirmed,
		Trust:        record.TrustVerified,
		ServedAt:     "/openapi.json",
	})
	if err != nil {
		t.Fatalf("building the input route: %v", err)
	}
	// The fixture has to actually carry the permissive values, or this test
	// proves nothing about the retag.
	if laundered.Confirmation() != ConfirmationConfirmed ||
		laundered.Trust() != record.TrustVerified ||
		laundered.Provenance() != record.InventoryProvenanceRuntimeSpec ||
		laundered.ServedAt() == "" {
		t.Fatalf("the input route does not carry the values this test exists to see "+
			"discarded: %#v", laundered)
	}

	got, err := retagAsRepoSpec(tgt, laundered)
	if err != nil {
		t.Fatalf("retagAsRepoSpec: %v", err)
	}
	if got.Confirmation() != ConfirmationCandidate {
		t.Errorf("the retag carried %q through. A confirmed route entering Tier 1 moves "+
			"into the numerator of endpoint_coverage for an endpoint nobody probed",
			got.Confirmation())
	}
	if got.Provenance() != record.InventoryProvenanceRepoSpec {
		t.Errorf("the retag carried provenance %q through", got.Provenance())
	}
	if got.Trust() != record.TrustUntrusted {
		t.Errorf("the retag carried trust %q through", got.Trust())
	}
	if got.ServedAt() != "" {
		t.Errorf("the retag carried ServedAt %q through", got.ServedAt())
	}
	// Everything the retag is supposed to preserve, preserved.
	if got.Method() != laundered.Method() || got.Path() != laundered.Path() ||
		got.Operation() != laundered.Operation() ||
		!reflect.DeepEqual(got.Params(), laundered.Params()) {
		t.Errorf("the retag changed something it should have carried: %#v vs %#v",
			got, laundered)
	}
}

// TestADocumentCannotTalkItselfIntoBeingConfirmed. The retag above is the code
// path; this is the input path. A committed document that sets every field it
// might hope Anvil reads changes nothing, because none of them is read.
func TestADocumentCannotTalkItselfIntoBeingConfirmed(t *testing.T) {
	const hopeful = `{"openapi":"3.0.3","x-anvil-confirmation":"confirmed",
	 "x-anvil-trust":"verified","x-anvil-provenance":"runtime_spec",
	 "paths":{"/a":{"get":{"operationId":"a","x-anvil-confirmed":true,
	   "status":"confirmed","confirmation":"confirmed","trust":"anvil_generated"}}}}`
	fr := t1Ingest(t, "hopeful.json", hopeful)
	if len(fr.Routes) != 1 {
		t.Fatalf("got %d routes", len(fr.Routes))
	}
	r := fr.Routes[0]
	if r.Confirmation() != ConfirmationCandidate || r.Trust() != record.TrustUntrusted ||
		r.Provenance() != record.InventoryProvenanceRepoSpec {
		t.Fatalf("a document talked itself into %s", r)
	}
}

// ===========================================================================
// A COMMITTED FILE IS ATTACKER-AUTHORED, AND IT MAY NOT WIDEN SCOPE
//
// The manifest packet's lesson, transposed: 169.254.169.254 was a legal
// Compose service name, so a committed file could point Anvil's health check
// at the cloud metadata endpoint. These are the three places a committed spec
// file names a network destination, and all three are read, recorded and
// ignored — with only the PATH half ever reaching a route.
// ===========================================================================

const metadataHost = "169.254.169.254"

const fixtureOpenAPIForeignServers = `{"openapi":"3.0.3",
 "servers":[{"url":"http://169.254.169.254/latest/meta-data"}],
 "paths":{"/creds":{"get":{"operationId":"creds"}}}}`

const fixtureWSDLForeignAddress = `<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="urn:evil" targetNamespace="urn:evil">
  <message name="In"><part name="a" type="xsd:string"/></message>
  <portType name="P"><operation name="Op"><input message="tns:In"/></operation></portType>
  <binding name="B" type="tns:P"/>
  <service name="S">
    <port name="Port" binding="tns:B">
      <soap:address location="http://169.254.169.254/latest/meta-data/iam"/>
    </port>
  </service>
</definitions>`

const fixturePostmanForeignHost = `{"info":{"name":"x",
  "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
 "item":[{"name":"steal","request":{"method":"GET",
   "url":{"raw":"http://169.254.169.254/latest/meta-data/iam/security-credentials"}}}]}`

// TestACommittedSpecCanNeverWidenScope is the packet's central adversarial
// requirement.
//
// The route paths ARE taken from the hostile URLs in two of the three cases,
// and that is the design rather than a leak: gate 9 pins the host and a path
// cannot move it, so the path half is safe to use and the host half is not.
// The test asserts both halves of that: the path arrived, and the target did
// not move.
func TestACommittedSpecCanNeverWidenScope(t *testing.T) {
	tgt := mustBareTarget(t)
	cases := []struct {
		name     string
		uri      string
		content  string
		wantPath string
	}{
		{"an OpenAPI servers entry", "openapi.json", fixtureOpenAPIForeignServers, "/creds"},
		{"a WSDL soap:address location", "s.wsdl", fixtureWSDLForeignAddress,
			"/latest/meta-data/iam"},
		{"a Postman request URL", "c.json", fixturePostmanForeignHost,
			"/latest/meta-data/iam/security-credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := t1Ingest(t, tc.uri, tc.content)
			if !fr.DeclaredForeignOrigin {
				t.Fatalf("%s named %s and the parse did not record a divergence. A "+
					"committed file pointing Anvil at the cloud metadata endpoint has to "+
					"reach the record", tc.name, metadataHost)
			}
			if !t1HasReason(fr.Refusals, RefusalForeignOriginIgnored) {
				t.Fatalf("no %s row: %v", RefusalForeignOriginIgnored, fr.Refusals)
			}
			if len(fr.Routes) != 1 {
				t.Fatalf("got %d routes: %v", len(fr.Routes), t1RouteKeys(fr.Routes))
			}
			r := fr.Routes[0]
			if r.Target() != tgt {
				t.Fatalf("route %s does not live on the pinned target. The declared host "+
					"moved the route, which is the whole thing gate 11's asymmetry "+
					"forbids", r)
			}
			if r.Path() != tc.wantPath {
				t.Fatalf("route path is %q, want %q", r.Path(), tc.wantPath)
			}
			if strings.Contains(r.Path(), metadataHost) ||
				strings.Contains(r.String(), metadataHost) {
				t.Fatalf("the declared host reached the route itself: %s", r)
			}
			for _, ref := range fr.Refusals {
				if strings.Contains(ref.Path, metadataHost) {
					t.Fatalf("a refusal carries the declared host in its PATH field, "+
						"which a later packet reads as an address: %#v", ref)
				}
			}
		})
	}
}

// TestTheHarvestersDeclaredFormatCannotChooseTheParser.
//
// The harvester classifies on the filename it found in the repository, and the
// filename is in the repository. Letting the declared format pick the parser
// would let a committed file choose how Anvil reads it, which is one step
// short of choosing what Anvil reads.
func TestTheHarvestersDeclaredFormatCannotChooseTheParser(t *testing.T) {
	f, err := NewSpecFile(SpecFileFacts{
		Location:       record.ArtifactLocation{URI: "not-really.wsdl"},
		Content:        record.ArtifactContent{Text: fixtureSwaggerJSON},
		DeclaredFormat: FormatWSDL,
	})
	if err != nil {
		t.Fatalf("NewSpecFile: %v", err)
	}
	fr, err := IngestSpecFile(t1Config(t), f)
	if err != nil {
		t.Fatalf("IngestSpecFile: %v", err)
	}
	if fr.Format != FormatSwagger2 {
		t.Fatalf("the declared format %s chose the parser; the bytes are Swagger 2 and "+
			"the result is %s", FormatWSDL, fr.Format)
	}
	if !fr.DeclaredFormatDiverged {
		t.Fatal("the divergence between the harvester's claim and the bytes was not " +
			"recorded. It is evidence that the harvest side is classifying on filename")
	}
	if len(fr.Routes) != 2 {
		t.Fatalf("got %d routes; the bytes still had to parse as what they are",
			len(fr.Routes))
	}
}

// TestAPostmanMethodCollidingWithAnOpenAPIStructuralKeyIsCountedNotSkipped.
//
// This is the specific silent-loss the conversion could cause and the reason
// the method check runs BEFORE the conversion: `parameters`, `summary`,
// `description`, `servers` and `$ref` are structural keys in an OpenAPI path
// item, so a collection whose request method is "servers" would be skipped as
// structure and never counted as an operation. A skipped operation shrinks the
// coverage denominator, which makes endpoint_coverage look better.
func TestAPostmanMethodCollidingWithAnOpenAPIStructuralKeyIsCountedNotSkipped(t *testing.T) {
	for _, method := range []string{"servers", "parameters", "summary", "description", "$ref"} {
		t.Run(method, func(t *testing.T) {
			doc := fmt.Sprintf(`{"info":{"name":"x",
			 "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
			 "item":[{"name":"sneak","request":{"method":%q,
			   "url":{"raw":"https://target.example.com/a"}}}]}`, method)
			fr := t1Ingest(t, "c.json", doc)
			if len(fr.Routes) != 0 {
				t.Fatalf("a method the kernel does not carry became a route: %v",
					t1RouteKeys(fr.Routes))
			}
			if fr.Seen != 1 {
				t.Fatalf("Seen is %d; the collection declared one operation and it must "+
					"be counted whether or not it could be represented", fr.Seen)
			}
			if !t1HasReason(fr.Refusals, RefusalMethodNotAllowlisted) {
				t.Fatalf("no %s row: %v", RefusalMethodNotAllowlisted, fr.Refusals)
			}
			if fr.DenominatorFloorFor() != 1 {
				t.Fatalf("the refused operation left the coverage denominator")
			}
		})
	}
}

// DenominatorFloorFor is a test-local restatement of the denominator rule, so
// the assertion above does not depend on IngestResult's own arithmetic to
// check IngestResult's own arithmetic.
func (f FileResult) DenominatorFloorFor() int {
	n := len(f.Routes)
	for _, r := range f.Refusals {
		if r.Reason.PerOperation() {
			n++
		}
	}
	return n
}

func TestAPostmanDuplicateOperationIsCountedNotCollapsed(t *testing.T) {
	const doc = `{"info":{"name":"x",
	 "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	 "item":[
	  {"name":"one","request":{"method":"GET","url":{"raw":"https://target.example.com/a"}}},
	  {"name":"two","request":{"method":"GET","url":{"raw":"https://target.example.com/a"}}}]}`
	fr := t1Ingest(t, "c.json", doc)
	if len(fr.Routes) != 1 {
		t.Fatalf("got %d routes", len(fr.Routes))
	}
	if fr.Seen != 2 {
		t.Fatalf("Seen is %d; the collection declared the operation twice and a JSON map "+
			"would have kept one silently", fr.Seen)
	}
	if !t1HasReason(fr.Refusals, RefusalDuplicateRoute) {
		t.Fatalf("no duplicate row: %v", fr.Refusals)
	}
}

func TestAPostmanVariableRefusesRatherThanInventingAnAddress(t *testing.T) {
	const doc = `{"info":{"name":"x",
	 "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	 "item":[{"name":"templated","request":{"method":"GET",
	   "url":{"raw":"{{baseUrl}}/api/{{version}}/users"}}}]}`
	fr := t1Ingest(t, "c.json", doc)
	if len(fr.Routes) != 0 {
		t.Fatalf("an unresolved Postman variable became the address %v",
			t1RouteKeys(fr.Routes))
	}
	if fr.Seen != 1 || !t1HasReason(fr.Refusals, RefusalPathRejectedByKernel) {
		t.Fatalf("seen=%d refusals=%v; the operation exists and Anvil has no address for "+
			"it, so it belongs in the denominator with a row", fr.Seen, fr.Refusals)
	}
}

// TestAGraphQLSchemaWithNoConfiguredEndpointStillCountsItsRootFields.
//
// A committed SDL document declares a schema and names no URL. The alternative
// to one refusal per root field would be one refusal for the whole document,
// which leaves the entire schema out of the coverage denominator — and a
// smaller denominator makes endpoint_coverage look BETTER.
func TestAGraphQLSchemaWithNoConfiguredEndpointStillCountsItsRootFields(t *testing.T) {
	cfg := t1Config(t)
	cfg.GraphQLEndpoint = ""
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"sdl", fixtureGraphQLSDL},
		{"introspection dump", fixtureIntrospectionJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr, err := IngestSpecFile(cfg, t1File(t, "schema", tc.content))
			if err != nil {
				t.Fatalf("IngestSpecFile: %v", err)
			}
			if err := fr.AssertAccountedFor(); err != nil {
				t.Fatalf("%v", err)
			}
			if len(fr.Routes) != 0 {
				t.Fatalf("routes were built with no endpoint to build them on: %v",
					t1RouteKeys(fr.Routes))
			}
			if fr.Seen != 4 {
				t.Fatalf("Seen is %d and the schema declares 4 root fields. A schema that "+
					"vanished from the denominator makes coverage look better than it is",
					fr.Seen)
			}
			if fr.DenominatorFloorFor() != 4 {
				t.Fatalf("the denominator floor is %d, want 4", fr.DenominatorFloorFor())
			}
		})
	}
	// And with an endpoint configured, the same schema becomes routes.
	fr := t1Ingest(t, "schema.graphql", fixtureGraphQLSDL)
	if len(fr.Routes) != 4 {
		t.Fatalf("with an endpoint configured the schema yields %d routes, want 4",
			len(fr.Routes))
	}
}

const fixtureIntrospectionJSON = `{"data":{"__schema":{
  "queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},
  "types":[
   {"kind":"OBJECT","name":"Query","fields":[
     {"name":"user","args":[{"name":"id","type":{"kind":"NON_NULL",
       "ofType":{"kind":"SCALAR","name":"ID"}}}]},
     {"name":"search","args":[]}]},
   {"kind":"OBJECT","name":"Mutation","fields":[
     {"name":"createUser","args":[]},{"name":"deleteUser","args":[]}]}]}}}`

// ===========================================================================
// THE BLOCK-YAML SUBSET
//
// Every case below is the SAME base document plus exactly one construct from
// outside the subset. The base is asserted to produce a route first, so a case
// that produces none is the construct being refused rather than the base
// having rotted.
// ===========================================================================

const yamlBase = `openapi: 3.0.3
info:
  title: Base
paths:
  /a:
    get:
      operationId: a
`

func TestTheYAMLBaseDocumentParses(t *testing.T) {
	fr := t1Ingest(t, "base.yaml", yamlBase)
	if len(fr.Routes) != 1 || fr.Routes[0].Operation() != "a" {
		t.Fatalf("the base fixture yields %v; every subset test below is the base plus "+
			"one hostile construct and would prove nothing if the base were already dead",
			t1RouteKeys(fr.Routes))
	}
}

func TestTheYAMLSubsetRefusesTheWholeDocumentOnAnythingOutsideIt(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"an anchor", "openapi: 3.0.3\ninfo: &base\n  title: Base\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"an alias", "openapi: 3.0.3\ninfo:\n  title: Base\nother: *base\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"a merge key", "openapi: 3.0.3\ninfo:\n  <<: defaults\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"a tag", "openapi: !!str 3.0.3\npaths:\n  /a:\n    get:\n      operationId: a\n"},
		{"a flow mapping", "openapi: 3.0.3\ninfo: {title: Base}\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"a flow sequence", "openapi: 3.0.3\ntags: [a, b]\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"an explicit key", "openapi: 3.0.3\n? info\n: Base\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"a tab in the indentation", "openapi: 3.0.3\ninfo:\n\ttitle: Base\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"a second document", yamlBase + "---\nopenapi: 3.0.3\npaths: {}\n"},
		{"a directive", "%YAML 1.2\n" + yamlBase},
		{"a duplicate key", yamlBase + "openapi: 3.1.0\n"},
		{"a block scalar with an indentation indicator",
			"openapi: 3.0.3\ninfo:\n  title: |2\n    Base\n" +
				"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"an unterminated quoted scalar", "openapi: 3.0.3\ninfo:\n  title: \"Base\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"an escape outside the allowlist", `openapi: 3.0.3` + "\ninfo:\n  title: \"a\\qb\"\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
		{"a reserved indicator", "openapi: 3.0.3\ninfo: @reserved\n" +
			"paths:\n  /a:\n    get:\n      operationId: a\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := t1Ingest(t, "hostile.yaml", tc.content)
			if len(fr.Routes) != 0 {
				t.Fatalf("%s produced %v. A document half-read is a shorter route list, "+
					"and a shorter route list is a smaller coverage denominator",
					tc.name, t1RouteKeys(fr.Routes))
			}
			if !t1HasReason(fr.Refusals, RefusalYAMLUnsupported) {
				t.Fatalf("%s was not refused by name: %v", tc.name, fr.Refusals)
			}
		})
	}
}

// TestTheYAMLReaderBuildsTheSameTreeAsTheEquivalentJSON. The subset reader is
// only useful if it agrees with a real parser on documents inside the subset;
// this pins that against encoding/json rather than against expectations.
func TestTheYAMLReaderBuildsTheSameTreeAsTheEquivalentJSON(t *testing.T) {
	const asYAML = `openapi: 3.0.3
info:
  title: Same
  enabled: true
  retired: false
  successor: null
  aliases:
    - one
    - two
servers:
  - url: https://target.example.com
    description: primary
paths:
  /a:
    get:
      operationId: a
`
	const asJSON = `{"openapi":"3.0.3",
	 "info":{"title":"Same","enabled":true,"retired":false,"successor":null,
	   "aliases":["one","two"]},
	 "servers":[{"url":"https://target.example.com","description":"primary"}],
	 "paths":{"/a":{"get":{"operationId":"a"}}}}`

	tree, err := yamlSubsetToTree([]byte(asYAML))
	if err != nil {
		t.Fatalf("yamlSubsetToTree: %v", err)
	}
	var want any
	if err := json.Unmarshal([]byte(asJSON), &want); err != nil {
		t.Fatalf("unmarshalling the JSON twin: %v", err)
	}
	// The one stated departure: every plain scalar is a string, so the JSON
	// twin is compared after re-encoding both through encoding/json.
	gotBytes, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("re-encoding the YAML tree: %v", err)
	}
	wantBytes, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("re-encoding the JSON twin: %v", err)
	}
	if string(gotBytes) != string(wantBytes) {
		t.Fatalf("the YAML reader built\n  %s\nand the equivalent JSON is\n  %s",
			gotBytes, wantBytes)
	}
}

// TestAnUnquotedSwaggerVersionIsNotResolvedToANumber pins the stated
// departure. YAML resolves `2.0` to a float; oasDoc.Swagger is a string, so a
// float would fail to decode and the whole document would be lost.
func TestAnUnquotedSwaggerVersionIsNotResolvedToANumber(t *testing.T) {
	const doc = `swagger: 2.0
basePath: /v1
paths:
  /a:
    get:
      operationId: a
      parameters:
        - name: q
          in: query
          type: string
`
	fr := t1Ingest(t, "swagger.yaml", doc)
	if fr.Format != FormatSwagger2YAML {
		t.Fatalf("format is %s, want %s", fr.Format, FormatSwagger2YAML)
	}
	if len(fr.Routes) != 1 || fr.Routes[0].Path() != "/v1/a" {
		t.Fatalf("routes are %v; an unquoted `swagger: 2.0` resolved to a number would "+
			"have lost the whole document", t1RouteKeys(fr.Routes))
	}
}

// TestBlockScalarsAreReadAndDoNotSwallowTheFollowingKey. A block scalar that
// over-consumed would eat `paths:` and produce an empty inventory with no row.
func TestBlockScalarsAreReadAndDoNotSwallowTheFollowingKey(t *testing.T) {
	cases := []struct {
		name  string
		style string
		want  string
	}{
		{"literal", "|", "line one\n  indented\n\nline two\n"},
		{"literal stripped", "|-", "line one\n  indented\n\nline two"},
		{"folded", ">", "line one\n  indented\nline two\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := "openapi: 3.0.3\ninfo:\n  description: " + tc.style +
				"\n    line one\n      indented\n\n    line two\n" +
				"paths:\n  /a:\n    get:\n      operationId: a\n"
			tree, err := yamlSubsetToTree([]byte(doc))
			if err != nil {
				t.Fatalf("yamlSubsetToTree: %v", err)
			}
			m, ok := tree.(map[string]any)
			if !ok {
				t.Fatalf("the tree is %T", tree)
			}
			if _, ok := m["paths"]; !ok {
				t.Fatalf("the block scalar swallowed `paths`; the document became %v", m)
			}
			info, _ := m["info"].(map[string]any)
			if got := info["description"]; got != tc.want {
				t.Fatalf("description is %q, want %q", got, tc.want)
			}
			fr := t1Ingest(t, "b.yaml", doc)
			if len(fr.Routes) != 1 {
				t.Fatalf("the document yields %v", t1RouteKeys(fr.Routes))
			}
		})
	}
}

func TestTheYAMLBoundsAreEnforced(t *testing.T) {
	deep := "openapi: 3.0.3\nx:\n"
	for i := 1; i <= maxYAMLDepth+4; i++ {
		deep += strings.Repeat(" ", i*2) + "y:\n"
	}
	fr := t1Ingest(t, "deep.yaml", deep)
	if len(fr.Routes) != 0 || !t1HasReason(fr.Refusals, RefusalYAMLUnsupported) {
		t.Fatalf("a document nested past the coded bound was not refused: %v", fr.Refusals)
	}
}

// ===========================================================================
// THE HOSTILE-HARVEST CORPUS
//
// A relation test in this repository swept 393,226 addresses and stayed green
// over a live bug because its generator emitted no zoned addresses. So the
// generator is tested FIRST: TestTheTier1GeneratorCanProduceEveryBreakingInput
// fails if the corpus stops REACHING a hazard class, judged by what came back
// rather than by what the fixture author intended, and only then does the
// sweep assert invariants over it.
// ===========================================================================

type t1Hazard string

const (
	t1HazForeignOrigin    t1Hazard = "a committed file naming an origin that is not the target"
	t1HazYAMLOutside      t1Hazard = "a YAML construct outside the subset"
	t1HazPostmanVariable  t1Hazard = "a Postman URL with an unresolved variable"
	t1HazStructuralMethod t1Hazard = "a request method that collides with an OpenAPI structural key"
	t1HazDuplicate        t1Hazard = "the same operation declared twice"
	t1HazBadPath          t1Hazard = "a path the kernel refuses"
	t1HazUnusableParam    t1Hazard = "a parameter that could not be named or typed"
	t1HazUnaddressable    t1Hazard = "a schema with no address to reach it on"
	t1HazRefusedByName    t1Hazard = "a format recognised and refused by name"
	t1HazUnreadableBytes  t1Hazard = "bytes that are no spec this tier reads"
	t1HazUnresolvedRef    t1Hazard = "a WSDL cross-reference that resolves to nothing"
	t1HazTruncated        t1Hazard = "a document past a coded bound"
)

type t1Fixture struct {
	name      string
	content   string
	gql       string
	hazards   []t1Hazard
	routeless bool
}

// everyTier1Fixture is the whole corpus: the five good fixtures the packet
// names, plus every hostile shape. It is deterministic and enumerated rather
// than random, because a fuzz seed that stops reaching a case is a silent loss
// of coverage and this list is reviewable in a diff.
func everyTier1Fixture() []t1Fixture {
	longName := strings.Repeat("n", maxIdentBytes+64)
	return []t1Fixture{
		{name: "openapi.yaml", content: fixtureOpenAPIYAML, gql: t1GraphQLEndpoint},
		{name: "swagger.json", content: fixtureSwaggerJSON, gql: t1GraphQLEndpoint},
		{name: "quote.wsdl", content: fixtureWSDL, gql: t1GraphQLEndpoint},
		{name: "schema.graphql", content: fixtureGraphQLSDL, gql: t1GraphQLEndpoint},
		{name: "collection.json", content: fixturePostman, gql: t1GraphQLEndpoint},
		{name: "introspection.json", content: fixtureIntrospectionJSON, gql: t1GraphQLEndpoint},

		{name: "openapi servers name the metadata endpoint",
			content: fixtureOpenAPIForeignServers, gql: t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazForeignOrigin}},
		{name: "wsdl address names the metadata endpoint",
			content: fixtureWSDLForeignAddress, gql: t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazForeignOrigin}},
		{name: "postman host is the metadata endpoint",
			content: fixturePostmanForeignHost, gql: t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazForeignOrigin}},

		{name: "yaml with an anchor",
			content: "openapi: 3.0.3\ninfo: &b\n  title: x\npaths:\n  /a:\n    get: {}\n",
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazYAMLOutside}, routeless: true},
		{name: "yaml with a tab",
			content: "openapi: 3.0.3\ninfo:\n\ttitle: x\npaths:\n  /a:\n    get:\n" +
				"      operationId: a\n",
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazYAMLOutside}, routeless: true},

		{name: "postman with an unresolved variable",
			content: `{"info":{"name":"x","schema":"https://schema.getpostman.com/json/` +
				`collection/v2.1.0/collection.json"},"item":[{"name":"t","request":` +
				`{"method":"GET","url":{"raw":"{{baseUrl}}/api/users"}}}]}`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazPostmanVariable, t1HazBadPath}, routeless: true},
		{name: "postman method collides with a structural key",
			content: `{"info":{"name":"x","schema":"https://schema.getpostman.com/json/` +
				`collection/v2.1.0/collection.json"},"item":[
				{"name":"a","request":{"method":"servers","url":{"raw":"https://target.example.com/a"}}},
				{"name":"b","request":{"method":"GET","url":{"raw":"https://target.example.com/b"}}},
				{"name":"c","request":{"method":"GET","url":{"raw":"https://target.example.com/b"}}}]}`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazStructuralMethod, t1HazDuplicate}},

		{name: "openapi with paths the kernel refuses",
			content: `{"openapi":"3.0.3","paths":{
				"relative":{"get":{}},
				"/with space":{"get":{}},
				"/a/../b":{"get":{}},
				"/ok":{"get":{"operationId":"ok"}}}}`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazBadPath}},
		{name: "openapi with parameters that cannot be represented",
			content: `{"openapi":"3.0.3","paths":{
				"/ref":{"get":{"parameters":[{"$ref":"#/components/parameters/P"}]}},
				"/badin":{"get":{"parameters":[{"name":"x","in":"matrix"}]}},
				"/long":{"get":{"operationId":"long","parameters":[
					{"name":"` + longName + `","in":"query","schema":{"type":"string"}}]}}}}`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazUnusableParam}},

		{name: "wsdl part with no name",
			content: `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
				xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tns="urn:x">
				<message name="In"><part type="xsd:string"/></message>
				<portType name="P"><operation name="Op"><input message="tns:In"/></operation></portType>
				<binding name="B" type="tns:P"/>
				<service name="S"><port name="Prt" binding="tns:B">
				<soap:address location="https://target.example.com/soap"/></port></service>
				</definitions>`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazUnusableParam}, routeless: true},
		{name: "wsdl port names a binding that does not exist",
			content: `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
				xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tns="urn:x">
				<portType name="P"><operation name="Op"/></portType>
				<service name="S"><port name="Prt" binding="tns:Missing">
				<soap:address location="https://target.example.com/soap"/></port></service>
				</definitions>`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazUnresolvedRef}, routeless: true},
		{name: "wsdl port declares no address",
			content: `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
				xmlns:tns="urn:x">
				<portType name="P"><operation name="Op"/></portType>
				<binding name="B" type="tns:P"/>
				<service name="S"><port name="Prt" binding="tns:B"/></service>
				</definitions>`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazBadPath}, routeless: true},

		{name: "graphql sdl with no configured endpoint",
			content: fixtureGraphQLSDL, gql: "",
			hazards: []t1Hazard{t1HazUnaddressable, t1HazBadPath}, routeless: true},

		{name: "asyncapi",
			content: `{"asyncapi":"2.6.0","channels":{"user/signedup":{"subscribe":{}}}}`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazRefusedByName}, routeless: true},
		{name: "asyncapi in yaml",
			content:   "asyncapi: 2.6.0\nchannels:\n  user/signedup:\n    subscribe: {}\n",
			gql:       t1GraphQLEndpoint,
			hazards:   []t1Hazard{t1HazRefusedByName},
			routeless: true},
		{name: "wsdl 2.0",
			content: `<description xmlns="http://www.w3.org/ns/wsdl"/>`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazRefusedByName}, routeless: true},

		{name: "bytes that are no spec at all",
			content: "this is a README, not a spec.\n", gql: t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazUnreadableBytes}, routeless: true},
		{name: "json that is no spec at all",
			content: `{"name":"package","dependencies":{}}`, gql: t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazUnreadableBytes}, routeless: true},
		{name: "xml that is no spec at all",
			content: `<project><modelVersion>4.0.0</modelVersion></project>`,
			gql:     t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazUnreadableBytes}, routeless: true},
		{name: "a spec body that does not parse",
			content: `{"openapi":"3.0.3","paths":{`, gql: t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazUnreadableBytes}, routeless: true},

		{name: "postman past the item bound",
			content: manyPostmanItems(maxPostmanItems + 8), gql: t1GraphQLEndpoint,
			hazards: []t1Hazard{t1HazTruncated}},

		{name: "an openapi document that declares nothing",
			content: `{"openapi":"3.0.3","paths":{}}`, gql: t1GraphQLEndpoint,
			routeless: true},
		{name: "an openapi document whose paths is an array",
			content: `{"openapi":"3.0.3","paths":[1,2,3]}`, gql: t1GraphQLEndpoint,
			routeless: true},
		{name: "a graphql sdl with no root types",
			content: "type User {\n  id: ID!\n}\n", gql: t1GraphQLEndpoint,
			routeless: true},
	}
}

func manyPostmanItems(n int) string {
	var b strings.Builder
	b.WriteString(`{"info":{"name":"x","schema":"https://schema.getpostman.com/json/`)
	b.WriteString(`collection/v2.1.0/collection.json"},"item":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":"i%d","request":{"method":"GET","url":`+
			`{"raw":"https://target.example.com/p%d"}}}`, i, i)
	}
	b.WriteString("]}")
	return b.String()
}

// t1Classify reports which hazards an ingest of fx actually EXERCISED, judged
// by what came back. A hazard the parsers silently tolerated is not exercised,
// and this is what notices.
func t1Classify(t *testing.T, fx t1Fixture) (FileResult, map[t1Hazard]bool) {
	t.Helper()
	cfg := t1Config(t)
	cfg.GraphQLEndpoint = fx.gql
	fr, err := IngestSpecFile(cfg, t1File(t, fx.name, fx.content))
	if err != nil {
		t.Fatalf("%s: IngestSpecFile: %v", fx.name, err)
	}
	got := map[t1Hazard]bool{}
	if fr.DeclaredForeignOrigin {
		got[t1HazForeignOrigin] = true
	}
	if fr.Truncated {
		got[t1HazTruncated] = true
	}
	for _, r := range fr.Refusals {
		switch r.Reason {
		case RefusalYAMLUnsupported:
			got[t1HazYAMLOutside] = true
		case RefusalMethodNotAllowlisted:
			got[t1HazStructuralMethod] = true
		case RefusalDuplicateRoute:
			got[t1HazDuplicate] = true
		case RefusalParamUnusable:
			got[t1HazUnusableParam] = true
		case RefusalSpecTruncated:
			got[t1HazTruncated] = true
		case RefusalFormatUnrecognised:
			if strings.Contains(r.Detail, "AsyncAPI") || strings.Contains(r.Detail, "WSDL 2.0") {
				got[t1HazRefusedByName] = true
			} else {
				got[t1HazUnreadableBytes] = true
			}
		case RefusalSpecUnparseable:
			if strings.Contains(r.Detail, "declares no such") {
				got[t1HazUnresolvedRef] = true
			} else {
				got[t1HazUnreadableBytes] = true
			}
		case RefusalPathRejectedByKernel:
			got[t1HazBadPath] = true
			if strings.Contains(r.Detail, "Postman variable") {
				got[t1HazPostmanVariable] = true
			}
			if strings.Contains(r.Detail, "no GraphQL endpoint is configured") ||
				strings.Contains(r.Detail, "No GraphQL endpoint is configured") {
				got[t1HazUnaddressable] = true
			}
		}
	}
	return fr, got
}

// TestTheTier1GeneratorCanProduceEveryBreakingInput runs BEFORE the sweep
// believes anything the sweep says.
func TestTheTier1GeneratorCanProduceEveryBreakingInput(t *testing.T) {
	all := map[t1Hazard]bool{}
	for _, fx := range everyTier1Fixture() {
		_, got := t1Classify(t, fx)
		for _, want := range fx.hazards {
			if !got[want] {
				t.Errorf("corpus entry %q claims to exercise %q and the ingest did not "+
					"report it. A generator that cannot produce the breaking input is the "+
					"defect, not the sweep that stayed green", fx.name, want)
			}
		}
		for h := range got {
			all[h] = true
		}
	}
	every := []t1Hazard{
		t1HazForeignOrigin, t1HazYAMLOutside, t1HazPostmanVariable, t1HazStructuralMethod,
		t1HazDuplicate, t1HazBadPath, t1HazUnusableParam, t1HazUnaddressable,
		t1HazRefusedByName, t1HazUnreadableBytes, t1HazUnresolvedRef, t1HazTruncated,
	}
	for _, h := range every {
		if !all[h] {
			t.Errorf("no corpus entry exercises %q. The sweep below would be green over a "+
				"live bug in exactly that case", h)
		}
	}
}

// TestTheHostileHarvestHoldsEveryInvariant is the sweep.
func TestTheHostileHarvestHoldsEveryInvariant(t *testing.T) {
	tgt := mustBareTarget(t)
	for _, fx := range everyTier1Fixture() {
		t.Run(fx.name, func(t *testing.T) {
			fr, _ := t1Classify(t, fx)
			if err := fr.AssertAccountedFor(); err != nil {
				t.Fatalf("%v", err)
			}
			for _, r := range fr.Routes {
				if !r.Constructed() {
					t.Fatalf("an unconstructed Route reached the output: %v", r)
				}
				if r.Provenance() != record.InventoryProvenanceRepoSpec {
					t.Fatalf("route %s is not repo_spec", r)
				}
				if r.Confirmation() != ConfirmationCandidate {
					t.Fatalf("route %s is not a candidate", r)
				}
				if r.Trust() != record.TrustUntrusted {
					t.Fatalf("route %s is not untrusted", r)
				}
				if r.Target() != tgt {
					t.Fatalf("route %s moved off the pinned target", r)
				}
				if err := kernelAcceptsPath(tgt, r.Method(), r.Path()); err != nil {
					t.Fatalf("route %s carries a path the kernel refuses: %v", r, err)
				}
				for _, p := range r.Params() {
					if p.Name == "" || !p.In.Valid() {
						t.Fatalf("route %s carries an unusable parameter %#v", r, p)
					}
					if len(p.Name) > maxIdentBytes || len(p.Type) > maxIdentBytes {
						t.Fatalf("route %s carries an unbounded identifier", r)
					}
				}
			}
			for _, ref := range fr.Refusals {
				if !ref.Valid() {
					t.Fatalf("a refusal carries an unrecognised reason: %#v", ref)
				}
			}
			seen := map[string]bool{}
			for _, r := range fr.Routes {
				if seen[r.Key()] {
					t.Fatalf("two routes share the identity %q; the Tier 0-2 union would "+
						"count this endpoint twice", r.Key())
				}
				seen[r.Key()] = true
			}
			if fx.routeless && len(fr.Routes) > 0 {
				t.Fatalf("%q is marked routeless and produced %v", fx.name,
					t1RouteKeys(fr.Routes))
			}
		})
	}
}

// TestARefusedOperationStaysInTheCoverageDenominator. An operation this tier
// saw and could not represent is attack surface that exists; leaving it out
// shrinks the denominator, and a smaller denominator makes endpoint_coverage
// look BETTER.
func TestATier1RefusedOperationStaysInTheCoverageDenominator(t *testing.T) {
	const doc = `{"openapi":"3.0.3","paths":{
		"relative":{"get":{}},
		"/a/../b":{"get":{}},
		"/ok":{"get":{"operationId":"ok"}}}}`
	res, err := IngestRepoSpecs(t1Config(t), []SpecFile{t1File(t, "o.json", doc)})
	if err != nil {
		t.Fatalf("IngestRepoSpecs: %v", err)
	}
	if len(res.Routes()) != 1 {
		t.Fatalf("got %d routes", len(res.Routes()))
	}
	if res.Seen() != 3 {
		t.Fatalf("Seen is %d and the document declares three operations", res.Seen())
	}
	if res.DenominatorFloor() != 3 {
		t.Fatalf("DenominatorFloor is %d and the document declares three operations. "+
			"Dropping the two Anvil could not represent would make coverage of this "+
			"repository read as 1/1", res.DenominatorFloor())
	}
}

// ===========================================================================
// AN EMPTY TIER 1 INVENTORY HAS THREE MEANINGS
// ===========================================================================

func TestAnEmptyTier1InventoryIsNotAllowedToLookLikeASpeclessRepository(t *testing.T) {
	unreadable := "this is a README, not a spec.\n"
	cases := []struct {
		name      string
		harvest   HarvestOutcome
		files     []string
		wantError bool
		why       string
	}{
		{name: "the harvest ran and the repository ships no spec files",
			harvest: HarvestRan, wantError: false,
			why: "a reportable fact about the repository"},
		{name: "the harvest never ran",
			harvest: HarvestSkipped, wantError: true,
			why: "a fact about Anvil, and it must not become a denominator"},
		{name: "files arrived and none was readable",
			harvest: HarvestRan, files: []string{unreadable, unreadable},
			wantError: true,
			why:       "a fact about Anvil's reach, not the repository's surface"},
		{name: "the harvest was skipped and files arrived anyway",
			harvest: HarvestSkipped, files: []string{fixtureSwaggerJSON},
			wantError: false,
			why:       "routes were extracted, so the inventory is not empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := t1Config(t)
			cfg.Harvest = tc.harvest
			files := make([]SpecFile, 0, len(tc.files))
			for i, c := range tc.files {
				files = append(files, t1File(t, fmt.Sprintf("f%d", i), c))
			}
			res, err := IngestRepoSpecs(cfg, files)
			if err != nil {
				t.Fatalf("IngestRepoSpecs: %v", err)
			}
			got := res.AssertNotSilentlyEmpty()
			if tc.wantError && got == nil {
				t.Fatalf("AssertNotSilentlyEmpty accepted %q, which is %s", tc.name, tc.why)
			}
			if !tc.wantError && got != nil {
				t.Fatalf("AssertNotSilentlyEmpty refused %q, which is %s: %v",
					tc.name, tc.why, got)
			}
			if tc.wantError && !errors.Is(got, ErrNothingIngested) {
				t.Fatalf("the refusal does not unwrap to ErrNothingIngested: %v", got)
			}
		})
	}
}

func TestAnUnsetHarvestOutcomeIsRefusedRatherThanDefaulted(t *testing.T) {
	cfg := t1Config(t)
	cfg.Harvest = HarvestOutcomeUnset
	if _, err := IngestRepoSpecs(cfg, nil); err == nil {
		t.Fatal("IngestRepoSpecs accepted an unset harvest outcome. An empty file slice " +
			"means one thing under harvest_ran and the opposite under harvest_skipped, " +
			"and a Go zero value must never pick the permissive one")
	}
	if _, err := IngestSpecFile(cfg, t1File(t, "a.json", fixtureSwaggerJSON)); err == nil {
		t.Fatal("IngestSpecFile accepted an unset harvest outcome")
	}
	if cfg.Constructed() {
		t.Fatal("IngestConfig.Constructed accepted an unset harvest outcome")
	}
	if HarvestOutcomeUnset.Valid() {
		t.Fatal("the zero HarvestOutcome reports itself valid")
	}
}

func TestAnIngestRefusesEveryHalfBuiltInput(t *testing.T) {
	good := t1File(t, "a.json", fixtureSwaggerJSON)
	cases := []struct {
		name string
		cfg  IngestConfig
	}{
		{"a Target the kernel never built",
			IngestConfig{Harvest: HarvestRan}},
		{"a harvest outcome nobody set",
			IngestConfig{Target: mustBareTarget(t)}},
		{"a harvest outcome nobody enumerated",
			IngestConfig{Target: mustBareTarget(t), Harvest: HarvestOutcome("probably_ran")}},
		{"a GraphQL endpoint the kernel refuses",
			IngestConfig{Target: mustBareTarget(t), Harvest: HarvestRan,
				GraphQLEndpoint: "graphql"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := IngestRepoSpecs(tc.cfg, []SpecFile{good}); err == nil {
				t.Fatalf("IngestRepoSpecs accepted %s", tc.name)
			}
		})
	}
	// An unconstructed SpecFile inside the slice must not lose the rest of the
	// harvest, and must not vanish either.
	res, err := IngestRepoSpecs(t1Config(t), []SpecFile{{}, good})
	if err != nil {
		t.Fatalf("IngestRepoSpecs: %v", err)
	}
	if len(res.Routes()) != 2 {
		t.Fatalf("the zero SpecFile took the rest of the harvest with it: %v",
			t1RouteKeys(res.Routes()))
	}
	if len(res.Refusals()) == 0 {
		t.Fatal("the zero SpecFile vanished without a row")
	}
}

func TestNewSpecFileRefusesEveryHalfBuiltFile(t *testing.T) {
	big := strings.Repeat("x", maxSpecFileBytes+1)
	cases := []struct {
		name  string
		facts SpecFileFacts
	}{
		{"no uri", SpecFileFacts{Content: record.ArtifactContent{Text: "{}"}}},
		{"no content", SpecFileFacts{Location: record.ArtifactLocation{URI: "a.json"}}},
		{"a uri past the bound", SpecFileFacts{
			Location: record.ArtifactLocation{URI: strings.Repeat("a", maxSpecURIBytes+1)},
			Content:  record.ArtifactContent{Text: "{}"}}},
		{"a uri carrying a control byte", SpecFileFacts{
			Location: record.ArtifactLocation{URI: "a\nb.json"},
			Content:  record.ArtifactContent{Text: "{}"}}},
		{"content past the bound", SpecFileFacts{
			Location: record.ArtifactLocation{URI: "a.json"},
			Content:  record.ArtifactContent{Text: big}}},
		{"a declared format nobody enumerated", SpecFileFacts{
			Location:       record.ArtifactLocation{URI: "a.json"},
			Content:        record.ArtifactContent{Text: "{}"},
			DeclaredFormat: SpecFormat("openapi9")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSpecFile(tc.facts); err == nil {
				t.Fatalf("NewSpecFile accepted %s", tc.name)
			}
		})
	}
	if (SpecFile{}).Constructed() {
		t.Fatal("the zero SpecFile reports itself constructed")
	}
	if got := (SpecFile{}).Trust(); got != record.TrustUntrusted {
		t.Fatalf("even the zero SpecFile must report %q, because the answer never depends "+
			"on a field: got %q", record.TrustUntrusted, got)
	}
}

// ===========================================================================
// COPY DISCIPLINE
//
// A test that mutates only the field where the copy is real proves nothing.
// Every reference field of every type this packet adds is mutated here, and
// the reflection guards below fail when a new one appears.
// ===========================================================================

var specFileAllFields = map[string]string{
	"uri":       "a string; immutable",
	"uriBaseID": "a string; immutable",
	"index":     "a *int from record.ArtifactLocation; DEEP-COPIED in and out",
	"content":   "a string; immutable",
	"declared":  "a SpecFormat, which is a string; immutable",
	"sealed":    "a bool; immutable",
}

var specFileReferenceFields = map[string]string{
	"index": "copyIntPtr on the way in and on the way out",
}

var ingestResultAllFields = map[string]string{
	"routes":   "cloned by cloneRoutes, which deep-copies each Route's params",
	"refusals": "cloned by cloneRefusals; Refusal is plain data",
	"files":    "cloned by cloneFileResults, which clones routes, refusals and Location.Index",
	"harvest":  "a HarvestOutcome, which is a string; immutable",
	"offered":  "an int; immutable",
	"ingested": "an int; immutable",
	"seen":     "an int; immutable",
	"truncate": "a bool; immutable",
	"sealed":   "a bool; immutable",
}

var ingestResultReferenceFields = map[string]string{
	"routes": "cloneRoutes", "refusals": "cloneRefusals", "files": "cloneFileResults",
}

var fileResultAllFields = map[string]string{
	"ParseResult":            "D.18's, embedded; its Routes and Refusals are cloned by cloneFileResults",
	"Location":               "a record.ArtifactLocation; its Index pointer is deep-copied",
	"DeclaredFormat":         "a SpecFormat, which is a string; immutable",
	"DeclaredFormatDiverged": "a bool; immutable",
}

func TestEveryReferenceFieldOfTheTier1TypesIsAccountedFor(t *testing.T) {
	check := func(name string, typ reflect.Type, all, refs map[string]string) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if _, known := all[f.Name]; !known {
				t.Errorf(`%s has a field %q (%s) that this guard has never heard of.

Add it to the field map with a phrase saying why it is safe to copy shallowly,
and — if it is a slice, map, pointer, channel, function or interface — add it to
the reference map AND write a mutation test for it. A copy test that exercises
only the fields somebody remembered is how this repository shipped an aliasing
bug twice, in two different packages.`, name, f.Name, f.Type)
				continue
			}
			switch f.Type.Kind() {
			case reflect.Slice, reflect.Map, reflect.Ptr, reflect.Chan,
				reflect.Func, reflect.Interface, reflect.UnsafePointer:
				if _, ok := refs[f.Name]; !ok {
					t.Errorf("%s.%s is a %s — a reference — and is not on the copy "+
						"allowlist, so two values would share it and a caller could edit "+
						"the inventory through the copy", name, f.Name, f.Type.Kind())
				}
			}
		}
		if len(all) != typ.NumField() {
			t.Errorf("the guard for %s lists %d fields and the type has %d; a field was "+
				"removed and the guard now describes a type that no longer exists",
				name, len(all), typ.NumField())
		}
	}
	check("SpecFile", reflect.TypeOf(SpecFile{}), specFileAllFields, specFileReferenceFields)
	check("IngestResult", reflect.TypeOf(IngestResult{}),
		ingestResultAllFields, ingestResultReferenceFields)
	check("FileResult", reflect.TypeOf(FileResult{}), fileResultAllFields,
		map[string]string{})

	// FileResult is a value type with exported fields, handed out by
	// IngestResult.Files() as a deep copy. Its two reference-bearing members
	// are inside ParseResult and Location; if either grows another, the guards
	// below stop describing the type.
	loc := reflect.TypeOf(record.ArtifactLocation{})
	refs := 0
	for i := 0; i < loc.NumField(); i++ {
		if loc.Field(i).Type.Kind() == reflect.Ptr {
			refs++
			if loc.Field(i).Name != "Index" {
				t.Errorf("record.ArtifactLocation has a new pointer field %q and "+
					"cloneFileResults deep-copies only Index", loc.Field(i).Name)
			}
		}
	}
	if refs != 1 {
		t.Errorf("record.ArtifactLocation has %d pointer fields and this packet copies 1",
			refs)
	}
	pr := reflect.TypeOf(ParseResult{})
	for i := 0; i < pr.NumField(); i++ {
		switch pr.Field(i).Type.Kind() {
		case reflect.Slice:
			switch pr.Field(i).Name {
			case "Routes", "Refusals":
			default:
				t.Errorf("ParseResult has a new slice field %q and cloneFileResults "+
					"clones only Routes and Refusals", pr.Field(i).Name)
			}
		case reflect.Map, reflect.Ptr, reflect.Chan, reflect.Func, reflect.Interface:
			t.Errorf("ParseResult.%s is a %s and cloneFileResults does not copy it",
				pr.Field(i).Name, pr.Field(i).Type.Kind())
		}
	}
}

func TestSpecFileCopiesItsArtifactIndexInAndOut(t *testing.T) {
	idx := 7
	f, err := NewSpecFile(SpecFileFacts{
		Location: record.ArtifactLocation{URI: "a.json", URIBaseID: "%SRCROOT%", Index: &idx},
		Content:  record.ArtifactContent{Text: "{}"},
	})
	if err != nil {
		t.Fatalf("NewSpecFile: %v", err)
	}
	// 1. The caller's pointer, written through after construction.
	idx = 99
	if got := f.Location(); got.Index == nil || *got.Index != 7 {
		t.Fatalf("NewSpecFile retained the caller's pointer: %v", got.Index)
	}
	// 2. The pointer the accessor hands out.
	out := f.Location()
	*out.Index = 42
	if got := f.Location(); *got.Index != 7 {
		t.Fatalf("Location() aliases the file's own pointer: %d", *got.Index)
	}
	// 3. Through a copy of the SpecFile value itself.
	dup := f
	*dup.Location().Index = 11
	if *f.Location().Index != 7 {
		t.Fatal("a copied SpecFile shares its index pointer with the original")
	}
	if got := f.Location().URIBaseID; got != "%SRCROOT%" {
		t.Fatalf("uriBaseId was not carried: %q", got)
	}
}

func TestIngestResultAccessorsHandOutCopies(t *testing.T) {
	idx := 3
	f, err := NewSpecFile(SpecFileFacts{
		Location: record.ArtifactLocation{URI: "a.json", Index: &idx},
		Content:  record.ArtifactContent{Text: fixtureSwaggerJSON},
	})
	if err != nil {
		t.Fatalf("NewSpecFile: %v", err)
	}
	res, err := IngestRepoSpecs(t1Config(t), []SpecFile{f})
	if err != nil {
		t.Fatalf("IngestRepoSpecs: %v", err)
	}
	before := t1RouteKeys(res.Routes())

	// Routes: the slice, the elements, and each element's params.
	rs := res.Routes()
	rs[0] = Route{}
	rs = append(rs, Route{})
	if after := t1RouteKeys(res.Routes()); !reflect.DeepEqual(after, before) {
		t.Fatalf("Routes() aliases the result's own slice: %v vs %v", after, before)
	}
	rs2 := res.Routes()
	if len(rs2[0].params) > 0 {
		rs2[0].params[0].Name = "MUTATED"
		if res.Routes()[0].Params()[0].Name == "MUTATED" {
			t.Fatal("Routes() copied the parameter slice header and not the elements")
		}
	}

	// Refusals.
	refs := res.Refusals()
	refs = append(refs, Refusal{Reason: RefusalDuplicateRoute})
	if len(res.Refusals()) == len(refs) {
		t.Fatal("Refusals() aliases the result's own slice")
	}

	// Files: the slice, each file's routes and refusals, and Location.Index.
	fs := res.Files()
	if len(fs) != 1 {
		t.Fatalf("got %d file results", len(fs))
	}
	fs[0].Routes[0] = Route{}
	fs[0].Refusals = append(fs[0].Refusals, Refusal{Reason: RefusalDuplicateRoute})
	if fs[0].Location.Index != nil {
		*fs[0].Location.Index = 999
	}
	again := res.Files()
	if !again[0].Routes[0].Constructed() {
		t.Fatal("Files() aliases each file's route slice")
	}
	if again[0].Location.Index == nil || *again[0].Location.Index != 3 {
		t.Fatalf("Files() aliases the artifact index pointer: %v", again[0].Location.Index)
	}
	if loc, ok := res.SourceOf(again[0].Routes[0].Key()); !ok {
		t.Fatal("SourceOf did not find the file a route came from")
	} else {
		if loc.Index != nil {
			*loc.Index = 555
		}
		if l2, _ := res.SourceOf(again[0].Routes[0].Key()); *l2.Index != 3 {
			t.Fatal("SourceOf aliases the artifact index pointer")
		}
		if loc.URI != "a.json" {
			t.Fatalf("SourceOf named %q", loc.URI)
		}
	}
}

func TestSpecFileBytesAreCopiedNotAliased(t *testing.T) {
	f := t1File(t, "a.json", `{"openapi":"3.0.3","paths":{}}`)
	b := f.Bytes()
	b[0] = 'X'
	if f.Bytes()[0] != '{' {
		t.Fatal("Bytes() hands out the file's own backing array")
	}
}

// ===========================================================================
// THIS TIER CANNOT HARVEST, AND THE GUARD IS STRUCTURAL
//
// plan/50-dast.md:628-630: "Do not have this step or its dependents re-derive
// spec harvesting from the repo directly — that is explicitly the SAST tier's
// job." A comment saying so is not a control. Both halves below are
// ALLOWLISTS, so the filesystem package nobody thought to ban and the glob
// nobody thought to ban are caught by default rather than by memory.
// ===========================================================================

const tier1File = "tier1_repospec.go"

// tier1AllowedImports is every package the implementation may import. Adding
// one is a deliberate edit to this list, and there is no entry through which a
// file can be opened or a socket constructed.
func tier1AllowedImports() map[string]bool {
	return map[string]bool{
		"encoding/json": true,
		"encoding/xml":  true,
		"errors":        true,
		"fmt":           true,
		"sort":          true,
		"strings":       true,
		"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz": true,
		"github.com/Susquehanna-Syntax/Anvil/internal/record":     true,
	}
}

func TestTier1KnowsNoRepositoryPathAndOpensNothing(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, tier1File, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v. This guard cannot report a clean file it could not read",
			tier1File, err)
	}

	allowed := tier1AllowedImports()
	if len(f.Imports) == 0 {
		t.Fatalf("%s imports nothing, so the import half of this guard is measuring "+
			"nothing", tier1File)
	}
	for _, imp := range f.Imports {
		path, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			t.Fatalf("unquoting an import path: %v", uerr)
		}
		if !allowed[path] {
			t.Errorf(`%s imports %q, which is not on the allowlist.

Tier 1 consumes what the SAST pass already harvested. It must not be able to
open a file, walk a directory or construct a socket — os, io/fs, path/filepath,
os/exec, net and net/http are all absent by DEFAULT here rather than by a list
of banned packages. If this import is genuinely inert, add it to
tier1AllowedImports with a reason.`, tier1File, path)
		}
	}

	found, hits := scanForPathLiterals(t, fset, f)
	if found == 0 {
		t.Fatalf("the scanner found ZERO string literals in %s, so it is measuring "+
			"nothing. A guard that reports clean because it could not see is worse than "+
			"no guard", tier1File)
	}
	for _, h := range hits {
		t.Errorf(`%s contains the path literal %q.

A repository path or a request path in this file is either a hard-coded harvest
glob — which is the SAST tier's job and this step's Forbidden action — or a
hard-coded default endpoint. Exactly one slash-leading literal is permitted,
"/" itself, so a convention nobody has heard of is caught by default.`, h.where, h.value)
	}
}

type pathLiteralHit struct {
	where string
	value string
}

func scanForPathLiterals(t *testing.T, fset *token.FileSet, f *ast.File) (int, []pathLiteralHit) {
	t.Helper()
	found := 0
	var hits []pathLiteralHit
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		found++
		if strings.HasPrefix(v, "/") && len(v) > 1 {
			hits = append(hits, pathLiteralHit{fset.Position(lit.Pos()).String(), v})
		}
		return true
	})
	return found, hits
}

// TestTheTier1StructuralScannersCanSeeAViolation. Both guards above are only
// answers if they can go red; this proves the detection on fixtures rather
// than on the real file.
func TestTheTier1StructuralScannersCanSeeAViolation(t *testing.T) {
	src := "package p\n\n" +
		"import (\n\t\"os\"\n\t\"path/filepath\"\n\t\"strings\"\n)\n\n" +
		"var globs = []string{\"/repo/openapi.yaml\", \"/repo/schema.graphql\"}\n" +
		"var sep = \"/\"\n" +
		"var _ = os.Open\nvar _ = filepath.Walk\nvar _ = strings.TrimSpace\n"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the fixture: %v", err)
	}

	allowed := tier1AllowedImports()
	var banned []string
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if !allowed[p] {
			banned = append(banned, p)
		}
	}
	sort.Strings(banned)
	if want := []string{"os", "path/filepath"}; !reflect.DeepEqual(banned, want) {
		t.Fatalf("the import guard flagged %v on a fixture that imports %v, and it must "+
			"also leave an allowlisted import alone", banned, want)
	}

	_, hits := scanForPathLiterals(t, fset, f)
	var values []string
	for _, h := range hits {
		values = append(values, h.value)
	}
	sort.Strings(values)
	if want := []string{"/repo/openapi.yaml", "/repo/schema.graphql"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("the literal scanner found %v on a fixture that hard-codes %v, and it "+
			"must also leave the bare separator alone", values, want)
	}
}

// TestTier1ContainsNoSkip. The packet's standing rule is that an unprovable
// control is written down in internal/SKIPPED-CONTROLS.md, never turned into a
// t.Skip. Tier 1 issues no request and has nothing unprovable in it, so the
// rule reduces to a scan.
func TestTier1ContainsNoSkip(t *testing.T) {
	for _, file := range []string{tier1File, "tier1_repospec_test.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Skip", "Skipf", "SkipNow":
				t.Errorf("%s calls t.%s at %s. An unprovable control is written down in "+
					"internal/SKIPPED-CONTROLS.md naming what would settle it, never "+
					"skipped", file, sel.Sel.Name, fset.Position(sel.Pos()))
			}
			return true
		})
	}
}

// ===========================================================================
// FORMAT DETECTION READS THE BYTES
// ===========================================================================

func TestDetectRepoSpecFormat(t *testing.T) {
	cases := []struct {
		name string
		body string
		want SpecFormat
	}{
		{"openapi 3 json", `{"openapi":"3.0.3","paths":{}}`, FormatOpenAPI3},
		{"swagger 2 json", `{"swagger":"2.0","paths":{}}`, FormatSwagger2},
		{"openapi 3 yaml", "openapi: 3.0.3\npaths: {}\n", FormatOpenAPI3YAML},
		{"swagger 2 yaml", "swagger: \"2.0\"\npaths: {}\n", FormatSwagger2YAML},
		{"a yaml whose dialect key follows info",
			"info:\n  title: x\nopenapi: 3.0.3\n", FormatOpenAPI3YAML},
		{"a yaml with only paths", "paths:\n  /a: {}\n", FormatOpenAPI3YAML},
		{"asyncapi json", `{"asyncapi":"2.6.0","channels":{}}`, FormatAsyncAPI},
		{"asyncapi yaml", "asyncapi: 2.6.0\nchannels: {}\n", FormatAsyncAPI},
		{"a postman collection", `{"info":{"schema":"https://schema.getpostman.com/x"},
			"item":[]}`, FormatPostmanCollection},
		{"a postman collection with only item", `{"item":[{"name":"a"}]}`,
			FormatPostmanCollection},
		{"an introspection dump", `{"data":{"__schema":{"types":[]}}}`,
			FormatGraphQLIntrospection},
		{"a bare introspection dump", `{"__schema":{"types":[]}}`,
			FormatGraphQLIntrospection},
		{"a wsdl", `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"/>`, FormatWSDL},
		{"a wsdl behind a declaration and a comment",
			"<?xml version=\"1.0\"?>\n<!-- c -->\n<wsdl:definitions/>", FormatWSDL},
		{"a graphql sdl", "type Query {\n  a: Int\n}\n", FormatGraphQLSDL},
		{"a graphql sdl behind a comment", "# c\nschema {\n  query: Q\n}\n",
			FormatGraphQLSDL},
		{"a byte-order mark", "\ufeff" + `{"openapi":"3.0.3"}`, FormatOpenAPI3},
		{"a README", "This project ships an OpenAPI spec.\n", FormatUnrecognised},
		{"a package.json", `{"name":"x","dependencies":{}}`, FormatUnrecognised},
		{"a pom", `<project><modelVersion>4.0.0</modelVersion></project>`,
			FormatUnrecognised},
		{"nothing at all", "", FormatUnrecognised},
		{"whitespace", "   \n\t\n", FormatUnrecognised},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectRepoSpecFormat([]byte(tc.body)); got != tc.want {
				t.Fatalf("DetectRepoSpecFormat = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestZeroValuesOfTheTier1EnumsAreNotValues(t *testing.T) {
	if HarvestOutcomeUnset.Valid() {
		t.Error("the zero HarvestOutcome reports itself valid")
	}
	if knownRepoSpecFormat("") {
		t.Error("the empty SpecFormat is a known repo-spec format")
	}
	if readableRepoSpecFormats()[""] || readableRepoSpecFormats()[FormatUnrecognised] {
		t.Error("an unrecognised format reports itself readable, so IngestResult.Ingested " +
			"would count a file nothing could read")
	}
	if readableRepoSpecFormats()[FormatAsyncAPI] {
		t.Error("AsyncAPI reports itself readable; it is refused by name and produces no " +
			"routes, so counting it as ingested would hide an empty inventory")
	}
	// The readable set is an ALLOWLIST of the vocabulary, never a denylist.
	for f := range readableRepoSpecFormats() {
		if !knownRepoSpecFormat(f) {
			t.Errorf("%q is readable and is not in the vocabulary", f)
		}
	}
}

// TestEveryRefusalThisTierProducesIsRecognised.
//
// RefusalReason's vocabulary and Refusal.Valid live in tier0_runtime.go, which
// is outside this packet's write scope. Every refusal raised here therefore
// has to come out of the existing set, and this sweep is what would notice a
// new literal that Recognised() does not carry — a refusal that reports itself
// invalid is a row D.26 has no bucket for.
func TestEveryRefusalThisTierProducesIsRecognised(t *testing.T) {
	seen := map[RefusalReason]int{}
	for _, fx := range everyTier1Fixture() {
		fr, _ := t1Classify(t, fx)
		for _, r := range fr.Refusals {
			if !r.Reason.Recognised() {
				t.Fatalf("%s produced the unrecognised reason %q", fx.name, r.Reason)
			}
			if !r.Valid() {
				t.Fatalf("%s produced an invalid refusal: %#v", fx.name, r)
			}
			seen[r.Reason]++
		}
	}
	if len(seen) < 6 {
		t.Fatalf("the corpus produced only %d distinct refusal reasons (%v), so this "+
			"sweep is barely measuring anything", len(seen), seen)
	}
}

// ===========================================================================
// DETERMINISM AND THE RECORD
// ===========================================================================

// TestIngestIsDeterministic. Go map iteration is randomized, and so is the
// order a harvester walks a directory tree. An unstable route order makes
// record.PropRunRouteTableDigest churn for a repository that never changed.
func TestIngestIsDeterministic(t *testing.T) {
	files := []SpecFile{
		t1File(t, "b/openapi.yaml", fixtureOpenAPIYAML),
		t1File(t, "a/swagger.json", fixtureSwaggerJSON),
		t1File(t, "c/quote.wsdl", fixtureWSDL),
		t1File(t, "d/schema.graphql", fixtureGraphQLSDL),
		t1File(t, "e/collection.json", fixturePostman),
	}
	var first []string
	for i := 0; i < 32; i++ {
		res, err := IngestRepoSpecs(t1Config(t), files)
		if err != nil {
			t.Fatalf("IngestRepoSpecs: %v", err)
		}
		got := make([]string, 0, len(res.Routes()))
		for _, r := range res.Routes() {
			got = append(got, r.String())
		}
		if i == 0 {
			first = got
			continue
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d ordered the inventory differently:\n%v\n%v", i, got, first)
		}
	}
	fs := []FileResult{{Location: record.ArtifactLocation{URI: "z"}},
		{Location: record.ArtifactLocation{URI: "a"}}}
	SortFileResults(fs)
	if fs[0].Location.URI != "a" {
		t.Fatalf("SortFileResults did not order by URI: %v", fs)
	}
}

// TestATier1ResultComposesIntoARecordDastCoverage. The point of the two axes
// is what D.26 does with them; this checks the arithmetic actually validates
// against internal/record rather than merely looking plausible here.
func TestATier1ResultComposesIntoARecordDastCoverage(t *testing.T) {
	files := []SpecFile{
		t1File(t, "openapi.yaml", fixtureOpenAPIYAML),
		t1File(t, "collection.json", fixturePostman),
	}
	res, err := IngestRepoSpecs(t1Config(t), files)
	if err != nil {
		t.Fatalf("IngestRepoSpecs: %v", err)
	}
	if err := res.AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("%v", err)
	}

	mix := map[record.InventoryProvenance]int{}
	confirmed, candidate := 0, 0
	for _, r := range res.Routes() {
		mix[r.Provenance()]++
		switch r.Confirmation() {
		case ConfirmationConfirmed:
			confirmed++
		case ConfirmationCandidate:
			candidate++
		}
	}
	cov := &record.DastCoverage{
		ProbedCount:            confirmed,
		InventoryUnionCount:    res.DenominatorFloor(),
		EndpointCoverage:       float64(confirmed) / float64(res.DenominatorFloor()),
		ServerLineCoverage:     nil,
		InventoryProvenanceMix: mix,
		ConfirmedCount:         confirmed,
		CandidateCount:         candidate,
	}
	if err := record.ValidateDastCoverage(cov); err != nil {
		t.Fatalf("a Tier 1 result does not compose into a valid anvil/dastCoverage: %v", err)
	}
	if confirmed != 0 {
		t.Fatalf("Tier 1 contributed %d confirmed endpoints to the numerator. It probes "+
			"nothing; every one of them is D.22's to promote", confirmed)
	}
	if cov.EndpointCoverage != 0 {
		t.Fatalf("a repository whose spec files were merely READ reports %v coverage",
			cov.EndpointCoverage)
	}
	if len(mix) != 1 || mix[record.InventoryProvenanceRepoSpec] != candidate {
		t.Fatalf("the provenance mix is %v and every Tier 1 route is repo_spec", mix)
	}
	// The literals are the record's own, not a copy of them.
	if string(record.InventoryProvenanceRepoSpec) != "repo_spec" {
		t.Fatalf("internal/record spells repo_spec %q and this tier assumes the constant",
			record.InventoryProvenanceRepoSpec)
	}
}

// TestTwoHarvestedFilesDeclaringOneEndpointDoNotDoubleTheInventory. An
// openapi.yaml and the Postman collection generated from it is the ordinary
// case, and counting the endpoint twice inflates the coverage denominator.
func TestTwoHarvestedFilesDeclaringOneEndpointDoNotDoubleTheInventory(t *testing.T) {
	const spec = `{"openapi":"3.0.3","paths":{"/a":{"get":{"operationId":"a"}}}}`
	res, err := IngestRepoSpecs(t1Config(t), []SpecFile{
		t1File(t, "one.json", spec),
		t1File(t, "two.json", spec),
	})
	if err != nil {
		t.Fatalf("IngestRepoSpecs: %v", err)
	}
	if len(res.Routes()) != 1 {
		t.Fatalf("got %d routes: %v", len(res.Routes()), t1RouteKeys(res.Routes()))
	}
	if !t1HasReason(res.Refusals(), RefusalDuplicateRoute) {
		t.Fatal("the second declaration vanished without a row")
	}
	if res.Ingested() != 2 {
		t.Fatalf("Ingested is %d; both files were readable", res.Ingested())
	}
	// SourceOf attributes the surviving route to the file it came from.
	loc, ok := res.SourceOf(res.Routes()[0].Key())
	if !ok || loc.URI != "one.json" {
		t.Fatalf("SourceOf returned (%v, %v)", loc, ok)
	}
}

func TestSpecFileStringAndFileResultReadableAreHonest(t *testing.T) {
	if got := (SpecFile{}).String(); got != "specfile(unconstructed)" {
		t.Fatalf("the zero SpecFile renders as %q", got)
	}
	f := t1File(t, "a.json", "{}")
	if got := f.String(); !strings.Contains(got, "a.json") || !strings.Contains(got, "2 bytes") {
		t.Fatalf("SpecFile.String is %q", got)
	}
	if (FileResult{ParseResult: ParseResult{Format: FormatAsyncAPI}}).Readable() {
		t.Fatal("an AsyncAPI file reports itself readable")
	}
	if !(FileResult{ParseResult: ParseResult{Format: FormatWSDL}}).Readable() {
		t.Fatal("a WSDL file reports itself unreadable")
	}
	if (IngestResult{}).Constructed() {
		t.Fatal("the zero IngestResult reports itself constructed")
	}
	if err := (IngestResult{}).AssertNotSilentlyEmpty(); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("AssertNotSilentlyEmpty on a zero IngestResult returned %v", err)
	}
}
