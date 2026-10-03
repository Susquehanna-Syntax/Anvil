// This file is the runtime spec probe: Tier 0, the runtime spec route.
//
// ===========================================================================
// THE TWO AXES, AND WHY NEITHER MAY BE DEFAULTED
// ===========================================================================
//
// plan/design/dynamic-tier.md's Coverage Reporting Contract (line 1154) defines
// `inventory_provenance` as a PER-ROUTE enum {runtime_spec, repo_spec,
// static_extraction, crawl} PLUS confirmed/candidate, "aggregated to a
// record-level summary in coverage reporting. This is what makes the SAST->DAST handoff
// auditable."
//
// Those are two independent axes and this package treats them as two fields:
//
//	Route.Provenance()   record.InventoryProvenance -- which tier found it
//	Route.Confirmation() Confirmation               -- did Anvil observe it
//
// The reason they cannot be defaulted is arithmetic. plan/design/dynamic-tier.md:1152
// defines `endpoint_coverage` as confirmed-probed endpoints divided by the
// union of the Tier 0-2 inventory, and says in bold "Never a raw request
// count." A candidate endpoint that reads as confirmed moves into the
// NUMERATOR of that fraction, and a scan that probed nothing then reports
// coverage. So Confirmation's zero value is ConfirmationUnset, NewRoute
// refuses it, and there is no code path in this package that supplies a
// default. A Go zero value never means "permitted" here.
//
// ===========================================================================
// TIER 0 IS THE SPEC THE RUNNING APPLICATION SERVES, AND IT IS UNTRUSTED
// ===========================================================================
//
// Tier 0 asks the target for its own description: an OpenAPI document at a
// well-known path, a springdoc `api-docs` document, a GraphQL introspection
// response (research/22-attack-surface-discovery.md, "Tier 0 -- ask the target
// for its own spec"). That document is the most complete description of the
// attack surface that exists, and it is also ATTACKER-CONTROLLED BYTES
// DESCRIBING ATTACK SURFACE.
//
// The asymmetry this package respects is gate 11's, exactly:
//
//	A DOCUMENT SERVED BY THE TARGET MAY ONLY ADD DENIES, NEVER GRANTS.
//
// Applied here:
//
//	MAY   add CANDIDATE routes to the inventory
//	MAY   enlarge the denominator of endpoint_coverage
//	NEVER widen scope         -- `servers`, `host` and `schemes` are read only
//	                             so the divergence can be RECORDED, and are
//	                             never used to reach anything
//	NEVER grant authorization -- this package cannot mint an
//	                             authz.Authorization and cannot dial
//	NEVER mark anything confirmed -- ParseSpec stamps ConfirmationCandidate
//	                             on every route it extracts, unconditionally,
//	                             whatever the document claims
//
// record.TrustUntrusted is stamped on every route this package produces.
// internal/record's own contract test records why: "a repo source snippet is
// `untrusted` even though Anvil is the component that put it in the struct...
// The question TrustLevel answers is 'who wrote these bytes', never 'who
// assigned this field'."
//
// DEVIATION FROM plan/design/dynamic-tier.md:606-608, stated rather than hidden. That
// block says every Tier 0 route is "status: confirmed (a spec straight from
// the running service is definitionally confirmed, not a candidate)". This
// file does not do that, on the orchestrator's standing instruction, and the
// instruction is right: what Anvil observed is that the DOCUMENT exists. That
// GET /<spec path> returned 200 is Anvil's own observation and is reported as
// ProbedSpecEndpoints. That `POST /internal/admin/reset` appears INSIDE the
// document is the target's claim about itself, and a target that lies about
// its own surface — by omission, which is the cheap direction — would
// otherwise hand Anvil a numerator. Confirmation of a route belongs to the
// packet that probes it, not to this one.
//
// ===========================================================================
// THIS PACKAGE OPENS NO SOCKET AND CANNOT
// ===========================================================================
//
// Fetching a spec is a request, so it goes through the kernel like any other.
// The build-time guard's gate 3 tier 1 fails the build if any package under internal/dast
// outside internal/dast/authz imports something that can construct a
// connection, with no allowlist. So Tier 0 is shaped the way the Nuclei
// driver is shaped, deliberately and for the same reason:
//
//	Probe builds an authz.RequestIntent per endpoint
//	  -> authz.GateAudit.AuditedAdmit runs the per-request gate chain and
//	     writes one gate-21 row per gate
//	  -> only if the kernel admits does anything leave the process, and it
//	     leaves through a SpecFetcher supplied from OUTSIDE internal/dast
//	  -> the response body is read through authz.LimitBody, so gate 14's cap
//	     is enforced WHILE READING rather than after buffering
//
// A nil SpecFetcher is legal to construct and produces a LOUD REFUSAL at
// Probe, counted in the Result. It never produces an empty route list that
// reads as "this application has no endpoints."
//
// ===========================================================================
// WHAT CANNOT BE EXERCISED TODAY, AND WHY IT IS NOT A t.Skip
// ===========================================================================
//
// authz.Adjudicate is the only mint for an authz.Authorization, the admission
// chain contains Gate11RobotsDeny, and nothing is registered for it — so the
// chain refuses every target there and NO Authorization can be constructed
// from outside package authz. docs/controls.md U4 records this.
// The consequence for the runtime spec probe is exact: Probe's admit-and-fetch path cannot reach
// a fetcher today, and every test of it asserts a refusal.
//
// That is why this file splits the packet in two. ParseSpec takes an
// authz.Target — which authz.NewTarget builds without any authorization,
// because it is gate 8/9's OUTPUT and not a permission — and is therefore
// FULLY exercisable now, including the kernel's own path validation. The
// parameter-typed extraction plan/design/dynamic-tier.md:610 asks for is proven against
// fixtures today; only the socket half waits on gate 11. There is no t.Skip in
// this package.
//
// ===========================================================================
// THE PROBE LIST IS CONFIGURATION AND THERE IS NO DEFAULT
// ===========================================================================
//
// plan/design/dynamic-tier.md:601 forbids hard-coding the spec-endpoint list (the spine's
// "nothing about trigger/policy may be hard-coded", applied to the endpoint
// list itself). EndpointList has one constructor, it refuses an empty list,
// and no function in this file returns a populated one. The guard is not that
// rule written down: TestNoRequestPathIsHardCodedInThisFile parses this file's
// own syntax tree and fails on ANY string literal that begins with "/" and is
// longer than one byte. That is an allowlist — exactly one path-shaped literal
// is permitted, "/" itself — so a spec path nobody thought to ban is caught by
// default rather than by memory.
//
// ===========================================================================
// WHAT THE THREE LATER PACKETS INHERIT
// ===========================================================================
//
// The runtime spec probe is first into this package. Route, RouteFacts, NewRoute, Param,
// Confirmation, Refusal and Result are tier-NEUTRAL and belong to the repo spec reader
// (repo_spec), the static-extraction packet and the crawl packet equally.
// Three rules they inherit, each enforced by NewRoute rather than by
// documentation:
//
//  1. Provenance and Confirmation are both required. Neither has a default.
//  2. Trust must be legal for a string that originated outside Anvil.
//     record.TrustAnvilGenerated is refused for every provenance, because all
//     four provenances describe bytes somebody else wrote — repo source and a
//     checked-in spec file included.
//  3. Every path is validated by the KERNEL, by constructing an
//     authz.RequestIntent, rather than by a second path validator in this
//     package that could disagree with the kernel's.
//
// Sources: the runtime spec probe's design (lines 595-616) and the Coverage Reporting
// Contract (lines 1142-1160); research/22-attack-surface-discovery.md lines
// 319-323; internal/record/contract.go (InventoryProvenance, Trust,
// DastCoverage).

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrRefused is the sentinel every refusal in this package unwraps to.
	ErrRefused = errors.New("inventory: refused")

	// ErrUnconstructed is returned when a value that has a constructor
	// arrives as a composite literal or a zero value.
	ErrUnconstructed = errors.New("inventory: value was not built by its constructor")

	// ErrNothingProbed is what Result.AssertNotSilentlyEmpty returns when a
	// Tier 0 run produced no routes AND never received a single answer from
	// the target. An empty inventory is a claim about the application; this
	// error is the case where it is instead a claim about Anvil.
	ErrNothingProbed = errors.New("inventory: nothing was probed; an empty Tier 0 inventory " +
		"here describes Anvil, not the target")

	// ErrNoFetcher is returned when the kernel admitted a spec request and
	// there is no egress seam to issue it through. It is an error and not a
	// silent zero result for the reason the whole package exists.
	ErrNoFetcher = errors.New("inventory: no SpecFetcher is wired, so an admitted spec " +
		"request cannot be issued")
)

// ---------------------------------------------------------------------------
// Coded bounds
// ---------------------------------------------------------------------------

const (
	// maxRoutesPerSpec bounds how many routes one served document may add.
	// The document is attacker-controlled; a spec declaring ten million
	// paths is a resource-exhaustion probe pointed back at Anvil.
	maxRoutesPerSpec = 10000

	// maxParamsPerRoute bounds parameters on a single operation.
	maxParamsPerRoute = 256

	// maxIdentBytes bounds any single name or type string lifted out of a
	// served document.
	maxIdentBytes = 256

	// maxEndpointsPerProbe bounds the configured spec-endpoint list. The
	// list is operator configuration rather than target input, so this is a
	// sanity floor and not a containment control.
	maxEndpointsPerProbe = 64

	// maxTypeRefDepth bounds the GraphQL NON_NULL/LIST unwrap chain. A
	// hostile introspection response can nest ofType arbitrarily deep.
	maxTypeRefDepth = 16
)

// ---------------------------------------------------------------------------
// Confirmation — the second axis
// ---------------------------------------------------------------------------

// Confirmation says whether Anvil OBSERVED this endpoint or merely believes
// something claimed it exists.
//
// # Why this is declared here and not in internal/record
//
// internal/record owns every shared enum (contract.go's header comment: "The record area owns every
// shared enum, because it owns the record contract, and no other area may
// declare one"). record.InventoryProvenance is there for exactly that reason.
// The confirmed/candidate axis is NOT — record carries it as two aggregate
// counters, DastCoverage.ConfirmedCount and DastCoverage.CandidateCount, with
// no enum behind them. The literals below are chosen to match those counter
// names exactly, so coverage reporting's aggregation is a partition of this enum and not a
// mapping. FLAGGED TO THE ORCHESTRATOR as a candidate addition to
// internal/record/contract.go alongside InventoryProvenance; until it lands,
// this declaration is the one place the vocabulary is written.
//
// # The zero value is not a value
//
// ConfirmationUnset exists so that a Route somebody forgot to fill in is
// REFUSED rather than counted. "Confirmed" is the permissive direction here —
// it is what moves an endpoint toward the numerator of endpoint_coverage — so
// the zero value must not be it.
type Confirmation string

const (
	// ConfirmationUnset is the zero value and names nothing. NewRoute
	// refuses it.
	ConfirmationUnset Confirmation = ""

	// ConfirmationConfirmed: Anvil itself observed this endpoint. For Tier 0
	// that means Anvil issued a kernel-admitted request to it and the target
	// answered. It never means "a document said so".
	ConfirmationConfirmed Confirmation = "confirmed"

	// ConfirmationCandidate: something asserts this endpoint exists and
	// Anvil has not observed it. Every route lifted out of a served
	// document is one of these.
	ConfirmationCandidate Confirmation = "candidate"
)

// ConfirmationValues returns every legal literal, strongest evidence first.
func ConfirmationValues() []Confirmation {
	return []Confirmation{ConfirmationConfirmed, ConfirmationCandidate}
}

// Valid reports whether c is one of the two legal literals.
func (c Confirmation) Valid() bool {
	for _, k := range ConfirmationValues() {
		if k == c {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

// ParamIn says where on the wire a parameter travels.
type ParamIn string

const (
	// ParamInUnset is the zero value and names nothing.
	ParamInUnset ParamIn = ""
	// ParamInPath is a templated path segment.
	ParamInPath ParamIn = "path"
	// ParamInQuery is a query-string parameter.
	ParamInQuery ParamIn = "query"
	// ParamInHeader is a request header.
	ParamInHeader ParamIn = "header"
	// ParamInCookie is a cookie.
	ParamInCookie ParamIn = "cookie"
	// ParamInForm is a form field (Swagger 2's `formData`).
	ParamInForm ParamIn = "form"
	// ParamInBody is the request body.
	ParamInBody ParamIn = "body"
	// ParamInGraphQLArgument is an argument on a GraphQL root field.
	ParamInGraphQLArgument ParamIn = "graphql_argument"
)

// ParamInValues returns every legal literal.
func ParamInValues() []ParamIn {
	return []ParamIn{
		ParamInPath, ParamInQuery, ParamInHeader,
		ParamInCookie, ParamInForm, ParamInBody, ParamInGraphQLArgument,
	}
}

// Valid reports whether p is one of the legal literals.
func (p ParamIn) Valid() bool {
	for _, k := range ParamInValues() {
		if k == p {
			return true
		}
	}
	return false
}

// Param is one typed parameter of a route.
//
// The fields are exported because a Param carries no invariant a constructor
// could hold that NewRoute does not already hold for it: NewRoute validates
// every Param of every Route it builds, and a Param that never reached
// NewRoute is not in the inventory. Name and Type are lifted verbatim from an
// untrusted document, which is why Route.Trust() covers them.
type Param struct {
	// Name is the parameter's name as the document spelled it.
	Name string
	// In is where it travels.
	In ParamIn
	// Type is the declared type as the document spelled it, or "" when the
	// document declared none. It is deliberately a string and not an enum:
	// this is a foreign vocabulary and folding it into one of Anvil's would
	// invent information.
	Type string
	// Required is the document's own required flag.
	Required bool
}

// Typed reports whether the document actually declared a type for this
// parameter. plan/design/dynamic-tier.md:610 asks for "full parameter-typed route
// extraction"; this is the predicate that makes the claim measurable rather
// than asserted.
func (p Param) Typed() bool { return p.Type != "" }

func cloneParams(in []Param) []Param {
	if in == nil {
		return nil
	}
	out := make([]Param, len(in))
	copy(out, in)
	return out
}

// ---------------------------------------------------------------------------
// Route — the unit of the inventory
// ---------------------------------------------------------------------------

// RouteFacts is NewRoute's input. Every field that has no safe default is
// required; see NewRoute for what each refusal is for.
type RouteFacts struct {
	// Method is the HTTP method, as the KERNEL's allowlisted type. A method
	// the kernel does not recognise cannot be probed, so it cannot be a
	// Route; NewRoute refuses it and the caller records the refusal so the
	// operation stays visible.
	Method authz.Method

	// Path is the request path. It is validated by constructing an
	// authz.RequestIntent against Target, so the kernel's own bound and
	// charset rule apply and this package holds no second copy of them.
	Path string

	// Target is the kernel Target this route lives on. Required: it is what
	// makes the kernel's path validation possible, and it is what pins the
	// route to a host rather than leaving it a free-floating string.
	Target authz.Target

	// Operation names the operation within the path when the path alone does
	// not identify it — a GraphQL root field, or an OpenAPI operationId. It
	// may be empty for an ordinary REST route.
	Operation string

	// Params is the typed parameter list. Copied by NewRoute.
	Params []Param

	// Provenance is which tier produced this route. Required; no default.
	Provenance record.InventoryProvenance

	// Confirmation is whether Anvil observed it. Required; no default.
	Confirmation Confirmation

	// Trust is the record's trust label for the strings this route carries.
	// Required, and must be legal for a string that originated outside
	// Anvil — which every inventory provenance describes.
	Trust record.Trust

	// ServedAt is the well-known endpoint path this route was harvested
	// from, for a Tier 0 route. It is Anvil's configuration rather than
	// target input, and it is what lets a reader ask "which document said
	// so". Empty for tiers that have no such endpoint.
	ServedAt string
}

// Route is one endpoint in the attack-surface inventory.
//
// Every field is unexported and there is exactly one constructor. A composite
// literal in another package produces the zero Route, whose Confirmation is
// ConfirmationUnset and whose Provenance is the empty InventoryProvenance —
// and Constructed() is false, so it cannot be mistaken for an endpoint. That
// is the whole reason for the shape: the packet brief's requirement is that an
// endpoint "cannot exist without both values set", and a struct with exported
// fields cannot hold that.
type Route struct {
	method       authz.Method
	path         string
	operation    string
	params       []Param
	provenance   record.InventoryProvenance
	confirmation Confirmation
	trust        record.Trust
	servedAt     string
	target       authz.Target
	sealed       bool
}

// NewRoute validates the facts and seals them.
//
// The order of the checks is chosen so the message sends the reader to the
// right place: the two axes are checked FIRST, because a missing provenance or
// a missing confirmation is a programming error in a tier implementation,
// while a rejected path is usually the served document being hostile or odd.
func NewRoute(f RouteFacts) (Route, error) {
	if !f.Provenance.Valid() {
		return Route{}, fmt.Errorf("inventory: %w: inventory_provenance is %q, which is not "+
			"one of %v. plan/design/dynamic-tier.md:1154 makes provenance PER ROUTE and coverage reporting aggregates "+
			"it into the record; a route whose provenance nobody set is not a weaker route, "+
			"it is an unattributable one",
			ErrRefused, redact(string(f.Provenance)), record.InventoryProvenanceValues())
	}
	if !f.Confirmation.Valid() {
		return Route{}, fmt.Errorf("inventory: %w: confirmation is %q, which is not one of "+
			"%v. endpoint_coverage (plan/design/dynamic-tier.md:1152) is confirmed-probed endpoints over "+
			"the Tier 0-2 union, so an unset confirmation would either inflate the numerator "+
			"or vanish from the denominator depending on who read it",
			ErrRefused, redact(string(f.Confirmation)), ConfirmationValues())
	}
	if !f.Trust.Valid() || !f.Trust.LegalForExternalString() {
		return Route{}, fmt.Errorf("inventory: %w: trust is %q. Every inventory provenance "+
			"names bytes somebody outside Anvil wrote — a served spec, a checked-in spec, "+
			"repo source, a crawled response — so %q is refused here for the same reason "+
			"internal/record refuses it on a source snippet: the question is who wrote the "+
			"bytes, never who assigned the field",
			ErrRefused, redact(string(f.Trust)), record.TrustAnvilGenerated)
	}
	if !f.Target.Constructed() {
		return Route{}, fmt.Errorf("inventory: %w: the route carries a Target that "+
			"authz.NewTarget never built, so its path cannot be validated by the kernel and "+
			"the route names no host", ErrUnconstructed)
	}
	if !f.Method.Recognised() {
		return Route{}, fmt.Errorf("inventory: %w: %q is not on the kernel's method "+
			"allowlist. A method Anvil cannot express is a method Anvil cannot probe; the "+
			"caller records the refusal so the operation still counts toward the coverage "+
			"denominator", ErrRefused, redact(string(f.Method)))
	}
	if err := kernelAcceptsPath(f.Target, f.Method, f.Path); err != nil {
		return Route{}, err
	}
	if len(f.Params) > maxParamsPerRoute {
		return Route{}, fmt.Errorf("inventory: %w: the route declares %d parameters and the "+
			"coded bound is %d", ErrRefused, len(f.Params), maxParamsPerRoute)
	}
	for i, p := range f.Params {
		if err := validParam(i, p); err != nil {
			return Route{}, err
		}
	}
	if len(f.Operation) > maxIdentBytes {
		return Route{}, fmt.Errorf("inventory: %w: the operation name is %d bytes and the "+
			"coded bound is %d", ErrRefused, len(f.Operation), maxIdentBytes)
	}
	return Route{
		method:       f.Method,
		path:         f.Path,
		operation:    f.Operation,
		params:       cloneParams(f.Params),
		provenance:   f.Provenance,
		confirmation: f.Confirmation,
		trust:        f.Trust,
		servedAt:     f.ServedAt,
		target:       f.Target,
		sealed:       true,
	}, nil
}

func validParam(i int, p Param) error {
	if p.Name == "" {
		return fmt.Errorf("inventory: %w: parameter %d has no name. An unnamed parameter is "+
			"what an unresolved $ref looks like after unmarshalling, and a route carrying "+
			"one cannot be concretized into a request later", ErrRefused, i)
	}
	if len(p.Name) > maxIdentBytes {
		return fmt.Errorf("inventory: %w: parameter %d has a %d-byte name and the coded "+
			"bound is %d", ErrRefused, i, len(p.Name), maxIdentBytes)
	}
	if len(p.Type) > maxIdentBytes {
		return fmt.Errorf("inventory: %w: parameter %q has a %d-byte type and the coded "+
			"bound is %d", ErrRefused, redact(p.Name), len(p.Type), maxIdentBytes)
	}
	if !p.In.Valid() {
		return fmt.Errorf("inventory: %w: parameter %q travels in %q, which is not one of "+
			"%v", ErrRefused, redact(p.Name), redact(string(p.In)), ParamInValues())
	}
	return nil
}

// kernelAcceptsPath runs the path through the KERNEL's own validation rather
// than through a second copy of it in this package.
//
// authz.NewRequestIntent applies the kernel's path bound and charset rule
// (internal/dast/authz/phase2_admission.go's validRequestPath, 4096 bytes,
// printable ASCII, leading "/"). Re-implementing those here is precisely the
// "second canonicalization that can disagree with the kernel's" this build has
// a standing rule against, and the disagreement would be silent: a path this
// package accepted and the kernel later refused would sit in the coverage
// denominator forever as an endpoint that can never be probed.
//
// The `..` check is this package's own and is NOT a scope control — the host
// is pinned by gate 9 and a dot-segment cannot change it. It is an IDENTITY
// control: `/a/../b` and `/b` are the same endpoint and would otherwise be two
// rows in the Tier 0-2 union, inflating the denominator of a fraction that is
// supposed to be auditable.
func kernelAcceptsPath(target authz.Target, method authz.Method, path string) error {
	if _, err := authz.NewRequestIntent(authz.RequestFacts{
		Origin:   authz.OriginInitial,
		Admitted: target,
		Next:     target,
		Method:   method,
		Path:     path,
	}); err != nil {
		return fmt.Errorf("inventory: %w: the kernel rejected path %q: %w",
			ErrRefused, redact(path), err)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return fmt.Errorf("inventory: %w: path %q contains a \"..\" segment. Two "+
				"spellings of one endpoint are two rows in the Tier 0-2 union and one "+
				"inventory the coverage fraction cannot be audited against",
				ErrRefused, redact(path))
		}
	}
	return nil
}

// Constructed reports whether r came from NewRoute. The zero Route is not one.
func (r Route) Constructed() bool {
	return r.sealed && r.provenance.Valid() && r.confirmation.Valid() && r.target.Constructed()
}

// Method returns the HTTP method.
func (r Route) Method() authz.Method { return r.method }

// Path returns the request path.
func (r Route) Path() string { return r.path }

// Operation returns the operation name, or "" for an ordinary REST route.
func (r Route) Operation() string { return r.operation }

// Params returns a COPY of the parameter list. The copy is the point: a caller
// that sorts or truncates the returned slice must not be editing the
// inventory.
func (r Route) Params() []Param { return cloneParams(r.params) }

// Provenance returns which tier produced this route.
func (r Route) Provenance() record.InventoryProvenance { return r.provenance }

// Confirmation returns whether Anvil observed this endpoint.
func (r Route) Confirmation() Confirmation { return r.confirmation }

// Trust returns the record trust label for the strings this route carries.
func (r Route) Trust() record.Trust { return r.trust }

// ServedAt returns the well-known endpoint this route was harvested from, or
// "" for a tier with no such endpoint.
func (r Route) ServedAt() string { return r.servedAt }

// Target returns the kernel Target this route lives on.
func (r Route) Target() authz.Target { return r.target }

// FullyTyped reports whether every parameter carries a declared type. A route
// with no parameters is fully typed vacuously, which is correct: there is
// nothing untyped about it.
func (r Route) FullyTyped() bool {
	for _, p := range r.params {
		if !p.Typed() {
			return false
		}
	}
	return true
}

// Key is the route's identity within the inventory: method, path and
// operation. It is what coverage reporting must deduplicate the Tier 0-2 union on, and it is
// a method here rather than a convention there so the two cannot drift.
//
// The separator is a NUL byte, which cannot appear in any of the three
// components — the kernel's path rule is printable ASCII, the method comes
// from a closed allowlist, and the operation is bounded and checked. A joining
// character that CAN appear in a component makes distinct keys collide.
func (r Route) Key() string {
	return string(r.method) + "\x00" + r.path + "\x00" + r.operation
}

// String renders the route for a log line.
func (r Route) String() string {
	if !r.Constructed() {
		return "route(unconstructed)"
	}
	op := ""
	if r.operation != "" {
		op = " " + r.operation
	}
	return fmt.Sprintf("%s %s%s [%s/%s]", r.method, r.path, op, r.provenance, r.confirmation)
}

func cloneRoutes(in []Route) []Route {
	if in == nil {
		return nil
	}
	out := make([]Route, len(in))
	for i, r := range in {
		out[i] = r
		out[i].params = cloneParams(r.params)
	}
	return out
}

// SortRoutes orders routes deterministically by path, then method, then
// operation. Every function in this package that returns a route list has
// already applied it: Go map iteration is randomized, and a spec parser whose
// output order changes between runs makes the record's routeTableDigest
// (record.PropRunRouteTableDigest) unstable for an unchanged target.
func SortRoutes(rs []Route) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].path != rs[j].path {
			return rs[i].path < rs[j].path
		}
		if rs[i].method != rs[j].method {
			return rs[i].method < rs[j].method
		}
		return rs[i].operation < rs[j].operation
	})
}

// ---------------------------------------------------------------------------
// Refusals — what did NOT become a route, and why
// ---------------------------------------------------------------------------

// RefusalReason names why something the inventory saw did not become a Route.
//
// It is an enum rather than free text because Result.DenominatorFloor
// partitions on it: a refusal that dropped one OPERATION is attack surface
// Anvil saw and could not represent, and it must still count toward the
// coverage denominator. A refusal that dropped a whole DOCUMENT is not
// per-operation and cannot be counted that way.
type RefusalReason string

const (
	// RefusalUnset is the zero value and names nothing.
	RefusalUnset RefusalReason = ""

	// --- document-level, not per-operation ---

	// RefusalNoFetcherWired: the kernel admitted the request and there was
	// no egress seam to issue it through.
	RefusalNoFetcherWired RefusalReason = "no_fetcher_wired"
	// RefusalKernelRefused: the per-request gate chain refused.
	RefusalKernelRefused RefusalReason = "kernel_refused_the_request"
	// RefusalIntentRejected: the endpoint could not even be expressed as an
	// authz.RequestIntent.
	RefusalIntentRejected RefusalReason = "endpoint_is_not_a_valid_request_intent"
	// RefusalFetchFailed: the fetcher returned an error.
	RefusalFetchFailed RefusalReason = "fetch_failed"
	// RefusalStatusNotOK: the target answered with something other than 200.
	// This is an ANSWER — it counts toward Result.Answered.
	RefusalStatusNotOK RefusalReason = "status_was_not_200"
	// RefusalBodyExceedsCap: gate 14's body cap refused the read.
	RefusalBodyExceedsCap RefusalReason = "body_exceeded_the_coded_cap"
	// RefusalFormatUnrecognised: the bytes are not a spec this tier knows.
	RefusalFormatUnrecognised RefusalReason = "spec_format_unrecognised"
	// RefusalYAMLUnsupported: the document is YAML. modernc.org/sqlite is
	// this module's only dependency and there is no YAML parser in it, so a
	// YAML spec is refused BY NAME rather than silently misparsed.
	RefusalYAMLUnsupported RefusalReason = "yaml_spec_needs_a_parser_this_module_does_not_have"
	// RefusalGRPCReflectionUnsupported: gRPC server reflection is a
	// bidirectional HTTP/2 stream, not a document a GET returns.
	RefusalGRPCReflectionUnsupported RefusalReason = "grpc_reflection_is_not_a_fetchable_document"
	// RefusalSpecUnparseable: the bytes claimed a format and did not parse.
	RefusalSpecUnparseable RefusalReason = "spec_body_did_not_parse"
	// RefusalSpecTruncated: the document declared more routes than the coded
	// bound and parsing stopped.
	RefusalSpecTruncated RefusalReason = "spec_exceeded_the_coded_route_bound"
	// RefusalForeignOriginIgnored: the document named a host, scheme or
	// server URL that is not the target. Anvil READ it so the divergence is
	// on the record and IGNORED it, because a document served by the target
	// may add candidates and may never widen scope (gate 11's asymmetry).
	RefusalForeignOriginIgnored RefusalReason = "spec_declared_a_foreign_origin_and_it_was_ignored"
	// RefusalBasePathIgnored: the document declared a basePath that is not a
	// usable path prefix, so it was not applied.
	RefusalBasePathIgnored RefusalReason = "spec_declared_an_unusable_base_path"

	// --- per-operation ---

	// RefusalMethodNotAllowlisted: the document declared a method the
	// kernel's allowlist does not carry.
	RefusalMethodNotAllowlisted RefusalReason = "method_is_not_on_the_kernel_allowlist"
	// RefusalPathRejectedByKernel: the kernel refused the path.
	RefusalPathRejectedByKernel RefusalReason = "path_was_rejected_by_the_kernel"
	// RefusalParamUnusable: a parameter could not be named or typed — an
	// unresolved $ref, an unrecognised `in`, an over-deep GraphQL type ref.
	RefusalParamUnusable RefusalReason = "parameter_could_not_be_represented"
	// RefusalDuplicateRoute: the document declared the same route twice.
	RefusalDuplicateRoute RefusalReason = "duplicate_route"
	// RefusalRouteUnconstructible: NewRoute refused for a reason none of the
	// above named. It exists so that a future NewRoute check cannot make an
	// operation vanish without a row.
	RefusalRouteUnconstructible RefusalReason = "route_failed_its_own_constructor"
)

// perOperationReasons is the set of reasons that each dropped exactly ONE
// operation the document declared.
//
// It is an allowlist. A new RefusalReason is NOT per-operation until somebody
// adds it here, which is the safe direction: forgetting to add one understates
// DenominatorFloor's claim about itself rather than overstating coverage.
func perOperationReasons() map[RefusalReason]bool {
	return map[RefusalReason]bool{
		RefusalMethodNotAllowlisted: true,
		RefusalPathRejectedByKernel: true,
		RefusalParamUnusable:        true,
		RefusalDuplicateRoute:       true,
		RefusalRouteUnconstructible: true,
	}
}

// RefusalReasonValues returns every legal literal.
func RefusalReasonValues() []RefusalReason {
	return []RefusalReason{
		RefusalNoFetcherWired, RefusalKernelRefused, RefusalIntentRejected,
		RefusalFetchFailed, RefusalStatusNotOK, RefusalBodyExceedsCap,
		RefusalFormatUnrecognised, RefusalYAMLUnsupported,
		RefusalGRPCReflectionUnsupported, RefusalSpecUnparseable,
		RefusalSpecTruncated, RefusalForeignOriginIgnored, RefusalBasePathIgnored,
		RefusalMethodNotAllowlisted, RefusalPathRejectedByKernel,
		RefusalParamUnusable, RefusalDuplicateRoute, RefusalRouteUnconstructible,
	}
}

// Recognised reports whether r is one of the enumerated reasons.
func (r RefusalReason) Recognised() bool {
	for _, k := range RefusalReasonValues() {
		if k == r {
			return true
		}
	}
	return false
}

// PerOperation reports whether this reason dropped exactly one operation the
// document declared, and therefore whether it counts toward
// Result.DenominatorFloor.
func (r RefusalReason) PerOperation() bool { return perOperationReasons()[r] }

// Refusal is one thing the inventory saw and did not turn into a Route.
//
// It is RETURNED rather than logged, and that is a coverage decision rather
// than a diagnostics one. plan/design/dynamic-tier.md:1152 divides confirmed-probed
// endpoints by the Tier 0-2 union; an operation this tier could not represent
// is attack surface that exists, and dropping it silently SHRINKS the
// denominator, which makes coverage look better. Refusals travel so coverage reporting can
// count them.
type Refusal struct {
	// Endpoint is the well-known spec path being probed, or "" for a
	// refusal that arose during a pure parse.
	Endpoint string
	// Path is the route path the document declared, for a per-operation
	// refusal. Redacted: it is untrusted input that reaches a log.
	Path string
	// Method is the method the document declared, redacted for the same
	// reason.
	Method string
	// Reason is the enumerated cause.
	Reason RefusalReason
	// Detail is a short redacted explanation.
	Detail string
}

// Valid reports whether the refusal names a recognised reason.
func (r Refusal) Valid() bool { return r.Reason.Recognised() }

// String renders the refusal for a log line.
func (r Refusal) String() string {
	where := r.Endpoint
	if r.Path != "" {
		where = r.Method + " " + r.Path
	}
	return fmt.Sprintf("%s: %s (%s)", where, r.Reason, r.Detail)
}

func cloneRefusals(in []Refusal) []Refusal {
	if in == nil {
		return nil
	}
	out := make([]Refusal, len(in))
	copy(out, in)
	return out
}

// redact folds an untrusted string down to a bounded, printable form before it
// reaches an error message or a log line.
//
// It is a DISPLAY helper and never a matcher — nothing in this package
// compares redacted strings, so it cannot become a second canonicalization
// that disagrees with the kernel's. The kernel has an identical unexported
// helper; duplicating a formatter is not the hazard the standing rule is
// about, and importing one would mean exporting it from the choke point.
func redact(s string) string {
	const max = 96
	truncated := false
	if len(s) > max {
		s = s[:max]
		truncated = true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '*' || c == '/' || c == '{' ||
			c == '}' || c == ':' || c == ' '
		if ok {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('?')
	}
	if truncated {
		b.WriteString("...")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The endpoint list — configuration, with no default
// ---------------------------------------------------------------------------

// EndpointList is the configured set of well-known spec paths to probe.
//
// plan/design/dynamic-tier.md:601 forbids hard-coding it. The enforcement is structural in
// three parts:
//
//  1. There is exactly one constructor and it takes the list.
//  2. NewEndpointList REFUSES an empty list. There is no fallback, so a
//     caller that supplies nothing gets a refusal rather than a built-in
//     list nobody chose.
//  3. TestNoRequestPathIsHardCodedInThisFile walks this file's syntax tree
//     and fails on any string literal beginning with "/" that is longer than
//     one byte. A default added later does not compile past the suite.
type EndpointList struct {
	paths  []string
	sealed bool
}

// NewEndpointList validates and seals the configured probe list.
//
// The paths are validated for SHAPE only, and deliberately not against a
// target: the same configured list is used for every target in a run, and
// binding it to one would mean re-reading configuration per target. The
// kernel's own validation runs later, per endpoint, inside Probe.
func NewEndpointList(paths []string) (EndpointList, error) {
	if len(paths) == 0 {
		return EndpointList{}, fmt.Errorf("inventory: %w: the spec-endpoint probe list is "+
			"empty. plan/design/dynamic-tier.md forbids a hard-coded list, so there is no default to "+
			"fall back to and an empty list probes nothing rather than probing the usual "+
			"suspects", ErrRefused)
	}
	if len(paths) > maxEndpointsPerProbe {
		return EndpointList{}, fmt.Errorf("inventory: %w: the probe list has %d entries and "+
			"the coded bound is %d", ErrRefused, len(paths), maxEndpointsPerProbe)
	}
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for i, p := range paths {
		if p == "" || p[0] != '/' {
			return EndpointList{}, fmt.Errorf("inventory: %w: probe entry %d is %q; a spec "+
				"endpoint is a request path and must begin with a slash",
				ErrRefused, i, redact(p))
		}
		if len(p) > maxRequestPathDisplayBound {
			return EndpointList{}, fmt.Errorf("inventory: %w: probe entry %d is %d bytes",
				ErrRefused, i, len(p))
		}
		if seen[p] {
			return EndpointList{}, fmt.Errorf("inventory: %w: probe entry %d repeats %q. A "+
				"duplicated spec endpoint would be fetched twice and, if it answered, would "+
				"contribute its routes twice", ErrRefused, i, redact(p))
		}
		seen[p] = true
		out = append(out, p)
	}
	return EndpointList{paths: out, sealed: true}, nil
}

// maxRequestPathDisplayBound mirrors the kernel's request-path bound for the
// SHAPE check above. It is not a second copy of the kernel's rule: the kernel
// still validates every endpoint through authz.NewRequestIntent inside Probe,
// and this constant only stops a configuration file's megabyte-long entry
// reaching an error message. If it ever disagrees with the kernel the kernel
// wins, because the kernel's check is the one on the request path.
const maxRequestPathDisplayBound = 4096

// Constructed reports whether e came from NewEndpointList.
func (e EndpointList) Constructed() bool { return e.sealed && len(e.paths) > 0 }

// Paths returns a COPY of the configured list.
func (e EndpointList) Paths() []string {
	if len(e.paths) == 0 {
		return nil
	}
	out := make([]string, len(e.paths))
	copy(out, e.paths)
	return out
}

// Len returns how many endpoints are configured.
func (e EndpointList) Len() int { return len(e.paths) }

// ---------------------------------------------------------------------------
// Spec formats
// ---------------------------------------------------------------------------

// SpecFormat is the shape of a served document.
type SpecFormat string

const (
	// FormatUnrecognised is the zero value: bytes this tier cannot read.
	FormatUnrecognised SpecFormat = "unrecognised"
	// FormatOpenAPI3 is an OpenAPI 3.x JSON document.
	FormatOpenAPI3 SpecFormat = "openapi3_json"
	// FormatSwagger2 is a Swagger 2.0 JSON document.
	FormatSwagger2 SpecFormat = "swagger2_json"
	// FormatGraphQLIntrospection is a GraphQL introspection response.
	FormatGraphQLIntrospection SpecFormat = "graphql_introspection_json"
	// FormatYAML is a YAML spec. Recognised so it can be refused BY NAME.
	FormatYAML SpecFormat = "yaml"
	// FormatGRPCReflection is a gRPC reflection stream. Recognised so it can
	// be refused BY NAME.
	FormatGRPCReflection SpecFormat = "grpc_reflection"
)

// DetectFormat classifies a served document.
//
// It looks at the BYTES and at the declared content type, and it prefers the
// bytes: a target choosing its own Content-Type header is the target choosing
// how Anvil parses its document, which is one step short of choosing what
// Anvil parses. The content type is consulted only for the two formats that
// have no readable byte signature.
func DetectFormat(contentType string, body []byte) SpecFormat {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "application/grpc") {
		return FormatGRPCReflection
	}
	// U+FEFF is a byte-order mark, written as an escape because Go's scanner
	// refuses one mid-file even inside a string literal. A served document
	// that begins with a BOM would otherwise classify as
	// FormatUnrecognised, and "Anvil could not read it" would be
	// indistinguishable from "the target serves no spec".
	trimmed := strings.TrimLeft(string(body), " \t\r\n\ufeff")
	if trimmed == "" {
		return FormatUnrecognised
	}
	if trimmed[0] == '{' {
		var probe struct {
			OpenAPI json.RawMessage `json:"openapi"`
			Swagger json.RawMessage `json:"swagger"`
			Data    struct {
				Schema json.RawMessage `json:"__schema"`
			} `json:"data"`
			Schema json.RawMessage `json:"__schema"`
		}
		// The TRIMMED bytes, not the original: a document served with a
		// byte-order mark would otherwise fail to unmarshal here and come
		// back FormatUnrecognised, which reads as "the target serves no
		// spec". TestDetectFormat/with_a_byte_order_mark is the guard.
		if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
			return FormatUnrecognised
		}
		switch {
		case len(probe.OpenAPI) > 0:
			return FormatOpenAPI3
		case len(probe.Swagger) > 0:
			return FormatSwagger2
		case len(probe.Data.Schema) > 0, len(probe.Schema) > 0:
			return FormatGraphQLIntrospection
		}
		return FormatUnrecognised
	}
	// A YAML spec's first meaningful line is a top-level key. Recognising it
	// is what turns "this module has no YAML parser" from a silent empty
	// result into a named refusal.
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "openapi:") || strings.HasPrefix(line, "swagger:") ||
			strings.HasPrefix(line, "paths:") {
			return FormatYAML
		}
		break
	}
	return FormatUnrecognised
}

// ---------------------------------------------------------------------------
// ParseResult — the pure half
// ---------------------------------------------------------------------------

// ParseResult is what one served document produced.
//
// Seen, Routes and Refusals form an ACCOUNTING IDENTITY that
// AssertAccountedFor checks:
//
//	Seen == len(Routes) + (refusals whose reason is PerOperation)
//
// unless Truncated, in which case parsing stopped at the coded bound and Seen
// counts only what was read. The identity is what makes "nothing vanished
// silently" a checkable claim rather than a comment: an operation the parser
// dropped without a row would break it.
type ParseResult struct {
	// Format is what DetectFormat decided.
	Format SpecFormat
	// Routes is the extracted inventory, sorted deterministically. Every
	// entry is provenance runtime_spec, confirmation candidate, trust
	// untrusted.
	Routes []Route
	// Refusals is everything the document declared that did not become a
	// Route.
	Refusals []Refusal
	// Seen is how many operations the document declared, counting those that
	// were refused.
	Seen int
	// Truncated reports that the coded route bound stopped the parse.
	Truncated bool
	// DeclaredForeignOrigin reports that the document named a host, scheme
	// or server URL other than the target's — read and IGNORED.
	DeclaredForeignOrigin bool
}

// AssertAccountedFor checks the identity above.
//
// It is exported because it is a claim coverage reporting and the integration harness should
// be able to re-check, not merely a test helper: a parser change that starts
// dropping operations silently is a coverage inflation, and it should be
// catchable from outside this package.
func (p ParseResult) AssertAccountedFor() error {
	if p.Truncated {
		return nil
	}
	dropped := 0
	for _, r := range p.Refusals {
		if r.Reason.PerOperation() {
			dropped++
		}
	}
	if p.Seen != len(p.Routes)+dropped {
		return fmt.Errorf("inventory: %w: the parse saw %d operations and accounted for %d "+
			"(%d routes + %d per-operation refusals). An operation that vanished without a "+
			"refusal row shrinks the coverage denominator, which makes endpoint_coverage "+
			"look BETTER than it is", ErrRefused, p.Seen, len(p.Routes)+dropped,
			len(p.Routes), dropped)
	}
	return nil
}

// ---------------------------------------------------------------------------
// ParseSpec — one served document to routes
// ---------------------------------------------------------------------------

// ParseSpec turns one served document into candidate routes.
//
// It is a PURE function of (target, servedAt, contentType, body) and it opens
// nothing. That is what makes Tier 0's extraction fully testable while gate 11
// keeps the fetch half unreachable (docs/controls.md U4): a
// kernel Target is authz.NewTarget's output and needs no authorization,
// because it is gate 8/9's product and not a permission.
//
// Every route it returns carries, unconditionally and with no path through
// this function that can change any of them:
//
//	Provenance   record.InventoryProvenanceRuntimeSpec
//	Confirmation ConfirmationCandidate
//	Trust        record.TrustUntrusted
//
// A document that sets `x-anvil-confirmation`, `confirmed`, or any other field
// hoping to be believed changes nothing, because none of those fields is read.
func ParseSpec(target authz.Target, servedAt, contentType string, body []byte) (ParseResult, error) {
	if !target.Constructed() {
		return ParseResult{}, fmt.Errorf("inventory: %w: ParseSpec was handed a Target "+
			"authz.NewTarget never built, so no extracted path could be validated by the "+
			"kernel", ErrUnconstructed)
	}
	format := DetectFormat(contentType, body)
	switch format {
	case FormatOpenAPI3, FormatSwagger2:
		return parseOpenAPI(target, servedAt, format, body)
	case FormatGraphQLIntrospection:
		return parseGraphQL(target, servedAt, body)
	case FormatYAML:
		return ParseResult{Format: format, Refusals: []Refusal{{
			Endpoint: servedAt,
			Reason:   RefusalYAMLUnsupported,
			Detail: "the document is YAML and this module has no YAML parser; go.mod's " +
				"only requirement is modernc.org/sqlite. Adding one is a dependency " +
				"decision, not a local edit",
		}}}, nil
	case FormatGRPCReflection:
		return ParseResult{Format: format, Refusals: []Refusal{{
			Endpoint: servedAt,
			Reason:   RefusalGRPCReflectionUnsupported,
			Detail: "gRPC server reflection is a bidirectional HTTP/2 stream, not a " +
				"document a GET returns, so it cannot be reached through the spec-fetch " +
				"seam at all",
		}}}, nil
	default:
		return ParseResult{Format: FormatUnrecognised, Refusals: []Refusal{{
			Endpoint: servedAt,
			Reason:   RefusalFormatUnrecognised,
			Detail:   fmt.Sprintf("%d bytes that match no spec shape this tier reads", len(body)),
		}}}, nil
	}
}

// ---------------------------------------------------------------------------
// OpenAPI 3 / Swagger 2
// ---------------------------------------------------------------------------

type oasServer struct {
	URL string `json:"url"`
}

type oasDoc struct {
	OpenAPI  string                                `json:"openapi"`
	Swagger  string                                `json:"swagger"`
	Host     string                                `json:"host"`
	BasePath string                                `json:"basePath"`
	Schemes  []string                              `json:"schemes"`
	Servers  []oasServer                           `json:"servers"`
	Paths    map[string]map[string]json.RawMessage `json:"paths"`
}

type oasSchema struct {
	Type string `json:"type"`
	Ref  string `json:"$ref"`
}

type oasParam struct {
	Ref      string     `json:"$ref"`
	Name     string     `json:"name"`
	In       string     `json:"in"`
	Required bool       `json:"required"`
	Type     string     `json:"type"`
	Schema   *oasSchema `json:"schema"`
}

type oasMediaType struct {
	Schema *oasSchema `json:"schema"`
}

type oasRequestBody struct {
	Required bool                    `json:"required"`
	Content  map[string]oasMediaType `json:"content"`
}

type oasOp struct {
	OperationID string          `json:"operationId"`
	Parameters  []oasParam      `json:"parameters"`
	RequestBody *oasRequestBody `json:"requestBody"`
}

// pathItemStructuralKeys are the keys of an OpenAPI Path Item Object that are
// NOT operations.
//
// It is an allowlist and the default is a REFUSAL: a key that is neither an
// allowlisted method nor one of these produces a RefusalMethodNotAllowlisted
// row. A denylist here would let an operation under a key nobody anticipated
// disappear from the inventory without a trace, which is the direction that
// inflates coverage.
func pathItemStructuralKeys() map[string]bool {
	return map[string]bool{
		"parameters":  true,
		"summary":     true,
		"description": true,
		"servers":     true,
		"$ref":        true,
	}
}

func parseOpenAPI(target authz.Target, servedAt string, format SpecFormat, body []byte) (ParseResult, error) {
	var doc oasDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return ParseResult{Format: format, Refusals: []Refusal{{
			Endpoint: servedAt,
			Reason:   RefusalSpecUnparseable,
			Detail:   redact(err.Error()),
		}}}, nil
	}

	out := ParseResult{Format: format}
	prefix := ""

	// GATE 11'S ASYMMETRY, APPLIED. `host`, `schemes` and `servers` are read
	// ONLY so a divergence can be recorded. Nothing below assigns any of them
	// to anything the request layer will use.
	if foreign, detail := declaresForeignOrigin(target, doc); foreign {
		out.DeclaredForeignOrigin = true
		out.Refusals = append(out.Refusals, Refusal{
			Endpoint: servedAt,
			Reason:   RefusalForeignOriginIgnored,
			Detail:   detail,
		})
	}

	// Swagger 2's basePath prefixes every path. It is honoured because it
	// changes the PATH only — the host is pinned by gate 9 and nothing here
	// can move it — and because ignoring it produces an inventory of paths
	// that do not exist. It is honoured only when it is usable.
	if doc.BasePath != "" {
		if p, ok := usableBasePath(doc.BasePath); ok {
			prefix = p
		} else {
			out.Refusals = append(out.Refusals, Refusal{
				Endpoint: servedAt,
				Reason:   RefusalBasePathIgnored,
				Detail: fmt.Sprintf("basePath %q is not a usable prefix; paths are "+
					"recorded without it", redact(doc.BasePath)),
			})
		}
	}

	structural := pathItemStructuralKeys()
	seenKeys := make(map[string]bool)

	// Sorted so the output does not depend on Go's randomized map iteration.
	// An unstable route order makes record.PropRunRouteTableDigest churn for
	// a target that never changed.
	for _, rawPath := range sortedKeys(doc.Paths) {
		item := doc.Paths[rawPath]
		shared, sharedErr := decodeParams(item["parameters"])
		fullPath := prefix + rawPath

		for _, key := range sortedKeys(item) {
			if structural[key] {
				continue
			}
			out.Seen++
			if out.Seen > maxRoutesPerSpec {
				out.Truncated = true
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt,
					Reason:   RefusalSpecTruncated,
					Detail: fmt.Sprintf("the document declares more than %d operations; "+
						"parsing stopped", maxRoutesPerSpec),
				})
				SortRoutes(out.Routes)
				return out, nil
			}

			method := authz.Method(strings.ToUpper(key))
			if !method.Recognised() {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(fullPath), Method: redact(key),
					Reason: RefusalMethodNotAllowlisted,
					Detail: "the path item declares this key and it is neither an " +
						"allowlisted HTTP method nor a structural key",
				})
				continue
			}
			if sharedErr != nil {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(fullPath), Method: string(method),
					Reason: RefusalParamUnusable,
					Detail: "the path item's shared parameters did not decode: " +
						redact(sharedErr.Error()),
				})
				continue
			}

			var op oasOp
			if err := json.Unmarshal(item[key], &op); err != nil {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(fullPath), Method: string(method),
					Reason: RefusalParamUnusable,
					Detail: "the operation object did not decode: " + redact(err.Error()),
				})
				continue
			}

			params, perr := buildOASParams(format, shared, op)
			if perr != nil {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(fullPath), Method: string(method),
					Reason: RefusalParamUnusable,
					Detail: redact(perr.Error()),
				})
				continue
			}

			route, err := NewRoute(RouteFacts{
				Method:       method,
				Path:         fullPath,
				Target:       target,
				Operation:    boundIdent(op.OperationID),
				Params:       params,
				Provenance:   record.InventoryProvenanceRuntimeSpec,
				Confirmation: ConfirmationCandidate,
				Trust:        record.TrustUntrusted,
				ServedAt:     servedAt,
			})
			if err != nil {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(fullPath), Method: string(method),
					Reason: classifyRouteError(err),
					Detail: redact(err.Error()),
				})
				continue
			}
			if seenKeys[route.Key()] {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(fullPath), Method: string(method),
					Reason: RefusalDuplicateRoute,
					Detail: "the document declares this method and path more than once",
				})
				continue
			}
			seenKeys[route.Key()] = true
			out.Routes = append(out.Routes, route)
		}
	}
	SortRoutes(out.Routes)
	return out, nil
}

// classifyRouteError maps a NewRoute refusal onto a RefusalReason so the row
// says WHICH check refused.
//
// The default is RefusalRouteUnconstructible rather than a guess. A future
// NewRoute check therefore lands in a named bucket that is still counted
// per-operation, instead of being attributed to whichever existing reason
// happened to be closest.
func classifyRouteError(err error) RefusalReason {
	switch {
	case strings.Contains(err.Error(), "kernel rejected path"),
		strings.Contains(err.Error(), "\"..\" segment"):
		return RefusalPathRejectedByKernel
	case strings.Contains(err.Error(), "method allowlist"):
		return RefusalMethodNotAllowlisted
	case strings.Contains(err.Error(), "parameter"):
		return RefusalParamUnusable
	default:
		return RefusalRouteUnconstructible
	}
}

// declaresForeignOrigin reports whether the served document names an origin
// that is not the target's. It NEVER returns a value anything can dial.
func declaresForeignOrigin(target authz.Target, doc oasDoc) (bool, string) {
	canon := target.Canonical()
	if doc.Host != "" {
		host := doc.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if !strings.EqualFold(host, canon) {
			return true, fmt.Sprintf("the document declares host %q and the pinned target "+
				"is %q; the declaration was read and ignored", redact(doc.Host), redact(canon))
		}
	}
	for _, s := range doc.Servers {
		if s.URL == "" {
			continue
		}
		host := serverURLHost(s.URL)
		if host == "" {
			// A relative server URL names no origin, so it widens nothing.
			continue
		}
		if !strings.EqualFold(host, canon) {
			return true, fmt.Sprintf("the document declares server %q and the pinned "+
				"target is %q; the declaration was read and ignored",
				redact(s.URL), redact(canon))
		}
	}
	return false, ""
}

// serverURLHost extracts the host from an OpenAPI server URL WITHOUT using a
// URL parser, and returns "" for anything relative.
//
// net/url is on the kernel's inert-import allowlist and could be used here.
// It is not, on purpose: url.Parse's job is to produce a usable destination,
// and the only thing this function is allowed to produce is a string for a log
// message. A hand-rolled scan cannot accidentally hand a caller a *url.URL
// that a later edit dials.
func serverURLHost(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	// The character set is spelled "?#/" rather than "/?#" so that no string
	// literal in this file begins with a slash. That is not cosmetic:
	// TestNoRequestPathIsHardCodedInThisFile refuses every slash-leading
	// literal longer than one byte, which is how "the probe list is config"
	// is enforced by default rather than by a list of banned paths.
	if j := strings.IndexAny(rest, "?#/"); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.LastIndexByte(rest, '@'); j >= 0 {
		rest = rest[j+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			return rest[:j+1]
		}
		return rest
	}
	if j := strings.IndexByte(rest, ':'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// usableBasePath decides whether a declared basePath may prefix the document's
// paths. It refuses anything that is not a plain, dot-segment-free prefix.
func usableBasePath(b string) (string, bool) {
	if b == "" || b[0] != '/' || len(b) > maxRequestPathDisplayBound {
		return "", false
	}
	for _, seg := range strings.Split(b, "/") {
		if seg == ".." {
			return "", false
		}
	}
	// A trailing slash would double up against a path that already begins
	// with one.
	for len(b) > 1 && strings.HasSuffix(b, "/") {
		b = b[:len(b)-1]
	}
	if b == "/" {
		return "", true
	}
	return b, true
}

func decodeParams(raw json.RawMessage) ([]oasParam, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []oasParam
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func buildOASParams(format SpecFormat, shared []oasParam, op oasOp) ([]Param, error) {
	all := make([]oasParam, 0, len(shared)+len(op.Parameters))
	all = append(all, shared...)
	all = append(all, op.Parameters...)

	out := make([]Param, 0, len(all)+1)
	for _, p := range all {
		if p.Ref != "" && p.Name == "" {
			// The message avoids the "$ref" spelling on purpose: redact folds
			// "$" to "?", so a caller matching on the literal would be
			// matching a string this package never emits.
			return nil, fmt.Errorf("a parameter is a JSON Schema reference (%s) and this "+
				"tier resolves none, so it cannot be named or typed", redact(p.Ref))
		}
		if p.Name == "" {
			return nil, errors.New("a parameter has no name")
		}
		in, ok := paramInFromOAS(p.In)
		if !ok {
			return nil, fmt.Errorf("parameter %s travels in %q, which is not a location "+
				"this tier represents", redact(p.Name), redact(p.In))
		}
		out = append(out, Param{
			Name:     boundIdent(p.Name),
			In:       in,
			Type:     boundIdent(oasParamType(p)),
			Required: p.Required || in == ParamInPath,
		})
	}

	// OpenAPI 3 carries the body outside `parameters`. Swagger 2 carries it
	// as a parameter with in=body, which the loop above already handled, so
	// this runs for OpenAPI 3 only.
	if format == FormatOpenAPI3 && op.RequestBody != nil {
		out = append(out, Param{
			Name:     "requestBody",
			In:       ParamInBody,
			Type:     boundIdent(requestBodyType(op.RequestBody)),
			Required: op.RequestBody.Required,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// paramInFromOAS maps the document's `in` vocabulary onto this package's.
//
// It is an ALLOWLIST BY IDENTITY. An unrecognised location refuses the
// operation rather than defaulting it to query: a parameter filed in the wrong
// place produces a request that does not exercise the endpoint, and a probe
// that cannot reach the code it is aimed at reports clean.
func paramInFromOAS(in string) (ParamIn, bool) {
	switch in {
	case "path":
		return ParamInPath, true
	case "query":
		return ParamInQuery, true
	case "header":
		return ParamInHeader, true
	case "cookie":
		return ParamInCookie, true
	case "formData":
		return ParamInForm, true
	case "body":
		return ParamInBody, true
	default:
		return ParamInUnset, false
	}
}

// oasParamType renders the declared type, preferring Swagger 2's flat `type`,
// then OpenAPI 3's `schema.type`, then a `$ref` name.
//
// It returns "" when the document declared nothing, which is the honest
// answer: Param.Typed() then reports false and Route.FullyTyped() reports
// false, so "full parameter-typed extraction" stays a measurement.
func oasParamType(p oasParam) string {
	if p.Type != "" {
		return p.Type
	}
	if p.Schema == nil {
		return ""
	}
	if p.Schema.Type != "" {
		return p.Schema.Type
	}
	return refName(p.Schema.Ref)
}

func requestBodyType(rb *oasRequestBody) string {
	for _, media := range sortedKeys(rb.Content) {
		s := rb.Content[media].Schema
		switch {
		case s == nil:
			return media
		case s.Type != "":
			return media + ":" + s.Type
		case s.Ref != "":
			return media + ":" + refName(s.Ref)
		default:
			return media
		}
	}
	return ""
}

func refName(ref string) string {
	if ref == "" {
		return ""
	}
	if i := strings.LastIndexByte(ref, '/'); i >= 0 && i+1 < len(ref) {
		return ref[i+1:]
	}
	return ref
}

// ---------------------------------------------------------------------------
// GraphQL introspection
// ---------------------------------------------------------------------------

type gqlNamed struct {
	Name string `json:"name"`
}

type gqlTypeRef struct {
	Kind   string      `json:"kind"`
	Name   *string     `json:"name"`
	OfType *gqlTypeRef `json:"ofType"`
}

type gqlArg struct {
	Name string      `json:"name"`
	Type *gqlTypeRef `json:"type"`
}

type gqlField struct {
	Name string   `json:"name"`
	Args []gqlArg `json:"args"`
}

type gqlType struct {
	Kind   string     `json:"kind"`
	Name   string     `json:"name"`
	Fields []gqlField `json:"fields"`
}

type gqlSchema struct {
	QueryType        *gqlNamed `json:"queryType"`
	MutationType     *gqlNamed `json:"mutationType"`
	SubscriptionType *gqlNamed `json:"subscriptionType"`
	Types            []gqlType `json:"types"`
}

type gqlDoc struct {
	Data struct {
		Schema *gqlSchema `json:"__schema"`
	} `json:"data"`
	Schema *gqlSchema `json:"__schema"`
}

// parseGraphQL extracts one route per ROOT FIELD of the query, mutation and
// subscription types.
//
// A GraphQL service has one HTTP endpoint and an unbounded number of
// operations reachable through it. Counting it as ONE endpoint would make
// endpoint_coverage meaningless for a GraphQL target — probing the single
// endpoint once would read as complete coverage of the whole schema — so the
// unit of inventory here is the root field, and Route.Operation carries
// `Query.user` while Route.Path carries the endpoint the document arrived on.
func parseGraphQL(target authz.Target, servedAt string, body []byte) (ParseResult, error) {
	var doc gqlDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return ParseResult{Format: FormatGraphQLIntrospection, Refusals: []Refusal{{
			Endpoint: servedAt,
			Reason:   RefusalSpecUnparseable,
			Detail:   redact(err.Error()),
		}}}, nil
	}
	schema := doc.Data.Schema
	if schema == nil {
		schema = doc.Schema
	}
	out := ParseResult{Format: FormatGraphQLIntrospection}
	if schema == nil {
		out.Refusals = append(out.Refusals, Refusal{
			Endpoint: servedAt,
			Reason:   RefusalSpecUnparseable,
			Detail:   "the response carries no __schema object",
		})
		return out, nil
	}

	// The endpoint the introspection response arrived on is the path every
	// GraphQL operation is reached through. If the kernel will not accept it
	// there is nothing to inventory.
	if err := kernelAcceptsPath(target, authz.MethodPost, servedAt); err != nil {
		out.Refusals = append(out.Refusals, Refusal{
			Endpoint: servedAt,
			Reason:   RefusalPathRejectedByKernel,
			Detail:   redact(err.Error()),
		})
		return out, nil
	}

	byName := make(map[string]gqlType, len(schema.Types))
	for _, t := range schema.Types {
		if t.Name != "" {
			byName[t.Name] = t
		}
	}

	roots := []*gqlNamed{schema.QueryType, schema.MutationType, schema.SubscriptionType}
	seenKeys := make(map[string]bool)
	for _, root := range roots {
		if root == nil || root.Name == "" {
			continue
		}
		rootType, ok := byName[root.Name]
		if !ok {
			out.Refusals = append(out.Refusals, Refusal{
				Endpoint: servedAt,
				Reason:   RefusalSpecUnparseable,
				Detail: fmt.Sprintf("the schema names root type %s and the types list "+
					"does not contain it", redact(root.Name)),
			})
			continue
		}
		for _, field := range rootType.Fields {
			out.Seen++
			if out.Seen > maxRoutesPerSpec {
				out.Truncated = true
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt,
					Reason:   RefusalSpecTruncated,
					Detail: fmt.Sprintf("the schema declares more than %d root fields; "+
						"parsing stopped", maxRoutesPerSpec),
				})
				SortRoutes(out.Routes)
				return out, nil
			}
			operation := root.Name + "." + field.Name
			if field.Name == "" {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(servedAt),
					Method: string(authz.MethodPost),
					Reason: RefusalParamUnusable,
					Detail: "a root field of " + redact(root.Name) + " has no name",
				})
				continue
			}
			params, err := buildGQLParams(field.Args)
			if err != nil {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(servedAt),
					Method: string(authz.MethodPost),
					Reason: RefusalParamUnusable,
					Detail: redact(operation) + ": " + redact(err.Error()),
				})
				continue
			}
			route, err := NewRoute(RouteFacts{
				Method:       authz.MethodPost,
				Path:         servedAt,
				Target:       target,
				Operation:    boundIdent(operation),
				Params:       params,
				Provenance:   record.InventoryProvenanceRuntimeSpec,
				Confirmation: ConfirmationCandidate,
				Trust:        record.TrustUntrusted,
				ServedAt:     servedAt,
			})
			if err != nil {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(servedAt),
					Method: string(authz.MethodPost),
					Reason: classifyRouteError(err),
					Detail: redact(err.Error()),
				})
				continue
			}
			if seenKeys[route.Key()] {
				out.Refusals = append(out.Refusals, Refusal{
					Endpoint: servedAt, Path: redact(servedAt),
					Method: string(authz.MethodPost),
					Reason: RefusalDuplicateRoute,
					Detail: "the schema declares root field " + redact(operation) + " twice",
				})
				continue
			}
			seenKeys[route.Key()] = true
			out.Routes = append(out.Routes, route)
		}
	}
	SortRoutes(out.Routes)
	return out, nil
}

func buildGQLParams(args []gqlArg) ([]Param, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make([]Param, 0, len(args))
	for _, a := range args {
		if a.Name == "" {
			return nil, errors.New("an argument has no name")
		}
		rendered, required, err := renderTypeRef(a.Type, 0)
		if err != nil {
			return nil, fmt.Errorf("argument %s: %w", redact(a.Name), err)
		}
		out = append(out, Param{
			Name:     boundIdent(a.Name),
			In:       ParamInGraphQLArgument,
			Type:     boundIdent(rendered),
			Required: required,
		})
	}
	return out, nil
}

// renderTypeRef unwraps GraphQL's NON_NULL / LIST wrappers into a printable
// type string and reports whether the OUTERMOST wrapper was NON_NULL.
//
// The depth bound is not defensiveness: the ofType chain is attacker-supplied
// and self-referential JSON is cheap to write. An unbounded unwrap is a stack
// overflow reachable from a served document.
func renderTypeRef(t *gqlTypeRef, depth int) (string, bool, error) {
	if t == nil {
		return "", false, nil
	}
	if depth > maxTypeRefDepth {
		return "", false, fmt.Errorf("the type reference nests deeper than the coded bound "+
			"of %d", maxTypeRefDepth)
	}
	switch t.Kind {
	case "NON_NULL":
		inner, _, err := renderTypeRef(t.OfType, depth+1)
		if err != nil {
			return "", false, err
		}
		if inner == "" {
			return "", false, errors.New("a NON_NULL wrapper has no inner type")
		}
		return inner + "!", true, nil
	case "LIST":
		inner, _, err := renderTypeRef(t.OfType, depth+1)
		if err != nil {
			return "", false, err
		}
		if inner == "" {
			return "", false, errors.New("a LIST wrapper has no inner type")
		}
		return "[" + inner + "]", false, nil
	default:
		if t.Name == nil || *t.Name == "" {
			return "", false, errors.New("a named type reference has no name")
		}
		return *t.Name, false, nil
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// boundIdent truncates an identifier lifted from a served document to the
// coded bound. It truncates rather than refusing because a long operationId is
// cosmetic — NewRoute refuses anything that is still over the bound, so a
// truncation bug cannot smuggle an unbounded string past the constructor.
func boundIdent(s string) string {
	if len(s) <= maxIdentBytes {
		return s
	}
	return s[:maxIdentBytes]
}

// ---------------------------------------------------------------------------
// The egress seam
// ---------------------------------------------------------------------------

// SpecRequest is one kernel-admitted spec fetch.
//
// It has unexported fields and NO exported constructor, so the only
// SpecRequest that exists anywhere is one Probe built after
// authz.RequireAuthorization passed and authz.GateAudit.AuditedAdmit admitted.
// A composite literal in another package is a compile error, not a lint —
// which is the same property engines.AdmittedRequest holds, for the same
// reason: argument construction is a security boundary when the argument is a
// destination.
type SpecRequest struct {
	auth     authz.Authorization
	target   authz.Target
	endpoint string
	seq      authz.AuditSeq
	sealed   bool
}

// Constructed reports whether r was built by Probe.
func (r SpecRequest) Constructed() bool { return r.sealed && r.target.Constructed() }

// Authorization returns the kernel token this fetch rests on. An implementor
// MUST pass it to authz.RequireAuthorization (or authz.PinnedDialAddress,
// which calls it) immediately before constructing a socket.
func (r SpecRequest) Authorization() authz.Authorization { return r.auth }

// Target returns the authorized destination, pinned address and all.
func (r SpecRequest) Target() authz.Target { return r.target }

// Endpoint returns the well-known spec path to fetch.
func (r SpecRequest) Endpoint() string { return r.endpoint }

// Method returns the method this fetch uses. It is always GET: fetching a
// document is a read, and a spec probe that could be handed a state-changing
// method is a spec probe that can be pointed at a mutation.
func (r SpecRequest) Method() authz.Method { return authz.MethodGet }

// AuditSeq returns the gate-21 row this fetch was admitted under.
func (r SpecRequest) AuditSeq() authz.AuditSeq { return r.seq }

// SpecResponse is what the fetcher got back.
//
// Body is an io.Reader and not a []byte on purpose: Probe wraps it in
// authz.LimitBody so gate 14's cap is enforced WHILE READING. A []byte would
// mean the fetcher had already buffered whatever the target sent, and the cap
// would then be a check applied after the damage.
type SpecResponse struct {
	// Status is the HTTP status code the target answered with. A response
	// that reaches this struct at all counts toward Result.Answered, whatever
	// its status.
	Status int
	// ContentType is the response's declared media type. It is a target-
	// controlled string and is used only as a fallback hint by DetectFormat.
	ContentType string
	// Body is the response body, unread. May be nil for a status with none.
	Body io.Reader
}

// SpecFetcher is the egress seam.
//
// # Why this is an interface and not a function that dials
//
// The build-time guard's gate 3 tier 1: a socket constructed inside internal/dast outside
// internal/dast/authz fails the build, with no allowlist. This package
// therefore cannot dial, cannot hold an http.Client, and cannot import a
// package that could. The implementation lives on the far side of that
// boundary — in the kernel, or in cmd/anvil-dast — and is handed in.
type SpecFetcher interface {
	FetchSpec(ctx context.Context, req SpecRequest) (SpecResponse, error)
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

// Result is one Tier 0 run against one target.
//
// It carries counters and refusals alongside the routes because "no routes"
// has two completely different meanings and a bare `[]Route` cannot tell them
// apart: an application that serves no spec, and an Anvil that never got an
// answer. AssertNotSilentlyEmpty is where the caller is made to choose.
type Result struct {
	routes []Route
	// specEndpoints is every configured endpoint the target answered 200 on.
	// It is recorded rather than DERIVED from routes: a document that parses
	// and declares no paths still proves the endpoint exists, and deriving
	// this list would lose exactly that observation.
	specEndpoints []string
	refusals      []Refusal
	probed        int
	answered      int
	fetched       int
	truncated     bool
	sealed        bool
}

// Constructed reports whether r came from Probe.
func (r Result) Constructed() bool { return r.sealed }

// Routes returns a deep COPY of the inventory, sorted deterministically.
func (r Result) Routes() []Route { return cloneRoutes(r.routes) }

// Refusals returns a COPY of everything that did not become a route.
func (r Result) Refusals() []Refusal { return cloneRefusals(r.refusals) }

// Probed returns how many configured endpoints were attempted.
func (r Result) Probed() int { return r.probed }

// Answered returns how many endpoints the TARGET answered, whatever the
// status. It is the number that separates "this application serves no spec"
// from "Anvil never reached this application".
func (r Result) Answered() int { return r.answered }

// Fetched returns how many endpoints yielded a document that parsed.
func (r Result) Fetched() int { return r.fetched }

// Truncated reports that a served document exceeded the coded route bound.
func (r Result) Truncated() bool { return r.truncated }

// ProbedSpecEndpoints returns the endpoints Anvil itself observed: the ones
// that answered 200 with a parseable document.
//
// These are the ONLY endpoints in Tier 0 that a later packet may treat as
// CONFIRMED, and they are confirmed by Anvil's own kernel-admitted request
// rather than by anything a document said. Everything in Routes() is a
// candidate.
func (r Result) ProbedSpecEndpoints() []string {
	if len(r.specEndpoints) == 0 {
		return nil
	}
	out := make([]string, len(r.specEndpoints))
	copy(out, r.specEndpoints)
	return out
}

// DenominatorFloor is the smallest number of endpoints coverage reporting may use in the
// Tier 0 half of endpoint_coverage's denominator.
//
// It is len(routes) PLUS every per-operation refusal, and the addition is the
// point. An operation this tier saw and could not represent is attack surface
// that exists; leaving it out shrinks the denominator, and a smaller
// denominator makes endpoint_coverage look BETTER. Coverage arithmetic must
// only ever fail in the pessimistic direction.
func (r Result) DenominatorFloor() int {
	n := len(r.routes)
	for _, ref := range r.refusals {
		if ref.Reason.PerOperation() {
			n++
		}
	}
	return n
}

// AssertNotSilentlyEmpty decides whether an empty Tier 0 inventory is a
// statement about the TARGET or a statement about ANVIL.
//
// "The target serves no spec" and "nothing Anvil sent ever arrived" produce
// byte-identical route lists. For an attack-surface inventory that is the
// worst available failure mode, because the empty list flows straight into the
// denominator of endpoint_coverage and a denominator of zero is the shape
// every "100% covered" report is made of. So the two are separated by a
// predicate the caller must call.
//
// It returns nil when either at least one route was extracted, or the target
// answered at least once — an answer of 404 at every configured endpoint is a
// real, reportable finding that this application serves no runtime spec.
func (r Result) AssertNotSilentlyEmpty() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: AssertNotSilentlyEmpty was called on a Result "+
			"Probe never built", ErrUnconstructed)
	}
	if len(r.routes) > 0 || r.answered > 0 {
		return nil
	}
	return fmt.Errorf("%w: %d endpoints were attempted, the target answered %d times, and "+
		"%d refusals were recorded. An empty Tier 0 inventory here describes Anvil's reach, "+
		"not the target's surface, and must not become the denominator of endpoint_coverage",
		ErrNothingProbed, r.probed, r.answered, len(r.refusals))
}

// ---------------------------------------------------------------------------
// The prober
// ---------------------------------------------------------------------------

// Config is everything a Prober needs. Every field is required except Fetcher;
// there is no default for any of them, because a default here would be a gate
// running against a value nobody chose.
type Config struct {
	// Governor is the kernel's per-request interceptor for this target.
	Governor *authz.Governor
	// Audit is gate 21's writer, coupled to the interceptor by AuditedAdmit:
	// an admission whose audit row did not land is not an admission.
	Audit *authz.GateAudit
	// Authorization is the kernel token for Target.
	Authorization authz.Authorization
	// Target is the admitted target to probe.
	Target authz.Target
	// Endpoints is the CONFIGURED spec-endpoint list. There is no default.
	Endpoints EndpointList
	// Fetcher is the egress layer. A nil Fetcher is legal to construct and
	// produces a counted refusal at Probe — never a silent empty inventory.
	Fetcher SpecFetcher
}

// Prober is the Tier 0 runtime spec probe.
type Prober struct {
	cfg    Config
	sealed bool
}

// NewProber assembles the prober. It refuses anything the kernel did not
// build, and it checks the authorization against the target HERE — so a
// Prober that exists at all is one whose target passed gates 8, 9 and 10.
func NewProber(cfg Config) (*Prober, error) {
	if !cfg.Governor.Constructed() {
		return nil, fmt.Errorf("inventory: %w: the prober was handed a Governor "+
			"authz.NewGovernor never built. A nil governor enforces nothing, and enforcing "+
			"nothing is not admitting everything", ErrUnconstructed)
	}
	if !cfg.Audit.Constructed() {
		return nil, fmt.Errorf("inventory: %w: the prober was handed a GateAudit "+
			"authz.NewGateAudit never built. Gate 21 requires every decision recorded, and "+
			"a prober with no audit writer records none", ErrUnconstructed)
	}
	if !cfg.Endpoints.Constructed() {
		return nil, fmt.Errorf("inventory: %w: the prober was handed an EndpointList "+
			"NewEndpointList never built. plan/design/dynamic-tier.md forbids a hard-coded probe list "+
			"and there is therefore no default to substitute", ErrUnconstructed)
	}
	if !cfg.Target.Constructed() {
		return nil, fmt.Errorf("inventory: %w: the prober was handed a Target "+
			"authz.NewTarget never built", ErrUnconstructed)
	}
	if err := authz.RequireAuthorization(cfg.Authorization, cfg.Target); err != nil {
		return nil, fmt.Errorf("inventory: %w: %w", ErrRefused, err)
	}
	return &Prober{cfg: cfg, sealed: true}, nil
}

// Constructed reports whether p came from NewProber.
func (p *Prober) Constructed() bool { return p != nil && p.sealed }

// Probe fetches every configured spec endpoint through the kernel and parses
// whatever comes back.
//
// The order per endpoint, and what each step is for:
//
//	1  the endpoint becomes an authz.RequestIntent, which applies the
//	   kernel's own path rule rather than a copy of it here
//	2  authz.RequireAuthorization re-checks the token against the target
//	   immediately before anything can leave — gate 3's runtime half, done
//	   again even though NewProber already did it, because it costs a
//	   comparison
//	3  authz.GateAudit.AuditedAdmit runs the per-request gate chain and
//	   writes one gate-21 row per gate. A refusal at any of them ends this
//	   endpoint with a counted Refusal.
//	4  only now does anything leave the process, and it leaves through the
//	   SpecFetcher, which this package cannot implement
//	5  the body is read through authz.LimitBody, so gate 14's cap refuses at
//	   the byte that crosses it rather than after buffering
//	6  ParseSpec extracts CANDIDATES
//
// Every failure at every step produces a Refusal in the Result. None produces
// a shorter route list with no explanation.
func (p *Prober) Probe(ctx context.Context, now authz.Clock) (Result, error) {
	if !p.Constructed() {
		return Result{}, fmt.Errorf("inventory: %w: Probe was called on a Prober NewProber "+
			"never built", ErrUnconstructed)
	}
	out := Result{sealed: true}
	seenKeys := make(map[string]bool)

	for _, endpoint := range p.cfg.Endpoints.Paths() {
		out.probed++

		intent, err := authz.NewRequestIntent(authz.RequestFacts{
			Origin:   authz.OriginInitial,
			Admitted: p.cfg.Target,
			Next:     p.cfg.Target,
			Method:   authz.MethodGet,
			Path:     endpoint,
		})
		if err != nil {
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalIntentRejected,
				Detail:   redact(err.Error()),
			})
			continue
		}

		if err := authz.RequireAuthorization(p.cfg.Authorization, p.cfg.Target); err != nil {
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalKernelRefused,
				Detail:   redact(err.Error()),
			})
			continue
		}

		// TechniqueVersionFingerprint is what fetching a service's own
		// description is: a read that identifies the software. It is on
		// gate 15's permitted list, and naming it accurately matters
		// because gate 15 judges the DECLARED technique — calling this
		// passive_observation would be the mislabelling that gate's
		// residual-risk note warns about.
		lease, res := p.cfg.Audit.AuditedAdmit(p.cfg.Governor, intent,
			authz.TechniqueVersionFingerprint, now)
		if !res.Passed() {
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalKernelRefused,
				Detail: fmt.Sprintf("the kernel refused at %s: %s",
					res.Gate(), redact(errText(res.Err()))),
			})
			continue
		}

		req := SpecRequest{
			auth:     p.cfg.Authorization,
			target:   p.cfg.Target,
			endpoint: endpoint,
			seq:      p.cfg.Audit.LastSeq(),
			sealed:   true,
		}
		if p.cfg.Fetcher == nil {
			lease.Release()
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalNoFetcherWired,
				Detail: "the kernel admitted this spec fetch and there is no egress seam " +
					"to issue it through",
			})
			continue
		}

		resp, ferr := p.cfg.Fetcher.FetchSpec(ctx, req)
		lease.Release()
		if ferr != nil {
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalFetchFailed,
				Detail:   redact(ferr.Error()),
			})
			continue
		}

		// The target answered. This is the observation that separates an
		// application with no spec from an Anvil that never arrived.
		out.answered++

		if resp.Status == 200 {
			// THE ONE CONFIRMATION TIER 0 IS ENTITLED TO MAKE. Anvil issued
			// a kernel-admitted request to this path and the target answered
			// 200: that is Anvil's own observation, not the document's claim
			// about itself, and it is the only thing here a later packet may
			// treat as confirmed. Everything in Routes() stays a candidate.
			out.specEndpoints = append(out.specEndpoints, endpoint)
		}

		if resp.Status != 200 {
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalStatusNotOK,
				Detail:   fmt.Sprintf("the target answered %d", resp.Status),
			})
			continue
		}

		body, berr := readBounded(resp.Body)
		if berr != nil {
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalBodyExceedsCap,
				Detail:   redact(berr.Error()),
			})
			continue
		}

		parsed, perr := ParseSpec(p.cfg.Target, endpoint, resp.ContentType, body)
		if perr != nil {
			out.refusals = append(out.refusals, Refusal{
				Endpoint: redact(endpoint),
				Reason:   RefusalSpecUnparseable,
				Detail:   redact(perr.Error()),
			})
			continue
		}
		if parsed.Truncated {
			out.truncated = true
		}
		// Fetched counts documents this tier could READ, not documents that
		// happened to declare a path. A spec with an empty `paths` object is
		// a spec Anvil read; conflating it with an unreadable one would put
		// "we could not parse it" and "it declares nothing" in the same
		// bucket, which is the confusion this whole file is shaped against.
		switch parsed.Format {
		case FormatOpenAPI3, FormatSwagger2, FormatGraphQLIntrospection:
			out.fetched++
		}
		out.refusals = append(out.refusals, parsed.Refusals...)

		// Two configured endpoints can serve the same document — a
		// springdoc target commonly answers on more than one path. Merging
		// on Route.Key stops that counting the same surface twice, which
		// would inflate the denominator of endpoint_coverage.
		for _, rt := range parsed.Routes {
			if seenKeys[rt.Key()] {
				out.refusals = append(out.refusals, Refusal{
					Endpoint: redact(endpoint),
					Path:     redact(rt.Path()),
					Method:   string(rt.Method()),
					Reason:   RefusalDuplicateRoute,
					Detail:   "already inventoried from another spec endpoint",
				})
				continue
			}
			seenKeys[rt.Key()] = true
			out.routes = append(out.routes, rt)
		}
	}
	SortRoutes(out.routes)
	return out, nil
}

// ProbeRuntimeSpecs is the entry point the runtime spec probe's design names.
//
// DEVIATION, stated: the plan's expected schema is
// `ProbeRuntimeSpecs(target *Target, endpoints []string) ([]Route, error)`.
// Three things about it could not survive contact with the kernel's build-time
// guard and the nuclei driver's established seam, and each is a refusal this
// signature makes impossible:
//
//   - A bare `target` cannot issue a request. Every request in Anvil goes
//     through a Governor and a GateAudit against an Authorization, so those
//     are in Config rather than absent.
//   - A bare `[]Route` return cannot distinguish "this application serves no
//     spec" from "no request ever arrived", and the difference lands in the
//     denominator of endpoint_coverage. Result carries the counters and the
//     refusals; AssertNotSilentlyEmpty is the predicate.
//   - `endpoints []string` is kept, and NewEndpointList refuses an empty one,
//     because the plan's own Forbidden actions require the list to be config.
func ProbeRuntimeSpecs(ctx context.Context, cfg Config, now authz.Clock) (Result, error) {
	prober, err := NewProber(cfg)
	if err != nil {
		return Result{}, err
	}
	return prober.Probe(ctx, now)
}

// readBounded reads a response body through gate 14's cap.
//
// authz.LimitBody is the kernel's, and it refuses AT THE BYTE that crosses the
// cap rather than after io.ReadAll has already put the whole thing on the
// heap. The response body is the spine's highest-risk field; a
// resource-exhaustion probe pointed at Anvil is still a resource-exhaustion
// probe.
func readBounded(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, errors.New("the response carried no body")
	}
	bounded, res := authz.LimitBody(r, authz.CodedCaps())
	if !res.Passed() {
		return nil, fmt.Errorf("gate 14 refused to bound the body: %s", errText(res.Err()))
	}
	body, err := io.ReadAll(bounded)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func errText(err error) string {
	if err == nil {
		return "no detail"
	}
	return err.Error()
}
