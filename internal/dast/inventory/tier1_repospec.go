// This file is packet D.19: Tier 1, the repo-spec route.
//
// ===========================================================================
// WHAT TIER 1 IS, AND WHAT IT IS NOT
// ===========================================================================
//
// Tier 1 consumes spec files the SAST pass already harvested from the target
// repository — openapi.yaml, swagger.json, *.wsdl, schema.graphql, AsyncAPI
// documents, Postman collections — and turns them into inventory routes.
//
// plan/50-dast.md:628-630 forbids this step from harvesting anything itself:
// "Do not have this step or its dependents re-derive spec harvesting from the
// repo directly — that is explicitly the SAST tier's job." That is not a
// convention here. This file opens no file, knows no repository path, and
// cannot: TestTier1KnowsNoRepositoryPathAndOpensNothing parses this file's own
// syntax tree and fails on any filesystem import and on any slash-leading
// string literal longer than one byte. A glob nobody thought to ban is caught
// by default rather than by memory.
//
// ===========================================================================
// A SPEC FILE FROM THE REPOSITORY IS ATTACKER-AUTHORED INPUT
// ===========================================================================
//
// The manifest packet learned this the expensive way: 169.254.169.254 was a
// legal Compose service name, so a committed file could point Anvil's health
// check at the cloud metadata endpoint. A `servers[].url` in a committed
// OpenAPI document, a `soap:address location` in a committed WSDL, and a
// request URL in a committed Postman collection are the same shape of thing —
// A NETWORK DESTINATION SUPPLIED BY THE REPOSITORY — and they are treated
// exactly as hostile as that manifest's health.url.
//
// So gate 11's asymmetry, which D.18 applied to a document served by a live
// target, applies here verbatim:
//
//	A SPEC FILE FROM THE REPOSITORY MAY ONLY ADD DENIES, NEVER GRANTS.
//
//	MAY   add CANDIDATE routes to the inventory
//	MAY   enlarge the denominator of endpoint_coverage
//	NEVER widen scope         -- a declared `servers` URL, a WSDL address
//	                             location and a Postman host are read ONLY so
//	                             the divergence can be RECORDED. Only the PATH
//	                             component of any of them is ever used, and the
//	                             host is pinned by gate 9 where a path cannot
//	                             reach it.
//	NEVER grant authorization -- this file cannot mint an authz.Authorization,
//	                             holds no fetcher, and opens no socket
//	NEVER mark anything confirmed
//
// record.TrustUntrusted is stamped on every route this file produces, with no
// code path that can change it. The harvester does not get to say otherwise
// and neither does the file.
//
// ===========================================================================
// CONFIRMATION IS D.22's, NOT THIS PACKET's
// ===========================================================================
//
// DEVIATION FROM plan/50-dast.md:632-635, stated rather than hidden. That block
// says every Tier 1 route is "status: confirmed (a spec checked into the repo
// is authoritative for what the developer intended, though still worth Tier-0
// cross-checking where both exist)". This file does not do that, on the
// orchestrator's standing instruction, and the instruction is right for the
// same reason D.18's equivalent deviation is right:
//
//	`confirmed` is the direction that moves an endpoint into the NUMERATOR of
//	endpoint_coverage (plan/50-dast.md:1152). What Anvil observed here is that
//	A FILE EXISTS IN THE REPOSITORY AND PARSED. That `DELETE /internal/admin`
//	appears inside it is the repository's claim about a service Anvil has not
//	touched. A repo whose openapi.yaml is six months stale — which is the
//	normal condition of a checked-in spec — would otherwise hand Anvil a
//	numerator full of endpoints that no longer exist.
//
// research/22-attack-surface-discovery.md's own instruction for the adjacent
// tier is "promote to `confirmed` only on a non-404 response". Tier 1 stamps
// ConfirmationCandidate unconditionally; D.22 owns the promotion.
//
// ===========================================================================
// THE INPUT SHAPE, RECONCILED AGAINST internal/record (RULING 7)
// ===========================================================================
//
// plan/50-dast.md:625-627 told this packet to "treat the input as an injected
// []SpecFile{Path, Format, Content} slice and flag the exact record field name
// as a TODO for reconciliation with the SAST plan", and :1246-1248 records the
// input shape as an open question. The record schema is now built, committed
// and frozen, so the reconciliation is done rather than deferred, and it has a
// finding in it:
//
//	internal/record CARRIES NO SPEC-HARVEST FIELD. There is no `SpecFile`, no
//	`Artifacts` list, and no run-level slot for files the SAST pass harvested.
//	grep over internal/record/contract.go and internal/record/CONTRACT.md finds
//	nothing. That is reported to the orchestrator rather than fixed here:
//	internal/record is shared vocabulary four areas consume and it is outside
//	this packet's write scope.
//
// So SpecFile is built out of the SARIF vocabulary internal/record ACTUALLY
// owns for "a file in the target repo, and its bytes":
//
//	record.ArtifactLocation  (SARIF §3.4)  -- which file, as a URI
//	record.ArtifactContent   (SARIF §3.3)  -- its bytes, as text
//
// Those are the closest existing shapes, they are already the types the record
// uses to name repo files elsewhere (PhysicalLocation.ArtifactLocation,
// WebResponse.Body), and a later `record.SpecHarvest` field carrying the same
// two types drops straight in. The field this packet needs, named precisely
// for the orchestrator: a run-level `anvil/specHarvest` on record.RunProperties
// holding `[]{Location record.ArtifactLocation; Content record.ArtifactContent;
// Format string}` plus the harvest outcome below.
//
// ===========================================================================
// AN EMPTY TIER 1 INVENTORY HAS THREE MEANINGS AND THEY ARE NOT THE SAME
// ===========================================================================
//
//	the repository ships no spec files            -- a fact about the repo
//	the harvest pass never ran                    -- a fact about Anvil
//	files arrived and none of them could be read  -- a fact about Anvil
//
// All three produce a byte-identical empty route list, and that list flows
// into the denominator of endpoint_coverage where a zero denominator is the
// shape every "100% covered" report is made of. HarvestOutcome is therefore a
// REQUIRED input with no legal zero value, and AssertNotSilentlyEmpty is the
// predicate that makes the caller choose between the three.
//
// ===========================================================================
// THERE IS ONE OpenAPI PARSER IN THIS PACKAGE AND IT IS D.18's
// ===========================================================================
//
// Every format below converges on parseOpenAPI (tier0_runtime.go), which
// already holds the kernel path validation, the foreign-origin refusal, the
// basePath rule, the structural-key allowlist, the duplicate detection and the
// per-operation accounting. YAML is converted to JSON, a Postman collection is
// converted to an OpenAPI document at ingest (research 22: Nuclei's `-im`
// modes are `list, burp, jsonl, yaml, openapi, swagger` and do not include
// Postman), and both then go through that one parser.
//
// parseOpenAPI stamps record.InventoryProvenanceRuntimeSpec, because it was
// written for a document served by a live target. retagAsRepoSpec rebuilds
// every route it returns THROUGH NewRoute with repo_spec/candidate/untrusted,
// unconditionally, ignoring whatever the incoming route carried. A second
// OpenAPI parser in this file would be a second set of rules that can disagree
// with the first; a retag cannot disagree with anything.
//
// WSDL and GraphQL SDL have no OpenAPI equivalent and are parsed here, each
// ending at the same NewRoute.
//
// Sources: plan/50-dast.md D.19 (lines 617-643) and the Coverage Reporting
// Contract (lines 1142-1160); research/22-attack-surface-discovery.md lines
// 325-328; internal/record/contract.go (InventoryProvenance, Trust,
// ArtifactLocation, ArtifactContent, DastCoverage).
package inventory

import (
	"encoding/json"
	"encoding/xml"
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

// ErrNothingIngested is what IngestResult.AssertNotSilentlyEmpty returns when
// Tier 1 produced no routes and the run cannot show that the repository is
// genuinely specless. It is the Tier 1 twin of ErrNothingProbed.
var ErrNothingIngested = errors.New("inventory: nothing was ingested; an empty Tier 1 " +
	"inventory here describes Anvil's harvest, not the repository's surface")

// ---------------------------------------------------------------------------
// Coded bounds
// ---------------------------------------------------------------------------

const (
	// maxSpecFileBytes bounds one harvested file. The bytes are
	// attacker-authored and this tier holds them entirely in memory; a
	// hundred-megabyte openapi.yaml committed to a repository is a
	// resource-exhaustion probe pointed back at Anvil, and refusing it BY
	// NAME is the difference between a reported refusal and an OOM.
	maxSpecFileBytes = 4 << 20

	// maxSpecFilesPerIngest bounds how many harvested files one run may
	// carry.
	maxSpecFilesPerIngest = 4096

	// maxSpecURIBytes bounds the artifact URI naming a harvested file. The
	// URI is repository-authored and reaches log lines.
	maxSpecURIBytes = 2048

	// maxYAMLLines and maxYAMLLineBytes bound the block-YAML reader's input.
	maxYAMLLines     = 200000
	maxYAMLLineBytes = 65536

	// maxYAMLDepth bounds mapping/sequence nesting. Aliases are refused, so
	// a billion-laughs expansion cannot be built at all; this bounds plain
	// nesting, which is a stack overflow reachable from a committed file.
	maxYAMLDepth = 64

	// maxYAMLNodes bounds how many scalars, mapping entries and sequence
	// items one document may produce.
	maxYAMLNodes = 500000

	// maxSDLFields and maxSDLArgs bound GraphQL SDL extraction.
	maxSDLFields = 20000
	maxSDLArgs   = 256

	// maxPostmanItems bounds a Postman collection's item tree, counting
	// folders, and maxPostmanDepth bounds how deep folders may nest.
	maxPostmanItems = 20000
	maxPostmanDepth = 64

	// maxWSDLOperations bounds one WSDL document's (port x operation) grid.
	maxWSDLOperations = 20000
)

// ---------------------------------------------------------------------------
// Formats this tier reads, added to D.18's SpecFormat vocabulary
// ---------------------------------------------------------------------------

// These are constants of tier0_runtime.go's SpecFormat, not a parallel type.
// Four packets share this package and a second format enum is precisely the
// produce/consume break section 6 of plan/IMPLEMENTATION-PLAN.md exists to
// prevent. FormatUnrecognised, FormatOpenAPI3, FormatSwagger2 and
// FormatGraphQLIntrospection are D.18's and are reused as-is.
const (
	// FormatOpenAPI3YAML is an OpenAPI 3.x document written in YAML.
	FormatOpenAPI3YAML SpecFormat = "openapi3_yaml"
	// FormatSwagger2YAML is a Swagger 2.0 document written in YAML.
	FormatSwagger2YAML SpecFormat = "swagger2_yaml"
	// FormatWSDL is a WSDL 1.1 service description.
	FormatWSDL SpecFormat = "wsdl"
	// FormatGraphQLSDL is a GraphQL schema definition document.
	FormatGraphQLSDL SpecFormat = "graphql_sdl"
	// FormatPostmanCollection is a Postman collection, v2.x.
	FormatPostmanCollection SpecFormat = "postman_collection_json"
	// FormatAsyncAPI is an AsyncAPI document. Recognised so it can be
	// refused BY NAME: an AsyncAPI channel is a message topic on a broker,
	// not an HTTP endpoint, and inventing a route from one would put an
	// unprobeable row in the coverage denominator.
	FormatAsyncAPI SpecFormat = "asyncapi"
)

// RepoSpecFormatValues returns every format Tier 1 classifies, including the
// two it refuses by name.
func RepoSpecFormatValues() []SpecFormat {
	return []SpecFormat{
		FormatOpenAPI3, FormatSwagger2, FormatOpenAPI3YAML, FormatSwagger2YAML,
		FormatWSDL, FormatGraphQLSDL, FormatPostmanCollection,
		FormatGraphQLIntrospection, FormatAsyncAPI,
	}
}

// readableRepoSpecFormats is the set Tier 1 can turn into routes. It is an
// ALLOWLIST: a format added to the vocabulary is not readable until somebody
// adds it here, which is the safe direction — forgetting understates
// IngestResult.Ingested rather than overstating coverage.
func readableRepoSpecFormats() map[SpecFormat]bool {
	return map[SpecFormat]bool{
		FormatOpenAPI3:             true,
		FormatSwagger2:             true,
		FormatOpenAPI3YAML:         true,
		FormatSwagger2YAML:         true,
		FormatWSDL:                 true,
		FormatGraphQLSDL:           true,
		FormatPostmanCollection:    true,
		FormatGraphQLIntrospection: true,
	}
}

// ---------------------------------------------------------------------------
// HarvestOutcome — why the input slice is the length it is
// ---------------------------------------------------------------------------

// HarvestOutcome says what the SAST harvest pass did, which is the only thing
// that can distinguish "this repository ships no spec files" from "the handoff
// was never wired".
//
// The zero value names nothing and IngestRepoSpecs refuses it. A Go zero value
// must never mean "permitted", and here the permissive reading — treating an
// empty inventory as a fact about the repository — is exactly the one that
// makes endpoint_coverage's denominator vanish.
type HarvestOutcome string

const (
	// HarvestOutcomeUnset is the zero value and names nothing.
	HarvestOutcomeUnset HarvestOutcome = ""

	// HarvestRan: the SAST pass walked the repository and the slice handed
	// to IngestRepoSpecs is its COMPLETE output. An empty slice under this
	// outcome is a reportable fact about the repository.
	HarvestRan HarvestOutcome = "harvest_ran"

	// HarvestSkipped: the SAST pass did not run, or its output never reached
	// this tier. An empty slice under this outcome is a fact about Anvil and
	// AssertNotSilentlyEmpty refuses it.
	HarvestSkipped HarvestOutcome = "harvest_skipped"
)

// HarvestOutcomeValues returns every legal literal.
func HarvestOutcomeValues() []HarvestOutcome {
	return []HarvestOutcome{HarvestRan, HarvestSkipped}
}

// Valid reports whether h is one of the legal literals.
func (h HarvestOutcome) Valid() bool {
	for _, k := range HarvestOutcomeValues() {
		if k == h {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SpecFile — one harvested file
// ---------------------------------------------------------------------------

// SpecFileFacts is NewSpecFile's input.
type SpecFileFacts struct {
	// Location names the file, in internal/record's own vocabulary for
	// naming a file in the target repository (SARIF §3.4). URI is required.
	Location record.ArtifactLocation

	// Content carries the file's bytes (SARIF §3.3). Required and non-empty:
	// an empty spec file that parsed to nothing and an empty spec file that
	// was never read produce the same route list, and this tier refuses to
	// be the place those become indistinguishable.
	Content record.ArtifactContent

	// DeclaredFormat is what the harvester CLAIMS this file is. It is
	// recorded and it is NEVER believed — DetectRepoSpecFormat reads the
	// bytes and nothing else. It may be empty.
	//
	// It exists because a divergence between what the harvester said and
	// what the bytes are is worth reporting: a file the harvester filed as
	// `openapi3_json` whose bytes are a Postman collection means the harvest
	// side is classifying on filename, and filenames are repository-authored.
	DeclaredFormat SpecFormat
}

// SpecFile is one spec file the SAST pass harvested, sealed.
//
// Every field is unexported and there is exactly one constructor, for the same
// reason Route has one: a composite literal elsewhere would produce a file
// with no URI and no bytes, and the ingest would then report a clean empty
// inventory for it.
type SpecFile struct {
	uri       string
	uriBaseID string
	index     *int
	content   string
	declared  SpecFormat
	sealed    bool
}

// NewSpecFile validates and seals one harvested file.
func NewSpecFile(f SpecFileFacts) (SpecFile, error) {
	uri := f.Location.URI
	if uri == "" {
		return SpecFile{}, fmt.Errorf("inventory: %w: the harvested spec file carries no "+
			"artifactLocation.uri. A file nobody can name is a file no operator can go "+
			"look at when its routes turn out to be wrong", ErrRefused)
	}
	if len(uri) > maxSpecURIBytes {
		return SpecFile{}, fmt.Errorf("inventory: %w: the artifact URI is %d bytes and the "+
			"coded bound is %d", ErrRefused, len(uri), maxSpecURIBytes)
	}
	if err := printableIdentifier(uri); err != nil {
		return SpecFile{}, fmt.Errorf("inventory: %w: the artifact URI %q is not printable: "+
			"%w. A repository-authored path carrying control bytes is a log-injection "+
			"attempt, not a filename", ErrRefused, redact(uri), err)
	}
	if len(f.Location.URIBaseID) > maxSpecURIBytes {
		return SpecFile{}, fmt.Errorf("inventory: %w: the artifact uriBaseId is %d bytes "+
			"and the coded bound is %d", ErrRefused, len(f.Location.URIBaseID),
			maxSpecURIBytes)
	}
	if f.Content.Text == "" {
		return SpecFile{}, fmt.Errorf("inventory: %w: harvested file %q carries no content. "+
			"A zero-byte spec file and a file whose bytes never reached this tier produce "+
			"the same empty route list, and that difference lands in the denominator of "+
			"endpoint_coverage", ErrRefused, redact(uri))
	}
	if len(f.Content.Text) > maxSpecFileBytes {
		return SpecFile{}, fmt.Errorf("inventory: %w: harvested file %q is %d bytes and the "+
			"coded bound is %d", ErrRefused, redact(uri), len(f.Content.Text),
			maxSpecFileBytes)
	}
	if f.DeclaredFormat != "" && !knownRepoSpecFormat(f.DeclaredFormat) {
		return SpecFile{}, fmt.Errorf("inventory: %w: harvested file %q declares format "+
			"%q, which is not one of %v. The declared format is never believed, but an "+
			"unrecognised one means the harvest side and this tier no longer share a "+
			"vocabulary", ErrRefused, redact(uri), redact(string(f.DeclaredFormat)),
			RepoSpecFormatValues())
	}
	return SpecFile{
		uri:       uri,
		uriBaseID: f.Location.URIBaseID,
		index:     copyIntPtr(f.Location.Index),
		content:   f.Content.Text,
		declared:  f.DeclaredFormat,
		sealed:    true,
	}, nil
}

func knownRepoSpecFormat(f SpecFormat) bool {
	for _, k := range RepoSpecFormatValues() {
		if k == f {
			return true
		}
	}
	return false
}

// copyIntPtr deep-copies record.ArtifactLocation's only reference field.
func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// printableIdentifier refuses control bytes and DEL. It is not a path
// validator and never becomes one: this file never opens anything.
func printableIdentifier(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return fmt.Errorf("byte %d is 0x%02x", i, s[i])
		}
	}
	return nil
}

// Constructed reports whether f came from NewSpecFile. The zero SpecFile is
// not one.
func (f SpecFile) Constructed() bool { return f.sealed && f.uri != "" && f.content != "" }

// Location returns a COPY of the record artifact location naming this file.
func (f SpecFile) Location() record.ArtifactLocation {
	return record.ArtifactLocation{
		URI:       f.uri,
		URIBaseID: f.uriBaseID,
		Index:     copyIntPtr(f.index),
	}
}

// Content returns the record artifact content carrying this file's bytes.
func (f SpecFile) Content() record.ArtifactContent {
	return record.ArtifactContent{Text: f.content}
}

// URI returns the file's URI.
func (f SpecFile) URI() string { return f.uri }

// Bytes returns a COPY of the file's bytes.
func (f SpecFile) Bytes() []byte { return []byte(f.content) }

// DeclaredFormat returns what the harvester claimed, which this tier records
// and never believes.
func (f SpecFile) DeclaredFormat() SpecFormat { return f.declared }

// Trust returns the record trust label for every string this file carries. It
// is a constant. There is no argument and no field that can change it: the
// question record.Trust answers is who wrote the bytes, and a repository wrote
// these.
func (f SpecFile) Trust() record.Trust { return record.TrustUntrusted }

// String renders the file for a log line, redacted.
func (f SpecFile) String() string {
	if !f.Constructed() {
		return "specfile(unconstructed)"
	}
	return fmt.Sprintf("%s (%d bytes)", redact(f.uri), len(f.content))
}

// ---------------------------------------------------------------------------
// IngestConfig
// ---------------------------------------------------------------------------

// IngestConfig is everything the ingest needs that is not a file.
type IngestConfig struct {
	// Target is the kernel Target the resulting routes live on. Required for
	// the reason RouteFacts.Target is required: it is what makes the
	// KERNEL's own path validation possible, and it is what pins a route to
	// a host instead of leaving it a free-floating string that D.26 cannot
	// union with Tier 0's.
	//
	// It is authz.NewTarget's output and carries no authorization. Tier 1
	// issues no request, so it needs none.
	Target authz.Target

	// Harvest says what the SAST pass did. Required; the zero value is
	// refused.
	Harvest HarvestOutcome

	// GraphQLEndpoint is the request path a GraphQL SDL document's schema is
	// served on, when the operator has configured one.
	//
	// It is OPERATOR CONFIGURATION and it is not derived from any harvested
	// file: an SDL document declares a schema and names no URL at all, so
	// there is nothing in the file to read it from and nothing to hard-code.
	// When it is empty, every root field of every SDL document becomes a
	// counted per-operation refusal rather than a route — the surface stays
	// in the coverage denominator and none of it becomes an address.
	GraphQLEndpoint string
}

// Constructed reports whether the config carries everything with no default.
func (c IngestConfig) Constructed() bool { return c.Target.Constructed() && c.Harvest.Valid() }

// ---------------------------------------------------------------------------
// FileResult — one harvested file's outcome
// ---------------------------------------------------------------------------

// FileResult is what one harvested file produced.
//
// It embeds D.18's ParseResult so the accounting identity — Seen equals routes
// plus per-operation refusals — is the SAME check, not a second one that could
// drift from it. AssertAccountedFor is inherited.
type FileResult struct {
	ParseResult

	// Location names the file this came from, in the record's own
	// vocabulary. This is the finer-grained half of provenance: Route
	// carries `repo_spec`, and this says WHICH repo file.
	Location record.ArtifactLocation

	// DeclaredFormat is what the harvester claimed.
	DeclaredFormat SpecFormat

	// DeclaredFormatDiverged reports that the harvester's claim and the
	// bytes disagree. The bytes won.
	DeclaredFormatDiverged bool
}

// Readable reports whether this tier could turn the file's format into routes
// at all — as opposed to refusing it by name (AsyncAPI) or not recognising it.
func (f FileResult) Readable() bool { return readableRepoSpecFormats()[f.Format] }

// ---------------------------------------------------------------------------
// IngestResult
// ---------------------------------------------------------------------------

// IngestResult is one Tier 1 ingest over one repository's harvested files.
//
// It carries counters and refusals alongside the routes for D.18's reason: "no
// routes" has several meanings and a bare []Route cannot tell them apart.
type IngestResult struct {
	routes   []Route
	refusals []Refusal
	files    []FileResult
	harvest  HarvestOutcome
	offered  int
	ingested int
	seen     int
	truncate bool
	sealed   bool
}

// Constructed reports whether r came from IngestRepoSpecs.
func (r IngestResult) Constructed() bool { return r.sealed }

// Routes returns a deep COPY of the inventory, sorted deterministically.
func (r IngestResult) Routes() []Route { return cloneRoutes(r.routes) }

// Refusals returns a COPY of everything that did not become a route.
func (r IngestResult) Refusals() []Refusal { return cloneRefusals(r.refusals) }

// Files returns a deep COPY of the per-file outcomes.
func (r IngestResult) Files() []FileResult { return cloneFileResults(r.files) }

// Harvest returns the harvest outcome this ingest ran under.
func (r IngestResult) Harvest() HarvestOutcome { return r.harvest }

// Offered returns how many harvested files were handed to this tier.
func (r IngestResult) Offered() int { return r.offered }

// Ingested returns how many of them were a format this tier can read. It is
// the Tier 1 twin of Result.Answered: the number that separates "this
// repository ships no usable spec" from "nothing readable ever arrived".
func (r IngestResult) Ingested() int { return r.ingested }

// Seen returns how many operations the harvested files declared in total,
// counting those that were refused.
func (r IngestResult) Seen() int { return r.seen }

// Truncated reports that a harvested file exceeded the coded route bound.
func (r IngestResult) Truncated() bool { return r.truncate }

// DenominatorFloor is the smallest number of endpoints D.26 may use in the
// Tier 1 half of endpoint_coverage's denominator: the routes PLUS every
// per-operation refusal. An operation this tier saw and could not represent is
// attack surface that exists, and leaving it out shrinks the denominator,
// which makes coverage look BETTER. Coverage arithmetic may only ever fail
// pessimistically.
func (r IngestResult) DenominatorFloor() int {
	n := len(r.routes)
	for _, ref := range r.refusals {
		if ref.Reason.PerOperation() {
			n++
		}
	}
	return n
}

// SourceOf returns the harvested file a route came from, by Route.Key.
//
// Route has no field for a repository path — ServedAt is documented as a
// well-known ENDPOINT and D.18's GraphQL path uses it as a request path, so
// putting a repo URI there would be putting a filename where a later packet
// looks for an address. The mapping lives here instead. The gap is reported to
// the orchestrator: Route wants a tier-neutral source reference.
func (r IngestResult) SourceOf(key string) (record.ArtifactLocation, bool) {
	for _, f := range r.files {
		for _, rt := range f.Routes {
			if rt.Key() == key {
				loc := f.Location
				loc.Index = copyIntPtr(loc.Index)
				return loc, true
			}
		}
	}
	return record.ArtifactLocation{}, false
}

// AssertNotSilentlyEmpty decides whether an empty Tier 1 inventory is a
// statement about the REPOSITORY or a statement about ANVIL.
//
// It returns nil when at least one route was extracted, when at least one file
// was in a format this tier reads, or when the harvest pass RAN and reported
// no spec files at all — that last one being a real, reportable fact about the
// repository rather than a silence.
//
// It returns an error when files arrived and none was readable, and when the
// harvest never ran. Both of those are Anvil's reach and neither may become
// the denominator of endpoint_coverage.
func (r IngestResult) AssertNotSilentlyEmpty() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: AssertNotSilentlyEmpty was called on an "+
			"IngestResult IngestRepoSpecs never built", ErrUnconstructed)
	}
	if len(r.routes) > 0 || r.ingested > 0 {
		return nil
	}
	if r.harvest == HarvestRan && r.offered == 0 {
		return nil
	}
	return fmt.Errorf("%w: harvest outcome %q, %d files offered, %d readable, %d refusals. "+
		"An empty Tier 1 inventory here describes the harvest and not the repository, and "+
		"must not become the denominator of endpoint_coverage",
		ErrNothingIngested, r.harvest, r.offered, r.ingested, len(r.refusals))
}

func cloneFileResults(in []FileResult) []FileResult {
	if in == nil {
		return nil
	}
	out := make([]FileResult, len(in))
	for i, f := range in {
		out[i] = f
		out[i].Routes = cloneRoutes(f.Routes)
		out[i].Refusals = cloneRefusals(f.Refusals)
		out[i].Location.Index = copyIntPtr(f.Location.Index)
	}
	return out
}

// ---------------------------------------------------------------------------
// Format detection — the bytes decide, and nothing else does
// ---------------------------------------------------------------------------

// DetectRepoSpecFormat classifies a harvested file FROM ITS BYTES.
//
// It takes no filename and no declared format on purpose. Both are
// repository-authored — the harvester classifies on the path it found, and the
// path is in the repository — so letting either choose the parser would let a
// committed file choose how Anvil reads it. That is one step short of choosing
// what Anvil reads. D.18 made the same call about a served Content-Type:
// "a target choosing its own Content-Type header is the target choosing how
// Anvil parses its document".
func DetectRepoSpecFormat(body []byte) SpecFormat {
	// U+FEFF is written as an escape for the reason D.18 records: Go's
	// scanner refuses a byte-order mark mid-file even inside a string
	// literal. A committed file that begins with one would otherwise
	// classify as FormatUnrecognised, and "Anvil could not read it" would be
	// indistinguishable from "the repository ships no spec".
	trimmed := strings.TrimLeft(string(body), " \t\r\n\ufeff")
	if trimmed == "" {
		return FormatUnrecognised
	}
	switch trimmed[0] {
	case '{':
		return detectJSONSpec(trimmed)
	case '<':
		return detectXMLSpec(trimmed)
	}
	if f := detectYAMLSpec(trimmed); f != FormatUnrecognised {
		return f
	}
	if detectGraphQLSDL(trimmed) {
		return FormatGraphQLSDL
	}
	return FormatUnrecognised
}

func detectJSONSpec(trimmed string) SpecFormat {
	var probe struct {
		OpenAPI  json.RawMessage `json:"openapi"`
		Swagger  json.RawMessage `json:"swagger"`
		AsyncAPI json.RawMessage `json:"asyncapi"`
		Item     json.RawMessage `json:"item"`
		Info     struct {
			Schema string `json:"schema"`
		} `json:"info"`
		Data struct {
			Schema json.RawMessage `json:"__schema"`
		} `json:"data"`
		Schema json.RawMessage `json:"__schema"`
	}
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return FormatUnrecognised
	}
	switch {
	case len(probe.OpenAPI) > 0:
		return FormatOpenAPI3
	case len(probe.Swagger) > 0:
		return FormatSwagger2
	case len(probe.AsyncAPI) > 0:
		return FormatAsyncAPI
	case strings.Contains(probe.Info.Schema, postmanSchemaMarker), len(probe.Item) > 0:
		return FormatPostmanCollection
	case len(probe.Data.Schema) > 0, len(probe.Schema) > 0:
		return FormatGraphQLIntrospection
	}
	return FormatUnrecognised
}

// postmanSchemaMarker is the host-and-path fragment Postman writes into
// `info.schema`. It is matched as a substring of a value read out of the
// document, never used as a destination.
const postmanSchemaMarker = "schema.getpostman.com"

func detectXMLSpec(trimmed string) SpecFormat {
	name, ok := xmlRootLocalName(trimmed)
	if !ok {
		return FormatUnrecognised
	}
	switch name {
	case "definitions", "description":
		return FormatWSDL
	}
	return FormatUnrecognised
}

// xmlRootLocalName reads the local name of the first element START tag,
// skipping the XML declaration, comments, doctype and processing
// instructions. It uses encoding/xml's tokenizer rather than a hand scan, so
// the classification and the parse agree about what the root element is.
func xmlRootLocalName(s string) (string, bool) {
	dec := xml.NewDecoder(strings.NewReader(s))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		if st, ok := tok.(xml.StartElement); ok {
			return st.Name.Local, true
		}
	}
}

// detectYAMLSpec looks for a spec's top-level key at zero indentation.
//
// The whole document is scanned rather than only its first meaningful line:
// `info:` before `openapi:` is ordinary, and a first-line-only check would
// classify that file as unrecognised — which reads as "the repository ships no
// spec" rather than "Anvil could not tell".
func detectYAMLSpec(trimmed string) SpecFormat {
	found := FormatUnrecognised
	for i, line := range strings.Split(trimmed, "\n") {
		if i >= maxYAMLLines {
			break
		}
		line = strings.TrimRight(line, "\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		switch {
		case strings.HasPrefix(line, "openapi:"):
			return FormatOpenAPI3YAML
		case strings.HasPrefix(line, "swagger:"):
			return FormatSwagger2YAML
		case strings.HasPrefix(line, "asyncapi:"):
			return FormatAsyncAPI
		case strings.HasPrefix(line, "paths:"):
			// Provisional. A document with `paths:` and no dialect key is
			// read as OpenAPI 3 YAML; the converted JSON is re-classified
			// by D.18's DetectFormat before anything is parsed, and a
			// document that is neither dialect is refused there.
			found = FormatOpenAPI3YAML
		}
	}
	return found
}

// sdlKeywords is the set of GraphQL SDL top-level definition keywords. It is
// an allowlist: a document is SDL because it opens with one of these, not
// because it failed to be something else.
func sdlKeywords() map[string]bool {
	return map[string]bool{
		"schema": true, "type": true, "input": true, "interface": true,
		"enum": true, "union": true, "scalar": true, "extend": true,
		"directive": true, "fragment": true, "query": true, "mutation": true,
	}
}

func detectGraphQLSDL(trimmed string) bool {
	kw := sdlKeywords()
	for i, line := range strings.Split(trimmed, "\n") {
		if i >= maxYAMLLines {
			break
		}
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "\"") {
			continue
		}
		word := line
		if j := strings.IndexAny(word, " \t{("); j >= 0 {
			word = word[:j]
		}
		if kw[word] && len(word) < len(line) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The retag — how one OpenAPI parser serves two tiers
// ---------------------------------------------------------------------------

// retagAsRepoSpec rebuilds a route with Tier 1's two axes.
//
// parseOpenAPI and parseGraphQL stamp record.InventoryProvenanceRuntimeSpec
// because they were written for a document served by a live target. Rather
// than growing a second OpenAPI parser in this file — a second set of rules
// that can disagree with the first about a path, a method or a parameter —
// every route they produce is rebuilt HERE, THROUGH NewRoute, with:
//
//	Provenance   record.InventoryProvenanceRepoSpec
//	Confirmation ConfirmationCandidate
//	Trust        record.TrustUntrusted
//
// unconditionally. The incoming route's own values are read for none of the
// three. A route that arrived stamped `confirmed` comes out `candidate`, which
// is the property that matters: a retag is exactly the kind of function where
// a laundering bug would be invisible, so there is no branch in it to be
// wrong.
//
// ServedAt is deliberately dropped. It is documented as a well-known ENDPOINT
// path and D.18's GraphQL extraction uses it as a request path; putting a
// repository filename there would put a filename where a later packet looks
// for an address. IngestResult.SourceOf carries the file instead.
func retagAsRepoSpec(target authz.Target, r Route) (Route, error) {
	return NewRoute(RouteFacts{
		Method:       r.Method(),
		Path:         r.Path(),
		Target:       target,
		Operation:    r.Operation(),
		Params:       r.Params(),
		Provenance:   record.InventoryProvenanceRepoSpec,
		Confirmation: ConfirmationCandidate,
		Trust:        record.TrustUntrusted,
	})
}

// retagAll retags every route of a ParseResult.
//
// A retag failure becomes a per-operation Refusal rather than a dropped route,
// because the operation was declared by the file and is attack surface
// whatever this tier could do with it. The accounting identity therefore holds
// across the retag: a route that leaves the set is replaced by a row.
func retagAll(target authz.Target, pr ParseResult) ParseResult {
	if len(pr.Routes) == 0 {
		return pr
	}
	out := make([]Route, 0, len(pr.Routes))
	for _, r := range pr.Routes {
		tagged, err := retagAsRepoSpec(target, r)
		if err != nil {
			pr.Refusals = append(pr.Refusals, Refusal{
				Path:   redact(r.Path()),
				Method: string(r.Method()),
				Reason: classifyRouteError(err),
				Detail: "the route parsed and could not be retagged as repo_spec: " +
					redact(err.Error()),
			})
			continue
		}
		out = append(out, tagged)
	}
	pr.Routes = out
	SortRoutes(pr.Routes)
	return pr
}

// ---------------------------------------------------------------------------
// IngestSpecFile — one harvested file to candidate routes
// ---------------------------------------------------------------------------

// IngestSpecFile turns one harvested spec file into candidate routes.
//
// It is a PURE function of (config, file). It opens nothing, dials nothing,
// and cannot: Tier 1 issues no request at all, which is why this whole packet
// is exercisable today while D.18's fetch half depends on the kernel
// admitting. There is no t.Skip anywhere in this tier and nothing in
// internal/SKIPPED-CONTROLS.md belongs to it.
func IngestSpecFile(cfg IngestConfig, f SpecFile) (FileResult, error) {
	if !cfg.Target.Constructed() {
		return FileResult{}, fmt.Errorf("inventory: %w: IngestSpecFile was handed a Target "+
			"authz.NewTarget never built, so no extracted path could be validated by the "+
			"kernel and no route would name a host", ErrUnconstructed)
	}
	if !cfg.Harvest.Valid() {
		return FileResult{}, fmt.Errorf("inventory: %w: the harvest outcome is %q, which is "+
			"not one of %v. Without it an empty Tier 1 inventory cannot be told apart from "+
			"a harvest that never ran, and that difference is the denominator of "+
			"endpoint_coverage", ErrRefused, redact(string(cfg.Harvest)),
			HarvestOutcomeValues())
	}
	if !f.Constructed() {
		return FileResult{}, fmt.Errorf("inventory: %w: IngestSpecFile was handed a "+
			"SpecFile NewSpecFile never built. A zero SpecFile names no repository file "+
			"and carries no bytes, and would ingest to a clean empty inventory",
			ErrUnconstructed)
	}

	body := f.Bytes()
	format := DetectRepoSpecFormat(body)
	out := FileResult{
		Location:       f.Location(),
		DeclaredFormat: f.DeclaredFormat(),
	}
	out.DeclaredFormatDiverged = f.DeclaredFormat() != "" && f.DeclaredFormat() != format

	switch format {
	case FormatOpenAPI3, FormatSwagger2:
		out.ParseResult = retagAll(cfg.Target, parseOpenAPIBody(cfg.Target, format, body))
	case FormatOpenAPI3YAML, FormatSwagger2YAML:
		out.ParseResult = ingestOpenAPIYAML(cfg.Target, body)
	case FormatPostmanCollection:
		out.ParseResult = ingestPostman(cfg.Target, body)
	case FormatWSDL:
		out.ParseResult = ingestWSDL(cfg.Target, body)
	case FormatGraphQLSDL:
		out.ParseResult = ingestGraphQLSDL(cfg, body)
	case FormatGraphQLIntrospection:
		out.ParseResult = ingestGraphQLIntrospection(cfg, body)
	case FormatAsyncAPI:
		out.ParseResult = ParseResult{Format: FormatAsyncAPI, Refusals: []Refusal{{
			Reason: RefusalFormatUnrecognised,
			Detail: "the file is an AsyncAPI document. An AsyncAPI channel is a message " +
				"topic on a broker, not an HTTP endpoint; inventing a route from one " +
				"would put a row in the coverage denominator that no probe can ever " +
				"reach. Refused by name rather than parsed into fiction",
		}}}
	default:
		out.ParseResult = ParseResult{Format: FormatUnrecognised, Refusals: []Refusal{{
			Reason: RefusalFormatUnrecognised,
			Detail: fmt.Sprintf("%d bytes that match no spec shape this tier reads",
				len(body)),
		}}}
	}
	return out, nil
}

// parseOpenAPIBody calls D.18's parser and folds its error return into a
// refusal. parseOpenAPI's signature returns an error it never actually
// produces — every failure is already a Refusal row — and folding it here
// keeps the one-parser property without inventing a second error convention.
func parseOpenAPIBody(target authz.Target, format SpecFormat, body []byte) ParseResult {
	pr, err := parseOpenAPI(target, "", format, body)
	if err != nil {
		return ParseResult{Format: format, Refusals: []Refusal{{
			Reason: RefusalSpecUnparseable,
			Detail: redact(err.Error()),
		}}}
	}
	pr.Format = format
	return pr
}

// ---------------------------------------------------------------------------
// IngestRepoSpecs — the packet's entry point
// ---------------------------------------------------------------------------

// IngestRepoSpecs is plan/50-dast.md D.19's named entry point.
//
// DEVIATION, stated: the plan's expected schema is
// `IngestRepoSpecs(specs []SpecFile) ([]Route, error)`. Three things about it
// could not survive contact with what this package already is, and each is a
// refusal this signature makes impossible:
//
//   - A route with no authz.Target names no host, so the kernel cannot
//     validate its path and D.26 cannot union it with Tier 0's. The Target is
//     in IngestConfig. It carries no authorization and grants nothing: Tier 1
//     issues no request.
//   - A bare []Route return cannot distinguish "this repository ships no spec
//     files" from "the harvest never ran" from "files arrived and none was
//     readable", and all three land in the denominator of endpoint_coverage.
//     IngestResult carries the counters and the refusals;
//     AssertNotSilentlyEmpty is the predicate that makes the caller choose.
//   - HarvestOutcome is required and has no legal zero value, because the
//     first of those three is a fact about the repository and the other two
//     are facts about Anvil.
func IngestRepoSpecs(cfg IngestConfig, specs []SpecFile) (IngestResult, error) {
	if !cfg.Target.Constructed() {
		return IngestResult{}, fmt.Errorf("inventory: %w: the ingest was handed a Target "+
			"authz.NewTarget never built", ErrUnconstructed)
	}
	if !cfg.Harvest.Valid() {
		return IngestResult{}, fmt.Errorf("inventory: %w: the harvest outcome is %q, which "+
			"is not one of %v. There is no default: an empty file slice means one thing "+
			"under %q and the opposite thing under %q", ErrRefused,
			redact(string(cfg.Harvest)), HarvestOutcomeValues(), HarvestRan, HarvestSkipped)
	}
	if len(specs) > maxSpecFilesPerIngest {
		return IngestResult{}, fmt.Errorf("inventory: %w: the harvest offered %d files and "+
			"the coded bound is %d", ErrRefused, len(specs), maxSpecFilesPerIngest)
	}
	if cfg.GraphQLEndpoint != "" {
		if err := kernelAcceptsPath(cfg.Target, authz.MethodPost, cfg.GraphQLEndpoint); err != nil {
			return IngestResult{}, fmt.Errorf("inventory: %w: the configured GraphQL "+
				"endpoint is not a path the kernel accepts: %w", ErrRefused, err)
		}
	}

	out := IngestResult{
		sealed:  true,
		harvest: cfg.Harvest,
		offered: len(specs),
	}
	readable := readableRepoSpecFormats()
	seenKeys := make(map[string]bool)

	for i, f := range specs {
		fr, err := IngestSpecFile(cfg, f)
		if err != nil {
			// One malformed entry must not lose the rest of the harvest, and
			// it must not vanish either.
			out.refusals = append(out.refusals, Refusal{
				Reason: RefusalFormatUnrecognised,
				Detail: fmt.Sprintf("harvested file %d could not be ingested: %s",
					i, redact(err.Error())),
			})
			continue
		}
		if readable[fr.Format] {
			out.ingested++
		}
		if fr.Truncated {
			out.truncate = true
		}
		out.seen += fr.Seen
		out.refusals = append(out.refusals, fr.Refusals...)

		// Two harvested files can declare the same endpoint — an openapi.yaml
		// and the Postman collection generated from it is the ordinary case.
		// Merging on Route.Key stops the union counting one endpoint twice.
		//
		// The duplicate still gets a row, and that row is per-operation, so
		// DenominatorFloor counts the endpoint once as a route and once as a
		// refusal. That is D.18's established behaviour for the same case
		// (Probe, two spec endpoints serving one document) and it errs
		// pessimistically: a denominator that is too large makes coverage
		// look WORSE, which is the only direction coverage arithmetic is
		// allowed to fail in. D.26 should prefer the deduplicated union of
		// Routes() where it has it.
		kept := make([]Route, 0, len(fr.Routes))
		for _, rt := range fr.Routes {
			if seenKeys[rt.Key()] {
				out.refusals = append(out.refusals, Refusal{
					Path:   redact(rt.Path()),
					Method: string(rt.Method()),
					Reason: RefusalDuplicateRoute,
					Detail: "already inventoried from another harvested file",
				})
				continue
			}
			seenKeys[rt.Key()] = true
			kept = append(kept, rt)
			out.routes = append(out.routes, rt)
		}
		fr.Routes = kept
		out.files = append(out.files, fr)
	}
	SortRoutes(out.routes)
	return out, nil
}

// ===========================================================================
// OpenAPI / Swagger IN YAML
//
// D.18 refuses a SERVED YAML document by name (RefusalYAMLUnsupported) on the
// grounds that go.mod requires only modernc.org/sqlite and "adding one is a
// dependency decision, not a local edit". That ruling stands for tier 0 and it
// is not overturned here — no dependency is added. What is added is a reader
// for a STRICT BLOCK-YAML SUBSET, because D.19's stop condition requires
// `openapi.yaml` to parse and YAML is the format most repositories actually
// commit.
//
// The subset is defined by an ALLOWLIST, not by a list of banned constructs,
// because a denylist loses: the YAML feature nobody has heard of is not on it
// and the failure mode of forgetting is a PASSING PARSE OF THE WRONG TREE.
// Concretely:
//
//	a plain scalar's FIRST BYTE must be one of [A-Za-z0-9_./+-~$]
//	a plain key's  FIRST BYTE must be one of [A-Za-z0-9_./+-$]
//	an escape inside a double-quoted scalar must be one of \" \\ \/ \n \r \t
//	  \b \f \uXXXX
//	indentation is spaces, never tabs
//
// Everything else is outside the subset by construction. `&anchor`, `*alias`,
// `<<: *merge`, `!!tag`, `{flow: map}`, `[flow, seq]`, `? explicit key`,
// `%DIRECTIVE` and a second `---` all fail the first-byte allowlist or the
// document-marker scan, and none of them needed to be enumerated for that to
// happen. Block scalars (`|`, `|-`, `|+`, `>`, `>-`, `>+`) ARE supported,
// because a `description: |` is ordinary in a real OpenAPI file and refusing
// the whole document over one is a large, silent loss of inventory.
//
// AND THE REFUSAL IS ALWAYS OF THE WHOLE DOCUMENT. There is no path in this
// reader that skips a line it did not understand and carries on: a partially
// read spec yields a partial route list, a partial route list is a SMALLER
// coverage denominator, and a smaller denominator makes endpoint_coverage look
// better than it is. Fail closed means fail closed for the file.
//
// TWO DELIBERATE DEPARTURES FROM YAML 1.2, both stated because a reader who
// assumes conformance would be wrong:
//
//  1. EVERY PLAIN SCALAR BECOMES A JSON STRING except `true`/`false`/`null`/`~`.
//     YAML resolves `2.0` to a float, and `swagger: 2.0` — which real
//     documents write unquoted — would then decode into oasDoc's `string`
//     field as a type error and lose the entire document. Nothing this tier
//     reads out of a spec is a number, so the string reading loses nothing and
//     the float reading loses everything.
//  2. FOLDED SCALARS (`>`) fold in the ordinary way — blank line becomes a
//     line break, a more-indented line keeps its break, otherwise lines join
//     with a space — but a RUN of blank lines produces that many breaks rather
//     than n-1. Folded scalars appear in `description` and `summary`; no path,
//     method or parameter name in this package can come from one.
// ===========================================================================

// ingestOpenAPIYAML converts a committed YAML spec to JSON and hands it to the
// one OpenAPI parser this package has.
//
// The DIALECT is decided by D.18's DetectFormat over the CONVERTED bytes, not
// by the YAML scan that classified the file. detectYAMLSpec is allowed to be
// provisional (a document with `paths:` and no dialect key is read as OpenAPI
// 3); this is where that guess is checked against the actual document, and a
// converted tree that is neither dialect is refused rather than parsed.
func ingestOpenAPIYAML(target authz.Target, body []byte) ParseResult {
	tree, err := yamlSubsetToTree(body)
	if err != nil {
		return ParseResult{Format: FormatOpenAPI3YAML, Refusals: []Refusal{{
			Reason: RefusalYAMLUnsupported,
			Detail: "the document is outside the block-YAML subset this tier reads, so " +
				"the WHOLE file is refused rather than half-read: " + redact(err.Error()),
		}}}
	}
	encoded, err := json.Marshal(tree)
	if err != nil {
		return ParseResult{Format: FormatOpenAPI3YAML, Refusals: []Refusal{{
			Reason: RefusalSpecUnparseable,
			Detail: "the converted document could not be re-encoded: " + redact(err.Error()),
		}}}
	}
	dialect := DetectFormat("", encoded)
	var reported SpecFormat
	switch dialect {
	case FormatOpenAPI3:
		reported = FormatOpenAPI3YAML
	case FormatSwagger2:
		reported = FormatSwagger2YAML
	default:
		return ParseResult{Format: FormatUnrecognised, Refusals: []Refusal{{
			Reason: RefusalFormatUnrecognised,
			Detail: "the file parsed as YAML and the resulting document declares neither " +
				"an openapi nor a swagger version, so there is no dialect to read it in",
		}}}
	}
	pr := retagAll(target, parseOpenAPIBody(target, dialect, encoded))
	pr.Format = reported
	return pr
}

// ---------------------------------------------------------------------------
// The block-YAML subset reader
// ---------------------------------------------------------------------------

type yamlLine struct {
	num    int
	indent int
	// text is the line with leading spaces and trailing spaces removed. It
	// is NOT comment-stripped: inside a block scalar a `#` is content, and a
	// reader that stripped comments up front could not tell the difference.
	text string
	// blank reports that this line carries nothing OUTSIDE a block scalar —
	// it is empty or it is a comment.
	blank bool
}

type yamlReader struct {
	lines []yamlLine
	i     int
	nodes int
}

// yamlSubsetToTree reads a committed YAML document into the same shape
// encoding/json produces, so the result can be re-encoded and handed to the
// one OpenAPI parser.
func yamlSubsetToTree(body []byte) (any, error) {
	s := strings.TrimPrefix(string(body), "\ufeff")
	raw := strings.Split(s, "\n")
	if len(raw) > maxYAMLLines {
		return nil, fmt.Errorf("the document has %d lines and the coded bound is %d",
			len(raw), maxYAMLLines)
	}
	lines := make([]yamlLine, 0, len(raw))
	for n, l := range raw {
		l = strings.TrimRight(l, "\r")
		if len(l) > maxYAMLLineBytes {
			return nil, fmt.Errorf("line %d is %d bytes and the coded bound is %d",
				n+1, len(l), maxYAMLLineBytes)
		}
		indent := 0
		for indent < len(l) && l[indent] == ' ' {
			indent++
		}
		if indent < len(l) && l[indent] == '\t' {
			return nil, fmt.Errorf("line %d indents with a tab. YAML forbids it and a "+
				"reader that guessed a tab width would build a different tree than the "+
				"one the author meant", n+1)
		}
		text := strings.TrimRight(l[indent:], " ")
		lines = append(lines, yamlLine{
			num:    n + 1,
			indent: indent,
			text:   text,
			blank:  text == "" || text[0] == '#',
		})
	}
	if err := scanYAMLDocumentMarkers(lines); err != nil {
		return nil, err
	}

	r := &yamlReader{lines: lines}
	if !r.skipBlank() {
		return nil, errors.New("the document carries no content outside comments")
	}
	v, err := r.parseBlock(r.lines[r.i].indent, 0)
	if err != nil {
		return nil, err
	}
	if r.skipBlank() {
		return nil, fmt.Errorf("line %d: content follows the end of the document at a "+
			"lower indentation than it started", r.lines[r.i].num)
	}
	return v, nil
}

// scanYAMLDocumentMarkers refuses multi-document streams and directives, and
// drops a single leading `---` and a trailing `...`.
//
// A multi-document stream is refused rather than read-first-document: a
// committed file whose SECOND document holds the real `paths` would otherwise
// produce a short, quiet inventory.
func scanYAMLDocumentMarkers(lines []yamlLine) error {
	started := false
	for i := range lines {
		if lines[i].blank {
			continue
		}
		t := lines[i].text
		if lines[i].indent == 0 && strings.HasPrefix(t, "%") {
			return fmt.Errorf("line %d: a YAML directive is outside this subset",
				lines[i].num)
		}
		if lines[i].indent == 0 && (t == "---" || strings.HasPrefix(t, "--- ")) {
			if started {
				return fmt.Errorf("line %d: the file holds more than one YAML document. "+
					"Reading only the first would produce a short inventory and no row "+
					"saying so", lines[i].num)
			}
			lines[i].blank = true
			continue
		}
		if lines[i].indent == 0 && t == "..." {
			lines[i].blank = true
			continue
		}
		started = true
	}
	return nil
}

func (r *yamlReader) skipBlank() bool {
	for r.i < len(r.lines) && r.lines[r.i].blank {
		r.i++
	}
	return r.i < len(r.lines)
}

func (r *yamlReader) count() error {
	r.nodes++
	if r.nodes > maxYAMLNodes {
		return fmt.Errorf("the document declares more than %d nodes", maxYAMLNodes)
	}
	return nil
}

func isYAMLSeqLine(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (r *yamlReader) parseBlock(indent, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, fmt.Errorf("the document nests deeper than the coded bound of %d",
			maxYAMLDepth)
	}
	if !r.skipBlank() {
		return nil, nil
	}
	if isYAMLSeqLine(r.lines[r.i].text) {
		return r.parseSeq(indent, depth)
	}
	return r.parseMap(indent, depth)
}

func (r *yamlReader) parseMap(indent, depth int) (any, error) {
	m := make(map[string]any)
	for {
		if !r.skipBlank() {
			return m, nil
		}
		ln := r.lines[r.i]
		if ln.indent < indent {
			return m, nil
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("line %d: this line indents further than the mapping it "+
				"is in and no key opened a nested block", ln.num)
		}
		if isYAMLSeqLine(ln.text) {
			return nil, fmt.Errorf("line %d: a sequence entry appears where a mapping key "+
				"was expected", ln.num)
		}
		key, rest, err := splitYAMLKey(ln.text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln.num, err)
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("line %d: the mapping declares the key %q twice. One of "+
				"the two would silently win and, if it were `paths`, half the inventory "+
				"would disappear without a row", ln.num, redact(key))
		}
		if err := r.count(); err != nil {
			return nil, err
		}
		r.i++
		v, err := r.parseValue(rest, indent, depth, ln)
		if err != nil {
			return nil, err
		}
		m[key] = v
	}
}

func (r *yamlReader) parseSeq(indent, depth int) (any, error) {
	out := []any{}
	for {
		if !r.skipBlank() {
			return out, nil
		}
		ln := r.lines[r.i]
		if ln.indent < indent {
			return out, nil
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("line %d: this line indents further than the sequence "+
				"it is in", ln.num)
		}
		if !isYAMLSeqLine(ln.text) {
			return out, nil
		}
		if err := r.count(); err != nil {
			return nil, err
		}

		rest := ""
		contentIndent := indent + 1
		if ln.text != "-" {
			after := ln.text[1:]
			lead := len(after) - len(strings.TrimLeft(after, " "))
			contentIndent = indent + 1 + lead
			rest = strings.TrimLeft(after, " ")
		}

		if rest == "" || rest[0] == '#' {
			r.i++
			v, err := r.parseNested(indent, depth)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		if style, chomp, ok := yamlBlockScalarHeader(rest); ok {
			r.i++
			v, err := r.readBlockScalar(indent, style, chomp)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		if isYAMLSeqLine(rest) || isYAMLMappingStart(rest) {
			// The item's content starts on this line. Rewriting the line at
			// the column where the content begins is what makes
			//
			//	- name: q
			//	  in: query
			//
			// one mapping rather than two unrelated things: both lines are
			// then at indent 4 and the ordinary mapping parser reads them.
			r.lines[r.i] = yamlLine{num: ln.num, indent: contentIndent, text: rest}
			v, err := r.parseBlock(contentIndent, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		v, err := parseYAMLScalar(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln.num, err)
		}
		r.i++
		out = append(out, v)
	}
}

// parseValue reads what follows a `key:` on the same line, or the block below
// it.
func (r *yamlReader) parseValue(rest string, indent, depth int, ln yamlLine) (any, error) {
	t := strings.TrimLeft(rest, " ")
	if style, chomp, ok := yamlBlockScalarHeader(t); ok {
		return r.readBlockScalar(indent, style, chomp)
	}
	if t == "" || t[0] == '#' {
		return r.parseNested(indent, depth)
	}
	v, err := parseYAMLScalar(t)
	if err != nil {
		return nil, fmt.Errorf("line %d: %w", ln.num, err)
	}
	return v, nil
}

// parseNested reads the block indented under the line just consumed, or nil
// when there is none.
func (r *yamlReader) parseNested(parentIndent, depth int) (any, error) {
	if !r.skipBlank() {
		return nil, nil
	}
	if r.lines[r.i].indent <= parentIndent {
		return nil, nil
	}
	return r.parseBlock(r.lines[r.i].indent, depth+1)
}

// yamlBlockScalarHeader recognises `|`, `|-`, `|+`, `>`, `>-`, `>+`.
//
// An explicit indentation indicator (`|2`) is NOT recognised, and that is the
// fail-closed direction: the header then falls through to parseYAMLScalar,
// whose first-byte allowlist refuses `|`, and the WHOLE document is refused
// with a line number rather than half-read with a wrong indent base.
func yamlBlockScalarHeader(t string) (style byte, chomp byte, ok bool) {
	if t == "" || (t[0] != '|' && t[0] != '>') {
		return 0, 0, false
	}
	style = t[0]
	rest := t[1:]
	if rest != "" && (rest[0] == '-' || rest[0] == '+') {
		chomp = rest[0]
		rest = rest[1:]
	}
	rest = strings.TrimLeft(rest, " ")
	if rest != "" && rest[0] != '#' {
		return 0, 0, false
	}
	return style, chomp, true
}

// readBlockScalar collects the lines more indented than the key that opened
// the block.
func (r *yamlReader) readBlockScalar(parentIndent int, style, chomp byte) (any, error) {
	var collected []yamlLine
	for r.i < len(r.lines) {
		ln := r.lines[r.i]
		// A comment line inside a block scalar is CONTENT, so `blank` — which
		// counts comments as blank — is not the test here.
		if ln.text != "" && ln.indent <= parentIndent {
			break
		}
		collected = append(collected, ln)
		r.i++
		if err := r.count(); err != nil {
			return nil, err
		}
	}
	trailing := 0
	for len(collected) > 0 && collected[len(collected)-1].text == "" {
		collected = collected[:len(collected)-1]
		trailing++
	}
	if len(collected) == 0 {
		return "", nil
	}
	base := -1
	for _, ln := range collected {
		if ln.text != "" {
			base = ln.indent
			break
		}
	}
	if base < 0 {
		return "", nil
	}
	parts := make([]string, 0, len(collected))
	for _, ln := range collected {
		if ln.text == "" {
			parts = append(parts, "")
			continue
		}
		pad := ln.indent - base
		if pad < 0 {
			pad = 0
		}
		parts = append(parts, strings.Repeat(" ", pad)+ln.text)
	}

	var content string
	if style == '|' {
		content = strings.Join(parts, "\n")
	} else {
		content = foldYAMLBlock(parts)
	}
	switch chomp {
	case '-':
		// strip: no trailing break at all
	case '+':
		if content != "" {
			content += "\n" + strings.Repeat("\n", trailing)
		}
	default:
		if content != "" {
			content += "\n"
		}
	}
	return content, nil
}

// foldYAMLBlock folds a `>` scalar: a blank line becomes a break, a
// more-indented line keeps its break, and everything else joins with a space.
func foldYAMLBlock(parts []string) string {
	var b strings.Builder
	first := true
	prevMore := false
	for _, p := range parts {
		if p == "" {
			b.WriteString("\n")
			first = true
			prevMore = false
			continue
		}
		more := strings.HasPrefix(p, " ")
		switch {
		case first:
		case more || prevMore:
			b.WriteString("\n")
		default:
			b.WriteString(" ")
		}
		b.WriteString(p)
		first = false
		prevMore = more
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Keys and scalars — the first-byte allowlists
// ---------------------------------------------------------------------------

// plainYAMLKeyStart is the allowlist of first bytes a plain mapping key may
// have. `$` is here for `$ref`; `x-` extension keys start with a letter.
//
// Everything that opens a YAML feature outside this subset is absent by
// construction and none of them had to be listed: `&` anchor, `*` alias, `<`
// merge key, `!` tag, `{` and `[` flow collections, `?` explicit key, `%`
// directive, `#` comment, `|` and `>` block scalars, `@` and backtick
// (reserved).
func plainYAMLKeyStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '_' || c == '.' || c == '/' || c == '+' || c == '-' || c == '$'
}

// plainYAMLScalarStart is the same allowlist plus `~`, which is YAML's null.
func plainYAMLScalarStart(c byte) bool { return plainYAMLKeyStart(c) || c == '~' }

// splitYAMLKey splits `key: value` and `key:` into the two halves.
func splitYAMLKey(text string) (string, string, error) {
	if text == "" {
		return "", "", errors.New("an empty line cannot be a mapping key")
	}
	if text[0] == '"' || text[0] == '\'' {
		key, after, err := scanQuotedYAML(text)
		if err != nil {
			return "", "", err
		}
		after = strings.TrimLeft(after, " ")
		if after == "" || after[0] != ':' {
			return "", "", errors.New("a quoted mapping key is not followed by a colon")
		}
		if err := validYAMLKey(key); err != nil {
			return "", "", err
		}
		return key, after[1:], nil
	}
	if !plainYAMLKeyStart(text[0]) {
		return "", "", fmt.Errorf("a mapping key may not begin with %q; that byte opens a "+
			"YAML feature outside the subset this tier reads (anchor, alias, merge key, "+
			"tag, flow collection, explicit key or directive)", redact(text[:1]))
	}
	for i := 0; i < len(text); i++ {
		if text[i] != ':' {
			continue
		}
		if i+1 == len(text) || text[i+1] == ' ' || text[i+1] == '\t' {
			key := strings.TrimRight(text[:i], " ")
			if err := validYAMLKey(key); err != nil {
				return "", "", err
			}
			rest := ""
			if i+1 < len(text) {
				rest = text[i+1:]
			}
			return key, rest, nil
		}
	}
	return "", "", errors.New("the line is neither `key: value` nor `key:`")
}

func validYAMLKey(key string) error {
	if key == "" {
		return errors.New("the mapping key is empty")
	}
	if len(key) > maxYAMLLineBytes {
		return fmt.Errorf("the mapping key is %d bytes", len(key))
	}
	if err := printableIdentifier(key); err != nil {
		return fmt.Errorf("the mapping key carries a control byte: %w", err)
	}
	return nil
}

func isYAMLMappingStart(s string) bool {
	_, _, err := splitYAMLKey(s)
	return err == nil
}

// parseYAMLScalar reads one scalar.
//
// It returns a STRING for every plain scalar except the boolean and null
// literals. See this section's header for why: `swagger: 2.0` resolved to a
// float decodes into oasDoc's string field as a type error and loses the whole
// document, and nothing this tier reads out of a spec is a number.
func parseYAMLScalar(t string) (any, error) {
	if t == "" {
		return nil, nil
	}
	if t[0] == '"' || t[0] == '\'' {
		v, after, err := scanQuotedYAML(t)
		if err != nil {
			return nil, err
		}
		after = strings.TrimLeft(after, " ")
		if after != "" && after[0] != '#' {
			return nil, errors.New("a quoted scalar is followed by something that is " +
				"neither a comment nor the end of the line")
		}
		return v, nil
	}
	if !plainYAMLScalarStart(t[0]) {
		return nil, fmt.Errorf("a value may not begin with %q; that byte opens a YAML "+
			"feature outside the subset this tier reads (anchor, alias, tag, flow "+
			"collection or an unsupported block-scalar header)", redact(t[:1]))
	}
	v := strings.TrimRight(stripYAMLComment(t), " ")
	if err := printableIdentifier(v); err != nil {
		return nil, fmt.Errorf("the value carries a control byte: %w", err)
	}
	switch v {
	case "true", "True", "TRUE":
		return true, nil
	case "false", "False", "FALSE":
		return false, nil
	case "null", "Null", "NULL", "~":
		return nil, nil
	}
	return v, nil
}

// stripYAMLComment removes a trailing comment. A `#` only starts one when a
// space or tab precedes it, which is YAML's own rule and is why
// `application/json#fragment` survives.
func stripYAMLComment(t string) string {
	for i := 1; i < len(t); i++ {
		if t[i] == '#' && (t[i-1] == ' ' || t[i-1] == '\t') {
			return t[:i-1]
		}
	}
	return t
}

// scanQuotedYAML reads one quoted scalar and returns it with the remainder of
// the line.
//
// The escape set is an ALLOWLIST. An escape nobody enumerated refuses the
// document rather than being passed through as its own literal bytes, which is
// the direction that cannot silently change a path.
func scanQuotedYAML(t string) (string, string, error) {
	q := t[0]
	var b strings.Builder
	for i := 1; i < len(t); i++ {
		c := t[i]
		if q == '\'' {
			if c != '\'' {
				b.WriteByte(c)
				continue
			}
			if i+1 < len(t) && t[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			return b.String(), t[i+1:], nil
		}
		if c == '"' {
			return b.String(), t[i+1:], nil
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(t) {
			return "", "", errors.New("a double-quoted scalar ends in a backslash")
		}
		switch t[i] {
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case '/':
			b.WriteByte('/')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'u':
			if i+4 >= len(t) {
				return "", "", errors.New("a \\u escape is truncated")
			}
			var v rune
			for k := 1; k <= 4; k++ {
				d := hexDigit(t[i+k])
				if d < 0 {
					return "", "", errors.New("a \\u escape is not four hex digits")
				}
				v = v<<4 | rune(d)
			}
			b.WriteRune(v)
			i += 4
		default:
			return "", "", fmt.Errorf("the escape %q is outside the set this tier reads",
				redact(t[i:i+1]))
		}
	}
	return "", "", errors.New("a quoted scalar has no closing quote on its line")
}

func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// ---------------------------------------------------------------------------
// A URL IN A COMMITTED FILE IS A NETWORK DESTINATION THE REPOSITORY CHOSE
// ---------------------------------------------------------------------------

// serverURLPath extracts ONLY the path component of an absolute URL.
//
// It is the deliberate counterpart of D.18's serverURLHost, and the split is
// the whole control: the HOST half of a committed URL is read only so
// declaresForeignOrigin can record that the file pointed somewhere else, and
// the PATH half is the only part any route is ever built from. A path cannot
// move a host — gate 9 pins that — which is why the same asymmetry D.18
// applies to a served document's `servers` block is safe to apply to a WSDL
// address location and a Postman request URL.
//
// Like serverURLHost this deliberately does not use net/url. url.Parse's job
// is to produce a usable destination; the only thing this function is allowed
// to produce is a request path.
func serverURLPath(raw string) (string, bool) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return "", false
	}
	rest := raw[i+3:]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return "/", true
	}
	p := rest[j:]
	if k := strings.IndexAny(p, "?#"); k >= 0 {
		p = p[:k]
	}
	if p == "" {
		return "/", true
	}
	return p, true
}

// noteForeignOrigin reuses D.18's foreign-origin check by handing it the URL
// as if it were a `servers` entry.
//
// It is the SAME comparison the served-document path makes, against the same
// canonical target, rather than a second one here that could disagree about
// what "the target" means. 169.254.169.254 in a committed WSDL address and
// 169.254.169.254 in a served OpenAPI document produce identical rows.
func noteForeignOrigin(target authz.Target, url string, out *ParseResult) {
	if url == "" {
		return
	}
	foreign, detail := declaresForeignOrigin(target, oasDoc{Servers: []oasServer{{URL: url}}})
	if !foreign {
		return
	}
	out.DeclaredForeignOrigin = true
	out.Refusals = append(out.Refusals, Refusal{
		Reason: RefusalForeignOriginIgnored,
		Detail: detail,
	})
}

// ---------------------------------------------------------------------------
// WSDL 1.1
// ---------------------------------------------------------------------------

type wsdlPart struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Element string `xml:"element,attr"`
}

type wsdlMessage struct {
	Name  string     `xml:"name,attr"`
	Parts []wsdlPart `xml:"part"`
}

type wsdlOpMessage struct {
	Message string `xml:"message,attr"`
}

type wsdlOperation struct {
	Name  string         `xml:"name,attr"`
	Input *wsdlOpMessage `xml:"input"`
}

type wsdlPortType struct {
	Name       string          `xml:"name,attr"`
	Operations []wsdlOperation `xml:"operation"`
}

type wsdlAddress struct {
	Location string `xml:"location,attr"`
}

type wsdlPort struct {
	Name      string        `xml:"name,attr"`
	Binding   string        `xml:"binding,attr"`
	Addresses []wsdlAddress `xml:"address"`
}

type wsdlService struct {
	Name  string     `xml:"name,attr"`
	Ports []wsdlPort `xml:"port"`
}

type wsdlBinding struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type wsdlDefinitions struct {
	XMLName   xml.Name
	Messages  []wsdlMessage  `xml:"message"`
	PortTypes []wsdlPortType `xml:"portType"`
	Bindings  []wsdlBinding  `xml:"binding"`
	Services  []wsdlService  `xml:"service"`
}

// localName drops a QName's namespace prefix. WSDL cross-references
// (`binding="tns:Foo"`, `type="tns:Bar"`, `message="tns:Baz"`) are resolved on
// the local half, which is what makes a document readable without a full
// namespace table.
func localName(q string) string {
	if i := strings.LastIndexByte(q, ':'); i >= 0 {
		return q[i+1:]
	}
	return q
}

// ingestWSDL extracts one route per (service port, portType operation).
//
// A SOAP service exposes one HTTP path and an unbounded number of operations
// through it, exactly like GraphQL. Counting the port as ONE endpoint would
// make endpoint_coverage meaningless for a SOAP target — probing the single
// path once would read as complete coverage — so the unit of inventory is the
// operation, Route.Operation carries `PortType.operation`, and Route.Path
// carries the path from the port's address location.
//
// The decoder runs STRICT, which is what keeps a committed WSDL from being an
// entity-expansion bomb: encoding/xml refuses an undeclared entity in strict
// mode rather than expanding it. Only the root-element scan that classified
// the file runs non-strict, and it reads one element name and nothing else.
func ingestWSDL(target authz.Target, body []byte) ParseResult {
	root, ok := xmlRootLocalName(string(body))
	if ok && root == "description" {
		return ParseResult{Format: FormatUnrecognised, Refusals: []Refusal{{
			Reason: RefusalFormatUnrecognised,
			Detail: "the file is a WSDL 2.0 description. This tier reads WSDL 1.1 " +
				"definitions only; the two have different element vocabularies and " +
				"guessing between them would invent operations",
		}}}
	}

	var doc wsdlDefinitions
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	dec.Strict = true
	if err := dec.Decode(&doc); err != nil {
		return ParseResult{Format: FormatWSDL, Refusals: []Refusal{{
			Reason: RefusalSpecUnparseable,
			Detail: redact(err.Error()),
		}}}
	}

	out := ParseResult{Format: FormatWSDL}
	portTypes := make(map[string]wsdlPortType, len(doc.PortTypes))
	for _, pt := range doc.PortTypes {
		if pt.Name != "" {
			portTypes[pt.Name] = pt
		}
	}
	bindings := make(map[string]wsdlBinding, len(doc.Bindings))
	for _, b := range doc.Bindings {
		if b.Name != "" {
			bindings[b.Name] = b
		}
	}
	messages := make(map[string]wsdlMessage, len(doc.Messages))
	for _, m := range doc.Messages {
		if m.Name != "" {
			messages[m.Name] = m
		}
	}

	seenKeys := make(map[string]bool)
	for _, svc := range doc.Services {
		for _, port := range svc.Ports {
			binding, hasBinding := bindings[localName(port.Binding)]
			if !hasBinding {
				out.Refusals = append(out.Refusals, Refusal{
					Reason: RefusalSpecUnparseable,
					Detail: fmt.Sprintf("service %s port %s names binding %s and the "+
						"document declares no such binding, so its operation count is "+
						"unknown and none of them could be counted",
						redact(svc.Name), redact(port.Name), redact(port.Binding)),
				})
				continue
			}
			pt, hasPT := portTypes[localName(binding.Type)]
			if !hasPT {
				out.Refusals = append(out.Refusals, Refusal{
					Reason: RefusalSpecUnparseable,
					Detail: fmt.Sprintf("binding %s names portType %s and the document "+
						"declares no such portType", redact(binding.Name),
						redact(binding.Type)),
				})
				continue
			}

			location := ""
			for _, a := range port.Addresses {
				if a.Location != "" {
					location = a.Location
					break
				}
			}
			noteForeignOrigin(target, location, &out)
			path, pathOK := serverURLPath(location)

			for _, op := range pt.Operations {
				out.Seen++
				if out.Seen > maxWSDLOperations {
					out.Truncated = true
					out.Refusals = append(out.Refusals, Refusal{
						Reason: RefusalSpecTruncated,
						Detail: fmt.Sprintf("the document declares more than %d "+
							"(port, operation) pairs; parsing stopped",
							maxWSDLOperations),
					})
					SortRoutes(out.Routes)
					return out
				}
				operation := pt.Name + "." + op.Name
				if op.Name == "" {
					out.Refusals = append(out.Refusals, Refusal{
						Method: string(authz.MethodPost),
						Reason: RefusalParamUnusable,
						Detail: "an operation of portType " + redact(pt.Name) +
							" has no name",
					})
					continue
				}
				if !pathOK {
					out.Refusals = append(out.Refusals, Refusal{
						Method: string(authz.MethodPost),
						Reason: RefusalPathRejectedByKernel,
						Detail: fmt.Sprintf("operation %s is reached through service %s "+
							"port %s, whose address location %q is not an absolute URL "+
							"with a usable path", redact(operation), redact(svc.Name),
							redact(port.Name), redact(location)),
					})
					continue
				}
				params, perr := wsdlInputParams(messages, op)
				if perr != nil {
					out.Refusals = append(out.Refusals, Refusal{
						Path: redact(path), Method: string(authz.MethodPost),
						Reason: RefusalParamUnusable,
						Detail: redact(operation) + ": " + redact(perr.Error()),
					})
					continue
				}
				route, err := NewRoute(RouteFacts{
					Method:       authz.MethodPost,
					Path:         path,
					Target:       target,
					Operation:    boundIdent(operation),
					Params:       params,
					Provenance:   record.InventoryProvenanceRepoSpec,
					Confirmation: ConfirmationCandidate,
					Trust:        record.TrustUntrusted,
				})
				if err != nil {
					out.Refusals = append(out.Refusals, Refusal{
						Path: redact(path), Method: string(authz.MethodPost),
						Reason: classifyRouteError(err),
						Detail: redact(err.Error()),
					})
					continue
				}
				if seenKeys[route.Key()] {
					out.Refusals = append(out.Refusals, Refusal{
						Path: redact(path), Method: string(authz.MethodPost),
						Reason: RefusalDuplicateRoute,
						Detail: "the document reaches operation " + redact(operation) +
							" on this path more than once",
					})
					continue
				}
				seenKeys[route.Key()] = true
				out.Routes = append(out.Routes, route)
			}
		}
	}
	SortRoutes(out.Routes)
	return out
}

// wsdlInputParams turns the input message's parts into typed parameters.
//
// Every part travels in the SOAP body, so ParamInBody is the honest location.
// A part with no name refuses the operation rather than producing an anonymous
// parameter: the same rule buildOASParams applies to an unresolved $ref, for
// the same reason — an unnamed parameter cannot be concretized into a request
// later, so a probe built from it would not exercise the endpoint.
func wsdlInputParams(messages map[string]wsdlMessage, op wsdlOperation) ([]Param, error) {
	if op.Input == nil || op.Input.Message == "" {
		return nil, nil
	}
	msg, ok := messages[localName(op.Input.Message)]
	if !ok {
		return nil, fmt.Errorf("the input names message %s and the document declares no "+
			"such message", redact(op.Input.Message))
	}
	if len(msg.Parts) == 0 {
		return nil, nil
	}
	out := make([]Param, 0, len(msg.Parts))
	for _, p := range msg.Parts {
		if p.Name == "" {
			return nil, fmt.Errorf("message %s declares a part with no name",
				redact(msg.Name))
		}
		typ := p.Type
		if typ == "" {
			typ = p.Element
		}
		out = append(out, Param{
			Name:     boundIdent(p.Name),
			In:       ParamInBody,
			Type:     boundIdent(typ),
			Required: true,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// GraphQL
// ---------------------------------------------------------------------------

// defaultGraphQLRoots are the names GraphQL itself gives the three root
// operation types when a `schema` block does not rename them. They are not
// Anvil policy and they are not configuration: they are the language's
// defaults, and a document that renames them says so in its own `schema`
// block, which is read below.
func defaultGraphQLRoots() []string { return []string{"Query", "Mutation", "Subscription"} }

// ingestGraphQLIntrospection reads a committed introspection dump.
//
// It is D.18's parseGraphQL, retagged. The one thing this tier must add is the
// PATH: an introspection response served by a live target arrived on a known
// endpoint, and a JSON file committed to a repository did not.
func ingestGraphQLIntrospection(cfg IngestConfig, body []byte) ParseResult {
	if cfg.GraphQLEndpoint == "" {
		return graphQLWithNoConfiguredEndpoint(
			countIntrospectionRootFields(body), FormatGraphQLIntrospection)
	}
	pr, err := parseGraphQL(cfg.Target, cfg.GraphQLEndpoint, body)
	if err != nil {
		return ParseResult{Format: FormatGraphQLIntrospection, Refusals: []Refusal{{
			Reason: RefusalSpecUnparseable,
			Detail: redact(err.Error()),
		}}}
	}
	out := retagAll(cfg.Target, pr)
	out.Format = FormatGraphQLIntrospection
	return out
}

// countIntrospectionRootFields counts the root fields of a committed
// introspection dump using D.18's OWN decoder types.
//
// It is a different PROJECTION of the same decode, not a second parser: it
// reads gqlDoc exactly as parseGraphQL does and returns only a count. A number
// cannot disagree with a route about a path.
func countIntrospectionRootFields(body []byte) int {
	var doc gqlDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0
	}
	schema := doc.Data.Schema
	if schema == nil {
		schema = doc.Schema
	}
	if schema == nil {
		return 0
	}
	byName := make(map[string]gqlType, len(schema.Types))
	for _, t := range schema.Types {
		if t.Name != "" {
			byName[t.Name] = t
		}
	}
	n := 0
	for _, root := range []*gqlNamed{schema.QueryType, schema.MutationType, schema.SubscriptionType} {
		if root == nil || root.Name == "" {
			continue
		}
		if t, ok := byName[root.Name]; ok {
			n += len(t.Fields)
		}
	}
	return n
}

// graphQLWithNoConfiguredEndpoint turns a schema Anvil can read but cannot
// address into ONE COUNTED REFUSAL PER ROOT FIELD.
//
// The alternative — one document-level refusal — would leave the whole schema
// out of the coverage denominator, and a smaller denominator makes
// endpoint_coverage look BETTER. These operations exist; Anvil simply has no
// address for them, and that is what the rows say.
func graphQLWithNoConfiguredEndpoint(fields int, format SpecFormat) ParseResult {
	out := ParseResult{Format: format, Seen: fields}
	for i := 0; i < fields; i++ {
		out.Refusals = append(out.Refusals, Refusal{
			Method: string(authz.MethodPost),
			Reason: RefusalPathRejectedByKernel,
			Detail: "a GraphQL document declares a schema and no URL. No GraphQL endpoint " +
				"is configured, so this root field has no address and could not become a " +
				"route. It still counts toward the coverage denominator, because the " +
				"operation exists whether or not Anvil can reach it",
		})
	}
	if fields == 0 {
		out.Refusals = append(out.Refusals, Refusal{
			Reason: RefusalIntentRejected,
			Detail: "a GraphQL document that declares no readable root fields, and no " +
				"GraphQL endpoint is configured",
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// GraphQL SDL
// ---------------------------------------------------------------------------

type sdlArg struct {
	name string
	typ  string
}

type sdlField struct {
	name string
	args []sdlArg
}

// ingestGraphQLSDL extracts one route per root field of a committed schema
// document, on the configured GraphQL endpoint.
func ingestGraphQLSDL(cfg IngestConfig, body []byte) ParseResult {
	src, err := sanitizeSDL(string(body))
	if err != nil {
		return ParseResult{Format: FormatGraphQLSDL, Refusals: []Refusal{{
			Reason: RefusalSpecUnparseable,
			Detail: redact(err.Error()),
		}}}
	}
	roots := sdlRootTypeNames(src)

	var fields []struct {
		root  string
		field sdlField
	}
	for _, root := range roots {
		for _, bodyStr := range sdlTypeBodies(src, root) {
			fs, ferr := parseSDLFields(bodyStr)
			if ferr != nil {
				return ParseResult{Format: FormatGraphQLSDL, Refusals: []Refusal{{
					Reason: RefusalSpecUnparseable,
					Detail: "type " + redact(root) + ": " + redact(ferr.Error()),
				}}}
			}
			for _, f := range fs {
				fields = append(fields, struct {
					root  string
					field sdlField
				}{root, f})
			}
		}
	}

	if cfg.GraphQLEndpoint == "" {
		return graphQLWithNoConfiguredEndpoint(len(fields), FormatGraphQLSDL)
	}

	out := ParseResult{Format: FormatGraphQLSDL}
	seenKeys := make(map[string]bool)
	for _, rf := range fields {
		out.Seen++
		if out.Seen > maxRoutesPerSpec {
			out.Truncated = true
			out.Refusals = append(out.Refusals, Refusal{
				Endpoint: cfg.GraphQLEndpoint,
				Reason:   RefusalSpecTruncated,
				Detail: fmt.Sprintf("the schema declares more than %d root fields; "+
					"parsing stopped", maxRoutesPerSpec),
			})
			SortRoutes(out.Routes)
			return out
		}
		operation := rf.root + "." + rf.field.name
		params := make([]Param, 0, len(rf.field.args))
		for _, a := range rf.field.args {
			params = append(params, Param{
				Name:     boundIdent(a.name),
				In:       ParamInGraphQLArgument,
				Type:     boundIdent(a.typ),
				Required: strings.HasSuffix(a.typ, "!"),
			})
		}
		route, err := NewRoute(RouteFacts{
			Method:       authz.MethodPost,
			Path:         cfg.GraphQLEndpoint,
			Target:       cfg.Target,
			Operation:    boundIdent(operation),
			Params:       params,
			Provenance:   record.InventoryProvenanceRepoSpec,
			Confirmation: ConfirmationCandidate,
			Trust:        record.TrustUntrusted,
		})
		if err != nil {
			out.Refusals = append(out.Refusals, Refusal{
				Endpoint: cfg.GraphQLEndpoint, Method: string(authz.MethodPost),
				Reason: classifyRouteError(err),
				Detail: redact(err.Error()),
			})
			continue
		}
		if seenKeys[route.Key()] {
			out.Refusals = append(out.Refusals, Refusal{
				Endpoint: cfg.GraphQLEndpoint, Method: string(authz.MethodPost),
				Reason: RefusalDuplicateRoute,
				Detail: "the schema declares root field " + redact(operation) + " twice",
			})
			continue
		}
		seenKeys[route.Key()] = true
		out.Routes = append(out.Routes, route)
	}
	SortRoutes(out.Routes)
	return out
}

// sanitizeSDL blanks out comments and string literals while PRESERVING THE
// BYTE OFFSETS of everything else.
//
// The offsets matter: brace matching runs over the sanitized text and a `}`
// inside a description string would otherwise close a type body early and cut
// the rest of its fields out of the inventory without a row.
func sanitizeSDL(s string) (string, error) {
	if len(s) > maxSpecFileBytes {
		return "", fmt.Errorf("the document is %d bytes", len(s))
	}
	b := []byte(s)
	out := make([]byte, len(b))
	copy(out, b)
	blank := func(from, to int) {
		for k := from; k < to && k < len(out); k++ {
			if out[k] != '\n' {
				out[k] = ' '
			}
		}
	}
	for i := 0; i < len(b); {
		switch {
		case b[i] == '#':
			j := i
			for j < len(b) && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case strings.HasPrefix(s[i:], `"""`):
			j := i + 3
			for j < len(b) && !strings.HasPrefix(s[j:], `"""`) {
				j++
			}
			if j >= len(b) {
				return "", errors.New("a block description is never closed")
			}
			blank(i, j+3)
			i = j + 3
		case b[i] == '"':
			j := i + 1
			for j < len(b) && b[j] != '"' {
				if b[j] == '\\' {
					j++
				}
				if b[j] == '\n' {
					return "", errors.New("a quoted description crosses a line break")
				}
				j++
			}
			if j >= len(b) {
				return "", errors.New("a quoted description is never closed")
			}
			blank(i, j+1)
			i = j + 1
		default:
			i++
		}
	}
	return string(out), nil
}

// sdlRootTypeNames reads the `schema { query: X mutation: Y }` block, falling
// back to the language's own default root names.
func sdlRootTypeNames(src string) []string {
	bodies := sdlBlockBodies(src, "schema", "")
	if len(bodies) == 0 {
		return defaultGraphQLRoots()
	}
	var out []string
	seen := map[string]bool{}
	for _, body := range bodies {
		for _, line := range strings.FieldsFunc(body, func(r rune) bool {
			return r == '\n' || r == ',' || r == '\r'
		}) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			switch strings.TrimSpace(parts[0]) {
			case "query", "mutation", "subscription":
			default:
				continue
			}
			name := strings.TrimSpace(parts[1])
			name = strings.TrimSuffix(name, "!")
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	if len(out) == 0 {
		return defaultGraphQLRoots()
	}
	return out
}

// sdlTypeBodies returns the body of every `type <name> { ... }` block,
// including the bodies of `extend type <name>`. Both are collected because
// `extend type Query` adds root fields and reading only the first definition
// would drop them silently.
func sdlTypeBodies(src, name string) []string { return sdlBlockBodies(src, "type", name) }

// sdlBlockBodies finds `<keyword> [name] ... { ... }` and returns the braced
// bodies, with brace depth counted so a nested `{}` (an argument's default
// value) does not close the block early.
func sdlBlockBodies(src, keyword, name string) []string {
	var out []string
	for i := 0; i+len(keyword) <= len(src); {
		j := strings.Index(src[i:], keyword)
		if j < 0 {
			return out
		}
		at := i + j
		i = at + len(keyword)
		if at > 0 && isSDLNameByte(src[at-1]) {
			continue
		}
		k := at + len(keyword)
		if k < len(src) && isSDLNameByte(src[k]) {
			continue
		}
		rest := src[k:]
		if name != "" {
			trimmed := strings.TrimLeft(rest, " \t\r\n")
			if !strings.HasPrefix(trimmed, name) {
				continue
			}
			after := trimmed[len(name):]
			if after != "" && isSDLNameByte(after[0]) {
				continue
			}
		}
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			return out
		}
		// A `{` that appears after the next top-level keyword is not this
		// block's body; a definition with no body (`scalar X`) is skipped by
		// the caller only passing keywords that have one.
		depth := 0
		end := -1
		for p := open; p < len(rest); p++ {
			switch rest[p] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = p
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return out
		}
		out = append(out, rest[open+1:end])
		i = k + end + 1
	}
	return out
}

func isSDLNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

// parseSDLFields reads `name(args): Type` entries out of a type body.
func parseSDLFields(body string) ([]sdlField, error) {
	var out []sdlField
	i := 0
	for i < len(body) {
		c := body[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' {
			i++
			continue
		}
		if c == '@' {
			i = skipSDLDirective(body, i)
			continue
		}
		if !isSDLNameByte(c) {
			return nil, fmt.Errorf("a field name may not begin with %q", redact(body[i:i+1]))
		}
		start := i
		for i < len(body) && isSDLNameByte(body[i]) {
			i++
		}
		fieldName := body[start:i]
		i = skipSDLSpace(body, i)

		var args []sdlArg
		if i < len(body) && body[i] == '(' {
			end, ok := matchSDLDelim(body, i, '(', ')')
			if !ok {
				return nil, fmt.Errorf("field %s has an unclosed argument list",
					redact(fieldName))
			}
			var err error
			args, err = parseSDLArgs(body[i+1 : end])
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", redact(fieldName), err)
			}
			i = end + 1
			i = skipSDLSpace(body, i)
		}
		if i >= len(body) || body[i] != ':' {
			return nil, fmt.Errorf("field %s is not followed by a type", redact(fieldName))
		}
		i++
		i = skipSDLSpace(body, i)
		for i < len(body) && isSDLTypeByte(body[i]) {
			i++
		}
		if len(out) >= maxSDLFields {
			return nil, fmt.Errorf("the type declares more than %d fields", maxSDLFields)
		}
		out = append(out, sdlField{name: fieldName, args: args})
	}
	return out, nil
}

func parseSDLArgs(s string) ([]sdlArg, error) {
	var out []sdlArg
	for _, piece := range splitSDLTopLevel(s) {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		if piece[0] == '@' {
			continue
		}
		colon := strings.IndexByte(piece, ':')
		if colon < 0 {
			return nil, fmt.Errorf("the argument %q declares no type", redact(piece))
		}
		name := strings.TrimSpace(piece[:colon])
		if name == "" {
			return nil, errors.New("an argument has no name")
		}
		typ := strings.TrimSpace(piece[colon+1:])
		if eq := strings.IndexByte(typ, '='); eq >= 0 {
			typ = strings.TrimSpace(typ[:eq])
		}
		if at := strings.IndexByte(typ, '@'); at >= 0 {
			typ = strings.TrimSpace(typ[:at])
		}
		if typ == "" {
			return nil, fmt.Errorf("the argument %s declares no type", redact(name))
		}
		if len(out) >= maxSDLArgs {
			return nil, fmt.Errorf("the field declares more than %d arguments", maxSDLArgs)
		}
		out = append(out, sdlArg{name: name, typ: typ})
	}
	return out, nil
}

// splitSDLTopLevel splits on commas and line breaks that are not inside
// brackets, parentheses or braces — so an argument whose default value is
// `{a: 1, b: 2}` stays one argument.
func splitSDLTopLevel(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',', '\n':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func skipSDLSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

func skipSDLDirective(s string, i int) int {
	i++
	for i < len(s) && isSDLNameByte(s[i]) {
		i++
	}
	j := skipSDLSpace(s, i)
	if j < len(s) && s[j] == '(' {
		if end, ok := matchSDLDelim(s, j, '(', ')'); ok {
			return end + 1
		}
	}
	return i
}

func isSDLTypeByte(c byte) bool {
	return isSDLNameByte(c) || c == '[' || c == ']' || c == '!'
}

func matchSDLDelim(s string, at int, open, closing byte) (int, bool) {
	depth := 0
	for i := at; i < len(s); i++ {
		switch s[i] {
		case open:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Postman collections, converted to OpenAPI at ingest
//
// research/22-attack-surface-discovery.md line 328: "Convert Postman to
// OpenAPI at ingest, because Nuclei's `-im` modes are `list, burp, jsonl,
// yaml, openapi, swagger` and do not include Postman." The conversion runs
// here rather than downstream so that everything after this point sees one
// document shape, and — the part that matters more — so that a Postman request
// URL goes through THE SAME foreign-origin check a served OpenAPI `servers`
// entry does. Every absolute request URL in the collection is emitted into the
// converted document's `servers` array for exactly that purpose, and only the
// PATH half of any of them is ever used to build a route.
// ---------------------------------------------------------------------------

type pmKV struct {
	Key      string `json:"key"`
	Disabled bool   `json:"disabled"`
}

type pmBody struct {
	Mode string `json:"mode"`
}

type pmRequestObj struct {
	Method string          `json:"method"`
	Header []pmKV          `json:"header"`
	URL    json.RawMessage `json:"url"`
	Body   *pmBody         `json:"body"`
}

type pmURLObj struct {
	Raw   string          `json:"raw"`
	Path  json.RawMessage `json:"path"`
	Query []pmKV          `json:"query"`
}

type pmItem struct {
	Name    string          `json:"name"`
	Item    []pmItem        `json:"item"`
	Request json.RawMessage `json:"request"`
}

type pmCollection struct {
	Item []pmItem `json:"item"`
}

// ingestPostman converts a committed collection into an OpenAPI 3 document and
// hands it to the one OpenAPI parser this package has.
//
// The refusals raised BEFORE the conversion are the ones the conversion itself
// would swallow, and each of them increments Seen so the accounting identity
// still holds across the two halves:
//
//   - a method the kernel's allowlist does not carry. This one is not
//     defensiveness: a converted operation is a KEY in an OpenAPI path item,
//     and `parameters`, `summary`, `description`, `servers` and `$ref` are
//     STRUCTURAL keys there. A collection whose request method is "servers"
//     would be silently skipped as structure rather than counted as an
//     operation, and a silent skip shrinks the coverage denominator.
//   - a duplicate (path, method), which would collapse into one JSON map entry
//     and take its Seen count with it.
//   - a URL with no usable path, including one still carrying an unresolved
//     `{{variable}}` — an address Anvil cannot form is surface Anvil cannot
//     probe, and it belongs in the denominator with a row saying why.
func ingestPostman(target authz.Target, body []byte) ParseResult {
	var coll pmCollection
	if err := json.Unmarshal(body, &coll); err != nil {
		return ParseResult{Format: FormatPostmanCollection, Refusals: []Refusal{{
			Reason: RefusalSpecUnparseable,
			Detail: redact(err.Error()),
		}}}
	}

	out := ParseResult{Format: FormatPostmanCollection}
	paths := map[string]map[string]any{}
	var servers []map[string]any
	seenOrigin := map[string]bool{}
	seenOp := map[string]bool{}
	items := 0

	var walk func(list []pmItem, depth int) bool
	walk = func(list []pmItem, depth int) bool {
		if depth > maxPostmanDepth {
			out.Truncated = true
			out.Refusals = append(out.Refusals, Refusal{
				Reason: RefusalSpecTruncated,
				Detail: fmt.Sprintf("the collection nests folders deeper than the coded "+
					"bound of %d; parsing stopped", maxPostmanDepth),
			})
			return false
		}
		for _, it := range list {
			items++
			if items > maxPostmanItems {
				out.Truncated = true
				out.Refusals = append(out.Refusals, Refusal{
					Reason: RefusalSpecTruncated,
					Detail: fmt.Sprintf("the collection declares more than %d items; "+
						"parsing stopped", maxPostmanItems),
				})
				return false
			}
			if len(it.Item) > 0 {
				if !walk(it.Item, depth+1) {
					return false
				}
				continue
			}
			if len(it.Request) == 0 {
				continue
			}
			// refuseItem is where Seen is incremented for this half of the
			// parse. An item that converts successfully is counted by
			// parseOpenAPI when it reads the converted document; counting it
			// here as well would double it, and the accounting identity
			// (Seen == routes + per-operation refusals) is what notices.
			refuseItem := func(r Refusal) {
				out.Seen++
				out.Refusals = append(out.Refusals, r)
			}
			method, rawURL, params, bodyMedia, derr := decodePostmanRequest(it.Request)
			if derr != nil {
				refuseItem(Refusal{
					Reason: RefusalParamUnusable,
					Detail: "item " + redact(it.Name) + ": " + redact(derr.Error()),
				})
				continue
			}
			if !authz.Method(method).Recognised() {
				refuseItem(Refusal{
					Method: redact(method),
					Reason: RefusalMethodNotAllowlisted,
					Detail: "item " + redact(it.Name) + " declares a method the kernel's " +
						"allowlist does not carry. It is refused here rather than written " +
						"into the converted document, where a method that collided with " +
						"an OpenAPI structural key would be skipped without a row",
				})
				continue
			}
			if rawURL != "" && strings.Contains(rawURL, "://") && !seenOrigin[rawURL] {
				seenOrigin[rawURL] = true
				servers = append(servers, map[string]any{"url": rawURL})
			}
			path, ok, why := postmanRequestPath(rawURL)
			if !ok {
				refuseItem(Refusal{
					Method: method,
					Reason: RefusalPathRejectedByKernel,
					Detail: "item " + redact(it.Name) + ": " + why,
				})
				continue
			}
			key := method + "\x00" + path
			if seenOp[key] {
				refuseItem(Refusal{
					Path: redact(path), Method: method,
					Reason: RefusalDuplicateRoute,
					Detail: "the collection declares this method and path more than once; " +
						"the converted document would keep only one of them",
				})
				continue
			}
			seenOp[key] = true
			params = append(params, postmanPathParams(path)...)

			op := map[string]any{"operationId": boundIdent(it.Name)}
			if len(params) > 0 {
				op["parameters"] = params
			}
			if bodyMedia != "" {
				op["requestBody"] = map[string]any{
					"content": map[string]any{bodyMedia: map[string]any{}},
				}
			}
			if paths[path] == nil {
				paths[path] = map[string]any{}
			}
			paths[path][strings.ToLower(method)] = op
		}
		return true
	}
	walk(coll.Item, 0)

	doc := map[string]any{"openapi": "3.0.3", "paths": paths}
	if len(servers) > 0 {
		doc["servers"] = servers
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		out.Refusals = append(out.Refusals, Refusal{
			Reason: RefusalSpecUnparseable,
			Detail: "the converted collection could not be encoded: " + redact(err.Error()),
		})
		return out
	}

	converted := retagAll(target, parseOpenAPIBody(target, FormatOpenAPI3, encoded))
	out.Routes = converted.Routes
	out.Seen += converted.Seen
	out.Refusals = append(out.Refusals, converted.Refusals...)
	out.DeclaredForeignOrigin = out.DeclaredForeignOrigin || converted.DeclaredForeignOrigin
	out.Truncated = out.Truncated || converted.Truncated
	SortRoutes(out.Routes)
	return out
}

// decodePostmanRequest reads the two shapes Postman writes a request in: an
// object, and a bare string meaning "GET this URL".
func decodePostmanRequest(raw json.RawMessage) (method, url string, params []map[string]any,
	bodyMedia string, err error) {
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		return string(authz.MethodGet), asString, nil, "", nil
	}
	var obj pmRequestObj
	if uerr := json.Unmarshal(raw, &obj); uerr != nil {
		return "", "", nil, "", fmt.Errorf("the request is neither a URL string nor an "+
			"object: %w", uerr)
	}
	method = strings.ToUpper(strings.TrimSpace(obj.Method))
	if method == "" {
		method = string(authz.MethodGet)
	}
	urlObj, uerr := decodePostmanURL(obj.URL)
	if uerr != nil {
		return "", "", nil, "", uerr
	}
	for _, h := range obj.Header {
		if h.Disabled || h.Key == "" {
			continue
		}
		params = append(params, map[string]any{
			"name": boundIdent(h.Key), "in": "header",
			"schema": map[string]any{"type": "string"},
		})
	}
	for _, q := range urlObj.Query {
		if q.Disabled || q.Key == "" {
			continue
		}
		params = append(params, map[string]any{
			"name": boundIdent(q.Key), "in": "query",
			"schema": map[string]any{"type": "string"},
		})
	}
	if obj.Body != nil {
		bodyMedia = postmanBodyMedia(obj.Body.Mode)
	}
	return method, urlObj.Raw, params, bodyMedia, nil
}

// decodePostmanURL reads the two shapes Postman writes a URL in: an object
// with a `raw` field, and a bare string.
func decodePostmanURL(raw json.RawMessage) (pmURLObj, error) {
	if len(raw) == 0 {
		return pmURLObj{}, errors.New("the request declares no url")
	}
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		return pmURLObj{Raw: asString}, nil
	}
	var obj pmURLObj
	if err := json.Unmarshal(raw, &obj); err != nil {
		return pmURLObj{}, fmt.Errorf("the url is neither a string nor an object: %w", err)
	}
	if obj.Raw == "" {
		if joined, ok := joinPostmanPathSegments(obj.Path); ok {
			obj.Raw = joined
		}
	}
	return obj, nil
}

// joinPostmanPathSegments rebuilds a path from `url.path`, which Postman
// writes as a string, as an array of strings, or as an array of
// `{"value": "..."}` objects.
func joinPostmanPathSegments(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		if asString == "" {
			return "", false
		}
		if asString[0] == '/' {
			return asString, true
		}
		return "/" + asString, true
	}
	var asAny []json.RawMessage
	if json.Unmarshal(raw, &asAny) != nil {
		return "", false
	}
	segs := make([]string, 0, len(asAny))
	for _, el := range asAny {
		var s string
		if json.Unmarshal(el, &s) == nil {
			segs = append(segs, s)
			continue
		}
		var o struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(el, &o) == nil && o.Value != "" {
			segs = append(segs, o.Value)
			continue
		}
		return "", false
	}
	if len(segs) == 0 {
		return "", false
	}
	return "/" + strings.Join(segs, "/"), true
}

func postmanBodyMedia(mode string) string {
	switch mode {
	case "urlencoded":
		return "application/x-www-form-urlencoded"
	case "formdata":
		return "multipart/form-data"
	case "file":
		return "application/octet-stream"
	case "graphql":
		return "application/json"
	case "raw":
		return "application/json"
	case "":
		return ""
	default:
		// An unrecognised mode still means the request HAS a body. Naming it
		// as an unspecified media type is honest; guessing JSON would put a
		// type in the inventory the collection never declared.
		return "application/octet-stream"
	}
}

// postmanPathParams declares one path parameter per templated segment.
//
// This is a TRANSLATION and not an invention. Postman writes a path variable
// as `:id` in the URL itself and carries no parameter object beside it, so the
// segment IS the declaration; converting it to OpenAPI's `{id}` without also
// declaring the parameter would produce a route whose path is templated and
// whose parameter list is empty, and D.22 would have nothing to fill.
//
// The type is left EMPTY, which is the honest answer: a Postman collection
// declares no type for a path variable. Param.Typed() then reports false and
// Route.FullyTyped() reports false, so "parameter-typed extraction" stays a
// measurement rather than an assertion.
func postmanPathParams(path string) []map[string]any {
	var out []map[string]any
	for _, seg := range strings.Split(path, "/") {
		if len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}' {
			out = append(out, map[string]any{
				"name": boundIdent(seg[1 : len(seg)-1]), "in": "path", "required": true,
			})
		}
	}
	return out
}

// postmanRequestPath extracts the path half of a Postman request URL.
//
// An unresolved `{{variable}}` refuses the operation. The alternative would be
// a route whose path carries a template Anvil cannot fill, which is an address
// that cannot be probed sitting permanently in the coverage denominator's
// numerator-eligible pool. `:id` path variables ARE translated, to OpenAPI's
// `{id}`, because that is the same templated-segment concept OpenAPI already
// has and D.18's parser already carries.
func postmanRequestPath(raw string) (string, bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, "the request declares no url"
	}
	if strings.Contains(raw, "{{") {
		return "", false, "the url still carries an unresolved Postman variable, so no " +
			"address could be formed for it: " + redact(raw)
	}
	var p string
	if strings.Contains(raw, "://") {
		got, ok := serverURLPath(raw)
		if !ok {
			return "", false, "the url is not one this tier can split: " + redact(raw)
		}
		p = got
	} else {
		j := strings.IndexByte(raw, '/')
		if j < 0 {
			return "", false, "the url carries no path component: " + redact(raw)
		}
		p = raw[j:]
		if k := strings.IndexAny(p, "?#"); k >= 0 {
			p = p[:k]
		}
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if len(s) > 1 && s[0] == ':' {
			segs[i] = "{" + s[1:] + "}"
		}
	}
	p = strings.Join(segs, "/")
	if p == "" {
		p = "/"
	}
	return p, true, ""
}

// ---------------------------------------------------------------------------
// Deterministic ordering
// ---------------------------------------------------------------------------

// SortFileResults orders per-file outcomes by artifact URI.
//
// Go map iteration is randomized and so is the order a harvester walks a
// directory tree. A Tier 1 ingest whose file order changes between runs makes
// record.PropRunRouteTableDigest churn for a repository that never changed,
// which is the same instability SortRoutes exists to prevent one level down.
func SortFileResults(fs []FileResult) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Location.URI < fs[j].Location.URI })
}
