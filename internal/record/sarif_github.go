package record

// sarif_github.go — R.14, the reduced-SARIF GitHub code-scanning projection.
//
// ===========================================================================
// THIS FILE IS THE SINGLE DEFINITION OF THE GITHUB PROJECTION
// ===========================================================================
//
// Every GitHub code-scanning cap, every strip rule and every drop rule Anvil
// applies lives HERE and nowhere else. Any area that needs to emit SARIF to
// GitHub calls ProjectForGitHub; it does not re-derive a limit, re-spell a
// cap, or re-implement the filter.
//
// This is not style. plan/IMPLEMENTATION-PLAN.md §6 closed TEN confirmed
// cross-area defects whose single shared shape was "two areas that could not
// see each other each defined the same vocabulary from their own side, and no
// step was ever assigned to reconcile them." A second copy of `25000` in
// another package is a second definition of GitHub's contract, and it will
// drift the same way `dast_status` drifted into two disjoint enums.
//
// See GitHubProjectionOwner below, which records that ownership in code so it
// survives the plan documents.
//
// ===========================================================================
// THE READ GATE APPLIES HERE TOO, AND IT IS CALLED, NOT RE-DERIVED
// ===========================================================================
//
// plan/IMPLEMENTATION-PLAN.md §6 ruling G5: "`sealed` is load-bearing: R.6
// makes it the hard read gate ('do not allow a consumer to read a half's
// results before that half's `status` equals `sealed`')". GitHub code scanning
// is the most externally visible consumer Anvil has, so it is the LAST place
// that gate may be skipped — and CRITIQUE-03 B1 found this file skipping it
// entirely, projecting every run in `l.Runs` unconditionally.
//
// A run whose half sealing.go's HalfReadGate refuses contributes no results,
// and each of them is ledgered under GitHubDropHalfNotReadable with the half's
// `anvil/status` and the audit's `anvil/state`. The gate is CALLED — this file
// does not ask `src.Properties.Status == HalfStatusSealed` for itself. Four
// authors have now re-derived that question locally and four got it wrong in
// four different ways; sealing.go's read-gate section lists them.
//
// AssertMasked is a precondition for the same structural reason readpath.go
// makes it one: every surface MaskRecord covers is independently stripped
// below, so no leak is demonstrable through this file TODAY, which means the
// safety rests entirely on the strip list staying exhaustive.
//
// ===========================================================================
// WHY THE PROJECTION IS LOSSY, AND WHY THE LOSS IS ENUMERATED
// ===========================================================================
//
// research/18-unified-audit-record.md, "What Anvil loses by choosing SARIF":
//
//	"GitHub throws away the DAST half. webRequest, webResponse, taxonomies,
//	 provenance and property bags are not in GitHub's supported-property list
//	 [S2], and a DAST-only result has no startLine to satisfy GitHub's
//	 location requirement [S2]. Design rule: the GitHub upload is a
//	 projection, not the record."
//
// and research/18 Risk #6:
//
//	"GitHub silently discards the entire DAST half... If anyone treats the
//	 GitHub UI as the audit, they will believe Anvil found only static
//	 issues."
//
// Risk #6 is a risk about a HUMAN BELIEF, and no amount of correct filtering
// addresses it. What addresses it is making the loss countable: every result
// this projection refuses to upload is recorded in GitHubProjectionLoss with
// its finding id and a reason, and every field it strips is counted by kind.
// A consumer can ask "what did GitHub not get, and why" and receive a total,
// enumerable answer instead of a shrug.
//
// Two distinct kinds of loss are tracked separately, because they answer
// different questions:
//
//   - GitHubDropReason  — a whole RESULT never reaches GitHub. GitHub could
//     not render it as an alert at all.
//   - GitHubStripReason — a result reaches GitHub with FIELDS removed. The
//     alert exists but carries less than the record does.
//
// ===========================================================================
// WHY THE STRIPPING IS EXPLICIT AND NOT LEFT TO GITHUB
// ===========================================================================
//
// GitHub accepts any valid SARIF 2.1.0 file and ignores every property
// outside its supported list [S2]. It would therefore "work" to upload the
// whole record and let GitHub discard the DAST half itself. This packet
// forbids that, and the reason is size, not tidiness: the ignored bytes still
// count against the 10 MB gzip limit, so relying on silent ignoring converts
// a display no-op into an upload REJECTION on exactly the large audits that
// most need to be uploaded. Stripping is therefore done here, before the byte
// count is taken.
//
// The projection also never emits an `anvil/*` property bag. That is enforced
// structurally, not by zeroing fields: the wire types below (GitHubSARIFLog,
// GitHubRun, GitHubResult, GitHubLocation) simply have no `properties`
// member, so no future edit to AuditProperties, RunProperties or
// ResultProperties can leak one into a GitHub upload. Reusing SARIFLog with
// its properties zeroed would have emitted `"properties":{"anvil/findingId":
// "", ...}` — a bag of empty anvil keys, which is the forbidden thing.
//
// ===========================================================================
// WHAT COUNTS AS "A PHYSICAL CODE LOCATION" — STRICTER THAN Validate()
// ===========================================================================
//
// contract.go has an unexported hasPhysicalCodeLocation used by Validate to
// decide whether primaryLocationLineHash is REQUIRED. It asks a different
// question than this file asks, and it deliberately answers it more loosely:
// it is satisfied by any region with startLine > 0, including research/18's
// annotated DAST result, whose endpoint location carries
// `"region": {"startLine": 1, ...}` described in the source as a
// "placeholder so GitHub can render it".
//
// That placeholder does not survive contact with GitHub. GitHub resolves
// `artifactLocation.uri` against the repository root; an absolute URI such as
// `https://staging.payments.internal/api/login` resolves to no file, so the
// alert cannot render, and uploading it additionally publishes an internal
// hostname to GitHub. So this file asks its own, stricter question — is this
// a REPO-RELATIVE path with a real start line? — and records the difference
// as GitHubDropLocationNotRepoRelative rather than letting a DAST result
// through on a placeholder.
//
// This is not a second definition of a shared predicate. Validate answers
// "must this record carry the hash?"; isRepoCodeLocation answers "can GitHub
// render this?". Merging them would break Validate for legitimately
// endpoint-located DAST results.
//
// ===========================================================================
// WHAT THIS FILE DOES NOT DO: it does not COMPUTE primaryLocationLineHash
// ===========================================================================
//
// It filters ON that key and drops results that lack it
// (GitHubDropNoPrimaryLocationLineHash). It does not fill it in.
//
// This is a live, unresolved ownership question and it is deliberately left
// visible rather than absorbed. fingerprint.go says the key "is owned by the
// GitHub projection (R.14)"; plan/40-record-and-storage.md's Record Field
// Contract names the producer as the fingerprint engine; and
// internal/record/CRITIQUE-01.md's MAJOR 3 records that the disagreement is
// unruled and that no code in the tree produces the value today. R.14's
// packet scopes this file to the projection and says nothing about producing
// a fingerprint.
//
// Implementing it here anyway would be the §6 defect exactly: an identity
// hash defined in two places, silently disagreeing, with regression matching
// failing forever and nothing to catch it. So the gap is surfaced at runtime
// instead — a record whose results lack the key produces a projection that
// drops every one of them and says so, by name and count.
//
// ===========================================================================
// SHARDING POLICY: ONE RUN PER FILE
// ===========================================================================
//
// research/18: "keep any single emitted SARIF projection under 25,000
// results/run and 10 MB gzipped so the GitHub path never fails [S2]. A
// full-repo audit exceeding that must shard by run, not truncate."
//
// This file shards by run and puts exactly one run in each file. GitHub
// permits 20 runs per file; emitting one makes GitHubMaxRunsPerFile
// unreachable by construction rather than by arithmetic, keeps every file as
// small as possible against the binding 10 MB constraint, and keeps a shard
// attributable to exactly one half of the audit.
//
// Sharding a run forces one further change, and it is not cosmetic: GitHub
// keys an analysis on `runAutomationDetails.id`, so two shards uploaded under
// the same id would make the second REPLACE the first and silently lose half
// the alerts. Shards after the first therefore receive a distinct, derived id
// (see shardAutomationID) and have `automationDetails.guid` cleared, because
// a guid identifies one run object and copying it across shards asserts
// something false. Both are recorded as strips.
//
// ===========================================================================
// TRUNCATION IS NEVER SILENT AND NEVER FIRST
// ===========================================================================
//
// Results are never truncated to fit; the run is split until the parts fit.
// The one case that cannot be split is a SINGLE result whose own file exceeds
// 10 MB gzipped. That result is dropped with
// GitHubDropExceedsFileSizeCap rather than being allowed to make the whole
// projection fail, and the guarantee "no returned file exceeds a documented
// cap on any input" is preserved. If even a result-free run exceeds the cap
// (tool metadata alone over 10 MB), ProjectForGitHub returns an error: at
// that point nothing legal can be emitted and pretending otherwise would be
// worse.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"strings"
)

// GitHubProjectionOwner records, in code, which step owns this logic, in the
// same spirit as AreaMappingOwners in contract.go: the plan documents are not
// compiled and a later area cannot grep them from its own package.
//
// Area O's O.9 (the GitHub upload step) CONSUMES ProjectForGitHub. It does
// not re-implement the caps, the strip list or the shard rule. A second
// implementation of a documented external limit is a second definition of
// that limit.
const GitHubProjectionOwner = "R.14 — internal/record/sarif_github.go is the single definition of the " +
	"GitHub code-scanning projection: its caps, its strip list, its drop rules and its shard policy. " +
	"O.9 calls ProjectForGitHub; it does not fork this logic (plan/IMPLEMENTATION-PLAN.md §6)."

// ---------------------------------------------------------------------------
// GitHub's documented limits
//
// Every number here is quoted from research/18-unified-audit-record.md,
// "What GitHub actually accepts — hard numbers", sourced to [S2] (GitHub's
// SARIF-support documentation, graded A but explicitly "vendor-specific
// behaviour; limits can change without notice"). They are declared once,
// here, so that a change to GitHub's documentation is a one-line change in
// one package.
// ---------------------------------------------------------------------------

const (
	// GitHubMaxResultsPerRun is GitHub's "25,000 results per run" limit.
	GitHubMaxResultsPerRun = 25000

	// GitHubDisplayedResultsPerRun is the number of results GitHub actually
	// DISPLAYS per run, "only the top 5,000 by severity". It is not a cap
	// and nothing here enforces it; it is declared so a consumer reporting
	// "we uploaded 25,000 alerts" can also say how many a human will see.
	GitHubDisplayedResultsPerRun = 5000

	// GitHubMaxRunsPerFile is GitHub's "20 runs per file" limit. This file
	// emits one run per file, so the limit is unreachable by construction;
	// it is still checked by WithinCaps, because an invariant that is only
	// true by construction stops being true the moment the construction
	// changes.
	GitHubMaxRunsPerFile = 20

	// GitHubRunsPerProjectedFile is Anvil's own, stricter policy. See the
	// sharding-policy section of this file's header.
	GitHubRunsPerProjectedFile = 1

	// GitHubMaxGzipBytes is GitHub's "10 MB gzip-compressed file" limit.
	// This is the binding constraint in practice: a full-repo audit hits it
	// long before it hits 25,000 results.
	GitHubMaxGzipBytes = 10 * 1024 * 1024

	// GitHubMaxRulesPerRun is GitHub's "25,000 rules per run" limit. A
	// projected run emits only the rules its own results reference, and a
	// run carries at most GitHubMaxResultsPerRun results, so distinct rules
	// can never exceed distinct results and this cap is unreachable. Checked
	// anyway by WithinCaps.
	GitHubMaxRulesPerRun = 25000

	// GitHubMaxToolExtensionsPerRun is GitHub's "100 tool extensions per
	// run" limit. contract.go's Tool carries a driver and no extensions, so
	// Anvil emits zero. Declared for completeness of the cap table.
	GitHubMaxToolExtensionsPerRun = 100

	// GitHubMaxLocationsPerResult is GitHub's "1,000 locations per result
	// (100 displayed)" limit. Enforced by truncation, counted as a strip.
	GitHubMaxLocationsPerResult = 1000

	// GitHubMaxThreadFlowLocationsPerResult is GitHub's "10,000 thread-flow
	// locations per result (top 1,000 displayed)" limit, counted across
	// every code flow of one result. Enforced by truncation, counted as a
	// strip.
	GitHubMaxThreadFlowLocationsPerResult = 10000
)

// ---------------------------------------------------------------------------
// Loss vocabulary — why a whole result never reached GitHub
// ---------------------------------------------------------------------------

// GitHubDropReason names, in one closed vocabulary, every reason this
// projection refuses to upload a result.
//
// Lowercase snake_case, matching plan/IMPLEMENTATION-PLAN.md §6: "Lowercase
// snake_case is the record's convention throughout."
//
// These are NOT record enums. They never appear in a record, a column or an
// `anvil/*` bag; they are the projection's own diagnostic vocabulary, owned
// by R.14 inside area 40. Nothing outside this package may declare a second
// set of them.
type GitHubDropReason string

const (
	// GitHubDropHalfNotReadable: the result's HALF did not pass the read gate
	// — its `anvil/status` is not `sealed`, or the audit has expired. This
	// gate is evaluated per RUN and outranks every per-result reason below,
	// because none of them is a question worth asking about results a consumer
	// is not permitted to read at all.
	//
	// plan/IMPLEMENTATION-PLAN.md §6 ruling G5: "`sealed` is load-bearing: R.6
	// makes it the hard read gate ('do not allow a consumer to read a half's
	// results before that half's `status` equals `sealed`')". CRITIQUE-03 B1
	// found this file asking nobody: it projected every run unconditionally,
	// so a `running` half's provisional findings and a `failed` half's
	// crash-truncated output were both publishable to GitHub code scanning —
	// the most externally visible consumer Anvil has, read by humans and by
	// branch-protection rules, and keyed on `runAutomationDetails.id` so that
	// a premature upload is REPLACED by the real one after the seal.
	GitHubDropHalfNotReadable GitHubDropReason = "half_not_readable"

	// GitHubDropNoLocations: the result carries no `locations[]` at all.
	// GitHub requires `message.text`, `locations[]` and
	// `partialFingerprints` on every result.
	GitHubDropNoLocations GitHubDropReason = "no_locations"

	// GitHubDropNoPhysicalLocation: the result's PRIMARY location
	// (`locations[0]`) carries no `physicalLocation`. A logical location
	// alone cannot render as a code-scanning alert.
	GitHubDropNoPhysicalLocation GitHubDropReason = "no_physical_location"

	// GitHubDropLocationNotRepoRelative: the primary location's
	// `artifactLocation.uri` is not a repository-relative path — it is an
	// absolute URI (`https://…`, a DAST endpoint), an absolute filesystem
	// path (a host finding), or escapes the root with `..`. GitHub resolves
	// the uri against the repository root, so such a location renders no
	// alert; uploading it would also publish an internal hostname.
	//
	// This is the reason a correlated DAST finding is dropped even though it
	// carries research/18's `startLine: 1` placeholder region.
	GitHubDropLocationNotRepoRelative GitHubDropReason = "location_not_repo_relative"

	// GitHubDropNoStartLine: the primary location is a repository file but
	// its region has no positive `startLine`. GitHub requires one.
	GitHubDropNoStartLine GitHubDropReason = "no_start_line"

	// GitHubDropNoPrimaryLocationLineHash: `partialFingerprints` does not
	// carry PartialFingerprintPrimaryLocationLineHash, the only partial
	// fingerprint GitHub reads. Uploading without it makes GitHub mint a
	// duplicate alert on every scan, so the result is withheld instead.
	//
	// A projection in which EVERY result carries this reason is the visible
	// form of the unresolved producer question described in this file's
	// header. See CRITIQUE-01 MAJOR 3.
	GitHubDropNoPrimaryLocationLineHash GitHubDropReason = "no_primary_location_line_hash"

	// GitHubDropNoMessageText: `message.text` is empty or blank. GitHub
	// requires it, and an alert with no text is not worth an upload slot.
	GitHubDropNoMessageText GitHubDropReason = "no_message_text"

	// GitHubDropExceedsFileSizeCap: this single result, alone in a file,
	// still exceeds GitHubMaxGzipBytes. It cannot be sharded any further,
	// so it is dropped rather than being permitted to break the cap.
	GitHubDropExceedsFileSizeCap GitHubDropReason = "exceeds_file_size_cap"
)

// GitHubDropReasonValues returns every drop reason, in evaluation order.
// The order is meaningful: a result that fails several checks is recorded
// under the FIRST reason in this slice that it fails, so the reported reason
// is deterministic and does not depend on struct traversal order.
func GitHubDropReasonValues() []GitHubDropReason {
	return []GitHubDropReason{
		GitHubDropHalfNotReadable,
		GitHubDropNoLocations,
		GitHubDropNoPhysicalLocation,
		GitHubDropLocationNotRepoRelative,
		GitHubDropNoStartLine,
		GitHubDropNoPrimaryLocationLineHash,
		GitHubDropNoMessageText,
		GitHubDropExceedsFileSizeCap,
	}
}

// Valid reports whether r is a member of the closed drop vocabulary.
func (r GitHubDropReason) Valid() bool { return inEnum(r, GitHubDropReasonValues()) }

// Explain returns the GitHub rule that forces this drop, so a consumer asking
// "why was this not uploaded" gets the external constraint and not just a
// token.
func (r GitHubDropReason) Explain() string {
	switch r {
	case GitHubDropHalfNotReadable:
		return "this half has not passed Anvil's read gate (anvil/status is not \"" + string(HalfStatusSealed) +
			"\", or the audit has expired); §6 G5 makes that gate hard, and provisional or withdrawn " +
			"findings must not reach a third-party alert feed"
	case GitHubDropNoLocations:
		return "GitHub requires locations[] on every result; this result has none"
	case GitHubDropNoPhysicalLocation:
		return "GitHub renders alerts from locations[0].physicalLocation; this result's primary location has none"
	case GitHubDropLocationNotRepoRelative:
		return "GitHub resolves artifactLocation.uri against the repository root; an absolute URI or path (a DAST endpoint or a host file) resolves to no file and cannot render"
	case GitHubDropNoStartLine:
		return "GitHub requires region.startLine on the primary location"
	case GitHubDropNoPrimaryLocationLineHash:
		return "GitHub de-duplicates alerts using only partialFingerprints." +
			PartialFingerprintPrimaryLocationLineHash +
			"; without it every scan mints duplicate alerts, so the result is withheld"
	case GitHubDropNoMessageText:
		return "GitHub requires message.text on every result"
	case GitHubDropExceedsFileSizeCap:
		return fmt.Sprintf("this single result alone exceeds GitHub's %d-byte gzip file limit and cannot be sharded further",
			GitHubMaxGzipBytes)
	}
	return "unknown drop reason"
}

// ---------------------------------------------------------------------------
// Loss vocabulary — what was removed from results that DID reach GitHub
// ---------------------------------------------------------------------------

// GitHubStripReason names every field-level loss. A stripped field means the
// alert exists on GitHub but carries less than the record does; the record
// remains the audit.
type GitHubStripReason string

const (
	// GitHubStripWebRequest / GitHubStripWebResponse: SARIF §3.27.14/15, the
	// DAST evidence slots. Outside GitHub's supported-property list, and the
	// response body is the highest-risk field in the record
	// (plan/00-SPINE.md S7) — there is no reason to ship it to a third party
	// that will not display it.
	GitHubStripWebRequest  GitHubStripReason = "web_request"
	GitHubStripWebResponse GitHubStripReason = "web_response"

	// GitHubStripRunTaxonomies / GitHubStripResultTaxa /
	// GitHubStripRuleRelationships / GitHubStripDriverTaxa: the
	// taxonomies-as-relationships mechanism (CWE). Unsupported by GitHub,
	// and the three parts are stripped TOGETHER because result.taxa and
	// rule.relationships reference run.taxonomies by index — keeping either
	// without the array would emit a dangling index.
	GitHubStripRunTaxonomies     GitHubStripReason = "run_taxonomies"
	GitHubStripResultTaxa        GitHubStripReason = "result_taxa"
	GitHubStripRuleRelationships GitHubStripReason = "rule_relationships"
	GitHubStripDriverTaxa        GitHubStripReason = "driver_taxa"

	// GitHubStripResultProvenance: SARIF §3.48 regression history.
	// Unsupported by GitHub; Anvil's own store is the regression record.
	GitHubStripResultProvenance GitHubStripReason = "result_provenance"

	// GitHubStripResultFixes: SARIF §3.27.30 proposed patches. Withheld
	// deliberately: plan/00-SPINE.md S7 is "Never auto-merge. Propose only",
	// and a fix rendered in a third-party UI as an accept-here button is not
	// the proposal path Anvil owns.
	GitHubStripResultFixes GitHubStripReason = "result_fixes"

	// GitHubStripAuditProperties / GitHubStripRunProperties /
	// GitHubStripResultProperties / GitHubStripLocationProperties: the
	// `anvil/*` bags. Structurally impossible to emit — the projected types
	// have no properties member — and counted here so the loss is visible
	// rather than merely absent.
	GitHubStripAuditProperties    GitHubStripReason = "audit_anvil_properties"
	GitHubStripRunProperties      GitHubStripReason = "run_anvil_properties"
	GitHubStripResultProperties   GitHubStripReason = "result_anvil_properties"
	GitHubStripLocationProperties GitHubStripReason = "location_anvil_properties"

	// GitHubStripExternalPropertyFileReferences: SARIF §3.15. GitHub does
	// not fetch external property files, so leaving the reference in place
	// would advertise results that never arrive.
	GitHubStripExternalPropertyFileReferences GitHubStripReason = "external_property_file_references"

	// GitHubStripPartialFingerprintKey: a partialFingerprints key other than
	// the two identity keys the projection keeps
	// (PartialFingerprintPrimaryLocationLineHash, which GitHub reads, and
	// PartialFingerprintAnvilFindingID, which is what lets a GitHub alert be
	// traced back to a record finding).
	GitHubStripPartialFingerprintKey GitHubStripReason = "partial_fingerprint_key"

	// GitHubStripRelatedLocationNotRepoRelative: a relatedLocation that is
	// not a repository file — typically the cross-half pointer at a DAST
	// endpoint. Dropped for the same reason as a primary endpoint location.
	GitHubStripRelatedLocationNotRepoRelative GitHubStripReason = "related_location_not_repo_relative"

	// GitHubStripSecondaryLocationNotRepoRelative: a NON-primary entry in
	// locations[] that is not a repository file. The primary location is
	// never re-chosen — see the projectResult comment.
	GitHubStripSecondaryLocationNotRepoRelative GitHubStripReason = "secondary_location_not_repo_relative"

	// GitHubStripThreadFlowLocationNotRepoRelative: a code-flow step whose
	// location is not a repository file.
	GitHubStripThreadFlowLocationNotRepoRelative GitHubStripReason = "thread_flow_location_not_repo_relative"

	// GitHubStripCodeFlowEmptied: a code flow every step of which was
	// stripped. An empty threadFlow is not valid SARIF, so the flow goes.
	GitHubStripCodeFlowEmptied GitHubStripReason = "code_flow_emptied"

	// GitHubStripLocationsOverCap / GitHubStripThreadFlowLocationsOverCap:
	// truncation forced by GitHubMaxLocationsPerResult and
	// GitHubMaxThreadFlowLocationsPerResult. Counted in LOCATIONS removed,
	// not results.
	GitHubStripLocationsOverCap           GitHubStripReason = "locations_over_cap"
	GitHubStripThreadFlowLocationsOverCap GitHubStripReason = "thread_flow_locations_over_cap"

	// GitHubStripUnreferencedRule: a rule descriptor that NO shard of its
	// source run delivers, because no surviving result anywhere in that run
	// references it. Dropping it is what keeps GitHubMaxRulesPerRun
	// unreachable and the file small.
	//
	// Counted against the SHARD SET, once per source run — never per shard.
	// See tallyRuleLoss.
	GitHubStripUnreferencedRule GitHubStripReason = "unreferenced_rule"

	// GitHubStripDuplicateRule: a second `reportingDescriptor` for a rule id
	// already emitted. SARIF's rule array is a set keyed by id, so the
	// duplicate cannot be carried; it was previously dropped with no tally at
	// all, which made it the one silent loss in this file.
	GitHubStripDuplicateRule GitHubStripReason = "duplicate_rule_descriptor"

	// GitHubStripRunGUIDOnShard: `automationDetails.guid` cleared on the
	// second and later shards of one run, because a guid identifies a single
	// run object.
	GitHubStripRunGUIDOnShard GitHubStripReason = "run_guid_cleared_on_shard"
)

// GitHubStripReasonValues returns every strip reason, in a fixed order that
// Summary uses so its output is byte-stable.
func GitHubStripReasonValues() []GitHubStripReason {
	return []GitHubStripReason{
		GitHubStripWebRequest,
		GitHubStripWebResponse,
		GitHubStripRunTaxonomies,
		GitHubStripResultTaxa,
		GitHubStripRuleRelationships,
		GitHubStripDriverTaxa,
		GitHubStripResultProvenance,
		GitHubStripResultFixes,
		GitHubStripAuditProperties,
		GitHubStripRunProperties,
		GitHubStripResultProperties,
		GitHubStripLocationProperties,
		GitHubStripExternalPropertyFileReferences,
		GitHubStripPartialFingerprintKey,
		GitHubStripRelatedLocationNotRepoRelative,
		GitHubStripSecondaryLocationNotRepoRelative,
		GitHubStripThreadFlowLocationNotRepoRelative,
		GitHubStripCodeFlowEmptied,
		GitHubStripLocationsOverCap,
		GitHubStripThreadFlowLocationsOverCap,
		GitHubStripUnreferencedRule,
		GitHubStripDuplicateRule,
		GitHubStripRunGUIDOnShard,
	}
}

// Valid reports whether r is a member of the closed strip vocabulary.
func (r GitHubStripReason) Valid() bool { return inEnum(r, GitHubStripReasonValues()) }

// ---------------------------------------------------------------------------
// The loss ledger
// ---------------------------------------------------------------------------

// GitHubDroppedResult identifies one result that never reached GitHub.
//
// It carries the record-local FindingID deliberately: without it, "we dropped
// 412 results" is unactionable, and the anvil/* bag that would otherwise
// answer "which ones" is exactly what the projection strips.
type GitHubDroppedResult struct {
	// SourceRunIndex and SourceResultIndex locate the result in the INPUT
	// SARIFLog, so a consumer can go back to the record and read it.
	SourceRunIndex    int `json:"sourceRunIndex"`
	SourceResultIndex int `json:"sourceResultIndex"`

	FindingID string `json:"findingId"`
	RuleID    string `json:"ruleId,omitempty"`

	// Half is the frozen anvil/half literal of the producing run.
	Half Half `json:"half"`

	// HalfStatus and AuditState are the two inputs to the read gate, recorded
	// on every drop so a reader of the ledger can tell "this half never
	// sealed" from "the audit expired holding a sealed half" without going
	// back to the record. Both are frozen enum literals.
	HalfStatus HalfStatus `json:"halfStatus,omitempty"`
	AuditState State      `json:"auditState,omitempty"`

	Reason GitHubDropReason `json:"reason"`
}

// GitHubProjectionLoss is the complete, enumerable account of what the
// projection discarded. One ledger describes one whole ProjectForGitHub call;
// every returned file points at the SAME ledger object, so files[0].Loss is
// the whole answer and the ledger is not sliced up per file.
//
// It is JSON-serialisable on purpose: the intended use is that the uploader
// persists it next to the upload, so "GitHub shows 12 alerts and the audit
// found 31" is answerable months later.
type GitHubProjectionLoss struct {
	// AuditID is anvil/auditId, copied from the record being projected.
	AuditID string `json:"auditId"`

	// SourceResultCount and ProjectedResultCount are the two numbers whose
	// difference this ledger explains.
	SourceResultCount    int `json:"sourceResultCount"`
	ProjectedResultCount int `json:"projectedResultCount"`

	// DroppedResults is TOTAL — one entry per dropped result, never
	// truncated or sampled. A ledger that summarised itself would reproduce
	// the failure it exists to prevent.
	DroppedResults []GitHubDroppedResult `json:"droppedResults"`

	// DropCounts and StripCounts are the aggregate view. DropCounts is
	// derivable from DroppedResults; it is materialised because the common
	// question is a count, and recomputing it invites a second, disagreeing
	// implementation of the aggregation.
	DropCounts  map[GitHubDropReason]int  `json:"dropCounts"`
	StripCounts map[GitHubStripReason]int `json:"stripCounts"`
}

func newGitHubProjectionLoss(auditID string) *GitHubProjectionLoss {
	return &GitHubProjectionLoss{
		AuditID:     auditID,
		DropCounts:  map[GitHubDropReason]int{},
		StripCounts: map[GitHubStripReason]int{},
	}
}

func (l *GitHubProjectionLoss) dropResult(d GitHubDroppedResult) {
	l.DroppedResults = append(l.DroppedResults, d)
	l.DropCounts[d.Reason]++
}

func (l *GitHubProjectionLoss) strip(r GitHubStripReason, n int) {
	if n <= 0 {
		return
	}
	l.StripCounts[r] += n
}

// TotalDropped returns the number of results withheld from GitHub.
func (l *GitHubProjectionLoss) TotalDropped() int { return len(l.DroppedResults) }

// DroppedFor returns every result dropped for one reason, in input order.
// This is the "ask what was dropped and why" entry point.
func (l *GitHubProjectionLoss) DroppedFor(r GitHubDropReason) []GitHubDroppedResult {
	var out []GitHubDroppedResult
	for _, d := range l.DroppedResults {
		if d.Reason == r {
			out = append(out, d)
		}
	}
	return out
}

// Summary renders the ledger as deterministic, loggable text: reasons in
// GitHubDropReasonValues / GitHubStripReasonValues order, zero counts
// omitted. Map iteration order never reaches the output.
//
// This is what satisfies "excluded with a LOGGED count rather than silently
// dropped": the caller logs this string, and the counts in it are the ones a
// human is owed when GitHub shows fewer alerts than the audit found.
func (l *GitHubProjectionLoss) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "github projection loss for audit %q: %d source results, %d projected, %d dropped\n",
		l.AuditID, l.SourceResultCount, l.ProjectedResultCount, l.TotalDropped())

	b.WriteString("  dropped results (whole results GitHub never receives):\n")
	anyDrop := false
	for _, r := range GitHubDropReasonValues() {
		if n := l.DropCounts[r]; n > 0 {
			anyDrop = true
			fmt.Fprintf(&b, "    %-32s %6d  — %s\n", r, n, r.Explain())
		}
	}
	if !anyDrop {
		b.WriteString("    (none)\n")
	}

	b.WriteString("  stripped fields (results GitHub receives, with less than the record holds):\n")
	anyStrip := false
	for _, r := range GitHubStripReasonValues() {
		if n := l.StripCounts[r]; n > 0 {
			anyStrip = true
			fmt.Fprintf(&b, "    %-32s %6d\n", r, n)
		}
	}
	if !anyStrip {
		b.WriteString("    (none)\n")
	}
	return b.String()
}

// GitHubLossOf returns the shared loss ledger carried by a projection's
// files, or nil if there are none. Every file points at the same ledger, so
// any file answers for all of them.
func GitHubLossOf(files []GitHubSarifFile) *GitHubProjectionLoss {
	if len(files) == 0 {
		return nil
	}
	return files[0].Loss
}

// ---------------------------------------------------------------------------
// The projected wire types
//
// These are a strict SUBSET of contract.go's SARIF types with every
// `properties` member removed. They are separate types rather than reused
// ones precisely so that no `anvil/*` bag can be emitted here by accident.
// ---------------------------------------------------------------------------

// GitHubSARIFLog is one uploadable SARIF 2.1.0 file. `$schema` and `version`
// are pinned from the contract's constants: GitHub supports 2.1.0 only.
type GitHubSARIFLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []GitHubRun `json:"runs"`
}

// GitHubRun is one projected run. It carries no `properties`, no
// `taxonomies` and no `externalPropertyFileReferences`.
type GitHubRun struct {
	Tool               Tool                        `json:"tool"`
	AutomationDetails  RunAutomationDetails        `json:"automationDetails"`
	OriginalURIBaseIDs map[string]ArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []GitHubResult              `json:"results"`
}

// GitHubResult is one projected result: SARIF-native fields GitHub documents
// support for, and nothing else.
type GitHubResult struct {
	RuleID          string   `json:"ruleId"`
	RuleIndex       *int     `json:"ruleIndex,omitempty"`
	Kind            Kind     `json:"kind,omitempty"`
	Level           Level    `json:"level,omitempty"`
	Rank            *float64 `json:"rank,omitempty"`
	GUID            string   `json:"guid,omitempty"`
	CorrelationGUID string   `json:"correlationGuid,omitempty"`

	Message          Message          `json:"message"`
	Locations        []GitHubLocation `json:"locations"`
	RelatedLocations []GitHubLocation `json:"relatedLocations,omitempty"`
	CodeFlows        []GitHubCodeFlow `json:"codeFlows,omitempty"`

	// PartialFingerprints carries at most two keys: the one GitHub reads and
	// the one that maps the alert back to a record finding.
	PartialFingerprints map[string]string `json:"partialFingerprints"`

	// srcResultIndex and srcFindingID are unexported and therefore never
	// marshalled. They exist so that a result dropped LATE — during size
	// bisection, long after the filter stage — still produces a ledger entry
	// naming the record finding it came from. Without them the one drop
	// reason that fires after projection would be the one drop reason a
	// consumer could not trace, which is exactly the hole this projection is
	// supposed to close.
	srcResultIndex int
	srcFindingID   string
}

// GitHubLocation is SARIF §3.28 without the `anvil/*` location bag.
type GitHubLocation struct {
	ID               *int              `json:"id,omitempty"`
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
	Message          *Message          `json:"message,omitempty"`
}

// GitHubCodeFlow is SARIF §3.36 with its steps projected.
type GitHubCodeFlow struct {
	Message     *Message           `json:"message,omitempty"`
	ThreadFlows []GitHubThreadFlow `json:"threadFlows"`
}

// GitHubThreadFlow is SARIF §3.37.
type GitHubThreadFlow struct {
	Locations []GitHubThreadFlowLocation `json:"locations"`
}

// GitHubThreadFlowLocation is SARIF §3.38.
type GitHubThreadFlowLocation struct {
	Importance string         `json:"importance,omitempty"`
	Location   GitHubLocation `json:"location"`
}

// ---------------------------------------------------------------------------
// The output file
// ---------------------------------------------------------------------------

// GitHubSarifFile is one shard: a complete, uploadable SARIF file together
// with the bytes that were actually measured against GitHub's caps.
//
// JSON and Gzip are both returned so that the caller uploads EXACTLY what was
// measured. Returning only a byte count would leave the caller free to
// re-compress at a different level and exceed a cap this package promised was
// respected.
type GitHubSarifFile struct {
	// Name is a deterministic, filesystem-safe suggested filename. It is a
	// suggestion: nothing here writes files.
	Name string `json:"name"`

	// Half is the frozen anvil/half literal of the source run this shard
	// came from, so an uploader can label the analysis correctly.
	Half Half `json:"half"`

	// SourceRunIndex is the index of the source run in the input record.
	// ShardIndex is 1-based within that run; ShardCount is the total number
	// of shards that run produced.
	SourceRunIndex int `json:"sourceRunIndex"`
	ShardIndex     int `json:"shardIndex"`
	ShardCount     int `json:"shardCount"`

	// Log is the projected SARIF. JSON is its compact encoding and Gzip is
	// the gzip of exactly those bytes.
	Log  GitHubSARIFLog `json:"-"`
	JSON []byte         `json:"-"`
	Gzip []byte         `json:"-"`

	// ResultCount is len(Log.Runs[0].Results); GzipBytes is len(Gzip).
	// Both are surfaced so a caller can report cap headroom without
	// re-deriving it.
	ResultCount int `json:"resultCount"`
	GzipBytes   int `json:"gzipBytes"`

	// Loss is the WHOLE-PROJECTION ledger, shared by every file of one
	// ProjectForGitHub call. It is not this file's private loss.
	Loss *GitHubProjectionLoss `json:"-"`
}

// WithinCaps re-checks a built file against every documented GitHub cap.
//
// It is not a substitute for building the file correctly; it is the
// independent check that the build was correct, and ProjectForGitHub runs it
// on every file before returning. A cap violation is returned as an error
// rather than logged, because an over-cap file is not a degraded upload — it
// is a rejected one.
func (f *GitHubSarifFile) WithinCaps() error {
	if n := len(f.Log.Runs); n > GitHubMaxRunsPerFile {
		return fmt.Errorf("github projection %q: %d runs exceeds GitHub's %d runs per file",
			f.Name, n, GitHubMaxRunsPerFile)
	}
	if n := len(f.Log.Runs); n > GitHubRunsPerProjectedFile {
		return fmt.Errorf("github projection %q: %d runs exceeds Anvil's own %d-run-per-file shard policy",
			f.Name, n, GitHubRunsPerProjectedFile)
	}
	for i := range f.Log.Runs {
		run := &f.Log.Runs[i]
		if n := len(run.Results); n > GitHubMaxResultsPerRun {
			return fmt.Errorf("github projection %q: run %d has %d results, exceeding GitHub's %d per run",
				f.Name, i, n, GitHubMaxResultsPerRun)
		}
		if n := len(run.Tool.Driver.Rules); n > GitHubMaxRulesPerRun {
			return fmt.Errorf("github projection %q: run %d has %d rules, exceeding GitHub's %d per run",
				f.Name, i, n, GitHubMaxRulesPerRun)
		}
		for j := range run.Results {
			res := &run.Results[j]
			// locations + relatedLocations, together: the independent check
			// has to ask the same question the builder answered, or it
			// certifies a guarantee narrower than the one the file promises.
			// See capLocationPair.
			if n := len(res.Locations) + len(res.RelatedLocations); n > GitHubMaxLocationsPerResult {
				return fmt.Errorf("github projection %q: run %d result %d has %d locations "+
					"(%d locations + %d relatedLocations), exceeding GitHub's %d per result",
					f.Name, i, j, n, len(res.Locations), len(res.RelatedLocations), GitHubMaxLocationsPerResult)
			}
			if n := countThreadFlowLocations(res.CodeFlows); n > GitHubMaxThreadFlowLocationsPerResult {
				return fmt.Errorf("github projection %q: run %d result %d has %d thread-flow locations, exceeding GitHub's %d per result",
					f.Name, i, j, n, GitHubMaxThreadFlowLocationsPerResult)
			}
		}
	}
	if n := len(f.Gzip); n > GitHubMaxGzipBytes {
		return fmt.Errorf("github projection %q: %d gzip bytes exceeds GitHub's %d-byte file limit",
			f.Name, n, GitHubMaxGzipBytes)
	}
	return nil
}

func countThreadFlowLocations(flows []GitHubCodeFlow) int {
	n := 0
	for _, cf := range flows {
		for _, tf := range cf.ThreadFlows {
			n += len(tf.Locations)
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// ProjectForGitHub
// ---------------------------------------------------------------------------

// ProjectForGitHub reduces an Anvil audit record to one or more SARIF files
// GitHub code scanning can accept.
//
// Every returned file satisfies WithinCaps. Every result in every returned
// file has a repository-relative primary code location with a start line and
// a populated PartialFingerprintPrimaryLocationLineHash. Everything the
// projection refused to carry is enumerated in the shared
// GitHubProjectionLoss ledger reachable from any returned file's Loss field
// (or via GitHubLossOf).
//
// One file is emitted per source run even when that run contributed no
// results. That is deliberate on two counts: a zero-result run is a
// meaningful SARIF upload (it tells GitHub the previous scan's alerts for
// that analysis are resolved), and it keeps the loss ledger reachable in the
// exact case where the loss is total — a DAST-only half, where every result
// is dropped and a "no files" return would take the explanation with it.
// Callers that do not want to upload an empty analysis skip files whose
// ResultCount is zero.
//
// It returns an error only when nothing legal can be emitted at all: a
// result-free run whose tool metadata alone exceeds the gzip cap.
func ProjectForGitHub(l *SARIFLog) ([]GitHubSarifFile, error) {
	if l == nil {
		return nil, fmt.Errorf("github projection: nil record")
	}
	// Masking is a PRECONDITION, exactly as it is on readpath.go's Reader.
	// This projection strips every surface MaskRecord covers, so no leak could
	// be demonstrated through it today (CRITIQUE-03 B1 records that as
	// unverified harm) — which is the point: the safety currently rests on the
	// strip list staying exhaustive, and the day a carried field is added,
	// this post-condition is what catches it instead of a third party.
	if err := AssertMasked(l); err != nil {
		return nil, fmt.Errorf("github projection: refusing to project audit %q: %w "+
			"(R.8's masker runs before any sink, and a third-party alert feed is a sink)",
			l.Properties.AuditID, err)
	}
	p := &ghProjector{
		loss:      newGitHubProjectionLoss(l.Properties.AuditID),
		auditSlug: fileSlug(l.Properties.AuditID),
		shardSeq:  map[int]int{},
	}

	// The audit-level anvil/* bag is never carried. Count it once: the bag
	// is always present on a real record, and "the whole envelope was
	// dropped" is part of the honest answer to "what did GitHub not get".
	p.loss.strip(GitHubStripAuditProperties, 1)

	var files []GitHubSarifFile
	for i := range l.Runs {
		src := &l.Runs[i]
		p.loss.strip(GitHubStripRunProperties, 1)
		if len(src.Taxonomies) > 0 {
			p.loss.strip(GitHubStripRunTaxonomies, len(src.Taxonomies))
		}
		if len(src.Tool.Driver.Taxa) > 0 {
			p.loss.strip(GitHubStripDriverTaxa, len(src.Tool.Driver.Taxa))
		}
		if src.ExternalPropertyFileReferences != nil {
			p.loss.strip(GitHubStripExternalPropertyFileReferences, 1)
		}

		kept := p.projectResults(l, src, i)
		runFiles, err := p.shardRun(src, i, kept)
		if err != nil {
			return nil, err
		}
		// The rule ledger is reconciled against the SHARD SET, once per source
		// run, and never per shard. See tallyRuleLoss.
		p.tallyRuleLoss(src, runFiles)
		files = append(files, runFiles...)
	}

	// ShardCount is only knowable once a run is fully sharded.
	counts := map[int]int{}
	for _, f := range files {
		counts[f.SourceRunIndex]++
	}
	for i := range files {
		files[i].ShardCount = counts[files[i].SourceRunIndex]
		files[i].Loss = p.loss
		p.loss.ProjectedResultCount += files[i].ResultCount
		if err := files[i].WithinCaps(); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// ghProjector holds the mutable state of one ProjectForGitHub call. It exists
// so the loss ledger is threaded through every decision by construction: a
// drop that forgot to touch the ledger would have to go out of its way.
type ghProjector struct {
	loss      *GitHubProjectionLoss
	auditSlug string
	// shardSeq maps a source run index to the number of shards emitted for
	// it so far, so shard ids are assigned in emission order.
	shardSeq map[int]int
}

// projectResults filters and projects one run's results, recording a reason
// for every result it refuses.
//
// THE READ GATE RUNS FIRST, AND IT RUNS PER RUN. A run whose half has not
// passed sealing.go's HalfReadGate contributes NO results, and every one of
// them is ledgered under GitHubDropHalfNotReadable — the loss must be
// countable here for the same reason every other refusal is, and CRITIQUE-03
// B1's probe found the ledger recording ZERO drops in every unsealed case, so
// the loss was not merely permitted but invisible.
//
// The gate is called, never re-derived. `src.Properties.Status` is right there
// and `l.Properties.State` is one dereference further away; three of the four
// bypasses sealing.go's header lists were made by reaching for the near one.
func (p *ghProjector) projectResults(l *SARIFLog, src *Run, srcRunIdx int) []GitHubResult {
	half := src.Properties.Half
	seal := halfSealOfRun(l, src)
	gateErr := HalfReadGate(l.Properties.AuditID, seal)

	kept := make([]GitHubResult, 0, len(src.Results))
	for j := range src.Results {
		p.loss.SourceResultCount++
		res := &src.Results[j]
		entry := GitHubDroppedResult{
			SourceRunIndex:    srcRunIdx,
			SourceResultIndex: j,
			FindingID:         res.Properties.FindingID,
			RuleID:            res.RuleID,
			Half:              half,
			HalfStatus:        seal.Status,
			AuditState:        seal.AuditState,
		}
		if gateErr != nil {
			entry.Reason = GitHubDropHalfNotReadable
			p.loss.dropResult(entry)
			continue
		}
		gr, reason, ok := p.projectResult(res)
		if !ok {
			entry.Reason = reason
			p.loss.dropResult(entry)
			continue
		}
		gr.srcResultIndex = j
		gr.srcFindingID = res.Properties.FindingID
		kept = append(kept, gr)
	}
	return kept
}

// projectResult applies the drop rules in GitHubDropReasonValues order and,
// for a surviving result, strips every unsupported field.
//
// THE PRIMARY LOCATION IS NEVER RE-CHOSEN. If locations[0] is not a
// repository code location the result is dropped, even when a later entry in
// locations[] is one. The reason is identity: primaryLocationLineHash was
// computed against the record's PRIMARY location, so promoting locations[1]
// would upload a fingerprint that describes a different line than the alert
// it is attached to, and GitHub's de-duplication would key on the mismatch
// forever.
func (p *ghProjector) projectResult(r *Result) (GitHubResult, GitHubDropReason, bool) {
	if len(r.Locations) == 0 {
		return GitHubResult{}, GitHubDropNoLocations, false
	}
	primary := r.Locations[0]
	if primary.PhysicalLocation == nil {
		return GitHubResult{}, GitHubDropNoPhysicalLocation, false
	}
	if !isRepoRelativeURI(primary.PhysicalLocation.ArtifactLocation.URI) {
		return GitHubResult{}, GitHubDropLocationNotRepoRelative, false
	}
	if primary.PhysicalLocation.Region == nil || primary.PhysicalLocation.Region.StartLine <= 0 {
		return GitHubResult{}, GitHubDropNoStartLine, false
	}
	if r.PartialFingerprints[PartialFingerprintPrimaryLocationLineHash] == "" {
		return GitHubResult{}, GitHubDropNoPrimaryLocationLineHash, false
	}
	if strings.TrimSpace(r.Message.Text) == "" {
		return GitHubResult{}, GitHubDropNoMessageText, false
	}

	// From here the result is kept; everything below is field-level loss.
	p.loss.strip(GitHubStripResultProperties, 1)
	if r.WebRequest != nil {
		p.loss.strip(GitHubStripWebRequest, 1)
	}
	if r.WebResponse != nil {
		p.loss.strip(GitHubStripWebResponse, 1)
	}
	if len(r.Taxa) > 0 {
		p.loss.strip(GitHubStripResultTaxa, len(r.Taxa))
	}
	if r.Provenance != nil {
		p.loss.strip(GitHubStripResultProvenance, 1)
	}
	if len(r.Fixes) > 0 {
		p.loss.strip(GitHubStripResultFixes, len(r.Fixes))
	}

	out := GitHubResult{
		RuleID:              r.RuleID,
		Kind:                r.Kind,
		Level:               r.Level,
		Rank:                r.Rank,
		GUID:                r.GUID,
		CorrelationGUID:     r.CorrelationGUID,
		Message:             r.Message,
		PartialFingerprints: p.projectPartialFingerprints(r.PartialFingerprints),
	}

	// locations[0] is kept as-is; later entries survive only if they are
	// repository files too.
	out.Locations = append(out.Locations, p.projectLocation(primary))
	for _, loc := range r.Locations[1:] {
		if !isRepoCodeLocation(loc) {
			p.loss.strip(GitHubStripSecondaryLocationNotRepoRelative, 1)
			continue
		}
		out.Locations = append(out.Locations, p.projectLocation(loc))
	}

	for _, loc := range r.RelatedLocations {
		if !isRepoCodeLocation(loc) {
			p.loss.strip(GitHubStripRelatedLocationNotRepoRelative, 1)
			continue
		}
		out.RelatedLocations = append(out.RelatedLocations, p.projectLocation(loc))
	}

	// THE CAP IS ON THE PAIR. See capLocationPair.
	p.capLocationPair(&out)

	out.CodeFlows = p.projectCodeFlows(r.CodeFlows)
	return out, "", true
}

// capLocationPair enforces GitHubMaxLocationsPerResult across `locations` AND
// `relatedLocations` together, filling from `locations` first.
//
// WHY THE PAIR AND NOT EACH ARRAY (CRITIQUE-03 M4). research/18 records the
// limit as "1,000 locations per result (100 displayed)", sourced to [S2], and
// nothing in the tree says whether GitHub counts `relatedLocations` toward
// that figure — the critic could not source it and neither can this file. The
// projection previously truncated `locations` at 1,000 and appended
// `relatedLocations` without limit, so a fan-out finding shipped 4,000
// locations under a cap the file's own header promises "no returned file
// exceeds ... on any input".
//
// Of the two readings, only one is safe under both: capping the pair is
// correct if `relatedLocations` DO count, and merely conservative if they do
// not. An asymmetry that is wrong under one reading is not. If [S2] is ever
// checked and says related locations are exempt, the fix is to relax this
// function with the source quoted next to GitHubMaxLocationsPerResult, with
// the same sourcing rigour every other number in that block has — not to
// re-introduce an unexplained asymmetry.
//
// Both overflows are counted under GitHubStripLocationsOverCap: the strip
// vocabulary answers "what kind of loss", and a truncated location is one kind
// whichever array it sat in.
func (p *ghProjector) capLocationPair(out *GitHubResult) {
	if over := len(out.Locations) - GitHubMaxLocationsPerResult; over > 0 {
		out.Locations = out.Locations[:GitHubMaxLocationsPerResult]
		p.loss.strip(GitHubStripLocationsOverCap, over)
	}
	room := GitHubMaxLocationsPerResult - len(out.Locations)
	if over := len(out.RelatedLocations) - room; over > 0 {
		out.RelatedLocations = out.RelatedLocations[:room]
		p.loss.strip(GitHubStripLocationsOverCap, over)
	}
	if len(out.RelatedLocations) == 0 {
		out.RelatedLocations = nil
	}
}

// projectPartialFingerprints keeps the key GitHub reads and the key that maps
// an alert back to a record finding, and counts the rest.
func (p *ghProjector) projectPartialFingerprints(in map[string]string) map[string]string {
	out := make(map[string]string, 2)
	for k, v := range in {
		switch k {
		case PartialFingerprintPrimaryLocationLineHash, PartialFingerprintAnvilFindingID:
			if v != "" {
				out[k] = v
			}
		default:
			p.loss.strip(GitHubStripPartialFingerprintKey, 1)
		}
	}
	return out
}

func (p *ghProjector) projectLocation(loc Location) GitHubLocation {
	if len(loc.Properties) > 0 {
		p.loss.strip(GitHubStripLocationProperties, 1)
	}
	out := GitHubLocation{
		ID:               loc.ID,
		LogicalLocations: loc.LogicalLocations,
		Message:          loc.Message,
	}
	if loc.PhysicalLocation != nil {
		pl := *loc.PhysicalLocation
		out.PhysicalLocation = &pl
	}
	return out
}

// projectCodeFlows keeps GitHub-renderable taint paths, dropping steps that
// are not repository files and flows that end up empty. The per-result
// thread-flow cap is applied across the whole result, which is how GitHub
// counts it.
func (p *ghProjector) projectCodeFlows(flows []CodeFlow) []GitHubCodeFlow {
	var out []GitHubCodeFlow
	budget := GitHubMaxThreadFlowLocationsPerResult
	for _, cf := range flows {
		var gcf GitHubCodeFlow
		gcf.Message = cf.Message
		for _, tf := range cf.ThreadFlows {
			var gtf GitHubThreadFlow
			for _, tfl := range tf.Locations {
				if !isRepoCodeLocation(tfl.Location) {
					p.loss.strip(GitHubStripThreadFlowLocationNotRepoRelative, 1)
					continue
				}
				if budget <= 0 {
					p.loss.strip(GitHubStripThreadFlowLocationsOverCap, 1)
					continue
				}
				budget--
				gtf.Locations = append(gtf.Locations, GitHubThreadFlowLocation{
					Importance: tfl.Importance,
					Location:   p.projectLocation(tfl.Location),
				})
			}
			if len(gtf.Locations) == 0 {
				continue
			}
			gcf.ThreadFlows = append(gcf.ThreadFlows, gtf)
		}
		if len(gcf.ThreadFlows) == 0 {
			p.loss.strip(GitHubStripCodeFlowEmptied, 1)
			continue
		}
		out = append(out, gcf)
	}
	return out
}

// ---------------------------------------------------------------------------
// Location predicates
// ---------------------------------------------------------------------------

// isRepoCodeLocation reports whether a location is something GitHub can
// render as a code-scanning alert: a repository-relative artifact with a
// positive start line.
func isRepoCodeLocation(loc Location) bool {
	pl := loc.PhysicalLocation
	if pl == nil || pl.Region == nil || pl.Region.StartLine <= 0 {
		return false
	}
	return isRepoRelativeURI(pl.ArtifactLocation.URI)
}

// isRepoRelativeURI reports whether uri can resolve to a file inside the
// repository GitHub is uploading against.
//
// It rejects, in order: the empty string; absolute POSIX and Windows-style
// paths; anything carrying a URI scheme (`https:`, `file:`, and also `C:` —
// a Windows drive letter is syntactically a scheme, and rejecting it is the
// correct outcome either way); and any path with a `..` segment, which cannot
// be guaranteed to stay inside the repository root.
//
// Note what it deliberately does NOT consult: `location.properties`
// ["anvil/locationKind"]. That key has no frozen enum in R.1's contract, so
// depending on its literals here would create a vocabulary this file
// half-owns — the exact pattern §6 closed ten defects over. The URI shape is
// self-contained and needs no shared vocabulary.
func isRepoRelativeURI(uri string) bool {
	if uri == "" {
		return false
	}
	if strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, `\`) {
		return false
	}
	if hasURIScheme(uri) {
		return false
	}
	for _, seg := range strings.Split(strings.ReplaceAll(uri, `\`, "/"), "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// hasURIScheme reports whether s begins with an RFC 3986 scheme followed by
// ':'.
func hasURIScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' {
			return i > 0
		}
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 {
			if !alpha {
				return false
			}
			continue
		}
		digit := c >= '0' && c <= '9'
		if !alpha && !digit && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Sharding
// ---------------------------------------------------------------------------

// shardRun splits one run's projected results into files that each satisfy
// every cap, and guarantees at least one file per source run.
func (p *ghProjector) shardRun(src *Run, srcRunIdx int, results []GitHubResult) ([]GitHubSarifFile, error) {
	var out []GitHubSarifFile
	if err := p.shard(src, srcRunIdx, results, &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		// Every result was dropped for size. Emit the empty run anyway so
		// the loss is still attached to something the caller receives.
		f, fits, tally, err := p.tryBuild(src, srcRunIdx, nil)
		if err != nil {
			return nil, err
		}
		if !fits {
			return nil, fmt.Errorf(
				"github projection: run %d has no results and still exceeds GitHub's %d-byte gzip limit (%d bytes); "+
					"the tool metadata alone cannot be uploaded", srcRunIdx, GitHubMaxGzipBytes, len(f.Gzip))
		}
		p.commit(tally)
		p.shardSeq[srcRunIdx] = f.ShardIndex
		out = append(out, f)
	}
	return out, nil
}

// shard emits files for results, splitting until every part fits.
//
// The count cap is applied first and greedily, so a run of 25,001 results
// yields a full 25,000-result shard and a 1-result shard rather than two
// half-full ones. The size cap is then applied by bisection, which
// terminates: each step halves the slice, and a single result that still does
// not fit is dropped with GitHubDropExceedsFileSizeCap.
//
// # The bisection re-marshals and re-gzips discarded candidates, deliberately
//
// CRITIQUE-03 m4: a run needing k size splits does O(n log n) bytes of
// gzip.BestCompression work near the 10 MB boundary. That is real, and it is
// KEPT, because the two obvious remedies both weaken the guarantee this file
// exists to make:
//
//   - estimating the split point from the uncompressed size makes the split
//     depend on a compression ratio nobody measured, so a mis-estimate turns
//     into an extra round of bisection anyway and buys nothing on the
//     pathological inputs;
//   - probing at a cheap gzip level and re-compressing the keeper at
//     BestCompression means the bytes that decided the split are not the bytes
//     that ship. GitHubSarifFile returns Gzip precisely so the caller uploads
//     exactly what was measured; measuring one artefact and shipping another
//     is the shape of cap guarantee that is false in the field and true in the
//     test.
//
// The count cap runs first and bounds every candidate at 25,000 results, so
// the bisection only engages when 25,000 results still exceed 10 MB gzipped —
// which needs roughly 400 bytes of incompressible payload per result. If that
// ever becomes a routine shape rather than a pathological one, the fix is to
// shard on a running uncompressed-size estimate BEFORE the first build, not to
// make the measured bytes and the shipped bytes two different things.
func (p *ghProjector) shard(src *Run, srcRunIdx int, results []GitHubResult, out *[]GitHubSarifFile) error {
	if len(results) > GitHubMaxResultsPerRun {
		if err := p.shard(src, srcRunIdx, results[:GitHubMaxResultsPerRun], out); err != nil {
			return err
		}
		return p.shard(src, srcRunIdx, results[GitHubMaxResultsPerRun:], out)
	}

	f, fits, tally, err := p.tryBuild(src, srcRunIdx, results)
	if err != nil {
		return err
	}
	if fits {
		p.commit(tally)
		p.shardSeq[srcRunIdx] = f.ShardIndex
		*out = append(*out, f)
		return nil
	}
	if len(results) == 0 {
		return fmt.Errorf(
			"github projection: run %d has no results and still exceeds GitHub's %d-byte gzip limit (%d bytes)",
			srcRunIdx, GitHubMaxGzipBytes, len(f.Gzip))
	}
	if len(results) == 1 {
		p.loss.dropResult(GitHubDroppedResult{
			SourceRunIndex:    srcRunIdx,
			SourceResultIndex: results[0].srcResultIndex,
			FindingID:         results[0].srcFindingID,
			RuleID:            results[0].RuleID,
			Half:              src.Properties.Half,
			Reason:            GitHubDropExceedsFileSizeCap,
		})
		return nil
	}
	mid := len(results) / 2
	if err := p.shard(src, srcRunIdx, results[:mid], out); err != nil {
		return err
	}
	return p.shard(src, srcRunIdx, results[mid:], out)
}

// ghStripTally accumulates the field-level loss of ONE candidate shard.
//
// It exists because tryBuild is speculative: a candidate that does not fit is
// discarded and re-split, and a candidate's strips must not reach the ledger
// unless that candidate is kept. Counting them directly would inflate every
// strip count by the number of failed bisection attempts — a ledger that
// over-reports loss is as untrustworthy as one that under-reports it.
type ghStripTally map[GitHubStripReason]int

func (t ghStripTally) add(r GitHubStripReason, n int) {
	if n > 0 {
		t[r] += n
	}
}

// commit folds a KEPT candidate's strips into the projection ledger.
func (p *ghProjector) commit(t ghStripTally) {
	for r, n := range t {
		p.loss.strip(r, n)
	}
}

// tryBuild assembles, marshals and compresses one candidate file. It reports
// whether the file is within the gzip cap; the caller either keeps it (and
// commits the returned tally) or splits and discards it. The compressed bytes
// are produced here and kept, so a file is never compressed twice and what
// was measured is what is returned.
func (p *ghProjector) tryBuild(src *Run, srcRunIdx int, results []GitHubResult) (GitHubSarifFile, bool, ghStripTally, error) {
	shardIdx := p.shardSeq[srcRunIdx] + 1
	tally := ghStripTally{}

	rules, ruleIndex := projectRules(src.Tool.Driver.Rules, results)
	// Re-point each result at its rule's index in THIS shard's rule array.
	// The source index is meaningless after filtering, and a stale ruleIndex
	// is worse than none: it names a different rule.
	shardResults := make([]GitHubResult, len(results))
	copy(shardResults, results)
	for i := range shardResults {
		if idx, ok := ruleIndex[shardResults[i].RuleID]; ok {
			n := idx
			shardResults[i].RuleIndex = &n
		} else {
			shardResults[i].RuleIndex = nil
		}
	}

	driver := src.Tool.Driver
	driver.Rules = rules
	driver.Taxa = nil

	auto := src.AutomationDetails
	if shardIdx > 1 {
		auto.ID = shardAutomationID(auto.ID, shardIdx)
		if auto.GUID != "" {
			auto.GUID = ""
			tally.add(GitHubStripRunGUIDOnShard, 1)
		}
	}

	run := GitHubRun{
		Tool:               Tool{Driver: driver},
		AutomationDetails:  auto,
		OriginalURIBaseIDs: src.OriginalURIBaseIDs,
		Results:            shardResults,
	}
	if run.Results == nil {
		run.Results = []GitHubResult{}
	}

	log := GitHubSARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs:    []GitHubRun{run},
	}
	raw, err := json.Marshal(&log)
	if err != nil {
		return GitHubSarifFile{}, false, nil, fmt.Errorf("github projection: marshal run %d shard %d: %w", srcRunIdx, shardIdx, err)
	}
	gz, err := gzipBytes(raw)
	if err != nil {
		return GitHubSarifFile{}, false, nil, fmt.Errorf("github projection: gzip run %d shard %d: %w", srcRunIdx, shardIdx, err)
	}

	half := src.Properties.Half
	f := GitHubSarifFile{
		Name:           fmt.Sprintf("anvil-%s-%s-%03d.sarif", p.auditSlug, fileSlug(string(half)), shardIdx),
		Half:           half,
		SourceRunIndex: srcRunIdx,
		ShardIndex:     shardIdx,
		Log:            log,
		JSON:           raw,
		Gzip:           gz,
		ResultCount:    len(shardResults),
		GzipBytes:      len(gz),
	}
	return f, len(gz) <= GitHubMaxGzipBytes, tally, nil
}

// projectRules returns the rule descriptors this shard's results actually
// reference, in source order, with taxonomy relationships stripped, plus the
// ruleId -> new index map.
//
// Emitting only referenced rules is what makes GitHubMaxRulesPerRun
// unreachable: distinct referenced rules can never exceed the shard's result
// count, which is already capped at GitHubMaxResultsPerRun.
//
// IT TALLIES NOTHING. Rule-level loss is a property of the SHARD SET, not of
// one shard, and this function runs once per candidate shard — including the
// candidates bisection throws away. tallyRuleLoss is where the counting
// happens; see it for the whole argument.
func projectRules(src []ReportingDescriptor, results []GitHubResult) ([]ReportingDescriptor, map[string]int) {
	referenced := make(map[string]bool, len(results))
	for i := range results {
		referenced[results[i].RuleID] = true
	}
	out := make([]ReportingDescriptor, 0, len(referenced))
	index := make(map[string]int, len(referenced))
	for _, rule := range src {
		if !referenced[rule.ID] {
			continue
		}
		if _, dup := index[rule.ID]; dup {
			continue
		}
		if len(rule.Relationships) > 0 {
			rule.Relationships = nil
		}
		index[rule.ID] = len(out)
		out = append(out, rule)
	}
	if len(out) == 0 {
		return nil, index
	}
	return out, index
}

// tallyRuleLoss reconciles one SOURCE RUN's rule descriptors against the rules
// its shards actually deliver, and is the only place rule-level loss reaches
// the ledger.
//
// # Why this is not per shard (CRITIQUE-03 M2)
//
// projectRules used to count GitHubStripUnreferencedRule for every rule not
// referenced by the shard being built. A rule referenced only by shard 2 was
// therefore counted as "stripped" while shard 1 was assembled, even though it
// IS delivered to GitHub in shard 2. The probe: 25,010 results across two
// shards, four rules in the source run, two of them genuinely lost — and a
// ledger reading 6. Six exceeds the four rules that exist, which is by itself
// proof the number counted nothing real, and it scaled with shard count, so it
// was worst on exactly the large audits the ledger exists for.
//
// That contradicts ghStripTally's own stated principle — "a ledger that
// over-reports loss is as untrustworthy as one that under-reports it" — and
// the ledger is the whole mechanism by which R.14 answers research/18 Risk #6.
// A number a reader learns to discount is worse than no number.
//
// GitHubStripRuleRelationships moves here for the same reason: one source
// descriptor's relationships are one loss however many shards carry the rule.
//
// GitHubStripDuplicateRule closes the file's one remaining silent drop: a
// second descriptor for an id already emitted was skipped with no tally at
// all.
//
// A per-shard rule COUNT, if anyone ever wants one, belongs on
// GitHubSarifFile — not in the shared ledger, which describes the projection.
func (p *ghProjector) tallyRuleLoss(src *Run, files []GitHubSarifFile) {
	delivered := map[string]bool{}
	for i := range files {
		for j := range files[i].Log.Runs {
			for _, rule := range files[i].Log.Runs[j].Tool.Driver.Rules {
				delivered[rule.ID] = true
			}
		}
	}

	seen := map[string]bool{}
	for _, rule := range src.Tool.Driver.Rules {
		if seen[rule.ID] {
			p.loss.strip(GitHubStripDuplicateRule, 1)
			continue
		}
		seen[rule.ID] = true
		if !delivered[rule.ID] {
			p.loss.strip(GitHubStripUnreferencedRule, 1)
			continue
		}
		if n := len(rule.Relationships); n > 0 {
			p.loss.strip(GitHubStripRuleRelationships, n)
		}
	}
}

// shardAutomationID derives a distinct analysis id for shards after the
// first.
//
// GitHub keys an analysis on runAutomationDetails.id, so uploading two shards
// under one id makes the second REPLACE the first. GitHub's convention is
// that the id is a category ending in '/', optionally followed by a run id,
// so the suffix is appended as a further category segment and the trailing
// '/' is preserved.
func shardAutomationID(id string, shardIdx int) string {
	suffix := fmt.Sprintf("shard-%03d/", shardIdx)
	if id == "" {
		return suffix
	}
	if strings.HasSuffix(id, "/") {
		return id + suffix
	}
	return id + "/" + suffix
}

// fileSlug reduces a string to characters that are safe in a filename on
// every platform Anvil builds for, so a suggested name never depends on what
// an audit id happens to contain.
func fileSlug(s string) string {
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// gzipBytes compresses raw at the maximum level. The level matters: these
// exact bytes are what the caller uploads and what was measured against
// GitHubMaxGzipBytes, so measuring at one level and uploading at another
// would make the cap guarantee false.
func gzipBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
