// The three-tier read path the coding agent consumes (step R.13).
//
// # The three tiers, and why they are tiers
//
// research/18-unified-audit-record.md ("Size — the three-tier read path"):
//
//	Tier 0 — Manifest (always read, target <= 8 KB). Audit metadata, per-half
//	         seal status, counts, the deterministic read order, and inverted
//	         indexes. Results are EXTERNALISED, not inlined.
//	Tier 1 — Task cards (the unit the agent actually reads, ~1,500–2,500
//	         tokens each). One self-contained JSON per finding, DERIVED from
//	         the record.
//	Tier 2 — Blobs (fetched on demand, content-addressed by `sha256:` digest).
//	         Full response bodies, long taint paths, whole-file contents.
//
// The tiers exist because a 128k-context coding model that reads the whole
// SARIF record reads nothing else. Tier 0 tells it what exists and in what
// order to work; Tier 1 is what fits in its context; Tier 2 is what it fetches
// only if it turns out to need it.
//
// # Budgets are enforced here, not documented here
//
// MaxTier0ManifestBytes and MaxTier1CardTokens are declared in contract.go.
// This file MEASURES the marshalled bytes and refuses to emit anything over
// budget: over-budget output degrades deterministically by spilling the
// largest optional structures to Tier-2 blobs, in a fixed order, and only an
// EXPLICIT, LOGGED override (Reader.AllowOversizeTier0 /
// .AllowOversizeTier1) may produce an oversized tier. R.13's forbidden
// actions: "Do not exceed the 8KB Tier-0 manifest budget or the
// ~1,500–2,500 token Tier-1 card budget without an explicit, logged override."
//
// Nothing is ever silently dropped. Every shrink step records a Spill naming
// the field and the `sha256:` reference to the bytes that left the tier.
//
// MEASURED, so the limit is a fact rather than a hope: the nine-finding
// fixture in readpath_test.go produces a 3,008-byte manifest, and a
// 409-finding record produces an 8,063-byte manifest — 98% of the budget —
// with all four shrink steps taken, carrying the first 40 card refs inline and
// the remaining 369 behind one Tier-2 reference. The crossover is around fifty
// findings: beyond that the whole materialised read order stops fitting
// alongside the envelope, and the tail (never the head) moves to Tier 2, where
// TierSpill names it, counts it and content-addresses it. The read order is
// never LOST, and it is never RE-DERIVED by the consumer; the part that does
// not fit is fetched.
//
// # The read order is deterministic and is not the model's to choose
//
// DefaultReadOrder() — clusters, then SAST-only by rank, then DAST-only by
// rank — is the only order this file emits. Correlated clusters come first
// because they carry runtime proof; within every bucket the sort is total
// (rank desc, evidence-class strength, finding id) so repeated calls on the
// same input produce byte-identical output.
//
// # Two gates this file will not open
//
//  1. THE READ GATE. A half's results are readable only when its
//     `anvil/status` is HalfStatusSealed (R.6, and IMPLEMENTATION-PLAN.md §6
//     ruling G5: "`sealed` is load-bearing … the hard read gate") AND the
//     audit has not expired. BOTH ARMS, ASKED IN ONE PLACE: this file calls
//     sealing.go's HalfReadGate and never re-derives readability from
//     `run.Properties.Status`. See sealing.go's read-gate section for the four
//     separate bypasses that made that rule necessary.
//
//     Cards are built only from readable halves. The manifest still REPORTS
//     the unreadable half — count, status and the gate's own refusal reason —
//     because a consumer that cannot see the half exists is a consumer that
//     reads "no DAST findings" as "no dynamic vulnerabilities", which is
//     research/23 Risk #1.
//
//  2. THE HOST GATE. plan/00-SPINE.md S7 makes the host agent read-only, "no
//     package manager in a mutating mode, not behind a flag", so
//     `remediable_by_agent` is false for every host finding
//     (IMPLEMENTATION-PLAN.md §6, S7). contract.go's validator enforces that
//     on the RECORD. This file enforces it again on the READ PATH, because
//     the record's validator is the producer's gate and a card is what the
//     agent actually receives: a host finding is never handed out as
//     actionable, even if a malformed record claims it is.
//
// # Masking is a precondition
//
// BuildTaskCards refuses a record that has not been through R.8's masker.
// plan/00-SPINE.md S7 names the DAST response body "the highest-risk field —
// up to 32 KB of attacker-controlled bytes fed to a repo-credentialed agent",
// and the read path is precisely the step that does the feeding.
//
// Sources: research/18-unified-audit-record.md ("Size — the three-tier read
// path", the annotated Tier-1 task card); research/24-coding-agent-consumption
// .md ("What the audit record must carry"); plan/40-record-and-storage.md
// (R.13); plan/00-SPINE.md S1, S6, S7.
package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Budgets and the token approximation
// ---------------------------------------------------------------------------

// ApproxBytesPerToken is the byte-to-token ratio this package uses to measure
// a task card against MaxTier1CardTokens.
//
// It is DELIBERATELY PESSIMISTIC. research/18 records the budget as an
// estimate rather than a measurement ("Token budget for task cards is an
// estimate, not a measurement"), and R.13's expected output schema asks for
// "a token-count approximation, not a hard requirement on an exact
// tokenizer". Real BPE tokenizers land between 3 and 4 bytes per token on
// dense JSON carrying source code; choosing 3 means this package's count is an
// UPPER bound on every mainstream tokenizer, so a card that passes here passes
// on the real one. Choosing 4 would have made the check optimistic, which is
// the failure mode that matters: an under-counted card silently blows the
// agent's context and the run degrades with no error anywhere.
const ApproxBytesPerToken = 3

// MaxTier1CardBytes is MaxTier1CardTokens expressed in bytes at
// ApproxBytesPerToken. It lands at 7,500 bytes, just under research/18's
// independent "target <= 8 KB each" figure for the same object — the two
// numbers were derived from different sides of the same budget and agree,
// which is the only reason to trust either.
const MaxTier1CardBytes = MaxTier1CardTokens * ApproxBytesPerToken

// MaxAdvisoryExcerptBytes is research/24's "<=800 tokens" advisory-excerpt cap
// in bytes at the same ratio.
const MaxAdvisoryExcerptBytes = MaxAdvisoryExcerptTokens * ApproxBytesPerToken

// CardVersion is the task-card shape version, `cardVersion` in research/18's
// annotated card. It is NOT the record's SchemaVersion: a card is derived, and
// the projection may change shape without the record changing at all.
const CardVersion = "1.0.0"

// Default Tier-1 and Tier-2 path prefixes, written into Index.TaskCards and
// Index.Blobs.
const (
	DefaultTaskCardPrefix = "cards/"
	DefaultBlobPrefix     = "blobs/"
)

// ApproxTokens converts a byte length to the approximate token count this
// package budgets against. See ApproxBytesPerToken for why the ratio is
// pessimistic.
func ApproxTokens(byteLen int) int {
	if byteLen <= 0 {
		return 0
	}
	return (byteLen + ApproxBytesPerToken - 1) / ApproxBytesPerToken
}

// ---------------------------------------------------------------------------
// Sources and sinks
// ---------------------------------------------------------------------------

// RecordSource supplies the assembled, masked record for an audit id.
//
// R.13 depends only on R.1 and R.2, so this file holds no database handle and
// no store import: the store (R.4/R.5) satisfies this interface from the
// outside, and so does a test. The dependency runs from the store to the read
// path, never back.
type RecordSource interface {
	Record(auditID string) (*SARIFLog, error)
}

// RecordSourceFunc adapts a function to RecordSource.
type RecordSourceFunc func(auditID string) (*SARIFLog, error)

// Record implements RecordSource.
func (f RecordSourceFunc) Record(auditID string) (*SARIFLog, error) { return f(auditID) }

// RecordMap is an in-memory RecordSource keyed by audit id.
type RecordMap map[string]*SARIFLog

// Record implements RecordSource.
func (m RecordMap) Record(auditID string) (*SARIFLog, error) {
	l, ok := m[auditID]
	if !ok || l == nil {
		return nil, fmt.Errorf("record: no audit record for audit id %q", auditID)
	}
	return l, nil
}

// BlobSink persists one Tier-2 blob. Ref is the `sha256:<64 hex>` reference
// written into the tier that spilled it.
//
// NewReader ALWAYS installs one (Reader.RetainedBlobs), so the default path
// never produces a spill whose bytes nothing holds. A caller that owns real
// Tier-2 storage replaces it. See Reader.Blobs.
type BlobSink func(ref string, content []byte) error

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// BudgetError reports a tier that could not be brought under its budget by
// spilling, and for which no explicit override was configured.
type BudgetError struct {
	Tier    string // "tier-0 manifest" or "tier-1 task card"
	Subject string // audit id or finding id
	Bytes   int
	Budget  int
	Tokens  int
	MaxTok  int
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf(
		"record: %s for %q is %d bytes (~%d tokens) after every shrink step, over the %d-byte (%d-token) budget; "+
			"set Reader.AllowOversize with a reason to emit it anyway (R.13 requires the override to be explicit and logged)",
		e.Tier, e.Subject, e.Bytes, e.Tokens, e.Budget, e.MaxTok)
}

// ---------------------------------------------------------------------------
// Tier 0 — the manifest
// ---------------------------------------------------------------------------

// Manifest is Tier 0: the first and only thing the coding agent reads before
// it decides what to read next. Target <= MaxTier0ManifestBytes.
//
// It is DERIVED. Nothing here is authoritative; the record is. Where a
// manifest and the record disagree, the record wins and the manifest is a
// stale projection to be rebuilt.
type Manifest struct {
	// ManifestVersion is the shape version of this projection, independent of
	// the record's SchemaVersion.
	ManifestVersion string `json:"manifestVersion"`

	SchemaVersion string `json:"anvil/schemaVersion"`
	AuditID       string `json:"anvil/auditId"`
	State         State  `json:"anvil/state"`
	Version       int    `json:"anvil/version"`
	CreatedAt     string `json:"anvil/createdAt"`

	Target   ManifestTarget `json:"anvil/target"`
	Deadline ManifestClaim  `json:"anvil/deadline"`

	// DastStatus is carried verbatim and is never absent. DynamicallyScanned
	// Clean is DastStatus.MeansDynamicallyScannedClean() precomputed, so a
	// consumer cannot arrive at "no dynamic vulnerabilities" by testing
	// `dastStatus != "completed_findings"` — the naive check research/23
	// Risk #1 exists to prevent.
	DastStatus              DastStatus `json:"anvil/dastStatus"`
	DynamicallyScannedClean bool       `json:"anvil/dynamicallyScannedClean"`

	// Halves reports BOTH halves, readable or not. An unreadable half is
	// reported with its result count so that "0 cards from the DAST half" and
	// "the DAST half has not sealed" are visibly different observations.
	Halves []ManifestHalf `json:"anvil/halves"`

	// Index is contract.go's Tier-0 index: counts, the deterministic read
	// order, and the inverted indexes. Any index dropped to stay under budget
	// is null here and named in Spills.
	Index Index `json:"anvil/index"`

	// Cards is the read order, materialised: one entry per emitted task card,
	// in the exact order BuildTaskCards returns them.
	Cards []CardRef `json:"anvil/cards"`

	// Spills names every structure moved out of this tier to stay under
	// budget, with the `sha256:` reference to its bytes. Never empty when
	// something was dropped, and nothing is ever dropped without an entry.
	Spills []TierSpill `json:"anvil/spills,omitempty"`

	// Override is non-nil only when the manifest exceeded its budget after
	// every shrink step AND the caller explicitly authorised that.
	Override *BudgetOverride `json:"anvil/budgetOverride,omitempty"`

	// Bytes and Tokens are what this manifest measured at.
	Bytes  int `json:"anvil/manifestBytes"`
	Tokens int `json:"anvil/manifestTokens"`

	// Blobs are the Tier-2 bytes this manifest spilled, keyed by reference.
	// NOT serialised: they are the thing that left the tier, and writing them
	// back into it would defeat the spill.
	Blobs map[string][]byte `json:"-"`
}

// ManifestTarget is the trimmed `anvil/target`. Both G4+G7 fields survive:
// provenance (what happened when we tried to run the target) and provisioning
// (which path produced one) are different measurements and the agent needs
// both to know what it is looking at.
type ManifestTarget struct {
	RepoURL        string             `json:"repoUrl"`
	Ref            string             `json:"ref"`
	Commit         string             `json:"commit"`
	Subpath        string             `json:"subpath,omitempty"`
	RuntimeBaseURL string             `json:"runtimeBaseUrl,omitempty"`
	Provenance     TargetProvenance   `json:"provenance"`
	Provisioning   TargetProvisioning `json:"provisioning"`
}

// ManifestClaim is the claim clock, flattened. DeadlineAt is the claim
// timeout, never a retention or confidentiality guarantee (SECRETS.md).
type ManifestClaim struct {
	DeadlineAt          string `json:"deadlineAt"`
	ClaimTimeoutSeconds int    `json:"claimTimeoutSeconds"`
}

// ManifestHalf is one half's seal state as the agent must see it.
type ManifestHalf struct {
	Half     Half       `json:"half"`
	Status   HalfStatus `json:"status"`
	SealedAt string     `json:"sealedAt,omitempty"`

	// Readable is sealing.go's HalfReadGate, and is never re-derived here: a
	// half is readable when its status is exactly HalfStatusSealed AND the
	// audit has not expired. A half may be TERMINAL without being READABLE — a
	// skipped DAST half is finished and unreadable at once — and a cleanly
	// SEALED half is unreadable once the claim window closes, because the
	// reaper has dropped the payload the cards would be built from.
	Readable bool `json:"readable"`

	// ReadRefusal is the gate's own reason, present exactly when Readable is
	// false. It is what keeps "the half never sealed" and "the audit expired
	// holding a sealed half" from arriving at the consumer as the same
	// observation — the manifest already reports Status and the envelope
	// already reports State, but a consumer should not have to join them.
	ReadRefusal string `json:"readRefusal,omitempty"`

	// Results is how many results the half carries in the record, whether or
	// not any card was emitted for them.
	Results int `json:"results"`

	// Cards is how many cards were emitted from this half. It is 0 whenever
	// Readable is false.
	Cards int `json:"cards"`

	Tool string `json:"tool,omitempty"`

	// Coverage is the DAST half's probed/inventory pair. Carried as the pair
	// and never as a bare ratio, for the reason DastCoverage documents.
	Coverage *ManifestCoverage `json:"coverage,omitempty"`
}

// ManifestCoverage is DastCoverage reduced to what Tier 0 can afford.
type ManifestCoverage struct {
	ProbedCount         int     `json:"probedCount"`
	InventoryUnionCount int     `json:"inventoryUnionCount"`
	EndpointCoverage    float64 `json:"endpointCoverage"`
}

// CardRef is one entry in the read order.
type CardRef struct {
	FindingID string `json:"findingId"`

	// Card is the Tier-1 path, Index.TaskCards + a filesystem-safe form of
	// FindingID.
	Card string `json:"card"`

	// Bucket is which of DefaultReadOrder()'s three buckets this finding came
	// from. It is not decoration: it is how a consumer verifies the order it
	// was handed is the order R.13 promises.
	Bucket string `json:"bucket"`

	Half          Half          `json:"half"`
	EvidenceClass EvidenceClass `json:"evidenceClass"`
	Rank          float64       `json:"rank"`
	ClusterID     string        `json:"clusterId,omitempty"`

	// Actionable is the coding agent's gate. False for every host finding,
	// always — see this file's header, gate 2.
	Actionable bool `json:"actionable"`
}

// TierSpill is one structure moved out of a tier to a Tier-2 blob.
type TierSpill struct {
	// Field names what left, in the tier's own vocabulary.
	Field string `json:"field"`
	// Ref is the `sha256:<64 lowercase hex>` reference to the bytes.
	Ref string `json:"ref"`
	// Bytes is the length of the spilled JSON. Items, where the spilled
	// structure is a collection, is how many entries it held.
	Bytes int `json:"bytes"`
	Items int `json:"items,omitempty"`
}

// BudgetOverride records an explicit decision to emit an over-budget tier. It
// exists so that "we exceeded the budget" is a fact in the artifact rather
// than a silence.
type BudgetOverride struct {
	Reason string `json:"reason"`
	Bytes  int    `json:"bytes"`
	Budget int    `json:"budget"`
}

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

// Reader builds the three tiers from a RecordSource. The zero value is not
// usable — it has no source; use NewReader.
type Reader struct {
	// Source resolves an audit id to its assembled, masked record.
	Source RecordSource

	// TaskCardPrefix and BlobPrefix are the Tier-1 and Tier-2 path prefixes
	// written into Index. Empty means the defaults.
	TaskCardPrefix string
	BlobPrefix     string

	// Blobs is called for every Tier-2 spill. NewReader installs the Reader's
	// own in-memory retainer here; a caller with real Tier-2 storage replaces
	// it, and only a caller that has deliberately set it to nil gets the old
	// behaviour of a spill with nowhere to land.
	//
	// WHY THE DEFAULT IS NOT NIL (CRITIQUE-03 M3, consequence 2). The spilled
	// bytes are returned in Manifest.Blobs / TaskCard.Blobs, both of which are
	// `json:"-"`. A caller that marshals the manifest and drops the struct —
	// the obvious thing to do with a projection — therefore shipped a Tier-0
	// manifest whose most load-bearing content, the materialised read order,
	// was a dangling `sha256:` reference. The hazard was documented; the
	// default walked straight into it. It now takes an explicit `rd.Blobs =
	// nil` to reach.
	Blobs BlobSink

	// retained backs the default sink. It is per-Reader and unbounded, which
	// is why DrainRetainedBlobs exists: a long-lived Reader projecting many
	// audits should drain after each one.
	//
	// It is a POINTER to a locked struct rather than a map plus a mutex field,
	// for two reasons: a Reader stays copyable (a mutex field would make every
	// `rd := *other` a vet copylocks error), and a Reader shared by two
	// goroutines building two audits' tiers cannot race on the retainer. Every
	// other field of Reader is configuration, written once before use.
	retained *blobRetainer

	// AllowOversizeTier0 and AllowOversizeTier1 are the explicit, logged
	// overrides R.13 requires before an over-budget tier may be emitted. The
	// string IS the log: it is the reason, it is recorded in the emitted
	// tier's BudgetOverride, and an empty string means "not authorised", which
	// is the default.
	AllowOversizeTier0 string
	AllowOversizeTier1 string

	// RequireMasked defaults to true via NewReader. Setting it false skips
	// AssertMasked, which is only ever correct for a caller that has already
	// run it.
	RequireMasked bool
}

// NewReader returns a Reader over src with the safe defaults: masking
// required, no oversize override authorised, default tier prefixes, and a
// Tier-2 blob sink that retains every spill on the Reader.
//
// The sink is a default, not a policy: a caller with durable Tier-2 storage
// assigns its own BlobSink to Reader.Blobs and this one is never called.
func NewReader(src RecordSource) *Reader {
	rd := &Reader{
		Source:         src,
		TaskCardPrefix: DefaultTaskCardPrefix,
		BlobPrefix:     DefaultBlobPrefix,
		RequireMasked:  true,
		retained:       &blobRetainer{blobs: map[string][]byte{}},
	}
	rd.Blobs = rd.retained.put
	return rd
}

// blobRetainer is the in-memory Tier-2 store behind NewReader's default sink.
type blobRetainer struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

// put is the default BlobSink. It never fails: an in-memory map cannot refuse
// a write, and a sink that could would make the default path able to fail in a
// way the caller did not ask for.
func (r *blobRetainer) put(ref string, content []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blobs == nil {
		r.blobs = map[string][]byte{}
	}
	r.blobs[ref] = content
	return nil
}

func (r *blobRetainer) snapshot(drain bool) map[string][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]byte, len(r.blobs))
	for ref, content := range r.blobs {
		out[ref] = content
	}
	if drain {
		r.blobs = map[string][]byte{}
	}
	return out
}

// RetainedBlobs returns every Tier-2 blob this Reader's default sink has
// retained, keyed by `sha256:` reference.
//
// It is a copy of the map (the byte slices are shared, and are never mutated
// after a spill), so a caller can iterate it while building another tier.
// Empty when the caller supplied its own BlobSink — the Reader retains nothing
// it did not write.
func (rd *Reader) RetainedBlobs() map[string][]byte {
	if rd == nil || rd.retained == nil {
		return map[string][]byte{}
	}
	return rd.retained.snapshot(false)
}

// DrainRetainedBlobs returns RetainedBlobs and forgets them, so a Reader used
// for many audits does not accumulate every blob it ever spilled.
func (rd *Reader) DrainRetainedBlobs() map[string][]byte {
	if rd == nil || rd.retained == nil {
		return map[string][]byte{}
	}
	return rd.retained.snapshot(true)
}

func (rd *Reader) cardPrefix() string {
	if rd.TaskCardPrefix == "" {
		return DefaultTaskCardPrefix
	}
	return rd.TaskCardPrefix
}

func (rd *Reader) blobPrefix() string {
	if rd.BlobPrefix == "" {
		return DefaultBlobPrefix
	}
	return rd.BlobPrefix
}

func (rd *Reader) load(auditID string) (*SARIFLog, error) {
	if rd == nil || rd.Source == nil {
		return nil, fmt.Errorf("record: Reader has no RecordSource; use NewReader")
	}
	l, err := rd.Source.Record(auditID)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("record: RecordSource returned a nil record for audit id %q", auditID)
	}
	if l.Properties.AuditID != auditID {
		return nil, fmt.Errorf("record: RecordSource returned audit %q for audit id %q; "+
			"the audit identity is the join key and a mismatch means the wrong record was fetched",
			l.Properties.AuditID, auditID)
	}
	if rd.RequireMasked {
		if err := AssertMasked(l); err != nil {
			return nil, fmt.Errorf("record: refusing to build the read path for audit %q: %w "+
				"(00-SPINE.md S7: the read path feeds a repo-credentialed agent; masking is R.8's step and runs before this one)",
				auditID, err)
		}
	}
	return l, nil
}

// BuildManifest builds the Tier-0 manifest for auditID.
//
// R.13's expected output schema names `BuildManifest(auditID string)
// (Manifest, error)`. It is a method rather than a package-level function
// because the record has to come from somewhere and the alternative — a
// package-level default source — is exactly the kind of hidden global state
// that makes two callers disagree about which record they read.
func (rd *Reader) BuildManifest(auditID string) (Manifest, error) {
	l, err := rd.load(auditID)
	if err != nil {
		return Manifest{}, err
	}
	return rd.ManifestFromLog(l)
}

// BuildTaskCards builds the Tier-1 task cards for auditID, in the
// deterministic read order.
func (rd *Reader) BuildTaskCards(auditID string) ([]TaskCard, error) {
	l, err := rd.load(auditID)
	if err != nil {
		return nil, err
	}
	return rd.CardsFromLog(l)
}

// ---------------------------------------------------------------------------
// The deterministic read order
// ---------------------------------------------------------------------------

// Read-order bucket names. These are the members of DefaultReadOrder(), which
// contract.go owns; TestReadOrderBucketsMatchTheContract asserts the two
// cannot drift.
const (
	BucketClusters   = "clusters"
	BucketSastByRank = "sastByRank"
	BucketDastByRank = "dastByRank"
)

// orderedResult is one result in read order, with the coordinates needed to
// point back into the record.
type orderedResult struct {
	runIndex    int
	resultIndex int
	run         *Run
	result      *Result
	bucket      string
	clusterID   string
	rank        float64
}

// evidenceClassStrength returns the index of e in EvidenceClassValues(), which
// contract.go documents as "descending evidence strength — which is also the
// default rank order". Lower is stronger. An unknown class sorts last rather
// than panicking: the read path is not the place to reject a record.
func evidenceClassStrength(e EvidenceClass) int {
	for i, v := range EvidenceClassValues() {
		if v == e {
			return i
		}
	}
	return len(EvidenceClassValues())
}

// resultRank reads SARIF's `result.rank` — PRIORITY, not confidence and not
// severity (contract.go, ResultProperties.Confidence). An absent rank sorts
// below every present one instead of defaulting to 0, which would silently
// promote unranked findings past genuinely rank-0 ones.
func resultRank(r *Result) float64 {
	if r.Rank != nil {
		return *r.Rank
	}
	return -1
}

// IsHostFinding reports whether r is a host-package finding, by EITHER of the
// two fields that can say so.
//
// Both are checked because they are set by different producers and a record in
// which only one says "host" is a record whose host-ness is still true. The
// read path's job is to never hand such a finding to an agent that cannot fix
// it (plan/00-SPINE.md S7: the host agent is read-only).
func IsHostFinding(r *Result) bool {
	return r.Properties.Detector.Kind == DetectorKindHost ||
		r.Properties.EvidenceClass == EvidenceClassHost
}

// readOrder returns every READABLE result in the one order R.13 permits:
// correlated clusters first, then SAST-only by rank, then DAST-only by rank.
//
// Results from a half the read gate refuses are omitted entirely. THE GATE IS
// sealing.go's HalfReadGate AND NOTHING ELSE. This function used to ask
// IsReadableHalfStatus(run.Properties.Status) directly, which is only the
// status arm; CRITIQUE-03 M1 reproduced the consequence — an EXPIRED audit
// yielded nine cards, six of them actionable, against a claim window that had
// already closed and handoff rows already subject to ReclaimExpired.
func (rd *Reader) readOrder(l *SARIFLog) []orderedResult {
	var clustered, sastOnly, dastOnly []orderedResult

	for ri := range l.Runs {
		run := &l.Runs[ri]
		if HalfReadGate(l.Properties.AuditID, halfSealOfRun(l, run)) != nil {
			continue
		}
		for si := range run.Results {
			res := &run.Results[si]
			o := orderedResult{
				runIndex:    ri,
				resultIndex: si,
				run:         run,
				result:      res,
				rank:        resultRank(res),
			}
			switch {
			case res.Properties.Correlation != nil:
				o.bucket = BucketClusters
				o.clusterID = res.Properties.Correlation.ClusterID
				clustered = append(clustered, o)
			case res.Properties.Half == HalfDast:
				o.bucket = BucketDastByRank
				dastOnly = append(dastOnly, o)
			default:
				o.bucket = BucketSastByRank
				sastOnly = append(sastOnly, o)
			}
		}
	}

	out := make([]orderedResult, 0, len(clustered)+len(sastOnly)+len(dastOnly))
	out = append(out, orderClusters(clustered)...)
	sortByRank(sastOnly)
	out = append(out, sastOnly...)
	sortByRank(dastOnly)
	out = append(out, dastOnly...)
	return out
}

// sortByRank is the total order inside a bucket: rank descending, then
// evidence strength, then finding id. The finding-id tie-break is what makes
// the order STABLE rather than merely deterministic-for-this-input — two
// findings with identical rank and class still cannot swap between calls.
func sortByRank(rs []orderedResult) {
	sort.SliceStable(rs, func(i, j int) bool { return lessByRank(rs[i], rs[j]) })
}

func lessByRank(a, b orderedResult) bool {
	if a.rank != b.rank {
		return a.rank > b.rank
	}
	as, bs := evidenceClassStrength(a.result.Properties.EvidenceClass),
		evidenceClassStrength(b.result.Properties.EvidenceClass)
	if as != bs {
		return as < bs
	}
	return a.result.Properties.FindingID < b.result.Properties.FindingID
}

// orderClusters groups the clustered results by cluster id and emits whole
// clusters, strongest cluster first.
//
// A cluster is emitted CONTIGUOUSLY and never merged: both members survive as
// separate cards, because the SAST finding owns the file and line and the DAST
// finding owns the proof (research/18, "link, never merge"). Within a cluster
// the SAST member comes first — it is the one carrying the code the agent has
// to edit.
func orderClusters(rs []orderedResult) []orderedResult {
	if len(rs) == 0 {
		return nil
	}
	byCluster := map[string][]orderedResult{}
	for _, o := range rs {
		byCluster[o.clusterID] = append(byCluster[o.clusterID], o)
	}

	ids := make([]string, 0, len(byCluster))
	for id := range byCluster {
		ids = append(ids, id)
		members := byCluster[id]
		sort.SliceStable(members, func(i, j int) bool {
			a, b := members[i], members[j]
			if a.result.Properties.Half != b.result.Properties.Half {
				return a.result.Properties.Half == HalfSast
			}
			return lessByRank(a, b)
		})
		byCluster[id] = members
	}

	// Cluster order: best member's rank descending, then cluster id. Ranging
	// over the map above collected the ids in map order; this sort is what
	// makes the result deterministic, and it is a total order because cluster
	// ids are unique keys. The best rank is precomputed rather than derived
	// inside the comparator, so the comparator is a pure comparison and cannot
	// be quadratic in cluster size.
	best := make(map[string]float64, len(byCluster))
	for id, members := range byCluster {
		top := members[0].rank
		for _, m := range members {
			if m.rank > top {
				top = m.rank
			}
		}
		best[id] = top
	}
	sort.SliceStable(ids, func(i, j int) bool {
		bi, bj := best[ids[i]], best[ids[j]]
		if bi != bj {
			return bi > bj
		}
		return ids[i] < ids[j]
	})

	out := make([]orderedResult, 0, len(rs))
	for _, id := range ids {
		out = append(out, byCluster[id]...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Tier 0 assembly
// ---------------------------------------------------------------------------

// ManifestFromLog builds the Tier-0 manifest from an already-loaded record.
func (rd *Reader) ManifestFromLog(l *SARIFLog) (Manifest, error) {
	if l == nil {
		return Manifest{}, fmt.Errorf("record: ManifestFromLog got a nil *SARIFLog")
	}
	p := &l.Properties
	order := rd.readOrder(l)
	clusters := clustersOf(order)

	m := Manifest{
		ManifestVersion: CardVersion,
		SchemaVersion:   p.SchemaVersion,
		AuditID:         p.AuditID,
		State:           p.State,
		Version:         p.Version,
		CreatedAt:       formatTime(p.CreatedAt),
		Target: ManifestTarget{
			RepoURL:        p.Target.RepoURL,
			Ref:            p.Target.Ref,
			Commit:         p.Target.Commit,
			Subpath:        p.Target.Subpath,
			RuntimeBaseURL: p.Target.RuntimeBaseURL,
			Provenance:     p.Target.Provenance,
			Provisioning:   p.Target.Provisioning,
		},
		Deadline: ManifestClaim{
			DeadlineAt:          formatTime(p.Deadline.DeadlineAt),
			ClaimTimeoutSeconds: p.Deadline.ClaimTimeoutSeconds,
		},
		DastStatus:              p.DastStatus,
		DynamicallyScannedClean: p.DastStatus.MeansDynamicallyScannedClean(),
		Blobs:                   map[string][]byte{},
	}

	cardsPerHalf := map[Half]int{}
	counts := IndexCounts{}
	byCluster := map[string][]string{}
	byCwe := map[string][]string{}
	byPath := map[string][]string{}
	clusterSeen := map[string]bool{}

	for _, o := range order {
		fid := o.result.Properties.FindingID
		actionable, _ := cardActionable(o.result, clusters[o.clusterID])
		m.Cards = append(m.Cards, CardRef{
			FindingID:     fid,
			Card:          rd.cardPath(fid),
			Bucket:        o.bucket,
			Half:          o.result.Properties.Half,
			EvidenceClass: o.result.Properties.EvidenceClass,
			Rank:          o.rank,
			ClusterID:     o.clusterID,
			// cardActionable, never isActionable: the manifest's read order and
			// the card must agree, and they only agree if they ask one
			// function. TestManifestReadOrderMatchesTheCards asserts it.
			Actionable: actionable,
		})
		cardsPerHalf[o.result.Properties.Half]++
		counts.Total++
		switch o.result.Properties.Half {
		case HalfSast:
			counts.Sast++
		case HalfDast:
			counts.Dast++
		}
		if o.clusterID != "" {
			byCluster[o.clusterID] = append(byCluster[o.clusterID], fid)
			if !clusterSeen[o.clusterID] {
				clusterSeen[o.clusterID] = true
				counts.Clusters++
			}
		} else {
			counts.Unclustered++
		}
		for _, taxon := range taxonIDs(o.result) {
			byCwe[taxon] = append(byCwe[taxon], fid)
		}
		if path := primaryPath(o.result); path != "" {
			byPath[path] = append(byPath[path], fid)
		}
	}

	for ri := range l.Runs {
		run := &l.Runs[ri]
		// The SAME gate readOrder applied, so a half can never be reported
		// readable while contributing no cards, or vice versa.
		seal := halfSealOfRun(l, run)
		h := ManifestHalf{
			Half:        run.Properties.Half,
			Status:      run.Properties.Status,
			Readable:    seal.Readable(),
			ReadRefusal: halfReadRefusal(seal),
			Results:     len(run.Results),
			Cards:       cardsPerHalf[run.Properties.Half],
			Tool:        run.Tool.Driver.Name,
		}
		if run.Properties.SealedAt != nil {
			h.SealedAt = formatTime(*run.Properties.SealedAt)
		}
		if c := run.Properties.DastCoverage; c != nil {
			h.Coverage = &ManifestCoverage{
				ProbedCount:         c.ProbedCount,
				InventoryUnionCount: c.InventoryUnionCount,
				EndpointCoverage:    c.EndpointCoverage,
			}
		}
		m.Halves = append(m.Halves, h)
	}

	m.Index = Index{
		Counts:    counts,
		ReadOrder: DefaultReadOrder(),
		ByCluster: emptyToNil(byCluster),
		ByCwe:     emptyToNil(byCwe),
		ByPath:    emptyToNil(byPath),
		TaskCards: rd.cardPrefix(),
		Blobs:     rd.blobPrefix(),
	}

	if err := rd.fitManifest(&m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// fitManifest brings the manifest under MaxTier0ManifestBytes by spilling, in
// a FIXED order, the structures that can be reconstructed from Tier 2.
//
// The order is least-to-most load-bearing for the agent's next action:
//
//	byPath    — a convenience index; every card names its own path.
//	byCwe     — a convenience index; every card names its own taxa.
//	byCluster — the cluster membership; the cards still carry cluster ids.
//	cards     — the materialised read order. Dropped LAST, because without it
//	            the agent has to reconstruct the order, and R.13 forbids any
//	            order but this one.
//
// Nothing is deleted: each step writes the structure to a Tier-2 blob and
// records a TierSpill naming the field and the `sha256:` reference.
//
// # The three index steps are all-or-nothing; the read order is NOT
//
// An index is a lookup table: half a `byPath` map is not a smaller index, it
// is an index that silently lies about which paths it knows, so those three
// steps still remove the WHOLE field.
//
// The read order is a LIST, and half a list in read order is exactly the first
// half of the work. So the `anvil/cards` step is PARTIAL (spillCardTail): it
// keeps as many card refs inline as the remaining budget affords, in read
// order, and spills only the tail — with the spilled count in TierSpill.Items,
// which the type has carried since it was written.
//
// CRITIQUE-03 M3 measured what the all-or-nothing version cost: at the
// crossover — around fifty findings — the manifest went from just over 8,192
// bytes to about 1,776 in one step, and roughly 78% of the Tier-0 budget then
// sat unused while the agent had to fetch Tier 2 before it could start on the
// FIRST finding. The budget was never exceeded and the order was never lost,
// so it was a utilisation defect rather than a correctness one; it is now
// fixed rather than documented. TestTier0PartialSpillUsesTheBudget asserts the
// budget is USED at nine sizes, not merely respected.
func (rd *Reader) fitManifest(m *Manifest) error {
	steps := []struct {
		field string
		take  func(*Manifest) (any, int, bool)
	}{
		{"anvil/index.byPath", func(m *Manifest) (any, int, bool) {
			v := m.Index.ByPath
			if len(v) == 0 {
				return nil, 0, false
			}
			m.Index.ByPath = nil
			return v, len(v), true
		}},
		{"anvil/index.byCwe", func(m *Manifest) (any, int, bool) {
			v := m.Index.ByCwe
			if len(v) == 0 {
				return nil, 0, false
			}
			m.Index.ByCwe = nil
			return v, len(v), true
		}},
		{"anvil/index.byCluster", func(m *Manifest) (any, int, bool) {
			v := m.Index.ByCluster
			if len(v) == 0 {
				return nil, 0, false
			}
			m.Index.ByCluster = nil
			return v, len(v), true
		}},
	}

	size, err := measureManifest(m)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if size <= MaxTier0ManifestBytes {
			break
		}
		payload, items, ok := st.take(m)
		if !ok {
			continue
		}
		if err := rd.spill(&m.Spills, m.Blobs, st.field, payload, items); err != nil {
			return err
		}
		if size, err = measureManifest(m); err != nil {
			return err
		}
	}

	// The last step, and the only partial one.
	if size > MaxTier0ManifestBytes && len(m.Cards) > 0 {
		if size, err = rd.spillCardTail(m); err != nil {
			return err
		}
	}

	if size > MaxTier0ManifestBytes {
		if rd.AllowOversizeTier0 == "" {
			return &BudgetError{
				Tier: "tier-0 manifest", Subject: m.AuditID,
				Bytes: size, Budget: MaxTier0ManifestBytes,
				Tokens: ApproxTokens(size), MaxTok: ApproxTokens(MaxTier0ManifestBytes),
			}
		}
		m.Override = &BudgetOverride{
			Reason: rd.AllowOversizeTier0,
			Bytes:  size,
			Budget: MaxTier0ManifestBytes,
		}
		if _, err = measureManifest(m); err != nil {
			return err
		}
	}
	return nil
}

// spillCardTail is the `anvil/cards` shrink step. It keeps the longest PREFIX
// of the read order that fits the remaining Tier-0 budget and spills the rest
// to one Tier-2 blob, returning the manifest's size afterwards.
//
// A PREFIX, not a sample: the read order is the order R.13 requires the agent
// to work in, so the refs worth keeping inline are the ones it needs FIRST.
// The spilled blob holds the tail alone, so `m.Cards` followed by the blob's
// contents is the whole order, once, in order — a consumer never has to
// reconcile two overlapping copies, and TierSpill.Items says exactly how many
// entries are on the other side of the reference.
//
// The search is a binary search over trial measurements rather than an
// estimate from an average ref size, because the thing being fitted is the
// MARSHALLED manifest: card refs differ in length (finding ids, cluster ids,
// bucket names), the spill entry it is competing with grows its own decimal
// fields, and measureManifest re-stamps `anvil/manifestBytes` on every call.
// A trial measures what all three do together. Each trial marshals the tail,
// so the step costs O(log n) marshals; nothing is persisted until the size is
// settled, so a rejected trial never reaches the BlobSink.
func (rd *Reader) spillCardTail(m *Manifest) (int, error) {
	all := m.Cards
	if len(all) == 0 {
		return measureManifest(m)
	}

	// trial measures m as it WOULD stand with the first keep refs inline and
	// the remaining ones spilled, then restores m exactly as it found it.
	trial := func(keep int) (int, []byte, error) {
		raw, err := json.Marshal(all[keep:])
		if err != nil {
			return 0, nil, fmt.Errorf("record: spilling anvil/cards to a Tier-2 blob failed: %w", err)
		}
		m.Cards = cardPrefix(all, keep)
		m.Spills = append(m.Spills, TierSpill{
			Field: "anvil/cards", Ref: BlobRef(raw), Bytes: len(raw), Items: len(all) - keep,
		})
		size, err := measureManifest(m)
		m.Spills = m.Spills[:len(m.Spills)-1]
		m.Cards = all
		return size, raw, err
	}

	// keep == len(all) is not a candidate: this step is only reached because
	// the manifest is over budget with the whole order inline, and a spill
	// step that spills nothing would record a TierSpill for zero items.
	lo, hi, best := 0, len(all)-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		size, _, err := trial(mid)
		if err != nil {
			return 0, err
		}
		if size <= MaxTier0ManifestBytes {
			best, lo = mid, mid+1
		} else {
			hi = mid - 1
		}
	}
	// best < 0 means not even an empty `anvil/cards` fits; spill the whole
	// order and let the caller raise the BudgetError or apply the override.
	// That is the old all-or-nothing behaviour, reached only when the
	// envelope alone is over budget.
	keep := best
	if keep < 0 {
		keep = 0
	}

	_, raw, err := trial(keep)
	if err != nil {
		return 0, err
	}
	m.Cards = cardPrefix(all, keep)
	if err := rd.spillBytes(&m.Spills, m.Blobs, "anvil/cards", raw, len(all)-keep); err != nil {
		return 0, err
	}
	return measureManifest(m)
}

// cardPrefix returns the first keep refs, and nil rather than an empty slice
// when keep is zero: `"anvil/cards": null` is how a manifest that carries no
// inline read order has always spelled it, and a consumer distinguishing `null`
// from `[]` should not start seeing a new spelling because the step became
// partial.
func cardPrefix(all []CardRef, keep int) []CardRef {
	if keep <= 0 {
		return nil
	}
	return all[:keep]
}

// measureManifest marshals m, stamps the measurement into m, and returns the
// size m ACTUALLY has once stamped.
//
// The stamping is why this is not one line: writing the byte count into the
// object changes the object's byte count. Re-measuring after each stamp
// converges — the only thing that changes is the decimal width of two integers
// that are already close to their final value — and the loop bounds it. It
// matters because the budget check must run against the size the manifest ends
// up with, not the size it had before it described itself; a few bytes of
// self-report are exactly how a check like this ends up passing on an object
// that is over budget on disk.
func measureManifest(m *Manifest) (int, error) {
	size, err := measure(m)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 8; i++ {
		m.Bytes, m.Tokens = size, ApproxTokens(size)
		next, err := measure(m)
		if err != nil {
			return 0, err
		}
		if next == size {
			return size, nil
		}
		size = next
	}
	m.Bytes, m.Tokens = size, ApproxTokens(size)
	return measure(m)
}

// ---------------------------------------------------------------------------
// Spilling to Tier 2
// ---------------------------------------------------------------------------

// BlobRef returns the `sha256:<64 lowercase hex>` reference for content. It is
// the same spelling R.8's masker writes, deliberately: one content-addressing
// scheme, or a consumer has to guess which one it is looking at.
func BlobRef(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (rd *Reader) spill(dst *[]TierSpill, blobs map[string][]byte, field string, payload any, items int) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("record: spilling %s to a Tier-2 blob failed: %w", field, err)
	}
	return rd.spillBytes(dst, blobs, field, raw, items)
}

// spillBytes is spill for content that is already bytes. A body spills as the
// bytes themselves, not as a JSON string containing them: R.8's masker
// content-addresses the raw masked body, and two spellings of the same blob
// would content-address to two different digests.
func (rd *Reader) spillBytes(dst *[]TierSpill, blobs map[string][]byte, field string, raw []byte, items int) error {
	ref := BlobRef(raw)
	if blobs != nil {
		blobs[ref] = raw
	}
	if rd.Blobs != nil {
		if err := rd.Blobs(ref, raw); err != nil {
			return fmt.Errorf("record: persisting Tier-2 blob %s for %s failed: %w", ref, field, err)
		}
	}
	*dst = append(*dst, TierSpill{Field: field, Ref: ref, Bytes: len(raw), Items: items})
	return nil
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

func measure(v any) (int, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return 0, fmt.Errorf("record: measuring a read-path tier failed: %w", err)
	}
	return len(raw), nil
}

func emptyToNil(m map[string][]string) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

// formatTime renders a timestamp in the one form the whole read path uses:
// RFC 3339 in UTC, which is what time.Time's own JSON encoding produces.
//
// A zero time renders as the empty string rather than as year 1, which a
// consumer would otherwise parse as a real timestamp.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// cardPath is the Tier-1 path for a finding id.
//
// Finding ids are `sast:8c1e4b0f…` in research/18's own example, and a colon
// is not a legal path character on Windows — where this project is being
// developed. The sanitisation is a total, deterministic function so the same
// finding always lands at the same path on every platform.
func (rd *Reader) cardPath(findingID string) string {
	return rd.cardPrefix() + SanitizeCardFilename(findingID) + ".json"
}

// SanitizeCardFilename maps a finding id onto a filesystem-safe, deterministic
// basename. Every byte outside [A-Za-z0-9._-] becomes '-'.
func SanitizeCardFilename(findingID string) string {
	var b strings.Builder
	b.Grow(len(findingID))
	for i := 0; i < len(findingID); i++ {
		c := findingID[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// taxonIDs returns the result's taxon ids (CWE, in practice), deduplicated and
// sorted so the inverted index is stable.
func taxonIDs(r *Result) []string {
	if len(r.Taxa) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range r.Taxa {
		if t.ID == "" || seen[t.ID] {
			continue
		}
		seen[t.ID] = true
		out = append(out, t.ID)
	}
	sort.Strings(out)
	return out
}

// primaryPath returns the first physical location's artifact URI, which is
// SARIF's own notion of "the file this result is about".
func primaryPath(r *Result) string {
	for _, loc := range r.Locations {
		if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI != "" {
			return loc.PhysicalLocation.ArtifactLocation.URI
		}
	}
	return ""
}
