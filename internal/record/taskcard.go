// Tier 1 of the read path: the task card the coding agent actually reads
// (step R.13, with readpath.go).
//
// # A task card is DERIVED. The record is authoritative.
//
// This is the single most important sentence in this file. research/18:
// "One self-contained JSON per finding, *derived* from the SARIF (the SARIF
// stays authoritative)." A card is a projection built for one consumer's
// context window. It is not a second copy of the truth, it is not written
// back, and it has no independent lifetime:
//
//   - Where a card and the record disagree, THE RECORD WINS and the card is a
//     stale projection to be rebuilt. TaskCard.CheckAgainstRecord reports the
//     disagreements rather than leaving a reader to find them.
//   - A card is never the input to another card. Rebuilding from the record is
//     always correct; rebuilding from a card is always a lossy copy of a lossy
//     copy.
//   - The agent's patch is written back to `result.fixes` in the RECORD
//     (SARIF §3.27.30) — TaskCard.WriteBackTo names the pointer — never to the
//     card.
//
// The one direction in which a card may legally differ from the record is
// PERMISSIVENESS, and only downward: a card may withhold an action the record
// would have allowed, and may never grant one the record does not. That is
// what makes the three clamps below safe to implement here.
//
// # Three clamps, one rule
//
// Each is a gate the record's own validator already enforces, re-enforced here
// because THE CARD IS WHAT THE AGENT RECEIVES and a malformed producer, a
// hand-edited row or a future column default must not be able to reach past
// the producer's gate into the agent's context.
//
//  1. THE HOST GATE — RemediableByAgent, below.
//  2. THE VERIFIED GATE — cardCorrelation clamps `verified` against
//     CorrelationSignal.SufficientForVerified via correlation.go's own
//     verificationOf, never a second copy of the rule. CRITIQUE-03 m2: the
//     host gate was enforced three times and this one, the same class of S7
//     gate, was taken on trust.
//  3. THE BORROWED LOCUS — cardActionable withholds the action from a cluster
//     member whose file and line came from its peer. See cardActionable for
//     the whole argument; the short form is that one defect must not become
//     two patch tasks, and that a locus the finding did not observe must not
//     be presented as one it did.
//
// All three are WITHHOLDINGS, so CheckAgainstRecord does not report them.
// GroupID would be the mechanism that collapses a duplicated cluster task
// downstream, and it is RESERVED for the consumption pipeline (contract.go),
// so nothing collapses them here — which is why clamp 3 is a clamp and not a
// note for a later step.
//
// # The host gate
//
// plan/00-SPINE.md S7 makes the host agent read-only — "no package manager in
// a mutating mode, not behind a flag" — so `remediable_by_agent` is false for
// every host finding. contract.go's Validate() enforces it on the record and
// internal/store enforces it with a CHECK constraint.
//
// This file enforces it a THIRD time, on the card, because the card is what
// the agent receives. The two upstream gates protect the record; if a record
// reaches this package with a host finding marked remediable — a malformed
// producer, a hand-edited row, a future column default — the card must still
// not hand the agent a task it is forbidden to perform. RemediableByAgent is
// clamped to false and the reason is recorded in ActionBlockers.
//
// # What a card must carry
//
// research/24-coding-agent-consumption.md's non-negotiable handoff fields,
// "because there is no orchestrator to compute them later": `finding_id`,
// `fingerprint.primary_location_line_hash`, `fingerprint.region_sha256`,
// `evidence_class`, `dast.reproduction`, `risk.*`, `locus.*`,
// `advisory_excerpt` (<=800 tokens) and `group_id`. Every one has a field
// below, and TestCardCarriesTheNonNegotiableFields asserts it.
package record

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// The card
// ---------------------------------------------------------------------------

// TaskCard is Tier 1: one self-contained JSON per finding, carrying
// everything needed to write the patch with no further lookups, inside
// MaxTier1CardTokens.
type TaskCard struct {
	CardVersion string `json:"cardVersion"`
	AuditID     string `json:"auditId"`
	FindingID   string `json:"findingId"`

	// Bucket is which of DefaultReadOrder()'s buckets this card came from,
	// and Position is its 0-based index in the whole read order. A consumer
	// that receives cards out of band can verify the order it was handed.
	Bucket   string `json:"bucket"`
	Position int    `json:"position"`

	Half      Half   `json:"half"`
	ClusterID string `json:"clusterId,omitempty"`

	// GroupID is research/24's `group_id`. It is RESERVED and assigned by the
	// coding-agent consumption pipeline, not here (contract.go,
	// ResultProperties.GroupID); the card carries whatever the record carries,
	// which on a freshly assembled record is empty.
	GroupID string `json:"groupId,omitempty"`

	Rank          float64       `json:"rank"`
	EvidenceClass EvidenceClass `json:"evidenceClass"`
	Verdict       Verdict       `json:"verdict"`
	Confidence    float64       `json:"confidence"`

	// ConsumptionClass is DERIVED here; see deriveConsumptionClass. The
	// authoritative value is `handoff.consumption_class` (R.4).
	ConsumptionClass ConsumptionClass `json:"consumptionClass"`

	// RemediableByAgent is the record's value CLAMPED: never true for a host
	// finding. See this file's header.
	RemediableByAgent bool `json:"remediableByAgent"`

	// Actionable is the single gate a consumer should branch on: the agent may
	// propose a patch for this finding. ActionBlockers is why not, when not —
	// never empty when Actionable is false, so "not actionable" is never
	// unexplained.
	Actionable     bool     `json:"actionable"`
	ActionBlockers []string `json:"actionBlockers,omitempty"`

	Task string    `json:"task"`
	Rule *CardRule `json:"rule,omitempty"`

	Fingerprint CardFingerprint `json:"fingerprint"`
	Locus       CardLocus       `json:"locus"`

	Static      *CardStatic      `json:"static,omitempty"`
	Dynamic     *CardDynamic     `json:"dynamic,omitempty"`
	Advisory    *CardAdvisory    `json:"advisory,omitempty"`
	Risk        *Risk            `json:"risk,omitempty"`
	Correlation *CardCorrelation `json:"correlation,omitempty"`
	Constraints *PatchContext    `json:"constraints,omitempty"`

	// Trust classifies the card's own strings. See CardTrust.
	Trust CardTrust `json:"trust"`

	// Spills names everything this card moved to a Tier-2 blob, either
	// because it exceeded an inline cap or to stay inside the token budget.
	Spills []TierSpill `json:"spills,omitempty"`

	// Override is non-nil only when the card exceeded its budget after every
	// shrink step AND Reader.AllowOversizeTier1 explicitly authorised it.
	Override *BudgetOverride `json:"budgetOverride,omitempty"`

	// WriteBackTo is the RFC 6901 pointer, from the sarifLog root, of the
	// result's `fixes` array. plan/00-SPINE.md S7: "Never auto-merge. Propose
	// only." The proposal lands in the record, not in the card.
	WriteBackTo string `json:"writeBackTo"`

	Bytes  int `json:"cardBytes"`
	Tokens int `json:"cardTokens"`

	// Blobs are the Tier-2 bytes this card spilled, keyed by reference. NOT
	// serialised, for the same reason Manifest.Blobs is not.
	Blobs map[string][]byte `json:"-"`
}

// CardRule is the rule that fired, as the agent needs to understand it.
type CardRule struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	HelpURI     string `json:"helpUri,omitempty"`
}

// CardFingerprint carries research/24's three non-negotiable identity fields.
// The keys they live under are contract.go's, never spelled by hand.
type CardFingerprint struct {
	// AnvilFindingID is the full, never-truncated anvil-fp/v1 digest.
	AnvilFindingID string `json:"anvilFindingId"`
	// PrimaryLocationLineHash is the only partial fingerprint GitHub reads.
	PrimaryLocationLineHash string `json:"primaryLocationLineHash,omitempty"`
	// RegionSha256 is research/24's `fingerprint.region_sha256`. It is
	// optional on the wire — CONTRACT.md deviation 2 leaves the decision to
	// populate it open — so the card carries it when the record has it and
	// says nothing when it does not, rather than inventing a value.
	RegionSha256 string `json:"regionSha256,omitempty"`
}

// CardLocus is research/24's `locus.*`. Path, line range and enclosing symbol
// are read out of the SARIF-native slots (Locus in the property bag carries
// only ProximityClass, precisely so there is one source of truth for them).
type CardLocus struct {
	Path            string `json:"path,omitempty"`
	StartLine       int    `json:"startLine,omitempty"`
	EndLine         int    `json:"endLine,omitempty"`
	EnclosingSymbol string `json:"enclosingSymbol,omitempty"`
	ProximityClass  string `json:"proximityClass,omitempty"`

	// BorrowedFrom names the cluster peer this locus came from, and is set
	// exactly when this finding did not observe a file and line of its own.
	//
	// It is the difference between OBSERVED and INFERRED, and it is on the
	// card because the card is what the agent reads: a DAST finding's locus is
	// the correlation's conclusion about where the defect lives, not something
	// the dynamic probe saw. Empty means the finding observed its own locus.
	// A card with this set is never Actionable; see cardActionable.
	BorrowedFrom string `json:"borrowedFrom,omitempty"`
}

// CardStatic is the static evidence: the code the agent edits.
type CardStatic struct {
	FindingID string `json:"findingId"`
	File      string `json:"file,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	Symbol    string `json:"symbol,omitempty"`

	// Code is the defect region's snippet; Context is the surrounding region
	// the agent needs to patch it (SARIF §3.29.4 / §3.29.5). Both are
	// VERBATIM TARGET-REPO SOURCE and therefore untrusted — see CardTrust.
	Code    string       `json:"code,omitempty"`
	Context *CardContext `json:"context,omitempty"`

	// TaintPath is the code flow flattened to one line per step.
	TaintPath []string `json:"taintPath,omitempty"`

	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning,omitempty"`
}

// CardContext is the context region around the defect.
type CardContext struct {
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	Text      string `json:"text,omitempty"`
}

// CardDynamic is research/24's `dast.reproduction`: the replayable request and
// what it produced, which doubles as the accept oracle for the fix.
//
// plan/00-SPINE.md S7: only a reproduction that now FAILS earns "verified
// fixed", so Env is carried — a replay under a different sanitizer or ASLR
// setting is not the same experiment.
type CardDynamic struct {
	FindingID string `json:"findingId"`

	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`

	// RequestBody is capped at MaxInlineRequestBodyBytes and ResponseExcerpt
	// at MaxInlineResponseBodyBytes — R.8's caps, restated here because the
	// card is a second place the bytes could be inlined. The remainder is a
	// Tier-2 blob named in TaskCard.Spills.
	RequestBody     string `json:"requestBody,omitempty"`
	StatusCode      int    `json:"statusCode,omitempty"`
	ResponseExcerpt string `json:"responseExcerpt,omitempty"`

	// ResponseBodyRef is the record's own `sha256:` reference to the full
	// masked response body, when it has one.
	ResponseBodyRef string `json:"responseBodyRef,omitempty"`

	BaselineStatusCode int `json:"baselineStatusCode,omitempty"`

	Payload         string         `json:"payload,omitempty"`
	PayloadEncoding string         `json:"payloadEncoding,omitempty"`
	InjectionPoint  string         `json:"injectionPoint,omitempty"`
	ObservedSignal  EvidenceSignal `json:"observedSignal,omitempty"`
	// Observed is the regex-extracted evidence span, never a raw body
	// (plan/00-SPINE.md S7).
	Observed string `json:"observed,omitempty"`

	Steps            []string          `json:"steps,omitempty"`
	Curl             string            `json:"curl,omitempty"`
	ExpectedAfterFix *ReproExpectation `json:"expectedAfterFix,omitempty"`
	Env              *ReproEnv         `json:"env,omitempty"`
	SideEffects      string            `json:"sideEffects,omitempty"`

	Confidence float64 `json:"confidence"`
}

// CardAdvisory is the advisory context, with the excerpt capped at
// research/24's <=800 tokens.
type CardAdvisory struct {
	Taxa             []string `json:"taxa,omitempty"`
	IDs              []string `json:"ids,omitempty"`
	CveIDs           []string `json:"cveIds,omitempty"`
	SourceFeed       string   `json:"sourceFeed,omitempty"`
	LicenseSpdx      string   `json:"licenseSpdx,omitempty"`
	AsOf             string   `json:"asOf,omitempty"`
	StalenessSeconds int      `json:"stalenessSeconds"`
	// ParseDegraded means the feed parsed with loss. A consumer must
	// down-weight, not silently trust, degraded context.
	ParseDegraded bool   `json:"parseDegraded"`
	Excerpt       string `json:"excerpt,omitempty"`
}

// CardCorrelation is the LINK, never a merge. Peers names the findings this
// one is linked to; each of them has its own card.
type CardCorrelation struct {
	ClusterID string   `json:"clusterId"`
	Role      Half     `json:"role"`
	Peers     []string `json:"peers,omitempty"`
	Signals   []string `json:"signals,omitempty"`

	// PeersUnreadable is the subset of Peers for which NO card exists, because
	// the peer's half did not pass the read gate. It is a subset, not a
	// removal: the link is a fact recorded on this result and deleting it
	// would make "not linked" and "linked to something you cannot fetch yet"
	// the same observation.
	//
	// CRITIQUE-03 m3: a card is documented as self-contained, and one that
	// asserts `verified: true` against evidence the read gate has not opened
	// is asserting something the consumer cannot check. Caveat says so in
	// prose as well.
	PeersUnreadable []string `json:"peersUnreadable,omitempty"`

	Confidence float64 `json:"confidence"`
	// Verified is true only when a stack-trace match or a re-run flip is
	// present. Confidence alone never qualifies (plan/00-SPINE.md S7).
	//
	// It is CLAMPED, not copied: contract.go's Validate() rejects a record
	// whose correlation claims verification with no sufficient signal, but the
	// card is what the agent receives and a malformed producer, a hand-edited
	// row or a future column default must not be able to hand it an unearned
	// `verified`. Same reasoning as the host clamp; see cardCorrelation.
	Verified bool   `json:"verified"`
	Caveat   string `json:"caveat,omitempty"`

	// Merged is always false and is emitted explicitly rather than omitted,
	// because "the field is absent" and "we did not merge" are different
	// statements to a reader.
	Merged bool `json:"merged"`
}

// CardTrust classifies the card's own strings, by RFC 6901 pointer relative to
// the card.
//
// The default is TrustUntrusted, unconditionally. A card exists to be pasted
// into a repo-credentialed agent's context, and almost everything interesting
// on it — the source snippet, the context region, the advisory text, the
// response excerpt — originated outside Anvil. The record's TrustAssertion
// cannot be copied across verbatim because its pointers address the RESULT
// object and these address the CARD, so the classification is rebuilt here
// with the conservative default and an explicit list of the few strings Anvil
// itself wrote.
type CardTrust struct {
	Default Trust            `json:"default"`
	Fields  map[string]Trust `json:"fields,omitempty"`
}

// ---------------------------------------------------------------------------
// Building cards
// ---------------------------------------------------------------------------

// CardsFromLog builds every Tier-1 card from an already-loaded record, in the
// deterministic read order: correlated clusters first, then SAST-only by rank,
// then DAST-only by rank.
func (rd *Reader) CardsFromLog(l *SARIFLog) ([]TaskCard, error) {
	if l == nil {
		return nil, fmt.Errorf("record: CardsFromLog got a nil *SARIFLog")
	}
	// readOrder is where the read gate is applied, so everything below this
	// line is already past it: a half the gate refused contributes no
	// orderedResult and therefore no card.
	order := rd.readOrder(l)
	clusters := clustersOf(order)
	readable := readableFindingIDs(order)

	cards := make([]TaskCard, 0, len(order))
	for i, o := range order {
		c, err := rd.buildCard(l, i, o, clusters[o.clusterID], readable)
		if err != nil {
			return nil, err
		}
		cards = append(cards, c)
	}
	return cards, nil
}

// clustersOf groups an already-ordered result set by cluster id. Both tiers
// call it, so the manifest's view of a cluster and the card's view are the
// same set — see cardActionable for why that matters.
func clustersOf(order []orderedResult) map[string][]orderedResult {
	clusters := map[string][]orderedResult{}
	for _, o := range order {
		if o.clusterID != "" {
			clusters[o.clusterID] = append(clusters[o.clusterID], o)
		}
	}
	return clusters
}

// readableFindingIDs is the set of findings that survived the read gate, i.e.
// the exact set for which a card exists. cardCorrelation uses it to mark a
// peer the consumer cannot fetch.
func readableFindingIDs(order []orderedResult) map[string]bool {
	out := make(map[string]bool, len(order))
	for _, o := range order {
		out[o.result.Properties.FindingID] = true
	}
	return out
}

// isActionable is the gate: may the coding agent propose a patch for r?
//
// Three independent conditions, each of which alone withholds the finding:
//
//  1. Not a host finding. plan/00-SPINE.md S7 — the host agent is read-only.
//  2. remediable_by_agent is true in the record.
//  3. The verdict is true_positive. The consumption pipeline drops
//     false_positive and demotes insufficient_context to report-only
//     (contract.go, Verdict); report-only is not actionable.
func isActionable(r *Result) bool {
	return !IsHostFinding(r) &&
		r.Properties.RemediableByAgent &&
		r.Properties.Verdict == VerdictTruePositive
}

// staticPeerFor returns the cluster peer whose static evidence r must BORROW
// to have a file and a line at all, or nil when r has its own (or when the
// cluster offers none).
//
// It is the single definition of "this card's locus is inferred, not
// observed"; buildCard, cardActionable and the manifest all ask it, so the
// three cannot disagree about which member of a cluster owns the patch site.
func staticPeerFor(r *Result, cluster []orderedResult) *Result {
	if hasStaticEvidence(r) {
		return nil
	}
	for _, peer := range cluster {
		if peer.result != r && hasStaticEvidence(peer.result) {
			return peer.result
		}
	}
	return nil
}

// cardActionable is THE read-path actionability gate: isActionable, plus the
// borrowed-locus withholding below. Every tier asks this function — the card's
// Actionable field and the manifest's CardRef.Actionable — so the read order
// and the cards can never disagree about what the agent may act on.
//
// # Why a borrowed locus withholds the action (CRITIQUE-03 m1)
//
// A DAST-only member of a cluster has no file and no line of its own. It
// borrows its SAST peer's path, line range, enclosing symbol and snippet so
// that the card stays self-contained, which is what research/18's annotated
// Tier-1 card shows and is genuinely what an agent needs to understand the
// finding. But both members were then independently actionable and pointed at
// the same line, so one defect produced TWO patch tasks writing proposals into
// two different `result.fixes` arrays, and two `handoff` rows charged twice
// against the budget R.11's reservation is dividing. `group_id` is the
// mechanism that would collapse them and it is RESERVED for the consumption
// pipeline, so nothing collapses them here.
//
// The borrowed side is withheld rather than the borrowing being removed,
// because the locus is INFERRED for that finding — the DAST result did not
// observe app/db.py:412, the correlation concluded it — and handing an agent
// an inferred location as a patch site is presenting inference as observation.
// The SAST peer, which observed the line and (by the same borrowing, in the
// other direction) carries the DAST reproduction as its accept oracle, is
// strictly the better task and stays actionable.
//
// This is the ONE legal direction of divergence between a card and the record,
// named in this file's header: a card may withhold an action the record
// allows, never grant one it does not. CheckAgainstRecord therefore does not
// report it.
func cardActionable(r *Result, cluster []orderedResult) (bool, []string) {
	blockers := actionBlockers(r)
	actionable := isActionable(r)
	if peer := staticPeerFor(r, cluster); peer != nil {
		if actionable {
			var clusterID string
			if co := r.Properties.Correlation; co != nil {
				clusterID = co.ClusterID
			}
			blockers = append(blockers, fmt.Sprintf(
				"corroborating half of cluster %q: this finding's locus is BORROWED from peer %q, "+
					"which observed the file and line and carries the actionable card; "+
					"patching from both members would write two proposals for one defect",
				clusterID, peer.Properties.FindingID))
		}
		actionable = false
	}
	return actionable, blockers
}

// actionBlockers explains a false isActionable, in a fixed order so the text
// is deterministic.
func actionBlockers(r *Result) []string {
	var out []string
	if IsHostFinding(r) {
		out = append(out, fmt.Sprintf(
			"host finding: the host agent is read-only (00-SPINE.md S7), so %s is false for it and no patch may be proposed",
			PropResultRemediableByAgent))
	}
	if !r.Properties.RemediableByAgent && !IsHostFinding(r) {
		out = append(out, fmt.Sprintf("%s is false in the record", PropResultRemediableByAgent))
	}
	switch r.Properties.Verdict {
	case VerdictFalsePositive:
		out = append(out, fmt.Sprintf("%s is %q: dropped by the consumption pipeline",
			PropResultVerdict, VerdictFalsePositive))
	case VerdictInsufficientContext:
		out = append(out, fmt.Sprintf("%s is %q: report-only, never silently dropped",
			PropResultVerdict, VerdictInsufficientContext))
	}
	return out
}

// deriveConsumptionClass maps a finding onto the gate R.4 stores on the
// handoff row.
//
// A finding carrying a reproduction is RequiresDynamicConfirmation: it has a
// dynamic accept oracle, and plan/00-SPINE.md S7 says only that reproduction
// failing afterwards earns "verified fixed" — a compile-and-test pass does
// not. Everything else is StaticOnly, which is the class research/24's triage
// gate operates on.
//
// This is DERIVED. `handoff.consumption_class` is authoritative; if the two
// ever disagree, the stored row wins for the same reason the record wins over
// the card.
func deriveConsumptionClass(r *Result) ConsumptionClass {
	if r.Properties.Repro != nil || r.Properties.EvidenceClass == EvidenceClassDastConfirmed {
		return ConsumptionClassRequiresDynamicConfirmation
	}
	return ConsumptionClassStaticOnly
}

func (rd *Reader) buildCard(l *SARIFLog, position int, o orderedResult, cluster []orderedResult, readable map[string]bool) (TaskCard, error) {
	r := o.result
	p := &r.Properties
	actionable, blockers := cardActionable(r, cluster)

	c := TaskCard{
		CardVersion:      CardVersion,
		AuditID:          l.Properties.AuditID,
		FindingID:        p.FindingID,
		Bucket:           o.bucket,
		Position:         position,
		Half:             p.Half,
		ClusterID:        o.clusterID,
		GroupID:          p.GroupID,
		Rank:             o.rank,
		EvidenceClass:    p.EvidenceClass,
		Verdict:          p.Verdict,
		Confidence:       p.Confidence,
		ConsumptionClass: deriveConsumptionClass(r),
		// THE CLAMP. Never true for a host finding, whatever the record says.
		RemediableByAgent: p.RemediableByAgent && !IsHostFinding(r),
		Actionable:        actionable,
		ActionBlockers:    blockers,
		Task:              r.Message.Text,
		Fingerprint: CardFingerprint{
			AnvilFindingID:          r.PartialFingerprints[PartialFingerprintAnvilFindingID],
			PrimaryLocationLineHash: r.PartialFingerprints[PartialFingerprintPrimaryLocationLineHash],
			RegionSha256:            r.PartialFingerprints[PartialFingerprintRegionSHA256],
		},
		Constraints: p.PatchContext,
		Risk:        p.Risk,
		WriteBackTo: fmt.Sprintf("/runs/%d/results/%d/fixes", o.runIndex, o.resultIndex),
		Blobs:       map[string][]byte{},
	}
	c.Rule = cardRule(o.run, r)

	// A cluster member's card carries its PEER's evidence as well as its own,
	// so that one card is self-contained (research/18's annotated Tier-1 card
	// has both halves in it). This is NOT a merge: both findings remain
	// separate results in the record and each gets its own card. The card is a
	// read-side convenience; the record's link is the fact.
	//
	// Borrowed evidence is LABELLED, never passed off as this finding's own
	// observation — CardStatic.FindingID and CardLocus.BorrowedFrom both name
	// the peer it came from — and a borrowed LOCUS withholds the action. See
	// cardActionable.
	staticFrom, dynamicFrom := r, r
	if peer := staticPeerFor(r, cluster); peer != nil {
		staticFrom = peer
	}
	for _, peer := range cluster {
		if peer.result == r {
			continue
		}
		if dynamicFrom == r && !hasDynamicEvidence(r) && hasDynamicEvidence(peer.result) {
			dynamicFrom = peer.result
		}
	}

	if hasStaticEvidence(staticFrom) {
		c.Static = cardStatic(staticFrom)
	}
	if hasDynamicEvidence(dynamicFrom) {
		c.Dynamic = cardDynamic(dynamicFrom)
	}
	c.Locus = cardLocus(staticFrom, r)
	if staticFrom != r {
		c.Locus.BorrowedFrom = staticFrom.Properties.FindingID
	}
	c.Advisory = cardAdvisory(r)
	c.Correlation = cardCorrelation(r, cluster, readable)
	c.Trust = cardTrust(&c)

	if err := rd.fitCard(&c); err != nil {
		return TaskCard{}, err
	}
	return c, nil
}

func hasStaticEvidence(r *Result) bool { return primaryPath(r) != "" }

func hasDynamicEvidence(r *Result) bool {
	return r.Properties.Repro != nil || r.WebRequest != nil || r.WebResponse != nil
}

func cardRule(run *Run, r *Result) *CardRule {
	if r.RuleID == "" {
		return nil
	}
	out := &CardRule{ID: r.RuleID}
	for i := range run.Tool.Driver.Rules {
		rule := &run.Tool.Driver.Rules[i]
		if rule.ID != r.RuleID {
			continue
		}
		out.Name = rule.Name
		out.HelpURI = rule.HelpURI
		if rule.ShortDescription != nil {
			out.Description = rule.ShortDescription.Text
		}
		break
	}
	return out
}

func cardStatic(r *Result) *CardStatic {
	s := &CardStatic{
		FindingID:  r.Properties.FindingID,
		File:       primaryPath(r),
		Confidence: r.Properties.Confidence,
		Reasoning:  r.Properties.Reasoning,
	}
	if loc := primaryPhysical(r); loc != nil {
		if loc.Region != nil {
			s.StartLine, s.EndLine = loc.Region.StartLine, loc.Region.EndLine
			if loc.Region.Snippet != nil {
				s.Code = loc.Region.Snippet.Text
			}
		}
		if loc.ContextRegion != nil {
			ctx := &CardContext{StartLine: loc.ContextRegion.StartLine, EndLine: loc.ContextRegion.EndLine}
			if loc.ContextRegion.Snippet != nil {
				ctx.Text = loc.ContextRegion.Snippet.Text
			}
			s.Context = ctx
		}
	}
	s.Symbol = enclosingSymbol(r)
	s.TaintPath = taintPath(r)
	return s
}

func cardDynamic(r *Result) *CardDynamic {
	d := &CardDynamic{FindingID: r.Properties.FindingID, Confidence: r.Properties.Confidence}
	if req := r.WebRequest; req != nil {
		d.Method, d.URL = req.Method, req.Target
		if req.Body != nil {
			d.RequestBody = req.Body.Text
		}
	}
	if resp := r.WebResponse; resp != nil {
		d.StatusCode = resp.StatusCode
		if resp.Body != nil {
			d.ResponseExcerpt = resp.Body.Text
		}
	}
	if rp := r.Properties.Repro; rp != nil {
		d.Payload, d.PayloadEncoding = rp.Payload, rp.PayloadEncoding
		d.InjectionPoint = string(rp.InjectionPoint.Kind)
		if rp.InjectionPoint.Name != "" {
			d.InjectionPoint += ":" + rp.InjectionPoint.Name
		}
		d.ObservedSignal = rp.ObservedSignal.Kind
		if rp.ObservedSignal.Match != nil {
			d.Observed = rp.ObservedSignal.Match.Text
		}
		d.ResponseBodyRef = rp.ObservedSignal.BodySha256
		if rp.Baseline != nil {
			d.BaselineStatusCode = rp.Baseline.StatusCode
		}
		d.Steps = rp.Steps
		d.Curl = rp.Curl
		d.ExpectedAfterFix = rp.ExpectedAfterFix
		d.SideEffects = rp.SideEffects
		env := rp.Env
		d.Env = &env
	}
	return d
}

// cardLocus fills research/24's locus.*. Path, lines and enclosing symbol come
// from the SARIF-native slots of the finding that HAS them (the SAST peer, for
// a DAST-only card in a cluster); proximity_class comes from the card's own
// finding, because it is that finding's grouping input.
func cardLocus(staticFrom, own *Result) CardLocus {
	lo := CardLocus{Path: primaryPath(staticFrom), EnclosingSymbol: enclosingSymbol(staticFrom)}
	if loc := primaryPhysical(staticFrom); loc != nil && loc.Region != nil {
		lo.StartLine, lo.EndLine = loc.Region.StartLine, loc.Region.EndLine
	}
	if own.Properties.Locus != nil {
		lo.ProximityClass = own.Properties.Locus.ProximityClass
	}
	return lo
}

func cardAdvisory(r *Result) *CardAdvisory {
	taxa := taxonIDs(r)
	a := r.Properties.Advisory
	if a == nil && len(taxa) == 0 {
		return nil
	}
	out := &CardAdvisory{Taxa: taxa}
	if a == nil {
		return out
	}
	out.IDs, out.CveIDs = a.IDs, a.CveIDs
	out.SourceFeed, out.LicenseSpdx = a.SourceFeed, a.LicenseSpdx
	out.AsOf = formatTime(a.AsOf)
	out.StalenessSeconds, out.ParseDegraded = a.StalenessSeconds, a.ParseDegraded
	if a.Excerpt != nil {
		out.Excerpt = a.Excerpt.Text
	}
	return out
}

func cardCorrelation(r *Result, cluster []orderedResult, readable map[string]bool) *CardCorrelation {
	co := r.Properties.Correlation
	if co == nil {
		return nil
	}
	// THE VERIFIED CLAMP. verificationOf is correlation.go's own predicate,
	// which asks CorrelationSignal.SufficientForVerified and nothing else —
	// never a second copy of the rule. The record's bit can only be withheld
	// here, never granted, which is the one legal direction of divergence.
	earned, _ := verificationOf(co.Signals)
	out := &CardCorrelation{
		ClusterID:  co.ClusterID,
		Role:       co.Role,
		Confidence: co.Confidence,
		Verified:   co.Verified && earned,
		Caveat:     co.Caveat,
		Merged:     false,
	}
	for _, s := range co.Signals {
		out.Signals = append(out.Signals, string(s.Name))
	}
	seen := map[string]bool{r.Properties.FindingID: true}
	for _, id := range co.Peers {
		if !seen[id] {
			seen[id] = true
			out.Peers = append(out.Peers, id)
		}
	}
	// The cluster as actually assembled is the better peer list when the
	// record's own Peers array is empty or stale; both are unioned, then
	// sorted so the card is byte-stable.
	for _, m := range cluster {
		id := m.result.Properties.FindingID
		if !seen[id] {
			seen[id] = true
			out.Peers = append(out.Peers, id)
		}
	}
	sort.Strings(out.Peers)

	// A peer named here that has no card is a peer the read gate refused. Say
	// so, on the card, in both the machine-readable list and the caveat prose.
	for _, id := range out.Peers {
		if !readable[id] {
			out.PeersUnreadable = append(out.PeersUnreadable, id)
		}
	}
	if len(out.PeersUnreadable) > 0 {
		note := fmt.Sprintf(
			"peers %s are linked to this finding but their half has not passed the read gate, "+
				"so no task card exists for them and this link cannot be checked against their evidence yet",
			strings.Join(out.PeersUnreadable, ", "))
		if out.Caveat == "" {
			out.Caveat = note
		} else {
			out.Caveat += "; " + note
		}
	}
	return out
}

// cardTrust classifies the card's strings: untrusted by default, with an
// explicit list of the strings Anvil itself generated.
func cardTrust(c *TaskCard) CardTrust {
	t := CardTrust{Default: TrustUntrusted, Fields: map[string]Trust{}}
	if c.Task != "" {
		t.Fields["/task"] = TrustAnvilGenerated
	}
	if c.Static != nil && c.Static.Reasoning != "" {
		t.Fields["/static/reasoning"] = TrustAnvilGenerated
	}
	if len(t.Fields) == 0 {
		t.Fields = nil
	}
	return t
}

func primaryPhysical(r *Result) *PhysicalLocation {
	for i := range r.Locations {
		if r.Locations[i].PhysicalLocation != nil {
			return r.Locations[i].PhysicalLocation
		}
	}
	return nil
}

func enclosingSymbol(r *Result) string {
	for i := range r.Locations {
		for _, ll := range r.Locations[i].LogicalLocations {
			if ll.FullyQualifiedName != "" {
				return ll.FullyQualifiedName
			}
			if ll.Name != "" {
				return ll.Name
			}
		}
	}
	return ""
}

// taintPath flattens the first code flow to one "path:line symbol-or-snippet"
// string per step — research/18's `taintPath` array.
func taintPath(r *Result) []string {
	var out []string
	for _, cf := range r.CodeFlows {
		for _, tf := range cf.ThreadFlows {
			for _, tfl := range tf.Locations {
				pl := tfl.Location.PhysicalLocation
				if pl == nil {
					continue
				}
				step := pl.ArtifactLocation.URI
				if pl.Region != nil && pl.Region.StartLine > 0 {
					step += ":" + strconv.Itoa(pl.Region.StartLine)
				}
				switch {
				case pl.Region != nil && pl.Region.Snippet != nil && pl.Region.Snippet.Text != "":
					step += " " + strings.TrimSpace(pl.Region.Snippet.Text)
				case tfl.Location.Message != nil && tfl.Location.Message.Text != "":
					step += " " + tfl.Location.Message.Text
				}
				out = append(out, step)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Fitting a card inside its budget
// ---------------------------------------------------------------------------

// fitCard enforces, in order:
//
//  1. The INLINE CAPS. The advisory excerpt at research/24's <=800 tokens; the
//     request body at MaxInlineRequestBodyBytes and the response excerpt at
//     MaxInlineResponseBodyBytes, which are R.8's ZAP-derived caps. These
//     apply whatever the card's total size is, because they are about what may
//     be inlined at all, not about what fits.
//
//  2. The TOKEN BUDGET, by spilling fields in a fixed order, least to most
//     load-bearing for writing the patch:
//
//     reasoning — the detector's prose; the agent re-derives it from the code.
//     taintPath — navigational; the locus already names the sink.
//     context   — the surrounding region; the snippet still names the defect.
//     excerpt   — advisory prose.
//     response  — the observed evidence span, which the repro can regenerate.
//     request   — the request body, which `curl` already carries.
//     code      — the defect snippet. LAST: without it the card cannot do its
//     one job, and a card that has spilled its code is a card
//     the agent must make a Tier-2 fetch to use.
//
// Every step writes the spilled text to a Tier-2 blob and records a TierSpill.
// If the card is still over budget afterwards, it is an error unless
// Reader.AllowOversizeTier1 carries an explicit reason.
func (rd *Reader) fitCard(c *TaskCard) error {
	if c.Advisory != nil {
		if err := rd.capCardText(c, "/advisory/excerpt", &c.Advisory.Excerpt, MaxAdvisoryExcerptBytes); err != nil {
			return err
		}
	}
	if c.Dynamic != nil {
		if err := rd.capCardText(c, "/dynamic/requestBody", &c.Dynamic.RequestBody, MaxInlineRequestBodyBytes); err != nil {
			return err
		}
		if err := rd.capCardText(c, "/dynamic/responseExcerpt", &c.Dynamic.ResponseExcerpt, MaxInlineResponseBodyBytes); err != nil {
			return err
		}
	}

	steps := []struct {
		field string
		take  func(*TaskCard) (string, bool)
	}{
		{"/static/reasoning", func(c *TaskCard) (string, bool) {
			if c.Static == nil || c.Static.Reasoning == "" {
				return "", false
			}
			v := c.Static.Reasoning
			c.Static.Reasoning = ""
			return v, true
		}},
		{"/static/taintPath", func(c *TaskCard) (string, bool) {
			if c.Static == nil || len(c.Static.TaintPath) == 0 {
				return "", false
			}
			v := strings.Join(c.Static.TaintPath, "\n")
			c.Static.TaintPath = nil
			return v, true
		}},
		{"/static/context/text", func(c *TaskCard) (string, bool) {
			if c.Static == nil || c.Static.Context == nil || c.Static.Context.Text == "" {
				return "", false
			}
			v := c.Static.Context.Text
			c.Static.Context.Text = ""
			return v, true
		}},
		{"/advisory/excerpt", func(c *TaskCard) (string, bool) {
			if c.Advisory == nil || c.Advisory.Excerpt == "" {
				return "", false
			}
			v := c.Advisory.Excerpt
			c.Advisory.Excerpt = ""
			return v, true
		}},
		{"/dynamic/responseExcerpt", func(c *TaskCard) (string, bool) {
			if c.Dynamic == nil || c.Dynamic.ResponseExcerpt == "" {
				return "", false
			}
			v := c.Dynamic.ResponseExcerpt
			c.Dynamic.ResponseExcerpt = ""
			return v, true
		}},
		{"/dynamic/requestBody", func(c *TaskCard) (string, bool) {
			if c.Dynamic == nil || c.Dynamic.RequestBody == "" {
				return "", false
			}
			v := c.Dynamic.RequestBody
			c.Dynamic.RequestBody = ""
			return v, true
		}},
		{"/static/code", func(c *TaskCard) (string, bool) {
			if c.Static == nil || c.Static.Code == "" {
				return "", false
			}
			v := c.Static.Code
			c.Static.Code = ""
			return v, true
		}},
	}

	size, err := measureCard(c)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if size <= MaxTier1CardBytes {
			break
		}
		text, ok := st.take(c)
		if !ok {
			continue
		}
		// A field the inline caps already spilled is NOT spilled twice: the
		// full bytes are in Tier 2 under the reference already recorded, and a
		// second blob holding the truncated prefix of the same field would
		// make Spills name one field twice with two different contents.
		if !hasSpill(c.Spills, st.field) {
			if err := rd.spillBytes(&c.Spills, c.Blobs, st.field, []byte(text), 0); err != nil {
				return err
			}
		}
		if size, err = measureCard(c); err != nil {
			return err
		}
	}

	if size > MaxTier1CardBytes {
		if rd.AllowOversizeTier1 == "" {
			return &BudgetError{
				Tier: "tier-1 task card", Subject: c.FindingID,
				Bytes: size, Budget: MaxTier1CardBytes,
				Tokens: ApproxTokens(size), MaxTok: MaxTier1CardTokens,
			}
		}
		c.Override = &BudgetOverride{Reason: rd.AllowOversizeTier1, Bytes: size, Budget: MaxTier1CardBytes}
		if _, err = measureCard(c); err != nil {
			return err
		}
	}
	return nil
}

// measureCard is measureManifest for a card: it stamps the measurement into
// the card and returns the size the card actually has once stamped. See
// measureManifest for why the stamp has to be inside the measurement.
func measureCard(c *TaskCard) (int, error) {
	size, err := measure(c)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 8; i++ {
		c.Bytes, c.Tokens = size, ApproxTokens(size)
		next, err := measure(c)
		if err != nil {
			return 0, err
		}
		if next == size {
			return size, nil
		}
		size = next
	}
	c.Bytes, c.Tokens = size, ApproxTokens(size)
	return measure(c)
}

func hasSpill(spills []TierSpill, field string) bool {
	for _, s := range spills {
		if s.Field == field {
			return true
		}
	}
	return false
}

// capCardText enforces one inline cap: text longer than limit keeps a prefix
// plus an in-band pointer, and the FULL text becomes a Tier-2 blob.
//
// The in-band notice is R.8's truncationNotice, byte for byte, so a reader
// meets one truncation spelling across the record and the read path rather
// than two.
func (rd *Reader) capCardText(c *TaskCard, field string, dst *string, limit int) error {
	if dst == nil || len(*dst) <= limit {
		return nil
	}
	full := *dst
	if err := rd.spillBytes(&c.Spills, c.Blobs, field, []byte(full), 0); err != nil {
		return err
	}
	ref := c.Spills[len(c.Spills)-1].Ref
	budget := limit - len(truncationNotice(limit, len(full), ref))
	if budget < 0 {
		budget = 0
	}
	inline := truncateToRuneBoundary(full, budget)
	*dst = inline + truncationNotice(len(inline), len(full), ref)
	return nil
}

// ---------------------------------------------------------------------------
// The record wins
// ---------------------------------------------------------------------------

// ActionableTaskCards returns the cards the coding agent may act on.
//
// It exists so that "filter the cards" is one call with one definition rather
// than a predicate each caller writes for itself — the second copy of a
// predicate is how a host finding ends up in front of a read-only agent.
func ActionableTaskCards(cards []TaskCard) []TaskCard {
	out := make([]TaskCard, 0, len(cards))
	for _, c := range cards {
		if c.Actionable {
			out = append(out, c)
		}
	}
	return out
}

// CheckAgainstRecord reports every place this card contradicts the result it
// was derived from.
//
// THE RECORD WINS. This function never repairs anything and never touches the
// record; it names the disagreements so a caller can rebuild the card, which
// is the only correct repair.
//
// One asymmetry is deliberate and is NOT reported: a card may be LESS
// permissive than the record — RemediableByAgent false where the record says
// true, Actionable false where the record would allow it. That is the host
// clamp and the verdict demotion, and both are safe by construction. The
// reverse — a card granting an action the record does not — is always an
// error.
func (c *TaskCard) CheckAgainstRecord(r *Result) error {
	if r == nil {
		return fmt.Errorf("record: CheckAgainstRecord got a nil *Result for card %q", c.FindingID)
	}
	var problems []string
	note := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.FindingID != r.Properties.FindingID {
		note("card is for finding %q but was checked against %q", c.FindingID, r.Properties.FindingID)
	}
	if c.EvidenceClass != r.Properties.EvidenceClass {
		note("evidenceClass: card %q, record %q", c.EvidenceClass, r.Properties.EvidenceClass)
	}
	if c.Verdict != r.Properties.Verdict {
		note("verdict: card %q, record %q", c.Verdict, r.Properties.Verdict)
	}
	if c.Half != r.Properties.Half {
		note("half: card %q, record %q", c.Half, r.Properties.Half)
	}
	if c.Confidence != r.Properties.Confidence {
		note("confidence: card %v, record %v", c.Confidence, r.Properties.Confidence)
	}
	if want := r.PartialFingerprints[PartialFingerprintAnvilFindingID]; c.Fingerprint.AnvilFindingID != want {
		note("fingerprint %s: card %q, record %q", PartialFingerprintAnvilFindingID,
			c.Fingerprint.AnvilFindingID, want)
	}
	if c.RemediableByAgent && !r.Properties.RemediableByAgent {
		note("%s is true on the card and false in the record; a card may withhold an action, never grant one",
			PropResultRemediableByAgent)
	}
	if c.RemediableByAgent && IsHostFinding(r) {
		note("%s is true on the card for a HOST finding; the host agent is read-only (00-SPINE.md S7)",
			PropResultRemediableByAgent)
	}
	if c.Actionable && !isActionable(r) {
		note("card is actionable but the record does not permit it (host=%t remediable=%t verdict=%q)",
			IsHostFinding(r), r.Properties.RemediableByAgent, r.Properties.Verdict)
	}
	if c.Correlation != nil && c.Correlation.Merged {
		note("correlation.merged is true; link, never merge")
	}
	// `verified` is an S7 gate of the same class as the host gate, so it gets
	// the same treatment: the card may not assert a verification the SIGNALS
	// do not earn, whatever bit the record carries. Checked against the
	// signals rather than against the record's own `verified` flag, because a
	// record whose flag is wrong is precisely the case this catches.
	if c.Correlation != nil && c.Correlation.Verified {
		co := r.Properties.Correlation
		if co == nil {
			note("correlation.verified is true on the card but the record carries no %s at all",
				PropResultCorrelation)
		} else if earned, _ := verificationOf(co.Signals); !earned {
			note("correlation.verified is true on the card but no %q or %q signal is present in the record; "+
				"confidence alone never qualifies (00-SPINE.md S7)",
				CorrelationSignalResponseStackTrace, CorrelationSignalRerunFlip)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("record: task card %q disagrees with the record, and the record wins: %s",
		c.FindingID, strings.Join(problems, "; "))
}
