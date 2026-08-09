// Correlation policy — LINK, NEVER MERGE (step R.12).
//
// # What this file owns
//
// The decision of whether one SAST finding and one DAST finding are assertions
// about the same underlying defect, and — when they are — the LINK object that
// records that assertion with a method, a weighted signal list, a confidence,
// and a verification claim. It owns nothing else. In particular it never
// rewrites, combines, drops, or reorders a Result: the inputs are read and the
// output is a separate []Cluster.
//
// research/18-unified-audit-record.md, "Correlation policy — link, never
// merge":
//
//  1. Both findings always survive in the record. The SAST finding owns the
//     file and line; the DAST finding owns the proof. Merging destroys exactly
//     the thing the other one contributes.
//  2. A link is an assertion with a method, a weighted signal list, and a
//     confidence. Never a silent hash collision.
//  3. Require >=2 independent signals (Table 2) before emitting a link at all.
//     CWE match alone is banned as a sole signal.
//  4. verified:true ONLY when the response body carried a stack trace naming
//     the same file as the SAST finding, or when a re-run of the recorded
//     webRequest after the patch flips from failing to passing. Everything
//     else is verified:false with a confidence float.
//  5. Report uncorrelated findings as uncorrelated. The MAJORITY of findings
//     will have no peer. That is the expected state, not a bug.
//
// # This file declares no policy of its own
//
// The >=2-signal rule, the CWE-only ban and the verified:true criteria are
// contract.go's, not this file's. Every candidate link is handed to
// contract.go's own validateCorrelation before it is emitted, and a link that
// fails it is dropped rather than downgraded. There is deliberately no second
// notion of "sufficient" here: a second copy of a rule is a second definition,
// which is how plan/IMPLEMENTATION-PLAN.md §6's ten defects happened.
// MinCorrelationSignals, CorrelationSignal and
// CorrelationSignal.SufficientForVerified are consumed, never re-derived.
//
// # PATENT RISK — NOT RESOLVED HERE, DELIBERATELY
//
// US10043004B2 (SAST/DAST correlation; priority 2015-01-30, granted
// 2018-08-07, expires approximately 2035; assignee Denim Group Ltd. /
// Coalfire Systems) is MATERIALLY SIMILAR to the mechanism implemented in this
// file: the patent's Endpoint DB stores path, HTTP method, filename and line
// number, compares "associated parameter objects", and compares vulnerability
// type "using the CWE standard taxonomy" — which is, respectively, the
// CorrelationSignalRouteTable, CorrelationSignalParameterName and
// CorrelationSignalCweMatch signals below.
//
// This is plan/40-record-and-storage.md, Open Questions #1, and R.12's packet
// forbids this step from attempting to resolve it. It is flagged, not settled.
// plan/00-SPINE.md S8 already names the patent and explicitly declines to
// resolve it via the Apache-2.0 licence choice. research/18 Risk #1's
// instruction is verbatim: "Escalate to the owner; do not assume this is
// fine." Open Questions #1 additionally requires escalation to the owner
// BEFORE this file's output ships in a release. R.15's critic verifies that
// this flag exists; it does not resolve it either.
//
// # Untrusted bytes never reach the output
//
// The strongest signal available, CorrelationSignalResponseStackTrace, is read
// out of the DAST half's response body — which plan/00-SPINE.md S7 names the
// highest-risk field in the system, "up to 32 KB of attacker-controlled bytes
// fed to a repo-credentialed agent". So:
//
//   - Response bytes and request parameter VALUES are read only to compute a
//     boolean. No byte of either is ever copied into a SignalWeight.Detail, a
//     VerificationMethod, a Caveat, or a ClusterID. Every string this file
//     emits is Anvil-generated (TrustAnvilGenerated) except the finding IDs it
//     was given and numeric CWE identifiers, which are re-checked to be
//     digits before use.
//   - The converse hazard is REAL AND NOT CLOSED HERE: an attacker who
//     controls the scanned target's response body can print a fabricated stack
//     trace naming any file in the repository, manufacturing the one signal
//     that is sufficient for Verified. See the note on stackTraceNamesLocus.
//
// Sources: research/18-unified-audit-record.md ("Correlation policy — link,
// never merge"; Table 2 — correlation signals, cost, and how each one fails;
// the annotated record's anvil/correlation block); plan/00-SPINE.md S7;
// plan/40-record-and-storage.md (Open Questions #1).
//
// (Free-floating file comment: contract.go carries the package doc.)
package record

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
)

// CorrelationMethodV1 is the value written to Correlation.Method. It names the
// algorithm that produced the link, so a consumer reading a stored record can
// tell which correlator asserted it. Versioned for the same reason
// FingerprintAlgV1 is: changing which signals are derived, or how, changes the
// meaning of every link already on the wire.
const CorrelationMethodV1 = "anvil-correlate/v1"

// ---------------------------------------------------------------------------
// Signal weights
// ---------------------------------------------------------------------------

// Signal weights, in [0,1). These are a DOCUMENTED PRIOR, NOT A MEASURED
// ACCURACY, and must not be cited as one.
//
// research/18 is explicit that no published measured accuracy exists for any
// SAST/DAST correlation technique ([S9][S10][S11][S12]) — which is the whole
// reason the policy is "link, never merge" rather than "merge above a
// threshold". The ordering below is Table 2's own ordering by specificity and
// by failure mode, and nothing finer should be read into the exact values:
//
//   - responseStackTrace and rerunFlip are the two that name the static locus
//     or re-observe the behaviour, and are the only two S7 lets set Verified.
//   - routeTable and callGraphReach tie a route to a symbol. Table 2 records
//     that both degrade on dynamic dispatch, reverse-proxy rewrites and
//     middleware fan-out.
//   - parameterName is a plain string compare that renamed or DTO-bound
//     parameters defeat.
//   - cweMatch is Table 2's "necessary, never sufficient": thousands of
//     CWE-89 pairs per repository. It is weighted near zero so that it cannot
//     lift a weak link's confidence, and contract.go bans it as a sole signal
//     independently of its weight.
//
// Changing a weight changes every confidence already stored. Treat an edit
// here as a CorrelationMethodV1 -> v2 event.
const (
	weightResponseStackTrace = 0.60
	weightRerunFlip          = 0.60
	weightRouteTable         = 0.30
	weightCallGraphReach     = 0.30
	weightParameterName      = 0.20
	weightCweMatch           = 0.05
)

// CorrelationSignalWeight returns the evidence weight of one correlation
// signal. An unrecognised signal weighs zero, so an unknown token can never
// raise a confidence; contract.go's ValidateCorrelationSignal rejects it
// outright one step earlier.
func CorrelationSignalWeight(s CorrelationSignal) float64 {
	switch s {
	case CorrelationSignalResponseStackTrace:
		return weightResponseStackTrace
	case CorrelationSignalRerunFlip:
		return weightRerunFlip
	case CorrelationSignalRouteTable:
		return weightRouteTable
	case CorrelationSignalCallGraphReach:
		return weightCallGraphReach
	case CorrelationSignalParameterName:
		return weightParameterName
	case CorrelationSignalCweMatch:
		return weightCweMatch
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Out-of-record evidence
// ---------------------------------------------------------------------------

// Evidence carries the three Table 2 signals that CANNOT be derived from two
// Results alone, because they are facts about the repository or about a later
// run rather than facts recorded in the findings themselves.
//
// Correlate passes the zero Evidence, which is a legal and common case: with
// no route table, no call graph and no re-run, only the three intrinsic
// signals (responseStackTrace, parameterName, cweMatch) are available. That is
// enough for a link, and — via responseStackTrace — enough for Verified.
//
// The zero value carries no entries and therefore asserts nothing. It never
// causes a link to be emitted and never causes one to be suppressed.
type Evidence struct {
	// Routes is the parsed route table: (method, template) -> handler symbol
	// and file. Table 2's "very low cost, one AST pass at scan time,
	// cacheable" signal. Producer: the attack-surface / route-extraction
	// subsystem (a different area); this file only consumes it.
	Routes []RouteBinding

	// Reachability is the call-graph edge set: handler symbol -> reachable
	// sink. Table 2 records that without a call graph, commercial tools
	// degrade to file-level matching; that degradation here is simply the
	// absence of the signal, never a silent substitution of a weaker one.
	Reachability []Reachability

	// RerunFlips are post-patch re-runs of a recorded reproduction. Only a
	// flip from FAILING to PASSING may set Verified (plan/00-SPINE.md S7:
	// "Only a DAST reproduction that now fails earns 'verified fixed.' A clean
	// SAST rescan does not.").
	RerunFlips []RerunFlip
}

// RouteBinding binds one route to the source location that handles it.
type RouteBinding struct {
	// Method is the HTTP method. Compared case-insensitively. EMPTY MEANS
	// "any method", which is how a framework's catch-all handler is expressed;
	// it is deliberately permissive because the alternative is to drop the
	// binding entirely.
	Method string
	// RouteTemplate is the route as the framework declares it, e.g.
	// "/api/users/{id}/orders". Canonicalised with CanonicalRouteTemplate
	// before comparison.
	RouteTemplate string
	// HandlerSymbol is the fully-qualified handler symbol, matched against a
	// SAST result's logicalLocations[].fullyQualifiedName.
	HandlerSymbol string
	// HandlerPath is the handler's repository-relative file, matched against a
	// SAST result's physicalLocation.artifactLocation.uri after
	// CanonicalRepoRelPath.
	HandlerPath string
}

// Reachability asserts a call-graph path from a route handler to a sink.
type Reachability struct {
	// FromSymbol is the handler symbol, which must also appear as a
	// RouteBinding.HandlerSymbol for the route in question — otherwise there
	// is nothing tying the reachability claim to the DAST finding, and the
	// signal does not fire.
	FromSymbol string
	// ToSymbol and ToPath identify the sink. Either may be empty; at least one
	// must match the SAST finding for the signal to fire.
	ToSymbol string
	ToPath   string
}

// RerunFlip records the outcome of re-running a recorded reproduction after a
// patch.
type RerunFlip struct {
	// DastFindingID is the finding whose reproduction was re-run. Required.
	DastFindingID string
	// SastFindingID scopes the flip to one static peer. If empty, the flip
	// applies to every static peer of DastFindingID — which is the honest
	// reading when the patch touched several files and nothing recorded which
	// one closed the hole.
	SastFindingID string
	// Flipped is true ONLY for a transition from failing to passing. A run
	// that still fails, a run that errored, and a run that was never performed
	// are all false. There is deliberately no third state: an unknown outcome
	// must not be able to set Verified.
	Flipped bool
}

// ---------------------------------------------------------------------------
// Link and Cluster
// ---------------------------------------------------------------------------

// Link is the pairwise assertion that ONE SAST finding and ONE DAST finding
// are about the same underlying defect. It is the unit at which all evidence
// is held and all policy is enforced; Cluster is a grouping of Links and
// derives everything it reports from them.
//
// A Link never contains a Result and never contains a copy of any field of
// one. It contains two finding IDs.
type Link struct {
	// SastFindingID and DastFindingID are ResultProperties.FindingID values.
	SastFindingID string
	DastFindingID string

	// Signals are the independent signals supporting this link, in
	// CorrelationSignalValues order, deduplicated. len(Signals) is always
	// >= MinCorrelationSignals and is never a lone CorrelationSignalCweMatch:
	// contract.go's validateCorrelation gates that, and a candidate that fails
	// it is dropped rather than emitted with a lower confidence.
	Signals []SignalWeight

	// Confidence is the noisy-OR combination of the signal weights, in [0,1).
	Confidence float64

	// Verified is true only when a signal satisfying
	// CorrelationSignal.SufficientForVerified is present. Confidence alone
	// never qualifies, however high.
	Verified bool

	// VerificationMethod names the signal that earned Verified, or is empty.
	VerificationMethod string

	// Caveat records why this link should or should not be trusted.
	// Anvil-generated text only.
	Caveat string
}

// Cluster is a connected component of Links: the set of findings that some
// chain of pairwise links ties together. It is the unit SARIF's per-result
// correlationGuid can express, since a result carries exactly one such GUID
// (SARIF §3.27.4, research/18: "result.correlationGuid is assigned per
// cluster, not per finding").
//
// NOTHING IS MERGED. SastFindingIDs and DastFindingIDs are lists of
// identifiers; every Result they name survives in the record untouched and is
// the only place its file, line, snippet, request, response and proof live.
// Merged is a field that is never assigned true anywhere in this package, and
// contract.go's validateCorrelation rejects a Correlation whose Merged is true
// even if some future caller sets it by hand.
//
// Fan-out is expected, not exceptional: Table 2 records that a middleware sink
// produces one DAST finding against N SAST findings. Such a component holds
// several Links, and Cluster's aggregates are deliberately the CONSERVATIVE
// combination of them (see Confidence and Verified).
type Cluster struct {
	// ClusterID is a deterministic RFC 9562 version-8 UUID derived from the
	// sorted member finding IDs. Same members, same id, on every host and in
	// every process; no clock, no randomness, no map iteration.
	ClusterID string

	// Method names the correlator. Always CorrelationMethodV1.
	Method string

	// SastFindingIDs and DastFindingIDs are the members, each sorted, each
	// deduplicated.
	SastFindingIDs []string
	DastFindingIDs []string

	// Links is every pairwise link in this component, sorted by
	// (SastFindingID, DastFindingID). This is where the per-pair evidence
	// lives and it is not summarised away.
	Links []Link

	// Signals is the UNION of the member links' signals, deduplicated, keeping
	// the highest weight seen for each, in CorrelationSignalValues order. It
	// describes the component as a whole and is therefore weaker than any
	// individual Link's list — read Links for the per-pair evidence.
	Signals []SignalWeight

	// Confidence is the MINIMUM link confidence in the component: a cluster is
	// only as trustworthy as the weakest assertion holding it together. Taking
	// the maximum, or a mean, would let one strong pair vouch for a chain of
	// weak ones.
	Confidence float64

	// Verified is true only when EVERY link in the component is verified.
	//
	// This can UNDER-claim — a stack-trace-verified pair joined by an
	// unverified third finding reports false — and that is the intended
	// direction. plan/00-SPINE.md S7 gates "verified fixed" on this bit, so an
	// over-claim is a correctness failure and an under-claim is a lost
	// opportunity. Per-finding verification is narrower still and is computed
	// by CorrelationFor from the incident links only.
	Verified bool

	// VerificationMethod names the signals that earned Verified, or is empty.
	VerificationMethod string

	// Merged is ALWAYS false. See the type comment.
	Merged bool

	// Caveat records why this cluster should or should not be trusted.
	Caveat string
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

// Correlate links SAST findings to DAST findings using only the evidence
// carried inside the findings themselves, and returns the resulting clusters.
//
// It NEVER merges: the returned clusters reference findings by ID, the input
// slices are not modified, and no Result is combined with, replaced by, or
// derived from another.
//
// Results are matched CROSS-HALF ONLY. Two SAST findings are never linked to
// each other and neither are two DAST findings; a same-half relationship is a
// different question (fix grouping, anvil/locus) owned by a different step.
//
// Inputs are read defensively, because this function has no error channel and
// silently producing a wrong link is worse than producing none:
//
//   - A result whose ResultProperties.FindingID is empty, or contains
//     FingerprintFieldSeparator, is skipped. It cannot be named as a peer, and
//     an id carrying the separator would make ClusterID ambiguous.
//   - A duplicate FindingID within one slice is skipped after its first
//     occurrence.
//   - The slice a result was passed in — not its ResultProperties.Half — is
//     what assigns its role, because the parameter names say so.
//
// The output is deterministic: same inputs in any order produce byte-identical
// clusters, ids included.
func Correlate(sast, dast []Result) []Cluster {
	return CorrelateWithEvidence(sast, dast, Evidence{})
}

// CorrelateWithEvidence is Correlate with the three out-of-record Table 2
// signals supplied: the route table, call-graph reachability, and post-patch
// re-run flips. See Evidence.
//
// Every guarantee documented on Correlate holds here unchanged; ev is read and
// never modified.
func CorrelateWithEvidence(sast, dast []Result, ev Evidence) []Cluster {
	sastViews := buildViews(sast, HalfSast)
	dastViews := buildViews(dast, HalfDast)
	if len(sastViews) == 0 || len(dastViews) == 0 {
		return nil
	}

	links := make([]Link, 0, len(sastViews))
	for _, s := range sastViews {
		for _, d := range dastViews {
			if l, ok := buildLink(s, d, ev); ok {
				links = append(links, l)
			}
		}
	}
	if len(links) == 0 {
		return nil
	}
	sortLinks(links)
	return groupIntoClusters(links, sastViews, dastViews)
}

// CorrelationFor returns the `anvil/correlation` property bag for one member
// of this cluster, ready to be written into ResultProperties.Correlation by
// the caller that owns the Result. It reports false if findingID is not a
// member.
//
// This function does not take a Result and cannot modify one. Writing the
// returned value onto a result — together with the SARIF-native
// result.correlationGuid, which contract.go's Validate requires alongside it —
// is the caller's step, and it is an ADDITION to the result, never a
// replacement of any part of it.
//
// The view is narrower than the cluster's own aggregate, on purpose:
//
//   - Peers are the DIRECT peers of findingID, i.e. the other-half findings it
//     is itself linked to. A finding two hops away in the component is a
//     cluster member but not a peer, because no evidence ties it to this
//     finding.
//   - Signals, Confidence and Verified are computed from the INCIDENT links
//     only, with the same conservative combination Cluster uses (union of
//     signals, minimum confidence, verified only if every incident link is
//     verified).
func (c Cluster) CorrelationFor(findingID string) (*Correlation, bool) {
	if findingID == "" {
		return nil, false
	}
	var role Half
	switch {
	case containsString(c.SastFindingIDs, findingID):
		role = HalfSast
	case containsString(c.DastFindingIDs, findingID):
		role = HalfDast
	default:
		return nil, false
	}

	var (
		incident []Link
		peers    []string
	)
	for _, l := range c.Links {
		switch {
		case role == HalfSast && l.SastFindingID == findingID:
			incident = append(incident, l)
			peers = append(peers, l.DastFindingID)
		case role == HalfDast && l.DastFindingID == findingID:
			incident = append(incident, l)
			peers = append(peers, l.SastFindingID)
		}
	}
	if len(incident) == 0 {
		// A member with no incident link cannot exist: membership is defined
		// by the links. Refuse rather than emit a peerless correlation.
		return nil, false
	}
	sort.Strings(peers)
	peers = dedupeSorted(peers)

	signals, confidence, verified, method := combineLinks(incident)
	return &Correlation{
		ClusterID:          c.ClusterID,
		Role:               role,
		Peers:              peers,
		Method:             c.Method,
		Signals:            signals,
		Confidence:         confidence,
		Verified:           verified,
		VerificationMethod: method,
		Merged:             false, // LINK, NEVER MERGE.
		Caveat:             caveatFor(signals, verified, len(incident)),
	}, true
}

// ---------------------------------------------------------------------------
// Link construction — one SAST finding against one DAST finding
// ---------------------------------------------------------------------------

func buildLink(s, d *findingView, ev Evidence) (Link, bool) {
	// Collected into a map so a signal detected twice by two routes counts
	// once. len(collected) is therefore the count of INDEPENDENT signals,
	// which is what MinCorrelationSignals means.
	collected := map[CorrelationSignal]SignalWeight{}
	add := func(name CorrelationSignal, detail string) {
		if _, ok := collected[name]; ok {
			return
		}
		collected[name] = SignalWeight{
			Name:   name,
			Weight: CorrelationSignalWeight(name),
			Detail: detail,
		}
	}

	if cwe, ok := sharedCWE(s, d); ok {
		add(CorrelationSignalCweMatch, "both findings carry CWE-"+cwe)
	}
	if stackTraceNamesLocus(s, d) {
		add(CorrelationSignalResponseStackTrace,
			"the recorded response names the static finding's source location")
	}
	if injectedParameterAppearsAtTaintSource(s, d) {
		add(CorrelationSignalParameterName,
			"the injected parameter name appears at the static taint source")
	}
	handlers := routeHandlers(d, ev)
	if routeBindsToLocus(s, handlers) {
		add(CorrelationSignalRouteTable,
			"the route table binds this route to the static finding's file or symbol")
	}
	if handlerReachesSink(s, handlers, ev) {
		add(CorrelationSignalCallGraphReach,
			"the route handler reaches the static sink in the call graph")
	}
	if rerunFlipped(s, d, ev) {
		add(CorrelationSignalRerunFlip,
			"the recorded reproduction flipped from failing to passing after the patch")
	}

	signals := orderSignals(collected)
	confidence := noisyOr(signals)
	verified, method := verificationOf(signals)

	link := Link{
		SastFindingID:      s.id,
		DastFindingID:      d.id,
		Signals:            signals,
		Confidence:         confidence,
		Verified:           verified,
		VerificationMethod: method,
		Caveat:             caveatFor(signals, verified, 1),
	}

	// THE GATE. contract.go's own rule set decides whether this link may
	// exist: at least MinCorrelationSignals signals, never a lone cweMatch,
	// Verified only with a SufficientForVerified signal, confidence in [0,1],
	// Merged false. A candidate that fails is DROPPED — never emitted with a
	// reduced confidence, never emitted with Verified cleared, because a link
	// that does not meet the policy is not a weaker link, it is not a link.
	probe := &Correlation{
		ClusterID:          "probe",
		Role:               HalfSast,
		Peers:              []string{d.id},
		Method:             CorrelationMethodV1,
		Signals:            link.Signals,
		Confidence:         link.Confidence,
		Verified:           link.Verified,
		VerificationMethod: link.VerificationMethod,
		Merged:             false,
	}
	if err := validateCorrelation(probe); err != nil {
		return Link{}, false
	}
	return link, true
}

// ---------------------------------------------------------------------------
// Signal derivation
// ---------------------------------------------------------------------------

// sharedCWE reports the lowest-numbered CWE identifier both findings carry.
//
// Table 2: "necessary, never sufficient — thousands of CWE-89 pairs per repo."
// It is derived here so that a link resting on route + parameter evidence can
// say the classes agree, and it is weighted and gated so that it can never
// carry a link by itself.
func sharedCWE(s, d *findingView) (string, bool) {
	for _, c := range s.cwes { // sorted at construction, so this is deterministic
		if containsString(d.cwes, c) {
			return c, true
		}
	}
	return "", false
}

// stackTraceNamesLocus reports whether the DAST half's recorded response text
// names the SAST finding's file or enclosing symbol.
//
// Table 2: "Response leaks File \"app/db.py\", line 412 ... near zero cost,
// regex over a body Anvil already stores." It is one of the two signals
// plan/00-SPINE.md S7 lets set verified:true.
//
// THE THREAT THIS DOES NOT DEFEND AGAINST, stated rather than hidden: the
// response body is attacker-controlled (S7 names it the highest-risk field in
// the system). A target that can print arbitrary bytes can print a fabricated
// stack trace naming any path in the repository, and thereby manufacture the
// signal that promotes a link to Verified. The mitigations applied here are
// partial and are not a fix:
//
//   - The match must be against a full repository-relative path or a full
//     fully-qualified symbol of at least minLocusTokenLen characters. A bare
//     basename such as "main.go" is not enough.
//   - Matching is case-sensitive, because target repositories are.
//   - Not one byte of the response reaches the output; only this boolean does.
//
// What would actually close it is an out-of-band check that the trace came
// from the code under test — an instrumented run, or a signed error channel.
// Neither exists in Anvil today. Recorded so a later reader does not mistake
// Verified for tamper-proof.
func stackTraceNamesLocus(s, d *findingView) bool {
	if len(d.traces) == 0 {
		return false
	}
	for _, trace := range d.traces {
		for _, p := range s.paths {
			if len(p) >= minLocusTokenLen && strings.Contains(trace, p) {
				return true
			}
		}
		for _, sym := range s.symbols {
			if len(sym) >= minLocusTokenLen && strings.Contains(trace, sym) {
				return true
			}
		}
	}
	return false
}

// injectedParameterAppearsAtTaintSource reports whether a parameter name the
// DAST half injected into appears as an identifier at the SAST half's taint
// SOURCE.
//
// Table 2: "DAST injected `username`; SAST threadFlow first location reads
// request.form[\"username\"]". Failure mode, quoted: "Renamed/wrapped params;
// body-schema binding to DTOs hides the name." Those produce a MISSING signal,
// never a wrong one.
//
// Deliberate narrowings:
//
//   - The SAST side is the FIRST threadFlowLocation of the FIRST codeFlow when
//     one exists — the taint source, as Table 2 specifies — and falls back to
//     the primary region snippet only when the finding carries no code flow at
//     all. The fallback is broader and therefore weaker; it is why this signal
//     is weighted below the route signals.
//   - Matching is on whole identifiers, not substrings, so `id` does not match
//     `idempotency_key`.
//   - Names shorter than minParameterNameLen are ignored entirely. A one- or
//     two-character parameter name matches almost any snippet, and a signal
//     that fires everywhere is not evidence.
func injectedParameterAppearsAtTaintSource(s, d *findingView) bool {
	for _, name := range d.paramNames { // sorted at construction
		if len(name) < minParameterNameLen {
			continue
		}
		if s.sourceTokens[name] {
			return true
		}
	}
	return false
}

// routeHandlers returns the handler symbols and files bound to the DAST
// finding's route by the supplied route table, sorted and deduplicated. It is
// empty when no route table was supplied or when nothing matches, and an empty
// result silently withholds both route-derived signals rather than
// substituting a weaker match.
func routeHandlers(d *findingView, ev Evidence) routeMatch {
	var m routeMatch
	if d.route == "" || len(ev.Routes) == 0 {
		return m
	}
	for _, b := range ev.Routes {
		method := strings.ToUpper(strings.TrimSpace(b.Method))
		// An empty binding method is a framework catch-all and matches any
		// method; anything else must match exactly.
		if method != "" && d.method != "" && method != d.method {
			continue
		}
		if CanonicalRouteTemplate(b.RouteTemplate) != d.route {
			continue
		}
		if sym := strings.TrimSpace(b.HandlerSymbol); sym != "" {
			m.symbols = append(m.symbols, sym)
		}
		if p := CanonicalRepoRelPath(b.HandlerPath); p != "" {
			m.paths = append(m.paths, p)
		}
	}
	sort.Strings(m.symbols)
	sort.Strings(m.paths)
	m.symbols = dedupeSorted(m.symbols)
	m.paths = dedupeSorted(m.paths)
	return m
}

// routeMatch is the handler set a route table binds to one DAST route.
type routeMatch struct {
	symbols []string
	paths   []string
}

func (m routeMatch) empty() bool { return len(m.symbols) == 0 && len(m.paths) == 0 }

// routeBindsToLocus reports whether the route's handler is the SAST finding's
// own file or symbol. Table 2's "route table -> handler symbol" signal, at the
// resolution the record actually carries.
func routeBindsToLocus(s *findingView, handlers routeMatch) bool {
	for _, sym := range handlers.symbols {
		if containsString(s.symbols, sym) {
			return true
		}
	}
	for _, p := range handlers.paths {
		if containsString(s.paths, p) {
			return true
		}
	}
	return false
}

// handlerReachesSink reports whether the call graph proves a path from the
// route's handler to the SAST finding's sink.
//
// It requires the handler to have been identified by the route table first:
// without that, a reachability edge says nothing about the DAST finding, and
// counting it would make callGraphReach a free second signal alongside
// anything at all. Table 2's failure modes — dynamic dispatch, ORM/reflection,
// DI containers, 1-DAST-to-N-SAST middleware fan-out — all manifest as this
// returning false.
func handlerReachesSink(s *findingView, handlers routeMatch, ev Evidence) bool {
	if handlers.empty() || len(ev.Reachability) == 0 {
		return false
	}
	for _, r := range ev.Reachability {
		from := strings.TrimSpace(r.FromSymbol)
		if from == "" || !containsString(handlers.symbols, from) {
			continue
		}
		if sym := strings.TrimSpace(r.ToSymbol); sym != "" && containsString(s.symbols, sym) {
			return true
		}
		if p := CanonicalRepoRelPath(r.ToPath); p != "" && containsString(s.paths, p) {
			return true
		}
	}
	return false
}

// rerunFlipped reports whether a recorded reproduction of the DAST finding was
// re-run after a patch and flipped from failing to passing.
//
// plan/00-SPINE.md S7: "Only a DAST reproduction that now fails earns 'verified
// fixed.' A clean SAST rescan does not." An entry whose Flipped is false — a
// run that still fails, a run that errored, a run never performed — is not a
// weaker signal, it is no signal.
func rerunFlipped(s, d *findingView, ev Evidence) bool {
	for _, f := range ev.RerunFlips {
		if !f.Flipped || f.DastFindingID != d.id {
			continue
		}
		if f.SastFindingID == "" || f.SastFindingID == s.id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Combination
// ---------------------------------------------------------------------------

// noisyOr combines independent signal weights as 1 - prod(1 - w).
//
// Chosen because it is deterministic, bounded in [0,1), monotone in adding
// evidence, and never reaches certainty however many signals agree — which is
// the right shape for a technique with NO published measured accuracy. It
// assumes the signals are independent, which Table 2 broadly supports (a route
// table, a parameter string and a leaked stack trace are different
// observations) but does not guarantee: a stack trace naming a file and a
// route table binding the same file are both statements about file identity,
// and this arithmetic double-counts that overlap. Recorded as a known
// limitation, not compensated for, because inventing a correlation matrix
// would be inventing measured accuracy.
//
// The result is rounded to confidenceDecimals places so that a stored
// confidence is stable under recomputation and readable in a golden.
func noisyOr(signals []SignalWeight) float64 {
	remaining := 1.0
	for _, s := range signals {
		w := s.Weight
		if w <= 0 {
			continue
		}
		if w > 1 {
			w = 1
		}
		remaining *= 1 - w
	}
	scale := math.Pow(10, confidenceDecimals)
	c := math.Round((1-remaining)*scale) / scale
	if c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}

// verificationOf reports whether the signal set earns Verified, and names the
// signals that did. It asks CorrelationSignal.SufficientForVerified and
// nothing else — there is no threshold on confidence here, and there must
// never be one: plan/00-SPINE.md S7 makes verification a question about the
// KIND of evidence, and a confidence float cannot answer it.
func verificationOf(signals []SignalWeight) (bool, string) {
	var names []string
	for _, s := range signals {
		if s.Name.SufficientForVerified() {
			names = append(names, string(s.Name))
		}
	}
	if len(names) == 0 {
		return false, ""
	}
	return true, strings.Join(names, "+")
}

// combineLinks reduces a set of links to one conservative view: the union of
// their signals, the MINIMUM of their confidences, and Verified only if EVERY
// link is verified. See Cluster.Verified for why the direction is this way.
func combineLinks(links []Link) (signals []SignalWeight, confidence float64, verified bool, method string) {
	if len(links) == 0 {
		return nil, 0, false, ""
	}
	union := map[CorrelationSignal]SignalWeight{}
	confidence = links[0].Confidence
	verified = true
	for _, l := range links {
		if l.Confidence < confidence {
			confidence = l.Confidence
		}
		if !l.Verified {
			verified = false
		}
		for _, s := range l.Signals {
			if prev, ok := union[s.Name]; !ok || s.Weight > prev.Weight {
				union[s.Name] = s
			}
		}
	}
	signals = orderSignals(union)
	if verified {
		_, method = verificationOf(signals)
	}
	return signals, confidence, verified, method
}

// caveatFor produces the Anvil-generated explanation of why a link or cluster
// should or should not be trusted. It never contains target-derived text.
func caveatFor(signals []SignalWeight, verified bool, linkCount int) string {
	var parts []string
	if !verified {
		parts = append(parts,
			"not verified: no "+string(CorrelationSignalResponseStackTrace)+
				" or "+string(CorrelationSignalRerunFlip)+
				" signal; confidence alone never qualifies and a clean SAST rescan never qualifies (00-SPINE.md S7)")
	}
	if onlyWeakNonCwe(signals) {
		parts = append(parts,
			"weak link: a parameter-name match is the only signal beyond the CWE class match, "+
				"and Table 2 records that renamed or DTO-bound parameters defeat it")
	}
	if linkCount > 1 {
		parts = append(parts, fmt.Sprintf(
			"aggregate of %d pairwise links; the per-pair evidence is in Links and is not summarised away",
			linkCount))
	}
	return strings.Join(parts, "; ")
}

// onlyWeakNonCwe reports whether parameterName is the sole signal beyond a CWE
// class match — the weakest link the policy still permits.
func onlyWeakNonCwe(signals []SignalWeight) bool {
	nonCwe := 0
	param := false
	for _, s := range signals {
		if s.Name == CorrelationSignalCweMatch {
			continue
		}
		nonCwe++
		if s.Name == CorrelationSignalParameterName {
			param = true
		}
	}
	return nonCwe == 1 && param
}

// ---------------------------------------------------------------------------
// Clustering
// ---------------------------------------------------------------------------

// groupIntoClusters partitions links into connected components.
//
// Connected components, rather than one cluster per pair, because SARIF gives
// a result exactly ONE correlationGuid: a finding that pairs with two peers
// cannot carry two cluster ids, so pairwise clusters would be unrepresentable
// on the wire. The cost of the choice is that a weak link can pull a finding
// into a component with a strong one, which is precisely why Cluster's
// aggregates take the minimum confidence and demand every link be verified.
func groupIntoClusters(links []Link, sastViews, dastViews []*findingView) []Cluster {
	// Union-find over namespaced keys, so a SAST and a DAST finding that
	// happen to share an id string cannot collide.
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		p, ok := parent[x]
		if !ok || p == x {
			parent[x] = x
			return x
		}
		root := find(p)
		parent[x] = root
		return root
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		// Deterministic tie-break: the lexicographically smaller root wins, so
		// component membership does not depend on link order.
		if ra < rb {
			parent[rb] = ra
		} else {
			parent[ra] = rb
		}
	}

	sastKey := func(id string) string { return string(HalfSast) + FingerprintFieldSeparator + id }
	dastKey := func(id string) string { return string(HalfDast) + FingerprintFieldSeparator + id }

	for _, l := range links {
		union(sastKey(l.SastFindingID), dastKey(l.DastFindingID))
	}

	grouped := map[string][]Link{}
	for _, l := range links {
		root := find(sastKey(l.SastFindingID))
		grouped[root] = append(grouped[root], l)
	}

	// Iterate over a SORTED key list: ranging a map directly would make the
	// output order depend on Go's per-process map seed.
	roots := make([]string, 0, len(grouped))
	for r := range grouped {
		roots = append(roots, r)
	}
	sort.Strings(roots)

	clusters := make([]Cluster, 0, len(roots))
	for _, r := range roots {
		members := grouped[r]
		sortLinks(members)

		var sastIDs, dastIDs []string
		for _, l := range members {
			sastIDs = append(sastIDs, l.SastFindingID)
			dastIDs = append(dastIDs, l.DastFindingID)
		}
		sort.Strings(sastIDs)
		sort.Strings(dastIDs)
		sastIDs = dedupeSorted(sastIDs)
		dastIDs = dedupeSorted(dastIDs)

		signals, confidence, verified, method := combineLinks(members)
		clusters = append(clusters, Cluster{
			ClusterID:          deriveClusterID(sastIDs, dastIDs),
			Method:             CorrelationMethodV1,
			SastFindingIDs:     sastIDs,
			DastFindingIDs:     dastIDs,
			Links:              members,
			Signals:            signals,
			Confidence:         confidence,
			Verified:           verified,
			VerificationMethod: method,
			Merged:             false, // LINK, NEVER MERGE.
			Caveat:             caveatFor(signals, verified, len(members)),
		})
	}

	sort.SliceStable(clusters, func(i, j int) bool {
		a, b := clusters[i], clusters[j]
		if a.SastFindingIDs[0] != b.SastFindingIDs[0] {
			return a.SastFindingIDs[0] < b.SastFindingIDs[0]
		}
		if a.DastFindingIDs[0] != b.DastFindingIDs[0] {
			return a.DastFindingIDs[0] < b.DastFindingIDs[0]
		}
		return a.ClusterID < b.ClusterID
	})
	return clusters
}

// deriveClusterID derives a deterministic RFC 9562 version-8 (custom) UUID
// from the cluster's sorted membership.
//
// A UUID shape is used because SARIF §3.27.4 types result.correlationGuid as a
// GUID. It is DERIVED rather than random so that re-running the correlator on
// an unchanged record yields the same ids — a random GUID would make every
// re-scan look like a new set of clusters. This is not a fingerprint, is not
// part of anvil-fp/v1, and must never be treated as one; it reuses
// FingerprintFieldSeparator solely because that is the package's one declared
// unambiguous field separator and a second copy of it would be a second
// definition.
func deriveClusterID(sastIDs, dastIDs []string) string {
	h := sha256.New()
	h.Write([]byte(CorrelationMethodV1))
	for _, id := range sastIDs {
		h.Write([]byte(FingerprintFieldSeparator))
		h.Write([]byte(string(HalfSast) + ":" + id))
	}
	for _, id := range dastIDs {
		h.Write([]byte(FingerprintFieldSeparator))
		h.Write([]byte(string(HalfDast) + ":" + id))
	}
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x80 // version 8: custom, RFC 9562 §5.8
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10x, RFC 9562 §4.1
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---------------------------------------------------------------------------
// Finding views — everything read out of a Result, read once
// ---------------------------------------------------------------------------

const (
	// minLocusTokenLen is the shortest path or symbol a response body may be
	// matched against. A short token ("db.py", "main.go") appears in
	// unrelated traces constantly, and this signal is one of the two that can
	// set Verified, so the bar is raised rather than lowered.
	minLocusTokenLen = 8

	// minParameterNameLen is the shortest injected parameter name that may
	// produce a signal. "id" and "q" appear in almost any snippet.
	minParameterNameLen = 3

	// confidenceDecimals is the precision a confidence is rounded to, so a
	// stored value is reproducible and diffable.
	confidenceDecimals = 4
)

// findingView is everything this file needs from one Result, extracted once so
// the O(SAST x DAST) comparison loop does no parsing and so every map in the
// pipeline is built once and only ever read by key.
type findingView struct {
	id string

	// paths are canonical repository-relative source paths. URIs carrying a
	// scheme (an http endpoint) are excluded: they are locations, not files.
	paths []string
	// symbols are fully-qualified logical location names.
	symbols []string
	// cwes are numeric CWE identifiers, sorted, deduplicated.
	cwes []string

	// DAST side.
	method     string   // upper-cased HTTP method, may be empty
	route      string   // canonicalised route template, may be empty
	paramNames []string // injected parameter names, sorted, deduplicated
	traces     []string // recorded response text, separator-normalised

	// SAST side. sourceTokens is a SET, read only by key — never ranged over,
	// because map iteration order is not stable across processes.
	sourceTokens map[string]bool
}

func buildViews(results []Result, half Half) []*findingView {
	views := make([]*findingView, 0, len(results))
	seen := map[string]bool{}
	for i := range results {
		r := &results[i]
		id := r.Properties.FindingID
		if id == "" || strings.Contains(id, FingerprintFieldSeparator) || seen[id] {
			continue
		}
		seen[id] = true
		views = append(views, newFindingView(r, id, half))
	}
	return views
}

func newFindingView(r *Result, id string, half Half) *findingView {
	v := &findingView{id: id}

	// Locations ONLY — never RelatedLocations.
	//
	// research/18's annotated record uses relatedLocations as "THE CROSS-HALF
	// POINTER": it is where a PREVIOUS correlation pass writes the peer's
	// location. Reading it back as evidence would be circular — the record's
	// own assertion that two findings are linked would become a reason to
	// assert that they are linked, and a single bad link would then be
	// self-sustaining across every re-scan. Only a finding's own locations
	// count as evidence about that finding.
	for _, loc := range r.Locations {
		v.absorbLocation(loc)
	}
	v.paths = sortedDedupe(v.paths)
	v.symbols = sortedDedupe(v.symbols)
	v.cwes = sortedDedupe(cweIDs(r))

	if half == HalfDast {
		v.method, v.route = dastRoute(r)
		v.paramNames = sortedDedupe(injectedParameterNames(r))
		v.traces = responseTexts(r)
		return v
	}

	v.sourceTokens = taintSourceTokens(r)
	return v
}

func (v *findingView) absorbLocation(loc Location) {
	if loc.PhysicalLocation != nil {
		if p := repoRelPath(loc.PhysicalLocation.ArtifactLocation.URI); p != "" {
			v.paths = append(v.paths, p)
		}
	}
	for _, ll := range loc.LogicalLocations {
		if n := strings.TrimSpace(ll.FullyQualifiedName); n != "" {
			v.symbols = append(v.symbols, n)
		}
	}
}

// repoRelPath canonicalises an artifact URI to a repository-relative path, or
// returns "" if the URI is an absolute URL (a DAST endpoint is a location, not
// a file, and treating one as a path would let an endpoint string match a
// stack trace).
func repoRelPath(uri string) string {
	u := strings.TrimSpace(uri)
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i > 0 {
		return ""
	}
	return CanonicalRepoRelPath(u)
}

// cweIDs returns the numeric CWE identifiers a result carries in its SARIF
// taxa. A taxon whose id is not a plain decimal number is ignored: this value
// is echoed into a SignalWeight.Detail and therefore into the record, and
// third-party SARIF is untrusted input (research/18 Risk #8).
func cweIDs(r *Result) []string {
	var out []string
	for _, t := range r.Taxa {
		if t.ToolComponent != nil && t.ToolComponent.Name != "" &&
			!strings.EqualFold(t.ToolComponent.Name, "CWE") {
			continue
		}
		id := strings.TrimSpace(t.ID)
		id = strings.TrimPrefix(id, "CWE-")
		id = strings.TrimPrefix(id, "cwe-")
		if id == "" || !isDecimal(id) {
			continue
		}
		out = append(out, id)
	}
	return out
}

func isDecimal(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// dastRoute extracts the HTTP method and canonical route template of a DAST
// finding, preferring the record's own PropLocationRouteTemplate (which the
// annotated record in research/18 writes as "POST /api/login") and falling
// back to the SARIF-native webRequest.
//
// NOTE, per CRITIQUE-01 BLOCKER 2: CanonicalRouteTemplate performs no
// segment templating today, so a concrete "/api/users/12345/orders" and a
// declared "/api/users/{id}/orders" will simply FAIL to match. That is the
// conservative direction — a missing link, never a wrong one — and this file
// does not paper over it with a fuzzy match, because a fuzzy route match is
// exactly the "silent hash collision" research/18 forbids.
func dastRoute(r *Result) (method, route string) {
	for _, loc := range r.Locations {
		raw, _ := loc.Properties[PropLocationRouteTemplate].(string)
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		m, path := splitMethodAndPath(raw)
		if path == "" {
			continue
		}
		if c := CanonicalRouteTemplate(path); c != "" {
			return m, c
		}
	}
	if r.WebRequest == nil {
		return "", ""
	}
	method = strings.ToUpper(strings.TrimSpace(r.WebRequest.Method))
	target := strings.TrimSpace(r.WebRequest.Target)
	if target == "" {
		return method, ""
	}
	path := target
	if u, err := url.Parse(target); err == nil && u.Path != "" {
		path = u.Path
	}
	return method, CanonicalRouteTemplate(path)
}

// splitMethodAndPath splits "POST /api/login" into ("POST", "/api/login"), and
// leaves a bare path alone. A leading token is treated as a method only when
// it is all ASCII letters, so "/a b" is not mistaken for one.
func splitMethodAndPath(raw string) (method, path string) {
	fields := strings.Fields(raw)
	switch len(fields) {
	case 0:
		return "", ""
	case 1:
		return "", fields[0]
	}
	if isASCIILetters(fields[0]) {
		return strings.ToUpper(fields[0]), fields[1]
	}
	return "", fields[0]
}

func isASCIILetters(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// injectedParameterNames returns the parameter NAMES the DAST half injected
// into. Names only — a parameter VALUE is the attacker's payload and is never
// read here.
func injectedParameterNames(r *Result) []string {
	var out []string
	if p := r.Properties.Repro; p != nil {
		if n := strings.TrimSpace(p.InjectionPoint.Name); n != "" {
			out = append(out, n)
		}
	}
	if r.WebRequest != nil {
		// Sorted before use: ranging a map in place would make the derived
		// signal order, and therefore the emitted Detail, process-dependent.
		keys := make([]string, 0, len(r.WebRequest.Parameters))
		for k := range r.WebRequest.Parameters {
			if n := strings.TrimSpace(k); n != "" {
				keys = append(keys, n)
			}
		}
		sort.Strings(keys)
		out = append(out, keys...)
	}
	return out
}

// responseTexts returns the recorded response text a stack trace could appear
// in, separator-normalised so a Windows-style path in a trace still matches a
// canonical repository path.
//
// These bytes are TrustUntrusted and are used ONLY to compute booleans. None
// of them is copied into any value this file returns.
func responseTexts(r *Result) []string {
	var out []string
	add := func(s string) {
		if s != "" {
			out = append(out, strings.ReplaceAll(s, `\`, "/"))
		}
	}
	if p := r.Properties.Repro; p != nil &&
		p.ObservedSignal.Kind == EvidenceSignalResponseStackTrace &&
		p.ObservedSignal.Match != nil {
		add(p.ObservedSignal.Match.Text)
	}
	if r.WebResponse != nil && r.WebResponse.Body != nil {
		add(r.WebResponse.Body.Text)
	}
	return out
}

// taintSourceTokens returns the identifier set at the SAST finding's TAINT
// SOURCE: the first threadFlowLocation of the first codeFlow, per Table 2.
//
// Only when the finding carries no code flow at all does it fall back to the
// primary region snippet. The fallback is broader — it sees every identifier
// at the sink, not the ones the source reads — and that breadth is one reason
// CorrelationSignalParameterName is weighted below the route signals.
func taintSourceTokens(r *Result) map[string]bool {
	tokens := map[string]bool{}
	collected := false
	for _, cf := range r.CodeFlows {
		for _, tf := range cf.ThreadFlows {
			if len(tf.Locations) == 0 {
				continue
			}
			absorbLocationTokens(tokens, tf.Locations[0].Location)
			collected = true
			break
		}
		if collected {
			break
		}
	}
	if collected {
		return tokens
	}
	for _, loc := range r.Locations {
		absorbLocationTokens(tokens, loc)
	}
	return tokens
}

func absorbLocationTokens(tokens map[string]bool, loc Location) {
	for _, ll := range loc.LogicalLocations {
		addIdentifiers(tokens, ll.Name)
		addIdentifiers(tokens, ll.FullyQualifiedName)
	}
	if loc.PhysicalLocation == nil {
		return
	}
	for _, reg := range []*Region{loc.PhysicalLocation.Region, loc.PhysicalLocation.ContextRegion} {
		if reg != nil && reg.Snippet != nil {
			addIdentifiers(tokens, reg.Snippet.Text)
		}
	}
}

// addIdentifiers records every [A-Za-z_][A-Za-z0-9_]* run in s. Whole
// identifiers only, so `id` never matches inside `idempotency_key`.
func addIdentifiers(tokens map[string]bool, s string) {
	start := -1
	for i := 0; i <= len(s); i++ {
		var c byte
		if i < len(s) {
			c = s[i]
		}
		isStart := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isPart := isStart || (c >= '0' && c <= '9')
		switch {
		case start < 0 && isStart:
			start = i
		case start >= 0 && (i == len(s) || !isPart):
			tokens[s[start:i]] = true
			start = -1
		}
	}
}

// ---------------------------------------------------------------------------
// Small deterministic helpers
// ---------------------------------------------------------------------------

// orderSignals flattens a signal set into CorrelationSignalValues declaration
// order. The map is never ranged over; the enum's own ordering drives the
// walk, so the output cannot depend on a map seed.
func orderSignals(set map[CorrelationSignal]SignalWeight) []SignalWeight {
	if len(set) == 0 {
		return nil
	}
	out := make([]SignalWeight, 0, len(set))
	for _, name := range CorrelationSignalValues() {
		if s, ok := set[name]; ok {
			out = append(out, s)
		}
	}
	return out
}

func sortLinks(links []Link) {
	sort.SliceStable(links, func(i, j int) bool {
		if links[i].SastFindingID != links[j].SastFindingID {
			return links[i].SastFindingID < links[j].SastFindingID
		}
		return links[i].DastFindingID < links[j].DastFindingID
	})
}

func sortedDedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return dedupeSorted(out)
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
