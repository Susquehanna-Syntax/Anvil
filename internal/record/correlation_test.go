// Tests for the R.12 correlation policy: LINK, NEVER MERGE.
//
// The two the packet names explicitly are TestCweOnlyMatchProducesZeroClusters
// and TestVerifiedRequiresAStackTraceOrRerunFlipSignalSpecifically. The rest
// exist because the failure modes around them are silent: a merge that loses
// the DAST proof, an attacker-controlled byte copied into the record, a
// process-dependent cluster id, or a link emitted on one signal all produce a
// plausible-looking record and no error.
package record

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fixtures — modelled on research/18's annotated unified audit record
// ---------------------------------------------------------------------------

const (
	fxSastID = "sast-8c1e4b0f9a2d77c5"
	fxDastID = "dast-41b7c2ee9f10a3d8"
	fxPath   = "app/db.py"
	fxSymbol = "app.db.authenticate"
	fxRoute  = "POST /api/login"
	fxParam  = "username"
	fxCWE    = "89"

	// A leaked Python traceback of the shape Table 2 describes.
	fxStackTrace = `Traceback (most recent call last):
  File "app/db.py", line 412, in authenticate
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
sqlite3.OperationalError: near "OR": syntax error`
)

type sastOpts struct {
	id      string
	path    string
	symbol  string
	cwes    []string
	source  string // taint-source snippet, becomes the first threadFlowLocation
	related []string
}

func mkSast(o sastOpts) Result {
	if o.id == "" {
		o.id = fxSastID
	}
	if o.path == "" {
		o.path = fxPath
	}
	if o.symbol == "" {
		o.symbol = fxSymbol
	}
	if o.cwes == nil {
		o.cwes = []string{fxCWE}
	}
	r := Result{
		RuleID: "ANVIL.SAST.SQLI-STRING-CONCAT",
		Locations: []Location{{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: o.path, URIBaseID: "REPOROOT"},
				Region:           &Region{StartLine: 412, Snippet: &Snippet{Text: "cur.execute(q)"}},
			},
			LogicalLocations: []LogicalLocation{{FullyQualifiedName: o.symbol, Kind: "function"}},
		}},
		Properties: ResultProperties{
			FindingID:     o.id,
			Half:          HalfSast,
			EvidenceClass: EvidenceClassSastReachable,
			Verdict:       VerdictTruePositive,
		},
	}
	for _, rp := range o.related {
		r.RelatedLocations = append(r.RelatedLocations, Location{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: rp, URIBaseID: "REPOROOT"},
				Region:           &Region{StartLine: 1},
			},
		})
	}
	for _, c := range o.cwes {
		r.Taxa = append(r.Taxa, ReportingDescriptorReference{
			ID: c, ToolComponent: &ToolComponentRef{Name: "CWE"},
		})
	}
	if o.source != "" {
		r.CodeFlows = []CodeFlow{{ThreadFlows: []ThreadFlow{{Locations: []ThreadFlowLocation{{
			Location: Location{PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: o.path},
				Region:           &Region{StartLine: 380, Snippet: &Snippet{Text: o.source}},
			}},
		}}}}}}
	}
	return r
}

type dastOpts struct {
	id       string
	route    string // written into location.properties["anvil/routeTemplate"]
	cwes     []string
	param    string
	respBody string
	noRoute  bool
}

func mkDast(o dastOpts) Result {
	if o.id == "" {
		o.id = fxDastID
	}
	if o.route == "" {
		o.route = fxRoute
	}
	if o.cwes == nil {
		o.cwes = []string{fxCWE}
	}
	r := Result{
		RuleID: "ANVIL.DAST.SQLI-ERROR-BASED",
		Properties: ResultProperties{
			FindingID:     o.id,
			Half:          HalfDast,
			EvidenceClass: EvidenceClassDastConfirmed,
			Verdict:       VerdictTruePositive,
		},
	}
	if !o.noRoute {
		r.Locations = []Location{{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: "https://staging.internal/api/login"},
				Region:           &Region{StartLine: 1},
			},
			Properties: map[string]any{
				PropLocationKind:          "httpEndpoint",
				PropLocationRouteTemplate: o.route,
			},
		}}
	}
	for _, c := range o.cwes {
		r.Taxa = append(r.Taxa, ReportingDescriptorReference{
			ID: c, ToolComponent: &ToolComponentRef{Name: "CWE"},
		})
	}
	if o.param != "" {
		r.Properties.Repro = &Repro{
			InjectionPoint: ReproInjection{Kind: InjectionPointBody, Name: o.param},
			ObservedSignal: ReproSignal{Kind: EvidenceSignalDBErrorString},
			Env:            ReproEnv{Sanitizers: []string{}},
		}
	}
	if o.respBody != "" {
		r.WebResponse = &WebResponse{StatusCode: 500, Body: &ArtifactContent{Text: o.respBody}}
	}
	return r
}

// fxRouteTable binds fxRoute to the SAST finding's own file and symbol.
func fxRouteTable() Evidence {
	return Evidence{Routes: []RouteBinding{{
		Method:        "POST",
		RouteTemplate: "/api/login",
		HandlerSymbol: fxSymbol,
		HandlerPath:   fxPath,
	}}}
}

func signalNames(sw []SignalWeight) []string {
	out := make([]string, 0, len(sw))
	for _, s := range sw {
		out = append(out, string(s.Name))
	}
	return out
}

func hasSignal(sw []SignalWeight, want CorrelationSignal) bool {
	for _, s := range sw {
		if s.Name == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The two assertions R.12's packet names
// ---------------------------------------------------------------------------

// research/18, Table 2: a CWE class match is "necessary, never sufficient" —
// thousands of CWE-89 pairs exist in one repository. A link resting on it
// alone is not a weak link; it is not a link.
func TestCweOnlyMatchProducesZeroClusters(t *testing.T) {
	// Same CWE, and deliberately NOTHING else in common: different file,
	// different symbol, an injected parameter that appears nowhere at the
	// taint source, no response body, no route table.
	sast := mkSast(sastOpts{
		path:   "app/reports.py",
		symbol: "app.reports.render",
		source: "rows = fetch_rows(report_id)",
	})
	dast := mkDast(dastOpts{param: "session_token", noRoute: true})

	got := Correlate([]Result{sast}, []Result{dast})
	if len(got) != 0 {
		t.Fatalf("a CWE-only match produced %d cluster(s), want 0; signals=%v",
			len(got), signalNames(got[0].Signals))
	}

	// Sharing SEVERAL CWE ids is still one signal, not several.
	sast.Taxa = append(sast.Taxa,
		ReportingDescriptorReference{ID: "20", ToolComponent: &ToolComponentRef{Name: "CWE"}},
		ReportingDescriptorReference{ID: "74", ToolComponent: &ToolComponentRef{Name: "CWE"}})
	dast.Taxa = append(dast.Taxa,
		ReportingDescriptorReference{ID: "20", ToolComponent: &ToolComponentRef{Name: "CWE"}},
		ReportingDescriptorReference{ID: "74", ToolComponent: &ToolComponentRef{Name: "CWE"}})
	if got := Correlate([]Result{sast}, []Result{dast}); len(got) != 0 {
		t.Fatalf("three shared CWE ids produced %d cluster(s), want 0 — a repeated signal is not an independent one", len(got))
	}
}

// plan/00-SPINE.md S7: "Only a DAST reproduction that now fails earns 'verified
// fixed.' A clean SAST rescan does not." Verified is a question about the KIND
// of evidence; no amount of confidence answers it.
func TestVerifiedRequiresAStackTraceOrRerunFlipSignalSpecifically(t *testing.T) {
	sast := mkSast(sastOpts{source: `name = request.form["username"]`})
	base := mkDast(dastOpts{param: fxParam})

	// (a) Four signals, none of them sufficient for verification: route table,
	// call-graph reachability, parameter name, CWE class. This is the case
	// that proves confidence alone never qualifies.
	ev := fxRouteTable()
	ev.Reachability = []Reachability{{FromSymbol: fxSymbol, ToSymbol: fxSymbol, ToPath: fxPath}}
	got := CorrelateWithEvidence([]Result{sast}, []Result{base}, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(got))
	}
	c := got[0]
	if len(c.Signals) != 4 {
		t.Fatalf("want 4 signals, got %v", signalNames(c.Signals))
	}
	if c.Confidence < 0.5 {
		t.Fatalf("expected a substantial confidence from four signals, got %v", c.Confidence)
	}
	if c.Verified {
		t.Errorf("verified:true with confidence %v and signals %v, but neither %q nor %q is present",
			c.Confidence, signalNames(c.Signals),
			CorrelationSignalResponseStackTrace, CorrelationSignalRerunFlip)
	}
	if c.VerificationMethod != "" {
		t.Errorf("unverified cluster names a verification method %q", c.VerificationMethod)
	}
	if !strings.Contains(c.Caveat, "not verified") {
		t.Errorf("unverified cluster does not say why: %q", c.Caveat)
	}

	// (b) Add the response stack trace naming the SAST file. Verified flips.
	withTrace := mkDast(dastOpts{param: fxParam, respBody: fxStackTrace})
	got = CorrelateWithEvidence([]Result{sast}, []Result{withTrace}, ev)
	if len(got) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(got))
	}
	if !got[0].Verified {
		t.Fatalf("a response stack trace naming %q did not earn verified; signals=%v",
			fxPath, signalNames(got[0].Signals))
	}
	if !strings.Contains(got[0].VerificationMethod, string(CorrelationSignalResponseStackTrace)) {
		t.Errorf("verificationMethod = %q, want it to name %q",
			got[0].VerificationMethod, CorrelationSignalResponseStackTrace)
	}

	// (c) A post-patch re-run flip earns it too, with no stack trace at all.
	ev2 := fxRouteTable()
	ev2.RerunFlips = []RerunFlip{{DastFindingID: fxDastID, SastFindingID: fxSastID, Flipped: true}}
	got = CorrelateWithEvidence([]Result{sast}, []Result{base}, ev2)
	if len(got) != 1 || !got[0].Verified {
		t.Fatalf("a re-run flip did not earn verified: %+v", got)
	}
	if !strings.Contains(got[0].VerificationMethod, string(CorrelationSignalRerunFlip)) {
		t.Errorf("verificationMethod = %q, want it to name %q",
			got[0].VerificationMethod, CorrelationSignalRerunFlip)
	}

	// (d) A re-run that did NOT flip is not a weaker signal, it is no signal.
	ev3 := fxRouteTable()
	ev3.RerunFlips = []RerunFlip{{DastFindingID: fxDastID, SastFindingID: fxSastID, Flipped: false}}
	got = CorrelateWithEvidence([]Result{sast}, []Result{base}, ev3)
	if len(got) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(got))
	}
	if got[0].Verified || hasSignal(got[0].Signals, CorrelationSignalRerunFlip) {
		t.Errorf("a re-run that did not flip produced verified=%v signals=%v",
			got[0].Verified, signalNames(got[0].Signals))
	}

	// (e) A clean SAST rescan is modelled by the absence of any dynamic
	// evidence. It must never verify anything, at any confidence.
	for _, cl := range CorrelateWithEvidence([]Result{sast}, []Result{base}, fxRouteTable()) {
		if cl.Verified {
			t.Errorf("static-only evidence produced verified:true")
		}
	}
}

// ---------------------------------------------------------------------------
// Link, never merge
// ---------------------------------------------------------------------------

// merged must be false in EVERY code path, on every cluster and on every
// per-finding correlation, across a matrix of inputs.
func TestMergedIsUnconditionallyFalse(t *testing.T) {
	sast := []Result{
		mkSast(sastOpts{source: `name = request.form["username"]`}),
		mkSast(sastOpts{id: "sast-second", path: "app/api.py", symbol: "app.api.login",
			source: `u = request.form["username"]`}),
	}
	dast := []Result{
		mkDast(dastOpts{param: fxParam, respBody: fxStackTrace}),
		mkDast(dastOpts{id: "dast-second", param: fxParam}),
	}
	ev := fxRouteTable()
	ev.Routes = append(ev.Routes, RouteBinding{
		Method: "POST", RouteTemplate: "/api/login",
		HandlerSymbol: "app.api.login", HandlerPath: "app/api.py",
	})
	ev.Reachability = []Reachability{{FromSymbol: fxSymbol, ToPath: fxPath}}
	ev.RerunFlips = []RerunFlip{{DastFindingID: fxDastID, Flipped: true}}

	clusters := CorrelateWithEvidence(sast, dast, ev)
	if len(clusters) == 0 {
		t.Fatal("fixture produced no clusters; the matrix would prove nothing")
	}
	for _, c := range clusters {
		if c.Merged {
			t.Errorf("cluster %s reports merged:true", c.ClusterID)
		}
		for _, id := range append(append([]string{}, c.SastFindingIDs...), c.DastFindingIDs...) {
			corr, ok := c.CorrelationFor(id)
			if !ok {
				t.Fatalf("member %q has no correlation view", id)
			}
			if corr.Merged {
				t.Errorf("correlation for %q reports merged:true", id)
			}
		}
	}
}

// Both findings must survive independently: the SAST finding owns the file and
// line, the DAST finding owns the proof. Correlate must not mutate, reorder,
// drop or combine either input.
func TestCorrelateNeverTouchesTheInputResults(t *testing.T) {
	sast := []Result{mkSast(sastOpts{source: `name = request.form["username"]`})}
	dast := []Result{mkDast(dastOpts{param: fxParam, respBody: fxStackTrace})}

	before := mustJSON(t, [2]any{sast, dast})
	clusters := CorrelateWithEvidence(sast, dast, fxRouteTable())
	after := mustJSON(t, [2]any{sast, dast})

	if before != after {
		t.Fatalf("Correlate modified its inputs\nbefore: %s\nafter:  %s", before, after)
	}
	if len(sast) != 1 || len(dast) != 1 {
		t.Fatalf("input slice lengths changed: sast=%d dast=%d", len(sast), len(dast))
	}
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	// The cluster names findings; it does not contain them.
	if !reflect.DeepEqual(clusters[0].SastFindingIDs, []string{fxSastID}) ||
		!reflect.DeepEqual(clusters[0].DastFindingIDs, []string{fxDastID}) {
		t.Fatalf("cluster membership = %v / %v", clusters[0].SastFindingIDs, clusters[0].DastFindingIDs)
	}
}

// ---------------------------------------------------------------------------
// The >=2 independent signals rule
// ---------------------------------------------------------------------------

// Even the strongest single signal does not make a link. research/18: "Require
// >=2 independent signals before emitting a link at all."
func TestASingleSignalNeverLinksEvenTheStrongestOne(t *testing.T) {
	cases := []struct {
		name string
		sast Result
		dast Result
		ev   Evidence
	}{
		{
			name: "responseStackTrace alone",
			sast: mkSast(sastOpts{cwes: []string{"79"}, source: "rows = q(a)"}),
			dast: mkDast(dastOpts{cwes: []string{fxCWE}, respBody: fxStackTrace, noRoute: true}),
		},
		{
			name: "parameterName alone",
			sast: mkSast(sastOpts{cwes: []string{"79"}, source: `name = request.form["username"]`}),
			dast: mkDast(dastOpts{cwes: []string{fxCWE}, param: fxParam, noRoute: true}),
		},
		{
			name: "routeTable alone",
			sast: mkSast(sastOpts{cwes: []string{"79"}, source: "rows = q(a)"}),
			dast: mkDast(dastOpts{cwes: []string{fxCWE}}),
			ev:   fxRouteTable(),
		},
		{
			name: "cweMatch alone",
			sast: mkSast(sastOpts{source: "rows = q(a)"}),
			dast: mkDast(dastOpts{noRoute: true}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CorrelateWithEvidence([]Result{tc.sast}, []Result{tc.dast}, tc.ev)
			if len(got) != 0 {
				t.Fatalf("one signal produced %d cluster(s) with signals %v; MinCorrelationSignals is %d",
					len(got), signalNames(got[0].Signals), MinCorrelationSignals)
			}
		})
	}
}

// Every emitted link must satisfy contract.go's OWN validator, because that is
// where the policy lives. If this test ever needs a second rule written here,
// the second rule is the bug.
func TestEveryEmittedCorrelationSatisfiesTheContractValidator(t *testing.T) {
	sast := []Result{
		mkSast(sastOpts{source: `name = request.form["username"]`}),
		mkSast(sastOpts{id: "sast-second", path: "app/api.py", symbol: "app.api.login",
			source: `u = request.form["username"]`}),
	}
	dast := []Result{
		mkDast(dastOpts{param: fxParam, respBody: fxStackTrace}),
		mkDast(dastOpts{id: "dast-second", param: fxParam}),
	}
	ev := fxRouteTable()
	ev.Routes = append(ev.Routes, RouteBinding{
		Method: "POST", RouteTemplate: "/api/login",
		HandlerSymbol: "app.api.login", HandlerPath: "app/api.py",
	})

	clusters := CorrelateWithEvidence(sast, dast, ev)
	if len(clusters) == 0 {
		t.Fatal("no clusters to validate")
	}
	checked := 0
	for _, c := range clusters {
		for _, id := range append(append([]string{}, c.SastFindingIDs...), c.DastFindingIDs...) {
			corr, ok := c.CorrelationFor(id)
			if !ok {
				t.Fatalf("member %q has no correlation view", id)
			}
			if err := validateCorrelation(corr); err != nil {
				t.Errorf("correlation for %q fails R.1's own validator: %v", id, err)
			}
			if len(corr.Peers) == 0 {
				t.Errorf("correlation for %q has no peers", id)
			}
			for _, s := range corr.Signals {
				if err := ValidateCorrelationSignal(string(s.Name)); err != nil {
					t.Errorf("emitted signal is not a frozen enum member: %v", err)
				}
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("validated nothing")
	}
}

func TestCorrelationForRejectsNonMembers(t *testing.T) {
	clusters := CorrelateWithEvidence(
		[]Result{mkSast(sastOpts{source: `name = request.form["username"]`})},
		[]Result{mkDast(dastOpts{param: fxParam, respBody: fxStackTrace})},
		fxRouteTable())
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	for _, id := range []string{"", "not-a-member", fxSastID + "x"} {
		if _, ok := clusters[0].CorrelationFor(id); ok {
			t.Errorf("CorrelationFor(%q) reported membership", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

func TestOutputIsDeterministicAcrossRepeatedCallsAndInputOrder(t *testing.T) {
	sast := []Result{
		mkSast(sastOpts{source: `name = request.form["username"]`}),
		mkSast(sastOpts{id: "sast-aaa", path: "app/api.py", symbol: "app.api.login",
			source: `u = request.form["username"]`}),
		mkSast(sastOpts{id: "sast-zzz", path: "app/other.py", symbol: "app.other.thing",
			source: "nothing_here = 1", cwes: []string{"79"}}),
	}
	dast := []Result{
		mkDast(dastOpts{param: fxParam, respBody: fxStackTrace}),
		mkDast(dastOpts{id: "dast-aaa", param: fxParam}),
	}
	ev := fxRouteTable()
	ev.Routes = append(ev.Routes, RouteBinding{
		Method: "POST", RouteTemplate: "/api/login",
		HandlerSymbol: "app.api.login", HandlerPath: "app/api.py",
	})

	want := mustJSON(t, CorrelateWithEvidence(sast, dast, ev))
	for i := 0; i < 5; i++ {
		if got := mustJSON(t, CorrelateWithEvidence(sast, dast, ev)); got != want {
			t.Fatalf("call %d differs:\n%s\n%s", i, want, got)
		}
	}

	rev := func(in []Result) []Result {
		out := make([]Result, len(in))
		for i := range in {
			out[i] = in[len(in)-1-i]
		}
		return out
	}
	if got := mustJSON(t, CorrelateWithEvidence(rev(sast), rev(dast), ev)); got != want {
		t.Fatalf("reversing the input order changed the output:\n%s\n%s", want, got)
	}
}

func TestClusterIDIsDerivedFromMembershipAndIsUUIDShaped(t *testing.T) {
	clusters := CorrelateWithEvidence(
		[]Result{mkSast(sastOpts{source: `name = request.form["username"]`})},
		[]Result{mkDast(dastOpts{param: fxParam, respBody: fxStackTrace})},
		fxRouteTable())
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	id := clusters[0].ClusterID
	parts := strings.Split(id, "-")
	if len(parts) != 5 ||
		len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Fatalf("clusterId %q is not UUID-shaped (SARIF §3.27.4 types correlationGuid as a GUID)", id)
	}
	if parts[2][0] != '8' {
		t.Errorf("clusterId %q does not carry RFC 9562 version 8 (custom): %q", id, parts[2])
	}
	if got := deriveClusterID([]string{fxSastID}, []string{fxDastID}); got != id {
		t.Errorf("clusterId is not a pure function of membership: %q vs %q", got, id)
	}
	if same := deriveClusterID([]string{fxDastID}, []string{fxSastID}); same == id {
		t.Error("swapping the halves produced the same cluster id; the role is not in the derivation")
	}
}

// ---------------------------------------------------------------------------
// Untrusted bytes
// ---------------------------------------------------------------------------

// plan/00-SPINE.md S7 names the DAST response body the highest-risk field in
// the system. Correlation reads it to compute booleans; not one byte of it,
// nor of any payload value or repo snippet, may reach the record through this
// file's output.
func TestNoTargetControlledByteReachesTheOutput(t *testing.T) {
	const marker = "ZZ-ATTACKER-CONTROLLED-MARKER-ZZ"

	sast := mkSast(sastOpts{source: `name = request.form["username"] # ` + marker})
	dast := mkDast(dastOpts{param: fxParam, respBody: fxStackTrace + "\n" + marker})
	dast.WebRequest = &WebRequest{
		Method:     "POST",
		Target:     "https://staging.internal/api/login",
		Parameters: map[string]string{fxParam: "' OR '1'='1' -- " + marker},
		Headers:    map[string]string{"Authorization": "Bearer " + marker},
		Body:       &ArtifactContent{Text: marker},
	}

	clusters := CorrelateWithEvidence([]Result{sast}, []Result{dast}, fxRouteTable())
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	blob := mustJSON(t, clusters)
	corr, ok := clusters[0].CorrelationFor(fxSastID)
	if !ok {
		t.Fatal("no correlation view for the SAST member")
	}
	blob += mustJSON(t, corr)

	if strings.Contains(blob, marker) {
		t.Fatalf("target-controlled bytes reached the correlation output:\n%s", blob)
	}
	// The stack trace itself must not be echoed either, marker or no marker.
	if strings.Contains(blob, "sqlite3.OperationalError") || strings.Contains(blob, "Traceback") {
		t.Fatalf("response body text reached the correlation output:\n%s", blob)
	}
	// ... but the signal it produced is recorded.
	if !hasSignal(clusters[0].Signals, CorrelationSignalResponseStackTrace) {
		t.Error("the stack-trace signal was not recorded at all")
	}
}

// A CWE id is echoed into a signal detail, so a non-numeric taxon id from
// ingested third-party SARIF (research/18 Risk #8: ingested SARIF is
// untrusted) must be ignored rather than copied.
func TestNonNumericCweIdsAreIgnoredNotEchoed(t *testing.T) {
	const bad = "89\"><script>alert(1)</script>"
	sast := mkSast(sastOpts{cwes: []string{bad}, source: `name = request.form["username"]`})
	dast := mkDast(dastOpts{cwes: []string{bad}, param: fxParam, respBody: fxStackTrace})

	clusters := CorrelateWithEvidence([]Result{sast}, []Result{dast}, fxRouteTable())
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	if hasSignal(clusters[0].Signals, CorrelationSignalCweMatch) {
		t.Error("a non-numeric taxon id produced a cweMatch signal")
	}
	if blob := mustJSON(t, clusters); strings.Contains(blob, "script") {
		t.Fatalf("a non-numeric taxon id was echoed into the output:\n%s", blob)
	}
}

// ---------------------------------------------------------------------------
// Signal narrowness — a signal that fires everywhere is not evidence
// ---------------------------------------------------------------------------

func TestParameterNameMatchesWholeIdentifiersOnlyAndIgnoresShortNames(t *testing.T) {
	cases := []struct {
		name   string
		param  string
		source string
		want   bool
	}{
		{"whole identifier", "username", `n = request.form["username"]`, true},
		{"substring is not a match", "id", `key = request.form["idempotency_key"]`, false},
		{"short name ignored", "id", `key = request.form["id"]`, false},
		{"case sensitive", "Username", `n = request.form["username"]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sast := mkSast(sastOpts{source: tc.source})
			dast := mkDast(dastOpts{param: tc.param})
			got := CorrelateWithEvidence([]Result{sast}, []Result{dast}, fxRouteTable())
			if len(got) != 1 {
				t.Fatalf("want 1 cluster (route+cwe always link this fixture), got %d", len(got))
			}
			if fired := hasSignal(got[0].Signals, CorrelationSignalParameterName); fired != tc.want {
				t.Errorf("parameterName signal = %v, want %v (signals: %v)",
					fired, tc.want, signalNames(got[0].Signals))
			}
		})
	}
}

func TestStackTraceMustNameAFullPathOrSymbolNotABasename(t *testing.T) {
	sast := mkSast(sastOpts{source: `name = request.form["username"]`})
	// A trace that mentions only the basename. This is the case that would
	// otherwise let "main.go" verify any Go finding in the repository.
	dast := mkDast(dastOpts{
		param:    fxParam,
		respBody: `Traceback: File "db.py", line 412 in authenticate`,
	})
	got := CorrelateWithEvidence([]Result{sast}, []Result{dast}, fxRouteTable())
	if len(got) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(got))
	}
	if hasSignal(got[0].Signals, CorrelationSignalResponseStackTrace) {
		t.Error("a basename-only trace produced the stack-trace signal")
	}
	if got[0].Verified {
		t.Error("a basename-only trace earned verified:true")
	}
}

// A Windows-form path inside a trace still matches a canonical repo path;
// the separator form is normalised, the case is not.
func TestStackTracePathSeparatorsAreNormalised(t *testing.T) {
	sast := mkSast(sastOpts{source: `name = request.form["username"]`})
	dast := mkDast(dastOpts{param: fxParam, respBody: `at app\db.py line 412`})
	got := CorrelateWithEvidence([]Result{sast}, []Result{dast}, fxRouteTable())
	if len(got) != 1 || !hasSignal(got[0].Signals, CorrelationSignalResponseStackTrace) {
		t.Fatalf("a backslash-form path in a trace did not match: %v", got)
	}
}

// relatedLocations is where a PREVIOUS correlation pass writes the peer's
// location. Reading it back as evidence would make a link self-sustaining.
func TestRelatedLocationsAreNotTreatedAsEvidence(t *testing.T) {
	// The route table binds the route to app/routes.py. The SAST finding's own
	// location is app/models.py; app/routes.py appears only in the
	// relatedLocations a previous pass would have written.
	circular := mkSast(sastOpts{
		path: "app/models.py", symbol: "app.models.q",
		source: "rows = q(a)", related: []string{"app/routes.py"},
	})
	dast := mkDast(dastOpts{})
	ev := Evidence{Routes: []RouteBinding{{
		Method: "POST", RouteTemplate: "/api/login",
		HandlerSymbol: "app.routes.login", HandlerPath: "app/routes.py",
	}}}

	if got := CorrelateWithEvidence([]Result{circular}, []Result{dast}, ev); len(got) != 0 {
		t.Fatalf("relatedLocations supplied the route signal, closing a circular loop: signals=%v",
			signalNames(got[0].Signals))
	}

	// Control: the same route table DOES link a finding whose OWN location is
	// the handler file, so the test above is not passing for a trivial reason.
	honest := mkSast(sastOpts{path: "app/routes.py", symbol: "app.routes.login", source: "rows = q(a)"})
	if got := CorrelateWithEvidence([]Result{honest}, []Result{dast}, ev); len(got) != 1 {
		t.Fatalf("control case did not link: got %d clusters", len(got))
	}
}

func TestCallGraphReachRequiresTheRouteTableToNameTheHandler(t *testing.T) {
	sast := mkSast(sastOpts{path: "app/models.py", symbol: "app.models.q", source: "rows = q(a)"})
	dast := mkDast(dastOpts{})
	// Reachability from a handler that no route binding ties to this route.
	ev := Evidence{Reachability: []Reachability{{
		FromSymbol: "app.routes.login", ToSymbol: "app.models.q", ToPath: "app/models.py",
	}}}
	if got := CorrelateWithEvidence([]Result{sast}, []Result{dast}, ev); len(got) != 0 {
		t.Fatalf("call-graph reachability fired with no route binding: signals=%v",
			signalNames(got[0].Signals))
	}
}

// ---------------------------------------------------------------------------
// Clusters, fan-out and the uncorrelated majority
// ---------------------------------------------------------------------------

// Table 2: "middleware sinks fan out 1 DAST : N SAST". The component's
// aggregate must be the conservative combination of its links, never the best
// one.
func TestFanOutClusterIsUnverifiedWhenAnyLinkIsUnverified(t *testing.T) {
	strong := mkSast(sastOpts{source: `name = request.form["username"]`})
	weak := mkSast(sastOpts{
		id: "sast-weak", path: "app/api.py", symbol: "app.api.login",
		source: `u = request.form["username"]`,
	})
	dast := mkDast(dastOpts{param: fxParam, respBody: fxStackTrace})

	ev := fxRouteTable()
	ev.Routes = append(ev.Routes, RouteBinding{
		Method: "POST", RouteTemplate: "/api/login",
		HandlerSymbol: "app.api.login", HandlerPath: "app/api.py",
	})

	clusters := CorrelateWithEvidence([]Result{strong, weak}, []Result{dast}, ev)
	if len(clusters) != 1 {
		t.Fatalf("want one fan-out cluster, got %d", len(clusters))
	}
	c := clusters[0]
	if len(c.Links) != 2 {
		t.Fatalf("want 2 links in the component, got %d", len(c.Links))
	}
	if c.Verified {
		t.Error("the cluster is verified although one of its two links is not")
	}
	// ... while the strong pair's own per-finding view still is.
	corr, ok := c.CorrelationFor(fxSastID)
	if !ok {
		t.Fatal("no correlation view for the stack-trace-backed member")
	}
	if !corr.Verified {
		t.Errorf("the stack-trace-backed member lost its verification to an unrelated peer: %+v", corr)
	}
	weakCorr, ok := c.CorrelationFor("sast-weak")
	if !ok {
		t.Fatal("no correlation view for the weak member")
	}
	if weakCorr.Verified {
		t.Error("the weak member inherited verification from its cluster")
	}
	// The cluster's confidence is the weakest link's, not the strongest.
	min := c.Links[0].Confidence
	for _, l := range c.Links {
		if l.Confidence < min {
			min = l.Confidence
		}
	}
	if c.Confidence != min {
		t.Errorf("cluster confidence %v is not the minimum link confidence %v", c.Confidence, min)
	}
}

// research/18: "Report uncorrelated findings as uncorrelated ... the MAJORITY
// of findings will have no peer. That is the expected state, not a bug."
func TestUncorrelatedFindingsProduceNoClusterAndNoError(t *testing.T) {
	lonely := []Result{
		mkSast(sastOpts{id: "s1", path: "app/a.py", symbol: "app.a.f", cwes: []string{"22"}, source: "x = 1"}),
		mkSast(sastOpts{id: "s2", path: "app/b.py", symbol: "app.b.g", cwes: []string{"78"}, source: "y = 2"}),
	}
	dast := []Result{mkDast(dastOpts{id: "d1", cwes: []string{"79"}, noRoute: true, param: "token"})}

	if got := Correlate(lonely, dast); got != nil {
		t.Fatalf("uncorrelated findings produced %d cluster(s)", len(got))
	}
	if got := Correlate(lonely, nil); got != nil {
		t.Fatalf("an empty DAST half produced %d cluster(s)", len(got))
	}
	if got := Correlate(nil, dast); got != nil {
		t.Fatalf("an empty SAST half produced %d cluster(s)", len(got))
	}
	if got := Correlate(nil, nil); got != nil {
		t.Fatalf("two empty halves produced %d cluster(s)", len(got))
	}
}

// Two SAST findings are never linked to each other, and neither are two DAST
// findings. A same-half relationship is a different question (fix grouping)
// owned by a different step.
func TestNoSameHalfLinks(t *testing.T) {
	twins := []Result{
		mkSast(sastOpts{id: "s1", source: `name = request.form["username"]`}),
		mkSast(sastOpts{id: "s2", source: `name = request.form["username"]`}),
	}
	if got := CorrelateWithEvidence(twins, nil, fxRouteTable()); got != nil {
		t.Fatalf("two identical SAST findings were linked to each other: %d cluster(s)", len(got))
	}
	dastTwins := []Result{
		mkDast(dastOpts{id: "d1", param: fxParam, respBody: fxStackTrace}),
		mkDast(dastOpts{id: "d2", param: fxParam, respBody: fxStackTrace}),
	}
	if got := CorrelateWithEvidence(nil, dastTwins, fxRouteTable()); got != nil {
		t.Fatalf("two identical DAST findings were linked to each other: %d cluster(s)", len(got))
	}
}

func TestUnusableFindingIDsAreSkipped(t *testing.T) {
	good := mkSast(sastOpts{source: `name = request.form["username"]`})

	noID := mkSast(sastOpts{id: "x", source: `name = request.form["username"]`})
	noID.Properties.FindingID = ""

	sepID := mkSast(sastOpts{id: "y", source: `name = request.form["username"]`})
	sepID.Properties.FindingID = "sast" + FingerprintFieldSeparator + "1"

	dupe := mkSast(sastOpts{path: "app/other.py", symbol: "app.other.f",
		source: `name = request.form["username"]`}) // same id as good

	dast := []Result{mkDast(dastOpts{param: fxParam, respBody: fxStackTrace})}
	clusters := CorrelateWithEvidence([]Result{good, noID, sepID, dupe}, dast, fxRouteTable())
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	if !reflect.DeepEqual(clusters[0].SastFindingIDs, []string{fxSastID}) {
		t.Fatalf("membership = %v, want only %q", clusters[0].SastFindingIDs, fxSastID)
	}
	for _, l := range clusters[0].Links {
		if l.SastFindingID == "" || strings.Contains(l.SastFindingID, FingerprintFieldSeparator) {
			t.Errorf("an unusable finding id reached a link: %q", l.SastFindingID)
		}
	}
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

func TestConfidenceIsBoundedMonotoneAndNeverCertain(t *testing.T) {
	all := make([]SignalWeight, 0, len(CorrelationSignalValues()))
	prev := 0.0
	for _, name := range CorrelationSignalValues() {
		all = append(all, SignalWeight{Name: name, Weight: CorrelationSignalWeight(name)})
		c := noisyOr(all)
		if c < 0 || c > 1 {
			t.Fatalf("confidence %v out of [0,1] for %v", c, signalNames(all))
		}
		if c < prev {
			t.Errorf("adding %q lowered the confidence from %v to %v", name, prev, c)
		}
		prev = c
	}
	if prev >= 1 {
		t.Errorf("every signal agreeing produced certainty (%v); no technique here has a published measured accuracy", prev)
	}
	if got := noisyOr(nil); got != 0 {
		t.Errorf("noisyOr(nil) = %v, want 0", got)
	}
	// A cweMatch cannot lift a link's confidence meaningfully: it is Table 2's
	// "necessary, never sufficient".
	if w := CorrelationSignalWeight(CorrelationSignalCweMatch); w > 0.1 {
		t.Errorf("cweMatch weight %v is high enough to carry a link", w)
	}
	for _, s := range []CorrelationSignal{CorrelationSignalResponseStackTrace, CorrelationSignalRerunFlip} {
		if CorrelationSignalWeight(s) <= CorrelationSignalWeight(CorrelationSignalParameterName) {
			t.Errorf("%q does not outweigh a plain parameter-name match", s)
		}
	}
	if got := CorrelationSignalWeight(CorrelationSignal("not-a-signal")); got != 0 {
		t.Errorf("an unknown signal weighs %v, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// The patent flag R.15's critic is required to find
// ---------------------------------------------------------------------------

// plan/40-record-and-storage.md Open Questions #1 requires this step to flag
// the US10043004B2 patent risk in code, pointing at that document, without
// attempting to resolve it. R.15's critic verifies the flag exists. This test
// keeps a later refactor from quietly deleting it.
func TestPatentRiskIsFlaggedInSource(t *testing.T) {
	src, err := os.ReadFile("correlation.go")
	if err != nil {
		t.Fatalf("cannot read correlation.go: %v", err)
	}
	for _, want := range []string{
		"US10043004B2",
		"plan/40-record-and-storage.md",
		"Open Questions",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("correlation.go no longer mentions %q; the patent flag is required by "+
				"plan/40-record-and-storage.md Open Questions #1 and verified by R.15", want)
		}
	}
}

// ---------------------------------------------------------------------------

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
