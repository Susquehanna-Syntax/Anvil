// Regression tests for the defects CRITIQUE-02 found and the fix round closed.
//
// Each test here reproduces one ORIGINAL defect. They were written by the
// critic and the re-verifier as probes -- to prove a defect existed, and then
// to prove it was actually gone rather than merely claimed gone. They are kept
// permanently, and deliberately named after the finding they pin, because a
// fixed defect with no test is a defect waiting to return.
//
// Two of them earn their place especially:
//   - the masking probes build a MINIMAL record and assert the planted secret
//     appears exactly once before masking, so they cannot pass by propagation
//     from a header. That false-confidence pattern was itself a finding.
//   - the lease probes drive concurrent goroutines at the granting statement
//     rather than asserting on a single-threaded happy path.

package record

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Independent re-verification probes for CRITIQUE-02 B3 / M1 / M3, plus the
// completed_failed and DeriveDastStatus-totality claims. Written from the
// critique text, not from the shipped tests.
// ---------------------------------------------------------------------------

func probeMarshal(t *testing.T, l *SARIFLog) string {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// probeMinimalLog builds a record with NOTHING planted anywhere. Each probe
// then plants exactly one secret in exactly one field, so nothing can pass by
// propagation from a header the masker was already looking at. That
// propagation-false-confidence pattern is CRITIQUE-02 F11.
func probeMinimalLog() *SARIFLog {
	return &SARIFLog{
		Version: "2.1.0",
		Properties: AuditProperties{
			Target: Target{
				RepoURL: "https://github.invalid/org/repo.git",
			},
		},
		Runs: []Run{{
			Properties: RunProperties{Half: HalfDast, Status: HalfStatusSealed},
			Results: []Result{{
				WebRequest: &WebRequest{
					Target:  "https://app.invalid/v1/orders",
					Method:  "POST",
					Headers: map[string]string{"Content-Length": "42"},
				},
				WebResponse: &WebResponse{
					StatusCode: 200,
					Headers:    map[string]string{"Content-Type": "application/json"},
				},
			}},
		}},
	}
}

// ProbeB3ReproCurlOnly: the secret exists ONLY inside anvil/repro.curl. No
// header, no parameter, no URL anywhere in the record carries it, so pass 2
// propagation cannot rescue the assertion.
func TestProbeB3ReproCurlOnlySecret(t *testing.T) {
	const secret = "PROBE-CURL-ONLY-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	l := probeMinimalLog()
	l.Runs[0].Results[0].Properties.Repro = &Repro{
		Curl: "curl -X POST -H 'Authorization: Bearer " + secret + "' https://app.invalid/v1/orders",
	}

	before := probeMarshal(t, l)
	if strings.Count(before, secret) != 1 {
		t.Fatalf("fixture guard: secret occurs %d times before masking, want exactly 1 (in repro.curl only)",
			strings.Count(before, secret))
	}

	if err := MaskRecord(l); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	if after := probeMarshal(t, l); strings.Contains(after, secret) {
		t.Errorf("B3(i) REPRODUCED: anvil/repro.curl still carries %q after MaskRecord\n  curl = %s",
			secret, l.Runs[0].Results[0].Properties.Repro.Curl)
	}
	t.Logf("masked curl = %s", l.Runs[0].Results[0].Properties.Repro.Curl)
}

// ProbeB3 curl-only variants: other option shapes a real repro command uses.
func TestProbeB3ReproCurlOtherOptionShapes(t *testing.T) {
	cases := map[string]string{
		"-H long form --header": "curl --header 'X-Api-Key: %s' https://app.invalid/x",
		"-b cookie":             "curl -b 'session=%s' https://app.invalid/x",
		"-u basic auth":         "curl -u 'admin:%s' https://app.invalid/x",
		"-d data":               "curl -d 'password=%s' https://app.invalid/x",
		"url query in argument": "curl 'https://app.invalid/x?api_key=%s'",
		"--url flag":            "curl --url 'https://app.invalid/x?api_key=%s'",
		"userinfo in bare url":  "curl https://user:%s@app.invalid/x",
	}
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			secret := "PROBE-SHAPE-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			l := probeMinimalLog()
			l.Runs[0].Results[0].Properties.Repro = &Repro{Curl: fmt.Sprintf(tmpl, secret)}
			if err := MaskRecord(l); err != nil {
				t.Fatalf("MaskRecord: %v", err)
			}
			got := l.Runs[0].Results[0].Properties.Repro.Curl
			if strings.Contains(got, secret) {
				t.Errorf("secret survives in repro.curl: %s", got)
			}
			if err := AssertMasked(l); err != nil {
				t.Errorf("AssertMasked on the MASKED record: %v", err)
			}
		})
	}
}

// ProbeB3 second named field: the credential sits ONLY in anvil/target.repoUrl
// userinfo, the standard GitHub Actions checkout URL shape.
func TestProbeB3TargetRepoURLOnlySecret(t *testing.T) {
	const secret = "PROBE-CHECKOUT-cccccccccccccccccccccccccccc"

	for _, tc := range []struct {
		name string
		set  func(l *SARIFLog)
		get  func(l *SARIFLog) string
	}{
		{"anvil/target.repoUrl", func(l *SARIFLog) {
			l.Properties.Target.RepoURL = "https://x-access-token:" + secret + "@github.invalid/org/repo.git"
		}, func(l *SARIFLog) string { return l.Properties.Target.RepoURL }},
		{"anvil/target.runtimeBaseUrl", func(l *SARIFLog) {
			l.Properties.Target.RuntimeBaseURL = "https://scanner:" + secret + "@staging.invalid"
		}, func(l *SARIFLog) string { return l.Properties.Target.RuntimeBaseURL }},
		{"anvil/runtimeTarget.baseUrl", func(l *SARIFLog) {
			l.Runs[0].Properties.RuntimeTarget = &RuntimeTarget{
				BaseURL: "https://scanner:" + secret + "@staging.invalid",
			}
		}, func(l *SARIFLog) string { return l.Runs[0].Properties.RuntimeTarget.BaseURL }},
		{"anvil/runtimeTarget.scope[i]", func(l *SARIFLog) {
			l.Runs[0].Properties.RuntimeTarget = &RuntimeTarget{
				BaseURL: "https://staging.invalid",
				Scope:   []string{"https://staging.invalid/a?token=" + secret},
			}
		}, func(l *SARIFLog) string { return l.Runs[0].Properties.RuntimeTarget.Scope[0] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := probeMinimalLog()
			tc.set(l)
			if strings.Count(probeMarshal(t, l), secret) != 1 {
				t.Fatalf("fixture guard: secret must occur exactly once before masking")
			}
			if err := MaskRecord(l); err != nil {
				t.Fatalf("MaskRecord: %v", err)
			}
			if strings.Contains(probeMarshal(t, l), secret) {
				t.Errorf("B3(ii) REPRODUCED: %s still carries the credential: %s", tc.name, tc.get(l))
			}
		})
	}
}

// ProbeM1: AssertMasked must reject an UNMASKED record at every site Mask
// covers. This is run by planting one credential per site into an otherwise
// clean record and demanding a non-nil error each time.
func TestProbeM1AssertMaskedRejectsEverySite(t *testing.T) {
	const secret = "PROBE-SITE-dddddddddddddddddddddddddddddddd"

	sites := []struct {
		name string
		set  func(l *SARIFLog)
	}{
		{"webRequest.headers", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebRequest.Headers["Authorization"] = "Bearer " + secret
		}},
		{"webRequest.parameters", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebRequest.Parameters = map[string]string{"api_key": secret}
		}},
		{"webRequest.target (query)", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebRequest.Target = "https://app.invalid/v1?api_key=" + secret
		}},
		{"webRequest.target (userinfo)", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebRequest.Target = "https://u:" + secret + "@app.invalid/v1"
		}},
		{"webRequest.target (fragment)", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebRequest.Target = "https://app.invalid/v1#access_token=" + secret
		}},
		{"webResponse.headers", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebResponse.Headers["Set-Cookie"] = "session=" + secret
		}},
		{"anvil/target.repoUrl", func(l *SARIFLog) {
			l.Properties.Target.RepoURL = "https://x-access-token:" + secret + "@github.invalid/o/r.git"
		}},
		{"anvil/target.runtimeBaseUrl", func(l *SARIFLog) {
			l.Properties.Target.RuntimeBaseURL = "https://s:" + secret + "@staging.invalid"
		}},
		{"anvil/runtimeTarget.baseUrl", func(l *SARIFLog) {
			l.Runs[0].Properties.RuntimeTarget = &RuntimeTarget{BaseURL: "https://s:" + secret + "@staging.invalid"}
		}},
		{"anvil/repro.curl", func(l *SARIFLog) {
			l.Runs[0].Results[0].Properties.Repro = &Repro{
				Curl: "curl -H 'Authorization: Bearer " + secret + "' https://app.invalid/x",
			}
		}},
		{"webRequest.body over cap", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebRequest.Body = &ArtifactContent{
				Text: strings.Repeat("x", MaxInlineRequestBodyBytes+1),
			}
		}},
		{"webResponse.body over cap", func(l *SARIFLog) {
			l.Runs[0].Results[0].WebResponse.Body = &ArtifactContent{
				Text: strings.Repeat("x", MaxInlineResponseBodyBytes+1),
			}
		}},
	}

	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			l := probeMinimalLog()
			s.set(l)
			if err := AssertMasked(l); err == nil {
				t.Errorf("M1 REPRODUCED: AssertMasked returned nil on an UNMASKED %s", s.name)
			}
			// And after Mask it must accept.
			if err := MaskRecord(l); err != nil {
				t.Fatalf("MaskRecord: %v", err)
			}
			if err := AssertMasked(l); err != nil {
				t.Errorf("AssertMasked rejected a record Mask just produced: %v", err)
			}
		})
	}
}

// ProbeM1b: structural equality of the two walks. Count the sites each walk
// visits per kind; they must be identical, and AssertMasked must consume every
// kind the surface declares (no nil callback silently skipping a kind).
func TestProbeM1WalkCoverageIsIdentical(t *testing.T) {
	l := probeMinimalLog()
	l.Properties.Target.RuntimeBaseURL = "https://staging.invalid"
	l.Runs[0].Properties.RuntimeTarget = &RuntimeTarget{
		BaseURL:  "https://staging.invalid",
		Scope:    []string{"https://staging.invalid/a"},
		Excluded: []string{"https://staging.invalid/b"},
	}
	l.Runs[0].Results[0].Properties.Repro = &Repro{Curl: "curl https://app.invalid/x"}
	l.Runs[0].Results[0].WebRequest.Parameters = map[string]string{"q": "1"}
	l.Runs[0].Results[0].WebRequest.Body = &ArtifactContent{Text: "{}"}
	l.Runs[0].Results[0].WebResponse.Body = &ArtifactContent{Text: "{}"}

	counts := map[string]int{}
	walkMaskSurface(l, surface{
		Headers:     func(string, map[string]string) { counts["headers"]++ },
		Parameters:  func(string, map[string]string) { counts["parameters"]++ },
		URL:         func(string, *string) { counts["url"]++ },
		CommandLine: func(string, *string) { counts["commandline"]++ },
		Body:        func(string, *ArtifactContent, int) { counts["body"]++ },
	})
	t.Logf("mask surface sites: %v", counts)
	for _, k := range []string{"headers", "parameters", "url", "commandline", "body"} {
		if counts[k] == 0 {
			t.Errorf("surface kind %q visits no site in this fixture; probe is not exercising it", k)
		}
	}
	if counts["url"] < 6 {
		t.Errorf("url sites = %d; want at least 6 (repoUrl, runtimeBaseUrl, rt.baseUrl, scope, excluded, webRequest.target)",
			counts["url"])
	}
}

// ---------------------------------------------------------------------------
// M3 — Sealer.Inspect must honour expiry.
// ---------------------------------------------------------------------------

func TestProbeM3InspectHonoursExpiry(t *testing.T) {
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := NewSealer()
	s.SetClock(func() time.Time { return clock() })

	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "probe-a1", StartedAt: now, ClaimTimeoutSeconds: 3600, DastEnabled: false,
	}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := s.SealHalf("probe-a1", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}

	// Before expiry both agree.
	seal, ok := s.Inspect("probe-a1")
	if !ok {
		t.Fatal("Inspect: audit missing")
	}
	if !seal.Sast.Readable() {
		t.Fatalf("pre-expiry Inspect says SAST unreadable")
	}
	if _, err := s.ReadHalf("probe-a1", HalfSast); err != nil {
		t.Fatalf("pre-expiry ReadHalf: %v", err)
	}

	// Cross the deadline and expire.
	now = now.Add(2 * time.Hour)
	expired, err := s.ExpireIfDue("probe-a1")
	if err != nil {
		t.Fatalf("ExpireIfDue: %v", err)
	}
	if !expired {
		t.Fatal("ExpireIfDue did not expire a past-deadline audit")
	}

	_, readErr := s.ReadHalf("probe-a1", HalfSast)
	if readErr == nil {
		t.Fatal("ReadHalf accepted an expired audit; the gate itself is gone")
	}
	seal, ok = s.Inspect("probe-a1")
	if !ok {
		t.Fatal("Inspect: audit missing after expiry")
	}
	if seal.Sast.Readable() {
		t.Errorf("M3 REPRODUCED: Inspect reports Sast.Readable()=true on an expired audit that ReadHalf refuses with: %v", readErr)
	}
	if seal.Dast.Readable() {
		t.Errorf("M3 REPRODUCED (dast half): Inspect reports Dast.Readable()=true on an expired audit")
	}
	t.Logf("expired: Inspect Sast=%+v Readable=%v; ReadHalf err=%v", seal.Sast, seal.Sast.Readable(), readErr)
}

// M3 must not overshoot: a CONSUMED audit is still readable (S1 re-entrancy).
func TestProbeM3InspectStillReadableWhenConsumed(t *testing.T) {
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	s := NewSealer()
	s.SetClock(func() time.Time { return now })
	if _, err := s.BeginAudit(AuditConfig{
		AuditID: "probe-a2", StartedAt: now, ClaimTimeoutSeconds: 3600, DastEnabled: false,
	}); err != nil {
		t.Fatalf("BeginAudit: %v", err)
	}
	if err := s.SealHalf("probe-a2", HalfSast, HalfStatusSealed); err != nil {
		t.Fatalf("SealHalf: %v", err)
	}
	if err := s.Consume("probe-a2"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	seal, _ := s.Inspect("probe-a2")
	if !seal.Sast.Readable() {
		t.Errorf("a consumed audit reports Sast.Readable()=false; S1 requires a RE-ENTRANT consumer")
	}
	if _, err := s.ReadHalf("probe-a2", HalfSast); err != nil {
		t.Errorf("ReadHalf refused a consumed audit: %v", err)
	}
}

// Inspect and ReadHalf must never disagree over any reachable (state, status).
func TestProbeM3InspectNeverDisagreesWithReadHalf(t *testing.T) {
	type combo struct {
		state  State
		sast   HalfStatus
		reason string
	}
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	for _, st := range HalfStatusValues() {
		if !IsTerminalHalfStatus(st) {
			continue
		}
		for _, expire := range []bool{false, true} {
			name := fmt.Sprintf("sast=%s expired=%v", st, expire)
			t.Run(name, func(t *testing.T) {
				cur := now
				s := NewSealer()
				s.SetClock(func() time.Time { return cur })
				id := "probe-" + name
				if _, err := s.BeginAudit(AuditConfig{
					AuditID: id, StartedAt: cur, ClaimTimeoutSeconds: 3600, DastEnabled: false,
				}); err != nil {
					t.Fatalf("BeginAudit: %v", err)
				}
				if err := s.SealHalf(id, HalfSast, st); err != nil {
					t.Fatalf("SealHalf: %v", err)
				}
				if expire {
					cur = cur.Add(2 * time.Hour)
					if _, err := s.ExpireIfDue(id); err != nil {
						t.Fatalf("ExpireIfDue: %v", err)
					}
				}
				seal, _ := s.Inspect(id)
				_, err := s.ReadHalf(id, HalfSast)
				gateOpen := err == nil
				if seal.Sast.Readable() != gateOpen {
					t.Errorf("DISAGREEMENT: Inspect.Readable()=%v, ReadHalf ok=%v (err=%v)",
						seal.Sast.Readable(), gateOpen, err)
				}
			})
		}
	}
	_ = combo{}
}

// ---------------------------------------------------------------------------
// completed_failed and DeriveDastStatus totality.
// ---------------------------------------------------------------------------

func TestProbeCompletedFailedIsInTheEnum(t *testing.T) {
	found := false
	for _, v := range DastStatusValues() {
		if v == DastStatusCompletedFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("completed_failed missing from DastStatusValues(): %v", DastStatusValues())
	}
	if len(DastStatusValues()) != 10 {
		t.Errorf("DastStatusValues() has %d entries, want 10", len(DastStatusValues()))
	}
	if err := ValidateDastStatus("completed_failed"); err != nil {
		t.Errorf("ValidateDastStatus(completed_failed): %v", err)
	}
	if DastStatusCompletedFailed.MeansDynamicallyScannedClean() {
		t.Errorf("completed_failed reports MeansDynamicallyScannedClean")
	}
	// Duplicate / ordering sanity.
	seen := map[DastStatus]int{}
	for _, v := range DastStatusValues() {
		seen[v]++
		if seen[v] > 1 {
			t.Errorf("duplicate value %q in DastStatusValues()", v)
		}
	}
}

// TotalityProbe: enumerate EVERY (tier, provenance, half status, partial,
// count) tuple and demand exactly one legal, non-empty, deterministic image.
func TestProbeDeriveDastStatusIsTotalIndependently(t *testing.T) {
	images := map[string]DastStatus{}
	seen := map[DastStatus]bool{}
	pairs := 0
	for _, tier := range []bool{false, true} {
		for _, prov := range TargetProvenanceValues() {
			for _, st := range HalfStatusValues() {
				for _, partial := range []bool{false, true} {
					for _, count := range []int{0, 1, 3} {
						o := DastOutcome{TierInstalled: tier, Provenance: prov,
							PartialCoverage: partial, FindingCount: count}
						got, err := DeriveDastStatus(st, o)
						pairs++
						if err != nil {
							t.Errorf("NOT TOTAL: (tier=%v prov=%s status=%s partial=%v n=%d) errored: %v",
								tier, prov, st, partial, count, err)
							continue
						}
						if got == "" {
							t.Errorf("NOT TOTAL: (tier=%v prov=%s status=%s partial=%v n=%d) -> empty string",
								tier, prov, st, partial, count)
							continue
						}
						if !got.Valid() {
							t.Errorf("ILLEGAL IMAGE: (tier=%v prov=%s status=%s) -> %q not in the frozen enum",
								tier, prov, st, got)
						}
						// Determinism / single-valuedness.
						key := fmt.Sprintf("%v|%s|%s|%v|%d", tier, prov, st, partial, count)
						if prev, ok := images[key]; ok && prev != got {
							t.Errorf("NOT A FUNCTION: %s -> %q then %q", key, prev, got)
						}
						images[key] = got
						again, _ := DeriveDastStatus(st, o)
						if again != got {
							t.Errorf("NON-DETERMINISTIC: %s -> %q then %q", key, got, again)
						}
						seen[got] = true
					}
				}
			}
		}
	}
	t.Logf("enumerated %d tuples, %d distinct images", pairs, len(seen))
	for _, v := range DastStatusValues() {
		if !seen[v] {
			t.Errorf("UNREACHABLE: no tuple derives %q", v)
		}
	}
	// The specific fold the amendment claims to have removed.
	got, err := DeriveDastStatus(HalfStatusFailed, DastOutcome{
		TierInstalled: true, Provenance: TargetProvenanceBootedClean})
	if err != nil {
		t.Fatalf("DeriveDastStatus(failed, booted_clean): %v", err)
	}
	if got != DastStatusCompletedFailed {
		t.Errorf("(failed, booted_clean) = %q, want completed_failed", got)
	}
	// completed_clean must remain reachable ONLY from a sealed half against a
	// cleanly-booted target with zero findings and no partial coverage.
	for key, v := range images {
		if v != DastStatusCompletedClean {
			continue
		}
		if !strings.HasPrefix(key, "true|booted_clean|sealed|false|0") {
			t.Errorf("completed_clean reachable from %s", key)
		}
	}
}

// The frozen-vocabulary table in contract_test.go must agree with the Go enum.
// Re-derived here rather than trusting that file.
func TestProbeFrozenTableAgreesWithDastStatusValues(t *testing.T) {
	want := []string{}
	for _, v := range DastStatusValues() {
		want = append(want, string(v))
	}
	got := frozenEnums["anvil/dastStatus"]
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("frozen table mismatch\n  table: %v\n  enum:  %v", got, want)
	}
}

// The frozen vocabulary exists in four places. All four must agree, or the
// amendment is only half landed.
func TestProbePublishedSchemaAndDocAgreeOnDastStatus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "anvil-record-v1.schema.json"))
	if err != nil {
		t.Fatalf("read published JSON Schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse published JSON Schema: %v", err)
	}
	if !strings.Contains(string(raw), `"completed_failed"`) {
		t.Errorf("schemas/anvil-record-v1.schema.json does NOT list \"completed_failed\" in the "+
			"anvil/dastStatus enum, but DastStatusValues() does (%v). A record carrying the value "+
			"internal/record derives for a crashed DAST half fails wire validation.",
			DastStatusValues())
	}
	md, err := os.ReadFile("CONTRACT.md")
	if err != nil {
		t.Fatalf("read CONTRACT.md: %v", err)
	}
	if !strings.Contains(string(md), "completed_failed") {
		t.Errorf("internal/record/CONTRACT.md section 1.3 still documents the nine-value "+
			"anvil/dastStatus set; contract.go declares ten (%v)", DastStatusValues())
	}
	_ = doc
}

// F11's false-confidence pattern, checked against the SHIPPED fixture: the
// secrets that exist to prove the newly-covered sites are masked must occur in
// exactly ONE place in the record, or the assertion passes by propagation from
// a header pass 1 was already reading.
func TestProbeShippedFixtureSecretsAreSingleSited(t *testing.T) {
	l := dastFixture()
	blob := probeMarshal(t, l)
	for name, secret := range map[string]string{
		"plantedCurlOnly (repro.curl)":                    plantedCurlOnly,
		"plantedCheckoutToken (target.repoUrl)":           plantedCheckoutToken,
		"plantedRuntimeBasicAuth (target.runtimeBaseUrl)": plantedRuntimeBasicAuth,
	} {
		if n := strings.Count(blob, secret); n != 1 {
			t.Errorf("F11 PATTERN: %s occurs %d times in the unmasked fixture; it must occur "+
				"exactly once or the absence assertion proves nothing about the new site", name, n)
		}
	}
	// And each must be long enough that propagation could carry it, so a
	// single-sited value is genuinely testing the structural pass.
	for _, s := range []string{plantedCurlOnly, plantedCheckoutToken, plantedRuntimeBasicAuth} {
		if len(s) < MinPropagatedSecretLen {
			t.Errorf("planted value %q is shorter than MinPropagatedSecretLen", s)
		}
	}
}
