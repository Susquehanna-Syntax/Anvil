package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Planted secrets
//
// These are the fixtures R.8's stop condition names — "a bearer token, a
// session cookie, an API key in a query parameter" — plus three more that
// cover the ways a secret reaches the record WITHOUT sitting in a header the
// denylist knows by name.
//
// None of them contains a character encoding/json escapes ('<', '>', '&',
// '"', '\\'), so a substring search over the marshalled record is a search
// for the literal bytes and not for an escape sequence. That is deliberate:
// a test that searched for a value the encoder had rewritten would pass
// vacuously.
// ---------------------------------------------------------------------------

const (
	// plantedBearer is the credential half of an Authorization header.
	plantedBearer = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r-wW1gFWFOEjXk"
	// plantedCookie is one crumb's value inside a multi-crumb Cookie header.
	plantedCookie = "s%3AJk9pQ2xZ8vT4hN6mB1cD.7fFqR2wXyZ0aL5nP8jK3uV1eS6tG4hM9bC"
	// plantedAPIKey travels in the target's query string AND in
	// webRequest.parameters.
	plantedAPIKey = "AKIAIOSFODNN7EXAMPLE-9d8f7a6b5c4e3d2f1a0b"
	// plantedProxyCred is a Proxy-Authorization credential.
	plantedProxyCred = "cHJveHktdXNlcjpwcm94eS1wYXNzd29yZC0xMjM0NTY3OA=="
	// plantedSmuggled is a session id smuggled through a CRLF injection in
	// an innocuously-named header. No name-based denylist can see it.
	plantedSmuggled = "SM8ggl3dC00k13Va1u3AbCdEf"
	// plantedURLPassword sits in the URL userinfo.
	plantedURLPassword = "hunter2-correct-horse-battery"
	// plantedFragmentToken is an OAuth implicit-flow access token, which
	// never reaches the server and which a query-only masker ignores.
	plantedFragmentToken = "ya29.A0ARrdaM-IMPLICIT-FLOW-ACCESS-TOKEN-9f8e7d"
	// plantedCurlOnly appears in ONE place in the whole fixture: a header
	// option of anvil/repro.curl. CRITIQUE-02 F11: before this constant
	// existed the fixture put plantedBearer in both the Authorization header
	// and the curl string, so the stop-condition test passed by PROPAGATION
	// from the header and read as proof that repro.curl was masked. It was
	// not -- F3 reproduced a live token surviving there. A secret with no
	// other route into the record is the only fixture that can prove the
	// command line is masked in its own right.
	plantedCurlOnly = "ghp-CURL-ONLY-0000000000000000000000000000"
	// plantedCheckoutToken sits in the userinfo of anvil/target.repoUrl and
	// nowhere else. `https://x-access-token:<token>@github.com/...` is the
	// standard GitHub Actions checkout URL, i.e. this is the ordinary case
	// and not a contrived one.
	plantedCheckoutToken = "ghs-CHECKOUT-0000000000000000000000000000"
	// plantedRuntimeBasicAuth sits in the userinfo of
	// anvil/target.runtimeBaseUrl and nowhere else.
	plantedRuntimeBasicAuth = "runtime-basic-auth-0000000000000000"
)

func allPlantedSecrets() map[string]string {
	return map[string]string{
		"bearer token (Authorization header)":        plantedBearer,
		"session cookie (Cookie header crumb)":       plantedCookie,
		"api key (query parameter + parameters map)": plantedAPIKey,
		"proxy credential (Proxy-Authorization)":     plantedProxyCred,
		"session id smuggled through CRLF":           plantedSmuggled,
		"password in URL userinfo":                   plantedURLPassword,
		"access token in the URL fragment":           plantedFragmentToken,
		"bearer token reachable ONLY via repro.curl": plantedCurlOnly,
		"checkout token in anvil/target.repoUrl":     plantedCheckoutToken,
		"basic auth in anvil/target.runtimeBaseUrl":  plantedRuntimeBasicAuth,
	}
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

// dastFixture builds a record that passes Validate() and that carries every
// planted secret, each by a different route into the record. The response
// body is a stack trace — the shape research/18's annotated record uses —
// carrying no secrets of its own but ECHOING two of them, which is the case
// no header rule can reach and only value propagation can.
func dastFixture() *SARIFLog {
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	sealedAt := createdAt.Add(90 * time.Second)

	body := strings.Join([]string{
		"Traceback (most recent call last):",
		`  File "/srv/app/routes.py", line 94, in login`,
		"    user = db.authenticate(conn, username, password)",
		`  File "/srv/app/db.py", line 414, in authenticate`,
		"    cur.execute(query)",
		"sqlite3.OperationalError: unrecognized token",
		"",
		"-- request context echoed by the framework's debug page --",
		"session=" + plantedCookie,
		"api_key=" + plantedAPIKey,
		"set-cookie sid=" + plantedSmuggled,
	}, "\n")

	return &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Properties: AuditProperties{
			SchemaVersion: SchemaVersion,
			AuditID:       "0f9c2b1e-4a7d-4c33-9f21-6b8a0d5e7c14",
			State:         StateDastSealed,
			Version:       1,
			CreatedAt:     createdAt,
			Target: Target{
				RepoURL: "https://x-access-token:" + plantedCheckoutToken +
					"@git.invalid/acme/payments.git",
				Ref:    "refs/heads/main",
				Commit: "6f1d2c3b4a59687776655443322110ffeeddccbb",
				RuntimeBaseURL: "https://scanner:" + plantedRuntimeBasicAuth +
					"@staging.payments.internal",
				Provenance:   TargetProvenanceBootedClean,
				Provisioning: TargetProvisioningEphemeralManifest,
			},
			Trigger: Trigger{
				Kind:         "scheduled",
				PolicyID:     "nightly-full",
				PolicyRef:    ".anvil/policy.yml@6f1d2c3",
				ConfigSource: ".anvil/policy.yml",
				Actor:        "systemd-timer",
				ResolvedAt:   createdAt,
			},
			Deadline: Deadline{
				DeadlineAt:          createdAt.Add(DefaultClaimTimeoutSeconds * time.Second),
				ClaimTimeoutSeconds: DefaultClaimTimeoutSeconds,
			},
			Index: Index{
				Counts:    IndexCounts{Total: 1, Dast: 1},
				ReadOrder: DefaultReadOrder(),
				ByCwe:     map[string][]string{"89": {"f-1"}},
				TaskCards: "cards/",
				Blobs:     "blobs/",
			},
			DastStatus: DastStatusCompletedFindings,
		},
		Runs: []Run{{
			Tool: Tool{Driver: ToolComponent{Name: "nuclei", Version: "3.4.7"}},
			AutomationDetails: RunAutomationDetails{
				ID:              "anvil/dast/1",
				CorrelationGUID: "0f9c2b1e-4a7d-4c33-9f21-6b8a0d5e7c14",
			},
			Properties: RunProperties{
				Half:     HalfDast,
				Status:   HalfStatusSealed,
				SealedAt: &sealedAt,
				DastCoverage: &DastCoverage{
					ProbedCount:         31,
					InventoryUnionCount: 50,
					EndpointCoverage:    31.0 / 50.0,
					InventoryProvenanceMix: map[InventoryProvenance]int{
						InventoryProvenanceRuntimeSpec: 40,
						InventoryProvenanceCrawl:       10,
					},
					ConfirmedCount: 40,
					CandidateCount: 10,
				},
				RouteTableDigest: "sha256:9a1b",
				RuntimeTarget: &RuntimeTarget{
					BaseURL:        "https://staging.payments.internal",
					AuthProfileRef: ".anvil/auth.yml@6f1d2c3",
					Scope:          []string{"https://staging.payments.internal/"},
				},
			},
			Results: []Result{{
				RuleID: "sqli-login",
				Level:  LevelError,
				Message: Message{
					Text: "SQL injection at POST /api/login; the scan authenticated with api_key=" + plantedAPIKey,
				},
				WebRequest: &WebRequest{
					Protocol: "HTTP",
					Version:  "1.1",
					Target: "https://scanuser:" + plantedURLPassword + "@staging.payments.internal" +
						"/api/login?api_key=" + plantedAPIKey + "&user=admin" +
						"#access_token=" + plantedFragmentToken + "&state=xyz",
					Method: "POST",
					Headers: map[string]string{
						"Content-Type":        "application/json",
						"Accept":              "application/json",
						"Authorization":       "Bearer " + plantedBearer,
						"Proxy-Authorization": "Basic " + plantedProxyCred,
						"Cookie":              "theme=dark; session=" + plantedCookie + "; lang=en",
						"X-Trace-Id":          "ok\r\nSet-Cookie: sid=" + plantedSmuggled,
						"User-Agent":          "anvil-dast/0.1.0",
					},
					Parameters: map[string]string{
						"username": "' OR '1'='1' -- ",
						"password": "irrelevant",
						"api_key":  plantedAPIKey,
					},
					Body: &ArtifactContent{
						Text: `{"username":"' OR '1'='1' -- ","token":"` + plantedBearer + `"}`,
					},
				},
				WebResponse: &WebResponse{
					Protocol:     "HTTP",
					Version:      "1.1",
					StatusCode:   500,
					ReasonPhrase: "Internal Server Error",
					Headers: map[string]string{
						"Content-Type": "text/html; charset=utf-8",
						"Set-Cookie":   "session=" + plantedCookie + "; HttpOnly",
					},
					Body: &ArtifactContent{Text: body},
				},
				PartialFingerprints: map[string]string{
					PartialFingerprintAnvilFindingID: strings.Repeat("a", FingerprintDigestHexLen),
				},
				Properties: ResultProperties{
					FindingID:     "f-1",
					Half:          HalfDast,
					Confidence:    0.9,
					Verdict:       VerdictTruePositive,
					EvidenceClass: EvidenceClassDastConfirmed,
					Detector: DetectorRef{
						Kind: DetectorKindDast, Model: "nuclei", Revision: "3.4.7",
					},
					RemediableByAgent: true,
					Reasoning:         "Error-based SQL injection confirmed by a stack trace.",
					Trust:             TrustAssertion{Default: TrustUntrusted},
					Repro: &Repro{
						// plantedCurlOnly appears nowhere else in the record,
						// so its absence after masking cannot be explained by
						// propagation from a header (CRITIQUE-02 F11).
						Curl: "curl -X POST -H 'Authorization: Bearer " + plantedBearer +
							"' -H 'X-Session-Token: " + plantedCurlOnly +
							"' https://staging.payments.internal/api/login",
						InjectionPoint: ReproInjection{Kind: InjectionPointBody, Name: "username"},
						Payload:        "' OR '1'='1' -- ",
						ObservedSignal: ReproSignal{
							Kind:  EvidenceSignalResponseStackTrace,
							Match: &TrustedString{Text: "sqlite3.OperationalError", Trust: TrustUntrusted},
						},
						Env: ReproEnv{Sanitizers: []string{}, AslrEnabled: true},
					},
				},
			}},
		}},
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// The stop-condition test
// ---------------------------------------------------------------------------

// TestMaskRecordLeavesNoPlantedSecretAnywhere is R.8's stop condition: after
// masking, the SERIALIZED record contains zero occurrences of any planted
// value, anywhere in the output.
//
// It asserts over the marshalled whole record rather than over the fields it
// happens to know about, because the failure this guards against is a secret
// surviving in a field the author of the masker did not think of. Checking
// only webRequest.headers would pass while a live cookie sat in the response
// body two fields away.
func TestMaskRecordLeavesNoPlantedSecretAnywhere(t *testing.T) {
	log := dastFixture()

	// Sanity: the fixture must actually contain what we claim, or the
	// absence assertion below proves nothing.
	before := mustMarshal(t, log)
	for name, secret := range allPlantedSecrets() {
		if !strings.Contains(before, secret) {
			t.Fatalf("fixture bug: %s is not present before masking", name)
		}
	}

	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}

	after := mustMarshal(t, log)
	for name, secret := range allPlantedSecrets() {
		if strings.Contains(after, secret) {
			t.Errorf("%s survived masking; the serialized record still contains it", name)
		}
	}
	if !strings.Contains(after, RedactedPlaceholder) {
		t.Errorf("nothing was redacted at all")
	}
}

// TestMaskedRecordStillValidates: masking must not break the contract. A
// masker that produced an unstorable record would simply move the failure.
func TestMaskedRecordStillValidates(t *testing.T) {
	log := dastFixture()
	if err := log.Validate(); err != nil {
		t.Fatalf("fixture does not validate before masking: %v", err)
	}
	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	if err := log.Validate(); err != nil {
		t.Errorf("record does not validate after masking: %v", err)
	}
}

// TestMaskRecordPreservesEvidence. Over-redaction is safe for secrets and
// fatal for findings: the injection payload, the endpoint, the parameter
// NAMES and the stack trace are what the coding agent patches from.
func TestMaskRecordPreservesEvidence(t *testing.T) {
	log := dastFixture()
	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	r := &log.Runs[0].Results[0]

	if got := r.WebRequest.Parameters["username"]; got != "' OR '1'='1' -- " {
		t.Errorf("the injection payload was destroyed: username = %q", got)
	}
	if _, ok := r.WebRequest.Parameters["api_key"]; !ok {
		t.Errorf("the api_key parameter NAME was removed; the name is evidence, only the value is a secret")
	}
	if !strings.Contains(r.WebRequest.Target, "/api/login") {
		t.Errorf("the endpoint path was lost: %q", r.WebRequest.Target)
	}
	if !strings.Contains(r.WebRequest.Target, "user=admin") {
		t.Errorf("a non-sensitive query parameter was redacted: %q", r.WebRequest.Target)
	}
	if !strings.Contains(r.WebRequest.Target, "scanuser") {
		t.Errorf("the userinfo USERNAME was redacted; only the password is a secret: %q", r.WebRequest.Target)
	}
	if !strings.Contains(r.WebResponse.Body.Text, "sqlite3.OperationalError") {
		t.Errorf("the stack trace evidence was destroyed")
	}
	if r.WebResponse.Headers["Content-Type"] != "text/html; charset=utf-8" {
		t.Errorf("a benign header was redacted: %q", r.WebResponse.Headers["Content-Type"])
	}
	if r.Properties.Repro.Payload != "' OR '1'='1' -- " {
		t.Errorf("the repro payload was destroyed")
	}
}

// TestPropagationReachesNonHeaderFields pins the mechanism the stop-condition
// test depends on: a secret redacted at its header is also removed from every
// OTHER string that echoes it. Without this, `MaskRecord` would redact the
// Cookie header and leave the same cookie in the 30 KB debug page beneath it.
func TestPropagationReachesNonHeaderFields(t *testing.T) {
	log := dastFixture()
	rep, err := (&Masker{}).Mask(log)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if rep.PropagatedRedactions == 0 {
		t.Fatalf("propagation changed nothing; the echoed cookie and api key must have been removed")
	}
	r := &log.Runs[0].Results[0]
	for label, field := range map[string]string{
		"webResponse.body":        r.WebResponse.Body.Text,
		"result.message.text":     r.Message.Text,
		"anvil/repro.curl":        r.Properties.Repro.Curl,
		"webRequest.body":         r.WebRequest.Body.Text,
		"webRequest.target":       r.WebRequest.Target,
		"webResponse.reasonPhras": r.WebResponse.ReasonPhrase,
	} {
		for name, secret := range allPlantedSecrets() {
			if strings.Contains(field, secret) {
				t.Errorf("%s still contains %s", label, name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Fail-closed
// ---------------------------------------------------------------------------

// TestFailsClosedOnUnexpectedHeaderShape. A masker that fails OPEN on a
// header it cannot parse is worse than no masker, because the redactions it
// did make imply the rest were checked. Every case here must end in a
// redaction AND an anomaly.
func TestFailsClosedOnUnexpectedHeaderShape(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"space inside the field name", "X-Weird Header"},
		{"colon inside the field name", "X-Weird:Header"},
		{"empty field name", ""},
		{"non-ASCII field name", "X-Ünïcode"},
		{"control byte in the field name", "X-Tab\tName"},
		{"leading whitespace", " Authorization"},
		{"trailing whitespace", "Cookie "},
		{"comma-separated field name", "Cookie,Set-Cookie"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := dastFixture()
			h := log.Runs[0].Results[0].WebResponse.Headers
			h[tc.header] = "value-that-must-not-survive-0123456789"

			rep, err := (&Masker{}).Mask(log)
			if err != nil {
				t.Fatalf("Mask: %v", err)
			}
			if got := h[tc.header]; got != RedactedPlaceholder {
				t.Errorf("header %q was waved through with value %q; the masker failed OPEN", tc.header, got)
			}
			if !hasAnomaly(rep, "R1") {
				t.Errorf("no R1 anomaly recorded for %q; a silent fail-closed is still a silent surprise", tc.header)
			}
		})
	}
}

// TestFailsClosedOnCRLFInHeaderValue is the response-splitting case: the
// header NAME is innocent, and the live cookie rides in its value. A
// name-only denylist cannot see it.
func TestFailsClosedOnCRLFInHeaderValue(t *testing.T) {
	log := dastFixture()
	rep, err := (&Masker{}).Mask(log)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	h := log.Runs[0].Results[0].WebRequest.Headers
	if got := h["X-Trace-Id"]; got != RedactedPlaceholder {
		t.Errorf("a CRLF-smuggled Set-Cookie survived in X-Trace-Id: %q", got)
	}
	if !hasAnomaly(rep, "R2") {
		t.Errorf("no R2 anomaly recorded for the CRLF header value")
	}
	if strings.Contains(mustMarshal(t, log), plantedSmuggled) {
		t.Errorf("the smuggled session id survived elsewhere in the record")
	}
}

// TestFailsClosedOnUnclassifiableParameterName covers rule R3.
func TestFailsClosedOnUnclassifiableParameterName(t *testing.T) {
	log := dastFixture()
	p := log.Runs[0].Results[0].WebRequest.Parameters
	p["odd\x00name"] = "value-that-must-not-survive-0123456789"
	p[""] = "another-value-that-must-not-survive"

	rep, err := (&Masker{}).Mask(log)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	for _, name := range []string{"odd\x00name", ""} {
		if got := p[name]; got != RedactedPlaceholder {
			t.Errorf("parameter %q was waved through with %q", name, got)
		}
	}
	if !hasAnomaly(rep, "R3") {
		t.Errorf("no R3 anomaly recorded")
	}
}

func hasAnomaly(rep *MaskReport, rule string) bool {
	for _, a := range rep.Anomalies {
		if strings.HasPrefix(a.Reason, rule) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Denylist coverage
// ---------------------------------------------------------------------------

// TestDenylistMatchesThePlan pins the five names and two patterns
// plan/40-record-and-storage.md R.8 specifies. If a future edit drops one,
// this fails rather than the masker silently narrowing.
func TestDenylistMatchesThePlan(t *testing.T) {
	want := []string{"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
	got := DenylistedHeaderNames()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("the plan's denylist name %q is missing from DenylistedHeaderNames()", w)
		}
	}
	subs := DenylistedHeaderSubstrings()
	for _, w := range []string{"token", "secret"} {
		found := false
		for _, s := range subs {
			if s == w {
				found = true
			}
		}
		if !found {
			t.Errorf("the plan's %q pattern is missing from DenylistedHeaderSubstrings()", w)
		}
	}
}

// TestDenylistIsCaseInsensitiveAndPatternMatched. The plan says "any header
// matching *token*/*secret* case-insensitively".
func TestDenylistIsCaseInsensitiveAndPatternMatched(t *testing.T) {
	sensitive := []string{
		"AUTHORIZATION", "authorization", "AuThOrIzAtIoN",
		"COOKIE", "Set-COOKIE", "PROXY-AUTHORIZATION", "X-API-KEY",
		"X-Auth-Token", "x-csrf-token", "X-Amz-Security-Token", "X-Client-Secret",
		"refresh-TOKEN",
	}
	for _, name := range sensitive {
		log := dastFixture()
		h := log.Runs[0].Results[0].WebResponse.Headers
		h[name] = "live-value-0123456789"
		if err := MaskRecord(log); err != nil {
			t.Fatalf("MaskRecord: %v", err)
		}
		if got := h[name]; got != RedactedPlaceholder {
			t.Errorf("header %q was not redacted (got %q)", name, got)
		}
	}

	benign := []string{"Content-Type", "Accept", "User-Agent", "Content-Length", "ETag"}
	for _, name := range benign {
		log := dastFixture()
		h := log.Runs[0].Results[0].WebResponse.Headers
		h[name] = "benign-value"
		if err := MaskRecord(log); err != nil {
			t.Fatalf("MaskRecord: %v", err)
		}
		if got := h[name]; got != "benign-value" {
			t.Errorf("benign header %q was redacted (got %q); over-redaction destroys evidence", name, got)
		}
	}
}

// TestKnownDenylistGaps documents, executably, what the denylist as specified
// does NOT catch.
//
// plan/40-record-and-storage.md Open Question 8 records that this list is
// "documented but not exhaustively researched" and asks for a dedicated
// security review before the masking pipeline ships. This test is that
// admission in a form that cannot rot: it asserts the CURRENT behaviour, so
// when the review widens the list, this test fails and has to be updated
// deliberately rather than the gap being rediscovered in production.
func TestKnownDenylistGaps(t *testing.T) {
	gaps := []string{
		"Api-Key",          // only the exact `x-api-key` is listed
		"ApiKey",           //
		"WWW-Authenticate", // carries a challenge, sometimes a nonce
		"Authentication",   // not `Authorization`
		"Location",         // carries one-time codes and implicit-flow tokens
		"X-Amz-Credential",
	}
	for _, name := range gaps {
		if isDenylistedHeader(name) {
			t.Errorf("%q is now denylisted -- good, but this test and the Open Question 8 "+
				"note in mask.go both claim it is not. Update both.", name)
		}
	}
}

// TestKnownLimitationBodyOnlySecretSurvives is the other honest failure.
//
// There is no shape-based body scanner here, on purpose: a "looks like a JWT"
// regex cannot fail closed, so it manufactures exactly the false confidence
// this package exists to avoid. The consequence is that a secret which
// appears ONLY in a body, and never in a denylisted header or a
// secret-named parameter, is not removed. Asserting it makes the boundary of
// the guarantee testable instead of merely documented.
func TestKnownLimitationBodyOnlySecretSurvives(t *testing.T) {
	const bodyOnly = "ghp_bodyOnlySecretThatNoHeaderRuleCanSee123456"
	log := dastFixture()
	log.Runs[0].Results[0].WebResponse.Body.Text += "\nleaked=" + bodyOnly

	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	if !strings.Contains(log.Runs[0].Results[0].WebResponse.Body.Text, bodyOnly) {
		t.Errorf("a body-only secret is now removed -- good, but mask.go's header comment " +
			"states it is not. Update the comment and this test together.")
	}
}

// TestShortSecretsAreNotPropagated pins the MinPropagatedSecretLen bound: the
// header is still redacted unconditionally, but a 3-byte value is not chased
// through the rest of the record, because replacing every "abc" in a stack
// trace would destroy the evidence and protect nothing.
func TestShortSecretsAreNotPropagated(t *testing.T) {
	log := dastFixture()
	r := &log.Runs[0].Results[0]
	r.WebRequest.Headers["Cookie"] = "sid=abc"
	r.WebResponse.Body.Text = "the letters abc appear in ordinary prose"

	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	if r.WebRequest.Headers["Cookie"] != RedactedPlaceholder {
		t.Errorf("the short cookie was not redacted at its header; the length bound must not affect structural masking")
	}
	if !strings.Contains(r.WebResponse.Body.Text, "abc") {
		t.Errorf("a 3-byte value was propagated into ordinary prose: %q", r.WebResponse.Body.Text)
	}
}

// ---------------------------------------------------------------------------
// Body caps and Tier-2 spill
// ---------------------------------------------------------------------------

// TestBodyCapsAndSpill: the 8 KB / 32 KB ZAP thresholds hold, the remainder
// spills rather than being dropped, and the record says so in band.
func TestBodyCapsAndSpill(t *testing.T) {
	log := dastFixture()
	r := &log.Runs[0].Results[0]
	r.WebRequest.Body.Text = strings.Repeat("q", MaxInlineRequestBodyBytes+5000)
	r.WebResponse.Body.Text = strings.Repeat("s", MaxInlineResponseBodyBytes+9000)

	var sunk []Spill
	m := &Masker{Spill: func(s Spill) (string, error) {
		sunk = append(sunk, s)
		return "blobs/" + s.Sha256, nil
	}}
	rep, err := m.Mask(log)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}

	if rep.BodiesTruncated != 2 {
		t.Fatalf("BodiesTruncated = %d, want 2", rep.BodiesTruncated)
	}
	if len(sunk) != 2 {
		t.Fatalf("the spill sink saw %d bodies, want 2", len(sunk))
	}
	if len(r.WebRequest.Body.Text) > MaxInlineRequestBodyBytes {
		t.Errorf("request body is %d bytes, over the %d cap (the truncation notice must fit INSIDE the cap)",
			len(r.WebRequest.Body.Text), MaxInlineRequestBodyBytes)
	}
	if len(r.WebResponse.Body.Text) > MaxInlineResponseBodyBytes {
		t.Errorf("response body is %d bytes, over the %d cap",
			len(r.WebResponse.Body.Text), MaxInlineResponseBodyBytes)
	}
	for _, s := range rep.Spills {
		if !strings.Contains(bodyAt(t, log, s.Pointer), s.Ref) {
			t.Errorf("the record does not reference the spilled blob %s at %s", s.Ref, s.Pointer)
		}
		if !strings.HasPrefix(s.Ref, "blobs/") {
			t.Errorf("the SpillFunc's returned reference was ignored: %q", s.Ref)
		}
		sum := sha256.Sum256([]byte(s.Content))
		if want := "sha256:" + hex.EncodeToString(sum[:]); s.Sha256 != want {
			t.Errorf("spill digest %s does not match its content digest %s", s.Sha256, want)
		}
		if s.InlineBytes >= s.TotalBytes {
			t.Errorf("spill claims InlineBytes=%d of TotalBytes=%d", s.InlineBytes, s.TotalBytes)
		}
	}
}

func bodyAt(t *testing.T, log *SARIFLog, pointer string) string {
	t.Helper()
	r := &log.Runs[0].Results[0]
	switch {
	case strings.HasSuffix(pointer, "/webRequest/body"):
		return r.WebRequest.Body.Text
	case strings.HasSuffix(pointer, "/webResponse/body"):
		return r.WebResponse.Body.Text
	}
	t.Fatalf("unexpected spill pointer %q", pointer)
	return ""
}

// TestSpilledBlobIsMaskedAndItsDigestMatches is why truncation runs LAST.
//
// A secret sitting past the 32 KB cap is invisible to any check on the inline
// prefix. If the digest were taken before propagation, the Tier-2 blob would
// be a durable, content-addressed copy of a live credential -- the exact
// outcome research/18 Risk #10 forbids, moved one tier down.
func TestSpilledBlobIsMaskedAndItsDigestMatches(t *testing.T) {
	log := dastFixture()
	r := &log.Runs[0].Results[0]
	r.WebResponse.Body.Text = strings.Repeat("s", MaxInlineResponseBodyBytes+1000) +
		"\ntrailing echo: session=" + plantedCookie

	rep, err := (&Masker{}).Mask(log)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if len(rep.Spills) != 1 {
		t.Fatalf("got %d spills, want 1", len(rep.Spills))
	}
	sp := rep.Spills[0]
	if strings.Contains(sp.Content, plantedCookie) {
		t.Errorf("the spilled Tier-2 blob still contains the session cookie")
	}
	if !strings.Contains(sp.Content, RedactedPlaceholder) {
		t.Errorf("the spilled blob was never masked at all")
	}
	sum := sha256.Sum256([]byte(sp.Content))
	if want := "sha256:" + hex.EncodeToString(sum[:]); sp.Sha256 != want {
		t.Errorf("the reference digest is not over the MASKED bytes: got %s want %s", sp.Sha256, want)
	}
}

// TestTruncationDoesNotSplitARune.
func TestTruncationDoesNotSplitARune(t *testing.T) {
	log := dastFixture()
	// "…" is three bytes, so some cut points land mid-rune.
	body := strings.Repeat("…", MaxInlineResponseBodyBytes)
	log.Runs[0].Results[0].WebResponse.Body.Text = body

	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	got := log.Runs[0].Results[0].WebResponse.Body.Text
	if !utf8.ValidString(got) {
		t.Errorf("truncation split a UTF-8 rune")
	}
	if len(got) > MaxInlineResponseBodyBytes {
		t.Errorf("body is %d bytes, over the cap", len(got))
	}
}

// TestSpillFuncErrorAborts: a Tier-2 write that fails must not be reported as
// a clean mask, or the reference in the record points at nothing.
func TestSpillFuncErrorAborts(t *testing.T) {
	log := dastFixture()
	log.Runs[0].Results[0].WebResponse.Body.Text = strings.Repeat("s", MaxInlineResponseBodyBytes+1)
	m := &Masker{Spill: func(Spill) (string, error) { return "", errTestSpill }}
	if _, err := m.Mask(log); err == nil {
		t.Fatalf("Mask returned nil after the spill sink failed")
	}
}

var errTestSpill = &EnumError{Field: "test", Value: "spill", Allowed: []string{"nope"}}

// ---------------------------------------------------------------------------
// Determinism, idempotence, post-condition
// ---------------------------------------------------------------------------

// TestMaskRecordIsDeterministic. Map iteration order in Go is randomised;
// masking output that varies run to run cannot be golden-tested, and a masker
// nobody can pin is a masker nobody can prove.
func TestMaskRecordIsDeterministic(t *testing.T) {
	var first string
	var firstReport *MaskReport
	for i := 0; i < 25; i++ {
		log := dastFixture()
		rep, err := (&Masker{}).Mask(log)
		if err != nil {
			t.Fatalf("Mask: %v", err)
		}
		got := mustMarshal(t, log)
		if i == 0 {
			first, firstReport = got, rep
			continue
		}
		if got != first {
			t.Fatalf("iteration %d produced a different masked record", i)
		}
		if !reflect.DeepEqual(rep, firstReport) {
			t.Fatalf("iteration %d produced a different MaskReport:\n got %+v\nwant %+v", i, rep, firstReport)
		}
	}
}

// TestMaskRecordIsIdempotent. Masking is the last step of assembly, but a
// re-entrant consumer may re-assemble; masking an already-masked record must
// be a no-op rather than, say, truncating the truncation notice.
func TestMaskRecordIsIdempotent(t *testing.T) {
	log := dastFixture()
	log.Runs[0].Results[0].WebResponse.Body.Text = strings.Repeat("s", MaxInlineResponseBodyBytes+2000)
	if err := MaskRecord(log); err != nil {
		t.Fatalf("first MaskRecord: %v", err)
	}
	once := mustMarshal(t, log)
	if err := MaskRecord(log); err != nil {
		t.Fatalf("second MaskRecord: %v", err)
	}
	if twice := mustMarshal(t, log); twice != once {
		t.Errorf("masking twice changed the record")
	}
}

// TestAssertMaskedIsTheSinkGate. plan/00-SPINE.md S7 is "enforce in code, not
// documentation": a sink can refuse an unmasked record instead of trusting
// that some earlier step remembered.
func TestAssertMaskedIsTheSinkGate(t *testing.T) {
	log := dastFixture()
	if err := AssertMasked(log); err == nil {
		t.Fatalf("AssertMasked accepted a record with a live Authorization header")
	}
	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	if err := AssertMasked(log); err != nil {
		t.Errorf("AssertMasked rejected a masked record: %v", err)
	}

	t.Run("rejects an oversized body", func(t *testing.T) {
		log := dastFixture()
		if err := MaskRecord(log); err != nil {
			t.Fatalf("MaskRecord: %v", err)
		}
		log.Runs[0].Results[0].WebResponse.Body.Text = strings.Repeat("s", MaxInlineResponseBodyBytes+1)
		if err := AssertMasked(log); err == nil {
			t.Errorf("AssertMasked accepted a body over the 32 KB cap")
		}
	})

	t.Run("rejects an unmasked sensitive parameter", func(t *testing.T) {
		log := dastFixture()
		if err := MaskRecord(log); err != nil {
			t.Fatalf("MaskRecord: %v", err)
		}
		log.Runs[0].Results[0].WebRequest.Parameters["api_key"] = "put-back-0123456789"
		if err := AssertMasked(log); err == nil {
			t.Errorf("AssertMasked accepted a live api_key parameter")
		}
	})

	t.Run("rejects a CRLF header value", func(t *testing.T) {
		log := dastFixture()
		if err := MaskRecord(log); err != nil {
			t.Fatalf("MaskRecord: %v", err)
		}
		log.Runs[0].Results[0].WebResponse.Headers["X-Trace"] = "ok\r\nSet-Cookie: sid=live"
		if err := AssertMasked(log); err == nil {
			t.Errorf("AssertMasked accepted a CRLF-smuggled header")
		}
	})
}

// TestMaskRecordRejectsNil.
func TestMaskRecordRejectsNil(t *testing.T) {
	if err := MaskRecord(nil); err == nil {
		t.Errorf("MaskRecord(nil) returned nil")
	}
	if err := AssertMasked(nil); err == nil {
		t.Errorf("AssertMasked(nil) returned nil")
	}
}

// TestMaskRecordOnARecordWithoutDASTEvidence: the SAST half has no webRequest
// or webResponse at all, and masking must be a clean no-op rather than a nil
// dereference.
func TestMaskRecordOnARecordWithoutDASTEvidence(t *testing.T) {
	log := dastFixture()
	r := &log.Runs[0].Results[0]
	r.WebRequest, r.WebResponse = nil, nil
	// The reproduction command line is HTTP evidence too, and it is masked
	// even when the request/response pair is gone -- see
	// TestReproCurlIsMaskedFromItsOwnEvidence. Drop it so this test is about
	// the no-evidence case it claims to be about.
	r.Properties.Repro = nil
	r.Properties.Trust.Default = TrustUntrusted

	rep, err := (&Masker{}).Mask(log)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if rep.HeadersRedacted != 0 || rep.BodiesTruncated != 0 {
		t.Errorf("masked something on a record with no HTTP evidence: %+v", rep)
	}
	if err := AssertMasked(log); err != nil {
		t.Errorf("AssertMasked: %v", err)
	}
}

// ---------------------------------------------------------------------------
// URL handling
// ---------------------------------------------------------------------------

func TestMaskURL(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:         "query api key",
			in:           "https://h.invalid/p?api_key=LIVEKEY0123456789&user=admin",
			wantContains: []string{"api_key=" + RedactedPlaceholder, "user=admin"},
			wantAbsent:   []string{"LIVEKEY0123456789"},
		},
		{
			name:         "implicit-flow token in the fragment",
			in:           "https://h.invalid/cb#access_token=LIVETOKEN0123456789&state=xyz",
			wantContains: []string{"access_token=" + RedactedPlaceholder, "state=xyz"},
			wantAbsent:   []string{"LIVETOKEN0123456789"},
		},
		{
			name:         "userinfo password",
			in:           "https://alice:LIVEPASS0123456789@h.invalid/p",
			wantContains: []string{"alice:" + RedactedPlaceholder + "@h.invalid"},
			wantAbsent:   []string{"LIVEPASS0123456789"},
		},
		{
			name:         "percent-encoded payload is preserved byte for byte",
			in:           "https://h.invalid/p?q=%27%20OR%201%3D1&token=LIVE0123456789",
			wantContains: []string{"q=%27%20OR%201%3D1", "token=" + RedactedPlaceholder},
			wantAbsent:   []string{"LIVE0123456789"},
		},
		{
			name:         "plain anchor fragment is untouched",
			in:           "https://h.invalid/p#section-2",
			wantContains: []string{"#section-2"},
		},
		{
			name:         "bare flag with no value",
			in:           "https://h.invalid/p?debug&token=LIVE0123456789",
			wantContains: []string{"debug", "token=" + RedactedPlaceholder},
			wantAbsent:   []string{"LIVE0123456789"},
		},
		{
			name:         "no query at all",
			in:           "https://h.invalid/api/login",
			wantContains: []string{"https://h.invalid/api/login"},
			wantAbsent:   []string{"?", "#"},
		},
		{
			// A '?' that belongs to the fragment must not be promoted into a
			// query delimiter when the URL is rebuilt.
			name:         "question mark inside the fragment",
			in:           "https://h.invalid/p#a?b=c",
			wantContains: []string{"https://h.invalid/p#a?b=c"},
			wantAbsent:   []string{"p?#"},
		},
		{
			name:         "empty query is preserved as empty, not dropped",
			in:           "https://h.invalid/p?",
			wantContains: []string{"https://h.invalid/p?"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Masker{}
			got := m.maskURL("/t", tc.in, newSecretSet(MinPropagatedSecretLen), &MaskReport{})
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("maskURL(%q) = %q, want it to contain %q", tc.in, got, want)
				}
			}
			for _, bad := range tc.wantAbsent {
				if strings.Contains(got, bad) {
					t.Errorf("maskURL(%q) = %q, must not contain %q", tc.in, got, bad)
				}
			}
		})
	}
}

// TestTruncateToRuneBoundary.
func TestTruncateToRuneBoundary(t *testing.T) {
	const s = "abc…def" // 'e' is 3 bytes: a b c e0 80 a6 d e f
	for n := 0; n <= len(s); n++ {
		got := truncateToRuneBoundary(s, n)
		if len(got) > n {
			t.Errorf("truncateToRuneBoundary(%q, %d) = %q, longer than n", s, n, got)
		}
		if !utf8.ValidString(got) {
			t.Errorf("truncateToRuneBoundary(%q, %d) = %q, not valid UTF-8", s, n, got)
		}
		if !strings.HasPrefix(s, got) {
			t.Errorf("truncateToRuneBoundary(%q, %d) = %q, not a prefix", s, n, got)
		}
	}
}

// TestIsHTTPFieldName.
func TestIsHTTPFieldName(t *testing.T) {
	valid := []string{"Authorization", "X-Api-Key", "a", "X_Custom", "X.Y", "a1!#$%&'*+-.^_`|~"}
	for _, s := range valid {
		if !isHTTPFieldName(s) {
			t.Errorf("isHTTPFieldName(%q) = false, want true", s)
		}
	}
	invalid := []string{"", " ", "a b", "a:b", "a,b", "a\tb", "a\nb", "ü", "a(b)", "a/b", "a@b", `a"b`}
	for _, s := range invalid {
		if isHTTPFieldName(s) {
			t.Errorf("isHTTPFieldName(%q) = true, want false", s)
		}
	}
}

// TestJSONPointerEscape covers RFC 6901 §3.
func TestJSONPointerEscape(t *testing.T) {
	if got := jsonPointerEscape("a/b~c"); got != "a~1b~0c" {
		t.Errorf("jsonPointerEscape(%q) = %q, want %q", "a/b~c", got, "a~1b~0c")
	}
	if got := jsonPointerEscape("~/"); got != "~0~1" {
		t.Errorf("jsonPointerEscape(%q) = %q, want %q", "~/", got, "~0~1")
	}
}

// ---------------------------------------------------------------------------
// Regression guards for CRITIQUE-02 (R.10 critic gate 2).
// ---------------------------------------------------------------------------

// probeSecret is a credential planted by the tests below into ONE field at a
// time. It is long enough to be propagated and contains no character
// encoding/json escapes.
const probeSecret = "PROBE-LIVE-CREDENTIAL-0123456789abcdef"

// minimalLog is a record with no HTTP evidence at all: no webRequest, no
// webResponse, no runtime target, no credential in any URL. It is the fixture
// that makes a single-field assertion honest — whatever it proves cannot be
// explained by masking or propagation from somewhere else.
func minimalLog() *SARIFLog {
	l := dastFixture()
	l.Properties.Target.RepoURL = "https://git.invalid/acme/payments"
	l.Properties.Target.RuntimeBaseURL = ""
	l.Runs[0].Properties.RuntimeTarget = nil
	r := &l.Runs[0].Results[0]
	r.Message.Text = "SQL injection at POST /api/login"
	r.WebRequest, r.WebResponse = nil, nil
	r.Properties.Repro = nil
	return l
}

// TestReproCurlIsMaskedFromItsOwnEvidence is CRITIQUE-02 F3(i), reproduced and
// then closed.
//
// The credential is planted ONLY in anvil/repro.curl. There is no
// Authorization header anywhere in this record, so pass 2 propagation has
// nothing to propagate FROM: if the token is gone afterwards, pass 1 looked at
// the curl string itself. That is the assertion the flagship test could not
// make while the fixture put the same value in both places (F11).
func TestReproCurlIsMaskedFromItsOwnEvidence(t *testing.T) {
	log := minimalLog()
	log.Runs[0].Results[0].Properties.Repro = &Repro{
		Curl: "curl -X POST -H 'Authorization: Bearer " + probeSecret +
			"' https://staging.payments.internal/api/login",
		InjectionPoint: ReproInjection{Kind: InjectionPointBody, Name: "username"},
		Payload:        "' OR '1'='1' -- ",
		ObservedSignal: ReproSignal{
			Kind:  EvidenceSignalResponseStackTrace,
			Match: &TrustedString{Text: "sqlite3.OperationalError", Trust: TrustUntrusted},
		},
		Env: ReproEnv{Sanitizers: []string{}, AslrEnabled: true},
	}

	before := mustMarshal(t, log)
	if n := strings.Count(before, probeSecret); n != 1 {
		t.Fatalf("fixture bug: the probe appears %d times, want exactly 1 (in repro.curl only)", n)
	}
	// The gate must refuse it BEFORE masking, or the gate is decorative.
	if err := AssertMasked(log); err == nil {
		t.Error("AssertMasked accepted a record whose repro.curl carries a live bearer token")
	}

	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	curl := log.Runs[0].Results[0].Properties.Repro.Curl
	if strings.Contains(curl, probeSecret) {
		t.Errorf("anvil/repro.curl still carries the token after masking: %q", curl)
	}
	if strings.Contains(mustMarshal(t, log), probeSecret) {
		t.Errorf("the token survives somewhere in the record")
	}
	if !strings.Contains(curl, RedactedPlaceholder) {
		t.Errorf("the curl command was not redacted at all: %q", curl)
	}
	// Over-redaction is fatal for a reproduction: the command must still be
	// replayable once an operator supplies their own credential.
	for _, keep := range []string{"curl", "-X POST", "Authorization:", "/api/login"} {
		if !strings.Contains(curl, keep) {
			t.Errorf("masking destroyed the reproduction: %q is gone from %q", keep, curl)
		}
	}
	if err := AssertMasked(log); err != nil {
		t.Errorf("AssertMasked rejected the masked record: %v", err)
	}
}

// TestReproCurlCredentialCarriers walks the option shapes a curl reproduction
// actually uses. Each case plants the probe in one option and in nothing else.
func TestReproCurlCredentialCarriers(t *testing.T) {
	const sq = "'"
	const dq = "\""
	cases := []struct {
		name string
		curl string
		keep []string // evidence that must survive
	}{
		{"short header, quoted", "curl -H " + sq + "Authorization: Bearer " + probeSecret + sq + " https://h.invalid/p", []string{"Authorization:"}},
		{"long header", "curl --header " + dq + "X-Api-Key: " + probeSecret + dq + " https://h.invalid/p", []string{"X-Api-Key:"}},
		{"long header with =", "curl --header=" + dq + "X-Auth-Token: " + probeSecret + dq + " https://h.invalid/p", []string{"X-Auth-Token:"}},
		{"attached short header", "curl -HAuthorization:Bearer" + probeSecret + " https://h.invalid/p", []string{"Authorization:"}},
		{"clustered short option", "curl -sSH " + sq + "Authorization: Bearer " + probeSecret + sq + " https://h.invalid/p", []string{"-sSH", "Authorization:"}},
		{"proxy header", "curl --proxy-header " + sq + "Proxy-Authorization: Basic " + probeSecret + sq + " https://h.invalid/p", []string{"Proxy-Authorization:"}},
		{"cookie string", "curl -b " + sq + "session=" + probeSecret + "; theme=dark" + sq + " https://h.invalid/p", []string{"curl"}},
		{"user credentials", "curl -u scanuser:" + probeSecret + " https://h.invalid/p", []string{"scanuser:"}},
		{"long user credentials", "curl --user=scanuser:" + probeSecret + " https://h.invalid/p", []string{"scanuser:"}},
		{"data field", "curl -d " + sq + "user=admin&api_key=" + probeSecret + sq + " https://h.invalid/p", []string{"user=admin"}},
		{"url query", "curl https://h.invalid/p?api_key=" + probeSecret + "&user=admin", []string{"user=admin", "/p?"}},
		{"url userinfo", "curl https://scanuser:" + probeSecret + "@h.invalid/p", []string{"scanuser:"}},
		{"unparseable header argument", "curl -H " + sq + "not-a-header-" + probeSecret + sq + " https://h.invalid/p", []string{"curl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Masker{}
			got := m.maskCommandLine("/t", tc.curl, newSecretSet(MinPropagatedSecretLen), &MaskReport{})
			if strings.Contains(got, probeSecret) {
				t.Errorf("maskCommandLine left the credential live:\n  in:  %q\n  out: %q", tc.curl, got)
			}
			if !strings.Contains(got, RedactedPlaceholder) {
				t.Errorf("nothing was redacted:\n  in:  %q\n  out: %q", tc.curl, got)
			}
			for _, keep := range tc.keep {
				if !strings.Contains(got, keep) {
					t.Errorf("evidence %q was destroyed: %q", keep, got)
				}
			}
			// Idempotent, which is what lets AssertMasked re-derive and compare.
			if again := m.maskCommandLine("/t", got, newSecretSet(MinPropagatedSecretLen), &MaskReport{}); again != got {
				t.Errorf("maskCommandLine is not idempotent:\n  once:  %q\n  twice: %q", got, again)
			}
			// And the gate agrees with the masker in both directions.
			if err := assertCommandLineMasked("/t", tc.curl); err == nil {
				t.Errorf("assertCommandLineMasked accepted the unmasked command %q", tc.curl)
			}
			if err := assertCommandLineMasked("/t", got); err != nil {
				t.Errorf("assertCommandLineMasked rejected the masked command %q: %v", got, err)
			}
		})
	}
}

// TestReproCurlLeavesBenignCommandsAlone. Over-redaction destroys the
// reproduction, so a command with no credential in it must come out byte for
// byte identical.
func TestReproCurlLeavesBenignCommandsAlone(t *testing.T) {
	for _, cmd := range []string{
		"curl -X POST -H 'Content-Type: application/json' -d 'user=admin&q=%27%20OR%201%3D1' https://h.invalid/api/login",
		"curl -sS --compressed https://h.invalid/health",
		"curl -b cookies.txt https://h.invalid/p",
		"curl -u scanuser https://h.invalid/p",
		"",
		"curl",
	} {
		if got := (&Masker{}).maskCommandLine("/t", cmd, newSecretSet(MinPropagatedSecretLen), &MaskReport{}); got != cmd {
			t.Errorf("a benign command was rewritten:\n  in:  %q\n  out: %q", cmd, got)
		}
		if err := assertCommandLineMasked("/t", cmd); err != nil {
			t.Errorf("assertCommandLineMasked rejected a benign command %q: %v", cmd, err)
		}
	}
}

// TestTargetURLCredentialsAreMasked is CRITIQUE-02 F3(ii). The credential is
// planted only in anvil/target.repoUrl and anvil/target.runtimeBaseUrl, on a
// record with no HTTP evidence at all, so nothing else can account for its
// disappearance.
func TestTargetURLCredentialsAreMasked(t *testing.T) {
	log := minimalLog()
	log.Properties.Target.RepoURL = "https://x-access-token:" + probeSecret + "@github.com/org/repo.git"
	log.Properties.Target.RuntimeBaseURL = "https://svc:" + probeSecret + "@staging.internal"

	if err := AssertMasked(log); err == nil {
		t.Error("AssertMasked accepted a record whose repoUrl carries a live checkout token")
	}
	if err := MaskRecord(log); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	if got := log.Properties.Target.RepoURL; strings.Contains(got, probeSecret) {
		t.Errorf("anvil/target.repoUrl still carries a live credential: %q", got)
	}
	if got := log.Properties.Target.RuntimeBaseURL; strings.Contains(got, probeSecret) {
		t.Errorf("anvil/target.runtimeBaseUrl still carries a live credential: %q", got)
	}
	if strings.Contains(mustMarshal(t, log), probeSecret) {
		t.Error("the credential survives somewhere in the record")
	}
	// The repository identity is evidence and must survive.
	if !strings.Contains(log.Properties.Target.RepoURL, "github.com/org/repo.git") {
		t.Errorf("masking destroyed the repository identity: %q", log.Properties.Target.RepoURL)
	}
	if err := AssertMasked(log); err != nil {
		t.Errorf("AssertMasked rejected the masked record: %v", err)
	}
}

// TestAssertMaskedRejectsAnUnmaskedTargetURL is CRITIQUE-02 F4, stated as the
// sub-case TestAssertMaskedIsTheSinkGate was missing. Mask masks
// webRequest.target; before this fix AssertMasked did not look at it at all,
// so a record whose only credential was in a URL passed the gate that exists
// to catch precisely that.
func TestAssertMaskedRejectsAnUnmaskedTargetURL(t *testing.T) {
	for _, where := range []struct{ name, target string }{
		{"query", "https://app.invalid/v1/orders?api_key=" + probeSecret},
		{"fragment", "https://app.invalid/cb#access_token=" + probeSecret},
		{"userinfo", "https://alice:" + probeSecret + "@app.invalid/v1/orders"},
	} {
		t.Run(where.name, func(t *testing.T) {
			log := dastFixture()
			if err := MaskRecord(log); err != nil {
				t.Fatalf("MaskRecord: %v", err)
			}
			if err := AssertMasked(log); err != nil {
				t.Fatalf("the masked fixture does not pass the gate: %v", err)
			}
			// Put a credential back the way a record that skipped masking
			// would arrive at the sink.
			log.Runs[0].Results[0].WebRequest.Target = where.target
			if err := AssertMasked(log); err == nil {
				t.Errorf("AssertMasked accepted a webRequest.target carrying a live credential in the %s: %q",
					where.name, where.target)
			}
			// And Mask does clean it, which is what makes the gate's silence
			// a divergence rather than a shared limitation.
			if err := MaskRecord(log); err != nil {
				t.Fatalf("MaskRecord: %v", err)
			}
			if got := log.Runs[0].Results[0].WebRequest.Target; strings.Contains(got, probeSecret) {
				t.Errorf("Mask left the %s credential live: %q", where.name, got)
			}
		})
	}
}

// maskSite is one place walkMaskSurface visits, with a way to plant a live
// credential in it and to put the original value back.
type maskSite struct {
	pointer string
	kind    string
	plant   func()
	restore func()
}

// collectMaskSites enumerates every site of every kind in l. It is the whole
// mask surface, gathered by the same walker Mask and AssertMasked use, so a
// site added to the walker is automatically covered by the test below.
func collectMaskSites(l *SARIFLog) []maskSite {
	var sites []maskSite
	walkMaskSurface(l, surface{
		Headers: func(ptr string, h map[string]string) {
			if h == nil {
				return
			}
			const name = "Authorization"
			old, had := h[name]
			sites = append(sites, maskSite{ptr, "headers",
				func() { h[name] = "Bearer " + probeSecret },
				func() {
					if had {
						h[name] = old
					} else {
						delete(h, name)
					}
				}})
		},
		Parameters: func(ptr string, p map[string]string) {
			if p == nil {
				return
			}
			const name = "api_key"
			old, had := p[name]
			sites = append(sites, maskSite{ptr, "parameters",
				func() { p[name] = probeSecret },
				func() {
					if had {
						p[name] = old
					} else {
						delete(p, name)
					}
				}})
		},
		URL: func(ptr string, p *string) {
			old := *p
			sites = append(sites, maskSite{ptr, "url",
				func() { *p = "https://h.invalid/p?api_key=" + probeSecret },
				func() { *p = old }})
		},
		CommandLine: func(ptr string, p *string) {
			old := *p
			sites = append(sites, maskSite{ptr, "commandLine",
				func() {
					*p = "curl -H 'Authorization: Bearer " + probeSecret + "' https://h.invalid/p"
				},
				func() { *p = old }})
		},
		Body: func(ptr string, b *ArtifactContent, limit int) {
			if b == nil {
				return
			}
			old := b.Text
			sites = append(sites, maskSite{ptr, "body",
				func() { b.Text = strings.Repeat("s", limit+1) },
				func() { b.Text = old }})
		},
	})
	return sites
}

// TestAssertMaskedCoversEverySiteMaskCovers is the structural guard M1 asks
// for: for EVERY site the mask surface exposes, planting a live credential
// there must make AssertMasked refuse the record, and MaskRecord must then
// remove it.
//
// It is written against the walker rather than against a hand-written list of
// fields precisely so it cannot go stale. A future step that teaches Mask
// about a new field adds it to walkMaskSurface; this test then demands the
// sink gate cover it too, and fails if it does not. That is the property
// CRITIQUE-02 F4 found missing — "a gate weaker than the thing it guards is
// worse than none".
func TestAssertMaskedCoversEverySiteMaskCovers(t *testing.T) {
	reference := dastFixture()
	if err := MaskRecord(reference); err != nil {
		t.Fatalf("MaskRecord: %v", err)
	}
	n := len(collectMaskSites(reference))
	if n < 8 {
		t.Fatalf("the mask surface exposes only %d sites; the fixture is not exercising it", n)
	}
	kinds := map[string]bool{}

	for i := 0; i < n; i++ {
		// A fresh masked record per site, so one site's planted credential
		// cannot be scrubbed out of the next by propagation.
		log := dastFixture()
		if err := MaskRecord(log); err != nil {
			t.Fatalf("MaskRecord: %v", err)
		}
		sites := collectMaskSites(log)
		if len(sites) != n {
			t.Fatalf("the mask surface is not deterministic: %d sites, want %d", len(sites), n)
		}
		site := sites[i]
		kinds[site.kind] = true

		if err := AssertMasked(log); err != nil {
			t.Fatalf("%s: the masked fixture does not pass the gate: %v", site.pointer, err)
		}
		site.plant()
		if err := AssertMasked(log); err == nil {
			t.Errorf("AssertMasked accepted a live credential at %s (%s); "+
				"the sink gate is weaker than Mask", site.pointer, site.kind)
		}
		if err := MaskRecord(log); err != nil {
			t.Fatalf("%s: MaskRecord: %v", site.pointer, err)
		}
		if site.kind != "body" && strings.Contains(mustMarshal(t, log), probeSecret) {
			t.Errorf("Mask left the credential planted at %s live", site.pointer)
		}
		if err := AssertMasked(log); err != nil {
			t.Errorf("%s: AssertMasked rejected the re-masked record: %v", site.pointer, err)
		}
		site.restore()
	}

	for _, kind := range []string{"headers", "parameters", "url", "commandLine", "body"} {
		if !kinds[kind] {
			t.Errorf("the fixture exercises no %q site, so that kind is unproven", kind)
		}
	}
}

// TestMaskSurfaceCoversTheNamedCredentialCarriers pins the specific fields
// CRITIQUE-02 named, by POINTER, so that deleting one from walkMaskSurface is
// a test failure rather than a silent regression to F3.
func TestMaskSurfaceCoversTheNamedCredentialCarriers(t *testing.T) {
	seen := map[string]bool{}
	walkMaskSurface(dastFixture(), surface{
		Headers:     func(ptr string, _ map[string]string) { seen[ptr] = true },
		Parameters:  func(ptr string, _ map[string]string) { seen[ptr] = true },
		URL:         func(ptr string, _ *string) { seen[ptr] = true },
		CommandLine: func(ptr string, _ *string) { seen[ptr] = true },
		Body:        func(ptr string, _ *ArtifactContent, _ int) { seen[ptr] = true },
	})
	for _, ptr := range []string{
		"/properties/anvil~1target/repoUrl",
		"/properties/anvil~1target/runtimeBaseUrl",
		"/runs/0/properties/anvil~1runtimeTarget/baseUrl",
		"/runs/0/results/0/webRequest/headers",
		"/runs/0/results/0/webRequest/parameters",
		"/runs/0/results/0/webRequest/target",
		"/runs/0/results/0/webRequest/body",
		"/runs/0/results/0/webResponse/headers",
		"/runs/0/results/0/webResponse/body",
		"/runs/0/results/0/properties/anvil~1repro/curl",
	} {
		if !seen[ptr] {
			t.Errorf("%s is not on the mask surface; CRITIQUE-02 F3 named it as a live-credential carrier", ptr)
		}
	}
}
