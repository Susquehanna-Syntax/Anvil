// Tests for D.24, the authenticated-crawl helper.
//
// This packet holds a credential, so the suite is organised around the two
// properties that make it either safe or not, and every one of them is driven
// through the REAL kernel — authz.InitiateRun, authz.Adjudicate,
// authz.NewRequestIntent, authz.GateAudit.AuditedAdmit,
// authz.Governor.ObserveResponse — with AuthDriver and ArtifactSink as the
// only doubles, because D.9's gate 3 forbids this package from holding a
// socket.
//
//	THE CREDENTIAL NEVER APPEARS. The leak test collects the ACTUAL EMITTED
//	BYTES — every retained authz.GateRecord rendered field by field, every
//	session-event string, every artifact-record string, every byte handed to
//	the sink, every returned error, and %v/%+v/%#v/%q/%d/%x of every exported
//	value this package produces — concatenates them, and searches for the
//	credential. The fixture driver is BUILT TO LEAK: it puts the credential in
//	AuthOutcome.Detail, in LandedPath, in an artifact Name, in artifact bytes
//	raw, and in artifact bytes percent-encoded. A generator that could not
//	produce the breaking input would be the defect.
//
//	A FAILED LOGIN IS NOT AN AUTHENTICATED CRAWL. A driver that fails, a
//	driver that CLAIMS a session Anvil cannot observe, and a session lost
//	mid-scan each produce a different state, and the run timeline is
//	partitioned so that a crawl instant maps to exactly one of them. The
//	assertions are on COUNTS of instants per state, not on the existence of an
//	authenticated window.
//
//	THE KERNEL DECIDES. Without POST <login path> on the EndpointAllowance,
//	gate 15 refuses the credential submission and the driver is never called
//	AT ALL — asserted as authCalls == 0, which is what "nothing left the
//	process" means. With it, the driver sees two distinct, increasing audit
//	sequence numbers.
//
//	THE LIVENESS CHECK FAILS CLOSED IN EVERY DIRECTION. Six ways for a probe
//	to be unanswerable, each asserted to produce false.
//
// The guard-breaking runs are recorded in the packet report, not here: a break
// that stays green is a finding about the test.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
)

// ---------------------------------------------------------------------------
// The credentials every test in this file uses
// ---------------------------------------------------------------------------

const (
	// d24Password contains a SPACE and an "&" on purpose. redact() rewrites
	// "&" to "?", so a sweep run AFTER redaction would not find this string —
	// which is exactly the defect TestRedactionDoesNotDefeatTheSweep pins.
	d24Password = "s3cr3t Pa55w0rd&9xQz"
	// d24TOTP is a second, differently-spelled credential so that a sweep
	// that only ever looks at the first secret is visible.
	d24TOTP = "totp-7f3a91-code"
	// d24Username is NOT a credential. internal/record/mask.go keeps the
	// username deliberately: it names which account the scan authenticated
	// as, and that is evidence.
	d24Username = "scanuser"
)

// d24Credentials returns every credential value this file's fixtures use, as
// PLAINTEXT. It is the needle the leak test searches for, and it exists only
// in _test.go.
func d24Credentials() []string { return []string{d24Password, d24TOTP} }

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// d24AuditSink RETAINS every audit row, unlike countingSink which drops them.
// The leak test searches the rows' rendered bytes, so a credential that
// reached gate 21's Detail would be visible here and nowhere else.
type d24AuditSink struct {
	n    int
	rows []authz.GateRecord
}

func (s *d24AuditSink) WriteGateDecision(r authz.GateRecord) (authz.AuditSeq, error) {
	s.n++
	s.rows = append(s.rows, r)
	return authz.AuditSeq(s.n), nil
}

// bytes renders every field of every row. %+v over a struct of exported
// fields reaches all of them, which is the point: this must not be a
// hand-listed subset that a new field could slip past.
func (s *d24AuditSink) bytes() string {
	var b strings.Builder
	for _, r := range s.rows {
		fmt.Fprintf(&b, "%+v\n", r)
	}
	return b.String()
}

func (s *d24AuditSink) denials() []authz.GateRecord {
	var out []authz.GateRecord
	for _, r := range s.rows {
		if r.Outcome != authz.OutcomeAllow {
			out = append(out, r)
		}
	}
	return out
}

// d24Driver is the AuthDriver double. It records every AuthRequest it was
// handed so a test can assert what actually left rather than what the
// implementation says it sends.
type d24Driver struct {
	outcomes  []AuthOutcome
	outErrs   []error
	probes    []AuthProbe
	probeErrs []error

	seenAuth  []AuthRequest
	seenProbe []AuthRequest
	authCalls int
	probeCall int
}

func (d *d24Driver) Authenticate(_ context.Context, req AuthRequest) (AuthOutcome, error) {
	d.authCalls++
	d.seenAuth = append(d.seenAuth, req)
	i := d.authCalls - 1
	if i < len(d.outErrs) && d.outErrs[i] != nil {
		return AuthOutcome{}, d.outErrs[i]
	}
	if len(d.outcomes) == 0 {
		return AuthOutcome{}, nil
	}
	if i >= len(d.outcomes) {
		i = len(d.outcomes) - 1
	}
	return d.outcomes[i], nil
}

func (d *d24Driver) ProbeSession(_ context.Context, req AuthRequest) (AuthProbe, error) {
	d.probeCall++
	d.seenProbe = append(d.seenProbe, req)
	i := d.probeCall - 1
	if i < len(d.probeErrs) && d.probeErrs[i] != nil {
		return AuthProbe{}, d.probeErrs[i]
	}
	if len(d.probes) == 0 {
		return AuthProbe{}, nil
	}
	if i >= len(d.probes) {
		i = len(d.probes) - 1
	}
	return d.probes[i], nil
}

// d24Alive is the outcome/probe pair of a login that works.
func d24Alive() AuthProbe {
	return AuthProbe{Status: 200, Latency: 4 * time.Millisecond, SessionPresent: true}
}

func d24GoodOutcome() AuthOutcome {
	return AuthOutcome{
		NavStatus: 200, NavLatency: 5 * time.Millisecond,
		SubmitStatus: 302, SubmitLatency: 7 * time.Millisecond,
		SessionEstablished: true,
		LandedPath:         "/account",
		Detail:             "three steps ran",
	}
}

// d24LeakyOutcome is the fixture that PUTS THE CREDENTIAL EVERYWHERE it can.
// It exists so the sweep is tested against an input that actually contains the
// thing it is looking for, in five separate places and three spellings.
func d24LeakyOutcome() AuthOutcome {
	o := d24GoodOutcome()
	o.Detail = "typed " + d24Password + " into the password field"
	// The landed path carries the PASSWORD, not the TOTP, on purpose: the
	// password contains "&", which redact() rewrites, so a sweep that ran
	// after redaction rather than before would miss it and ship nineteen of
	// its twenty characters. The needle list below covers the redacted form
	// precisely so that this case fails rather than passes.
	o.LandedPath = "/account?next=" + d24Password
	o.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactHTTPExchange, Step: 2, Name: "post-login-" + d24Password,
			Bytes: []byte("POST /login\r\n\r\npassword=" + url.QueryEscape(d24Password))},
		{Kind: AuthArtifactStorageState, Step: 0, Name: "storage",
			Bytes: []byte(`{"localStorage":{"totp":"` + d24TOTP + `"}}`)},
		{Kind: AuthArtifactHTTPExchange, Step: 4, Name: "totp-exchange",
			Bytes: []byte("GET /v?c=" + url.PathEscape(d24TOTP))},
		{Kind: AuthArtifactHTTPExchange, Step: 1, Name: "pre-login",
			Bytes: []byte("GET /login HTTP/1.1\r\n\r\n")},
	}
	return o
}

// d24Sink is the ArtifactSink double. It retains the ACTUAL BYTES it was
// handed, which is what makes the leak assertion an assertion about what left
// rather than about what the code intended to send.
type d24Sink struct {
	stored []StoredArtifact
	err    error
}

func (s *d24Sink) StoreAuthArtifact(_ context.Context, a StoredArtifact) error {
	if s.err != nil {
		return s.err
	}
	s.stored = append(s.stored, a)
	return nil
}

func (s *d24Sink) bytes() string {
	var b strings.Builder
	for _, a := range s.stored {
		fmt.Fprintf(&b, "%s|%d|%s|%s\n", a.Kind(), a.Step(), a.Name(), string(a.Bytes()))
	}
	return b.String()
}

// d24Kernel builds a real Governor and GateAudit with a RETAINING audit sink
// and an optional per-endpoint allowance for the login POST.
func d24Kernel(t *testing.T, allow authz.EndpointAllowance) (
	*authz.Governor, *authz.GateAudit, *d24AuditSink) {

	t.Helper()
	init := initiateRun(t)
	scope, err := init.Scope()
	if err != nil {
		t.Fatalf("init.Scope: %v", err)
	}
	att, err := init.Attestation()
	if err != nil {
		t.Fatalf("init.Attestation: %v", err)
	}
	key, res := authz.NewAuditKey(att, scope)
	if !res.Passed() {
		t.Fatalf("authz.NewAuditKey: %v", res.Err())
	}
	run, err := init.RunClock()
	if err != nil {
		t.Fatalf("init.RunClock: %v", err)
	}
	sink := &d24AuditSink{}
	audit, res := authz.NewGateAudit(sink, key, run)
	if !res.Passed() {
		t.Fatalf("authz.NewGateAudit: %v", res.Err())
	}
	gov, res := authz.NewGovernor(authz.GovernorConfig{
		Target:      mustBareTarget(t),
		Scope:       scope,
		Attestation: att,
		Caps:        authz.CodedCaps(),
		Thresholds:  authz.CodedHealthThresholds(),
		Robots:      authz.RobotsNotFound(fixtureHost, 443),
		Allowance:   allow,
		Start:       mustClock(t),
	})
	if !res.Passed() {
		t.Fatalf("authz.NewGovernor: %v", res.Err())
	}
	return gov, audit, sink
}

func d24LoginAllowance(t *testing.T, path string) authz.EndpointAllowance {
	t.Helper()
	a, err := authz.NewEndpointAllowance(authz.EndpointRule{
		Method: authz.MethodPost, Path: path,
	})
	if err != nil {
		t.Fatalf("authz.NewEndpointAllowance: %v", err)
	}
	return a
}

func d24NoAllowance(t *testing.T) authz.EndpointAllowance {
	t.Helper()
	a, err := authz.NewEndpointAllowance()
	if err != nil {
		t.Fatalf("authz.NewEndpointAllowance: %v", err)
	}
	return a
}

func mustSecret(t *testing.T, v string) Secret {
	t.Helper()
	s, err := NewSecret(v)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	return s
}

// d24Steps is the fixture login flow: four steps, two of which carry a
// credential, in the shapes plan/50-dast.md D.24 enumerates.
func d24Steps(t *testing.T) AuthSteps {
	t.Helper()
	steps, err := NewAuthSteps(target.AuthMethodBrowser, ".anvil/auth-steps.yaml", []AuthStep{
		{Kind: AuthStepClick, Selector: "#sign-in"},
		{Kind: AuthStepAutoSteps, Selector: d24Username, Value: mustSecret(t, d24Password)},
		{Kind: AuthStepWait, Wait: 2 * time.Second},
		{Kind: AuthStepTOTPField, Selector: "#totp", Value: mustSecret(t, d24TOTP)},
	})
	if err != nil {
		t.Fatalf("NewAuthSteps: %v", err)
	}
	return steps
}

type d24Opts struct {
	driver     AuthDriver
	sink       ArtifactSink
	noAllow    bool
	loginPath  string
	livePath   string
	alive      []int
	shots      ScreenshotPolicy
	steps      *AuthSteps
	robots     string
	scope      *authz.Scope
	freezeTime bool
}

func d24Config(t *testing.T, o d24Opts) (AuthConfig, *d24AuditSink) {
	t.Helper()
	if o.loginPath == "" {
		o.loginPath = "/login"
	}
	if o.livePath == "" {
		o.livePath = "/account"
	}
	if o.alive == nil {
		o.alive = []int{200}
	}
	if o.shots == ScreenshotPolicyUnset {
		o.shots = ScreenshotPolicyExceptCredentialSteps
	}
	allow := d24LoginAllowance(t, o.loginPath)
	if o.noAllow {
		allow = d24NoAllowance(t)
	}
	gov, audit, sink := d24Kernel(t, allow)
	auth, _ := mintAuthorization(t)
	scope := c23NarrowedScope(t, o.robots)
	if o.scope != nil {
		scope = *o.scope
	}
	steps := d24Steps(t)
	if o.steps != nil {
		steps = *o.steps
	}
	cfg := AuthConfig{
		Governor:      gov,
		Audit:         audit,
		Authorization: auth,
		Target:        mustBareTarget(t),
		Scope:         scope,
		Steps:         steps,
		Driver:        o.driver,
		Sink:          o.sink,
		LoginPath:     o.loginPath,
		LivenessPath:  o.livePath,
		AliveStatuses: o.alive,
		Screenshots:   o.shots,
	}
	if !o.freezeTime {
		cfg.Clock = c22Advancing(t, time.Second)
	}
	return cfg, sink
}

// d24Working returns a driver that logs in and stays alive.
func d24Working() *d24Driver {
	return &d24Driver{
		outcomes: []AuthOutcome{d24GoodOutcome()},
		probes:   []AuthProbe{d24Alive()},
	}
}

// ---------------------------------------------------------------------------
// 1. The credential never appears — in the ACTUAL EMITTED BYTES
// ---------------------------------------------------------------------------

// d24Emitted collects everything this package emitted about a run.
//
// It reaches the rendered audit rows, the session ledger, the artifact ledger,
// the bytes handed to the sink, the returned errors, and the fmt renderings of
// every exported value. It is deliberately built from RENDERED OUTPUT rather
// than from selected fields: a field somebody adds next quarter is included
// automatically, and a leak test that only looks at fields somebody remembered
// to redact proves nothing.
func d24Emitted(s *Session, audit *d24AuditSink, sink *d24Sink, errs ...error) string {
	var b strings.Builder
	b.WriteString(audit.bytes())
	if sink != nil {
		b.WriteString(sink.bytes())
	}
	for _, e := range errs {
		if e != nil {
			fmt.Fprintf(&b, "err: %v | %s\n", e, e.Error())
		}
	}
	if s == nil {
		return b.String()
	}
	fmt.Fprintf(&b, "%v\n%+v\n%s\n%q\n%d\n%x\n", s, s, s, s, s, s)
	fmt.Fprintf(&b, "%s\n%s\n", s.CoverageLabel(), s.SourceRef())
	for _, e := range s.Events() {
		fmt.Fprintf(&b, "%v\n%+v\n%s\n%s\n", e, e, e.String(), e.Detail())
	}
	for _, r := range s.Report().Records() {
		fmt.Fprintf(&b, "%v\n%+v\n%s\n%s\n%s\n", r, r, r.String(), r.Name(), r.Detail())
	}
	for _, w := range s.Windows() {
		fmt.Fprintf(&b, "%v\n%s\n", w, w.String())
	}
	if err := s.AssertNoCredentialInLedger(); err != nil {
		fmt.Fprintf(&b, "ledger: %v\n", err)
	}
	if err := s.AssertReportRetained(); err != nil {
		fmt.Fprintf(&b, "retained: %v\n", err)
	}
	if err := s.AssertAllAuthenticated([]time.Time{s.StartedAt()}); err != nil {
		fmt.Fprintf(&b, "coverage: %v\n", err)
	}
	return b.String()
}

func d24AssertNoCredential(t *testing.T, where, emitted string) {
	t.Helper()
	if emitted == "" {
		t.Fatalf("%s: nothing was emitted, so this assertion measured nothing", where)
	}
	for _, cred := range d24Credentials() {
		// The REDACTED form is a needle too, and it is the one that catches
		// the ordering bug: redact() rewrites "&" to "?", so a credential
		// that went through redact() before the sweep is not the raw string
		// any more — it is this string, and it still carries nineteen of the
		// credential's twenty characters.
		for _, form := range []struct{ label, needle string }{
			{"raw", cred},
			{"query-escaped", url.QueryEscape(cred)},
			{"path-escaped", url.PathEscape(cred)},
			{"redacted", redact(cred)},
		} {
			if strings.Contains(emitted, form.needle) {
				i := strings.Index(emitted, form.needle)
				lo := i - 120
				if lo < 0 {
					lo = 0
				}
				hi := i + 120
				if hi > len(emitted) {
					hi = len(emitted)
				}
				t.Fatalf("%s: the %s form of a credential appears in the emitted bytes. "+
					"Context (credential itself elided by this message's own truncation "+
					"window being printed deliberately, because a failing leak test must "+
					"be diagnosable):\n...%s...", where, form.label, emitted[lo:hi])
			}
		}
	}
}

func TestNoCredentialReachesTheAuditTrailOrTheReport(t *testing.T) {
	drv := &d24Driver{
		outcomes: []AuthOutcome{d24LeakyOutcome()},
		probes:   []AuthProbe{d24Alive()},
	}
	sink := &d24Sink{}
	cfg, audit := d24Config(t, d24Opts{driver: drv, sink: sink})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	if !s.Authenticated() {
		t.Fatalf("the fixture login should have succeeded; state is %q", s.State())
	}

	// The fixture leaked in five places. Assert the COUNT of refusals rather
	// than that some refusal happened: three artifacts carried a credential,
	// one did not.
	if got, want := s.Report().CredentialRefusals(), 3; got != want {
		t.Fatalf("the sweep refused %d artifact(s), want %d. Disposition mix: %v",
			got, want, s.Report().DispositionMix())
	}
	if got, want := s.Report().StoredCount(), 1; got != want {
		t.Fatalf("%d artifact(s) reached the sink, want %d (only the one with no "+
			"credential in it). Mix: %v", got, want, s.Report().DispositionMix())
	}
	if got, want := len(sink.stored), 1; got != want {
		t.Fatalf("the sink actually received %d artifact(s), want %d", got, want)
	}
	if err := s.Report().AssertNoCredentialWasFound(); err == nil {
		t.Fatal("AssertNoCredentialWasFound passed on a run in which the sweep refused " +
			"three artifacts, so it cannot see the damage it exists to report")
	}

	d24AssertNoCredential(t, "a leaky driver's run",
		d24Emitted(s, audit, sink, err, s.AssertNoCredentialInLedger()))

	if err := s.AssertNoCredentialInLedger(); err != nil {
		t.Fatalf("AssertNoCredentialInLedger: %v", err)
	}
}

// TestRedactionDoesNotDefeatTheSweep pins the ordering bug the sweep is
// arranged to avoid: redact() rewrites "&" to "?", so a sweep run after
// redaction compares the wrong spelling and nineteen of the credential's
// twenty characters ship.
func TestRedactionDoesNotDefeatTheSweep(t *testing.T) {
	secrets := d24Steps(t).secrets()
	raw := "landed on /a?next=" + d24Password

	if _, hit := credentialIn([]byte(raw), secrets); !hit {
		t.Fatal("credentialIn did not find the credential in the RAW string, so nothing " +
			"below measures anything")
	}
	// The wrong order, spelled out, so the test states the defect rather than
	// describing it: sweeping the redacted form finds nothing.
	redacted := redact(raw)
	if _, hit := credentialIn([]byte(redacted), secrets); hit {
		t.Fatal("this fixture no longer demonstrates the hazard: redact() left the " +
			"credential intact, so pick a credential redact() rewrites")
	}
	if !strings.Contains(redacted, "s3cr3t Pa55w0rd") {
		t.Fatalf("the redacted form should still carry most of the credential, which is "+
			"the whole point; got %q", redacted)
	}
	// The right order.
	if got := sanitizeForLedger(raw, secrets); got != refusedForCredential {
		t.Fatalf("sanitizeForLedger(%q) = %q, want the whole string refused", raw, got)
	}
	// Both markers must survive redact() byte for byte, or a marker that has
	// been through the ledger is a different string from the constant and
	// every comparison against it is vacuous.
	for _, marker := range []string{redactedCredential, refusedForCredential} {
		if got := redact(marker); got != marker {
			t.Fatalf("redact(%q) = %q; the marker must be inside redact's allowlist",
				marker, got)
		}
	}
}

func TestCredentialInIsNotFooledByEncoding(t *testing.T) {
	secrets := d24Steps(t).secrets()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"raw password", "x=" + d24Password, true},
		{"query-escaped password", "x=" + url.QueryEscape(d24Password), true},
		{"path-escaped password", "/x/" + url.PathEscape(d24Password), true},
		{"raw totp", "{\"t\":\"" + d24TOTP + "\"}", true},
		{"query-escaped totp", "t=" + url.QueryEscape(d24TOTP), true},
		{"the username, which is not a credential", "user=" + d24Username, false},
		{"a prefix of the password", "x=s3cr3t Pa55", false},
		{"nothing", "GET /login HTTP/1.1", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := credentialIn([]byte(tc.in), secrets); got != tc.want {
				t.Fatalf("credentialIn(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestFmtCannotPrintACredential covers the case a String() method does NOT:
// fmt walks a struct's unexported fields by reflection and cannot call a
// method on a value it cannot Interface(), so a Stringer alone would leak
// through any struct that HOLDS a Secret.
func TestFmtCannotPrintACredential(t *testing.T) {
	sec := mustSecret(t, d24Password)
	holder := struct {
		s Secret
	}{s: sec}
	steps := d24Steps(t)

	renders := []string{
		fmt.Sprintf("%v", sec), fmt.Sprintf("%s", sec), fmt.Sprintf("%q", sec),
		fmt.Sprintf("%d", sec), fmt.Sprintf("%x", sec), fmt.Sprintf("%#v", sec),
		fmt.Sprintf("%+v", sec), sec.String(), fmt.Sprint(sec), fmt.Sprintln(sec),
		fmt.Sprintf("%v", holder), fmt.Sprintf("%+v", holder), fmt.Sprintf("%#v", holder),
		fmt.Sprintf("%v", []Secret{sec}), fmt.Sprintf("%#v", map[string]Secret{"p": sec}),
		fmt.Sprintf("%v", AuthStep{Kind: AuthStepCustomField, Selector: "#p", Value: sec}),
		fmt.Sprintf("%#v", AuthStep{Kind: AuthStepCustomField, Selector: "#p", Value: sec}),
		fmt.Sprintf("%v", steps), fmt.Sprintf("%+v", steps), fmt.Sprintf("%#v", steps),
		fmt.Sprintf("%s", steps), fmt.Sprintf("%d", steps),
		fmt.Sprintf("%v", steps.Steps()),
		fmt.Sprintf("%v", AuthRequest{steps: steps, sealed: true, path: "/login"}),
		fmt.Sprintf("%#v", AuthRequest{steps: steps, sealed: true, path: "/login"}),
	}
	// THE POSITIVE CONTROL. The claim above is that the MASKED STORAGE, not a
	// String() method, is what protects the reflective path — fmt cannot call
	// a method on a field it cannot Interface(), so a Stringer would not have
	// been consulted for `holder` at all. This proves the search is not
	// vacuous: the same struct shape with a plain unexported string field
	// leaks under exactly the verbs the assertion above searches.
	control := struct {
		s string
	}{s: d24Password}
	leaked := fmt.Sprintf("%v %+v %#v", control, control, control)
	if !strings.Contains(leaked, d24Password) {
		t.Fatalf("the positive control did not leak, so the assertion above measures "+
			"nothing: %q", leaked)
	}
	if strings.Contains(strings.Join(renders, "\n"), redactedCredential) == false {
		t.Fatal("no render produced the redaction marker, so these renders are not " +
			"reaching Secret at all and the assertion below is vacuous")
	}

	d24AssertNoCredential(t, "fmt over Secret and everything that holds one",
		strings.Join(renders, "\n"))

	// And the one exit still works, or the driver could never log in.
	if got := sec.Reveal(); got != d24Password {
		t.Fatalf("Secret.Reveal did not round-trip the credential (len %d)", len(got))
	}
	if !sec.Present() {
		t.Fatal("Secret.Present is false for a sealed credential")
	}
	if (Secret{}).Present() || (Secret{}).Reveal() != "" {
		t.Fatal("the zero Secret is not empty, so a step nobody configured could submit " +
			"something")
	}
}

func TestSecretRefusesToBeSerialized(t *testing.T) {
	sec := mustSecret(t, d24Password)
	if _, err := sec.MarshalJSON(); !errors.Is(err, ErrSecretMarshalled) {
		t.Fatalf("Secret.MarshalJSON returned %v, want ErrSecretMarshalled", err)
	}
	if _, err := sec.MarshalText(); !errors.Is(err, ErrSecretMarshalled) {
		t.Fatalf("Secret.MarshalText returned %v, want ErrSecretMarshalled", err)
	}
	if _, err := NewSecret(""); err == nil {
		t.Fatal("NewSecret accepted an empty credential; an empty credential is what a " +
			"failed lookup produces and submitting one is a login against a blank password")
	}
	if _, err := NewSecret(strings.Repeat("a", codedMaxSecretBytes+1)); err == nil {
		t.Fatal("NewSecret accepted a credential past the coded bound")
	}
}

// ---------------------------------------------------------------------------
// 2. The kernel decides — with a positive AND a negative control
// ---------------------------------------------------------------------------

func TestTheLoginPostNeedsAnExplicitEndpointAllowance(t *testing.T) {
	drv := d24Working()
	cfg, audit := d24Config(t, d24Opts{driver: drv, sink: &d24Sink{}, noAllow: true})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("AuthenticateAndMonitor returned %v, want ErrAuthFailed", err)
	}
	if s.Authenticated() {
		t.Fatal("a login the kernel refused reported as authenticated")
	}
	if s.State() != AuthStateAuthenticationFailed {
		t.Fatalf("state is %q, want %q", s.State(), AuthStateAuthenticationFailed)
	}
	// THE CONTAINMENT ASSERTION: nothing left the process at all.
	if drv.authCalls != 0 {
		t.Fatalf("the AuthDriver was called %d time(s) for a submission gate 15 refused; "+
			"want 0, because a refused admission must not spend a request", drv.authCalls)
	}
	denials := audit.denials()
	if len(denials) != 1 {
		t.Fatalf("the audit holds %d denial row(s), want exactly 1", len(denials))
	}
	if denials[0].Gate != authz.Gate15DestructiveTechniques {
		t.Fatalf("the denial names %s, want gate 15: a POST to the login path with no "+
			"per-endpoint allowance is precisely what gate 15 exists to refuse",
			denials[0].Gate)
	}
	if !hasEventKind(s, SessionEventLoginRefusedByKernel) {
		t.Fatalf("the ledger has no %q row: %v", SessionEventLoginRefusedByKernel, s.Events())
	}
}

func TestAnAdmittedLoginCarriesTwoDistinctAuditRows(t *testing.T) {
	drv := d24Working()
	cfg, audit := d24Config(t, d24Opts{driver: drv, sink: &d24Sink{}})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	if !s.Authenticated() {
		t.Fatalf("state is %q, want authenticated", s.State())
	}
	if drv.authCalls != 1 {
		t.Fatalf("the driver was asked to authenticate %d time(s), want 1", drv.authCalls)
	}
	if drv.probeCall != 1 {
		t.Fatalf("the driver was probed %d time(s), want exactly 1 — the verification "+
			"AuthenticateAndMonitor makes before it will call a session authenticated",
			drv.probeCall)
	}
	req := drv.seenAuth[0]
	if !req.Constructed() {
		t.Fatal("the driver was handed an AuthRequest nothing constructed")
	}
	if req.Method() != authz.MethodPost || req.Path() != "/login" {
		t.Fatalf("the driver was handed %s %s, want POST /login", req.Method(), req.Path())
	}
	if req.Technique() != authz.TechniqueAuthenticatedRead {
		t.Fatalf("the request declares technique %q, want %q",
			req.Technique(), authz.TechniqueAuthenticatedRead)
	}
	if req.NavAuditSeq() == 0 || req.SubmitAuditSeq() == 0 {
		t.Fatalf("the request carries nav seq %d and submit seq %d; a request with no "+
			"gate-21 row cannot be joined back to who authorized it",
			req.NavAuditSeq(), req.SubmitAuditSeq())
	}
	if req.NavAuditSeq() >= req.SubmitAuditSeq() {
		t.Fatalf("nav seq %d is not before submit seq %d, so the two admissions are not "+
			"two admissions", req.NavAuditSeq(), req.SubmitAuditSeq())
	}
	// The liveness probe is a SEPARATE admitted request and is handed NO
	// credential: a session check needs the session, never the password.
	probe := drv.seenProbe[0]
	if probe.Method() != authz.MethodGet || probe.Path() != "/account" {
		t.Fatalf("the liveness probe was %s %s, want GET /account",
			probe.Method(), probe.Path())
	}
	if probe.Steps().Constructed() || probe.Steps().Len() != 0 {
		t.Fatalf("the liveness probe was handed %d step(s); it must be handed none",
			probe.Steps().Len())
	}
	if len(audit.denials()) != 0 {
		t.Fatalf("a clean run produced %d denial row(s): %v",
			len(audit.denials()), audit.denials())
	}
	if audit.n < 3 {
		t.Fatalf("only %d audit row(s) were written for two admissions, two observations "+
			"and a liveness probe", audit.n)
	}
}

func TestScopeNarrowingStopsALoginOnADisallowedPath(t *testing.T) {
	drv := d24Working()
	// robots.txt removes the login path. Gate 11's narrowing is applied to
	// the Scope before this file sees it, and checkAuthPath consults it.
	cfg, _ := d24Config(t, d24Opts{
		driver: drv, sink: &d24Sink{},
		robots: "User-agent: *\nDisallow: /login\n",
	})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("AuthenticateAndMonitor returned %v, want ErrAuthFailed", err)
	}
	if drv.authCalls != 0 {
		t.Fatalf("the driver ran %d time(s) for a path gate 11 removed, want 0",
			drv.authCalls)
	}
	if s.State() != AuthStateAuthenticationFailed {
		t.Fatalf("state is %q, want %q", s.State(), AuthStateAuthenticationFailed)
	}
}

// ---------------------------------------------------------------------------
// 3. A failed login is not an authenticated crawl
// ---------------------------------------------------------------------------

func TestAFailedLoginIsNeverReportedAsAnAuthenticatedCrawl(t *testing.T) {
	bad := d24GoodOutcome()
	bad.SessionEstablished = false
	bad.FailedAtStep = 2
	bad.Detail = "the password field never appeared"
	drv := &d24Driver{outcomes: []AuthOutcome{bad}, probes: []AuthProbe{d24Alive()}}
	sink := &d24Sink{}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: sink})

	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("AuthenticateAndMonitor returned %v, want ErrAuthFailed", err)
	}
	if s == nil {
		t.Fatal("no Session was returned alongside the error, so a caller that drops the " +
			"error has nothing that says the crawl is unauthenticated")
	}
	if s.Authenticated() {
		t.Fatal("a failed login reported as authenticated")
	}
	if s.State() != AuthStateAuthenticationFailed {
		t.Fatalf("state is %q, want %q", s.State(), AuthStateAuthenticationFailed)
	}
	// The crawl that follows succeeds. Its instants must still not be
	// authenticated coverage.
	base := s.StartedAt()
	crawl := []time.Time{
		base.Add(1 * time.Minute), base.Add(2 * time.Minute),
		base.Add(3 * time.Minute), base.Add(4 * time.Minute),
	}
	mix := s.PartitionByState(crawl)
	if got, want := mix[AuthStateAuthenticationFailed], len(crawl); got != want {
		t.Fatalf("%d of %d crawl instant(s) landed in an authentication_failed window, "+
			"want all %d. Mix: %v", got, len(crawl), want, mix)
	}
	if mix[AuthStateAuthenticated] != 0 {
		t.Fatalf("%d crawl instant(s) landed in an AUTHENTICATED window after a failed "+
			"login. Mix: %v", mix[AuthStateAuthenticated], mix)
	}
	aerr := s.AssertAllAuthenticated(crawl)
	if !errors.Is(aerr, ErrCoverageIsNotAuthenticated) {
		t.Fatalf("AssertAllAuthenticated returned %v, want ErrCoverageIsNotAuthenticated",
			aerr)
	}
	if !strings.Contains(aerr.Error(), fmt.Sprintf("%d of %d", len(crawl), len(crawl))) {
		t.Fatalf("the error does not state the COUNT of unauthenticated instants: %v", aerr)
	}
	if !strings.Contains(s.CoverageLabel(), "PUBLIC SURFACE ONLY") {
		t.Fatalf("the coverage label does not distinguish a failed login from a target "+
			"with no login: %q", s.CoverageLabel())
	}
	// And it is a DIFFERENT value from a target that declares no auth at all.
	pub := UnauthenticatedSession(mustClock(t))
	if pub.State() == s.State() {
		t.Fatalf("a target with no auth section and a login that failed both report %q; "+
			"only the second means the scan is missing the application's interior",
			s.State())
	}
	if pub.Authenticated() {
		t.Fatal("UnauthenticatedSession reports authenticated")
	}
}

func TestTheDriversClaimOfASessionIsNotBelieved(t *testing.T) {
	// The driver says the login worked. The session cannot be observed.
	drv := &d24Driver{
		outcomes: []AuthOutcome{d24GoodOutcome()},
		probes:   []AuthProbe{{Status: 200, Latency: time.Millisecond, SessionPresent: false}},
	}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: &d24Sink{}})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("AuthenticateAndMonitor returned %v, want ErrAuthFailed", err)
	}
	if s.Authenticated() {
		t.Fatal("the driver's word alone produced an authenticated session; ruling 7 says " +
			"only an observation Anvil made through the kernel confirms")
	}
	if !hasEventKind(s, SessionEventLoginClaimed) {
		t.Fatal("the driver's claim was not recorded, so an operator cannot see that the " +
			"driver and the observation disagreed")
	}
	if !hasEventKind(s, SessionEventLivenessFailed) {
		t.Fatal("the failed observation was not recorded")
	}
	if s.Verifications() != 0 {
		t.Fatalf("%d verification(s) were counted for a session nothing observed",
			s.Verifications())
	}
}

func TestANilSessionIsNotAuthenticated(t *testing.T) {
	var s *Session
	if s.Authenticated() {
		t.Fatal("a nil *Session reports authenticated")
	}
	if s.State() != AuthStateUnset {
		t.Fatalf("a nil *Session reports state %q", s.State())
	}
	if s.StateAt(time.Now()) != AuthStateUnset {
		t.Fatal("a nil *Session labelled an instant")
	}
	if s.Constructed() || s.Attempts() != 0 || s.Events() != nil {
		t.Fatal("a nil *Session answered a question about a run that never happened")
	}
	if AuthStateUnset.AuthenticatedCoverage() {
		t.Fatal("the zero AuthState is authenticated coverage; a Go zero value must never " +
			"mean permitted")
	}
	for _, st := range AuthStateValues() {
		if st.AuthenticatedCoverage() && st != AuthStateAuthenticated {
			t.Fatalf("%q is on the authenticated-coverage allowlist and must not be", st)
		}
	}
	if !AuthStateAuthenticated.AuthenticatedCoverage() {
		t.Fatal("AuthStateAuthenticated is not authenticated coverage, so the allowlist " +
			"of one is empty and every assertion above is vacuous")
	}
}

// ---------------------------------------------------------------------------
// 4. The mid-scan logout, and the forced re-login
// ---------------------------------------------------------------------------

func TestAMidScanLogoutIsDetectedAndForcesAReLogin(t *testing.T) {
	drv := &d24Driver{
		outcomes: []AuthOutcome{d24GoodOutcome(), d24GoodOutcome()},
		probes: []AuthProbe{
			d24Alive(), // the initial verification
			d24Alive(), // phase 1 boundary: still alive
			// phase 2 boundary: the session is gone — the application still
			// ANSWERS, and bounces to the login page. A status check alone
			// would have called this alive.
			{Status: 302, Latency: time.Millisecond, Location: "/login?next=%2Faccount",
				SessionPresent: true},
			d24Alive(), // the forced re-login's verification
			d24Alive(), // phase 3 boundary: alive again
		},
		// 302 is on the allowlist below so that the ONLY thing distinguishing
		// the dead session is the bounce to the login path.
	}
	sink := &d24Sink{}
	cfg, audit := d24Config(t, d24Opts{driver: drv, sink: sink, alive: []int{200, 302}})
	now := mustClock(t)

	s, err := AuthenticateAndMonitor(context.Background(), cfg, now)
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	if !s.Authenticated() {
		t.Fatalf("the initial login did not authenticate: %q / %v", s.State(), s.Events())
	}
	firstVerified := lastEventOf(t, s, SessionEventVerified).At()

	// Phase 1 boundary — alive.
	if err := EnsureSessionBeforePhase(context.Background(), s, now); err != nil {
		t.Fatalf("EnsureSessionBeforePhase at the first boundary: %v", err)
	}
	if !s.Authenticated() {
		t.Fatalf("state after a passing boundary is %q", s.State())
	}
	secondVerified := lastEventOf(t, s, SessionEventVerified).At()

	// Phase 2 boundary — the logout, then the forced re-login.
	if err := EnsureSessionBeforePhase(context.Background(), s, now); err != nil {
		t.Fatalf("EnsureSessionBeforePhase did not recover the session: %v", err)
	}
	if !s.Authenticated() {
		t.Fatalf("state after a successful forced re-login is %q, want authenticated: %v",
			s.State(), s.Events())
	}

	// COUNTS, not existence.
	if got, want := drv.authCalls, 2; got != want {
		t.Fatalf("%d credential submission(s), want %d (the initial login and one forced "+
			"re-login)", got, want)
	}
	if got, want := s.Attempts(), 2; got != want {
		t.Fatalf("Session.Attempts is %d, want %d", got, want)
	}
	if got, want := s.ReLogins(), 1; got != want {
		t.Fatalf("Session.ReLogins is %d, want %d", got, want)
	}
	if got, want := s.LivenessFailures(), 1; got != want {
		t.Fatalf("Session.LivenessFailures is %d, want %d", got, want)
	}
	if got, want := s.Verifications(), 3; got != want {
		t.Fatalf("Session.Verifications is %d, want %d: the initial login's own "+
			"verification, the first phase boundary, and the forced re-login's "+
			"verification. The second boundary is the FAILURE and is counted separately",
			got, want)
	}
	if got, want := drv.probeCall, 4; got != want {
		t.Fatalf("the driver was probed %d time(s), want %d: three verifications plus "+
			"the one that detected the logout", got, want)
	}
	for _, k := range []SessionEventKind{
		SessionEventLivenessFailed, SessionEventReLoginForced, SessionEventReLoginSucceeded,
	} {
		if !hasEventKind(s, k) {
			t.Fatalf("the ledger has no %q row: %v", k, s.Events())
		}
	}

	// THE WINDOW THAT MATTERS: the stretch between the two passing checks is
	// authenticated; the stretch between the last pass and the failure is
	// UNVERIFIED, because the session died somewhere inside it.
	between := firstVerified.Add(secondVerified.Sub(firstVerified) / 2)
	if got := s.StateAt(between); got != AuthStateAuthenticated {
		t.Fatalf("an instant bracketed by two PASSING liveness observations is labelled "+
			"%q, want %q. Windows: %v", got, AuthStateAuthenticated, s.Windows())
	}
	lost := lastEventOf(t, s, SessionEventLivenessFailed).At()
	unverified := secondVerified.Add(lost.Sub(secondVerified) / 2)
	if got := s.StateAt(unverified); got != AuthStateUnverified {
		t.Fatalf("an instant between the last PASS and the FAILURE is labelled %q, want "+
			"%q: nothing observed the session in that stretch. Windows: %v",
			got, AuthStateUnverified, s.Windows())
	}
	if err := s.AssertAllAuthenticated([]time.Time{unverified}); err == nil {
		t.Fatal("AssertAllAuthenticated passed on an instant in an unverified window")
	}

	d24AssertNoCredential(t, "a run with a mid-scan logout",
		d24Emitted(s, audit, sink, err))
}

func TestAnUnrecoverableSessionLossIsNotSilent(t *testing.T) {
	drv := &d24Driver{
		outcomes: []AuthOutcome{d24GoodOutcome()},
		probes: []AuthProbe{
			d24Alive(),
			{Status: 401, Latency: time.Millisecond, SessionPresent: true},
			{Status: 401, Latency: time.Millisecond, SessionPresent: true},
		},
	}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: &d24Sink{}})
	now := mustClock(t)
	s, err := AuthenticateAndMonitor(context.Background(), cfg, now)
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	err = EnsureSessionBeforePhase(context.Background(), s, now)
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("EnsureSessionBeforePhase returned %v, want ErrSessionLost", err)
	}
	if s.Authenticated() {
		t.Fatal("a session that was lost and not recovered reports authenticated")
	}
	if s.State() != AuthStateSessionLost {
		t.Fatalf("state is %q, want %q", s.State(), AuthStateSessionLost)
	}
	after := lastEventOf(t, s, SessionEventLivenessFailed).At().Add(time.Hour)
	if got := s.StateAt(after); got.AuthenticatedCoverage() {
		t.Fatalf("an instant after an unrecovered loss is labelled %q, which is "+
			"authenticated coverage", got)
	}
}

func TestTheCredentialSubmissionBudgetIsBounded(t *testing.T) {
	// The login always "works" and the session is never observable, so every
	// boundary forces a fresh submission. Without the bound this loops.
	drv := &d24Driver{
		outcomes: []AuthOutcome{d24GoodOutcome()},
		probes:   []AuthProbe{{Status: 401, Latency: time.Millisecond, SessionPresent: false}},
	}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: &d24Sink{}})
	now := mustClock(t)
	s, _ := AuthenticateAndMonitor(context.Background(), cfg, now)
	for i := 0; i < 10; i++ {
		_ = EnsureSessionBeforePhase(context.Background(), s, now)
	}
	if got := drv.authCalls; got != codedMaxAuthAttempts {
		t.Fatalf("the driver submitted credentials %d time(s) across eleven attempts; the "+
			"coded bound is %d, and an unbounded retry loop against a target that keeps "+
			"refusing is gate 15's denylisted authentication_lockout_sequence",
			got, codedMaxAuthAttempts)
	}
	if !hasEventKind(s, SessionEventAttemptsExhausted) {
		t.Fatalf("the budget was spent and the ledger does not say so: %v", s.Events())
	}
}

// ---------------------------------------------------------------------------
// 5. Liveness fails closed in every direction
// ---------------------------------------------------------------------------

func TestCheckLivenessFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		probe AuthProbe
		err   error
	}{
		{"the session cookie is gone",
			AuthProbe{Status: 200, SessionPresent: false}, nil},
		{"the status is not on the configured allowlist",
			AuthProbe{Status: 403, SessionPresent: true}, nil},
		{"the status is not an HTTP status at all",
			AuthProbe{Status: 0, SessionPresent: true}, nil},
		{"the status is 999",
			AuthProbe{Status: 999, SessionPresent: true}, nil},
		{"the response bounces to the login page",
			AuthProbe{Status: 302, Location: "/login", SessionPresent: true}, nil},
		{"the response bounces to the login page with a query",
			AuthProbe{Status: 302, Location: "/login?next=/account", SessionPresent: true}, nil},
		{"the Location will not resolve",
			AuthProbe{Status: 302, Location: "://:::", SessionPresent: true}, nil},
		{"the Location leaves the admitted host",
			AuthProbe{Status: 302, Location: "https://evil.example.net/login",
				SessionPresent: true}, nil},
		{"the driver returned an error",
			AuthProbe{}, errors.New("the browser died")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drv := &d24Driver{
				outcomes: []AuthOutcome{d24GoodOutcome()},
				// The FIRST probe verifies the login; the second is the case.
				probes:    []AuthProbe{d24Alive(), tc.probe},
				probeErrs: []error{nil, tc.err},
			}
			cfg, _ := d24Config(t, d24Opts{
				driver: drv, sink: &d24Sink{}, alive: []int{200, 302},
			})
			now := mustClock(t)
			s, err := AuthenticateAndMonitor(context.Background(), cfg, now)
			if err != nil {
				t.Fatalf("the initial login must succeed or this case measures nothing: %v",
					err)
			}
			alive, _ := CheckLiveness(context.Background(), s, now)
			if alive {
				t.Fatalf("CheckLiveness reported ALIVE for %q, which is the direction that "+
					"lets a dead session's coverage report as authenticated", tc.name)
			}
			if s.LivenessFailures() != 1 {
				t.Fatalf("%d liveness failure(s) were counted, want 1",
					s.LivenessFailures())
			}
		})
	}
}

func TestCheckLivenessRefusesAnUnusableSession(t *testing.T) {
	if alive, err := CheckLiveness(context.Background(), nil, mustClock(t)); alive || err == nil {
		t.Fatalf("CheckLiveness(nil) = (%v, %v), want (false, an error)", alive, err)
	}
	if alive, err := CheckLiveness(context.Background(), &Session{}, mustClock(t)); alive || err == nil {
		t.Fatalf("CheckLiveness on an unconstructed session = (%v, %v)", alive, err)
	}
	// A session whose driver is nil cannot be observed, and an unobservable
	// session is never read as a live one.
	cfg, _ := d24Config(t, d24Opts{driver: nil, sink: &d24Sink{}})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if !errors.Is(err, ErrNoAuthDriver) {
		t.Fatalf("AuthenticateAndMonitor with no driver returned %v, want ErrNoAuthDriver",
			err)
	}
	if s.Authenticated() {
		t.Fatal("a run with no AuthDriver reported an authenticated session")
	}
}

// ---------------------------------------------------------------------------
// 6. The report, and the pixel problem
// ---------------------------------------------------------------------------

func TestScreenshotsOfCredentialStepsAreNeverStored(t *testing.T) {
	out := d24GoodOutcome()
	out.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactScreenshot, Step: 1, Name: "click", Bytes: []byte("PNG-1")},
		// Step 2 is AUTO_STEPS: it types the password.
		{Kind: AuthArtifactScreenshot, Step: 2, Name: "auto", Bytes: []byte("PNG-2")},
		{Kind: AuthArtifactScreenshot, Step: 3, Name: "wait", Bytes: []byte("PNG-3")},
		// Step 4 is TOTP_FIELD.
		{Kind: AuthArtifactScreenshot, Step: 4, Name: "totp", Bytes: []byte("PNG-4")},
		// A screenshot that names no step cannot be checked at all.
		{Kind: AuthArtifactScreenshot, Step: 0, Name: "flow", Bytes: []byte("PNG-0")},
		// A screenshot of a step that does not exist.
		{Kind: AuthArtifactScreenshot, Step: 99, Name: "ghost", Bytes: []byte("PNG-99")},
		{Kind: AuthArtifactHTTPExchange, Step: 2, Name: "http", Bytes: []byte("GET /login")},
		{Kind: AuthArtifactStorageState, Step: 0, Name: "storage", Bytes: []byte("{}")},
		{Kind: "video", Step: 1, Name: "screencast", Bytes: []byte("MP4")},
	}
	drv := &d24Driver{outcomes: []AuthOutcome{out}, probes: []AuthProbe{d24Alive()}}
	sink := &d24Sink{}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: sink})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}

	mix := s.Report().DispositionMix()
	want := map[ArtifactDisposition]int{
		// Steps 1 and 3 (CLICK, WAIT) plus the HTTP and storage artifacts.
		ArtifactStored: 4,
		// Steps 2 and 4 are credential steps; step 0 and step 99 cannot be
		// resolved, and an unresolvable screenshot is suppressed.
		ArtifactSuppressedCredentialStep: 4,
		ArtifactRefusedUnrecognisedKind:  1,
	}
	if len(mix) != len(want) {
		t.Fatalf("the disposition mix has %d entries, want %d: %v", len(mix), len(want), mix)
	}
	for d, n := range want {
		if mix[d] != n {
			t.Fatalf("disposition %s: got %d, want %d. Mix: %v", d, mix[d], n, mix)
		}
	}
	if got, want := len(sink.stored), 4; got != want {
		t.Fatalf("the sink actually received %d artifact(s), want %d", got, want)
	}
	for _, a := range sink.stored {
		if a.Kind() == AuthArtifactScreenshot && d24Steps(t).stepBears(a.Step()) {
			t.Fatalf("a screenshot of credential step %d reached the sink", a.Step())
		}
		if !a.Constructed() {
			t.Fatal("the sink was handed a StoredArtifact nothing constructed")
		}
	}
	if err := s.AssertReportRetained(); err != nil {
		t.Fatalf("AssertReportRetained: %v", err)
	}
}

func TestScreenshotPolicySuppressAllStoresNoImage(t *testing.T) {
	out := d24GoodOutcome()
	out.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactScreenshot, Step: 1, Name: "click", Bytes: []byte("PNG-1")},
		{Kind: AuthArtifactScreenshot, Step: 3, Name: "wait", Bytes: []byte("PNG-3")},
		{Kind: AuthArtifactHTTPExchange, Step: 1, Name: "http", Bytes: []byte("GET /login")},
	}
	drv := &d24Driver{outcomes: []AuthOutcome{out}, probes: []AuthProbe{d24Alive()}}
	sink := &d24Sink{}
	cfg, _ := d24Config(t, d24Opts{
		driver: drv, sink: sink, shots: ScreenshotPolicySuppressAll,
	})
	if _, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t)); err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	if got, want := len(sink.stored), 1; got != want {
		t.Fatalf("%d artifact(s) reached the sink, want %d (the HTTP exchange only)",
			got, want)
	}
	if sink.stored[0].Kind() != AuthArtifactHTTPExchange {
		t.Fatalf("the stored artifact is a %s", sink.stored[0].Kind())
	}
}

func TestTheReportIsStoredEvenWhenTheLoginFails(t *testing.T) {
	out := d24GoodOutcome()
	out.SessionEstablished = false
	out.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactScreenshot, Step: 1, Name: "click", Bytes: []byte("PNG-1")},
		{Kind: AuthArtifactHTTPExchange, Step: 1, Name: "http", Bytes: []byte("GET /login")},
	}
	drv := &d24Driver{outcomes: []AuthOutcome{out}, probes: []AuthProbe{d24Alive()}}
	sink := &d24Sink{}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: sink})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("AuthenticateAndMonitor returned %v, want ErrAuthFailed", err)
	}
	if got, want := len(sink.stored), 2; got != want {
		t.Fatalf("%d artifact(s) were stored for a FAILED login, want %d. A login that "+
			"failed is the one somebody needs the screenshots for", got, want)
	}
	if err := s.AssertReportRetained(); err != nil {
		t.Fatalf("AssertReportRetained after a failed login: %v", err)
	}
}

func TestAMissingSinkIsRecordedRatherThanSilent(t *testing.T) {
	out := d24GoodOutcome()
	out.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactHTTPExchange, Step: 1, Name: "http", Bytes: []byte("GET /login")},
	}
	drv := &d24Driver{outcomes: []AuthOutcome{out}, probes: []AuthProbe{d24Alive()}}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: nil})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	if got := s.Report().DispositionMix()[ArtifactRefusedNoSink]; got != 1 {
		t.Fatalf("%d artifact(s) recorded ArtifactRefusedNoSink, want 1: %v",
			got, s.Report().DispositionMix())
	}
	if err := s.AssertReportRetained(); err == nil {
		t.Fatal("AssertReportRetained passed on a run whose whole authentication report " +
			"went nowhere")
	}
	// A driver that produces NO artifact at all is a different finding again.
	drv2 := d24Working()
	cfg2, _ := d24Config(t, d24Opts{driver: drv2, sink: &d24Sink{}})
	s2, err := AuthenticateAndMonitor(context.Background(), cfg2, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	rerr := s2.AssertReportRetained()
	if rerr == nil || !strings.Contains(rerr.Error(), "NO report artifact") {
		t.Fatalf("AssertReportRetained did not distinguish \"the driver produced nothing\" "+
			"from \"nothing was stored\": %v", rerr)
	}
}

func TestAnOverLargeArtifactIsRefusedRatherThanTruncated(t *testing.T) {
	out := d24GoodOutcome()
	out.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactHTTPExchange, Step: 1, Name: "huge",
			Bytes: make([]byte, codedMaxArtifactBytes+1)},
	}
	drv := &d24Driver{outcomes: []AuthOutcome{out}, probes: []AuthProbe{d24Alive()}}
	sink := &d24Sink{}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: sink})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	if len(sink.stored) != 0 {
		t.Fatalf("%d over-large artifact(s) were stored", len(sink.stored))
	}
	if got := s.Report().DispositionMix()[ArtifactRefusedTooLarge]; got != 1 {
		t.Fatalf("the over-large artifact was recorded as %v",
			s.Report().DispositionMix())
	}
}

// ---------------------------------------------------------------------------
// 7. The step list — explicit, never autodetection
// ---------------------------------------------------------------------------

func TestNewAuthStepsRefusesEveryShapeThatIsNotAnExplicitFlow(t *testing.T) {
	pw := mustSecret(t, d24Password)
	cases := []struct {
		name   string
		method string
		ref    string
		steps  []AuthStep
	}{
		{"a method that is not on D.1's allowlist of one", "form", "a.yaml",
			[]AuthStep{{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"no source ref", target.AuthMethodBrowser, "  ",
			[]AuthStep{{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"an EMPTY step list, which is autodetection under another name",
			target.AuthMethodBrowser, "a.yaml", nil},
		{"a step kind nobody enumerated", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: "SUBMIT", Selector: "u"},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"the zero step kind", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepUnset},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"a credential-bearing step with no credential", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepCustomField, Selector: "#p"}}},
		{"a CLICK carrying a credential", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepClick, Selector: "#go", Value: pw},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"a flow that submits no credential at all", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepClick, Selector: "#go"},
				{Kind: AuthStepWait, Wait: time.Second}}},
		{"a WAIT with no duration", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepWait},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"a WAIT past the coded bound", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepWait, Wait: codedMaxStepWait + time.Second},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"a non-WAIT step carrying a duration", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepClick, Selector: "#go", Wait: time.Second},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"a CLICK with no selector", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepClick},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"a selector past the coded bound", target.AuthMethodBrowser, "a.yaml",
			[]AuthStep{{Kind: AuthStepClick, Selector: strings.Repeat("a", maxIdentBytes+1)},
				{Kind: AuthStepAutoSteps, Selector: "u", Value: pw}}},
		{"more steps than the coded bound", target.AuthMethodBrowser, "a.yaml",
			d24ManySteps(codedMaxAuthSteps+1, pw)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewAuthSteps(tc.method, tc.ref, tc.steps)
			if err == nil {
				t.Fatalf("NewAuthSteps accepted it and returned %v", got)
			}
			if got.Constructed() {
				t.Fatal("NewAuthSteps returned a CONSTRUCTED value alongside an error")
			}
			d24AssertNoCredential(t, "a NewAuthSteps refusal for "+tc.name, err.Error())
		})
	}
}

// TestNewAuthStepsRefusalDoesNotLeakACredentialFromTheKindField is the case a
// loader with a bug produces: the credential document's parser put the
// password in the `kind` field, and the refusal message prints the kind.
func TestNewAuthStepsRefusalDoesNotLeakACredentialFromTheKindField(t *testing.T) {
	pw := mustSecret(t, d24Password)
	_, err := NewAuthSteps(target.AuthMethodBrowser, "a.yaml", []AuthStep{
		{Kind: AuthStepKind(d24Password)},
		{Kind: AuthStepAutoSteps, Selector: "u", Value: pw},
	})
	if err == nil {
		t.Fatal("NewAuthSteps accepted a kind nobody enumerated")
	}
	d24AssertNoCredential(t, "a refusal naming the offending kind", err.Error())
	if !strings.Contains(err.Error(), refusedForCredential) {
		t.Fatalf("the kind was not swept, only redacted, so the credential's redacted "+
			"spelling may still be in there: %v", err)
	}
}

func d24ManySteps(n int, pw Secret) []AuthStep {
	out := make([]AuthStep, 0, n)
	out = append(out, AuthStep{Kind: AuthStepAutoSteps, Selector: "u", Value: pw})
	for len(out) < n {
		out = append(out, AuthStep{Kind: AuthStepClick, Selector: "#go"})
	}
	return out
}

func TestAuthStepsAcceptsTheFixtureFlowAndReportsItWithoutSecrets(t *testing.T) {
	steps := d24Steps(t)
	if !steps.Constructed() || steps.Len() != 4 {
		t.Fatalf("the fixture flow is %d step(s) and Constructed=%v",
			steps.Len(), steps.Constructed())
	}
	if steps.Method() != target.AuthMethodBrowser {
		t.Fatalf("method is %q", steps.Method())
	}
	if got, want := len(steps.secrets()), 2; got != want {
		t.Fatalf("the flow carries %d credential(s), want %d", got, want)
	}
	wantKinds := []AuthStepKind{
		AuthStepClick, AuthStepAutoSteps, AuthStepWait, AuthStepTOTPField,
	}
	got := steps.Kinds()
	if len(got) != len(wantKinds) {
		t.Fatalf("Kinds() = %v, want %v", got, wantKinds)
	}
	for i := range got {
		if got[i] != wantKinds[i] {
			t.Fatalf("Kinds()[%d] = %q, want %q", i, got[i], wantKinds[i])
		}
	}
	// stepBears is FAIL CLOSED outside the list.
	for i, want := range map[int]bool{1: false, 2: true, 3: false, 4: true, 0: true, 99: true} {
		if got := steps.stepBears(i); got != want {
			t.Fatalf("stepBears(%d) = %v, want %v", i, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 8. The manifest, and the two seams whose absence is loud
// ---------------------------------------------------------------------------

type d24Loader struct {
	steps []AuthStep
	err   error
	seen  []string
}

func (l *d24Loader) LoadAuthSteps(_ context.Context, p string) ([]AuthStep, error) {
	l.seen = append(l.seen, p)
	return l.steps, l.err
}

func TestAuthStepsFromManifestReadsD1RatherThanReparsing(t *testing.T) {
	m := &target.Manifest{
		SchemaVersion: target.SchemaVersion,
		Auth:          &target.Auth{Method: target.AuthMethodBrowser, StepsRef: "./.anvil/auth.yaml"},
	}
	loader := &d24Loader{steps: []AuthStep{
		{Kind: AuthStepAutoSteps, Selector: d24Username, Value: mustSecret(t, d24Password)},
	}}
	steps, err := AuthStepsFromManifest(context.Background(), m, "C:/repo", loader)
	if err != nil {
		t.Fatalf("AuthStepsFromManifest: %v", err)
	}
	if !steps.Constructed() {
		t.Fatal("AuthStepsFromManifest returned an unconstructed step list with no error")
	}
	if steps.SourceRef() != m.Auth.StepsRef {
		t.Fatalf("SourceRef is %q, want the manifest's own %q",
			steps.SourceRef(), m.Auth.StepsRef)
	}
	if len(loader.seen) != 1 {
		t.Fatalf("the loader was called %d time(s), want 1", len(loader.seen))
	}
	if !strings.Contains(loader.seen[0], "auth.yaml") {
		t.Fatalf("the loader was handed %q, which is not the resolved steps_ref",
			loader.seen[0])
	}
}

func TestAManifestWithNoAuthSectionIsNotAnError(t *testing.T) {
	m := &target.Manifest{SchemaVersion: target.SchemaVersion}
	steps, err := AuthStepsFromManifest(context.Background(), m, "C:/repo", &d24Loader{})
	if err != nil {
		t.Fatalf("AuthStepsFromManifest on a manifest with no auth section: %v", err)
	}
	if steps.Constructed() {
		t.Fatal("a manifest with no auth section produced a constructed step list")
	}
}

// TestALoaderErrorIsNotForwarded pins the rule that the loader read a document
// holding a credential, so its error text is treated as capable of containing
// one and is never reproduced.
func TestALoaderErrorIsNotForwarded(t *testing.T) {
	m := &target.Manifest{
		SchemaVersion: target.SchemaVersion,
		Auth:          &target.Auth{Method: target.AuthMethodBrowser, StepsRef: "./.anvil/auth.yaml"},
	}
	loader := &d24Loader{err: fmt.Errorf("line 3: bad value %q", d24Password)}
	_, err := AuthStepsFromManifest(context.Background(), m, "C:/repo", loader)
	if err == nil {
		t.Fatal("AuthStepsFromManifest swallowed the loader's failure")
	}
	d24AssertNoCredential(t, "a loader failure", err.Error())
	if strings.Contains(err.Error(), "line 3") {
		t.Fatalf("the loader's error text was forwarded verbatim: %v", err)
	}
}

func TestTheSeamsAbsencesAreLoud(t *testing.T) {
	d, err := SystemAuthDriver()
	if d != nil || err == nil {
		t.Fatalf("SystemAuthDriver() = (%v, %v); it must never return (nil, nil) and no "+
			"ZAP is drivable on this host", d, err)
	}
	if !errors.Is(err, ErrNoAuthDriver) {
		t.Fatalf("SystemAuthDriver's error is %v, want ErrNoAuthDriver", err)
	}
	l, err := SystemAuthStepLoader()
	if l != nil || err == nil {
		t.Fatalf("SystemAuthStepLoader() = (%v, %v)", l, err)
	}
	if !errors.Is(err, ErrNoAuthStepLoader) {
		t.Fatalf("SystemAuthStepLoader's error is %v, want ErrNoAuthStepLoader", err)
	}
}

// ---------------------------------------------------------------------------
// 9. Configuration has no default that means "permitted"
// ---------------------------------------------------------------------------

func TestAuthConfigRefusesRatherThanDegrades(t *testing.T) {
	base := func(t *testing.T) AuthConfig {
		t.Helper()
		cfg, _ := d24Config(t, d24Opts{driver: d24Working(), sink: &d24Sink{}})
		return cfg
	}
	// shapeOnly marks the cases Constructed() is NOT expected to catch.
	// Constructed() answers "does this value carry the kernel objects a run
	// needs", and validateAuthConfig answers the rest — the path checks and
	// the per-value range checks. The two are listed rather than excluded by
	// a chain of name comparisons so that a case moving between them is a
	// visible edit.
	cases := []struct {
		name      string
		shapeOnly bool
		mut       func(*AuthConfig)
	}{
		{"no target", false, func(c *AuthConfig) { c.Target = authz.Target{} }},
		{"a scope nobody narrowed", false, func(c *AuthConfig) { c.Scope = authz.Scope{} }},
		{"no governor", false, func(c *AuthConfig) { c.Governor = nil }},
		{"no audit", false, func(c *AuthConfig) { c.Audit = nil }},
		{"no authorization", false,
			func(c *AuthConfig) { c.Authorization = authz.Authorization{} }},
		{"an unsealed step list", false, func(c *AuthConfig) { c.Steps = AuthSteps{} }},
		{"no screenshot policy", false,
			func(c *AuthConfig) { c.Screenshots = ScreenshotPolicyUnset }},
		{"a screenshot policy nobody enumerated", false,
			func(c *AuthConfig) { c.Screenshots = "store_everything" }},
		{"no liveness statuses", false, func(c *AuthConfig) { c.AliveStatuses = nil }},
		{"too many liveness statuses", false, func(c *AuthConfig) {
			c.AliveStatuses = make([]int, codedMaxAliveStatuses+1)
			for i := range c.AliveStatuses {
				c.AliveStatuses[i] = 200
			}
		}},
		{"a liveness status that is not an HTTP status", true,
			func(c *AuthConfig) { c.AliveStatuses = []int{0} }},
		{"no login path", true, func(c *AuthConfig) { c.LoginPath = "" }},
		{"no liveness path", true, func(c *AuthConfig) { c.LivenessPath = "" }},
		{"a login path the kernel rejects", true, func(c *AuthConfig) { c.LoginPath = "login" }},
		{"a login path with a dot-segment", true,
			func(c *AuthConfig) { c.LoginPath = "/a/../login" }},
		{"the liveness path IS the login path", true,
			func(c *AuthConfig) { c.LivenessPath = c.LoginPath }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base(t)
			tc.mut(&cfg)
			if cfg.Constructed() != tc.shapeOnly {
				t.Fatalf("AuthConfig.Constructed() is %v for %q and the case says "+
					"shapeOnly=%v; Constructed and validateAuthConfig disagree about "+
					"whether this configuration is usable",
					cfg.Constructed(), tc.name, tc.shapeOnly)
			}
			s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
			if err == nil {
				t.Fatalf("AuthenticateAndMonitor accepted a configuration with %q", tc.name)
			}
			if s.Authenticated() {
				t.Fatalf("a refused configuration produced an authenticated session")
			}
			if s.State() != AuthStateAuthenticationFailed {
				t.Fatalf("state is %q, want %q", s.State(), AuthStateAuthenticationFailed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10. The window partition is total
// ---------------------------------------------------------------------------

func TestWindowsTileTheRunWithNoGapAndNoOverlap(t *testing.T) {
	drv := &d24Driver{
		outcomes: []AuthOutcome{d24GoodOutcome(), d24GoodOutcome()},
		probes: []AuthProbe{
			d24Alive(), d24Alive(),
			{Status: 401, SessionPresent: false},
			d24Alive(), d24Alive(),
		},
	}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: &d24Sink{}})
	now := mustClock(t)
	s, err := AuthenticateAndMonitor(context.Background(), cfg, now)
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	if err := EnsureSessionBeforePhase(context.Background(), s, now); err != nil {
		t.Fatalf("first boundary: %v", err)
	}
	if err := EnsureSessionBeforePhase(context.Background(), s, now); err != nil {
		t.Fatalf("second boundary: %v", err)
	}

	ws := s.Windows()
	if len(ws) < 3 {
		t.Fatalf("the run produced %d window(s); a run with a login, a loss and a "+
			"recovery has more than that: %v", len(ws), ws)
	}
	if !ws[0].From().Equal(s.StartedAt()) {
		t.Fatalf("the first window starts at %v and the session started at %v",
			ws[0].From(), s.StartedAt())
	}
	for i := 0; i < len(ws)-1; i++ {
		if ws[i].Open() {
			t.Fatalf("window %d is open and is not the last: %v", i, ws)
		}
		if !ws[i].To().Equal(ws[i+1].From()) {
			t.Fatalf("window %d closes at %v and window %d opens at %v: the partition has "+
				"a gap, so an instant in it maps to NO state",
				i, ws[i].To(), i+1, ws[i+1].From())
		}
		if !ws[i].State().Recognised() {
			t.Fatalf("window %d carries state %q, which nobody enumerated", i, ws[i].State())
		}
	}
	if !ws[len(ws)-1].Open() {
		t.Fatalf("the last window is closed, so an instant after the run maps to no state")
	}

	// Totality: every probe instant lands in EXACTLY ONE window.
	span := ws[len(ws)-1].From().Sub(ws[0].From())
	for i := 0; i <= 40; i++ {
		at := ws[0].From().Add(time.Duration(i) * span / 40)
		hits := 0
		for _, w := range ws {
			if w.Contains(at) {
				hits++
			}
		}
		if hits != 1 {
			t.Fatalf("instant %v falls in %d window(s), want exactly 1: %v", at, hits, ws)
		}
	}
	// An instant before the run is unauthenticated, not unknown.
	if got := s.StateAt(s.StartedAt().Add(-time.Hour)); got != AuthStateUnauthenticated {
		t.Fatalf("an instant before the session started is labelled %q, want %q",
			got, AuthStateUnauthenticated)
	}
	if got := s.StateAt(s.StartedAt()); !got.Recognised() {
		t.Fatalf("the session's own start instant is labelled %q", got)
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func hasEventKind(s *Session, k SessionEventKind) bool {
	for _, e := range s.Events() {
		if e.Kind() == k {
			return true
		}
	}
	return false
}

func lastEventOf(t *testing.T, s *Session, k SessionEventKind) SessionEvent {
	t.Helper()
	var out SessionEvent
	found := false
	for _, e := range s.Events() {
		if e.Kind() == k {
			out, found = e, true
		}
	}
	if !found {
		t.Fatalf("the ledger has no %q row: %v", k, s.Events())
	}
	return out
}
