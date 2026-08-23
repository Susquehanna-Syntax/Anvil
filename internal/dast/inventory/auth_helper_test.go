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
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strconv"
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
	// d24Password is CHOSEN TO BREAK THE SWEEP, not to suit it.
	//
	// A SPACE and an "&": redact() rewrites "&" to "?", so a sweep run AFTER
	// redaction would not find this string — the defect
	// TestRedactionDoesNotDefeatTheSweep pins.
	//
	// A '"', a '&', a '<' and a '>': every one of them is rewritten by an HTML
	// escaper and the '"' by a JSON one, so a byte-exact sweep over the raw,
	// query-escaped and path-escaped spellings MISSES this credential in the
	// two encodings an artifact most often carries. A generator that cannot
	// produce the breaking input is the defect, and the previous fixture
	// password could not: it was picked to suit redact().
	d24Password = `s3cr3t "Pa55w0rd" &<9xQz>`
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

// d24HTMLEscape is what a template engine writes into a page, and what the
// browser hands back in a DOM dump. It is here rather than from the `html`
// package because "html" is NOT on gate 3's inertImports, and reaching outside
// this packet's write scope to add it is not this packet's edit to make.
//
// The order matters: "&" first, or the ampersands of the later replacements
// get escaped a second time.
func d24HTMLEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return strings.ReplaceAll(s, "'", "&apos;")
}

// d24JSONEscape is what encoding/json writes, WITHOUT the surrounding quotes.
// AuthArtifactStorageState is JSON by definition, so this is the ordinary
// spelling for the artifact kind most likely to carry a credential — not an
// exotic one.
func d24JSONEscape(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if len(b) < 2 {
		t.Fatalf("json.Marshal produced %q", b)
	}
	return string(b[1 : len(b)-1])
}

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
//
// It exercises BOTH controls, and it is arranged so that neither can carry the
// other:
//
//	THE PROVENANCE RULE gets the three artifacts produced while a credential
//	was in flight — steps 2 and 4 type one, and the step-0 storage dump spans
//	the whole flow. Their bytes are never read.
//
//	THE BACKSTOP SWEEP gets the two artifacts the driver attached to step 3,
//	which types nothing at all. They carry the credential in the two spellings
//	the byte-exact sweep MISSED: HTML-entity-encoded, exactly the shape the
//	finding demonstrated (`value="s3cr3t Pa55w0rd&amp;9xQz"`), and
//	JSON-escaped, which is what AuthArtifactStorageState is made of.
func d24LeakyOutcome(t *testing.T) AuthOutcome {
	t.Helper()
	o := d24GoodOutcome()
	o.Detail = "typed " + d24Password + " into the password field"
	// The landed path carries the PASSWORD, not the TOTP, on purpose: the
	// password contains "&", which redact() rewrites, so a sweep that ran
	// after redaction rather than before would miss it and ship most of its
	// characters. The needle list below covers the redacted form precisely so
	// that this case fails rather than passes.
	o.LandedPath = "/account?next=" + d24Password
	o.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactHTTPExchange, Step: 2, Name: "post-login-" + d24Password,
			Bytes: []byte("POST /login\r\n\r\npassword=" + url.QueryEscape(d24Password))},
		{Kind: AuthArtifactStorageState, Step: 0, Name: "storage",
			Bytes: []byte(`{"localStorage":{"totp":"` + d24TOTP + `"}}`)},
		{Kind: AuthArtifactHTTPExchange, Step: 4, Name: "totp-exchange",
			Bytes: []byte("GET /v?c=" + url.PathEscape(d24TOTP))},
		// Step 3 is WAIT. It types nothing, so provenance permits these two
		// and the sweep is the only thing between them and the sink.
		{Kind: AuthArtifactHTTPExchange, Step: 3, Name: "reflected-form",
			Bytes: []byte(`<input name="password" value="` +
				d24HTMLEscape(d24Password) + `">`)},
		{Kind: AuthArtifactStorageState, Step: 3, Name: "session-json",
			Bytes: []byte(`{"localStorage":{"pw":"` + d24JSONEscape(t, d24Password) + `"}}`)},
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
	if err := s.AssertAllAuthenticated([]CoverageInstant{{At: s.StartedAt()}}); err != nil {
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
			// The two forms the byte-exact sweep shipped verbatim. They are
			// needles here so that a regression to a three-spelling sweep
			// fails this assertion rather than passing it.
			{"HTML-entity-encoded", d24HTMLEscape(cred)},
			{"JSON-escaped", d24JSONEscape(t, cred)},
		} {
			if form.needle == cred && form.label != "raw" {
				// A form that is byte-identical to the raw credential proves
				// nothing about that encoding, and would make this loop look
				// like it covered a case it did not.
				continue
			}
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
		outcomes: []AuthOutcome{d24LeakyOutcome(t)},
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

	// ASSERT THE COUNT PER CONTROL, not that some refusal happened, and not a
	// single total that either control could have produced on its own.
	//
	// Three artifacts were produced while a credential was in flight (steps 2
	// and 4 type one; the step-0 dump spans the whole flow) and are refused
	// without their bytes being read. Two more were attached to step 3, which
	// types nothing, and carry the credential HTML-entity-encoded and
	// JSON-escaped: those are the backstop's, and a byte-exact sweep would
	// have stored both.
	mix := s.Report().DispositionMix()
	if got, want := mix[ArtifactSuppressedCredentialStep], 3; got != want {
		t.Fatalf("the provenance rule suppressed %d artifact(s), want %d. Mix: %v",
			got, want, mix)
	}
	if got, want := s.Report().CredentialRefusals(), 2; got != want {
		t.Fatalf("the backstop sweep refused %d artifact(s), want %d — the HTML-entity "+
			"and JSON-escaped ones on step 3, which the provenance rule permits and a "+
			"byte-exact sweep would have stored. Mix: %v", got, want, mix)
	}
	if got, want := s.Report().StoredCount(), 1; got != want {
		t.Fatalf("%d artifact(s) reached the sink, want %d (only the one with no "+
			"credential in it). Mix: %v", got, want, mix)
	}
	if got, want := len(sink.stored), 1; got != want {
		t.Fatalf("the sink actually received %d artifact(s), want %d", got, want)
	}
	if err := s.Report().AssertNoCredentialWasFound(); err == nil {
		t.Fatal("AssertNoCredentialWasFound passed on a run in which the sweep refused " +
			"two artifacts, so it cannot see the damage it exists to report")
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
	for _, keep := range []string{"s3cr3t ", "Pa55w0rd", "9xQz"} {
		if !strings.Contains(redacted, keep) {
			t.Fatalf("the redacted form should still carry most of the credential, which "+
				"is the whole point; %q is missing from %q", keep, redacted)
		}
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
	jsonPW := d24JSONEscape(t, d24Password)
	htmlPW := d24HTMLEscape(d24Password)
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"raw password", "x=" + d24Password, true},
		{"query-escaped password", "x=" + url.QueryEscape(d24Password), true},
		{"path-escaped password", "/x/" + url.PathEscape(d24Password), true},
		// The two the byte-exact sweep shipped verbatim. The HTML one is the
		// finding's own fixture, spelled the way an artifact spells it.
		{"HTML-entity-encoded password",
			`<input name="password" value="` + htmlPW + `">`, true},
		{"JSON-escaped password", `{"localStorage":{"pw":"` + jsonPW + `"}}`, true},
		// Numeric character references, which is what an escaper that does not
		// use the six names emits. A denylist of names would lose to these.
		{"decimal character references", "v=" + d24DecimalEntities(d24Password), true},
		{"hex character references", "v=" + d24HexEntities(d24Password), true},
		// \uXXXX is what encoding/json writes when asked to escape HTML.
		{"unicode-escaped password", `{"pw":"` + d24UnicodeEscape(d24Password) + `"}`, true},
		// LAYERED: the JSON form of the HTML form. One decoder alone finds
		// nothing here; the fixpoint is what closes it.
		{"JSON-escaped HTML-entity-encoded password",
			`{"html":"` + d24JSONEscape(t, htmlPW) + `"}`, true},
		// Percent-encoded twice, the classic double-encoding walk-past.
		{"double percent-encoded password",
			"x=" + url.QueryEscape(url.QueryEscape(d24Password)), true},
		{"raw totp", "{\"t\":\"" + d24TOTP + "\"}", true},
		{"query-escaped totp", "t=" + url.QueryEscape(d24TOTP), true},
		{"the username, which is not a credential", "user=" + d24Username, false},
		{"a prefix of the password", "x=s3cr3t Pa55", false},
		{"the redacted password, which is not the password", "x=" + redact(d24Password), false},
		{"nothing", "GET /login HTTP/1.1", false},
		{"a malformed percent escape and no credential", "x=%zz%2", false},
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

// d24DecimalEntities and d24HexEntities encode EVERY byte as a numeric
// character reference. They exist to prove the entity decoder is generic
// rather than a list of six names.
func d24DecimalEntities(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "&#%d;", r)
	}
	return b.String()
}

func d24HexEntities(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "&#x%X;", r)
	}
	return b.String()
}

// d24UnicodeEscape is the \uXXXX spelling encoding/json writes with HTML
// escaping on, which is the default for encoding/json.Encoder.
func d24UnicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The character-reference decoder, tested by GENERATION rather than by a list
// ---------------------------------------------------------------------------
//
// The number of ways to spell one character as a numeric character reference is
// INFINITE: the specification puts no ceiling on the leading zeros, the base
// may be decimal or hexadecimal, the `x` and the hex digits have a case, and
// the terminating semicolon is optional. A fixture list of spellings is
// therefore a denylist of examples whose LENGTH IS THE ENCODER'S BUDGET — it
// needs one spelling the list does not carry. The tests below sample the space
// instead of enumerating it, which is why the padding widths run past every
// bound the decoder has ever had.

// d24Reference spells one rune as one numeric character reference, in the
// chosen base, with the chosen number of leading zeros, with or without the
// terminating semicolon, and in the chosen case.
func d24Reference(r rune, base, pad int, semi, upper bool) string {
	digits := strconv.FormatInt(int64(r), base)
	if upper {
		digits = strings.ToUpper(digits)
	}
	var b strings.Builder
	b.WriteString("&#")
	if base == 16 {
		if upper {
			b.WriteByte('X')
		} else {
			b.WriteByte('x')
		}
	}
	b.WriteString(strings.Repeat("0", pad))
	b.WriteString(digits)
	if semi {
		b.WriteByte(';')
	}
	return b.String()
}

// d24AllReferences spells EVERY rune of s the same way.
func d24AllReferences(s string, base, pad int, semi, upper bool) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(d24Reference(r, base, pad, semi, upper))
	}
	return b.String()
}

// TestNumericCharacterReferencesHaveNoDigitCeiling walks padding widths well
// past any bound a decoder could carry.
//
// The decoder this replaced scanned at most eight bytes past the '&' for a ';'
// and refused a body longer than that, so seven decimal zeros were decoded and
// eight were not, and the hexadecimal form — one byte longer because of the
// 'x' — lost a pad width earlier. Both are just numbers, and an encoder picks
// the next one.
func TestNumericCharacterReferencesHaveNoDigitCeiling(t *testing.T) {
	secrets := d24Steps(t).secrets()
	for _, base := range []int{10, 16} {
		for _, upper := range []bool{false, true} {
			if base == 10 && upper {
				continue // no case to vary in a decimal reference
			}
			for _, semi := range []bool{true, false} {
				for pad := 0; pad <= 40; pad++ {
					name := fmt.Sprintf("base%02d/pad%02d/semi=%v/upper=%v",
						base, pad, semi, upper)
					t.Run(name, func(t *testing.T) {
						in := `<input name="password" value="` +
							d24AllReferences(d24Password, base, pad, semi, upper) + `">`
						if _, hit := credentialIn([]byte(in), secrets); !hit {
							t.Fatalf("the sweep did not see the credential spelled as "+
								"numeric character references in base %d with %d leading "+
								"zero(s), semicolon=%v, upper=%v. A digit count is "+
								"unbounded by specification, so a decoder that bounds it "+
								"loses to the next pad width", base, pad, semi, upper)
						}
					})
				}
			}
		}
	}
}

// TestAHugeNumericReferenceIsBoundedByTheInputAndNotByADigitCap is the other
// half of removing the ceiling: the work has to stay bounded by the LENGTH OF
// THE INPUT, because that is the thing an artifact cap already bounds.
//
// Each rune of the credential is padded with twenty thousand leading zeros —
// about 440 KB of digits, well inside codedMaxArtifactBytes — and one
// reference asks for a value far above the largest scalar value there is. The
// test completing is the measurement: a decoder that grew work with the digit
// count, or that overflowed on the way, does not get here.
func TestAHugeNumericReferenceIsBoundedByTheInputAndNotByADigitCap(t *testing.T) {
	secrets := d24Steps(t).secrets()
	huge := d24AllReferences(d24Password, 10, 20000, true, false)
	if len(huge) < 400_000 {
		t.Fatalf("the fixture is %d bytes, which is too small to measure anything",
			len(huge))
	}
	if len(huge) > codedMaxArtifactBytes {
		t.Fatalf("the fixture is %d bytes, past the %d-byte artifact cap, so it is not "+
			"an input any artifact could carry", len(huge), codedMaxArtifactBytes)
	}
	if _, hit := credentialIn([]byte(huge), secrets); !hit {
		t.Fatal("the sweep did not see a credential spelled with twenty thousand " +
			"leading zeros per reference")
	}
	// A value past U+10FFFF has no character, and the digits after the point
	// where that is known must still be consumed rather than overflowing into
	// a value that has one.
	for _, over := range []string{
		"&#" + strings.Repeat("9", 40) + ";",
		"&#x" + strings.Repeat("F", 40) + ";",
		"&#" + strings.Repeat("9", 400000) + ";",
	} {
		if _, hit := credentialIn([]byte(over), secrets); hit {
			t.Fatalf("an out-of-range numeric reference of %d bytes was read as a "+
				"credential", len(over))
		}
	}
}

// TestMixedGeneratedSpellingsAreDecoded samples the space rather than walking
// it: every rune of the credential independently gets a literal, a decimal or a
// hexadecimal spelling, with an independently drawn pad width, case and
// terminator.
//
// A semicolon-less reference followed by a LITERAL character is genuinely
// ambiguous — `&#115` followed by a literal '3' is the single character
// U+0483 by specification, not 's' then '3' — so the generator terminates a
// reference whose successor is literal. That is not a concession to the
// decoder: it is the same rule a browser applies, and an encoder that ignored
// it would not be spelling the credential at all.
func TestMixedGeneratedSpellingsAreDecoded(t *testing.T) {
	secrets := d24Steps(t).secrets()
	rng := rand.New(rand.NewPCG(0x24, 0x2718))
	runes := []rune(d24Password)
	for iter := 0; iter < 400; iter++ {
		kinds := make([]int, len(runes)) // 0 literal, 1 decimal, 2 hexadecimal
		for i := range kinds {
			kinds[i] = rng.IntN(3)
		}
		var b strings.Builder
		for i, r := range runes {
			if kinds[i] == 0 {
				b.WriteRune(r)
				continue
			}
			base := 10
			if kinds[i] == 2 {
				base = 16
			}
			semi := rng.IntN(2) == 0
			if i+1 < len(kinds) && kinds[i+1] == 0 {
				semi = true
			}
			if i+1 == len(kinds) {
				semi = true // the closing quote below is not a digit, but say so anyway
			}
			b.WriteString(d24Reference(r, base, rng.IntN(30), semi, rng.IntN(2) == 0))
		}
		in := `{"pw":"` + b.String() + `"}`
		if _, hit := credentialIn([]byte(in), secrets); !hit {
			t.Fatalf("iteration %d: the sweep did not see the credential in the "+
				"generated spelling %q", iter, in)
		}
	}
}

// TestAnUnresolvableReferenceDoesNotHideACredential is the inversion the
// named-entity table needed.
//
// The table carries six names, and the previous shape treated a name outside it
// as ordinary text — so `&commat;` between two halves of a credential hid it,
// and the attacker's budget was "one name out of the two-thousand-odd the
// specification defines". A reference is now recognised BY SHAPE, and one whose
// value this decoder cannot determine decodes to a single wildcard rune that
// matches any one character. The name no longer has to be known; only the
// shape does.
//
// The names below are GENERATED, and the assertion is over every position of
// the credential rather than over the one position a fixture would pick.
func TestAnUnresolvableReferenceDoesNotHideACredential(t *testing.T) {
	secrets := d24Steps(t).secrets()
	rng := rand.New(rand.NewPCG(0x99, 0x1024))
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	runes := []rune(d24Password)
	for iter := 0; iter < 500; iter++ {
		var name strings.Builder
		for n := 1 + rng.IntN(14); n > 0; n-- {
			name.WriteByte(alnum[rng.IntN(len(alnum))])
		}
		if _, known := namedEntities[name.String()]; known {
			continue // a name the table resolves is not what this measures
		}
		pos := rng.IntN(len(runes))
		in := `value="` + string(runes[:pos]) + "&" + name.String() + ";" +
			string(runes[pos+1:]) + `"`
		if _, hit := credentialIn([]byte(in), secrets); !hit {
			t.Fatalf("iteration %d: character %d of the credential was written as the "+
				"unknown named reference &%s; and the sweep saw nothing", iter, pos,
				name.String())
		}
	}
	// AND THE OTHER DIRECTION, or the assertion above is satisfied by a
	// matcher that says yes to everything: a wildcard stands for exactly ONE
	// rune, so a reference that replaces two characters is not a match, and
	// neither is an unrelated string of the same length.
	//
	// The run of wildcards below is deliberately shorter than the SHORTEST
	// credential in the fixture set. A run at least as long as one of them
	// matches it — every rune undecided is a credential that may be there —
	// and that is the over-matching direction, not a defect.
	for _, miss := range []string{
		`value="` + string(runes[:4]) + `&commat;` + string(runes[6:]) + `"`,
		`value="` + strings.Repeat("&commat;", 3) + `"`,
		`value="&commat;"`,
	} {
		if _, hit := credentialIn([]byte(miss), secrets); hit {
			t.Fatalf("the wildcard matched %q, which is not the credential: a wildcard "+
				"that matches more than one rune makes every assertion above vacuous",
				miss)
		}
	}
}

// TestABareAmpersandIsNotAReference holds the other edge shut. A '&' that
// begins nothing — the ordinary case in a query string — must stay a '&', or
// the sweep's own fixture (`s3cr3t Pa55w0rd&9xQz`) stops matching itself.
func TestABareAmpersandIsNotAReference(t *testing.T) {
	secrets := d24Steps(t).secrets()
	for _, in := range []string{
		"x=" + d24Password,
		"/a?next=/b&" + d24Password,
		"a=1&b=2&" + d24Password,
		"&#" + d24Password,
		"&;" + d24Password,
		"&" + d24Password,
	} {
		if _, hit := credentialIn([]byte(in), secrets); !hit {
			t.Fatalf("the credential in %q was lost by the reference decoder", in)
		}
	}
}

// TestAPaddedReferenceOnAnInnocentStepIsRefused drives the reported defect all
// the way to the sink rather than only through credentialIn.
//
// The three artifacts below are attached to STEP 3, which types nothing, so the
// provenance rule permits every one of them — it is the case the backstop
// exists for, and the case in which the old decoder's bounds decided the
// outcome. Before the fix all three reached the ArtifactSink and both
// assertions returned nil.
func TestAPaddedReferenceOnAnInnocentStepIsRefused(t *testing.T) {
	out := d24GoodOutcome()
	out.Artifacts = []AuthArtifact{
		{Kind: AuthArtifactHTTPExchange, Step: 3, Name: "decimal-pad-12",
			Bytes: []byte(`value="` + d24AllReferences(d24Password, 10, 12, true, false) + `"`)},
		{Kind: AuthArtifactHTTPExchange, Step: 3, Name: "hex-pad-9-no-semicolon",
			Bytes: []byte(`value="` + d24AllReferences(d24Password, 16, 9, false, false) + `"`)},
		{Kind: AuthArtifactHTTPExchange, Step: 3, Name: "unknown-named-reference",
			Bytes: []byte(`value="` + strings.ReplaceAll(d24Password, "&", "&AMP;") + `"`)},
	}
	drv := &d24Driver{outcomes: []AuthOutcome{out}, probes: []AuthProbe{d24Alive()}}
	sink := &d24Sink{}
	cfg, audit := d24Config(t, d24Opts{driver: drv, sink: sink})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	mix := s.Report().DispositionMix()
	if got, want := mix[ArtifactSuppressedCredentialStep], 0; got != want {
		t.Fatalf("provenance suppressed %d artifact(s), want %d — step 3 types nothing, "+
			"so if provenance refused these the backstop measured nothing. Mix: %v",
			got, want, mix)
	}
	if got, want := s.Report().CredentialRefusals(), len(out.Artifacts); got != want {
		t.Fatalf("the backstop refused %d of %d artifact(s). Mix: %v", got, want, mix)
	}
	if got := len(sink.stored); got != 0 {
		t.Fatalf("%d artifact(s) carrying the credential reached the sink: %v",
			got, sink.stored)
	}
	if err := s.Report().AssertNoCredentialWasFound(); err == nil {
		t.Fatal("AssertNoCredentialWasFound passed on a run in which three artifacts " +
			"carried the credential")
	}
	d24AssertNoCredential(t, "a run with padded character references",
		d24Emitted(s, audit, sink, err, s.AssertNoCredentialInLedger()))
}

// d24Base64 is a standard-alphabet base64 encoder written out by hand.
//
// It is written out because encoding/base64 is NOT on gate 3's inertImports and
// this tree may not import it — which is the same reason credentialIn cannot
// decode base64, and therefore the reason this is the spelling the test below
// uses to demonstrate that the sweep has a residual at all.
func d24Base64(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	d := []byte(s)
	var b strings.Builder
	for i := 0; i < len(d); i += 3 {
		n := len(d) - i
		v := uint32(d[i]) << 16
		if n > 1 {
			v |= uint32(d[i+1]) << 8
		}
		if n > 2 {
			v |= uint32(d[i+2])
		}
		b.WriteByte(alphabet[(v>>18)&0x3F])
		b.WriteByte(alphabet[(v>>12)&0x3F])
		if n > 1 {
			b.WriteByte(alphabet[(v>>6)&0x3F])
		} else {
			b.WriteByte('=')
		}
		if n > 2 {
			b.WriteByte(alphabet[v&0x3F])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}

// TestTheSweepIsABackstopAndTheProvenanceRuleIsTheControl states the division
// of labour as an executable claim rather than as a comment.
//
// THE POSITIVE CONTROL IS THE POINT: the same bytes that the provenance rule
// refuses without reading are ALSO invisible to the sweep once they are spelled
// with an encoder the sweep does not know. If the sweep could see them, this
// test would not be measuring the thing it claims to measure.
func TestTheSweepIsABackstopAndTheProvenanceRuleIsTheControl(t *testing.T) {
	secrets := d24Steps(t).secrets()
	// THE RESIDUAL, SPELLED OUT. This used to be a named character reference
	// outside the six — `&AMP;` — and that spelling is now DECODED, so it
	// stopped demonstrating anything and this fixture was replaced rather than
	// the claim being weakened to fit it.
	//
	// base64 is what is left. credentialIn cannot decode it because
	// encoding/base64 is not on gate 3's inertImports, so this package may not
	// import it — which is also why the encoder below is written out by hand
	// here. Adding the import is a one-line widening of the egress allowlist in
	// internal/dast/authz/egress_chokepoint_test.go, is reported to the
	// orchestrator, and is recorded in internal/SKIPPED-CONTROLS.md (U10).
	beyond := d24Base64(d24Password)
	if _, hit := credentialIn([]byte(beyond), secrets); hit {
		t.Fatal("the sweep decoded base64, so this test no longer demonstrates the " +
			"limit credentialIn documents; widen the fixture")
	}
	if !strings.Contains(d24Base64("any"), "YW55") {
		t.Fatalf("d24Base64 does not encode base64, so the fixture is not the "+
			"encoding this test claims: d24Base64(%q) = %q", "any", d24Base64("any"))
	}

	out := d24GoodOutcome()
	out.Artifacts = []AuthArtifact{
		// Step 2 types the password. The bytes are spelled with the entity the
		// sweep cannot decode, so ONLY provenance can refuse this.
		{Kind: AuthArtifactHTTPExchange, Step: 2, Name: "beyond-the-sweep",
			Bytes: []byte(`value="` + beyond + `"`)},
		// The same bytes on a step that types nothing. Nothing catches this,
		// and the ledger says so rather than reporting a clean run.
		{Kind: AuthArtifactHTTPExchange, Step: 3, Name: "beyond-everything",
			Bytes: []byte(`value="` + beyond + `"`)},
	}
	drv := &d24Driver{outcomes: []AuthOutcome{out}, probes: []AuthProbe{d24Alive()}}
	sink := &d24Sink{}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: sink})
	s, err := AuthenticateAndMonitor(context.Background(), cfg, mustClock(t))
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}

	mix := s.Report().DispositionMix()
	if got, want := mix[ArtifactSuppressedCredentialStep], 1; got != want {
		t.Fatalf("provenance suppressed %d artifact(s), want %d: %v", got, want, mix)
	}
	if got, want := s.Report().CredentialRefusals(), 0; got != want {
		t.Fatalf("the sweep refused %d artifact(s), want %d — if it can see this "+
			"spelling the positive control above is wrong", got, want)
	}
	if got, want := len(sink.stored), 1; got != want {
		t.Fatalf("the sink received %d artifact(s), want %d", got, want)
	}
	// AND THE ONE THAT GOT THROUGH IS THE ONE THE DOC SAYS CAN: attached to a
	// step that types nothing, in a spelling the backstop does not decode.
	if got := sink.stored[0].Step(); got != 3 {
		t.Fatalf("the artifact that reached the sink belongs to step %d, want 3", got)
	}
	// AssertNoCredentialWasFound returns nil here, which is exactly why its
	// doc refuses to call that a clean run.
	if err := s.Report().AssertNoCredentialWasFound(); err != nil {
		t.Fatalf("AssertNoCredentialWasFound: %v", err)
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
	crawl := []CoverageInstant{
		{At: base.Add(1 * time.Minute)}, {At: base.Add(2 * time.Minute)},
		{At: base.Add(3 * time.Minute)}, {At: base.Add(4 * time.Minute)},
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
	// A nil session labels an observation the same way it labels an instant.
	if s.CoverageAt(CoverageInstant{At: time.Now(), CarriedSession: true}) != AuthStateUnset {
		t.Fatal("a nil *Session labelled an observation, and did it for a caller that " +
			"claimed the request carried a session")
	}
	// EVERY state has a sentence, including the ones no window carries. A
	// state whose meaning falls through to the default is reported to an
	// operator as "unknown" when it is nothing of the kind.
	for _, st := range append([]AuthState{AuthStateUnset}, AuthStateValues()...) {
		got := st.CoverageMeaning()
		if got == "" {
			t.Fatalf("%q has no coverage sentence", st)
		}
		if st != AuthStateUnset && strings.HasPrefix(got, "unknown:") {
			t.Fatalf("%q fell through to the unknown-state sentence: %q", st, got)
		}
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
	// A request that DEMONSTRABLY carried the session still cannot make an
	// unverified window authenticated: the window is a ceiling.
	if err := s.AssertAllAuthenticated([]CoverageInstant{
		s.Carried(unverified, "session cookie attached by the fixture"),
	}); err == nil {
		t.Fatal("AssertAllAuthenticated passed on an instant in an unverified window")
	}
	// AND THE OTHER DIRECTION, which is the one D.26 actually hits: an instant
	// inside a fully authenticated window is NOT authenticated coverage when
	// the request did not carry the session. Wall-clock overlap is not access.
	if got := s.CoverageAt(CoverageInstant{At: between}); got != AuthStateSessionNotCarried {
		t.Fatalf("an observation inside an authenticated window whose request carried no "+
			"session is labelled %q, want %q", got, AuthStateSessionNotCarried)
	}
	if got := s.CoverageAt(s.Carried(between, "session cookie attached by the fixture")); got !=
		AuthStateAuthenticated {
		t.Fatalf("an observation that DID carry the session inside an authenticated "+
			"window is labelled %q, want %q — if this is not reachable the assertion "+
			"above measures nothing", got, AuthStateAuthenticated)
	}
	// AND THE CLAIM WITHOUT THE EVIDENCE IS NOT THE EVIDENCE. The same instant,
	// in the same window, with the exported bool set by hand.
	if got := s.CoverageAt(CoverageInstant{At: between, CarriedSession: true}); got !=
		AuthStateSessionNotCarried {
		t.Fatalf("a struct literal that set CarriedSession widened the label to %q; the "+
			"seal Session.Carried applies is what CoverageAt must require", got)
	}
	if err := s.AssertAllAuthenticated([]CoverageInstant{{At: between}}); err == nil {
		t.Fatal("AssertAllAuthenticated passed on a request that did not carry the " +
			"session, which is the number D.26 would have reported as coverage behind " +
			"the login")
	}

	d24AssertNoCredential(t, "a run with a mid-scan logout",
		d24Emitted(s, audit, sink, err))
}

// d24AuthenticatedWindow returns a session and an instant that sits inside an
// AUTHENTICATED window of it — two passed liveness observations with the
// instant between them.
func d24AuthenticatedWindow(t *testing.T) (*Session, time.Time) {
	t.Helper()
	drv := &d24Driver{
		outcomes: []AuthOutcome{d24GoodOutcome()},
		probes:   []AuthProbe{d24Alive(), d24Alive()},
	}
	cfg, _ := d24Config(t, d24Opts{driver: drv, sink: &d24Sink{}})
	now := mustClock(t)
	s, err := AuthenticateAndMonitor(context.Background(), cfg, now)
	if err != nil {
		t.Fatalf("AuthenticateAndMonitor: %v", err)
	}
	first := lastEventOf(t, s, SessionEventVerified).At()
	if err := EnsureSessionBeforePhase(context.Background(), s, now); err != nil {
		t.Fatalf("EnsureSessionBeforePhase: %v", err)
	}
	second := lastEventOf(t, s, SessionEventVerified).At()
	between := first.Add(second.Sub(first) / 2)
	if got := s.StateAt(between); got != AuthStateAuthenticated {
		t.Fatalf("the fixture instant is in a %q window, not an authenticated one, so "+
			"nothing below measures a widening. Windows: %v", got, s.Windows())
	}
	return s, between
}

// TestAnUnsealedCarriageClaimIsNotCoverage is the guard under
// CoverageInstant.CarriedSession.
//
// The field is exported, has no constructor, and moves an observation from
// AuthStateSessionNotCarried to AuthStateAuthenticated — the one label in this
// package that means "Anvil looked behind the login". Before the seal, the only
// thing standing between a caller and that widening was the field's doc
// comment, and a sentence does not fail a build.
//
// The POSITIVE case is asserted first, because every negative below is vacuous
// if the sealed path cannot reach AuthStateAuthenticated at all.
func TestAnUnsealedCarriageClaimIsNotCoverage(t *testing.T) {
	s, between := d24AuthenticatedWindow(t)

	sealed := s.Carried(between, "session cookie attached by the fixture")
	if got := s.CoverageAt(sealed); got != AuthStateAuthenticated {
		t.Fatalf("a SEALED carriage claim inside an authenticated window is labelled "+
			"%q, want %q — the rest of this test measures nothing if this fails",
			got, AuthStateAuthenticated)
	}
	if sealed.CarriageEvidence() == "" {
		t.Fatal("a sealed instant does not name the mechanism it was minted with, so a " +
			"report cannot say why it counted")
	}
	// CarriageEvidence is a NEW EXPORTED STRING CHANNEL out of this package, so
	// it is swept like every other one: a caller that names the credential as
	// the mechanism gets the refusal marker back, not the credential.
	leaky := s.Carried(between, "cookie=session; password="+d24Password)
	if got := leaky.CarriageEvidence(); strings.Contains(got, d24Password) {
		t.Fatalf("CarriageEvidence returned the credential: %q", got)
	} else if got != refusedForCredential {
		t.Fatalf("a mechanism naming the credential rendered as %q, want the whole "+
			"string refused (%q)", got, refusedForCredential)
	}
	if got := s.CoverageAt(leaky); got != AuthStateAuthenticated {
		t.Fatalf("the refusal changed the LABEL to %q: sweeping the mechanism must not "+
			"silently drop the evidence, or a leaky caller loses coverage instead of "+
			"losing the string", got)
	}

	other, _ := d24AuthenticatedWindow(t)
	empty := s.Carried(between, "   ")
	var nilSession *Session
	for _, tc := range []struct {
		name string
		in   CoverageInstant
	}{
		{"a struct literal that sets the exported bool",
			CoverageInstant{At: between, CarriedSession: true}},
		{"evidence sealed by a DIFFERENT session",
			other.Carried(between, "session cookie attached by the fixture")},
		{"a mechanism that names nothing", empty},
		{"a nil session's evidence", nilSession.Carried(between, "a cookie")},
		{"an unsealed session's evidence", (&Session{}).Carried(between, "a cookie")},
		{"the zero value", CoverageInstant{At: between}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.CoverageAt(tc.in); got != AuthStateSessionNotCarried {
				t.Fatalf("%s produced %q, want %q: a coverage claim this session did not "+
					"seal is not evidence that a request carried it", tc.name, got,
					AuthStateSessionNotCarried)
			}
		})
	}
	// The three that mint nothing must also LOOK like nothing, or a caller
	// reads the bool back and believes it.
	for _, c := range []CoverageInstant{
		empty, nilSession.Carried(between, "a cookie"), (&Session{}).Carried(between, "x"),
	} {
		if c.CarriedSession || c.CarriageEvidence() != "" {
			t.Fatalf("a refused mint returned a claim anyway: %+v", c)
		}
	}
	// AND THE DOWNGRADE IS NOT SILENT.
	err := s.AssertAllAuthenticated([]CoverageInstant{
		{At: between, CarriedSession: true},
		sealed,
	})
	if err == nil {
		t.Fatal("AssertAllAuthenticated passed on an unattested carriage claim")
	}
	if !strings.Contains(err.Error(), "CLAIMED carriage") {
		t.Fatalf("the error does not distinguish an unattested claim from an honest "+
			"false: %v", err)
	}
	if !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("the error does not state the count, so the sealed instant beside it "+
			"was not counted as coverage: %v", err)
	}
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
		// Steps 1 and 3 only (CLICK, WAIT). The HTTP exchange of step 2 and
		// the step-0 storage dump are suppressed too: THE RULE IS ABOUT WHEN
		// THE ARTIFACT WAS PRODUCED, NOT ABOUT WHICH KIND IT IS, because an
		// encoding defeats a byte sweep and does not defeat provenance.
		ArtifactStored: 2,
		// Steps 2 and 4 type a credential; step 0 and step 99 cannot be
		// resolved to a step that does not. Six artifacts, three kinds.
		ArtifactSuppressedCredentialStep: 6,
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
	if got, want := len(sink.stored), 2; got != want {
		t.Fatalf("the sink actually received %d artifact(s), want %d", got, want)
	}
	// POINT THE ASSERTION AT EVERY KIND THAT CAN CARRY THE DAMAGE. The old
	// shape of this loop asked only about screenshots, so an HTTP transcript
	// of the password POST reaching the sink passed it.
	for _, a := range sink.stored {
		if d24Steps(t).stepBears(a.Step()) {
			t.Fatalf("a %s artifact of credential step %d reached the sink",
				a.Kind(), a.Step())
		}
		if a.Step() == 0 {
			t.Fatalf("a %s artifact that names no step reached the sink; it spans the "+
				"whole flow, including the step that types the credential", a.Kind())
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

// TestTheIndependentLookReadsTheBytesTheSinkReceives.
//
// AssertNoCredentialInLedger used to be documented as "a second, INDEPENDENT
// look" that "reads back what those decisions actually produced", and it never
// read the bytes handed to the ArtifactSink — it re-walked the same rendered
// strings the decision path had already sanitized. Two dependent looks are one
// look.
//
// The independent half now reads StoredArtifact.Bytes(), the exact value the
// sink itself reads, through the exact accessor the sink reads it through, at
// the delivery boundary. This test drives that boundary DIRECTLY, bypassing
// the decision path, because that is the shape of the bug it exists for: a
// refactor that sweeps one field and stores another.
func TestTheIndependentLookReadsTheBytesTheSinkReceives(t *testing.T) {
	sink := &d24Sink{}
	cfg, _ := d24Config(t, d24Opts{driver: d24Working(), sink: sink})
	s := &Session{
		cfg:       cfg,
		state:     AuthStateUnauthenticated,
		startedAt: mustClock(t).Instant(),
		sealed:    true,
	}
	secrets := cfg.Steps.secrets()
	if len(secrets) == 0 {
		t.Fatal("the fixture has no credentials, so nothing below measures anything")
	}

	// THE DEPENDENT HALF SEES NOTHING HERE, and that is the point: this
	// session has no events and no artifact rows, so a check that only
	// re-walks rendered strings has nothing to walk.
	if err := s.AssertNoCredentialInLedger(); err != nil {
		t.Fatalf("AssertNoCredentialInLedger on an empty ledger: %v", err)
	}

	// The negative control first: a clean artifact is delivered, recorded, and
	// the assertion stays nil.
	clean := StoredArtifact{
		kind: AuthArtifactHTTPExchange, step: 3, name: "clean",
		bytes: []byte("GET /login HTTP/1.1\r\n\r\n"), sealed: true,
	}
	if err := s.deliver(context.Background(), clean, secrets); err != nil {
		t.Fatalf("deliver refused a clean artifact: %v", err)
	}
	if len(sink.stored) != 1 {
		t.Fatalf("the sink received %d artifact(s) for one clean delivery", len(sink.stored))
	}
	if len(s.emitted) != 1 {
		t.Fatalf("%d delivery verdict(s) were recorded for one delivery", len(s.emitted))
	}
	if err := s.AssertNoCredentialInLedger(); err != nil {
		t.Fatalf("AssertNoCredentialInLedger after a clean delivery: %v", err)
	}

	// THE DAMAGE. Nothing in the decision path chose these bytes; they arrive
	// at the boundary the way a mis-wired store path would deliver them.
	bad := StoredArtifact{
		kind: AuthArtifactStorageState, step: 3, name: "leaked",
		bytes: []byte(`{"pw":"` + d24Password + `"}`), sealed: true,
	}
	err := s.deliver(context.Background(), bad, secrets)
	if !errors.Is(err, ErrCredentialInArtifact) {
		t.Fatalf("deliver returned %v, want ErrCredentialInArtifact", err)
	}
	if len(sink.stored) != 1 {
		t.Fatalf("the sink received %d artifact(s); the leaking one must never have "+
			"been handed over at all", len(sink.stored))
	}
	lerr := s.AssertNoCredentialInLedger()
	if !errors.Is(lerr, ErrCredentialInArtifact) {
		t.Fatalf("AssertNoCredentialInLedger returned %v after a delivery whose bytes "+
			"carried a credential; the look that can see the damage is the one that "+
			"reads what the sink was handed", lerr)
	}
	if !strings.Contains(lerr.Error(), "handed to the ArtifactSink") {
		t.Fatalf("the failure does not say WHERE it was seen, so an operator cannot "+
			"tell the independent half from the rendered one: %v", lerr)
	}
	// The verdict names the artifact and never the bytes.
	if !strings.Contains(lerr.Error(), string(AuthArtifactStorageState)) {
		t.Fatalf("the failure does not name the artifact kind: %v", lerr)
	}
	d24AssertNoCredential(t, "the independent look's own error",
		lerr.Error()+"\n"+err.Error())
}
