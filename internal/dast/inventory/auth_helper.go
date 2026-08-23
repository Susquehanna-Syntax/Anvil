// D.24 — the authenticated-crawl helper.
//
// THIS IS THE ONE FILE IN THE DYNAMIC TIER THAT HOLDS A CREDENTIAL, so it is
// the one file where getting logging wrong is itself the vulnerability. Two
// properties are load-bearing, and everything below is arranged around them.
//
// # 1. A credential must never reach a log, an error, an audit row or a report
//
// The package's redact() is a DISPLAY helper: it folds a string down to an
// allowlisted charset. That is exactly the wrong control here, because a
// credential is usually already inside that charset — redact("hunter2") is
// "hunter2". A redactor cannot protect a secret whose spelling is innocent.
//
// So this file uses two controls that do not depend on the secret's spelling:
//
//	Secret            the credential never exists as a plain string field on
//	                  any struct in this package. It is held XOR-masked, and
//	                  every fmt verb, every Marshal and every reflective walk
//	                  therefore renders "[credential redacted]" or two byte
//	                  slices — never the value. TestFmtCannotPrintACredential
//	                  measures this over %v %s %q %d %x %#v and over a struct
//	                  that CONTAINS a Secret in an unexported field, which is
//	                  the case fmt.Stringer alone does not cover: fmt cannot
//	                  call a method on a value it cannot Interface(), so a
//	                  String() method on its own would have leaked there.
//
//	PROVENANCE        an artifact produced while a credential was in flight is
//	                  never stored, WHATEVER ITS KIND AND WHATEVER SPELLING
//	                  ITS BYTES USE, because the rule does not read the bytes:
//	                  Session.credentialWasInFlight refuses every artifact
//	                  belonging to a step that types a secret, and every
//	                  artifact that names no step and therefore spans one. A
//	                  driver that wants an HTTP transcript or a storage dump
//	                  retained attaches it to a step that types nothing.
//
//	the sweep         the BACKSTOP under that rule, for the artifact a driver
//	                  attached to an innocent step whose bytes carry the
//	                  credential anyway. Every byte that leaves for the sink,
//	                  and every driver-authored string that reaches the
//	                  ledger, is expanded into the SET OF ITS CANDIDATE
//	                  READINGS — percent, backslash and HTML character
//	                  references decoded ONE DECODER AT A TIME, every
//	                  intermediate retained, every ambiguity branched where it
//	                  arises — and every member of that set is searched for
//	                  the credential's actual value, and the whole artifact or
//	                  string is REFUSED if it is found. Not redacted in place:
//	                  a partial rewrite has to anticipate every encoding, and
//	                  refusing the artifact does not.
//
// THE SWEEP IS NOT A COMPLETENESS CLAIM AND SAYS SO IN ITS OWN DOC. An earlier
// shape of it searched three ENCODINGS OF THE SECRET (raw, QueryEscape,
// PathEscape); an HTML-entity-encoded credential — `value="s3cr3t
// Pa55w0rd&amp;9xQz"` — was stored verbatim and every assertion reported
// clean. An enumeration of encodings is a denylist and loses; the answer was
// not a fourth spelling but the rule above it, which never looks at bytes.
//
// The masking is anti-disclosure, NOT cryptography. The pad sits beside the
// ciphertext and anyone holding the struct can undo it in two lines. It
// defeats fmt, log, reflection and encoding — which is the entire set of ways
// a credential has historically ended up in a scan report — and it defeats
// nothing else. That limit is stated here rather than implied by silence.
//
// What the sweep does NOT catch, stated rather than qualified away — each of
// these reaches the sink ONLY on an artifact whose step types no credential,
// because the provenance rule refuses the rest without reading them:
//
//	A NAMED REFERENCE WHOSE EXPANSION IS MORE THAN ONE RUNE. This bullet used
//	to say that a name outside the six predefined ones was the only way past
//	the sweep, because "the numeric forms are decoded generically". THE SECOND
//	HALF WAS FALSE AND THE FIRST DEPENDED ON IT. Measured against the decoder
//	that stood here, using this file's own credential: the reference body was
//	capped at eight bytes, so four decimal leading zeros decoded and five did
//	not, hexadecimal reached the same four for the credential as a whole (a
//	single '&' survived five decimal zeros and only four hexadecimal ones,
//	the 'x' spending a byte of the same eight), and NO semicolon-less
//	spelling decoded at any width though HTML5 permits it. 231 of the 246
//	generated spellings in TestNumericCharacterReferencesHaveNoDigitCeiling
//	were invisible to the sweep.
//
//	The decoder now recognises a reference BY SHAPE, reads numeric values with
//	no digit ceiling, and turns a name it cannot resolve into ONE WILDCARD
//	RUNE that matches any one character — so neither the digit count nor the
//	table's length is the encoder's budget any more. What one wildcard cannot
//	stand for is a name whose expansion is two runes.
//
//	TWO REFERENCES NEEDING DIFFERENT NON-GREEDY READINGS THAT THEN NEED
//	DECODING AGAIN. The sweep no longer resolves an ambiguity while producing
//	the form its own union is taken over — that defect is closed and measured
//	in credentialIn's doc — but one form still takes the SAME reading index at
//	every site, which is the diagonal of the cross-product rather than the
//	whole of it. The residual is exactly the off-diagonal, and only where the
//	readings must be decoded a second time; it is shown by a fixture in
//	TestTwoSitesNeedingDifferentReadingIndicesAreTheResidual rather than
//	asserted about.
//
//	TWO '+' SIGNS IN ONE FORM NEEDING DIFFERENT READINGS. THE SAME DIAGONAL,
//	ON A DIFFERENT AXIS, AND ITS ABSENCE FROM THIS LIST WAS ITSELF THE DEFECT.
//	'+' is a space in a query string and a literal plus everywhere else, and
//	plusToSpace is a WHOLE-STRING pass, so every '+' present in one form takes
//	the same reading in the form that pass produces. Across DEPTH the set does
//	express the mixture — a '+' already there can be read as a space while a
//	'+' that only appears after the next percent step is read as a plus — but
//	the same-depth cross-product is not produced. MEASURED: the secret "a b+c"
//	inside `pw=a+b+c` is NOT FOUND, while "a b c" and "a+b+c" in the same bytes
//	are, and "A B+C" inside `A+B%2BC` is.
//	TestTwoPlusSignsInOneFormNeedingDifferentReadingsAreTheResidual is the
//	fixture, and it carries those control rows so the gap cannot be read as
//	the whole mechanism.
//
//	A DEEPLY LAYERED ENCODING INSIDE AN ARTIFACT THAT DOES NOT SHRINK. This
//	bullet is here because its absence was itself a defect: the sweep re-ran
//	its pipeline THREE TIMES and nothing said so, so percent-encoding applied
//	four times was invisible and the residual list read as though it were
//	complete. The sweep now walks a candidate set to closure under a bound on
//	BYTES SCANNED rather than on layers — measured, it reaches 2767 layers of
//	repeated url.QueryEscape, and no constant in this file names a depth. What
//	remains is disclosed as a MEASURED CURVE at codedSweepWorkBytes: an
//	artifact that does not shrink as it is decoded is decoded eleven layers at
//	the 4 MiB cap, fifty at a megabyte, and more than sixty below 256 KiB.
//
//	base64 or any other re-encoding of the credential inside an artifact.
//	THE CLAIM THAT THIS WAS THE ONLY DEMONSTRABLE SPELLING IN THIS LIST IS
//	DELETED, BECAUSE IT WAS FALSE: the digit-run ambiguity under one encoding
//	layer was demonstrable too, and 135 of 450 generated re-spellings
//	demonstrated it. That one is closed now; the reading-index diagonal above
//	is the other bullet here that a fixture can still demonstrate, and both
//	fixtures are named beside their bullets so a reader can run them instead
//	of believing this comment. base64 remains
//	TestTheSweepIsABackstopAndTheProvenanceRuleIsTheControl's positive
//	control. Catching it needs encoding/base64, which is NOT on gate 3's
//	inertImports; adding it is a one-line edit in
//	internal/dast/authz/egress_chokepoint_test.go, is reported to the
//	orchestrator rather than made here, and is recorded as U10 in
//	internal/SKIPPED-CONTROLS.md.
//
//	a compressed artifact. compress/gzip IS allowlisted, so this one is
//	reachable; it is not done because an artifact sink that stores compressed
//	bytes does not exist yet, and a decompressor with no producer is untested
//	code in the credential path.
//
//	A CREDENTIAL RENDERED AS PIXELS. No byte sweep can see it, so screenshots
//	are handled by SUPPRESSION rather than by sweeping: under
//	ScreenshotPolicyExceptCredentialSteps a screenshot belonging to a step
//	that types a secret is never stored, and a screenshot that names no step
//	cannot be checked against the step list, so it is suppressed too.
//	ScreenshotPolicySuppressAll is the other choice. There is no third value
//	and no default.
//
// # 2. A FAILED LOGIN FOLLOWED BY A SUCCESSFUL CRAWL IS NOT AN AUTHENTICATED
// CRAWL
//
// An authenticated crawl reaches more of the application — that is the point —
// so "authenticated" is a claim about COVERAGE, and a run that logged in and
// a run that failed to log in produce route lists that look identical and mean
// different things. research/22's Risk #7 is that auth "silently zeroes out a
// scan"; the silence is the defect, not the zero.
//
// Two mechanisms make it impossible to report the wrong one:
//
//	THE DRIVER'S WORD IS NOT ACCEPTED. AuthOutcome.SessionEstablished is the
//	driver's claim, and a claim is not an observation. A Session reaches
//	AuthStateAuthenticated only after CheckLiveness — a request Anvil itself
//	pushed through NewRequestIntent, RequireAuthorization and AuditedAdmit —
//	comes back alive. That is ruling 7's rule ("only an observation Anvil
//	made through the kernel confirms") applied to a session instead of to an
//	endpoint. A driver that returns SessionEstablished:true and cannot then
//	be observed logged in produces AuthStateAuthenticationFailed.
//
//	THE RUN TIMELINE IS PARTITIONED, NOT SUMMARISED. Session.Windows()
//	returns contiguous, non-overlapping windows covering the whole run, each
//	labelled with one AuthState, and StateAt maps any instant to exactly one.
//	A window that begins at a PASSED liveness check and ends at a FAILED one
//	is AuthStateUnverified — the session died somewhere inside it and nobody
//	knows where — and only a window bracketed by two passes is
//	AuthStateAuthenticated. AuthState.AuthenticatedCoverage() is an allowlist
//	of exactly one value, so every other state, including the zero value,
//	answers false. D.26 joins a CrawlVisit's At() against this.
//
// # Everything still goes through the kernel
//
// A login is a state-changing request, so it is admitted as one: GET the login
// page, then POST to it, both through GateAudit.AuditedAdmit. The POST needs
// an explicit per-endpoint allow (authz.EndpointAllowance, gate 15) or the
// kernel refuses it — which means an operator has to name the login endpoint
// on purpose before Anvil will ever submit a credential to it. That is not a
// control this file adds; it is the kernel's, and this file's job is to route
// through it rather than around it.
//
// The technique is pinned to authz.TechniqueAuthenticatedRead and is not
// configurable, for the reason crawlMethod is a const: a caller who could
// choose it could choose one gate 15 judges differently.
//
// codedMaxAuthAttempts exists for a reason worth stating: a forced re-login is
// a credential submission, and an unbounded loop of them against a target that
// keeps refusing IS authz.TechniqueAccountLockout, which is on gate 15's
// destructive denylist. The bound is what stops Anvil's own session recovery
// from turning into the denylisted technique.
//
// # What this file does not do
//
// It does not parse .anvil/target.yaml. D.1 (internal/dast/target) parses and
// validates the `auth` section — method is an allowlist of one value, steps_ref
// is path-checked and repo-contained — and AuthStepsFromManifest reads that
// result rather than the file.
//
// It does not parse the steps document either. That document holds the
// credential, so the component that reads it is a SEAM (AuthStepLoader) and
// its absence is a loud typed refusal, exactly as ClientSpider's is. This
// module has no YAML parser (see RefusalYAMLUnsupported), so
// SystemAuthStepLoader always refuses on every host today.
//
// It holds no socket and cannot: D.9's gate 3 tier 1 makes that structural.
// The browser lives behind AuthDriver, and the obligations on an implementer
// are stated on that interface and enforced nowhere here — the same shape
// ClientSpider and engines.ZapRunner have, and the same integration lane owes
// the proof.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/engines"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrNoAuthDriver is returned when authentication was configured and no
	// browser seam is wired. It is an error and never a session: a run that
	// could not attempt a login must not produce a value whose Authenticated()
	// a caller might read as "the target has no auth".
	ErrNoAuthDriver = errors.New("inventory: no AuthDriver is wired, so no login was " +
		"attempted and any crawl that follows covers the PUBLIC surface only")

	// ErrNoAuthStepLoader is what SystemAuthStepLoader returns.
	ErrNoAuthStepLoader = errors.New("inventory: no AuthStepLoader is wired, so the " +
		"auth.steps_ref document was never read and no explicit step list exists")

	// ErrAuthFailed is what AuthenticateAndMonitor returns when a login was
	// attempted and did not produce a session Anvil could observe. The
	// Session is returned ALONGSIDE it, carrying the failed provenance, so a
	// caller that drops the error still cannot report an authenticated crawl.
	ErrAuthFailed = errors.New("inventory: authentication was configured and did not " +
		"succeed; a crawl that follows is an UNAUTHENTICATED crawl and its coverage " +
		"means something different")

	// ErrSessionLost is what EnsureSessionBeforePhase returns when liveness
	// failed and the forced re-login did not restore the session.
	ErrSessionLost = errors.New("inventory: the authenticated session was lost mid-scan " +
		"and the forced re-login did not restore it")

	// ErrCredentialInArtifact is what the sweep returns. It NEVER carries the
	// offending bytes, the offending string, or the credential — only the
	// index of the step whose secret was found, which is Anvil's own
	// configuration and not the secret.
	ErrCredentialInArtifact = errors.New("inventory: an authentication-report artifact " +
		"contained a credential in plaintext and was refused rather than stored")

	// ErrCoverageIsNotAuthenticated is what AssertAllAuthenticated returns.
	ErrCoverageIsNotAuthenticated = errors.New("inventory: coverage was measured at " +
		"instants this session cannot describe as authenticated")

	// ErrSecretMarshalled is returned by Secret's Marshal methods. Serializing
	// a credential is a bug, and a bug in the credential path fails LOUDLY
	// rather than writing a placeholder into a record nobody re-reads.
	ErrSecretMarshalled = errors.New("inventory: a credential was handed to a serializer; " +
		"a Secret is never a record field, and this is a defect in the caller")
)

// redactedCredential is the ONLY rendering of a Secret. It contains no length
// hint: length is its own payload.
//
// Every byte of it is inside redact()'s allowlist, so redact(marker) == marker
// and a marker that has been through the ledger is still recognisable. A
// marker spelled with square brackets came back as "?credential redacted?",
// which is a different string and would not compare equal in any test that
// looked for it. TestRedactionDoesNotDefeatTheSweep pins both markers.
const redactedCredential = "{credential redacted}"

// refusedForCredential replaces a whole driver-authored string in which a
// credential was found. The string is not partially rewritten; see the header.
const refusedForCredential = "{string refused: it contained a credential}"

// ---------------------------------------------------------------------------
// Coded bounds
// ---------------------------------------------------------------------------

const (
	// codedMaxAuthSteps bounds an operator's step list.
	codedMaxAuthSteps = 64

	// codedMaxSecretBytes bounds one credential.
	codedMaxSecretBytes = 4096

	// codedMaxAuthAttempts bounds how many times ONE session may submit
	// credentials — the initial login plus every forced re-login. See the
	// header: an unbounded retry loop is authz.TechniqueAccountLockout, which
	// gate 15 denies, and Anvil must not arrive there through its own
	// recovery path.
	codedMaxAuthAttempts = 3

	// codedMaxArtifactBytes bounds ONE stored report artifact.
	codedMaxArtifactBytes = 4 << 20

	// codedMaxArtifacts bounds how many artifacts one run stores.
	codedMaxArtifacts = 256

	// codedMaxAliveStatuses bounds the configured liveness allowlist.
	codedMaxAliveStatuses = 16

	// codedMaxStepWait bounds a WAIT step. A step list that can pause for an
	// hour is a way to spend gate 14's wall-clock cap on nothing.
	codedMaxStepWait = 2 * time.Minute
)

// authTechnique is the technique every request in this file declares.
//
// A const, not configuration: a login and a session probe are reads performed
// with credentials the operator supplied for the purpose, which is exactly
// what authz.TechniqueAuthenticatedRead names. A caller who could choose it
// could choose one gate 15 judges differently.
const authTechnique = authz.TechniqueAuthenticatedRead

// authNavMethod and authSubmitMethod are the two requests a browser-based
// login makes: the navigation to the login page, and the credential
// submission. They are admitted SEPARATELY because gate 15 judges them
// differently — the POST is state-changing and needs an explicit
// per-endpoint allow, the GET does not — and folding them into one admission
// would hide the one that needs the operator's permission.
const (
	authNavMethod    = authz.MethodGet
	authSubmitMethod = authz.MethodPost
)

// authLivenessMethod is the method a session probe uses. A liveness check
// reads; it never changes state.
const authLivenessMethod = authz.MethodGet

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

// Secret is a credential value that cannot be printed.
//
// The value is held XOR-masked so that no path through fmt, encoding or
// reflection can reach the plaintext: Format answers every verb with
// redactedCredential, the Marshal methods refuse, and a reflective walk of a
// struct that holds one — the case a String() method does NOT cover, because
// fmt cannot call a method on a field it cannot Interface() — finds two byte
// slices.
//
// The mask is not encryption; see this file's header for exactly what it does
// and does not defend against.
//
// The zero value holds nothing, Present() is false, and Reveal() returns "".
type Secret struct {
	enc    []byte
	pad    []byte
	sealed bool
}

// NewSecret seals a credential value.
//
// An empty credential is refused rather than stored: "" is what a failed
// environment lookup produces, and a login step configured with a credential
// nobody supplied must fail here rather than submit an empty password.
func NewSecret(raw string) (Secret, error) {
	if raw == "" {
		return Secret{}, fmt.Errorf("inventory: %w: the credential is empty. An empty "+
			"credential is what a failed lookup produces, and submitting one is a "+
			"login attempt against an account with a blank password", ErrRefused)
	}
	if len(raw) > codedMaxSecretBytes {
		return Secret{}, fmt.Errorf("inventory: %w: the credential exceeds the coded "+
			"bound of %d bytes", ErrRefused, codedMaxSecretBytes)
	}
	pad := make([]byte, len(raw))
	for i := 0; i < len(pad); i += 8 {
		v := rand.Uint64()
		for j := 0; j < 8 && i+j < len(pad); j++ {
			pad[i+j] = byte(v >> (8 * uint(j)))
		}
	}
	enc := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		enc[i] = raw[i] ^ pad[i]
	}
	return Secret{enc: enc, pad: pad, sealed: true}, nil
}

// Present reports whether s holds a credential. The zero value does not.
func (s Secret) Present() bool { return s.sealed && len(s.enc) > 0 }

// Reveal is THE ONE EXIT, and it exists because a driver has to type the
// credential into a form.
//
// Every caller of it in this package is in the credential path by design:
// the sweep (which compares artifact bytes against it and discards the result)
// and nothing else. A driver receives the Secret and calls this itself, at the
// keystroke, and owes the same obligation the rest of this file keeps.
func (s Secret) Reveal() string {
	if !s.sealed {
		return ""
	}
	b := make([]byte, len(s.enc))
	for i := range s.enc {
		b[i] = s.enc[i] ^ s.pad[i]
	}
	return string(b)
}

// Format renders s for EVERY fmt verb. It is deliberately not a String()
// method: fmt consults Formatter before anything else, so %d, %x and %#v are
// covered by this and would not be covered by Stringer alone.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedCredential))
}

// String renders s for a caller that reaches for it directly.
func (s Secret) String() string { return redactedCredential }

// MarshalJSON refuses. See ErrSecretMarshalled.
func (s Secret) MarshalJSON() ([]byte, error) { return nil, ErrSecretMarshalled }

// MarshalText refuses, which also closes encoding/json's TextMarshaler route
// and every encoder that honours it.
func (s Secret) MarshalText() ([]byte, error) { return nil, ErrSecretMarshalled }

// ---------------------------------------------------------------------------
// Steps — explicit, never autodetection
// ---------------------------------------------------------------------------

// AuthStepKind is one step of a browser-based login flow.
//
// The five literals are plan/50-dast.md D.24's own list. They are ZAP
// Authentication Helper step types; this module does not drive ZAP on any host
// it has measured, so the mapping from these names to ZAP's configuration is
// the integration lane's to prove and is NOT claimed here.
//
// AUTO_STEPS is on the list and is not a contradiction of "never
// autodetection". It is an EXPLICITLY REQUESTED step that performs the
// packaged username-and-password fill at a point the operator chose. What
// D.24 forbids is letting ZAP work out the whole login flow by itself; a step
// list containing AUTO_STEPS is still a step list somebody wrote.
type AuthStepKind string

const (
	// AuthStepUnset is the zero value and names nothing.
	AuthStepUnset AuthStepKind = ""
	// AuthStepAutoSteps fills the configured username and password.
	AuthStepAutoSteps AuthStepKind = "AUTO_STEPS"
	// AuthStepClick clicks the element the selector names.
	AuthStepClick AuthStepKind = "CLICK"
	// AuthStepCustomField types a value into a named field.
	AuthStepCustomField AuthStepKind = "CUSTOM_FIELD"
	// AuthStepTOTPField types a time-based one-time code into a named field.
	AuthStepTOTPField AuthStepKind = "TOTP_FIELD"
	// AuthStepWait pauses for a bounded interval.
	AuthStepWait AuthStepKind = "WAIT"
)

// AuthStepKindValues returns every legal literal.
func AuthStepKindValues() []AuthStepKind {
	return []AuthStepKind{
		AuthStepAutoSteps, AuthStepClick, AuthStepCustomField,
		AuthStepTOTPField, AuthStepWait,
	}
}

// Recognised reports whether k is one of the enumerated kinds. The zero value
// is not.
func (k AuthStepKind) Recognised() bool {
	for _, v := range AuthStepKindValues() {
		if v == k {
			return true
		}
	}
	return false
}

// secretBearingStepKinds is the ALLOWLIST of step kinds that put a credential
// on the screen or on the wire.
//
// It is an allowlist and the direction of its failure is chosen: a kind
// nobody classified is NOT on it, so Bearing() is false, so a screenshot of it
// would be stored. That would be the wrong direction — so the callers do not
// consult Bearing() alone. screenshotAllowedForStep refuses any step index it
// cannot resolve to a recognised, classified step, which turns "nobody
// classified this kind" into suppression rather than into storage.
func secretBearingStepKinds() map[AuthStepKind]bool {
	return map[AuthStepKind]bool{
		AuthStepAutoSteps:   true,
		AuthStepCustomField: true,
		AuthStepTOTPField:   true,
	}
}

// Bearing reports whether a step of this kind carries a credential.
func (k AuthStepKind) Bearing() bool { return secretBearingStepKinds()[k] }

// AuthStep is one step, as an operator wrote it.
//
// Exported fields, like authz.RequestFacts: a caller has to be able to write
// the facts down. Nothing is authorized because an AuthStep exists —
// NewAuthSteps validates every field and seals the list.
type AuthStep struct {
	// Kind is required and must be recognised.
	Kind AuthStepKind
	// Selector names the element or field the step acts on. For
	// AUTO_STEPS it is the USERNAME, which is not a credential: it names
	// which account the scan authenticated as, and internal/record/mask.go
	// keeps it for exactly that reason.
	Selector string
	// Value is the credential. Required for a secret-bearing kind and
	// refused on any other: a CLICK that carries a password is a step list
	// somebody wrote by mistake, and a mistake in the credential path is
	// refused rather than ignored.
	Value Secret
	// Wait is the pause for a WAIT step, required there and refused
	// elsewhere.
	Wait time.Duration
}

// AuthSteps is a sealed, validated login flow bound to the manifest that
// declared it.
type AuthSteps struct {
	method    string
	sourceRef string
	steps     []AuthStep
	sealed    bool
}

// NewAuthSteps validates a step list and seals it.
//
// method must be target.AuthMethodBrowser — D.1's allowlist of one — and is
// re-checked here rather than trusted, because AuthSteps can also be built
// from a step list that never came through a Manifest at all.
//
// An EMPTY step list is refused. An empty list is autodetection under another
// name: it asks the driver to work the login out for itself, which is the one
// thing D.24 forbids.
//
// A list with no secret-bearing step is refused. A login flow that submits no
// credential is not a login flow, and a session it produced could not honestly
// be called authenticated.
func NewAuthSteps(method, sourceRef string, steps []AuthStep) (AuthSteps, error) {
	if method != target.AuthMethodBrowser {
		return AuthSteps{}, fmt.Errorf("inventory: %w: auth.method is %q and the only "+
			"method D.1 accepts is %q", ErrRefused, redact(method), target.AuthMethodBrowser)
	}
	if strings.TrimSpace(sourceRef) == "" {
		return AuthSteps{}, fmt.Errorf("inventory: %w: the step list names no source. A "+
			"step list whose provenance nobody recorded cannot be joined back to the "+
			"manifest that declared it", ErrRefused)
	}
	if len(steps) == 0 {
		return AuthSteps{}, fmt.Errorf("inventory: %w: the step list is empty. An empty "+
			"list is autodetection under another name — it asks the driver to work the "+
			"login out for itself — and D.24 requires an explicit step list", ErrRefused)
	}
	if len(steps) > codedMaxAuthSteps {
		return AuthSteps{}, fmt.Errorf("inventory: %w: the step list has %d steps and the "+
			"coded bound is %d", ErrRefused, len(steps), codedMaxAuthSteps)
	}
	// The step list came from a document that holds credentials, so its own
	// unvalidated fields are swept before they can appear in a refusal
	// message. A loader that put the password in the `kind` field would
	// otherwise leak it through this function's error text.
	var offered []Secret
	for _, st := range steps {
		if st.Value.Present() {
			offered = append(offered, st.Value)
		}
	}
	bearing := 0
	out := make([]AuthStep, len(steps))
	for i, st := range steps {
		if !st.Kind.Recognised() {
			return AuthSteps{}, fmt.Errorf("inventory: %w: step %d names kind %q, which "+
				"is on none of the enumerated step kinds %v",
				ErrRefused, i+1, sanitizeForLedger(string(st.Kind), offered),
				AuthStepKindValues())
		}
		if st.Kind.Bearing() {
			bearing++
			if !st.Value.Present() {
				return AuthSteps{}, fmt.Errorf("inventory: %w: step %d is a %s and carries "+
					"no credential. A secret-bearing step with an empty Secret submits an "+
					"empty value", ErrRefused, i+1, st.Kind)
			}
		} else if st.Value.Present() {
			return AuthSteps{}, fmt.Errorf("inventory: %w: step %d is a %s and carries a "+
				"credential. Only %v put a credential on the wire, and a secret on any "+
				"other step is a step list somebody wrote by mistake",
				ErrRefused, i+1, st.Kind, sortedBearingKinds())
		}
		switch st.Kind {
		case AuthStepWait:
			if st.Wait <= 0 || st.Wait > codedMaxStepWait {
				return AuthSteps{}, fmt.Errorf("inventory: %w: step %d is a WAIT of %v and "+
					"must be in (0, %v]. A WAIT with no bound spends gate 14's wall-clock "+
					"cap on nothing", ErrRefused, i+1, st.Wait, codedMaxStepWait)
			}
		default:
			if st.Wait != 0 {
				return AuthSteps{}, fmt.Errorf("inventory: %w: step %d is a %s and carries "+
					"a WAIT duration, which only a WAIT step has", ErrRefused, i+1, st.Kind)
			}
		}
		if st.Kind == AuthStepClick || st.Kind == AuthStepCustomField {
			if strings.TrimSpace(st.Selector) == "" {
				return AuthSteps{}, fmt.Errorf("inventory: %w: step %d is a %s and names "+
					"no selector", ErrRefused, i+1, st.Kind)
			}
		}
		if len(st.Selector) > maxIdentBytes {
			return AuthSteps{}, fmt.Errorf("inventory: %w: step %d's selector is %d bytes "+
				"and the coded bound is %d", ErrRefused, i+1, len(st.Selector), maxIdentBytes)
		}
		out[i] = st
	}
	if bearing == 0 {
		return AuthSteps{}, fmt.Errorf("inventory: %w: no step in the list submits a "+
			"credential. A flow that submits nothing is not a login, and a session it "+
			"produced could not honestly be called authenticated", ErrRefused)
	}
	return AuthSteps{method: method, sourceRef: sourceRef, steps: out, sealed: true}, nil
}

func sortedBearingKinds() []AuthStepKind {
	var out []AuthStepKind
	for _, k := range AuthStepKindValues() {
		if k.Bearing() {
			out = append(out, k)
		}
	}
	return out
}

// Constructed reports whether a came from NewAuthSteps.
func (a AuthSteps) Constructed() bool { return a.sealed && len(a.steps) > 0 }

// Len is how many steps the flow has.
func (a AuthSteps) Len() int { return len(a.steps) }

// Method is the manifest's declared auth method.
func (a AuthSteps) Method() string { return a.method }

// SourceRef is the manifest's auth.steps_ref, verbatim.
func (a AuthSteps) SourceRef() string { return a.sourceRef }

// Kinds returns the ordered step kinds. It deliberately returns no selectors
// and no Secrets: this is what a ledger row may name.
func (a AuthSteps) Kinds() []AuthStepKind {
	out := make([]AuthStepKind, len(a.steps))
	for i, s := range a.steps {
		out[i] = s.Kind
	}
	return out
}

// Steps returns a COPY of the step list, Secrets included. It is what an
// AuthDriver is handed and there is no other way to reach the credential.
func (a AuthSteps) Steps() []AuthStep {
	out := make([]AuthStep, len(a.steps))
	copy(out, a.steps)
	return out
}

// Format renders the step list for a log line WITHOUT its selectors or its
// secrets, for every verb.
func (a AuthSteps) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(fmt.Sprintf("authSteps(%d steps from %s: %v)",
		len(a.steps), redact(a.sourceRef), a.Kinds())))
}

// secrets returns every credential in the flow. Unexported: it exists for the
// sweep and for nothing else.
func (a AuthSteps) secrets() []Secret {
	var out []Secret
	for _, s := range a.steps {
		if s.Value.Present() {
			out = append(out, s.Value)
		}
	}
	return out
}

// stepBears reports whether the 1-based step index is a credential step.
// An index outside the list answers TRUE — fail closed, because the caller is
// screenshotAllowedForStep and "I cannot resolve this step" must suppress.
func (a AuthSteps) stepBears(oneBased int) bool {
	if oneBased < 1 || oneBased > len(a.steps) {
		return true
	}
	return a.steps[oneBased-1].Kind.Bearing()
}

// ---------------------------------------------------------------------------
// The step loader seam
// ---------------------------------------------------------------------------

// AuthStepLoader reads the auth.steps_ref document.
//
// It is a seam because that document holds the credential: the component that
// parses it is the component that decides how a value becomes a Secret, and
// that decision belongs with whoever owns the secret store, not with a crawl
// helper. An implementation MUST construct every credential through NewSecret
// and MUST NOT retain the plaintext anywhere else.
type AuthStepLoader interface {
	// LoadAuthSteps reads the document at path — already resolved and
	// repo-contained by D.1 — and returns the steps it declares.
	LoadAuthSteps(ctx context.Context, path string) ([]AuthStep, error)
}

// SystemAuthStepLoader returns the loader this host can use.
//
// IT ALWAYS RETURNS AN ERROR, ON EVERY HOST, TODAY. auth.steps_ref is a YAML
// document (D.1's checkYAMLExt) and this module has no YAML parser — the same
// fact RefusalYAMLUnsupported records for Tier 0 spec bodies. Returning a
// loader that produced an empty step list would be autodetection with extra
// steps, and NewAuthSteps refuses an empty list anyway.
//
// It never returns (nil, nil).
func SystemAuthStepLoader() (AuthStepLoader, error) {
	return nil, fmt.Errorf("%w: auth.steps_ref names a YAML document and this module has "+
		"no YAML parser (see RefusalYAMLUnsupported). Nothing read the step list, so no "+
		"login can be attempted", ErrNoAuthStepLoader)
}

// AuthStepsFromManifest turns D.1's validated `auth` section into a sealed
// step list.
//
// It re-parses nothing: internal/dast/target already validated that
// auth.method is on the allowlist of one and that auth.steps_ref is a
// repo-relative, repo-contained YAML path, and AuthStepsPath resolves it.
//
// A manifest with NO auth section returns (AuthSteps{}, nil) — the zero value,
// whose Constructed() is false. That is the honest answer: this target
// declares no authentication, so the correct run is an unauthenticated one,
// and UnauthenticatedSession is how a caller says so on the record.
func AuthStepsFromManifest(ctx context.Context, m *target.Manifest, repoRoot string,
	loader AuthStepLoader) (AuthSteps, error) {

	if m == nil {
		return AuthSteps{}, fmt.Errorf("inventory: %w: no manifest was supplied, so "+
			"nothing declared an auth section one way or the other", ErrUnconstructed)
	}
	if m.Auth == nil {
		return AuthSteps{}, nil
	}
	if loader == nil {
		return AuthSteps{}, fmt.Errorf("%w: the manifest declares auth.steps_ref %q",
			ErrNoAuthStepLoader, redact(m.Auth.StepsRef))
	}
	path := m.AuthStepsPath(repoRoot)
	if path == "" {
		return AuthSteps{}, fmt.Errorf("inventory: %w: the manifest declares an auth "+
			"section whose steps_ref resolved to no path", ErrRefused)
	}
	steps, err := loader.LoadAuthSteps(ctx, path)
	if err != nil {
		// The loader touched the credential document. Its error text is
		// therefore treated as capable of containing a credential and is NOT
		// forwarded — only the fact of failure and the manifest's own
		// steps_ref, which D.1 validated and which Anvil wrote down.
		return AuthSteps{}, fmt.Errorf("inventory: %w: the AuthStepLoader failed on the "+
			"document auth.steps_ref names (%q). Its error text is not reproduced here: "+
			"it read a document that holds a credential",
			ErrRefused, redact(m.Auth.StepsRef))
	}
	return NewAuthSteps(m.Auth.Method, m.Auth.StepsRef, steps)
}

// ---------------------------------------------------------------------------
// The browser seam
// ---------------------------------------------------------------------------

// AuthRequest is one kernel-admitted request in the authentication path.
//
// A composite literal in another package produces the zero value, whose
// Constructed() is false — the property CrawlRequest, ConfirmRequest and
// engines.AdmittedRequest all hold.
type AuthRequest struct {
	auth      authz.Authorization
	target    authz.Target
	method    authz.Method
	path      string
	technique authz.Technique
	navSeq    authz.AuditSeq
	submitSeq authz.AuditSeq
	steps     AuthSteps
	sealed    bool
}

// Constructed reports whether r was built by this file.
func (r AuthRequest) Constructed() bool { return r.sealed && r.target.Constructed() }

// Authorization returns the kernel token this request rests on. An
// implementor MUST pass it to authz.RequireAuthorization (or
// authz.PinnedDialAddress) immediately before constructing a socket.
func (r AuthRequest) Authorization() authz.Authorization { return r.auth }

// Target returns the authorized destination, pinned address and all.
func (r AuthRequest) Target() authz.Target { return r.target }

// Method returns the method the audited admission named.
func (r AuthRequest) Method() authz.Method { return r.method }

// Path returns the concrete request path.
func (r AuthRequest) Path() string { return r.path }

// Technique returns the technique gate 15 judged.
func (r AuthRequest) Technique() authz.Technique { return r.technique }

// NavAuditSeq is the gate-21 row the login NAVIGATION was admitted under, or 0
// for a liveness probe.
func (r AuthRequest) NavAuditSeq() authz.AuditSeq { return r.navSeq }

// SubmitAuditSeq is the gate-21 row the credential SUBMISSION was admitted
// under, or 0 for a liveness probe.
func (r AuthRequest) SubmitAuditSeq() authz.AuditSeq { return r.submitSeq }

// Steps returns the login flow. It is populated for Authenticate and empty for
// ProbeSession: a liveness check needs the session, never the credential.
func (r AuthRequest) Steps() AuthSteps { return r.steps }

// Format renders the request for a log line, for every verb, without reaching
// the step list's selectors or secrets.
func (r AuthRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(fmt.Sprintf("authRequest(%s %s, nav %d, submit %d, %v)",
		r.method, redact(r.path), r.navSeq, r.submitSeq, r.steps)))
}

// AuthOutcome is what the driver did with a login flow.
//
// EVERY STRING FIELD IS DRIVER-AUTHORED AND UNTRUSTED, and every one goes
// through the sweep and then redact() before it reaches the ledger.
type AuthOutcome struct {
	// NavStatus and NavLatency describe the navigation to the login page.
	NavStatus  int
	NavLatency time.Duration
	// SubmitStatus and SubmitLatency describe the credential submission.
	SubmitStatus  int
	SubmitLatency time.Duration
	// SessionEstablished is the DRIVER'S CLAIM that a session exists. It is
	// not believed: a Session reaches AuthStateAuthenticated only after
	// CheckLiveness observes one through the kernel. The zero value is false,
	// which is the fail-closed direction.
	SessionEstablished bool
	// LandedPath is where the flow ended up.
	LandedPath string
	// FailedAtStep is the 1-based step that failed, or 0.
	FailedAtStep int
	// Detail is the driver's own explanation.
	Detail string
	// Artifacts are the authentication report's contents: screenshots, HTTP
	// exchanges and storage state.
	Artifacts []AuthArtifact
}

// AuthProbe is what the driver saw when asked whether the session is alive.
type AuthProbe struct {
	// Status is the HTTP status. A value outside [100,599] is treated as
	// "the seam returned nothing" and is never read as an answer.
	Status int
	// Latency feeds gates 16 and 17.
	Latency time.Duration
	// Location is the Location header verbatim on a 3xx. A bounce to the
	// login path is the classic silent logout.
	Location string
	// SessionPresent is the driver's report that the session cookie or
	// storage entry still exists. The zero value is false.
	SessionPresent bool
}

// AuthDriver is the browser seam for the authentication path.
//
// # The obligations an implementation takes on
//
//  1. HONOUR THE AUTHORIZATION. Call authz.RequireAuthorization with
//     AuthRequest.Authorization() and AuthRequest.Target() immediately before
//     each socket exists.
//  2. STAY ON THE ADMITTED TARGET. Every request the flow makes is to
//     AuthRequest.Target(). A login that redirects off-host is a walk-off,
//     and gate 13 can only judge a hop the driver hands back.
//  3. NEVER WRITE A CREDENTIAL ANYWHERE ANVIL DOES NOT SWEEP. The Secret
//     reaches the keystroke and nothing else: not a driver log, not a
//     temporary file, not an exception message. AuthOutcome.Detail is swept
//     by this package, and a driver that puts a credential in it will have
//     the whole string refused, which is a bug report and not a fix.
//  5. NAME THE STEP EVERY ARTIFACT BELONGS TO. AuthArtifact.Step is what the
//     provenance rule reads, and an artifact that names no step is refused —
//     it covers the whole flow, so it covers the credential step. This is the
//     one obligation whose breach costs the driver nothing but coverage: the
//     report is smaller, not less safe.
//  4. RUN THE EXPLICIT STEP LIST, in order, and nothing else. No
//     autodetection of the login form.
//
// Obligations 1 through 4 are STATED HERE AND ENFORCED NOWHERE IN THIS FILE.
// They are contracts on the implementer, of the same kind ClientSpider and
// engines.ZapRunner state, and an integration lane owes the proof.
type AuthDriver interface {
	// Authenticate runs the explicit step list and reports what happened.
	Authenticate(ctx context.Context, req AuthRequest) (AuthOutcome, error)
	// ProbeSession issues ONE request to the liveness path using the session
	// the last Authenticate established, and reports what came back. It must
	// NOT follow a redirect: the Location is what tells Anvil the session was
	// bounced to the login page.
	ProbeSession(ctx context.Context, req AuthRequest) (AuthProbe, error)
}

// SystemAuthDriver returns the authentication driver this host can run.
//
// IT ALWAYS RETURNS AN ERROR, ON EVERY HOST, TODAY — and the error is D.15's
// own, obtained by CALLING engines.SystemZapRunner rather than by asserting
// what it would say. D.24's driver is ZAP's Authentication Helper; no ZAP
// runner adapter is compiled into this module, so there is no Authentication
// Helper either.
//
// MEASURED 2026-08-22, PowerShell, on the development host (recorded in
// internal/dast/engines/zap.go's header and in SKIPPED-CONTROLS U5): no zap.sh,
// no zap, no zap.bat, no docker. A JVM is present; ZAP is not.
//
// It never returns (nil, nil).
func SystemAuthDriver() (AuthDriver, error) {
	_, err := engines.SystemZapRunner()
	if err == nil {
		return nil, fmt.Errorf("inventory: %w: engines.SystemZapRunner returned a runner "+
			"and no Authentication Helper adapter is wired to it. A ZAP that can run and "+
			"an auth flow Anvil can drive are two different things, and the second one "+
			"is missing", ErrNoAuthDriver)
	}
	return nil, fmt.Errorf("%w: D.24's driver is ZAP's Authentication Helper and ZAP is "+
		"not drivable here: %w", ErrNoAuthDriver, err)
}

// ---------------------------------------------------------------------------
// The authentication report
// ---------------------------------------------------------------------------

// AuthArtifactKind is one kind of authentication-report artifact.
// plan/50-dast.md D.24: "screenshots + HTTP + storage".
type AuthArtifactKind string

const (
	// AuthArtifactUnset is the zero value and names nothing.
	AuthArtifactUnset AuthArtifactKind = ""
	// AuthArtifactScreenshot is a rendered image. THE ONE KIND NO BYTE SWEEP
	// CAN CLEAR, because a credential in it is pixels.
	AuthArtifactScreenshot AuthArtifactKind = "screenshot"
	// AuthArtifactHTTPExchange is a request/response transcript.
	AuthArtifactHTTPExchange AuthArtifactKind = "http_exchange"
	// AuthArtifactStorageState is cookies, localStorage and sessionStorage.
	AuthArtifactStorageState AuthArtifactKind = "storage_state"
)

// AuthArtifactKindValues returns every legal literal.
func AuthArtifactKindValues() []AuthArtifactKind {
	return []AuthArtifactKind{
		AuthArtifactScreenshot, AuthArtifactHTTPExchange, AuthArtifactStorageState,
	}
}

// Recognised reports whether k is one of the enumerated kinds.
func (k AuthArtifactKind) Recognised() bool {
	for _, v := range AuthArtifactKindValues() {
		if v == k {
			return true
		}
	}
	return false
}

// AuthArtifact is one artifact the driver produced. Its Name and Bytes are
// driver-authored and untrusted.
type AuthArtifact struct {
	// Kind is required and must be recognised.
	Kind AuthArtifactKind
	// Step is the 1-based step this artifact belongs to, or 0 for an
	// artifact covering the whole flow.
	//
	// IT IS THE FIELD THE PROVENANCE RULE READS, so it decides whether this
	// artifact can be stored at all. Step 0 cannot be checked against the step
	// list and covers the credential step by definition, so it is suppressed —
	// for every kind, not only for screenshots. A driver that wants an
	// artifact retained names the step it belongs to, and names one that types
	// nothing.
	Step int
	// Name is a driver-authored label.
	Name string
	// Bytes are the artifact's contents.
	Bytes []byte
}

// ArtifactDisposition says what happened to one artifact, and why. It is an
// enum for the reason CrawlOutcome is one: "it was not stored" is several
// different facts, and only some of them are decisions.
type ArtifactDisposition string

const (
	// ArtifactDispositionUnset is the zero value and names nothing.
	ArtifactDispositionUnset ArtifactDisposition = ""
	// ArtifactStored: it went to the sink.
	ArtifactStored ArtifactDisposition = "stored"
	// ArtifactSuppressedCredentialStep: THE PROVENANCE REFUSAL, and it applies
	// to every kind rather than only to screenshots. The artifact belongs to a
	// step that types a credential, or names no step at all and therefore
	// spans one. No byte of it is read, so no encoding of the credential gets
	// past it — which is what the byte sweep beside it cannot promise.
	ArtifactSuppressedCredentialStep ArtifactDisposition = "suppressed_artifact_of_a_credential_step"
	// ArtifactSuppressedByPolicy: ScreenshotPolicySuppressAll.
	ArtifactSuppressedByPolicy ArtifactDisposition = "suppressed_all_screenshots_by_policy"
	// ArtifactRefusedCredentialFound: THE CREDENTIAL WAS IN THE BYTES. The
	// whole artifact is dropped, not rewritten.
	ArtifactRefusedCredentialFound ArtifactDisposition = "refused_the_bytes_contained_a_credential"
	// ArtifactRefusedUnrecognisedKind: the driver named a kind nobody
	// enumerated, so no rule about it exists.
	ArtifactRefusedUnrecognisedKind ArtifactDisposition = "refused_unrecognised_artifact_kind"
	// ArtifactRefusedTooLarge: over codedMaxArtifactBytes.
	ArtifactRefusedTooLarge ArtifactDisposition = "refused_artifact_exceeded_the_coded_bound"
	// ArtifactRefusedBudget: codedMaxArtifacts was reached.
	ArtifactRefusedBudget ArtifactDisposition = "refused_the_coded_artifact_count_bound_was_reached"
	// ArtifactRefusedNoSink: nothing was wired to store it.
	ArtifactRefusedNoSink ArtifactDisposition = "refused_no_artifact_sink_is_wired"
	// ArtifactRefusedSinkFailed: the sink returned an error.
	ArtifactRefusedSinkFailed ArtifactDisposition = "refused_the_sink_returned_an_error"
)

// Stored reports whether this disposition means the bytes left for the sink.
func (d ArtifactDisposition) Stored() bool { return d == ArtifactStored }

// ScreenshotPolicy is the operator's choice about screenshots. There is no
// default and the zero value is refused: "store a screenshot of the login
// form" is the permissive direction, and a Go zero value must never mean it.
type ScreenshotPolicy string

const (
	// ScreenshotPolicyUnset is the zero value and is refused by
	// validateAuthConfig.
	ScreenshotPolicyUnset ScreenshotPolicy = ""
	// ScreenshotPolicyExceptCredentialSteps stores screenshots of every step
	// EXCEPT the ones that type a credential, and except any screenshot whose
	// step cannot be resolved. That is the same rule the provenance check
	// applies to every other kind; this policy exists because a screenshot has
	// a second reason to be suppressed — a credential in an image is pixels
	// and no byte sweep can see it — and an operator may want none at all.
	ScreenshotPolicyExceptCredentialSteps ScreenshotPolicy = "store_except_credential_steps"
	// ScreenshotPolicySuppressAll stores no screenshot at all. HTTP and
	// storage artifacts are unaffected BY THIS POLICY — they are still
	// refused by the provenance rule when they belong to a credential step or
	// name no step, and swept when they do not.
	ScreenshotPolicySuppressAll ScreenshotPolicy = "suppress_all_screenshots"
)

// ScreenshotPolicyValues returns every legal literal.
func ScreenshotPolicyValues() []ScreenshotPolicy {
	return []ScreenshotPolicy{
		ScreenshotPolicyExceptCredentialSteps, ScreenshotPolicySuppressAll,
	}
}

// Recognised reports whether p is one of the enumerated policies.
func (p ScreenshotPolicy) Recognised() bool {
	for _, v := range ScreenshotPolicyValues() {
		if v == p {
			return true
		}
	}
	return false
}

// StoredArtifact is what an ArtifactSink receives: swept bytes, a redacted
// name, and no way for the sink to have been handed anything else.
type StoredArtifact struct {
	kind   AuthArtifactKind
	step   int
	name   string
	bytes  []byte
	sealed bool
}

// Constructed reports whether a came from the store path in this file.
func (a StoredArtifact) Constructed() bool { return a.sealed && a.kind.Recognised() }

// Kind is the artifact kind.
func (a StoredArtifact) Kind() AuthArtifactKind { return a.kind }

// Step is the 1-based step, or 0.
func (a StoredArtifact) Step() int { return a.step }

// Name is the driver's label, swept and redacted.
func (a StoredArtifact) Name() string { return a.name }

// Bytes returns a COPY of the swept artifact contents.
func (a StoredArtifact) Bytes() []byte {
	out := make([]byte, len(a.bytes))
	copy(out, a.bytes)
	return out
}

// ArtifactSink stores the authentication report.
//
// plan/50-dast.md D.24 requires every run to store the report for
// diagnosability. A nil sink is therefore a recorded refusal on every
// artifact, never a silent drop: a report nobody kept and a login that
// produced no artifacts are different findings.
type ArtifactSink interface {
	StoreAuthArtifact(ctx context.Context, a StoredArtifact) error
}

// ArtifactRecord is one ledger row about one artifact. IT HOLDS NO BYTES —
// only their count, which is why the ledger itself can never be the leak.
type ArtifactRecord struct {
	kind        AuthArtifactKind
	step        int
	name        string
	size        int
	disposition ArtifactDisposition
	detail      string
}

// Kind is the artifact kind, as the driver named it.
func (r ArtifactRecord) Kind() AuthArtifactKind { return r.kind }

// Step is the 1-based step, or 0.
func (r ArtifactRecord) Step() int { return r.step }

// Name is the driver's label, swept and redacted.
func (r ArtifactRecord) Name() string { return r.name }

// Size is how many bytes the artifact had. Never the bytes.
func (r ArtifactRecord) Size() int { return r.size }

// Disposition is what happened to it.
func (r ArtifactRecord) Disposition() ArtifactDisposition { return r.disposition }

// Detail is a short Anvil-authored explanation.
func (r ArtifactRecord) Detail() string { return r.detail }

// String renders the row for a log line.
func (r ArtifactRecord) String() string {
	return fmt.Sprintf("%s step %d %q (%d bytes) -> %s: %s",
		r.kind, r.step, r.name, r.size, r.disposition, r.detail)
}

// AuthReport is the authentication report's ledger: one row per artifact the
// driver offered, whatever became of it.
type AuthReport struct {
	records []ArtifactRecord
}

// Records returns a COPY of every row.
func (rep AuthReport) Records() []ArtifactRecord {
	out := make([]ArtifactRecord, len(rep.records))
	copy(out, rep.records)
	return out
}

// Offered is how many artifacts the driver produced.
func (rep AuthReport) Offered() int { return len(rep.records) }

// StoredCount is how many reached the sink.
func (rep AuthReport) StoredCount() int {
	n := 0
	for _, r := range rep.records {
		if r.disposition.Stored() {
			n++
		}
	}
	return n
}

// DispositionMix counts the ledger by disposition.
func (rep AuthReport) DispositionMix() map[ArtifactDisposition]int {
	out := map[ArtifactDisposition]int{}
	for _, r := range rep.records {
		out[r.disposition]++
	}
	return out
}

// CredentialRefusals is how many artifacts were dropped because a credential
// was found in their bytes. A NON-ZERO VALUE IS A DEFECT IN THE DRIVER, not a
// success of the sweep: the sweep caught it here, and the same bytes may have
// reached the driver's own log where Anvil cannot see them.
func (rep AuthReport) CredentialRefusals() int {
	return rep.DispositionMix()[ArtifactRefusedCredentialFound]
}

// AssertNoCredentialWasFound returns an error when the BACKSTOP SWEEP refused
// anything.
//
// ITS NIL IS NOT A CLEAN BILL OF HEALTH, and the name is the closest honest
// one available: nothing was FOUND. The sweep searches decoded forms of the
// bytes for the credential and the set of decoders is finite (credentialIn
// names every form it does not see), so a nil here means "no artifact the
// driver attached to an innocent step carried a spelling this recognises".
//
// What keeps a credential out of the report is not this. It is
// Session.credentialWasInFlight, which refuses every artifact produced while a
// credential was in flight WITHOUT READING ITS BYTES, and whose refusals are
// counted separately as ArtifactSuppressedCredentialStep.
func (rep AuthReport) AssertNoCredentialWasFound() error {
	if n := rep.CredentialRefusals(); n > 0 {
		return fmt.Errorf("%w: %d artifact(s) were refused. The sweep caught them before "+
			"the sink, and it can only see what the driver hands Anvil: the same bytes "+
			"may have reached the driver's own log", ErrCredentialInArtifact, n)
	}
	return nil
}

// ---------------------------------------------------------------------------
// AuthState — the provenance D.26 consumes
// ---------------------------------------------------------------------------

// AuthState labels what a stretch of a run's coverage means.
//
// # Why this is declared here
//
// internal/record has no session vocabulary today — InventoryProvenance says
// how an endpoint was FOUND, not whether Anvil was logged in when it found it.
// So this is declared here and FLAGGED TO THE ORCHESTRATOR for hoisting into
// internal/record beside InventoryProvenance if D.26 needs it in the record,
// exactly as D.23's ScanTrigger was. Until then this is the one place the
// vocabulary is written.
//
// # The zero value is not a value
//
// AuthStateUnset names nothing and AuthenticatedCoverage() is false for it. A
// Go zero value must never mean "this coverage was authenticated".
type AuthState string

const (
	// AuthStateUnset is the zero value and names nothing.
	AuthStateUnset AuthState = ""
	// AuthStateUnauthenticated: no login has succeeded in this stretch —
	// either none was configured, or none had run yet. Coverage here is the
	// PUBLIC surface, honestly labelled.
	AuthStateUnauthenticated AuthState = "unauthenticated"
	// AuthStateAuthenticationFailed: a login WAS configured and did not
	// produce a session Anvil could observe. Coverage here is the public
	// surface too — and the difference from AuthStateUnauthenticated is the
	// whole finding, because it means the scan is missing everything behind
	// the login.
	AuthStateAuthenticationFailed AuthState = "authentication_failed"
	// AuthStateAuthenticated: this stretch is bracketed by two PASSED
	// liveness observations, so the session held across all of it. THE ONLY
	// STATE WHOSE COVERAGE MAY BE CALLED AUTHENTICATED.
	AuthStateAuthenticated AuthState = "authenticated"
	// AuthStateUnverified: this stretch began at a passed liveness check and
	// ended at a FAILED one. The session died somewhere inside it and nobody
	// knows where, so its coverage is neither authenticated nor public.
	AuthStateUnverified AuthState = "authenticated_at_the_start_and_lost_by_the_end"
	// AuthStateSessionLost: liveness failed and no re-login has restored the
	// session.
	AuthStateSessionLost AuthState = "session_lost"
	// AuthStateSessionNotCarried: THE SESSION WAS ALIVE AND THE REQUEST DID
	// NOT USE IT.
	//
	// It is the only state here that is a fact about a REQUEST rather than
	// about a stretch of the run, and it exists because the two were being
	// conflated. A window's state says the session was alive between two
	// observations; it says nothing about whether the request measured inside
	// that window carried a cookie, a header or anything else belonging to it.
	// Wall-clock overlap with a live session is not authentication.
	//
	// Coverage here is the PUBLIC SURFACE, honestly labelled, and it is not
	// authenticated coverage.
	AuthStateSessionNotCarried AuthState = "the_session_was_alive_and_the_request_did_not_carry_it"
)

// AuthStateValues returns every legal literal.
func AuthStateValues() []AuthState {
	return []AuthState{
		AuthStateUnauthenticated, AuthStateAuthenticationFailed, AuthStateAuthenticated,
		AuthStateUnverified, AuthStateSessionLost, AuthStateSessionNotCarried,
	}
}

// Recognised reports whether s is one of the enumerated states.
func (s AuthState) Recognised() bool {
	for _, v := range AuthStateValues() {
		if v == s {
			return true
		}
	}
	return false
}

// authenticatedCoverageStates is an ALLOWLIST OF EXACTLY ONE, matched by
// identity. A state nobody enumerated is not on it, and neither is the zero
// value.
func authenticatedCoverageStates() map[AuthState]bool {
	return map[AuthState]bool{AuthStateAuthenticated: true}
}

// AuthenticatedCoverage reports whether coverage measured in this state may be
// described as authenticated.
func (s AuthState) AuthenticatedCoverage() bool { return authenticatedCoverageStates()[s] }

// ---------------------------------------------------------------------------
// The session ledger
// ---------------------------------------------------------------------------

// SessionEventKind is one thing that happened to a session.
type SessionEventKind string

const (
	// SessionEventUnset is the zero value and names nothing.
	SessionEventUnset SessionEventKind = ""
	// SessionEventLoginAttempted: a credential submission was about to be
	// admitted.
	SessionEventLoginAttempted SessionEventKind = "login_attempted"
	// SessionEventLoginRefusedByKernel: a gate refused the login request. The
	// commonest cause is gate 15 — nobody put POST <login path> on the
	// EndpointAllowance.
	SessionEventLoginRefusedByKernel SessionEventKind = "login_refused_by_the_kernel"
	// SessionEventLoginFailed: the driver ran the flow and no session came
	// out of it.
	SessionEventLoginFailed SessionEventKind = "login_failed"
	// SessionEventLoginClaimed: the DRIVER says a session exists. Not
	// believed until an observation says so.
	SessionEventLoginClaimed SessionEventKind = "driver_claimed_a_session"
	// SessionEventVerified: Anvil observed the session alive through the
	// kernel. THE ONLY EVENT THAT PRODUCES AuthStateAuthenticated.
	SessionEventVerified SessionEventKind = "session_observed_alive"
	// SessionEventLivenessFailed: Anvil observed that the session is gone.
	SessionEventLivenessFailed SessionEventKind = "session_observed_gone"
	// SessionEventReLoginForced: liveness failed between phases and a fresh
	// login was forced.
	SessionEventReLoginForced SessionEventKind = "re_login_forced"
	// SessionEventReLoginSucceeded: the forced login produced an observed
	// session.
	SessionEventReLoginSucceeded SessionEventKind = "re_login_succeeded"
	// SessionEventReLoginFailed: it did not.
	SessionEventReLoginFailed SessionEventKind = "re_login_failed"
	// SessionEventAttemptsExhausted: codedMaxAuthAttempts was reached. See
	// the header: the bound exists so Anvil's recovery cannot become
	// authz.TechniqueAccountLockout.
	SessionEventAttemptsExhausted SessionEventKind = "credential_submission_budget_exhausted"
	// SessionEventReportWritten: the authentication report was processed.
	// One row per LOGIN, carrying the artifact counts, so a reader of the
	// ledger alone can see whether a report exists.
	SessionEventReportWritten SessionEventKind = "authentication_report_written"
	// SessionEventNoAuthConfigured: this target declares no auth section, so
	// no login was attempted. It is a DIFFERENT fact from a login that
	// failed, and UnauthenticatedSession is what records it.
	SessionEventNoAuthConfigured SessionEventKind = "no_auth_section_is_declared"
)

// SessionEventKindValues returns every legal literal.
func SessionEventKindValues() []SessionEventKind {
	return []SessionEventKind{
		SessionEventLoginAttempted, SessionEventLoginRefusedByKernel,
		SessionEventLoginFailed, SessionEventLoginClaimed, SessionEventVerified,
		SessionEventLivenessFailed, SessionEventReLoginForced,
		SessionEventReLoginSucceeded, SessionEventReLoginFailed,
		SessionEventAttemptsExhausted, SessionEventReportWritten,
		SessionEventNoAuthConfigured,
	}
}

// Recognised reports whether k is one of the enumerated event kinds.
func (k SessionEventKind) Recognised() bool {
	for _, v := range SessionEventKindValues() {
		if v == k {
			return true
		}
	}
	return false
}

// SessionEvent is one row of the session's ledger.
//
// Detail is ALWAYS Anvil-authored or swept-then-redacted; nothing reaches it
// straight from a driver.
type SessionEvent struct {
	kind   SessionEventKind
	at     time.Time
	seq    authz.AuditSeq
	status int
	detail string
}

// Kind is what happened.
func (e SessionEvent) Kind() SessionEventKind { return e.kind }

// At is the run-clock instant.
func (e SessionEvent) At() time.Time { return e.at }

// AuditSeq is the gate-21 row this event was admitted under, or 0.
func (e SessionEvent) AuditSeq() authz.AuditSeq { return e.seq }

// Status is the HTTP status involved, or 0.
func (e SessionEvent) Status() int { return e.status }

// Detail is a short, swept, redacted explanation.
func (e SessionEvent) Detail() string { return e.detail }

// String renders the event for a log line.
func (e SessionEvent) String() string {
	return fmt.Sprintf("%s at %s [seq %d status %d]: %s",
		e.kind, e.at.UTC().Format(time.RFC3339Nano), e.seq, e.status, e.detail)
}

// AuthWindow is a contiguous stretch of the run with one AuthState.
//
// Windows tile the run: the first begins at the session's start instant, each
// ends where the next begins, and the last is OPEN (To().IsZero()). That is
// what makes StateAt total — every instant at or after the start lands in
// exactly one window — and totality is the point: a summary can omit a
// stretch, a partition cannot.
type AuthWindow struct {
	from          time.Time
	to            time.Time
	state         AuthState
	verifiedStart bool
	verifiedEnd   bool
}

// From is the instant the window opens, inclusive.
func (w AuthWindow) From() time.Time { return w.from }

// To is the instant the window closes, exclusive. The zero value means the
// window is still open.
func (w AuthWindow) To() time.Time { return w.to }

// Open reports whether the window has not been closed.
func (w AuthWindow) Open() bool { return w.to.IsZero() }

// State is what coverage in this window means.
func (w AuthWindow) State() AuthState { return w.state }

// VerifiedStart reports whether the window opened at a PASSED liveness
// observation.
func (w AuthWindow) VerifiedStart() bool { return w.verifiedStart }

// VerifiedEnd reports whether the window closed at a PASSED liveness
// observation. A window with both is bracketed, which is the only shape that
// earns AuthStateAuthenticated.
func (w AuthWindow) VerifiedEnd() bool { return w.verifiedEnd }

// Contains reports whether t falls in the window.
func (w AuthWindow) Contains(t time.Time) bool {
	if t.Before(w.from) {
		return false
	}
	if w.to.IsZero() {
		return true
	}
	return t.Before(w.to)
}

// String renders the window for a log line.
func (w AuthWindow) String() string {
	end := "open"
	if !w.to.IsZero() {
		end = w.to.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("[%s .. %s] %s", w.from.UTC().Format(time.RFC3339Nano), end, w.state)
}

// ---------------------------------------------------------------------------
// AuthConfig
// ---------------------------------------------------------------------------

// AuthConfig is everything AuthenticateAndMonitor needs. Nothing in it has a
// default that means "permitted".
type AuthConfig struct {
	// Governor is the kernel's per-request interceptor for this target.
	Governor *authz.Governor

	// Audit is gate 21's writer, coupled to the interceptor by AuditedAdmit.
	Audit *authz.GateAudit

	// Authorization is the kernel token for Target. authz.Adjudicate is the
	// only mint.
	Authorization authz.Authorization

	// Target is the admitted target. The login and the liveness probe both
	// live on it.
	Target authz.Target

	// Scope is the NARROWED scope — gate 11 already applied. Both paths are
	// checked against it, which is fail-closed on an origin nobody
	// determined. A robots.txt that disallows the login path therefore stops
	// the login, which is the correct answer and not a bug.
	Scope authz.Scope

	// Steps is the explicit login flow. Required and sealed.
	Steps AuthSteps

	// Driver is the browser seam. A nil Driver is a loud refusal and never a
	// silently unauthenticated run.
	Driver AuthDriver

	// Sink stores the authentication report. A nil Sink produces a recorded
	// refusal per artifact rather than a silent drop.
	Sink ArtifactSink

	// LoginPath is where the credential is submitted. POST on it must be on
	// the Governor's EndpointAllowance or gate 15 refuses the submission,
	// which means an operator named this endpoint on purpose.
	LoginPath string

	// LivenessPath is a path that REQUIRES authentication. Required, no
	// default: a liveness check against a public path answers 200 forever
	// and would report a dead session as alive, which is the exact failure
	// D.24 exists to detect.
	LivenessPath string

	// AliveStatuses is the allowlist of statuses that mean "still logged
	// in". Required and non-empty; matched by identity. Anything else — and
	// any redirect back to LoginPath — is a dead session.
	AliveStatuses []int

	// Screenshots is the operator's screenshot policy. Required; the zero
	// value is refused.
	Screenshots ScreenshotPolicy

	// Clock advances the instant between requests, exactly as
	// CrawlConfig.Clock does and for the same reason: gate 14's bucket
	// refills from the elapsed interval. Optional; absent, the run instant is
	// reused and the kernel refuses the overflow, which shows up as a
	// kernel-refused login rather than as a session that quietly never
	// existed.
	Clock ClockSource
}

// Constructed reports whether cfg carries what an authentication run needs.
// Every clause is one validateAuthConfig also checks.
func (c AuthConfig) Constructed() bool {
	return c.Target.Constructed() && c.Scope.Constructed() &&
		c.Governor.Constructed() && c.Audit.Constructed() &&
		authz.RequireAuthorization(c.Authorization, c.Target) == nil &&
		c.Steps.Constructed() && c.Screenshots.Recognised() &&
		len(c.AliveStatuses) > 0 && len(c.AliveStatuses) <= codedMaxAliveStatuses
}

func validateAuthConfig(cfg AuthConfig) error {
	if !cfg.Target.Constructed() {
		return fmt.Errorf("inventory: %w: the auth helper was handed a Target "+
			"authz.NewTarget never built, so no login request can be expressed",
			ErrUnconstructed)
	}
	if !cfg.Scope.Constructed() {
		return fmt.Errorf("inventory: %w: the auth helper was handed a Scope "+
			"authz.NewScope never built. The zero Scope permits no path, which is the "+
			"correct answer and a login that cannot happen", ErrUnconstructed)
	}
	if !cfg.Governor.Constructed() {
		return fmt.Errorf("inventory: %w: the auth helper was handed a Governor "+
			"authz.NewGovernor never built. A nil governor enforces nothing, and "+
			"enforcing nothing is not admitting everything", ErrUnconstructed)
	}
	if !cfg.Audit.Constructed() {
		return fmt.Errorf("inventory: %w: the auth helper was handed a GateAudit "+
			"authz.NewGateAudit never built. A credential submission with no audit row "+
			"cannot be joined back to who authorized it", ErrUnconstructed)
	}
	if err := authz.RequireAuthorization(cfg.Authorization, cfg.Target); err != nil {
		return fmt.Errorf("inventory: %w: %w", ErrRefused, err)
	}
	if !cfg.Steps.Constructed() {
		return fmt.Errorf("inventory: %w: the login flow is not a sealed AuthSteps. "+
			"NewAuthSteps is the only constructor, and it refuses an empty list because "+
			"an empty list is autodetection under another name", ErrUnconstructed)
	}
	if !cfg.Screenshots.Recognised() {
		return fmt.Errorf("inventory: %w: the screenshot policy is %q and must be one of "+
			"%v. There is no default: storing a screenshot of a login form is the "+
			"permissive direction, and a Go zero value must never mean it",
			ErrRefused, redact(string(cfg.Screenshots)), ScreenshotPolicyValues())
	}
	if len(cfg.AliveStatuses) == 0 || len(cfg.AliveStatuses) > codedMaxAliveStatuses {
		return fmt.Errorf("inventory: %w: %d liveness statuses were configured and the "+
			"allowlist must hold 1..%d. There is no default, because a default would be "+
			"Anvil deciding what \"still logged in\" looks like for an application it "+
			"has never seen", ErrRefused, len(cfg.AliveStatuses), codedMaxAliveStatuses)
	}
	for i, s := range cfg.AliveStatuses {
		if s < minStatusCode || s > maxStatusCode {
			return fmt.Errorf("inventory: %w: liveness status %d is %d, which is not an "+
				"HTTP status", ErrRefused, i, s)
		}
	}
	if err := checkAuthPath(cfg, "login", cfg.LoginPath); err != nil {
		return err
	}
	if err := checkAuthPath(cfg, "liveness", cfg.LivenessPath); err != nil {
		return err
	}
	if cfg.LoginPath == cfg.LivenessPath {
		return fmt.Errorf("inventory: %w: the login path and the liveness path are both "+
			"%q. A liveness check against the login page answers 200 whether or not the "+
			"session exists, which reports every dead session as alive — the exact "+
			"failure this packet exists to detect", ErrRefused, redact(cfg.LoginPath))
	}
	if !authTechnique.Classified() || authTechnique.Destructive() {
		return fmt.Errorf("inventory: %w: the pinned auth technique %q is unclassified or "+
			"destructive under gate 15", ErrRefused, authTechnique)
	}
	return nil
}

// checkAuthPath runs one configured path through the kernel's own validation
// and gate 11's narrowing, before any request is built from it.
func checkAuthPath(cfg AuthConfig, what, path string) error {
	if path == "" {
		return fmt.Errorf("inventory: %w: no %s path was configured. There is no default: "+
			"Anvil guessing a login or session endpoint would submit a credential to a "+
			"path nobody chose", ErrRefused, what)
	}
	if err := kernelAcceptsPath(cfg.Target, authNavMethod, path); err != nil {
		return fmt.Errorf("inventory: %w: the %s path was rejected: %w", ErrRefused, what, err)
	}
	if !cfg.Scope.PermitsPath(cfg.Target.Canonical(), cfg.Target.Port(), path) {
		return fmt.Errorf("inventory: %w: Scope.PermitsPath refused the %s path %q: "+
			"either no allow entry covers this origin, or gate 11's narrowing removed "+
			"this path, or no robots determination covers the origin at all — which is "+
			"refused rather than assumed permissive",
			ErrRefused, what, redact(path))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// Session is one authentication attempt and everything that happened to it.
//
// A nil *Session answers false to Authenticated() and AuthStateUnset to
// State(). That is deliberate: `sess, err := AuthenticateAndMonitor(...)`
// followed by a caller that drops err still cannot produce an authenticated
// claim from a nil session.
type Session struct {
	cfg       AuthConfig
	state     AuthState
	startedAt time.Time
	events    []SessionEvent
	report    AuthReport
	emitted   []emittedCheck
	attempts  int
	verified  int
	failures  int
	relogins  int
	sealed    bool
}

// emittedCheck is one verdict about THE BYTES THAT ACTUALLY LEFT for the
// ArtifactSink, taken at the delivery boundary by Session.deliver.
//
// IT HOLDS NO BYTES. Only the kind, the step, the size, whether a credential
// was found and which one — which is Anvil's own configuration and not the
// secret. This is what makes AssertNoCredentialInLedger's "second look" a look
// at something the first look did not read.
type emittedCheck struct {
	kind   AuthArtifactKind
	step   int
	size   int
	secret int
	hit    bool
}

// Format renders a session for a log line, for every verb, WITHOUT reaching
// its configuration — which holds the step list, which holds the credentials.
func (s *Session) Format(f fmt.State, _ rune) {
	if s == nil {
		_, _ = f.Write([]byte("session(nil)"))
		return
	}
	_, _ = f.Write([]byte(fmt.Sprintf(
		"session(%s, %d attempt(s), %d verified, %d liveness failure(s), %d artifact(s))",
		s.state, s.attempts, s.verified, s.failures, s.report.Offered())))
}

// Constructed reports whether s came from this file.
func (s *Session) Constructed() bool { return s != nil && s.sealed }

// State is the session's CURRENT state. Nil answers AuthStateUnset.
func (s *Session) State() AuthState {
	if s == nil {
		return AuthStateUnset
	}
	return s.state
}

// Authenticated reports whether the session is, right now, one whose coverage
// may be called authenticated. Nil answers false.
func (s *Session) Authenticated() bool { return s.State().AuthenticatedCoverage() }

// StartedAt is the run-clock instant the session began.
func (s *Session) StartedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.startedAt
}

// Attempts is how many credential submissions this session made — the initial
// login plus every forced re-login. Bounded by codedMaxAuthAttempts.
func (s *Session) Attempts() int {
	if s == nil {
		return 0
	}
	return s.attempts
}

// Verifications is how many times Anvil OBSERVED the session alive.
func (s *Session) Verifications() int {
	if s == nil {
		return 0
	}
	return s.verified
}

// LivenessFailures is how many times Anvil observed it gone.
func (s *Session) LivenessFailures() int {
	if s == nil {
		return 0
	}
	return s.failures
}

// ReLogins is how many forced re-logins ran.
func (s *Session) ReLogins() int {
	if s == nil {
		return 0
	}
	return s.relogins
}

// Events returns a COPY of the session ledger, in order.
func (s *Session) Events() []SessionEvent {
	if s == nil {
		return nil
	}
	out := make([]SessionEvent, len(s.events))
	copy(out, s.events)
	return out
}

// Report returns the authentication report's ledger.
func (s *Session) Report() AuthReport {
	if s == nil {
		return AuthReport{}
	}
	return AuthReport{records: s.report.Records()}
}

// SourceRef names the manifest's auth.steps_ref this session's flow came from,
// or "" when there is no flow.
func (s *Session) SourceRef() string {
	if s == nil {
		return ""
	}
	return s.cfg.Steps.SourceRef()
}

// CoverageLabel is one sentence naming what coverage collected under this
// session means. It is the sentence a report writes instead of the word
// "authenticated".
//
// It is the label of the session's CURRENT state. A per-observation label —
// which is what a request that did not carry the session needs — comes from
// AuthState.CoverageMeaning applied to CoverageAt's answer.
func (s *Session) CoverageLabel() string { return s.State().CoverageMeaning() }

// CoverageMeaning is one sentence naming what coverage labelled with this
// state means. Every enumerated state has one, INCLUDING the states no window
// ever carries: AuthStateSessionNotCarried is produced by CoverageAt and by
// nothing else, and a state with no sentence would be reported as a bare
// enum literal by whoever consumed it.
func (st AuthState) CoverageMeaning() string {
	switch st {
	case AuthStateAuthenticated:
		return "authenticated: Anvil observed the session alive through the kernel, so " +
			"coverage collected inside a bracketed window includes surface behind the login"
	case AuthStateAuthenticationFailed:
		return "PUBLIC SURFACE ONLY: authentication was configured and did not succeed, so " +
			"everything behind the login is missing from this run's coverage and the " +
			"denominator is smaller than the application"
	case AuthStateUnauthenticated:
		return "public surface: no authentication was configured for this target, so " +
			"coverage is of the unauthenticated application"
	case AuthStateUnverified:
		return "UNVERIFIED: the session was alive at the start of this stretch and gone by " +
			"the end, so coverage collected in it is neither authenticated nor public"
	case AuthStateSessionLost:
		return "SESSION LOST: the session was lost mid-scan and no re-login restored it, so " +
			"coverage after that point is the public surface"
	case AuthStateSessionNotCarried:
		return "public surface: the session was alive and the requests did not carry it, so " +
			"this coverage is of the unauthenticated application. A request issued while a " +
			"session happened to be alive is not an authenticated request"
	default:
		return "unknown: no session state was recorded, which is never read as authenticated"
	}
}

// note appends one ledger row. detail is swept against this session's
// credentials and then redacted, in that order — see sanitizeForLedger.
func (s *Session) note(kind SessionEventKind, at time.Time, seq authz.AuditSeq,
	status int, detail string) {

	s.events = append(s.events, SessionEvent{
		kind:   kind,
		at:     at,
		seq:    seq,
		status: status,
		detail: sanitizeForLedger(detail, s.cfg.Steps.secrets()),
	})
}

// ---------------------------------------------------------------------------
// Windows — the partition StateAt is total over
// ---------------------------------------------------------------------------

// Windows returns the run timeline as contiguous, non-overlapping windows.
//
// It is computed from the event ledger every time rather than maintained
// incrementally, for one reason: a window's state is not knowable when it
// opens. A stretch that begins at a passed liveness check is provisionally
// authenticated and is DOWNGRADED to AuthStateUnverified if the next liveness
// event is a failure — the session died somewhere inside it. Only a stretch
// bracketed by two passes keeps AuthStateAuthenticated.
func (s *Session) Windows() []AuthWindow {
	if s == nil || !s.sealed {
		return nil
	}
	cur := AuthWindow{from: s.startedAt, state: AuthStateUnauthenticated}
	var out []AuthWindow
	closeInto := func(at time.Time, verifiedEnd bool) {
		cur.to = at
		cur.verifiedEnd = verifiedEnd
		out = append(out, cur)
	}
	for _, e := range s.events {
		switch e.kind {
		case SessionEventVerified:
			closeInto(e.at, true)
			cur = AuthWindow{from: e.at, state: AuthStateAuthenticated, verifiedStart: true}
		case SessionEventLivenessFailed:
			if cur.verifiedStart {
				// The downgrade. It was alive when this window opened and it
				// is gone now; nothing observed the moment in between.
				cur.state = AuthStateUnverified
			}
			closeInto(e.at, false)
			cur = AuthWindow{from: e.at, state: AuthStateSessionLost}
		case SessionEventLoginFailed, SessionEventLoginRefusedByKernel:
			if cur.verifiedStart {
				cur.state = AuthStateUnverified
			}
			closeInto(e.at, false)
			cur = AuthWindow{from: e.at, state: AuthStateAuthenticationFailed}
		case SessionEventReLoginFailed, SessionEventAttemptsExhausted:
			closeInto(e.at, false)
			cur = AuthWindow{from: e.at, state: AuthStateSessionLost}
		}
	}
	return append(out, cur)
}

// StateAt maps one instant to exactly one AuthState.
//
// An instant BEFORE the session started answers AuthStateUnauthenticated: at
// that point no login had run, which is the truthful label and also the
// fail-closed one.
func (s *Session) StateAt(t time.Time) AuthState {
	if s == nil {
		return AuthStateUnset
	}
	ws := s.Windows()
	if len(ws) == 0 || t.Before(ws[0].from) {
		return AuthStateUnauthenticated
	}
	for _, w := range ws {
		if w.Contains(t) {
			return w.state
		}
	}
	return AuthStateUnset
}

// CoverageInstant is ONE MEASURED OBSERVATION, as the thing that labels it
// needs to see it: when it happened, AND whether the request that made it
// carried this session.
//
// # Why the second field exists
//
// StateAt answers a question about the SESSION — was it alive at this instant.
// D.26 was reading that answer as a question about the REQUEST — was this
// visit authenticated — and those are different claims joined by nothing but
// wall-clock overlap. A crawl request issued while a session happened to be
// alive is not an authenticated request; it is a request that happened at the
// same time as one.
//
// # It is false today for every crawl visit, and that is the finding
//
// Nothing in this module can attach a session to a crawl request: CrawlConfig
// carries no cookie jar, CrawlRequest has no header, cookie or credential
// field, and ClientSpider is handed neither. CoverageOfVisit therefore returns
// CarriedSession false for every CrawlVisit, and says so at its declaration.
// TestNoCrawlRequestCanCarryASession holds that shut: a field that could carry
// one turns this claim red rather than quietly making it obsolete.
//
// The zero value is false, which is the fail-closed direction.
//
// # The bool alone is a CLAIM, and a claim is not evidence
//
// CarriedSession is exported, has no constructor and widens a coverage label,
// so on its own it is a guard made of prose: a caller writing
// `CoverageInstant{At: t, CarriedSession: true}` moved an observation out of
// AuthStateSessionNotCarried and into AuthStateAuthenticated, and nothing
// anywhere disagreed. This package already knows the answer to that shape —
// Secret, AuthSteps, AuthRequest, StoredArtifact and Session are all SEALED,
// unforgeable outside their constructors — so a coverage instant is too. The
// bool is the claim; the unexported carriage below is the evidence, minted only
// by Session.Carried, and COVERAGE COUNTS ONLY WHEN BOTH ARE PRESENT AND THE
// EVIDENCE BELONGS TO THE SESSION DOING THE LABELLING.
type CoverageInstant struct {
	// At is when the observation was made.
	At time.Time
	// CarriedSession is the CLAIM that this particular request went out under
	// the session — a session cookie or header actually attached to it, not a
	// session that was alive somewhere else at the time. A caller that cannot
	// show that leaves this false.
	//
	// SETTING IT IN A STRUCT LITERAL IS NOT ENOUGH and never widens anything:
	// without the seal Session.Carried applies, CoverageAt reads the instant as
	// AuthStateSessionNotCarried, which is what "nobody demonstrated carriage"
	// honestly means.
	CarriedSession bool
	// carriage is the seal. Unexported, so no literal outside this package can
	// produce one, and bound to the session it was minted from.
	carriage sessionCarriage
}

// sessionCarriage is the evidence that one request went out under one session.
//
// WHAT IT PROVES AND WHAT IT DOES NOT, stated rather than implied. It makes the
// carriage claim UNMAKEABLE BY A STRUCT LITERAL and NON-TRANSFERABLE between
// sessions — both are compiler- and code-enforced, and both are measured by
// TestAnUnsealedCarriageClaimIsNotCoverage. It does not make the claim
// true: Session.Carried takes the caller's word for the mechanism, because
// nothing in this module can attach a session to a crawl request yet (see
// CoverageOfVisit). What the seal buys is that when such a producer exists,
// there is exactly ONE function for it to be checked in, and until then the
// only values in existence name where they came from.
type sessionCarriage struct {
	sealed bool
	// owner is the session this evidence is about. Evidence about one session
	// cannot label an observation of another.
	owner *Session
	// how names the mechanism that attached the session, for the report. It
	// has been through sanitizeForLedger, because it is caller-authored text
	// that CarriageEvidence renders back out.
	how string
}

// Carried is the ONE constructor for an observation that claims carriage.
//
// how must name the mechanism — the cookie jar, the header, the field — and an
// empty one mints nothing, because a claim that cannot say how is the zero
// value with extra steps. A nil or unsealed Session mints nothing either.
//
// how IS SWEPT, NOT MERELY REDACTED. It is a caller-authored string that
// CarriageEvidence renders back out of this package, which makes it the same
// kind of channel as an artifact name or a driver's Detail — and redact() alone
// cannot protect a credential whose spelling is innocent, which is this file's
// first paragraph. A mechanism that names the credential is refused whole.
func (s *Session) Carried(at time.Time, how string) CoverageInstant {
	c := CoverageInstant{At: at}
	if s == nil || !s.sealed || strings.TrimSpace(how) == "" {
		return c
	}
	c.CarriedSession = true
	c.carriage = sessionCarriage{
		sealed: true, owner: s, how: sanitizeForLedger(how, s.cfg.Steps.secrets()),
	}
	return c
}

// CarriageEvidence returns the mechanism this observation named, or "" when it
// carries no evidence. It is how a report can say WHY an instant counted.
func (c CoverageInstant) CarriageEvidence() string { return c.carriage.how }

// carriedFor reports whether this observation carries evidence, sealed by and
// belonging to s, that its request went out under the session.
//
// Every clause is fail-closed: an unsealed instant, an instant sealed by a
// different session, and an instant whose bool was set without the seal all
// answer false.
func (c CoverageInstant) carriedFor(s *Session) bool {
	return c.CarriedSession && c.carriage.sealed && c.carriage.owner == s && s != nil
}

// CoverageAt maps one observation to exactly one AuthState.
//
// The session's state at that instant is a CEILING, not the answer: a request
// that did not carry the session is never authenticated coverage no matter how
// healthy the session was, and a request that did carry it is still only as
// good as the window it landed in.
func (s *Session) CoverageAt(c CoverageInstant) AuthState {
	st := s.StateAt(c.At)
	if st == AuthStateAuthenticated && !c.carriedFor(s) {
		return AuthStateSessionNotCarried
	}
	return st
}

// PartitionByState counts observations by the state each maps to. It is the
// shape D.26 needs: a crawl's visits in, a labelled breakdown out.
func (s *Session) PartitionByState(instants []CoverageInstant) map[AuthState]int {
	out := map[AuthState]int{}
	for _, c := range instants {
		out[s.CoverageAt(c)]++
	}
	return out
}

// AssertAllAuthenticated returns an error naming HOW MANY observations are not
// authenticated coverage, and in which states.
//
// It asserts the COUNT rather than the existence of an authenticated window: a
// run whose first request landed in an authenticated window and whose other
// four hundred did not is exactly the shape this is written against.
func (s *Session) AssertAllAuthenticated(instants []CoverageInstant) error {
	mix := s.PartitionByState(instants)
	bad := 0
	var parts []string
	for _, st := range append([]AuthState{AuthStateUnset}, AuthStateValues()...) {
		if st.AuthenticatedCoverage() {
			continue
		}
		if n := mix[st]; n > 0 {
			bad += n
			parts = append(parts, fmt.Sprintf("%s: %d", st, n))
		}
	}
	if bad == 0 {
		return nil
	}
	// A caller that set the bool without the seal gets told so by name. The
	// downgrade is fail-closed either way, but an unattested claim is a
	// DIFFERENT mistake from an honest false, and silently treating them alike
	// is how the next reader concludes the bool works.
	unattested := 0
	for _, c := range instants {
		if c.CarriedSession && !c.carriedFor(s) {
			unattested++
		}
	}
	claims := ""
	if unattested > 0 {
		claims = fmt.Sprintf(" %d of them CLAIMED carriage with no evidence this session "+
			"sealed (CoverageInstant.CarriedSession set in a literal rather than by "+
			"Session.Carried), and were counted as not carried.", unattested)
	}
	return fmt.Errorf("%w: %d of %d instant(s) are not authenticated coverage (%s).%s %s",
		ErrCoverageIsNotAuthenticated, bad, len(instants), strings.Join(parts, ", "),
		claims, s.CoverageLabel())
}

// AssertNoCredentialInLedger reports on BOTH of the places a credential could
// have escaped, and it is explicit about which half of it is independent.
//
//	THE EMITTED BYTES — INDEPENDENT. Session.deliver read StoredArtifact
//	.Bytes(), the exact value the sink itself reads, through the exact
//	accessor the sink reads it through, AFTER the decision path had chosen it
//	and copied it. That is a different source from the one the decision read,
//	which is the whole point: a refactor that swept one field and stored
//	another passes the decision and fails here. The verdicts are recorded at
//	delivery and reported here.
//
//	THE RENDERED LEDGER — NOT INDEPENDENT, AND SAID SO. The walk below
//	re-derives the sweep over the strings note() and the artifact path already
//	sanitized. It reads the same values through the same matcher, so it cannot
//	catch a matcher that is wrong; what it catches is a RENDERING that
//	reassembles a credential out of fields each of which was clean alone —
//	SessionEvent.String() and ArtifactRecord.String() are both searched as
//	rendered, which is where that would show. Two dependent looks are one
//	look, and this half is the second look at the same thing.
//
// It never names the credential and never returns it.
func (s *Session) AssertNoCredentialInLedger() error {
	if s == nil {
		return nil
	}
	secrets := s.cfg.Steps.secrets()
	if len(secrets) == 0 {
		return nil
	}
	// The independent half, first: it is the one that can see damage the
	// decision path could not.
	for i, e := range s.emitted {
		if e.hit {
			return fmt.Errorf("%w: the credential from step-secret %d was in the bytes "+
				"handed to the ArtifactSink for delivery %d (%s, step %d, %d bytes). The "+
				"offending bytes are NOT reproduced here", ErrCredentialInArtifact,
				e.secret+1, i+1, e.kind, e.step, e.size)
		}
	}
	check := func(where, text string) error {
		if i, hit := credentialIn([]byte(text), secrets); hit {
			return fmt.Errorf("%w: the credential from step-secret %d appears in %s. The "+
				"offending text is NOT reproduced here", ErrCredentialInArtifact, i+1, where)
		}
		return nil
	}
	for i, e := range s.events {
		if err := check(fmt.Sprintf("session event %d (%s)", i+1, e.kind), e.detail); err != nil {
			return err
		}
		if err := check(fmt.Sprintf("session event %d rendered", i+1), e.String()); err != nil {
			return err
		}
	}
	for i, r := range s.report.records {
		if err := check(fmt.Sprintf("artifact record %d rendered", i+1), r.String()); err != nil {
			return err
		}
	}
	if err := check("the coverage label", s.CoverageLabel()); err != nil {
		return err
	}
	return check("the session rendering", fmt.Sprintf("%v %s", s, s.SourceRef()))
}

// AssertReportRetained returns an error when a login ran and NOTHING of its
// authentication report was stored.
//
// plan/50-dast.md D.24 requires every run to store the report. A run that
// stored nothing is not automatically a defect — every artifact may have been
// a suppressed screenshot — so this names which it was rather than passing on
// len(x) > 0.
func (s *Session) AssertReportRetained() error {
	if s == nil || !s.sealed {
		return fmt.Errorf("inventory: %w: no session, so no authentication report",
			ErrUnconstructed)
	}
	if s.attempts == 0 {
		return nil
	}
	if s.report.Offered() == 0 {
		return fmt.Errorf("inventory: %w: %d credential submission(s) ran and the driver "+
			"produced NO report artifact. D.24 requires screenshots, HTTP and storage on "+
			"every run: a login nobody can diagnose is the shape research/22's Risk #7 "+
			"takes", ErrRefused, s.attempts)
	}
	if s.report.StoredCount() == 0 {
		return fmt.Errorf("inventory: %w: %d artifact(s) were offered and none was "+
			"stored. Disposition mix: %v", ErrRefused, s.report.Offered(),
			s.report.DispositionMix())
	}
	return nil
}

// ---------------------------------------------------------------------------
// UnauthenticatedSession
// ---------------------------------------------------------------------------

// UnauthenticatedSession is how a caller records, on the ledger, that this
// target declares NO authentication.
//
// It exists so that "no auth section in the manifest" and "auth was configured
// and failed" are different values rather than the same nil. Both produce
// unauthenticated coverage; only the second means the scan is missing the
// application's interior, and a report that cannot tell them apart cannot say
// so.
func UnauthenticatedSession(now authz.Clock) *Session {
	return &Session{
		state:     AuthStateUnauthenticated,
		startedAt: now.Instant(),
		sealed:    true,
		events: []SessionEvent{{
			kind: SessionEventNoAuthConfigured,
			at:   now.Instant(),
			detail: "no auth section is declared for this target, so no login was " +
				"attempted and coverage is of the public surface",
		}},
	}
}

// ---------------------------------------------------------------------------
// AuthenticateAndMonitor
// ---------------------------------------------------------------------------

// AuthenticateAndMonitor is D.24: run the explicit login flow, store the
// authentication report, and OBSERVE the resulting session through the kernel.
//
// # Signature
//
// plan/50-dast.md D.24 writes it `AuthenticateAndMonitor(target *Target, steps
// AuthSteps) (*Session, error)`. There is no `*Target` in this package — the
// kernel's authz.Target is the type, and it is one of a dozen things an
// authenticated request needs — so the target, the steps and the kernel
// objects arrive in an AuthConfig, exactly as D.18's Config, D.22's
// ConfirmConfig and D.23's CrawlConfig do. The ctx and the run clock are
// explicit for the same reason CrawlWithClientSpider's are.
//
// # It returns a Session AND an error together, on failure
//
// That is unusual and it is the point. A caller that drops the error still
// holds a value whose Authenticated() is false, whose State() is
// AuthStateAuthenticationFailed and whose CoverageLabel() says PUBLIC SURFACE
// ONLY. There is no shape of this API in which a failed login and a successful
// crawl combine into an authenticated result.
//
// # Order
//
//	1 validate; refuse rather than degrade
//	2 admit the login NAVIGATION (GET) through the kernel
//	3 admit the credential SUBMISSION (POST) through the kernel — gate 15
//	  refuses this one unless an operator put it on the EndpointAllowance
//	4 only now does anything leave, and it leaves through AuthDriver
//	5 ObserveResponse on both leases; gates 16 and 17 see the login too
//	6 STORE THE REPORT — always, on success and on failure alike, because a
//	  login that failed is the one somebody needs the screenshots for
//	7 the driver's claim is recorded and NOT believed
//	8 CheckLiveness: Anvil's own observation, through the kernel. Only this
//	  produces AuthStateAuthenticated.
func AuthenticateAndMonitor(ctx context.Context, cfg AuthConfig, now authz.Clock) (*Session, error) {
	s := &Session{
		cfg:       cfg,
		state:     AuthStateUnauthenticated,
		startedAt: now.Instant(),
		sealed:    true,
	}
	if err := validateAuthConfig(cfg); err != nil {
		s.state = AuthStateAuthenticationFailed
		s.note(SessionEventLoginFailed, now.Instant(), 0, 0,
			"the authentication configuration was refused before any request was built: "+
				errText(err))
		return s, fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	if err := s.login(ctx, now, false); err != nil {
		return s, err
	}
	return s, nil
}

// login runs one credential submission and then verifies it.
func (s *Session) login(ctx context.Context, now authz.Clock, forced bool) error {
	if s.attempts >= codedMaxAuthAttempts {
		at := s.clockFor(now)
		s.state = AuthStateSessionLost
		s.note(SessionEventAttemptsExhausted, at.Instant(), 0, 0, fmt.Sprintf(
			"this session has already submitted credentials %d times, which is the coded "+
				"bound. An unbounded retry loop against a target that keeps refusing is "+
				"gate 15's denylisted authentication_lockout_sequence, and Anvil must not "+
				"reach it through its own recovery path", s.attempts))
		return fmt.Errorf("%w: the credential-submission budget of %d was exhausted",
			ErrAuthFailed, codedMaxAuthAttempts)
	}

	if s.cfg.Driver == nil {
		at := s.clockFor(now)
		s.state = AuthStateAuthenticationFailed
		s.note(SessionEventLoginFailed, at.Instant(), 0, 0,
			"no AuthDriver is wired, so no login was attempted. This is a fact about "+
				"Anvil: any crawl that follows covers the PUBLIC surface only")
		return fmt.Errorf("%w: %w", ErrAuthFailed, ErrNoAuthDriver)
	}

	s.attempts++
	at := s.clockFor(now)
	s.note(SessionEventLoginAttempted, at.Instant(), 0, 0, fmt.Sprintf(
		"attempt %d of %d, %d step(s) from %s, forced=%v",
		s.attempts, codedMaxAuthAttempts, s.cfg.Steps.Len(), redact(s.cfg.Steps.SourceRef()),
		forced))

	// Step 2: the navigation. A safe method; gate 15 needs no allowance.
	navLease, navSeq, err := s.admit(authNavMethod, s.cfg.LoginPath, at)
	if err != nil {
		s.state = AuthStateAuthenticationFailed
		s.note(SessionEventLoginRefusedByKernel, at.Instant(), 0, 0,
			"the kernel refused the login NAVIGATION: "+errText(err))
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}

	// Step 3: the submission. A state-changing method, so gate 15 refuses it
	// unless POST <login path> is on the Governor's EndpointAllowance — which
	// is an operator naming this endpoint on purpose before Anvil will ever
	// send a credential to it.
	subAt := s.clockFor(now)
	subLease, subSeq, err := s.admit(authSubmitMethod, s.cfg.LoginPath, subAt)
	if err != nil {
		// The navigation lease is still held. Release it as a connection
		// error: nothing was issued on it, and a leaked lease would spend
		// gate 14's concurrency slot for the rest of the run.
		s.release(navLease, at, 0, 0, false)
		s.state = AuthStateAuthenticationFailed
		s.note(SessionEventLoginRefusedByKernel, subAt.Instant(), navSeq, 0,
			"the kernel refused the credential SUBMISSION: "+errText(err))
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}

	req := AuthRequest{
		auth:      s.cfg.Authorization,
		target:    s.cfg.Target,
		method:    authSubmitMethod,
		path:      s.cfg.LoginPath,
		technique: authTechnique,
		navSeq:    navSeq,
		submitSeq: subSeq,
		steps:     s.cfg.Steps,
		sealed:    true,
	}

	// Step 4: the only thing that leaves the process.
	outcome, derr := s.cfg.Driver.Authenticate(ctx, req)

	// Step 5. Both leases are released exactly once, whatever happened.
	if derr != nil {
		s.release(navLease, at, 0, 0, false)
		s.release(subLease, subAt, 0, 0, false)
	} else {
		s.release(navLease, at, outcome.NavStatus, outcome.NavLatency,
			isHTTPStatus(outcome.NavStatus))
		s.release(subLease, subAt, outcome.SubmitStatus, outcome.SubmitLatency,
			isHTTPStatus(outcome.SubmitStatus))
	}

	// Step 6. THE REPORT IS STORED ON FAILURE TOO. A login that failed is the
	// one somebody needs the screenshots for.
	s.storeArtifacts(ctx, outcome.Artifacts, subAt)

	if derr != nil {
		s.state = AuthStateAuthenticationFailed
		// The driver's error text touched the credential path, so it is swept
		// before it reaches the ledger, exactly like its Detail.
		s.note(SessionEventLoginFailed, subAt.Instant(), subSeq, 0,
			"the AuthDriver returned an error: "+s.sweep(errText(derr)))
		return fmt.Errorf("%w: the AuthDriver failed", ErrAuthFailed)
	}
	if !isHTTPStatus(outcome.SubmitStatus) {
		s.state = AuthStateAuthenticationFailed
		s.note(SessionEventLoginFailed, subAt.Instant(), subSeq, 0, fmt.Sprintf(
			"the driver reported submission status %d, which is not an HTTP status. A "+
				"value that is not an answer is never read as one", outcome.SubmitStatus))
		return fmt.Errorf("%w: the driver returned a submission status that is not an "+
			"HTTP status", ErrAuthFailed)
	}
	if !outcome.SessionEstablished {
		s.state = AuthStateAuthenticationFailed
		s.note(SessionEventLoginFailed, subAt.Instant(), subSeq, outcome.SubmitStatus,
			fmt.Sprintf("the driver reports no session (failed at step %d of %d, landed "+
				"on %s): %s", outcome.FailedAtStep, s.cfg.Steps.Len(),
				s.sweep(outcome.LandedPath), s.sweep(outcome.Detail)))
		return fmt.Errorf("%w: the driver established no session", ErrAuthFailed)
	}

	// Step 7. The claim, recorded and not believed.
	s.note(SessionEventLoginClaimed, subAt.Instant(), subSeq, outcome.SubmitStatus,
		fmt.Sprintf("the driver claims a session (landed on %s): %s. A claim is not an "+
			"observation; the state does not change until CheckLiveness says so",
			s.sweep(outcome.LandedPath), s.sweep(outcome.Detail)))

	// Step 8. ANVIL'S OWN OBSERVATION.
	alive, lerr := CheckLiveness(ctx, s, now)
	if lerr != nil || !alive {
		s.state = AuthStateAuthenticationFailed
		if forced {
			s.note(SessionEventReLoginFailed, s.lastEventAt(subAt.Instant()), subSeq, 0,
				"the forced re-login's session could not be observed alive")
		}
		return fmt.Errorf("%w: the driver claimed a session and Anvil could not observe "+
			"one through the kernel", ErrAuthFailed)
	}
	s.state = AuthStateAuthenticated
	if forced {
		s.relogins++
		s.note(SessionEventReLoginSucceeded, s.lastEventAt(subAt.Instant()), subSeq, 0,
			"the forced re-login produced a session Anvil observed alive")
	}
	return nil
}

func (s *Session) lastEventAt(fallback time.Time) time.Time {
	if len(s.events) == 0 {
		return fallback
	}
	return s.events[len(s.events)-1].at
}

// admit runs one request through NewRequestIntent, RequireAuthorization and
// GateAudit.AuditedAdmit — the same three calls D.22's probeOne and D.23's
// crawlOne make, in the same order.
func (s *Session) admit(method authz.Method, path string, at authz.Clock) (
	*authz.Lease, authz.AuditSeq, error) {

	intent, err := authz.NewRequestIntent(authz.RequestFacts{
		Origin:   authz.OriginInitial,
		Admitted: s.cfg.Target,
		Next:     s.cfg.Target,
		Method:   method,
		Path:     path,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("inventory: %w: %s %s is not a valid request intent: %w",
			ErrRefused, method, redact(path), err)
	}
	// Gate 3's runtime half, at the moment a socket could be constructed.
	if err := authz.RequireAuthorization(s.cfg.Authorization, s.cfg.Target); err != nil {
		return nil, 0, fmt.Errorf("inventory: %w: %w", ErrRefused, err)
	}
	lease, res := s.cfg.Audit.AuditedAdmit(s.cfg.Governor, intent, authTechnique, at)
	if !res.Passed() {
		return nil, 0, fmt.Errorf("inventory: %w: the kernel refused %s %s at %s: %s",
			ErrRefused, method, redact(path), res.Gate(), redact(errText(res.Err())))
	}
	return lease, s.cfg.Audit.LastSeq(), nil
}

// release ends one lease exactly once. A lease that is never released spends
// gate 14's concurrency slot for the rest of the run, which would show up much
// later as a target that mysteriously stops being probed.
func (s *Session) release(lease *authz.Lease, at authz.Clock, status int,
	latency time.Duration, answered bool) {

	if lease == nil {
		return
	}
	var res authz.GateResult
	if answered {
		res = s.cfg.Governor.ObserveResponse(lease, status, latency, nil, at)
	} else {
		res = s.cfg.Governor.ObserveConnectionError(lease, at)
	}
	s.cfg.Audit.AuditedObservation(res, s.cfg.Target, at)
}

func (s *Session) clockFor(now authz.Clock) authz.Clock {
	if s.cfg.Clock == nil {
		return now
	}
	return s.cfg.Clock.NextInstant()
}

func isHTTPStatus(code int) bool { return code >= minStatusCode && code <= maxStatusCode }

// ---------------------------------------------------------------------------
// CheckLiveness
// ---------------------------------------------------------------------------

// CheckLiveness asks the target whether the session is still alive, through
// the kernel.
//
// # Signature
//
// plan/50-dast.md D.24 writes it `CheckLiveness(session *Session) (bool,
// error)`. The ctx and the run clock are explicit here for the reason
// CrawlWithClientSpider's are: a request that leaves the process needs a
// cancellation and an instant gate 14 can meter against, and reading either
// from ambient state would make the kernel's rate decision disagree with the
// request it was made about.
//
// # It is FAIL CLOSED in every direction
//
// A nil session, an unconstructed one, a driver error, a status that is not an
// HTTP status, a status outside the configured allowlist, a redirect back to
// the login path, and a driver reporting that the session cookie is gone all
// return false. There is no path through this function on which an
// unanswerable question becomes "alive".
//
// D.24 forbids relying on ZAP's logout-avoidance option as a substitute for
// this: research 22 records that it does not cover the Client Spider, so the
// component that would keep the session alive is not the component the crawl
// runs through.
func CheckLiveness(ctx context.Context, s *Session, now authz.Clock) (bool, error) {
	if s == nil || !s.sealed {
		return false, fmt.Errorf("inventory: %w: liveness was asked about a session "+
			"nothing constructed", ErrUnconstructed)
	}
	if !s.cfg.Constructed() {
		return false, fmt.Errorf("inventory: %w: liveness was asked about a session whose "+
			"configuration is not usable, so no probe could be admitted", ErrUnconstructed)
	}
	if s.cfg.Driver == nil {
		s.failures++
		at := s.clockFor(now)
		s.note(SessionEventLivenessFailed, at.Instant(), 0, 0,
			"no AuthDriver is wired, so the session could not be observed. An "+
				"unobservable session is never read as a live one")
		return false, fmt.Errorf("%w: %w", ErrSessionLost, ErrNoAuthDriver)
	}

	at := s.clockFor(now)
	lease, seq, err := s.admit(authLivenessMethod, s.cfg.LivenessPath, at)
	if err != nil {
		s.failures++
		s.note(SessionEventLivenessFailed, at.Instant(), 0, 0,
			"the kernel refused the liveness probe: "+errText(err))
		return false, fmt.Errorf("%w: %w", ErrSessionLost, err)
	}

	req := AuthRequest{
		auth:      s.cfg.Authorization,
		target:    s.cfg.Target,
		method:    authLivenessMethod,
		path:      s.cfg.LivenessPath,
		technique: authTechnique,
		sealed:    true,
		// steps is deliberately the ZERO AuthSteps: a liveness check needs
		// the session, never the credential, so the driver is not handed one.
	}
	probe, perr := s.cfg.Driver.ProbeSession(ctx, req)
	if perr != nil {
		s.release(lease, at, 0, 0, false)
		s.failures++
		s.note(SessionEventLivenessFailed, at.Instant(), seq, 0,
			"the AuthDriver's session probe returned an error: "+s.sweep(errText(perr)))
		return false, fmt.Errorf("%w: the session probe failed", ErrSessionLost)
	}
	if !isHTTPStatus(probe.Status) {
		s.release(lease, at, 0, 0, false)
		s.failures++
		s.note(SessionEventLivenessFailed, at.Instant(), seq, 0, fmt.Sprintf(
			"the probe returned status %d, which is not an HTTP status and is never read "+
				"as an answer", probe.Status))
		return false, fmt.Errorf("%w: the session probe returned no answer", ErrSessionLost)
	}
	s.release(lease, at, probe.Status, probe.Latency, true)

	if reason, dead := s.deadSessionReason(probe); dead {
		s.failures++
		s.note(SessionEventLivenessFailed, at.Instant(), seq, probe.Status, reason)
		return false, nil
	}
	s.verified++
	s.note(SessionEventVerified, at.Instant(), seq, probe.Status, fmt.Sprintf(
		"status %d is on the configured liveness allowlist %v, the session store still "+
			"holds a session, and the response did not bounce to the login path",
		probe.Status, s.cfg.AliveStatuses))
	return true, nil
}

// deadSessionReason applies the liveness rules in order and names the FIRST
// one that failed. Every rule's failure direction is "dead".
func (s *Session) deadSessionReason(p AuthProbe) (string, bool) {
	if !p.SessionPresent {
		return "the driver reports that the session cookie or storage entry is gone", true
	}
	allowed := false
	for _, code := range s.cfg.AliveStatuses {
		if code == p.Status {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Sprintf("status %d is not on the configured liveness allowlist %v. The "+
			"allowlist is matched by identity: a status nobody enumerated is a dead "+
			"session, not an unknown one", p.Status, s.cfg.AliveStatuses), true
	}
	if p.Status >= 300 && p.Status < 400 {
		if s.bouncesToLogin(p.Location) {
			return fmt.Sprintf("status %d redirects back to the login path, which is the "+
				"classic silent logout: the application answered, so a status check "+
				"alone would have called this alive", p.Status), true
		}
	}
	return "", false
}

// bouncesToLogin reports whether a Location header points at the login path.
//
// It resolves the header the same way the crawl resolves an href — through
// resolveLinkPath, which uses the KERNEL's canonicalization — so this file
// holds no second opinion about what two addresses being equal means. A
// Location that will not resolve at all counts as a bounce: an unreadable
// redirect is not evidence the session survived.
func (s *Session) bouncesToLogin(location string) bool {
	if strings.TrimSpace(location) == "" {
		return false
	}
	p, err := resolveLinkPath(s.cfg.Target, s.cfg.LivenessPath, location)
	if err != nil {
		return true
	}
	return stripQuery(p) == stripQuery(s.cfg.LoginPath)
}

// ---------------------------------------------------------------------------
// EnsureSessionBeforePhase
// ---------------------------------------------------------------------------

// EnsureSessionBeforePhase is the between-phases call D.24 specifies: check
// liveness, and force AuthenticateAndMonitor's login again on failure.
//
// It is the ONLY thing that turns a mid-scan logout into a recovered session,
// and it is bounded: codedMaxAuthAttempts caps the total credential
// submissions this session may make, for the reason in this file's header.
//
// On an unrecoverable loss the session's state is AuthStateSessionLost and the
// window that was open is closed — so a phase that runs after this returns an
// error is recorded as unauthenticated coverage, not as a gap.
func EnsureSessionBeforePhase(ctx context.Context, s *Session, now authz.Clock) error {
	if s == nil || !s.sealed {
		return fmt.Errorf("inventory: %w: no session, so nothing can be ensured before "+
			"the next phase", ErrUnconstructed)
	}
	alive, err := CheckLiveness(ctx, s, now)
	if alive && err == nil {
		return nil
	}
	at := s.clockFor(now)
	s.state = AuthStateSessionLost
	s.note(SessionEventReLoginForced, at.Instant(), 0, 0, fmt.Sprintf(
		"liveness failed before the next scan phase (%d failure(s) so far), so a fresh "+
			"login is forced. The probes issued between the last verification and this "+
			"one are UNVERIFIED coverage: the session was alive at the start of that "+
			"window and gone by its end", s.failures))

	if lerr := s.login(ctx, now, true); lerr != nil {
		s.state = AuthStateSessionLost
		return fmt.Errorf("%w: %w", ErrSessionLost, lerr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The report path
// ---------------------------------------------------------------------------

// storeArtifacts runs every artifact through the rules and the sweep, and
// records what became of it. NOTHING is dropped silently.
func (s *Session) storeArtifacts(ctx context.Context, arts []AuthArtifact, at authz.Clock) {
	secrets := s.cfg.Steps.secrets()
	for _, a := range arts {
		rec := ArtifactRecord{
			kind: a.Kind,
			step: a.Step,
			name: sanitizeForLedger(a.Name, secrets),
			size: len(a.Bytes),
		}
		switch {
		case len(s.report.records) >= codedMaxArtifacts:
			rec.disposition = ArtifactRefusedBudget
			rec.detail = fmt.Sprintf("the coded artifact bound of %d was reached",
				codedMaxArtifacts)
		case !a.Kind.Recognised():
			rec.disposition = ArtifactRefusedUnrecognisedKind
			rec.detail = fmt.Sprintf("kind %q is on none of %v, so no rule about storing "+
				"it exists and it is refused rather than stored under a default",
				sanitizeForLedger(string(a.Kind), secrets), AuthArtifactKindValues())
		case len(a.Bytes) > codedMaxArtifactBytes:
			rec.disposition = ArtifactRefusedTooLarge
			rec.detail = fmt.Sprintf("%d bytes exceeds the coded bound of %d",
				len(a.Bytes), codedMaxArtifactBytes)
		case a.Kind == AuthArtifactScreenshot && !s.screenshotAllowed(a):
			rec.disposition, rec.detail = s.screenshotRefusal(a)
		case s.credentialWasInFlight(a):
			// THE CONTROL. It reads no bytes, so no spelling defeats it.
			rec.disposition = ArtifactSuppressedCredentialStep
			rec.detail = s.inFlightRefusal(a)
		default:
			if i, hit := credentialIn(a.Bytes, secrets); hit {
				rec.disposition = ArtifactRefusedCredentialFound
				rec.detail = fmt.Sprintf("the credential from step-secret %d appears in "+
					"these bytes, which belong to a step that types no credential. The "+
					"whole artifact is refused rather than rewritten: a partial rewrite "+
					"has to anticipate every encoding and refusing does not. THIS IS A "+
					"DEFECT IN THE DRIVER", i+1)
			} else if s.cfg.Sink == nil {
				rec.disposition = ArtifactRefusedNoSink
				rec.detail = "no ArtifactSink is wired, so the authentication report was " +
					"not retained. A report nobody kept and a login that produced no " +
					"artifacts are different findings"
			} else {
				stored := StoredArtifact{
					kind:   a.Kind,
					step:   a.Step,
					name:   rec.name,
					bytes:  append([]byte(nil), a.Bytes...),
					sealed: true,
				}
				switch err := s.deliver(ctx, stored, secrets); {
				case errors.Is(err, ErrCredentialInArtifact):
					rec.disposition = ArtifactRefusedCredentialFound
					rec.detail = "the bytes the sink was about to receive contained a " +
						"credential, which the decision path above did not see. The sink " +
						"was never called. THIS IS A DEFECT IN THIS FILE, not in the driver"
				case err != nil:
					rec.disposition = ArtifactRefusedSinkFailed
					rec.detail = "the sink returned an error: " +
						sanitizeForLedger(errText(err), secrets)
				default:
					rec.disposition = ArtifactStored
					rec.detail = "swept and stored"
				}
			}
		}
		s.report.records = append(s.report.records, rec)
	}
	if len(arts) > 0 {
		mix := s.report.DispositionMix()
		s.note(SessionEventReportWritten, at.Instant(), 0, 0, fmt.Sprintf(
			"authentication report: %d artifact(s) offered, %d stored, mix %v",
			s.report.Offered(), s.report.StoredCount(), mix))
	}
}

// screenshotAllowed applies the screenshot policy. It is FAIL CLOSED on every
// question it cannot answer.
func (s *Session) screenshotAllowed(a AuthArtifact) bool {
	if s.cfg.Screenshots != ScreenshotPolicyExceptCredentialSteps {
		return false
	}
	if a.Step == 0 {
		// A screenshot that names no step cannot be checked against the step
		// list. "I cannot tell" is not "it is safe".
		return false
	}
	return !s.cfg.Steps.stepBears(a.Step)
}

func (s *Session) screenshotRefusal(a AuthArtifact) (ArtifactDisposition, string) {
	if s.cfg.Screenshots == ScreenshotPolicySuppressAll {
		return ArtifactSuppressedByPolicy,
			"the configured policy suppresses every screenshot. HTTP and storage " +
				"artifacts are unaffected: those are bytes, and bytes are swept"
	}
	if a.Step == 0 {
		return ArtifactSuppressedCredentialStep,
			"this screenshot names no step, so it cannot be checked against the step " +
				"list. A credential in an image is PIXELS and no byte sweep can see it, " +
				"so an unresolvable screenshot is suppressed"
	}
	return ArtifactSuppressedCredentialStep, fmt.Sprintf(
		"step %d is a %s, which types a credential. A credential in an image is PIXELS "+
			"and no byte sweep can see it, so this screenshot is never stored",
		a.Step, s.stepKind(a.Step))
}

// credentialWasInFlight reports whether this artifact was produced at a point
// in the flow where a credential existed outside the Secret.
//
// THIS IS THE CONTROL THE SWEEP IS ONLY A BACKSTOP FOR. It reads the
// artifact's PROVENANCE and never its bytes, so no encoding defeats it: an
// HTML-entity-encoded, JSON-escaped, base64'd or gzipped credential is refused
// by the same rule as a plaintext one, because the rule never looks.
//
// Two cases, and both are the fail-closed reading:
//
//	THE ARTIFACT BELONGS TO A STEP THAT TYPES A SECRET. Its bytes are the
//	request that carried the credential, the DOM that held it, or the storage
//	the browser wrote immediately after. There is no spelling of that artifact
//	that is safe to keep.
//
//	THE ARTIFACT NAMES NO STEP. Step 0 means "covering the whole flow", and a
//	whole-flow artifact NECESSARILY SPANS the step that types the credential.
//	It is also the shape AuthArtifactStorageState arrives in, which is JSON by
//	definition and is the kind most likely to carry a session. "I cannot tell
//	which step this is" is not "it is safe".
//
// A driver that wants storage state or an HTTP transcript retained must attach
// it to a step that types nothing. That is a contract a driver can keep, and
// it is checkable here, which is the difference between it and an obligation
// stated in prose.
func (s *Session) credentialWasInFlight(a AuthArtifact) bool {
	if len(s.cfg.Steps.secrets()) == 0 {
		return false
	}
	return a.Step == 0 || s.cfg.Steps.stepBears(a.Step)
}

// inFlightRefusal is the ledger sentence for credentialWasInFlight.
func (s *Session) inFlightRefusal(a AuthArtifact) string {
	if a.Step == 0 {
		return "this artifact names no step, so it covers the whole flow — including the " +
			"step that types the credential. It is suppressed by PROVENANCE rather than " +
			"swept, because a sweep can only refuse the spellings it knows"
	}
	return fmt.Sprintf("step %d is a %s, which types a credential, so every byte this "+
		"artifact holds was produced with the credential in flight. It is suppressed by "+
		"PROVENANCE rather than swept: an encoding defeats a sweep and does not defeat this",
		a.Step, s.stepKind(a.Step))
}

// deliver is THE ONE CALL THAT REACHES THE SINK, and the second, genuinely
// independent look at the credential question.
//
// The look above it reads a.Bytes — the value the decision path chose. This
// one reads StoredArtifact.Bytes(), THE EXACT VALUE THE SINK ITSELF WILL READ,
// through the exact accessor the sink reads it through. That is the difference
// between two looks and one look twice: a refactor that swept one field and
// stored another would pass the first and fail here.
//
// It records a verdict per delivery — kind, step, whether a credential was
// found, and how many bytes, NEVER the bytes — so AssertNoCredentialInLedger
// reports from what was emitted rather than from what was rendered.
//
// A hit here means the sink is NEVER CALLED. It is a defect in this file, and
// it is loud.
func (s *Session) deliver(ctx context.Context, a StoredArtifact, secrets []Secret) error {
	out := a.Bytes()
	i, hit := credentialIn(out, secrets)
	s.emitted = append(s.emitted, emittedCheck{
		kind:   a.Kind(),
		step:   a.Step(),
		size:   len(out),
		secret: i,
		hit:    hit,
	})
	if hit {
		return fmt.Errorf("%w: the bytes handed to the ArtifactSink for the %s artifact of "+
			"step %d contain the credential from step-secret %d. The sink was not called",
			ErrCredentialInArtifact, a.Kind(), a.Step(), i+1)
	}
	if err := s.cfg.Sink.StoreAuthArtifact(ctx, a); err != nil {
		return err
	}
	return nil
}

func (s *Session) stepKind(oneBased int) AuthStepKind {
	kinds := s.cfg.Steps.Kinds()
	if oneBased < 1 || oneBased > len(kinds) {
		return AuthStepUnset
	}
	return kinds[oneBased-1]
}

// ---------------------------------------------------------------------------
// The sweep — THE BACKSTOP, NOT THE CONTROL
// ---------------------------------------------------------------------------

// credentialIn reports whether any credential appears in b, and which one.
//
// # THIS IS A BACKSTOP AND IT DOES NOT CLAIM COMPLETENESS
//
// The control that keeps a credential out of a stored artifact is PROVENANCE,
// not content: credentialWasInFlight refuses every artifact belonging to a
// step that types a secret, and every artifact that names no step at all,
// WHATEVER ITS KIND AND WHATEVER SPELLING THE BYTES USE. That rule cannot be
// defeated by an encoding because it never looks at the bytes.
//
// This function exists for the case that rule cannot reach: an artifact the
// driver attached to an innocent step whose bytes carry the credential anyway.
// A hit here is a DEFECT IN THE DRIVER, and a miss here is not a clean run —
// it is a question this function did not answer.
//
// # It canonicalizes the haystack rather than enumerating spellings of the
// needle
//
// The previous shape searched three ENCODINGS OF THE SECRET — raw,
// url.QueryEscape, url.PathEscape — which is a denylist of spellings and lost
// to the fourth: an HTML-entity-encoded or JSON-escaped credential was stored
// verbatim and every assertion reported clean. AuthArtifactStorageState is
// JSON by definition, so the JSON-escaped case was the ORDINARY one for the
// artifact kind most likely to carry a credential.
//
// So the haystack is DECODED toward a canonical form and the raw secret is
// searched for in each form, which is the same rule gate 8 and the crawler's
// dot-segment handling reached: canonicalize before matching.
//
// # Where the haystack has more than one canonical form, all of them are searched
//
// Canonicalizing presumes there is one canonical form, and twice on this path
// there is not. '+' is a space in a query string and a literal plus everywhere
// else, and no byte settles it. A semicolon-less digit run has no byte that
// says where the number ends, so `&#1153` is U+0481 or 's' followed by '3'
// depending on what the encoder meant.
//
// AN AMBIGUOUS INPUT IS READ EVERY WAY AND ANY READING THAT CONTAINS THE SECRET
// REFUSES — AND IT IS READ EVERY WAY AT THE STEP WHERE THE AMBIGUITY ARISES,
// not where the answer is consumed. That distinction is the whole of ruling 11
// and it was got wrong once already: containsUnderEveryReading took the union
// over readings, but it took it over a FORM that decodeEntities had produced by
// picking the greedy reading, so the union existed at encoding depth 0 and
// nowhere else. Measured: 0 of 450 semicolon-less re-spellings of this file's
// credential missed flat, 135 of 450 missed under ONE url.QueryEscape.
//
// So sweepForms is a SET, one step is ONE decoder, every reading a step
// produces is retained, and the next step maps over all of them. The union at
// the point of matching is unchanged and still does the site-independent
// cross-product; what changed is that it is now taken over forms that still
// carry the ambiguous bytes at every depth, rather than over one form a decoder
// already resolved.
//
// # What it still does not see, stated rather than qualified away
//
// EVERY BULLET BELOW THAT IS STILL LIVE HAS A FIXTURE. Where a residual could
// not be demonstrated it has been deleted from this list rather than qualified,
// and where one is demonstrable the test that demonstrates it is named.
//
//	A NAMED REFERENCE THAT EXPANDS TO MORE THAN ONE RUNE. What stood here was
//	that a named entity outside the six got past the sweep because "the
//	numeric forms are decoded generically". The numeric forms were not
//	generic. The decoder scanned at most eight bytes past the '&' for a ';'
//	and refused a longer body, so — measured against this file's own
//	credential — `&#0000115;` decoded and `&#00000115;` did not, a single
//	'&' survived five decimal zeros but only four hexadecimal ones because
//	the 'x' spends a byte of the same eight, and the semicolon-less form
//	HTML5 permits was not read at all. What a blind spelling costs is measured
//	at the sink, not reasoned about: disable the reference decoder and
//	TestAPaddedReferenceOnAnInnocentStepIsRefused reports "the backstop
//	refused 0 of 3 artifact(s). Mix: map[stored:3]" — three artifacts carrying
//	the credential, on a step the provenance rule permits, STORED. That test
//	now refuses all three.
//
//	The shape of that failure is the shape of the fix. A reference is
//	recognised by SHAPE, numeric values are read with NO DIGIT CEILING (the
//	work is bounded by len(b), which codedMaxArtifactBytes bounds), the
//	optional semicolon is handled, and a name namedEntities cannot resolve
//	becomes ONE WILDCARD RUNE matching any one character. So the residual is
//	no longer "a name outside a list" — it is a name whose expansion is not
//	one rune, which one wildcard cannot stand for.
//
//	TWO CHARACTER REFERENCES THAT NEED DIFFERENT NON-GREEDY READINGS, AND NEED
//	THEM DECODED AGAIN AFTERWARDS. A step asks decodeEntitiesReading for the
//	k-th reading of the WHOLE STRING, so every site in one form takes the same
//	index: that is the diagonal of the cross-product, not the whole of it. The
//	off-diagonal matters only where the chosen readings must be decoded a
//	second time, because containsUnderEveryReading already unions the readings
//	of every site independently on bytes it can still see.
//	SHOWN, NOT ASSERTED AWAY: the secret "A\t0" inside `&#3741&#90` needs the
//	first site's reading 1 ('%', leaving "41" for a later percent step) and the
//	second site's reading 0 (a tab, leaving a literal '0'), and the sweep does
//	not find it. TestTwoSitesNeedingDifferentReadingIndicesAreTheResidual is
//	that fixture, and it fails loudly if the residual is ever closed so that
//	this list cannot go stale in the other direction. Closing it costs the full
//	cross-product, which is exponential in the number of ambiguous sites; the
//	provenance rule is what covers it.
//
//	TWO '+' SIGNS IN ONE FORM NEEDING DIFFERENT READINGS. THE SAME DIAGONAL AS
//	THE BULLET ABOVE, ON THE '+' AXIS, AND IT WAS MISSING FROM THIS LIST WHILE
//	sweepForms' DOC DESCRIBED THE '+' BRANCH AS EXPRESSING WHAT A PER-PIPELINE
//	FLAG COULD NOT. That is true of DEPTH and false of the same-depth
//	cross-product: plusToSpace is a whole-string pass, so the form it produces
//	reads every '+' in its input the same way.
//	SHOWN, NOT ASSERTED AWAY: the secret "a b+c" inside `pw=a+b+c` needs the
//	first '+' read as a space and the second as a literal plus, and the sweep
//	does not find it — while "a b c" and "a+b+c" in the same bytes are both
//	found, and "A B+C" inside `A+B%2BC`, where the two '+' signs live at
//	different depths, is found too.
//	TestTwoPlusSignsInOneFormNeedingDifferentReadingsAreTheResidual is that
//	fixture and it fails loudly if the residual closes. Closing it costs the
//	per-site cross-product over every '+' in the artifact, which is exponential
//	in their number; the provenance rule is what covers it.
//
//	A LAYERED ENCODING INSIDE AN ARTIFACT THAT DOES NOT SHRINK AS IT IS
//	DECODED. This bullet was MISSING once, and its absence was the defect: the
//	pipeline re-ran exactly three times, so url.QueryEscape applied four times
//	hid the credential and this list read as though nothing of the kind
//	existed. There is no round count now — sweepForms walks a candidate set and
//	spends bytes scanned — and what is left is a MEASURED CURVE at
//	codedSweepWorkBytes: an artifact of pure filler that does not shrink is
//	decoded eleven layers at the 4 MiB cap, fifty at a megabyte, and more than
//	sixty below 256 KiB, against four at the cap when four pipelines stood
//	here. The claim that there was NO residual below ~2 KiB is deleted: it was
//	derived for a single trajectory and a set is not one.
//
//	base64 or any other re-encoding. Catching it needs encoding/base64, which
//	is NOT on gate 3's inertImports; adding it is a one-line edit in
//	internal/dast/authz/egress_chokepoint_test.go, is reported to the
//	orchestrator rather than made here, and is U10 in
//	internal/SKIPPED-CONTROLS.md. It is the spelling the backstop's own
//	positive-control test uses.
//
//	a compressed artifact, and A CREDENTIAL RENDERED AS PIXELS. Both are in
//	this file's header with what each would cost.
//
// It returns the INDEX of the offending secret, never the secret.
func credentialIn(b []byte, secrets []Secret) (int, bool) {
	if len(b) == 0 || len(secrets) == 0 {
		return 0, false
	}
	for _, hay := range sweepForms(string(b)) {
		for i, sec := range secrets {
			if !sec.Present() {
				continue
			}
			raw := sec.Reveal()
			if raw == "" {
				continue
			}
			if containsUnderEveryReading(hay, raw) {
				return i, true
			}
		}
	}
	return 0, false
}

// codedSweepWorkBytes bounds the TOTAL BYTES the canonicalizer may scan while
// building one candidate set. It replaced a round count, and the difference is
// the whole point of it.
//
// # A round count was a ceiling on encoding DEPTH, and its size was the budget
//
// What stood here was `codedSweepRounds = 3`, justified as "more layers than
// any encoder on this path produces". Measured against this file's own
// credential: url.QueryEscape applied one, two or three times was found and
// FOUR, five and six were not — and the residual list in credentialIn's doc
// did not name it, so a reader took its absence for completeness. An
// undisclosed ceiling is worse than a disclosed one. An encoder picks the next
// depth exactly as it picks the next pad width.
//
// # What replaced it, and why the number below is not the same ceiling
//
// NO CONSTANT IN THIS FILE NAMES A DEPTH ANY MORE. sweepForms walks the
// candidate set until no form produces a form it has not already seen; what it
// spends is BYTES SCANNED, and it stops when the running total no longer fits
// in codedSweepWorkBytes. Depth is not a parameter of the decoder at all — it
// is whatever the artifact's own shape pays for, and two artifacts of the same
// size reach different depths, which is exactly what a fixed round count could
// not express.
//
// # The accounting is of PASSES ACTUALLY MADE, not of a chosen depth
//
// One step over a form of length N makes at most codedSweepStepPasses + r
// passes over it: the three single-decoder readings and the reference-depth
// scan are one pass each even when their fast path finds nothing to do, and
// each of the r character-reference readings the step returns is one more. The
// charge is exactly that, so the budget is an upper bound on work rather than a
// number that happens to correlate with it.
//
// # The multiplier, and why it is not the one that was here
//
// It was `4 *`, and it meant four passes down each of FOUR FIXED PIPELINES at
// the artifact cap. A traversal costs more per level than a pipeline does — a
// step is charged codedSweepStepPasses over the form before it is charged one
// pass per reading — so keeping `4 *` would have bought two layers at the cap
// where the pipelines bought four, and the multiplier is NOT chosen to make a
// sentence come out. It was set by measuring the thing the residual is about:
// with `16 *` a 4 MiB artifact of pure filler was decoded 2 layers, with `64 *`
// it is decoded 11, against 4 before this file had a set at all. The measured
// curve is in the residual section below.
//
// # What that buys, measured rather than reasoned about
//
// Applying url.QueryEscape repeatedly is the WORST shape for a byte budget: it
// re-encodes only the percent signs, so the artifact grows about two bytes per
// percent sign per layer and each pass shrinks it by the same trickle instead
// of collapsing it. Even there, and even with the traversal carrying both
// readings of every layer's '+', this file's own credential is found at 2767
// layers, against three when a round count stood here. An encoding that covers
// the whole body — backslash escaping at two bytes per byte, percent at three —
// collapses it geometrically instead.
//
// # THE BOUND IS NAMED FOR BYTES SCANNED AND IT BINDS BYTES RETAINED TOO
//
// This constant is disclosed above as a bound on WORK, and it silently sets a
// second ceiling as well. A bound disclosed on one dimension while binding on
// another is the same defect as an undisclosed ceiling, so the other dimension
// is measured here rather than left to be discovered. sweepForms RETAINS every
// candidate it produces — that is what makes a pass return a set — and the
// whole set is live at once while credentialIn iterates it.
//
// The ceiling is arithmetic rather than a cap, and it rests on two things, both
// of which are ASSERTED rather than assumed because either one is a budget if
// it is only asserted about.
//
//	NO DECODER GROWS A FORM. plusToSpace is length-preserving, decodePercent
//	and decodeBackslash replace a multi-byte escape with the byte it denotes,
//	and every character-reference reading spans at least as many bytes as the
//	UTF-8 of the rune it produces — the tightest cases are `&#0` and `&a;`,
//	three bytes in and the three bytes of U+FFFF out. So a retained form is
//	never longer than the parent whose length paid for it.
//
//	ONE STEP RETURNS AT MOST codedSweepStepReadings = 19 READINGS: the three
//	single-decoder ones, plus two unresolvedPolicy values times the at most
//	EIGHT reading indices referenceReadingsAt's arithmetic allows. That matters
//	because sweepForms checks the budget against the BASE passes before the
//	step and then subtracts the readings' cost UNCHECKED, so the last step of a
//	traversal can overspend, by at most one full-length form per reading.
//
// Hence, for a seed of length L — and L is the right variable, not the artifact
// cap, for the reason two paragraphs down —
//
//	BYTES RETAINED ≤ codedSweepWorkBytes + L × (codedSweepStepReadings + 1)
//
// the last term being the final step's overspend plus the seed, which is the
// one member nothing was charged for. THE OVERSPEND TERM IS NOT DECORATION AND
// IT WAS MISSING FROM THE FIRST VERSION OF THIS PARAGRAPH: at half the
// multiplier below, this file's own 4 MiB fixture retains 142606222 bytes
// against a budget of 134217728, which the ceiling without that term declares
// impossible.
//
// For an ARTIFACT the seed is credentialIn's b, which storeArtifacts refuses
// past codedMaxArtifactBytes, so L ≤ 4194304 and
//
//	268435456 + 4194304 × 20 = 352321536 bytes (336 MiB)
//
// MEASURED, for ONE artifact at that cap:
//
//	pure filler, which does not branch     4194304 bytes retained,  1 form
//	filler + `%2B%25&#0\\&#1114111+`     209714969 bytes retained, 50 forms, 0.18 s
//	worst of 120 generated tails        239072831 bytes retained, 57 forms, 0.21 s
//
// So a 4 MiB artifact can hold 200 MiB live for the duration of one
// credentialIn call. storeArtifacts sweeps artifacts one at a time and this
// package starts no goroutine, so that is the peak rather than a per-artifact
// increment — but it is the number to raise the multiplier against, not the
// 4 MiB the artifact cap suggests.
//
// AND THE ARTIFACT CAP IS NOT THE ONLY WAY IN, WHICH IS WHY THE CEILING IS
// WRITTEN OVER L. sweepOnly routes DRIVER-AUTHORED STRINGS through the same
// credentialIn — AuthOutcome.Detail, LandedPath, an artifact Name — and
// NOTHING BOUNDS THEIR LENGTH. MEASURED, a branching tail on a 64 MiB seed:
// 17 forms, 1140850632 bytes retained — 1.06 GiB, 3.2× the artifact
// ceiling, in 1.1 s — and note that this is FOUR TIMES codedSweepWorkBytes, so
// it is the overspend term and not the budget doing it. At that length one step
// costs more than the whole budget, the traversal makes exactly one, and the
// readings of that one step are charged after the fact.
//
// That is stated rather than capped on purpose. A cap here would be a length
// past which a string is NOT swept, which is a credential-shaped hole; the
// driver is in-process code an operator supplies, so the bound that belongs on
// its Detail belongs on the driver.
//
// TestTheCandidateSetIsBoundedInBytesScannedAndInBytesRetained pins the middle
// row and asserts BOTH premises above; if a decoder ever grows a form, or a
// step ever returns a twentieth reading, the ceiling here is void and that test
// is what says so rather than a reader discovering it in production.
//
// # The residual, disclosed because an absent one reads as completeness
//
// The budget bites on an artifact that does NOT shrink as it is decoded: plain
// filler with one deeply-nested credential in it costs a full pass per form
// visited, and those visits are shared with whatever branching the artifact
// forces. MEASURED, with the credential under N layers of repeated
// url.QueryEscape at the end of that much filler:
//
//	1 KiB      60+ layers        1 MiB      50 layers
//	16 KiB     60+ layers        2 MiB      24 layers
//	256 KiB    60+ layers        4 MiB      11 layers
//
// (60 is where the measurement stopped, not where the sweep did.) Two
// consequences, both stated rather than implied:
//
//	A 4 MiB artifact that is almost all filler, in which the credential is
//	deeper than twelve layers, is not reached. That is a real residual, it is
//	the provenance rule that covers it, and it is the one credentialIn's doc
//	names.
//
//	THE OLD CLAIM THAT BELOW ~2 KiB THERE IS NO RESIDUAL AT ALL IS GONE, AND
//	IT IS DELETED RATHER THAN QUALIFIED. It was derived from 3L passes on ONE
//	trajectory: 2·len+specials (specials being '&', '%', '\' and '+') strictly
//	decreases on every pass that changes anything, which still bounds the
//	traversal's DEPTH at 3L — but the traversal is a set, and nothing in that
//	argument bounds how many forms are reachable, so 3L² is no longer an upper
//	bound on the work. What replaced that claim is a MEASUREMENT: over four
//	thousand generated strings assembled out of nothing but escape fragments —
//	the shape that branches worst — the largest set observed is 476 forms
//	totalling 19515 bytes, from a 77-byte seed. THE SIZE OF THE SET IS A
//	MEASUREMENT AND NOT A CONTROL: a cap on it would be a budget an encoder
//	could step outside by shaping an artifact to branch harder, so it is
//	logged. What is ASSERTED about that corpus is the no-growth premise the
//	section above rests on, in
//	TestTheCandidateSetIsBoundedInBytesScannedAndInBytesRetained. The
//	assertion that stood there instead — that the returned set fits inside
//	codedSweepWorkBytes — WAS TRUE BY CONSTRUCTION FOR EVERY POSSIBLE INPUT and
//	is deleted: no growth plus the per-reading charge gives it, so it could
//	only ever fail if the constant on the next line changed, and a test that
//	cannot fail on a defect reports pass. The construction argument is a doc's
//	job and it is now done in the doc.
const codedSweepWorkBytes = 64 * codedMaxArtifactBytes

// codedSweepStepPasses is how many passes over a form one step makes before it
// makes one per reading it returns: plusToSpace, decodePercent, decodeBackslash
// and referenceReadingDepth, each of which scans the form even when its fast
// path finds nothing to decode. It is an accounting constant — no behaviour
// reads it — and it is here so that the budget charges what the step spends.
const codedSweepStepPasses = 4

// codedSweepStepReadings is the most readings one decodeStep can return: the
// three single-decoder ones, plus each of the two unresolvedPolicy values at
// each of the at most EIGHT reading indices referenceReadingsAt's arithmetic
// permits. Dedup can only lower it.
//
// IT IS A DERIVED NUMBER, NOT A LIMIT — nothing enforces it, decodeStep returns
// whatever the bytes produce, and if that ever exceeds this the code is right
// and this constant is wrong. It exists because the retained-bytes ceiling at
// codedSweepWorkBytes needs it: sweepForms charges the readings' cost WITHOUT
// re-checking the budget, so the final step of a traversal can overspend by one
// full-length form per reading it returns, and a ceiling that ignores that term
// is not a ceiling. Measured, 19 is reached rather than merely allowed, and
// TestTheCandidateSetIsBoundedInBytesScannedAndInBytesRetained holds it shut.
const codedSweepStepReadings = 3 + 2*8

// sweepForms returns the SET of candidate readings of s that the sweep
// searches. It is a set and not a string, and that is the whole of it.
//
// # A DECODING PASS RETURNS A SET, AND THE NEXT PASS MAPS OVER THE SET
//
// What stood here was four PIPELINES, each running `decodeEntities(
// decodeBackslash(decodePercent(x)))` to a fixpoint and retaining only each
// pass's composed output. Two things were lost inside every pass, and they are
// the same thing:
//
//	THE UNION EXISTED AT ENCODING DEPTH 0 AND NOWHERE ELSE.
//	containsUnderEveryReading reads an ambiguous digit run every way — but it
//	reads the FORM it is handed, and decodeEntities had already picked the
//	greedy reading while producing that form. At depth 0 the seed is itself a
//	form and still carries the ambiguous bytes, so the union had something to
//	work on; wrap the same string in ONE url.QueryEscape and the only form
//	carrying the credential is the output of a pass that decoded the percent
//	layer and the reference together, and the ambiguous bytes exist in no
//	retained form at all. Measured against this file's own credential: 0 of
//	450 semicolon-less re-spellings missed flat, 135 of 450 missed under one
//	QueryEscape — exactly the genuinely ambiguous ones.
//	A UNION TAKEN OVER THE OUTPUT OF A DECODER THAT ALREADY CHOSE IS NOT A
//	UNION.
//
//	THE THREE DECODERS COMPOSED INSIDE ONE PASS AND ONLY THE COMPOSITION WAS
//	RETAINED, so a secret whose OWN BYTES are an escape sequence was destroyed
//	by an earlier decoder before the later one could see the form containing
//	it. `pa\nssw0rd` under one percent layer is `pa%5Cnssw0rd`: decodePercent
//	produces the secret exactly, and decodeBackslash in the same pass eats it.
//	Six of the ten realistic secret shapes in d24EscapeShapedSecrets were lost
//	that way under ONE percent layer — a base64 secret carries '+' and '/', a
//	secret out of a JSON config carries a backslash, a key lifted out of a URL
//	carries a '%'.
//
// So an ambiguity branches AT THE STEP WHERE IT OCCURS rather than where the
// answer is consumed. One step is ONE decoder, every candidate it produces is
// retained, and the next step maps over all of them: composition of passes is
// composition of sets. An intermediate is a member of the set, not a value on
// its way somewhere.
//
// # What one step produces
//
// From a form x, decodeStep returns every one-decoder reading of x:
// plusToSpace, decodePercent, decodeBackslash, and the character-reference
// readings under each unresolvedPolicy. Three of the ambiguities are settled by
// producing both answers rather than choosing:
//
//	'+' means SPACE in a query string and a literal plus everywhere else, and
//	no byte settles it. Both are members. WHAT THAT BUYS IS THE DEPTH AXIS AND
//	NOT THE CROSS-PRODUCT, and the sentence that stood here did not separate
//	them: because plusToSpace is a step rather than a flag on a pipeline, a
//	trajectory may read a '+' present at one layer as a space and a '+' that
//	only APPEARS at the next layer as a plus, which a per-pipeline flag could
//	not express — measured, "A B+C" is found inside `A+B%2BC`. But plusToSpace
//	is a WHOLE-STRING pass, so two '+' signs already present in the same form
//	cannot take different readings in one candidate: "a b+c" inside `pw=a+b+c`
//	is MISSED. That is the same diagonal as the reading index below, it is a
//	disclosed residual in credentialIn's list and in this file's header, and
//	TestTwoPlusSignsInOneFormNeedingDifferentReadingsAreTheResidual pins it.
//
//	`&commat;` is a character reference under one reading and seven literal
//	characters under the other. Decoding it to a wildcard is what stops an
//	unknown name from hiding a credential; NOT decoding it is what stops a
//	credential that literally contains "&commat;" from being lost when an outer
//	layer is peeled.
//
//	A SEMICOLON-LESS DIGIT RUN has a reading per prefix that denotes a
//	character, and referenceReadingDepth counts them. The k-th reading of the
//	whole string takes each site's k-th reading, so a reading that must be
//	DECODED AGAIN before the secret appears — `&#3741` read as '%' then "41",
//	which the next percent step turns into 'A' — is a member of the set rather
//	than a possibility the matcher can only assert about bytes it can see.
//	Where the readings need no further decoding, containsUnderEveryReading
//	already unions them at the point of matching, over every site
//	independently, and that half is unchanged.
//
// # The work bound, which is disclosed because an absent one reads as
// completeness
//
// codedSweepWorkBytes now bounds the WHOLE traversal rather than one pipeline,
// and a step over a form is charged for every pass it makes over that form —
// codedSweepStepPasses of them before it makes one per reading it returns. Two
// properties keep that from being a depth ceiling in disguise:
//
//	THE SET CANNOT REVISIT. Each decoder strictly decreases 2·len+specials on
//	any form it changes (see codedSweepWorkBytes), so the traversal is a DAG of
//	depth at most 3·len and the seen map makes each form cost once.
//
//	THE FRONTIER RECONVERGES. The decoders are whole-string passes, not
//	per-site choices, so two orderings of the same work meet again: for
//	repeated url.QueryEscape the frontier is the two readings of the layer's
//	'+' and they collapse back to one form on the next percent step. Measured,
//	this file's credential is still found at the depths
//	TestLayeredEncodingIsDecodedToAFixpointAndNotToARoundCount walks.
//
// The residual is unchanged in kind and stated at codedSweepWorkBytes: an
// artifact that does not SHRINK as it is decoded pays a full pass per form, so
// it gets codedSweepWorkBytes/N form-visits. When the budget runs out the
// traversal stops where it is and returns what it has — it never collapses the
// set to make it fit.
//
// AND THE SAME BUDGET BOUNDS MEMORY, WHICH IS SAID HERE BECAUSE THE NAME OF
// THE CONSTANT DOES NOT SAY IT. Everything this returns is RETAINED, and the
// caller holds it all while it iterates: no decoder grows a form, so bytes
// retained are bounded by codedSweepWorkBytes plus the final step's overspend
// plus the seed, and measured, one 4 MiB artifact ending in
// `%2B%25&#0\\&#1114111+` produces 50 forms and 209714969 live bytes in 0.18 s.
// codedSweepWorkBytes' doc carries the arithmetic and the rest of the
// measurements.
//
// The over-matching direction is the one that REFUSES an artifact rather than
// the one that ships it.
func sweepForms(s string) []string {
	out := []string{s}
	seen := map[string]bool{s: true}
	frontier := []string{s}
	budget := codedSweepWorkBytes
	for len(frontier) > 0 {
		var next []string
		for _, cur := range frontier {
			// A form costs its own length per reading taken of it. The empty
			// string costs one so that a budget cannot be spent forever.
			cost := len(cur)
			if cost == 0 {
				cost = 1
			}
			// The base passes of the step are charged BEFORE the step runs, so
			// the budget cannot be overspent by more than the readings one
			// already-affordable step returns.
			if budget < cost*codedSweepStepPasses {
				return out // the budget is spent; the set stops growing here
			}
			budget -= cost * codedSweepStepPasses
			reads := decodeStep(cur)
			budget -= cost * len(reads)
			for _, r := range reads {
				if !seen[r] {
					seen[r] = true
					out = append(out, r)
					next = append(next, r)
				}
			}
		}
		frontier = next
	}
	return out
}

// decodeStep returns every reading of s that ONE decoder produces, excluding s
// itself. It is the step function ruling 11 requires: a pass returns a set.
//
// The decoders are applied SEPARATELY rather than composed, because composing
// them inside one step is what destroyed a secret whose own bytes are an
// escape sequence — the intermediate that held it was never a member of
// anything. Each is a whole-string pass, so this is one reading per decoder
// plus one per character-reference reading index, and never a per-site
// cross-product.
func decodeStep(s string) []string {
	var out []string
	add := func(v string) {
		if v == s {
			return
		}
		for _, have := range out {
			if have == v {
				return
			}
		}
		out = append(out, v)
	}
	add(plusToSpace(s))
	add(decodePercent(s))
	add(decodeBackslash(s))
	depth := referenceReadingDepth(s)
	for _, unresolved := range []unresolvedPolicy{
		unresolvedAsLiteral, unresolvedAsWildcard,
	} {
		for k := 0; k < depth; k++ {
			add(decodeEntitiesReading(s, unresolved, k))
		}
	}
	return out
}

// referenceReadingDepth returns the largest number of readings any character
// reference in s has, which is how many reading indices decodeStep has to walk.
//
// IT IS COUNTED FROM THE BYTES, NOT CAPPED. referenceReadingsAt's doc bounds it
// by arithmetic at eight — seven decimal prefixes of a digit run can denote a
// character before 10⁷ passes U+10FFFF, six in hexadecimal, plus the greedy
// reading — so this is a measurement of the input and not a budget an encoder
// can step outside by padding.
func referenceReadingDepth(s string) int {
	if strings.IndexByte(s, '&') < 0 {
		return 0
	}
	depth := 0
	var reads []referenceReading
	for i := 0; i < len(s); i++ {
		if s[i] != '&' {
			continue
		}
		reads = referenceReadingsAt(reads[:0], s, i)
		if len(reads) > depth {
			depth = len(reads)
		}
	}
	return depth
}

// containsUnderEveryReading reports whether needle occurs in hay under ANY
// plausible reading of hay's character references, treating a rune whose
// identity is undecided as standing for any one rune.
//
// # An ambiguous input is read every way, and any reading that contains the
// secret refuses
//
// `&#115` followed by a literal '3' is six bytes. Nothing in the artifact says
// whether the encoder wrote a three-digit reference for 's' and then the
// character '3', or a four-digit reference for U+0481. The decoder this
// replaced consumed the digit run GREEDILY — it PICKED a reading — and picking
// is what lost: six of the twenty-five single-character re-spellings of this
// file's own credential were invisible to the sweep in base 10 alone, and the
// credential shipped out through CarriageEvidence().
//
// sweepForms has run two pipelines over the '+' ambiguity from the day it was
// written, for exactly this reason: url.QueryEscape applied twice writes a
// space as "%2B", so '+' is a literal plus after one round and a space after
// two, and no byte settles it. A semicolon-less digit run is the same shape.
// The union is the fail-closed reading of an ambiguity, and it is the reading
// used here.
//
// # What counts as a reading, which is the thing with no budget in it
//
// At every byte offset the alternatives are:
//
//	the LITERAL rune at that offset, always — so a body that is not a
//	reference at all still matches byte for byte, and the '&' of a query
//	string's "&next=" stays a '&';
//
//	every reading of a character reference starting there, from
//	referenceReadingsAt — which is every PREFIX OF THE DIGIT RUN whose value is
//	a Unicode scalar value, plus the greedy reading.
//
// That set is not a list anybody wrote down: it is generated from the bytes,
// and its SIZE IS BOUNDED BY ARITHMETIC rather than by a cap. Prefix values are
// non-decreasing and multiply by the base at each digit, so at most seven
// decimal or six hexadecimal prefixes of any run can denote a character however
// long the run is or how many leading zeros it carries — 10⁷ and 16⁶ are both
// past U+10FFFF. A prefix that denotes no character contributes no reading,
// because a reference that spells no character cannot be a spelling of a
// character of the secret.
//
// # This is a matcher, not a decoder, and it says no to almost everything
//
// A wildcard is EXACTLY ONE RUNE. A named reference whose expansion is two
// runes is still not matched by one — that residual is unchanged.
// TestOneReadingOfAnAmbiguousReferenceIsNotEveryReading asserts the bound in
// the other direction so this does not decay into a matcher that says yes to
// everything.
//
// # Cost
//
// The fast path is one strings.Contains; a form with no '&' and no undecided
// rune returns immediately after it. Otherwise it is one forward pass over hay
// carrying a frontier of partial matches. The frontier stays small BY
// CONSTRUCTION, not by a cap: no character reference contains a '&', so the
// spans of two references never overlap, so at any offset at most one reference
// site and at most four literal-rune sites can still be pending — a dozen
// offsets, each carrying at most one entry per rune of the needle.
func containsUnderEveryReading(hay, needle string) bool {
	if strings.Contains(hay, needle) {
		return true
	}
	if needle == "" {
		return true
	}
	if strings.IndexByte(hay, '&') < 0 && !strings.ContainsRune(hay, unresolvedReference) {
		return false // no ambiguity to read a second way
	}
	n := []rune(needle)
	var (
		live   []readingState
		expect []int
		reads  []referenceReading
	)
	for i := 0; i < len(hay); i++ {
		// A match may begin at any offset, so index 0 of the needle is always
		// expected here; anything else expected here was left by an earlier
		// reading. States pointing past i are carried, states at or before i
		// are spent.
		expect = append(expect[:0], 0)
		keep := live[:0]
		for _, st := range live {
			switch {
			case st.at == i:
				expect = append(expect, st.next)
			case st.at > i:
				keep = append(keep, st)
			}
		}
		live = keep

		reads = reads[:0]
		lr, lw := utf8.DecodeRuneInString(hay[i:])
		reads = append(reads, referenceReading{
			r: lr, span: lw, undecided: lr == unresolvedReference,
		})
		if hay[i] == '&' {
			reads = referenceReadingsAt(reads, hay, i)
		}

		for _, rd := range reads {
			for _, j := range expect {
				if !rd.undecided && rd.r != n[j] {
					continue
				}
				if j+1 == len(n) {
					return true
				}
				live = addReadingState(live, readingState{at: i + rd.span, next: j + 1})
			}
		}
	}
	return false
}

// readingState is one partial match: the needle's rune at index next is
// expected at byte offset at of the haystack.
type readingState struct {
	at   int
	next int
}

// addReadingState adds st unless it is already live. The scan is linear over a
// frontier whose size containsUnderEveryReading's doc bounds by construction.
func addReadingState(live []readingState, st readingState) []readingState {
	for _, have := range live {
		if have == st {
			return live
		}
	}
	return append(live, st)
}

// plusToSpace reads every '+' as the space a query-string encoder writes.
func plusToSpace(s string) string {
	if strings.IndexByte(s, '+') < 0 {
		return s
	}
	return strings.ReplaceAll(s, "+", " ")
}

// hexVal returns the value of one hex digit, or -1.
func hexVal(c byte) int {
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

// decodePercent undoes %XX byte-wise.
//
// It is hand-rolled rather than net/url's because url.QueryUnescape REFUSES a
// string containing a malformed escape and returns nothing usable — and a
// credential hidden behind one valid escape in an artifact that also contains
// a stray '%' is exactly the input an attacker-shaped artifact has. A decoder
// that gives up on the whole string is a decoder that can be switched off.
func decodePercent(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, lo := hexVal(s[i+1]), hexVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// decodeBackslash undoes the escapes a JSON or Go string literal uses.
//
// AuthArtifactStorageState IS JSON — cookies, localStorage and sessionStorage
// as the browser dumps them — so this is not an exotic encoding to handle. It
// is the ordinary one for the artifact kind most likely to hold a session.
func decodeBackslash(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch c := s[i+1]; c {
		case '"', '\'', '\\', '/':
			b.WriteByte(c)
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'b':
			b.WriteByte('\b')
			i++
		case 'f':
			b.WriteByte('\f')
			i++
		case '0':
			b.WriteByte(0)
			i++
		case 'x':
			if i+3 < len(s) {
				hi, lo := hexVal(s[i+2]), hexVal(s[i+3])
				if hi >= 0 && lo >= 0 {
					b.WriteByte(byte(hi<<4 | lo))
					i += 3
					continue
				}
			}
			b.WriteByte(s[i])
		case 'u':
			if v, ok := hex4(s, i+2); ok {
				b.WriteRune(rune(v))
				i += 5
				continue
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// hex4 reads exactly four hex digits at off.
func hex4(s string, off int) (int, bool) {
	if off+4 > len(s) {
		return 0, false
	}
	v := 0
	for i := off; i < off+4; i++ {
		d := hexVal(s[i])
		if d < 0 {
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

// namedEntities is the resolution table for the six predefined character
// references — the ones an HTML escaper actually emits.
//
// ITS LENGTH IS NOT THE ENCODER'S BUDGET, and that is what changed. A name this
// table does not carry is still RECOGNISED AS A CHARACTER REFERENCE BY SHAPE —
// '&', a run of ASCII alphanumerics, ';' — and decodes to unresolvedReference,
// one rune of unknown value that matches any one character during the sweep. So
// `&commat;` standing where a credential's '@' belongs no longer hides it, and
// neither does any of the two-thousand-odd other names the specification
// defines. What this table decides is which references get their EXACT value;
// a name outside it is UNDECIDED, not absent, and undecided still matches.
var namedEntities = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'', "nbsp": ' ',
}

// unresolvedReference is the rune a character reference whose value this
// decoder cannot determine decodes to.
//
// U+FFFF is a Unicode NONCHARACTER: it is never a legal encoded character, so
// a literal one in an artifact is not text. Treating one that was already there
// as a wildcard too costs exactly one over-match, in the direction that REFUSES
// an artifact rather than the one that ships it.
const unresolvedReference = '\uFFFF'

// unresolvedPolicy is what decodeEntities does with a reference it recognises
// by shape and cannot resolve to a value.
//
// BOTH READINGS ARE SEARCHED, for the same reason both readings of '+' are:
// no artifact says whether the bytes `&commat;` are a character reference or
// the literal seven characters. sweepForms runs the pipeline under each.
type unresolvedPolicy bool

const (
	unresolvedAsLiteral  unresolvedPolicy = false
	unresolvedAsWildcard unresolvedPolicy = true
)

// decodeEntities undoes HTML character references.
//
// # It takes the GREEDY reading, and that is not where the ambiguity is handled
//
// This is a decoder: it produces one string, so it must choose one reading of
// `&#1153`, and it chooses the one a browser would. THE CHOICE IS SAFE ONLY
// BECAUSE IT IS NOT THE WHOLE STORY — the union over readings is taken at the
// point of matching instead, by containsUnderEveryReading, which needs no
// choice because it never has to produce a string. Read that function's doc
// before concluding from this one that the sweep reads a digit run one way.
//
// # A numeric reference has no digit ceiling here, because it has none in the
// specification
//
// `&#38;`, `&#x26;`, `&#0000000000000038;` and `&#x000000000000026;` are the
// same character. The decoder this replaced scanned at most eight bytes past
// the '&' for a ';' and refused a longer body, so a single '&' survived five
// decimal leading zeros and four hexadecimal ones — and an encoder picks the
// next pad width. A bound on the digit count is an enumeration with an edge;
// the digits are consumed to their end, and a value that has passed U+10FFFF
// stops accumulating rather than wrapping into one that has a character.
//
// The work is still bounded, by the thing that is already bounded: no byte is
// covered by more than one reference scan (a scan stops at the first byte that
// is neither a digit nor an alphanumeric, and neither of those is '&'), so this
// is linear in len(s) whatever the input claims, and codedMaxArtifactBytes
// bounds len(s).
//
// # The terminating semicolon is optional, because HTML5 makes it optional
//
// A numeric reference is terminated by the first non-digit, and the ';' is
// consumed if it is there — `&#38` and `&#38;` both decode. A NAMED reference
// without a ';' resolves only by longest match against namedEntities, and when
// nothing matches, the '&' stays ordinary text — otherwise a query string's
// `&next=` starts eating its neighbours — TestABareAmpersandIsNotAReference
// holds that shut.
//
// The fixture in the packet that produced this function was
// `<input name="password" value="s3cr3t Pa55w0rd&amp;9xQz">` — an artifact
// stored verbatim by the byte-exact sweep that preceded it.
func decodeEntities(s string, unresolved unresolvedPolicy) string {
	return decodeEntitiesReading(s, unresolved, greedyReadingIndex)
}

// greedyReadingIndex asks decodeEntitiesReading for the LAST reading at every
// site, which is the longest one and therefore the one a browser takes. Any
// index at or past a site's reading count means the same thing there, so a
// string whose deepest site has k readings is fully covered by indices 0..k-1.
const greedyReadingIndex = -1

// decodeEntitiesReading is decodeEntities with the reading chosen rather than
// assumed: every character reference in s takes its reading at index k, or its
// greedy reading when it has fewer than k+1 readings.
//
// THE INDEX IS THE STEP-LEVEL BRANCH. A decoder must emit one string, so it
// must pick; sweepForms therefore asks for every index the input actually has
// and keeps all the answers, which is what makes "a pass returns a set" true of
// this pass rather than only of the ones with a boolean ambiguity. What is NOT
// produced is a form in which two sites take DIFFERENT non-greedy indices —
// that is the diagonal of the cross-product and not the whole of it, and it is
// disclosed in credentialIn's residual list. The site-independent
// cross-product is covered where it can be: containsUnderEveryReading takes it
// at the point of matching, over bytes it can still see.
func decodeEntitiesReading(s string, unresolved unresolvedPolicy, k int) string {
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	var reads []referenceReading
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		reads = referenceReadingsAt(reads[:0], s, i)
		r, n, ok := nthReading(reads, k, unresolved)
		if !ok {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteRune(r)
		i += n
	}
	return b.String()
}

// maxScalarValue is the largest Unicode scalar value there is. A numeric
// reference above it denotes no character.
const maxScalarValue = 0x10FFFF

// referenceReading is one plausible reading of the bytes beginning at a '&':
// the rune they denote, how many bytes they span, and whether that rune's
// identity is actually known.
type referenceReading struct {
	r         rune
	span      int
	undecided bool
}

// referenceReadingsAt appends to dst EVERY plausible reading of the character
// reference beginning at the '&' at off, in order of increasing span, and
// returns the result. It appends nothing when those bytes are not a character
// reference at all.
//
// # A digit run with no terminator is ambiguous and every prefix of it is a
// reading
//
// A browser reads `&#1153` greedily, as U+0481. An ENCODER that wrote `&#115`
// for 's' and then the character '3' produced the same six bytes, and the
// artifact does not record which happened. Both are returned. The greedy
// reading is last, which is what makes greedyReading a one-liner and keeps the
// canonicalizing pipeline reading exactly what a browser would.
//
// # The number of readings is bounded by arithmetic, not by a cap
//
// Prefix values are non-decreasing and each further digit multiplies by the
// base, so once a prefix is non-zero at most ⌈log_base(U+110000)⌉ further
// prefixes can still denote a character — seven in decimal, six in
// hexadecimal. Leading zeros extend the run without adding readings, because a
// prefix worth zero denotes no character. So a run of a hundred thousand
// digits yields at most eight readings, and the SCAN is linear in the run
// because no reference contains a '&' and runs therefore never overlap.
//
// A prefix that denotes no character contributes no reading of its own. That is
// not a shortcut: a reference spelling no character cannot be an encoder's
// spelling of a character of the secret, and the undecided rune the greedy
// reading already contributes is what covers the case where the whole run
// spells nothing.
//
// # A name without a terminator is NOT read by shape
//
// `&commat;` is undecided and matches any one rune; `&commat` without the ';'
// is ordinary text, resolved only by matching the table, or a query string's
// "&next=" starts eating its neighbours. TestABareAmpersandIsNotAReference
// holds that shut.
func referenceReadingsAt(dst []referenceReading, s string, off int) []referenceReading {
	mark := len(dst)
	j := off + 1
	if j < len(s) && s[j] == '#' {
		j++
		base := 10
		if j < len(s) && (s[j] == 'x' || s[j] == 'X') {
			base, j = 16, j+1
		}
		start, v, over := j, 0, false
		for ; j < len(s); j++ {
			d := hexVal(s[j])
			if d < 0 || d >= base {
				break
			}
			if !over {
				// v is at most maxScalarValue here, so this cannot wrap. Once
				// it passes, it stops accumulating and no longer denotes
				// anything -- but the remaining digits are still part of the
				// run and are still consumed.
				v = v*base + d
				over = v > maxScalarValue
			}
			if !over && v != 0 && (v < 0xD800 || v > 0xDFFF) {
				dst = append(dst, referenceReading{r: rune(v), span: j + 1 - off})
			}
		}
		if j == start {
			return dst[:mark] // "&#" with no digits denotes nothing
		}
		end := j
		if end < len(s) && s[end] == ';' {
			end++ // the terminator is optional, so it is consumed if it is there
		}
		// The greedy reading spans the whole run. When the run as a whole
		// denotes a character that reading is already the last one appended and
		// only its span has to grow over the ';'; otherwise the run is a
		// reference that spells no character, which is UNDECIDED rather than
		// absent.
		if len(dst) > mark && dst[len(dst)-1].span == j-off {
			dst[len(dst)-1].span = end - off
			return dst
		}
		return append(dst, referenceReading{
			r: unresolvedReference, span: end - off, undecided: true,
		})
	}
	start := j
	for j < len(s) && isASCIIAlnum(s[j]) {
		j++
	}
	if j == start {
		return dst[:mark] // a bare '&' is a bare '&'
	}
	name := s[start:j]
	if j < len(s) && s[j] == ';' {
		if r, ok := namedEntities[name]; ok {
			return append(dst, referenceReading{r: r, span: j + 1 - off})
		}
		return append(dst, referenceReading{
			r: unresolvedReference, span: j + 1 - off, undecided: true,
		})
	}
	for n := 1; n <= len(name); n++ {
		if r, ok := namedEntities[name[:n]]; ok {
			dst = append(dst, referenceReading{r: r, span: (start + n) - off})
		}
	}
	return dst
}

// nthReading returns the reading at index k, clamping to the LAST — the
// longest, which is the one a browser takes — for any index the site does not
// have. It reports false when the bytes are not a reference at all, and when
// the chosen reading is undecided under a policy that reads an unresolvable
// reference as literal text.
func nthReading(reads []referenceReading, k int, unresolved unresolvedPolicy) (rune, int, bool) {
	if len(reads) == 0 {
		return 0, 0, false
	}
	if k < 0 || k >= len(reads) {
		k = len(reads) - 1
	}
	g := reads[k]
	if g.undecided && unresolved != unresolvedAsWildcard {
		return 0, 0, false
	}
	return g.r, g.span, true
}

// isASCIIAlnum reports whether c can appear in a named character reference.
func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// sweepOnly replaces a whole string in which a credential was found, and
// otherwise returns it unchanged.
//
// IT MUST RUN ON THE RAW STRING, BEFORE ANY REDACTION AND BEFORE THE STRING IS
// EMBEDDED IN A LARGER ONE. redact() rewrites bytes outside its allowlist to
// '?', so a credential spelled "s3cr3t Pa55w0rd&9xQz" becomes
// "s3cr3t Pa55w0rd?9xQz" — which no longer contains the credential, so a sweep
// run afterwards finds nothing and nineteen of its twenty characters ship.
// TestRedactionDoesNotDefeatTheSweep is the guard, and it is the reason every
// driver-authored field is swept individually at the point it arrives rather
// than once at the end.
func sweepOnly(s string, secrets []Secret) string {
	if _, hit := credentialIn([]byte(s), secrets); hit {
		return refusedForCredential
	}
	return s
}

// sanitizeForLedger is the ONE channel from a driver-authored string to the
// session ledger: sweep the raw bytes, then fold what remains through redact()
// for the charset and the length bound.
func sanitizeForLedger(s string, secrets []Secret) string {
	return redact(sweepOnly(s, secrets))
}

// sweep is the per-field call. It runs on a value the moment it arrives from a
// driver, before it is embedded in a message that redaction would rewrite.
func (s *Session) sweep(v string) string { return sweepOnly(v, s.cfg.Steps.secrets()) }
