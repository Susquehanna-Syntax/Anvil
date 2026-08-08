package record

// mask.go — R.8, the secrets-masking pipeline.
//
// ===========================================================================
// WHAT THIS FILE IS FOR, AND WHY IT RUNS WHERE IT RUNS
// ===========================================================================
//
// plan/00-SPINE.md S7 names one field the highest-risk in the whole system:
//
//	"Prompt injection: sanitize at ingest, not at prompt time. The DAST
//	 response body is the highest-risk field — up to 32 KB of
//	 attacker-controlled bytes fed to a repo-credentialed agent."
//
// research/18-unified-audit-record.md Risk #10 states the secrets half of the
// same problem:
//
//	"Bodies leak secrets. webRequest.headers will contain session cookies and
//	 bearer tokens by default. ZAP masks Authorization with asterisks; Anvil
//	 must do the same *before* the record reaches the buffer, the DB, or the
//	 coding agent's context — an 8-hour TTL is not a security control for a
//	 token that is still valid."
//
// Two consequences, and both are load-bearing:
//
//  1. MASKING IS AN INGEST STEP, NOT A RENDER STEP. It must be the last step
//     of record assembly and it must run BEFORE either sink — the store and
//     the model context. Masking on the way out to a prompt leaves the live
//     token sitting in SQLite, where the 8-hour claim timeout is the only
//     thing standing between it and an attacker, and a claim timeout is a
//     scheduling policy, not a confidentiality control (see SECRETS.md).
//
//  2. IT FAILS CLOSED. Every decision below resolves ambiguity by redacting.
//     A masker that fails open is worse than no masker at all, because it
//     manufactures confidence: a reviewer who sees `***REDACTED***` in three
//     places assumes the fourth header was checked and found harmless, when
//     in fact it was unparseable and waved through.
//
// ===========================================================================
// THE FOUR THINGS THIS FILE DOES
// ===========================================================================
//
//	1. Structural header masking. A header whose NAME is on the denylist has
//	   its value replaced with RedactedPlaceholder. A header whose name or
//	   value has an unexpected SHAPE is redacted too, and recorded as an
//	   anomaly (see "Fail-closed rules").
//
//	2. Structural parameter masking. webRequest.parameters entries with a
//	   secret-shaped NAME, plus the query string and fragment of EVERY URL the
//	   record carries, plus URL userinfo passwords, plus the option arguments
//	   of `anvil/repro.curl`. Values are redacted; names are preserved, because
//	   the parameter name is evidence (it is the injection point) while the
//	   value of `api_key` never is.
//
//	3. Value propagation. Every value redacted in steps 1 and 2 is collected,
//	   decomposed (a Cookie header into its name=value pairs, an
//	   Authorization header into the credential after the scheme), and then
//	   removed from EVERY other string in the record by exact substring
//	   replacement. This is what makes the substring-absence assertion hold:
//	   a session cookie echoed back inside a 30 KB HTML error page is not
//	   caught by any header rule, but it is caught here.
//
//	4. Body caps. webRequest.body at MaxInlineRequestBodyBytes and
//	   webResponse.body at MaxInlineResponseBodyBytes — the same 8 KB / 32 KB
//	   thresholds OWASP ZAP's SARIF reporter uses (research/18 [S8]). The
//	   remainder SPILLS to a content-addressed Tier-2 blob reference; it is
//	   never silently dropped.
//
// Ordering between them is not arbitrary. Structural masking runs first
// because it is what discovers the secret values. Propagation runs second, on
// the whole (still untruncated) record, so that a secret sitting past the
// 32 KB cap is scrubbed from the spilled blob as well as from the inline
// prefix. Truncation runs last, so the sha256 in the truncation notice is the
// digest of the MASKED body — the bytes a Tier-2 blob may legally hold — and
// not of a body that still had a live token in it.
//
// ===========================================================================
// FAIL-CLOSED RULES
// ===========================================================================
//
//	R1. A header name that is not an RFC 9110 field-name token (empty, or
//	    carrying whitespace, a control byte, a separator, or any non-ASCII
//	    byte) cannot be classified, so its value is redacted.
//
//	R2. A header VALUE containing CR or LF is redacted regardless of its
//	    name. This is the response-splitting case: `X-Trace: ok\r\nSet-Cookie:
//	    sid=live` presents to a name-based denylist as the innocent header
//	    `X-Trace`, and smuggles a live cookie into the record inside its
//	    value. A name-only denylist cannot see it.
//
//	R3. A parameter name that is empty or carries a control byte cannot be
//	    classified, so its value is redacted.
//
//	R4. A query- or fragment-pair name that will not percent-decode is
//	    redacted.
//
//	R5. A `-H` / `--header` argument in a reproduction command line that does
//	    not parse as `Name: Value` cannot be classified, so the WHOLE argument
//	    is redacted.
//
// Each of these records an Anomaly in the MaskReport. None of them returns an
// error: a DAST scan of a hostile target produces malformed headers as a
// matter of course, and erroring out would discard the finding — which is a
// worse outcome than an over-redacted one. The redaction IS the closed
// failure.
//
// ===========================================================================
// WHAT THIS FILE DELIBERATELY DOES NOT DO
// ===========================================================================
//
// NO SHAPE-BASED BODY SCANNING. There is no "looks like a JWT" or "looks like
// an AWS key" regex here. Such a scanner cannot be made to fail closed — it
// either matches or it does not, and every miss is invisible — so it would
// deliver exactly the false confidence this file exists to avoid. A secret
// that appears ONLY in a body, and never in a denylisted header or a
// secret-named parameter, is NOT removed by this package. That is a known,
// stated limitation, not an oversight. S7's actual control for body content
// is a different mechanism owned by a different step: "hash-and-reference by
// default; inline only a regex-extracted evidence span".
//
// THE DENYLIST IS NOT EXHAUSTIVE, AND IS NOT CLAIMED TO BE.
// plan/40-record-and-storage.md Open Question 8 records this explicitly: R.8
// uses a "documented but not exhaustively researched" denylist, and a
// dedicated security review of real-world header names is recommended before
// the masking pipeline ships in a release. Concrete names the list as
// specified does NOT catch, so the gap is visible rather than assumed
// covered: `api-key` and `apikey` (only the exact `x-api-key` is listed),
// `www-authenticate`, `authentication`, `x-csrf-token` is caught only via the
// `*token*` pattern, `x-amz-*` signature headers, `location` (which routinely
// carries a one-time code or an implicit-flow access token in a redirect),
// and any bespoke vendor header. Extend DenylistedHeaderNames when that
// review happens; do not assume the current list is complete.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// The denylists
// ---------------------------------------------------------------------------

// denylistedHeaderNames is the exact-match half of the header denylist from
// plan/40-record-and-storage.md R.8 ("Authorization, Cookie, Set-Cookie,
// Proxy-Authorization, X-Api-Key"). Stored ASCII-lowercased; comparison folds
// the record's name the same way. See Open Question 8 in the file header for
// what this list does not cover.
var denylistedHeaderNames = []string{
	"authorization",
	"cookie",
	"proxy-authorization",
	"set-cookie",
	"x-api-key",
}

// denylistedHeaderSubstrings is the pattern half of the same denylist: "any
// header matching *token*/*secret* case-insensitively". This is what catches
// `X-Auth-Token`, `X-Csrf-Token`, `X-Amz-Security-Token` and
// `X-Client-Secret` without naming each one.
var denylistedHeaderSubstrings = []string{
	"secret",
	"token",
}

// sensitiveParameterNames is the exact-match denylist for
// webRequest.parameters keys and for query/fragment pair names.
//
// PROVENANCE, STATED PLAINLY: unlike the header denylist, this list is NOT in
// the plan and NOT in the research corpus. R.8's stop condition requires an
// "API key in a query parameter" fixture to come out clean, so a parameter
// rule is required, and this is R.8's own choice. It belongs to the same
// security review as Open Question 8 and carries the same caveat.
//
// It is deliberately narrower than the reflex "redact anything suspicious":
// a DAST parameter value is usually the INJECTION PAYLOAD, and the payload is
// the evidence the coding agent needs. Redacting `username` because a scanner
// might one day put a credential there would destroy the finding.
var sensitiveParameterNames = []string{
	"access_key",
	"access_token",
	"api_key",
	"apikey",
	"auth",
	"authorization",
	"client_secret",
	"cookie",
	"credential",
	"credentials",
	"id_token",
	"jsessionid",
	"passwd",
	"password",
	"phpsessid",
	"pwd",
	"refresh_token",
	"secret",
	"sessid",
	"session",
	"session_id",
	"sessionid",
	"sid",
	"signature",
	"token",
}

// sensitiveParameterSubstrings is the pattern half of the parameter rule.
var sensitiveParameterSubstrings = []string{
	"api-key",
	"api_key",
	"apikey",
	"passwd",
	"password",
	"secret",
	"token",
}

// DenylistedHeaderNames returns a copy of the exact-match header denylist,
// ASCII-lowercased. Exported so the security review Open Question 8 asks for
// has something to diff against, and so a test can assert the plan's five
// names are all present.
func DenylistedHeaderNames() []string {
	return append([]string(nil), denylistedHeaderNames...)
}

// DenylistedHeaderSubstrings returns a copy of the pattern half of the header
// denylist, ASCII-lowercased.
func DenylistedHeaderSubstrings() []string {
	return append([]string(nil), denylistedHeaderSubstrings...)
}

// SensitiveParameterNames returns a copy of the exact-match parameter
// denylist. See sensitiveParameterNames for its provenance caveat.
func SensitiveParameterNames() []string {
	return append([]string(nil), sensitiveParameterNames...)
}

// SensitiveParameterSubstrings returns a copy of the pattern half of the
// parameter denylist.
func SensitiveParameterSubstrings() []string {
	return append([]string(nil), sensitiveParameterSubstrings...)
}

// MinPropagatedSecretLen is the shortest redacted value that is propagated
// through the rest of the record by substring replacement.
//
// The bound exists because propagation is exact substring replacement over
// every string in the record. A cookie crumb of `a=1` yields the value "1",
// and replacing every "1" in a 32 KB stack trace would destroy the evidence
// while protecting nothing — a one-byte value is not a credential. Eight
// bytes is short enough to catch a weak session id and long enough that a
// collision with ordinary body text is not a practical concern.
//
// CONSEQUENCE, STATED: a genuine secret shorter than this is still redacted
// AT ITS HEADER OR PARAMETER — that is structural and unconditional — but a
// copy of it echoed elsewhere in the record is not removed.
const MinPropagatedSecretLen = 8

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

// Anomaly is one fail-closed redaction: a place where the masker could not
// classify what it was looking at and redacted rather than guess.
//
// Anomalies are surfaced rather than swallowed because they are the signal
// that the denylist met something it was not designed for. A run producing
// them is a run whose target is doing something unusual with HTTP.
type Anomaly struct {
	// Pointer is an RFC 6901 JSON Pointer from the sarifLog root.
	Pointer string `json:"pointer"`
	// Reason names the fail-closed rule that fired (R1..R4 in this file's
	// header comment).
	Reason string `json:"reason"`
}

// Spill is one body that exceeded its inline cap.
//
// research/18's read path says the remainder "spills to a blob", and
// plan/40-record-and-storage.md's Tier-2 row says those blobs are
// "referenced by sha256: digest". Content is the FULL MASKED body — masking
// and propagation have already run over it — so it is safe to persist as a
// Tier-2 blob exactly as given.
type Spill struct {
	// Pointer is an RFC 6901 JSON Pointer from the sarifLog root to the
	// ArtifactContent that was truncated.
	Pointer string `json:"pointer"`
	// Ref is the reference written into the record. By default
	// "sha256:<64 lowercase hex>" over Content; a SpillFunc may return a
	// different reference (e.g. a store-relative blob path).
	Ref string `json:"ref"`
	// Sha256 is the "sha256:<64 lowercase hex>" digest of Content,
	// regardless of what Ref ended up being.
	Sha256 string `json:"sha256"`
	// TotalBytes is len(Content). InlineBytes is how much of it stayed in
	// the record.
	TotalBytes  int `json:"totalBytes"`
	InlineBytes int `json:"inlineBytes"`
	// Content is the full masked body. NOT serialised: a MaskReport is a
	// diagnostic object and must not become a second durable copy of the
	// body it was created to move out of the record.
	Content string `json:"-"`
}

// SpillFunc persists a spilled body and returns the reference to write into
// the record. Returning "" means "use the default sha256: reference". An
// error aborts masking — the record is left in whatever masked state it had
// reached, which is always at least as masked as it started.
type SpillFunc func(Spill) (string, error)

// MaskReport is what the masker did. It is diagnostic output, not part of the
// record.
type MaskReport struct {
	HeadersRedacted     int `json:"headersRedacted"`
	ParametersRedacted  int `json:"parametersRedacted"`
	QueryValuesRedacted int `json:"queryValuesRedacted"`
	// PropagatedRedactions counts STRINGS changed by the propagation pass,
	// not occurrences.
	PropagatedRedactions int `json:"propagatedRedactions"`
	BodiesTruncated      int `json:"bodiesTruncated"`

	Anomalies []Anomaly `json:"anomalies,omitempty"`
	Spills    []Spill   `json:"spills,omitempty"`
}

// ---------------------------------------------------------------------------
// The masker
// ---------------------------------------------------------------------------

// Masker masks a record. The zero value is usable and is what MaskRecord
// uses.
type Masker struct {
	// Spill, if non-nil, is called for every body that exceeds its cap,
	// before the reference is written into the record. If it is nil the
	// bytes past the cap are NOT retained by this package: the record keeps
	// a sha256 reference to a blob nobody stored. Callers that own Tier-2
	// storage must set this, or read MaskReport.Spills.
	Spill SpillFunc

	// MinPropagationLen overrides MinPropagatedSecretLen when > 0. Lowering
	// it increases over-redaction; it does not weaken anything.
	MinPropagationLen int
}

// MaskRecord is R.8's entry point: it masks l in place and reports whether
// masking could be completed.
//
// It MUST be the last step of record assembly, before the record reaches
// either sink — the store or any model context. There is no supported order
// in which an unmasked record is written anywhere first and scrubbed
// afterwards; a post-hoc scrub leaves the live credential in the store for
// the window between the two, and "the window is short" is the argument
// research/18 Risk #10 already rejected.
//
// The bytes of any body past its inline cap are not retained by this call —
// the record keeps a sha256 reference to them. Use Masker with a Spill sink,
// or Masker.Mask and read MaskReport.Spills, when those bytes must be
// persisted as Tier-2 blobs.
func MaskRecord(l *SARIFLog) error {
	_, err := (&Masker{}).Mask(l)
	return err
}

// Mask masks l in place and returns what it did.
//
// The returned error is reserved for conditions that mean the caller must not
// proceed: a nil log, or a SpillFunc that failed. An unclassifiable header is
// NOT one of them — see the fail-closed rules in this file's header.
func (m *Masker) Mask(l *SARIFLog) (*MaskReport, error) {
	if l == nil {
		return nil, fmt.Errorf("record: MaskRecord got a nil *SARIFLog; masking must run on the assembled record, before either sink")
	}
	rep := &MaskReport{}
	secrets := newSecretSet(m.minPropagationLen())

	// Pass 1 — structural. This is the pass that DISCOVERS secret values, and
	// it is driven by walkMaskSurface so that the set of places it looks and
	// the set of places AssertMasked checks cannot drift apart.
	walkMaskSurface(l, surface{
		Headers: func(ptr string, h map[string]string) {
			m.maskHeaders(ptr, h, secrets, rep)
		},
		Parameters: func(ptr string, p map[string]string) {
			m.maskParameters(ptr, p, secrets, rep)
		},
		URL: func(ptr string, p *string) {
			*p = m.maskURL(ptr, *p, secrets, rep)
		},
		CommandLine: func(ptr string, p *string) {
			*p = m.maskCommandLine(ptr, *p, secrets, rep)
		},
	})

	// Pass 2 — propagation, across the WHOLE record and the WHOLE body,
	// before anything is truncated.
	if vals := secrets.values(); len(vals) > 0 {
		rep.PropagatedRedactions = propagateSecrets(reflect.ValueOf(l), vals)
	}

	// Pass 3 — caps. Last, so every digest is over masked bytes.
	var capErr error
	walkMaskSurface(l, surface{
		Body: func(ptr string, b *ArtifactContent, limit int) {
			if capErr != nil {
				return
			}
			capErr = m.capBody(ptr, b, limit, rep)
		},
	})
	if capErr != nil {
		return rep, capErr
	}
	return rep, nil
}

// ---------------------------------------------------------------------------
// The mask surface
// ---------------------------------------------------------------------------

// surface is the set of callbacks walkMaskSurface invokes, one per KIND of
// maskable site. A nil callback means "this walk does not care about that
// kind"; the walk itself is unchanged either way.
//
// Splitting the enumeration of the sites from what is done to them is the
// whole point. CRITIQUE-02 F3 and F4 are both the same defect in two places:
// Mask inspected four sites, AssertMasked checked three of them, and neither
// looked at `anvil/repro.curl` or `anvil/target.repoUrl` — two fields that
// carry live credentials by construction (`-H 'Authorization: Bearer …'` and
// `https://x-access-token:<token>@github.com/…`, the standard GitHub Actions
// checkout URL). With one walker, a site added here is masked AND enforced,
// and TestAssertMaskedCoversEverySiteMaskCovers fails if that stops being true.
type surface struct {
	// Headers is an HTTP header map: name-keyed, denylist-classified.
	Headers func(ptr string, h map[string]string)
	// Parameters is a name/value map of request parameters.
	Parameters func(ptr string, p map[string]string)
	// URL is a settable field holding a single URL: userinfo, query and
	// fragment all classified.
	URL func(ptr string, p *string)
	// CommandLine is a settable field holding a shell reproduction command.
	CommandLine func(ptr string, p *string)
	// Body is an inline artifact content with its own byte cap.
	Body func(ptr string, b *ArtifactContent, limit int)
}

// walkMaskSurface visits every site in l that this package is responsible for,
// in a fixed order, passing an RFC 6901 JSON Pointer for each.
//
// THE URL SITES ARE NOT DECORATION. `anvil/target.repoUrl` is where a CI
// checkout URL lands, and `https://x-access-token:<token>@github.com/org/repo`
// is what GitHub Actions produces; `runtimeBaseUrl` and
// `anvil/runtimeTarget.baseUrl` are where a DAST target's basic-auth userinfo
// lands. maskURL already knew how to strip all of that — it was simply never
// pointed at these fields.
func walkMaskSurface(l *SARIFLog, s surface) {
	if l == nil {
		return
	}

	if s.URL != nil {
		t := &l.Properties.Target
		s.URL("/properties/anvil~1target/repoUrl", &t.RepoURL)
		s.URL("/properties/anvil~1target/runtimeBaseUrl", &t.RuntimeBaseURL)
	}

	for i := range l.Runs {
		run := &l.Runs[i]
		runBase := fmt.Sprintf("/runs/%d", i)

		if rt := run.Properties.RuntimeTarget; rt != nil && s.URL != nil {
			rtBase := runBase + "/properties/anvil~1runtimeTarget"
			s.URL(rtBase+"/baseUrl", &rt.BaseURL)
			for k := range rt.Scope {
				s.URL(fmt.Sprintf("%s/scope/%d", rtBase, k), &rt.Scope[k])
			}
			for k := range rt.Excluded {
				s.URL(fmt.Sprintf("%s/excluded/%d", rtBase, k), &rt.Excluded[k])
			}
		}

		for j := range run.Results {
			r := &run.Results[j]
			base := fmt.Sprintf("%s/results/%d", runBase, j)

			if r.WebRequest != nil {
				if s.Headers != nil {
					s.Headers(base+"/webRequest/headers", r.WebRequest.Headers)
				}
				if s.Parameters != nil {
					s.Parameters(base+"/webRequest/parameters", r.WebRequest.Parameters)
				}
				if s.URL != nil {
					s.URL(base+"/webRequest/target", &r.WebRequest.Target)
				}
				if s.Body != nil {
					s.Body(base+"/webRequest/body", r.WebRequest.Body, MaxInlineRequestBodyBytes)
				}
			}
			if r.WebResponse != nil {
				if s.Headers != nil {
					s.Headers(base+"/webResponse/headers", r.WebResponse.Headers)
				}
				if s.Body != nil {
					s.Body(base+"/webResponse/body", r.WebResponse.Body, MaxInlineResponseBodyBytes)
				}
			}
			if repro := r.Properties.Repro; repro != nil && s.CommandLine != nil {
				s.CommandLine(base+"/properties/anvil~1repro/curl", &repro.Curl)
			}
		}
	}
}

func (m *Masker) minPropagationLen() int {
	if m.MinPropagationLen > 0 {
		return m.MinPropagationLen
	}
	return MinPropagatedSecretLen
}

// ---------------------------------------------------------------------------
// Pass 1 — headers
// ---------------------------------------------------------------------------

func (m *Masker) maskHeaders(ptr string, headers map[string]string, secrets *secretSet, rep *MaskReport) {
	if len(headers) == 0 {
		return
	}
	for _, name := range sortedKeys(headers) {
		value := headers[name]
		reason := headerRedactionReason(name, value)
		if reason == "" {
			continue
		}
		if value != RedactedPlaceholder {
			secrets.addHeader(name, value)
		}
		headers[name] = RedactedPlaceholder
		rep.HeadersRedacted++
		if reason != reasonDenylisted {
			rep.Anomalies = append(rep.Anomalies, Anomaly{
				Pointer: ptr + "/" + jsonPointerEscape(name),
				Reason:  reason,
			})
		}
	}
}

const reasonDenylisted = "denylisted header name"

// headerRedactionReason returns "" when the header may stay, or the reason it
// must be redacted. The two fail-closed rules are checked BEFORE the
// denylist, because a malformed name cannot be meaningfully compared against
// a denylist at all.
func headerRedactionReason(name, value string) string {
	if !isHTTPFieldName(name) {
		return "R1: header name is not an RFC 9110 field-name token, so it cannot be classified"
	}
	if strings.ContainsAny(value, "\r\n") {
		return "R2: header value contains CR or LF, which can smuggle a second header past a name-based denylist"
	}
	if isDenylistedHeader(name) {
		return reasonDenylisted
	}
	return ""
}

// isDenylistedHeader folds name to ASCII lowercase and applies both halves of
// the denylist. It assumes isHTTPFieldName(name) already passed, which is
// what makes plain ASCII folding sufficient: strings.EqualFold would apply
// Unicode case folding, under which U+212A KELVIN SIGN folds to "k", so
// "coo<U+212A>ie" would compare equal to "cookie" — harmless here, but the
// same mechanism in the other direction is how fold-based comparisons get
// bypassed. Non-ASCII names never reach this function.
func isDenylistedHeader(name string) bool {
	lower := asciiLower(name)
	for _, d := range denylistedHeaderNames {
		if lower == d {
			return true
		}
	}
	for _, sub := range denylistedHeaderSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// isHTTPFieldName reports whether name is a non-empty RFC 9110 §5.1 token:
// one or more tchar. Anything else — empty, whitespace-padded, control bytes,
// separators like ':' or ',', or any byte >= 0x80 — is unexpected shape.
func isHTTPFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTChar(name[i]) {
			return false
		}
	}
	return true
}

// isTChar reports whether c is an RFC 9110 §5.6.2 tchar.
func isTChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Pass 1 — parameters and the target URL
// ---------------------------------------------------------------------------

func (m *Masker) maskParameters(ptr string, params map[string]string, secrets *secretSet, rep *MaskReport) {
	if len(params) == 0 {
		return
	}
	for _, name := range sortedKeys(params) {
		value := params[name]
		var reason string
		switch {
		case name == "" || containsControl(name):
			reason = "R3: parameter name is empty or carries a control byte, so it cannot be classified"
		case isSensitiveParameter(name):
			// Not an anomaly: this is the rule working as designed.
		default:
			continue
		}
		if value != RedactedPlaceholder {
			secrets.add(value)
		}
		params[name] = RedactedPlaceholder
		rep.ParametersRedacted++
		if reason != "" {
			rep.Anomalies = append(rep.Anomalies, Anomaly{
				Pointer: ptr + "/" + jsonPointerEscape(name),
				Reason:  reason,
			})
		}
	}
}

func isSensitiveParameter(name string) bool {
	lower := asciiLower(strings.TrimSpace(name))
	for _, d := range sensitiveParameterNames {
		if lower == d {
			return true
		}
	}
	for _, sub := range sensitiveParameterSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// maskURL redacts secrets carried in webRequest.target: the userinfo
// password, the query string, and the fragment.
//
// The fragment is not an afterthought. OAuth 2.0's implicit flow returns
// `#access_token=...`, so a redirect captured by a DAST run can carry a live
// access token in the one part of a URL that never reaches the server and
// that a query-only masker ignores entirely.
//
// It works LEXICALLY, not through url.Parse plus re-encoding. Round-tripping
// a URL through net/url normalises percent-encoding, and for a DAST record
// the exact bytes of the target ARE the evidence: `%27%20OR%201%3D1` and
// `' OR 1=1` are the same URL and different findings. Only the bytes of a
// redacted value change.
func (m *Masker) maskURL(ptr, target string, secrets *secretSet, rep *MaskReport) string {
	if target == "" {
		return target
	}
	head, query, fragment, hasQuery, hasFragment := splitURL(target)
	head = maskUserinfoPassword(head, secrets, rep, ptr)
	if query != "" {
		masked, n := m.maskPairs(ptr+"/query", query, secrets, rep)
		query = masked
		rep.QueryValuesRedacted += n
	}
	// A fragment without '=' is an ordinary anchor and carries no pairs.
	if strings.Contains(fragment, "=") {
		masked, n := m.maskPairs(ptr+"/fragment", fragment, secrets, rep)
		fragment = masked
		rep.QueryValuesRedacted += n
	}
	// The delimiters are reinstated from splitURL's flags, never by scanning
	// the original target for '?' or '#'. `https://h/p#a?b=c` has a '?' that
	// belongs to the FRAGMENT, and rebuilding from a scan would invent a
	// query delimiter that was never there, silently rewriting the endpoint
	// the finding is about.
	out := head
	if hasQuery {
		out += "?" + query
	}
	if hasFragment {
		out += "#" + fragment
	}
	return out
}

// splitURL splits target into everything before the query, the raw query, and
// the raw fragment, without decoding anything. A '#' before a '?' means there
// is no query — the '?' is inside the fragment. The two bools distinguish an
// absent component from a present-but-empty one.
func splitURL(target string) (head, query, fragment string, hasQuery, hasFragment bool) {
	rest := target
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		fragment, hasFragment = rest[i+1:], true
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query, hasQuery = rest[i+1:], true
		rest = rest[:i]
	}
	return rest, query, fragment, hasQuery, hasFragment
}

// maskUserinfoPassword redacts the password half of `scheme://user:pass@host`.
// The username stays: it identifies which account the scan authenticated as,
// which is evidence. The password never is.
func maskUserinfoPassword(head string, secrets *secretSet, rep *MaskReport, ptr string) string {
	i := strings.Index(head, "//")
	if i < 0 {
		return head
	}
	authStart := i + 2
	authEnd := len(head)
	if j := strings.IndexByte(head[authStart:], '/'); j >= 0 {
		authEnd = authStart + j
	}
	authority := head[authStart:authEnd]
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return head
	}
	userinfo := authority[:at]
	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 {
		return head
	}
	pass := userinfo[colon+1:]
	if pass == "" || pass == RedactedPlaceholder {
		return head
	}
	secrets.add(pass)
	if dec, err := url.QueryUnescape(pass); err == nil {
		secrets.add(dec)
	}
	rep.QueryValuesRedacted++
	rep.Anomalies = append(rep.Anomalies, Anomaly{
		Pointer: ptr,
		Reason:  "credential carried in URL userinfo",
	})
	return head[:authStart] + userinfo[:colon+1] + RedactedPlaceholder + authority[at:] + head[authEnd:]
}

// maskPairs masks `name=value` pairs joined by '&', preserving the original
// bytes of every name and of every value it does not redact.
func (m *Masker) maskPairs(ptr, raw string, secrets *secretSet, rep *MaskReport) (string, int) {
	parts := strings.Split(raw, "&")
	n := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			// A bare flag with no value carries nothing to redact.
			continue
		}
		name, value := part[:eq], part[eq+1:]
		decoded, err := url.QueryUnescape(name)
		var reason string
		switch {
		case err != nil:
			reason = "R4: query/fragment pair name will not percent-decode, so it cannot be classified"
		case isSensitiveParameter(decoded):
			// Rule working as designed; not an anomaly.
		default:
			continue
		}
		if value != RedactedPlaceholder && value != "" {
			secrets.add(value)
			if dec, derr := url.QueryUnescape(value); derr == nil {
				secrets.add(dec)
			}
		}
		parts[i] = name + "=" + RedactedPlaceholder
		n++
		if reason != "" {
			rep.Anomalies = append(rep.Anomalies, Anomaly{Pointer: ptr, Reason: reason})
		}
	}
	return strings.Join(parts, "&"), n
}

// ---------------------------------------------------------------------------
// Pass 1 — reproduction command lines (`anvil/repro.curl`)
// ---------------------------------------------------------------------------

// Command-line option classes. Only options whose ARGUMENT can carry a
// credential are listed; everything else is left byte for byte, because a
// reproduction command is the evidence a human replays.
type cmdArgKind int

const (
	cmdArgNone cmdArgKind = iota
	cmdArgHeader
	cmdArgCookie
	cmdArgUser
	cmdArgData
)

// cmdLongOptions maps `--name` to what its argument is. `--proxy-header`
// carries a proxy Authorization as routinely as `--header` carries an
// Authorization.
var cmdLongOptions = map[string]cmdArgKind{
	"--header":         cmdArgHeader,
	"--proxy-header":   cmdArgHeader,
	"--cookie":         cmdArgCookie,
	"--user":           cmdArgUser,
	"--proxy-user":     cmdArgUser,
	"--data":           cmdArgData,
	"--data-raw":       cmdArgData,
	"--data-ascii":     cmdArgData,
	"--data-binary":    cmdArgData,
	"--data-urlencode": cmdArgData,
	"--form":           cmdArgData,
	"--form-string":    cmdArgData,
}

// cmdShortOptions maps the single-letter forms. curl allows the argument to be
// attached (`-HAuthorization: …`) or separate, and allows clustering, so both
// shapes are handled below.
var cmdShortOptions = map[byte]cmdArgKind{
	'H': cmdArgHeader,
	'b': cmdArgCookie,
	'u': cmdArgUser,
	'U': cmdArgUser,
	'd': cmdArgData,
	'F': cmdArgData,
}

// maskCommandLine redacts credentials carried in a reproduction command line.
//
// WHY THIS FIELD IS NOT OPTIONAL COVER. `anvil/repro.curl` is a full command
// the record invites a human to replay, and the thing that makes it replayable
// is precisely the credential: `-H 'Authorization: Bearer …'`, `-b
// 'session=…'`, `-u user:password`, or an API key in the URL. CRITIQUE-02 F3
// reproduced a live GitHub token surviving MaskRecord in exactly this field.
//
// It is NOT shape-based body scanning (which this file refuses to do, see the
// header): a curl command line is a STRUCTURED string with known credential
// positions — option flags — and structural masking is exactly what those are
// for. What is not an option argument or a URL is left alone.
//
// The command is re-emitted byte for byte apart from the values redacted:
// quoting, spacing and option order are all preserved, because a reproduction
// that has been "tidied" is a different experiment.
func (m *Masker) maskCommandLine(ptr, cmd string, secrets *secretSet, rep *MaskReport) string {
	if cmd == "" || !strings.ContainsAny(cmd, " \t") {
		// A single bare word cannot carry an option argument. A URL-only
		// value still goes through maskURL below, so only the truly empty and
		// the truly wordless short-circuit here.
		if !strings.Contains(cmd, "://") {
			return cmd
		}
	}

	pieces, isToken := splitCommandLine(cmd)
	expect := cmdArgNone

	for i, piece := range pieces {
		if !isToken[i] {
			continue
		}
		quote, body := unquoteToken(piece)

		if expect != cmdArgNone {
			pieces[i] = requoteToken(quote, m.maskQuotedArg(ptr, expect, body, secrets, rep))
			expect = cmdArgNone
			continue
		}

		switch {
		case strings.HasPrefix(body, "--"):
			name, value, hasValue := strings.Cut(body, "=")
			kind, ok := cmdLongOptions[asciiLower(name)]
			if !ok {
				continue
			}
			if !hasValue {
				expect = kind
				continue
			}
			pieces[i] = requoteToken(quote, name+"="+m.maskQuotedArg(ptr, kind, value, secrets, rep))

		case strings.HasPrefix(body, "-") && len(body) > 1:
			// A cluster like `-sSH`: scan for the first letter that takes an
			// argument. Anything after it on the same token IS that argument.
			for k := 1; k < len(body); k++ {
				kind, ok := cmdShortOptions[body[k]]
				if !ok {
					continue
				}
				if k+1 < len(body) {
					pieces[i] = requoteToken(quote,
						body[:k+1]+m.maskQuotedArg(ptr, kind, body[k+1:], secrets, rep))
				} else {
					expect = kind
				}
				break
			}

		case strings.Contains(body, "://"):
			pieces[i] = requoteToken(quote, m.maskURL(ptr+"/url", body, secrets, rep))
		}
	}
	return strings.Join(pieces, "")
}

// maskQuotedArg strips one layer of quoting the argument may carry in its own
// right — `--header="X-Api-Key: …"` and `-H'Authorization: …'` both put the
// quotes INSIDE the token, not around it — masks the contents, then puts the
// same quote pair back. Without this the closing quote is lost and the next
// pass tokenises the command differently, which is exactly the kind of drift
// that makes an idempotence-based gate unusable.
func (m *Masker) maskQuotedArg(ptr string, kind cmdArgKind, arg string, secrets *secretSet, rep *MaskReport) string {
	quote, body := unquoteToken(arg)
	return requoteToken(quote, m.maskCommandArg(ptr, kind, body, secrets, rep))
}

// maskCommandArg masks one option argument according to what the option is.
// It is idempotent: an argument already carrying RedactedPlaceholder is
// returned unchanged, which is what lets AssertMasked re-derive the masked
// form and compare.
//
// It never changes the WHITESPACE of what it keeps either. `-HAuthorization:X`
// rewritten as `-HAuthorization: ***REDACTED***` would introduce a space that
// splits the token in two on the next pass, so the original separator between
// the colon and the value is preserved verbatim.
func (m *Masker) maskCommandArg(ptr string, kind cmdArgKind, arg string, secrets *secretSet, rep *MaskReport) string {
	switch kind {
	case cmdArgHeader:
		colon := strings.IndexByte(arg, ':')
		if colon <= 0 {
			// R5: not a `Name: Value` header at all, so it cannot be
			// classified against the denylist. Redact the whole argument.
			if arg == RedactedPlaceholder {
				return arg
			}
			secrets.add(arg)
			rep.HeadersRedacted++
			rep.Anomalies = append(rep.Anomalies, Anomaly{
				Pointer: ptr,
				Reason:  "R5: -H/--header argument does not parse as `Name: Value`, so it cannot be classified",
			})
			return RedactedPlaceholder
		}
		name := strings.TrimSpace(arg[:colon])
		value := strings.TrimLeft(arg[colon+1:], " \t")
		// The bytes between the colon and the value, kept exactly.
		sep := arg[colon+1 : len(arg)-len(value)]
		reason := headerRedactionReason(name, value)
		if reason == "" {
			return arg
		}
		if value != RedactedPlaceholder {
			secrets.addHeader(name, value)
		}
		rep.HeadersRedacted++
		if reason != reasonDenylisted {
			rep.Anomalies = append(rep.Anomalies, Anomaly{
				Pointer: ptr + "/" + jsonPointerEscape(name),
				Reason:  reason,
			})
		}
		return arg[:colon+1] + sep + RedactedPlaceholder

	case cmdArgCookie:
		// `-b` takes either a cookie string or a file name. Only a cookie
		// string has crumbs, and a file name has no '=' in it.
		if !strings.Contains(arg, "=") || arg == RedactedPlaceholder {
			return arg
		}
		secrets.addHeader("cookie", arg)
		rep.HeadersRedacted++
		return RedactedPlaceholder

	case cmdArgUser:
		// `-u user:password`. The username stays — it identifies which account
		// the reproduction authenticates as, which is evidence.
		colon := strings.IndexByte(arg, ':')
		if colon < 0 {
			return arg // curl would prompt for the password; none is present
		}
		pass := arg[colon+1:]
		if pass == "" || pass == RedactedPlaceholder {
			return arg
		}
		secrets.add(pass)
		if dec, err := url.QueryUnescape(pass); err == nil {
			secrets.add(dec)
		}
		rep.QueryValuesRedacted++
		rep.Anomalies = append(rep.Anomalies, Anomaly{
			Pointer: ptr,
			Reason:  "credential carried in a -u/--user command-line argument",
		})
		return arg[:colon+1] + RedactedPlaceholder

	case cmdArgData:
		masked, n := m.maskPairs(ptr+"/data", arg, secrets, rep)
		rep.ParametersRedacted += n
		return masked
	}
	return arg
}

// splitCommandLine splits s into alternating separator and token pieces,
// preserving every byte: strings.Join(pieces, "") == s.
//
// It is a SPLITTER, not a shell. It does not expand variables, resolve
// backslash escapes or evaluate anything — it only needs to know where one
// argument ends and the next begins, and which bytes are a quote pair, so that
// a redacted value can be put back inside the same quotes.
func splitCommandLine(s string) (pieces []string, isToken []bool) {
	i := 0
	for i < len(s) {
		if isCmdSpace(s[i]) {
			start := i
			for i < len(s) && isCmdSpace(s[i]) {
				i++
			}
			pieces = append(pieces, s[start:i])
			isToken = append(isToken, false)
			continue
		}
		start := i
		var quote byte
		for i < len(s) {
			c := s[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
				i++
				continue
			}
			if isCmdSpace(c) {
				break
			}
			if c == '\'' || c == '"' {
				quote = c
			}
			i++
		}
		pieces = append(pieces, s[start:i])
		isToken = append(isToken, true)
	}
	return pieces, isToken
}

func isCmdSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// unquoteToken strips one matched pair of surrounding quotes and reports which
// quote byte it was, so requoteToken can put the same pair back.
func unquoteToken(tok string) (quote byte, body string) {
	if len(tok) >= 2 {
		q := tok[0]
		if (q == '\'' || q == '"') && tok[len(tok)-1] == q {
			return q, tok[1 : len(tok)-1]
		}
	}
	return 0, tok
}

func requoteToken(quote byte, body string) string {
	if quote == 0 {
		return body
	}
	return string(quote) + body + string(quote)
}

// ---------------------------------------------------------------------------
// Pass 2 — value propagation
// ---------------------------------------------------------------------------

// secretSet collects the literal values structural masking removed, plus the
// sub-values decomposed out of them.
//
// Decomposition matters. `Authorization: Bearer eyJhbGciOi...` is redacted as
// a whole, so the propagation set would contain "Bearer eyJhbGciOi..." — and
// an error page that echoes the raw token WITHOUT the scheme prefix would not
// match. Same for `Cookie: theme=dark; session=abc123`: the crumb the
// application echoes is `abc123`, not the whole header line.
type secretSet struct {
	minLen int
	seen   map[string]bool
}

func newSecretSet(minLen int) *secretSet {
	return &secretSet{minLen: minLen, seen: map[string]bool{}}
}

func (s *secretSet) add(v string) {
	v = strings.TrimSpace(v)
	if len(v) < s.minLen || v == RedactedPlaceholder {
		return
	}
	// A value that already contains the placeholder is a partially masked
	// string, not a secret.
	if strings.Contains(v, RedactedPlaceholder) {
		return
	}
	s.seen[v] = true
}

// addHeader adds the whole header value and its decomposed sub-values.
func (s *secretSet) addHeader(name, value string) {
	s.add(value)
	lower := asciiLower(name)
	switch {
	case lower == "authorization" || lower == "proxy-authorization":
		// `<scheme> <credentials>` — the credentials alone are what gets
		// echoed and logged.
		if i := strings.IndexByte(value, ' '); i > 0 {
			s.add(value[i+1:])
		}
	case lower == "cookie" || lower == "set-cookie":
		for _, crumb := range strings.Split(value, ";") {
			eq := strings.IndexByte(crumb, '=')
			if eq < 0 {
				continue
			}
			s.add(strings.Trim(strings.TrimSpace(crumb[eq+1:]), `"`))
		}
	}
	// A value carrying CR or LF is a smuggled header block (fail-closed rule
	// R2). Decompose it as one: `X-Trace: ok\r\nSet-Cookie: sid=live` hides
	// a real cookie whose crumb the application will echo back on its own,
	// without the `Set-Cookie:` prefix that the whole-value entry carries.
	// Splitting on CR/LF strips them, so the recursion terminates one level
	// down.
	if strings.ContainsAny(value, "\r\n") {
		for _, line := range strings.FieldsFunc(value, func(r rune) bool { return r == '\r' || r == '\n' }) {
			if c := strings.IndexByte(line, ':'); c > 0 {
				s.addHeader(strings.TrimSpace(line[:c]), strings.TrimSpace(line[c+1:]))
			}
		}
	}

	// Quoted values are echoed unquoted often enough to be worth adding.
	if unquoted := strings.Trim(value, `"`); unquoted != value {
		s.add(unquoted)
	}
}

// values returns the collected secrets sorted LONGEST FIRST, then
// lexicographically.
//
// Length ordering is required for correctness, not tidiness: if the set holds
// both `Bearer eyJ...` and `eyJ...`, replacing the short one first leaves
// `Bearer ***REDACTED***` and the long one can never match again. Replacing
// longest first collapses both to one placeholder. Lexicographic ordering
// within a length class makes the output deterministic, which a golden test
// can depend on.
func (s *secretSet) values() []string {
	out := make([]string, 0, len(s.seen))
	for v := range s.seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

var timeType = reflect.TypeOf(time.Time{})

// propagateSecrets replaces every occurrence of every collected secret, in
// every settable string anywhere in v, with RedactedPlaceholder. It returns
// the number of strings it changed.
//
// It walks by REFLECTION rather than by an enumerated field list on purpose.
// An enumerated list is auditable but goes stale the moment R.13 or the DAST
// area adds a string field to the contract, and the failure mode of a stale
// list is a secret surviving in the new field with nothing to indicate it.
// Reflection covers new fields the day they are added.
func propagateSecrets(v reflect.Value, secrets []string) int {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return 0
		}
		return propagateSecrets(v.Elem(), secrets)

	case reflect.Struct:
		// time.Time's fields are unexported and carry no attacker text.
		if v.Type() == timeType {
			return 0
		}
		n := 0
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" { // unexported
				continue
			}
			n += propagateSecrets(v.Field(i), secrets)
		}
		return n

	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return 0
		}
		n := 0
		for i := 0; i < v.Len(); i++ {
			n += propagateSecrets(v.Index(i), secrets)
		}
		return n

	case reflect.Map:
		if v.IsNil() {
			return 0
		}
		n := 0
		// Map values are not addressable, so each is copied into an
		// addressable temporary, walked, and written back. Keys are visited
		// in sorted order so the change count is deterministic.
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface())
		})
		for _, k := range keys {
			elem := reflect.New(v.Type().Elem()).Elem()
			elem.Set(v.MapIndex(k))
			if c := propagateSecrets(elem, secrets); c > 0 {
				v.SetMapIndex(k, elem)
				n += c
			}
		}
		return n

	case reflect.String:
		if !v.CanSet() {
			return 0
		}
		before := v.String()
		if before == "" {
			return 0
		}
		after := scrub(before, secrets)
		if after == before {
			return 0
		}
		v.SetString(after)
		return 1
	}
	return 0
}

// scrub replaces every occurrence of every secret in s with the placeholder.
func scrub(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, RedactedPlaceholder)
		}
	}
	return s
}

// ---------------------------------------------------------------------------
// Pass 3 — body caps and Tier-2 spill
// ---------------------------------------------------------------------------

// capBody truncates body to at most limit bytes TOTAL, including the
// truncation notice, and records the remainder as a spill.
//
// The remainder is never dropped: the notice carries a content-addressed
// reference to the full masked body, and MaskReport.Spills carries the bytes
// themselves for a caller that owns Tier-2 storage.
func (m *Masker) capBody(ptr string, body *ArtifactContent, limit int, rep *MaskReport) error {
	if body == nil || len(body.Text) <= limit {
		return nil
	}
	full := body.Text
	sum := sha256.Sum256([]byte(full))
	digest := "sha256:" + hex.EncodeToString(sum[:])

	sp := Spill{
		Pointer:    ptr,
		Ref:        digest,
		Sha256:     digest,
		TotalBytes: len(full),
		Content:    full,
	}
	if m.Spill != nil {
		ref, err := m.Spill(sp)
		if err != nil {
			return fmt.Errorf("record: spilling %s to a Tier-2 blob failed: %w", ptr, err)
		}
		if ref != "" {
			sp.Ref = ref
		}
	}

	// Size the notice against `limit` first. digits(n) <= digits(limit) for
	// every 0 <= n <= limit, so the notice built with the real inline count
	// is never longer than this estimate, and the final text is therefore
	// never longer than limit.
	budget := limit - len(truncationNotice(limit, len(full), sp.Ref))
	if budget < 0 {
		budget = 0
	}
	inline := truncateToRuneBoundary(full, budget)
	body.Text = inline + truncationNotice(len(inline), len(full), sp.Ref)

	sp.InlineBytes = len(inline)
	rep.Spills = append(rep.Spills, sp)
	rep.BodiesTruncated++
	return nil
}

// truncationNotice is the in-band Tier-2 pointer, in the shape research/18's
// annotated record uses ("…[truncated at 32768 bytes, full body at
// blobs/sha256:5c0d…]"). It is in-band because SARIF's artifactContent
// (§3.3) has no property bag to hang it on, and an out-of-band-only reference
// would leave a reader of the record with no indication that what they are
// reading is a prefix.
func truncationNotice(inlineBytes, totalBytes int, ref string) string {
	return "\n[anvil: body truncated at " + strconv.Itoa(inlineBytes) +
		" of " + strconv.Itoa(totalBytes) + " bytes; full masked body at " + ref + "]"
}

// truncateToRuneBoundary cuts s to at most n bytes without splitting a UTF-8
// rune. A split rune would make the record invalid JSON text in practice and
// would corrupt the last visible character of the evidence for no gain.
func truncateToRuneBoundary(s string, n int) string {
	if len(s) <= n {
		return s
	}
	b := s[:n]
	for len(b) > 0 {
		r, size := utf8.DecodeLastRuneInString(b)
		if r == utf8.RuneError && size <= 1 {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	return b
}

// ---------------------------------------------------------------------------
// Post-condition
// ---------------------------------------------------------------------------

// AssertMasked reports whether l satisfies R.8's post-condition: every site
// Mask is responsible for has already been masked, and no inline body exceeds
// its cap.
//
// plan/00-SPINE.md S7 is "enforce in code, not documentation". This is the
// enforceable half of it: a sink — the store writer, the prompt builder, the
// GitHub projection — can call it and refuse the record rather than trusting
// that some earlier step remembered to mask.
//
// IT COVERS EXACTLY WHAT Mask COVERS, AND THAT IS STRUCTURAL. It walks the
// same walkMaskSurface enumeration Mask does, and for the sites whose masking
// is a pure function of the field (URLs and command lines) it RE-DERIVES the
// masked form and demands the record already equal it. A gate that checked
// less than the masker is worse than no gate, because it manufactures the
// confidence it fails to justify — CRITIQUE-02 F4 found exactly that: Mask
// masked webRequest.target and AssertMasked did not, so a record whose only
// credential sat in a URL passed the check that exists to catch it.
//
// It does NOT prove the absence of secrets. It cannot: it does not know what
// the secrets were, and value propagation (pass 2) is not re-derivable from
// the masked record. It proves that the structural rules were applied, which
// is a necessary condition, not a sufficient one.
func AssertMasked(l *SARIFLog) error {
	if l == nil {
		return fmt.Errorf("record: AssertMasked got a nil *SARIFLog")
	}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	walkMaskSurface(l, surface{
		Headers: func(ptr string, h map[string]string) {
			note(assertHeadersMasked(ptr, h))
		},
		Parameters: func(ptr string, p map[string]string) {
			note(assertParametersMasked(ptr, p))
		},
		URL: func(ptr string, p *string) {
			note(assertURLMasked(ptr, *p))
		},
		CommandLine: func(ptr string, p *string) {
			note(assertCommandLineMasked(ptr, *p))
		},
		Body: func(ptr string, b *ArtifactContent, limit int) {
			note(assertBodyCapped(ptr, b, limit))
		},
	})
	return firstErr
}

// assertURLMasked re-derives what Mask would produce for this URL and refuses
// the record if it differs. maskURL is idempotent, so equality means "already
// masked" and inequality means "a userinfo password, a sensitive query
// parameter or a fragment token is still live in this field".
func assertURLMasked(ptr, target string) error {
	if masked := (&Masker{}).maskURL(ptr, target, newSecretSet(MinPropagatedSecretLen), &MaskReport{}); masked != target {
		return fmt.Errorf("record: %s still carries an unmasked credential in a URL "+
			"(userinfo password, sensitive query parameter, or fragment token); "+
			"R.8 masking must run before the store and before any model context", ptr)
	}
	return nil
}

// assertCommandLineMasked is assertURLMasked's twin for `anvil/repro.curl`.
// maskCommandLine is idempotent for the same reason, so any difference is a
// live credential sitting in an option argument.
func assertCommandLineMasked(ptr, cmd string) error {
	if masked := (&Masker{}).maskCommandLine(ptr, cmd, newSecretSet(MinPropagatedSecretLen), &MaskReport{}); masked != cmd {
		return fmt.Errorf("record: %s still carries an unmasked credential in a reproduction "+
			"command line (a header, cookie, user or data option argument); "+
			"R.8 masking must run before either sink", ptr)
	}
	return nil
}

func assertHeadersMasked(ptr string, headers map[string]string) error {
	for _, name := range sortedKeys(headers) {
		value := headers[name]
		if headerRedactionReason(name, value) == "" {
			continue
		}
		if value != RedactedPlaceholder {
			return fmt.Errorf("record: %s/%s is unmasked (%s); R.8 masking must run before the store and before any model context",
				ptr, jsonPointerEscape(name), headerRedactionReason(name, value))
		}
	}
	return nil
}

func assertParametersMasked(ptr string, params map[string]string) error {
	for _, name := range sortedKeys(params) {
		value := params[name]
		if name != "" && !containsControl(name) && !isSensitiveParameter(name) {
			continue
		}
		if value != RedactedPlaceholder {
			return fmt.Errorf("record: %s/%s is an unmasked sensitive parameter; R.8 masking must run before either sink",
				ptr, jsonPointerEscape(name))
		}
	}
	return nil
}

func assertBodyCapped(ptr string, body *ArtifactContent, limit int) error {
	if body == nil || len(body.Text) <= limit {
		return nil
	}
	return fmt.Errorf("record: %s is %d bytes, over the %d-byte inline cap; the remainder must spill to a Tier-2 blob",
		ptr, len(body.Text), limit)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// asciiLower folds A-Z only. See isDenylistedHeader for why Unicode folding
// is deliberately not used.
func asciiLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// containsControl reports whether s carries a C0 control byte or DEL.
func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// jsonPointerEscape applies RFC 6901 §3 escaping so a header name containing
// '/' or '~' produces a well-formed pointer.
func jsonPointerEscape(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}

// sortedKeys makes every map iteration in this file deterministic. Masking
// output that varies run to run cannot be golden-tested, and a masker nobody
// can pin is a masker nobody can prove.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
