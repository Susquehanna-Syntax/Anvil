// Package poller is Lane A step A.7: the authenticated conditional-GET poller.
//
// ===========================================================================
// WHAT THIS PACKAGE IS FOR
// ===========================================================================
//
// research/06 Recommendation item 1: "Change detection = authenticated
// conditional GET, on a per-feed configurable schedule. For each feed, store
// `etag` + `last_modified` + a monotonic `watermark`. Send `If-None-Match` /
// `If-Modified-Since` with a PAT. A 304 costs zero rate-limit budget *because*
// the request is authorized. Honour `x-poll-interval` when present."
//
// Every clause of that sentence is a code path below, and the reason each one
// exists is written at the code path rather than here.
//
// ===========================================================================
// THE THREE RULES THAT ARE NOT NEGOTIABLE
// ===========================================================================
//
//  1. NEVER SEND AN UNAUTHENTICATED REQUEST TO A GITHUB-HOSTED FEED.
//     research/06 Risk #8 and GitHub's own words: the 304 rate-limit exemption
//     is conditioned on being "correctly authorized with an Authorization
//     header", so an UNAUTHENTICATED 304 still costs one of the 60 requests an
//     hour an anonymous client gets. A poller that quietly drops the header on
//     the conditional path burns the budget on the requests that were supposed
//     to be free. See authorize and gitHubRateLimited.
//
//  2. NEVER FOLLOW A REDIRECT OFF THE CONFIGURED HOST, AND RE-VALIDATE SCOPE
//     ON EVERY HOP. plan/00-SPINE.md S7: "Re-validate scope on every request
//     including every redirect hop; never follow cross-host redirects." A feed
//     that 302s to an attacker's host turns a scheduled background fetch into
//     an SSRF with the feed's own credential attached, and Go's default client
//     follows up to ten redirects with no opinion about where they go. See
//     checkScope, which runs against the CONFIGURED URL — not against the
//     previous hop, because a chain of individually-small steps is still a
//     chain that lands somewhere else.
//
//  3. NEVER WRITE RAW FETCHED TEXT INTO THE CACHE. Two controls, in this
//     order, and the order is the point:
//
//     internal/ingest/license.Resolve (A.4) runs FIRST, BEFORE THE REQUEST IS
//     MADE. A feed whose licence evidence is absent is not fetched at all:
//     nothing may be written under mirror/, so spending a request — and a slice
//     of the rate-limit budget — on bytes that must then be discarded buys
//     nothing. It also means the poller can never be the component that
//     acquired data Anvil had no right to hold.
//
//     internal/ingest/sanitize (A.3) runs on every externally-sourced string
//     this package stores — the ETag, the Last-Modified value and the
//     watermark. See acceptHeaderValue for what "runs on" means here, which is
//     stricter than "was passed through": a value the sanitizer MODIFIED is
//     dropped rather than stored, because a modified ETag is not the server's
//     ETag and storing it would be a lie about what the feed said.
//
// ===========================================================================
// WHAT THIS PACKAGE DELIBERATELY DOES NOT DO
// ===========================================================================
//
//   - IT DOES NOT PARSE THE BODY AND IT WRITES NO ADVISORY ROW. A.8 (bootstrap)
//     and A.14 (delta) own that. The body leaves here inside a Payload, which
//     cannot be constructed without an admitted licence Decision and which
//     carries that decision's write-path check. THE OBLIGATION TRANSFERS WITH
//     IT: every string a consumer extracts from those bytes and binds to an
//     `advisory`, `affected` or `advisory_fts` column must go through
//     sanitize.Ingest first. internal/ingest/sanitize's writerguard_test.go is
//     what enforces that on the consumer, and it cannot enforce it from here.
//
//   - IT DOES NOT RUN GIT. config.SyncGitBloblessFetch is refused with
//     ErrMechanismNotHTTP. research/06 Risk #7 is about the shallow-clone trap
//     and A.8 owns the blobless clone; a `git fetch` reached from a poller
//     would be a second, unreviewed implementation of it.
//
//   - IT DOES NOT SCHEDULE. Poll is one poll. NextPollAfter is the answer to
//     "when may this feed be polled again", which is the caller's input to its
//     own scheduler, because a scheduler in here would need a cadence, and
//     every cadence lives in the feed table (research/06 Recommendation item 4).
//
//   - IT DOES NOT LOG. Like A.3, it returns what happened. A poller that wrote
//     to a global logger would be a poller that could log a token; see
//     "CREDENTIALS" below.
//
// ===========================================================================
// CREDENTIALS
// ===========================================================================
//
// A secret NEVER appears in this package's source, in an error, in a result, or
// in any String method. config.FeedConfig.CredentialEnv names an environment
// variable and CredentialSource reads it; the value goes into a header and
// nowhere else. Errors name the VARIABLE, never the value. poller_test.go
// sweeps every error and every rendered result for the fixture token and fails
// if one of them contains it.
//
// ===========================================================================
// NO FEED URL AND NO CADENCE IS WRITTEN IN GO HERE
// ===========================================================================
//
// internal/ingest/config owns the feed table and feeds_test.go asserts
// mechanically that feeds.go contains no feed URL, feed id, feed host or
// cadence literal. The same defect on the CONSUMING side would be just as
// fatal, so poller_test.go carries the same AST assertion against poller.go.
//
// It has exactly one documented exemption, gitHubRateLimitedDomains, and that
// exemption is the subject of its own assertion: those two literals may appear
// in that declaration and nowhere else. They are a fact about a PROVIDER's rate
// limiter that several feeds happen to share, not a fact about any feed — see
// the declaration.
package poller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

// Status is the typed outcome of one poll. It is the "typed 304-vs-200-vs-error
// result" A.7's expected output schema names.
//
// It is Lane-A-local vocabulary with no counterpart among the record contract's
// six frozen enums, so declaring it here does not violate the single-owner rule
// in plan/IMPLEMENTATION-PLAN.md section 6; it exists so that a caller switches
// on a constant rather than on an HTTP status code it re-derives.
type Status string

const (
	// StatusUpdated is a 200 with a body the caller may consume.
	StatusUpdated Status = "updated"

	// StatusNotModified is a 304: the feed has not changed, no body was read,
	// and nothing but last_ok_at moved in feed_state.
	StatusNotModified Status = "not_modified"

	// StatusRefused is ANVIL declining: the licence gate refused the feed, the
	// row would have sent an unauthenticated request to a rate-limited
	// provider, the response redirected off-host, the body exceeded the cap.
	// A refusal is a decision, not a fault in the network.
	StatusRefused Status = "refused"

	// StatusFailed is the fetch not working: a transport error, a timeout, an
	// unexpected HTTP status. It is the only status that means "try again
	// later on the feed's own terms".
	StatusFailed Status = "failed"
)

// StatusValues returns every legal Status, in declaration order.
func StatusValues() []Status {
	return []Status{StatusUpdated, StatusNotModified, StatusRefused, StatusFailed}
}

// Valid reports whether s is one of the four declared statuses.
func (s Status) Valid() bool {
	for _, v := range StatusValues() {
		if s == v {
			return true
		}
	}
	return false
}

// IntervalSource records WHY NextPollAfter has the value it has. A caller that
// cannot tell "the operator configured this" from "the server asked for this"
// cannot debug a feed that has gone quiet.
type IntervalSource string

const (
	// IntervalFromFeedTable means the value is config.FeedConfig.Interval().
	IntervalFromFeedTable IntervalSource = "feed_table"

	// IntervalFromServer means an x-poll-interval header asked for longer than
	// the configured cadence and was honoured (research/06 S2).
	IntervalFromServer IntervalSource = "x_poll_interval"

	// IntervalFromRetryAfter means a Retry-After header asked for longer than
	// the configured cadence and was honoured. It is not in A.7's packet text;
	// it is here because ignoring Retry-After on a 429 is how a client earns a
	// secondary rate limit, and research/06's rate-limit section is the reason
	// this package exists at all.
	IntervalFromRetryAfter IntervalSource = "retry_after"
)

// Header names. They are constants so that a misspelling is a compile error in
// one place rather than a silently absent conditional request.
const (
	headerETag            = "ETag"
	headerLastModified    = "Last-Modified"
	headerIfNoneMatch     = "If-None-Match"
	headerIfModifiedSince = "If-Modified-Since"
	headerPollInterval    = "X-Poll-Interval"
	headerRetryAfter      = "Retry-After"
	headerAuthorization   = "Authorization"
	headerUserAgent       = "User-Agent"
)

// bearerPrefix is the Authorization scheme used for a GitHub PAT or App
// installation token. The token itself is never in this file.
const bearerPrefix = "Bearer "

// gitHubRateLimitedDomains are the registrable domains whose rate limiter
// applies research/06 Risk #8: a 304 is free ONLY when the request carried an
// Authorization header, and costs one of 60 requests an hour when it did not.
//
// THIS IS THE ONE PLACE IN THIS FILE THAT NAMES A HOST, AND poller_test.go
// ASSERTS THAT IT IS THE ONLY ONE. The exemption is narrow and deliberate:
//
//   - It is a fact about a PROVIDER, not about a feed. Several rows in the feed
//     table are served from these domains and more will be; none of them is
//     named here, no URL is built from these strings, and no behaviour keys on
//     WHICH feed is being polled.
//   - It cannot come from the feed table, because the failure it prevents IS a
//     wrong feed table: a row that sets auth_mode: none on a GitHub-hosted URL
//     is exactly the mistake research/06 Risk #8 describes, and a check that
//     read the answer from the row being checked would agree with it.
//
// Matching is on the registrable domain or any subdomain of it, so a new GitHub
// content host needs no code change.
var gitHubRateLimitedDomains = []string{"github.com", "githubusercontent.com"}

// gitHubRateLimited reports whether host is served by the provider whose
// unauthenticated-304 penalty research/06 Risk #8 records.
func gitHubRateLimited(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range gitHubRateLimitedDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrPollRefused is the umbrella every REFUSAL satisfies: Anvil decided not
	// to make, continue or accept this request. It is separate from
	// ErrPollFailed because the two need different operator responses — a
	// refusal is fixed by changing configuration or acquiring evidence, a
	// failure is fixed by the network recovering.
	ErrPollRefused = errors.New("poller: refused")

	// ErrPollFailed is the umbrella every FETCH FAILURE satisfies.
	ErrPollFailed = errors.New("poller: fetch failed")

	// ErrNoCache reports a Poller built without the A.2 ingestion cache. There
	// is no in-memory fallback: a poll that cannot persist feed_state would
	// re-fetch the whole feed on every run, which is the cost conditional GET
	// exists to avoid.
	ErrNoCache = errors.New("poller: no ingestion cache")

	// ErrFeedDisabled reports a row with enabled: false. Polling it would
	// ignore the operator's switch.
	ErrFeedDisabled = errors.New("poller: feed is disabled")

	// ErrNotPolled reports config.SyncDerived or config.SyncNone —
	// SyncMechanism.Polled() is false. A derived feed's bytes arrive inside its
	// carrier's payload, so polling it would fetch a second copy of the same
	// data under a different licence record.
	ErrNotPolled = errors.New("poller: feed has no steady-state poll")

	// ErrMechanismNotHTTP reports config.SyncGitBloblessFetch. That mechanism
	// is a git fetch into an existing --filter=blob:none clone and belongs to
	// A.8; research/06 Risk #7 is explicit that it must never become a shallow
	// clone, and re-implementing it here is how a second version acquires a
	// different opinion about that.
	ErrMechanismNotHTTP = errors.New("poller: sync mechanism is not an HTTP poll")

	// ErrInsecureURL reports a feed URL this package will not fetch: a scheme
	// other than https, a missing host, or inline credentials. The loader
	// enforces the same rule at parse time; this is the check for a FeedConfig
	// that was built in Go and never went through the loader.
	ErrInsecureURL = errors.New("poller: feed URL is not a usable https endpoint")

	// ErrUnauthenticatedGitHub is research/06 Risk #8 enforced: a feed served
	// by a rate-limited provider declared auth_mode: none, so every conditional
	// request it makes — including the 304s — would consume the anonymous
	// 60/hour budget.
	ErrUnauthenticatedGitHub = errors.New("poller: rate-limited host polled without a credential")

	// ErrMissingCredential reports that the environment variable named by
	// credential_env is unset or empty. The variable is named in the error; the
	// value never is, because there is no value.
	ErrMissingCredential = errors.New("poller: credential environment variable is unset")

	// ErrMissingCredentialHeader reports auth_mode: api_key_header on a row
	// with no credential_header, so there is no header to put the key in.
	ErrMissingCredentialHeader = errors.New("poller: no credential header configured")

	// ErrUnknownAuthMode reports an auth_mode outside config.AuthModeValues().
	// Sending the request without a credential would be the fail-open answer.
	ErrUnknownAuthMode = errors.New("poller: unknown auth mode")

	// ErrCrossHostRedirect is spine S7 enforced: a redirect pointed at a host
	// other than the configured one and was NOT followed.
	ErrCrossHostRedirect = errors.New("poller: redirect leaves the configured host")

	// ErrScopeViolation is the rest of S7's per-hop re-validation: a scheme
	// change, a port change, or inline credentials appearing mid-chain.
	ErrScopeViolation = errors.New("poller: redirect leaves the configured scope")

	// ErrTooManyRedirects reports a chain longer than the configured cap.
	ErrTooManyRedirects = errors.New("poller: too many redirects")

	// ErrBodyTooLarge reports a response body over MaxBodyBytes. The read stops
	// at the cap; an unbounded ReadAll against a feed is a memory exhaustion
	// primitive handed to whoever controls the feed.
	ErrBodyTooLarge = errors.New("poller: response body exceeds the configured cap")

	// ErrUnexpectedStatus reports an HTTP status that is neither 200 nor 304.
	ErrUnexpectedStatus = errors.New("poller: unexpected HTTP status")

	// ErrTransport reports a request that never produced a response.
	ErrTransport = errors.New("poller: transport error")

	// ErrCacheWrite reports a failure to read or write feed_state.
	ErrCacheWrite = errors.New("poller: ingestion cache write failed")

	// ErrNoPayload reports Payload.Bytes called on a payload that carries no
	// admitted licence decision — including the zero Payload, whose zero
	// Decision would otherwise present as tier 0, the most permissive tier
	// there is. internal/ingest/license's Decision.ManifestRow returns an error
	// for exactly this reason and this is the same defence one layer out.
	ErrNoPayload = errors.New("poller: payload carries no admitted licence decision")

	// ErrWatermark reports a Watermarker that failed or that tried to move the
	// request off the configured endpoint.
	ErrWatermark = errors.New("poller: watermark hook refused")
)

// refuse builds a refusal. Every refusal satisfies ErrPollRefused as well as
// its own sentinel, so a caller switching on the umbrella never sees one leak
// past as an unrecognised error.
func refuse(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrPollRefused, sentinel, fmt.Sprintf(format, args...))
}

// fail builds a fetch failure, with the same umbrella property.
func fail(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrPollFailed, sentinel, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

// CredentialSource resolves the environment variable a feed row NAMES into the
// secret it holds.
//
// It is an interface for one reason: a test must never read a real environment.
// The GitHub PAT is ops-provisioned; nothing in this repository creates one,
// and nothing in a test may depend on one being present.
type CredentialSource interface {
	// Credential returns the value of the named environment variable and
	// whether it was set. Implementations must not log, echo or persist it.
	Credential(envName string) (value string, ok bool)
}

// EnvCredentials reads the process environment. It is the production
// implementation and it is the only one in this repository that touches os.
type EnvCredentials struct{}

// Credential implements CredentialSource against the process environment.
func (EnvCredentials) Credential(envName string) (string, bool) {
	return os.LookupEnv(envName)
}

// Response is what a Watermarker sees after a successful fetch. It is a
// narrowed view of the HTTP response: enough to advance a cursor, not enough to
// make a second request.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Watermarker is the hook config.SyncWatermarkAPI needs, and the reason it is
// an injected interface rather than code in this file is A.1's rule: a
// watermark is a FEED-SPECIFIC cursor — an NVD lastModStartDate window, a page
// token, a delta filename — and a poller that knew how to build one would know
// which feed it was polling. That is a hard-coded feed table wearing a
// different hat.
//
// A nil Watermarker means the URL is used verbatim and the stored watermark is
// carried forward unchanged, which is correct for every mechanism except
// config.SyncWatermarkAPI and is refused for that one.
type Watermarker interface {
	// Apply returns the URL to fetch for a stored cursor. It MUST NOT change
	// the host, scheme or port: the result is re-validated against the
	// configured endpoint and a hook that moves it is refused, because a hook
	// that could relocate the request would be a way around checkScope.
	Apply(feed config.FeedConfig, watermark string, u *url.URL) (*url.URL, error)

	// Advance returns the cursor to store after a successful fetch.
	Advance(feed config.FeedConfig, previous string, resp Response) (string, error)
}

// ---------------------------------------------------------------------------
// Poller
// ---------------------------------------------------------------------------

// Options configures a Poller. Every field is optional except DB.
type Options struct {
	// DB is the A.2 ingestion cache, already migrated. It is NOT
	// internal/store: the two are separate database files opened by separate
	// packages, and only feed_state is written here.
	DB *sql.DB

	// Mirror is the filesystem A.4's licence evidence is read from, rooted
	// where mirror/ sits. Nil means os.DirFS("."). Tests pass an fstest.MapFS
	// and nothing in the licence gate opens a network connection.
	Mirror fs.FS

	// Transport is the HTTP transport. Nil means http.DefaultTransport. Tests
	// pass an httptest server's transport; this package never constructs a
	// client that could reach the real internet from a test.
	Transport http.RoundTripper

	// Credentials resolves credential_env. Nil means EnvCredentials.
	Credentials CredentialSource

	// Now is the clock. Nil means time.Now. It is injected so that last_ok_at
	// is assertable rather than approximately assertable.
	Now func() time.Time

	// MaxBodyBytes caps a single response body. Zero means
	// DefaultMaxBodyBytes. It is a client safety limit and not a per-feed fact,
	// which is why it is here and not in the feed table.
	MaxBodyBytes int64

	// MaxRedirects caps the redirect chain. Zero means DefaultMaxRedirects.
	// Every hop is scope-checked regardless of the cap; the cap only bounds a
	// same-host redirect loop.
	MaxRedirects int

	// UserAgent is sent on every request. Empty means DefaultUserAgent.
	UserAgent string

	// Watermarks is the config.SyncWatermarkAPI hook. Nil is legal and makes
	// that mechanism a refusal rather than a silent no-op.
	Watermarks Watermarker

	// MetadataSPDX reports what a registry or forge API says about a feed's
	// licence, or "" if nobody asked one. A.4 never trusts it: a value that
	// disagrees with the row's declaration makes spine S8's manual note
	// mandatory, which is the CISA KEV case. Nil means "nobody asked".
	MetadataSPDX func(config.FeedConfig) string
}

// Defaults for the Options fields that have them.
const (
	// DefaultMaxBodyBytes is 1 GiB. research/06 S8 measured the largest
	// artifact Lane A fetches at 570,845,537 bytes (the cvelistV5 midnight
	// baseline), so this is under 2x headroom over the real worst case and
	// still three orders of magnitude below a memory-exhaustion payload.
	DefaultMaxBodyBytes int64 = 1 << 30

	// DefaultMaxRedirects bounds a same-host chain. Cross-host hops are refused
	// outright and do not consume it.
	DefaultMaxRedirects = 5

	// DefaultUserAgent identifies Anvil to a feed operator. It names no feed
	// and no version of anything that would need updating in two places.
	DefaultUserAgent = "anvil-ingest"

	// maxStoredHeaderBytes bounds an ETag or Last-Modified value before it is
	// considered for storage. A feed that answers with a megabyte-long ETag is
	// not answering with an ETag.
	maxStoredHeaderBytes = 512

	// timeLayout is the on-disk format for feed_state.last_ok_at.
	//
	// It is fixed-width for the reason internal/handoff/state_machine.go
	// records at its own timeLayout: time.RFC3339Nano trims trailing zeros from
	// the fractional part, so "10:00:00Z" sorts AFTER "10:00:00.5Z" under
	// lexicographic comparison and any SQL that compared these as TEXT would
	// mis-order them. Nothing here relies on that, and a later index range scan
	// over last_ok_at would also be correct.
	timeLayout = "2006-01-02T15:04:05.000000000Z"
)

// Poller polls feeds. It is safe for concurrent use by multiple goroutines: it
// holds no per-poll mutable state, and the redirect policy that needs per-poll
// state is a closure created inside Poll.
type Poller struct {
	db           *sql.DB
	mirror       fs.FS
	transport    http.RoundTripper
	creds        CredentialSource
	now          func() time.Time
	maxBody      int64
	maxRedirects int
	userAgent    string
	watermarks   Watermarker
	metadataSPDX func(config.FeedConfig) string
}

// New builds a Poller. The only hard requirement is the ingestion cache.
func New(opts Options) (*Poller, error) {
	if opts.DB == nil {
		return nil, fmt.Errorf("%w: a poll that cannot persist feed_state cannot make a conditional request", ErrNoCache)
	}
	p := &Poller{
		db:           opts.DB,
		mirror:       opts.Mirror,
		transport:    opts.Transport,
		creds:        opts.Credentials,
		now:          opts.Now,
		maxBody:      opts.MaxBodyBytes,
		maxRedirects: opts.MaxRedirects,
		userAgent:    opts.UserAgent,
		watermarks:   opts.Watermarks,
		metadataSPDX: opts.MetadataSPDX,
	}
	if p.transport == nil {
		p.transport = http.DefaultTransport
	}
	if p.creds == nil {
		p.creds = EnvCredentials{}
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.maxBody <= 0 {
		p.maxBody = DefaultMaxBodyBytes
	}
	if p.maxRedirects <= 0 {
		p.maxRedirects = DefaultMaxRedirects
	}
	if p.userAgent == "" {
		p.userAgent = DefaultUserAgent
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// Payload — a body that cannot be separated from the licence that admitted it
// ---------------------------------------------------------------------------

// Payload is a fetched body bound to the licence Decision that admitted it.
//
// It exists so that a body and its licence cannot drift apart between here and
// A.8/A.14. A consumer that wants the bytes has to hold the decision, and the
// decision is what answers "where may this be written" — CheckWritePath is the
// second half of the tier 2 quarantine and it is right here on the value the
// caller is about to write.
//
// The zero Payload yields ErrNoPayload rather than nil bytes and a tier 0
// decision.
type Payload struct {
	decision license.Decision
	body     []byte
	sha256   string
}

// Decision returns the licence decision the body was admitted under.
func (p *Payload) Decision() license.Decision {
	if p == nil {
		return license.Decision{Tier: config.LicenseTier(license.NoTier)}
	}
	return p.decision
}

// Bytes returns the fetched body.
//
// It returns an error rather than nil bytes when the payload carries no
// admitted decision, because "no bytes" and "bytes nobody may keep" are
// different facts and a caller that cannot tell them apart writes the second
// one to disk.
func (p *Payload) Bytes() ([]byte, error) {
	if p == nil || p.decision.Refused() {
		return nil, refuse(ErrNoPayload,
			"the licence decision behind this payload is a refusal (or absent), so the bytes may not be used")
	}
	return p.body, nil
}

// Len returns the body length in bytes, and 0 for a nil payload.
func (p *Payload) Len() int {
	if p == nil {
		return 0
	}
	return len(p.body)
}

// SHA256 returns the lowercase hex digest of the body, for a consumer that
// wants to skip re-parsing an artifact it already ingested.
func (p *Payload) SHA256() string {
	if p == nil {
		return ""
	}
	return p.sha256
}

// CheckWritePath refuses any path outside the directory this payload's licence
// decision admits. It delegates to the decision, so there is one definition of
// the quarantine and it lives in A.4.
func (p *Payload) CheckWritePath(path string) error {
	if p == nil || p.decision.Refused() {
		return refuse(ErrNoPayload, "no admitted licence decision, so no write path is permitted")
	}
	return p.decision.CheckWritePath(path)
}

// ---------------------------------------------------------------------------
// PollResult
// ---------------------------------------------------------------------------

// PollResult is what one poll did. It is returned even on an error, because
// "what did we do before it went wrong" is the question an operator asks first
// — how many requests were made, what state was written, whether the feed was
// ever contacted.
type PollResult struct {
	// FeedID echoes the row polled.
	FeedID string

	// Status is the typed outcome.
	Status Status

	// HTTPStatus is the final response's status code, or 0 if no response was
	// received (including every refusal made before the request).
	HTTPStatus int

	// Requests is how many HTTP requests were actually issued: one, plus one
	// for each redirect FOLLOWED. A refused redirect is not counted, because it
	// was not made.
	Requests int

	// ETag, LastModified and Watermark are the values now in feed_state. On a
	// 304 they are the values that were already there.
	ETag         string
	LastModified string
	Watermark    string

	// LastOKAt is the last_ok_at now stored, and is the zero time when the poll
	// did not succeed.
	LastOKAt time.Time

	// ConsecutiveFailures is the counter now in feed_state.
	ConsecutiveFailures int

	// StateWritten reports whether feed_state was touched at all. It is false
	// for every refusal made before a request went out.
	StateWritten bool

	// BodyBytes is how many bytes were read from the response body. IT IS
	// ALWAYS ZERO ON A 304, and poller_test.go proves that by counting Read
	// calls on the response body rather than by trusting this field.
	BodyBytes int64

	// Payload is the fetched body bound to its licence decision, and is nil for
	// every outcome except StatusUpdated.
	Payload *Payload

	// Decision is A.4's licence decision for this feed. It is the gate's
	// conclusion, and feed_state.license_tier is written from it rather than
	// from the row's own claim.
	Decision license.Decision

	// Sanitize is the merged A.3 report over every externally-sourced string
	// this poll considered storing.
	Sanitize sanitize.SanitizeStats

	// HeaderRejected counts response header values that were DROPPED rather
	// than stored: sanitizer-modified, malformed, or over the length cap. A
	// non-zero value on a feed that should have an ETag means the next poll
	// will be unconditional, which is worth an operator's attention.
	HeaderRejected int

	// NextPollAfter is the shortest delay before this feed may be polled again,
	// and IntervalSource says where the number came from.
	NextPollAfter      time.Duration
	IntervalSource     IntervalSource
	IntervalCapped     bool
	ServerPollInterval time.Duration
}

// ---------------------------------------------------------------------------
// Poll
// ---------------------------------------------------------------------------

// Poll performs one poll of one feed.
//
// It is A.7's `Poll(ctx, feed FeedConfig) (PollResult, error)`; the
// dependencies that signature has no room for — the cache, the clock, the
// transport, the credential source — live on the receiver, so that no call site
// can supply a different one per call and no default can be reached by
// accident.
//
// THE ORDER OF WHAT FOLLOWS IS THE CONTRACT:
//
//  1. the row is checked for pollability            (no I/O)
//  2. the URL is checked for scope                  (no I/O)
//  3. A.4's licence gate runs                       (reads the mirror FS)
//  4. feed_state is read                            (reads the cache)
//  5. the request is built and authorized           (reads the environment)
//  6. the request is made, every hop scope-checked  (network)
//  7. what is stored is sanitized, then stored      (writes the cache)
//
// Steps 1-3 are all refusals-before-any-request. Nothing before step 6 can
// consume a rate-limit budget and nothing before step 7 can write.
//
// A non-nil error is returned with a populated PollResult, never instead of one.
func (p *Poller) Poll(ctx context.Context, feed config.FeedConfig) (PollResult, error) {
	res := PollResult{
		FeedID:         feed.ID,
		Status:         StatusRefused,
		NextPollAfter:  feed.Interval(),
		IntervalSource: IntervalFromFeedTable,
		Decision:       license.Decision{Tier: config.LicenseTier(license.NoTier)},
	}

	if err := checkPollable(feed); err != nil {
		return res, err
	}
	target, err := parseFeedURL(feed)
	if err != nil {
		return res, err
	}

	// A.4 BEFORE THE NETWORK. See the package comment: a feed whose licence
	// evidence is absent is not fetched, because the bytes could not be kept
	// and the request would still have cost budget.
	decision, err := p.resolveLicense(feed)
	if err != nil {
		return res, err
	}
	res.Decision = decision

	st, err := p.readState(ctx, feed.ID)
	if err != nil {
		res.Status = StatusFailed
		return res, err
	}
	res.ETag, res.LastModified, res.Watermark = st.etag, st.lastModified, st.watermark
	res.ConsecutiveFailures = st.failures

	req, err := p.buildRequest(ctx, feed, target, st)
	if err != nil {
		return res, err
	}

	hops := 0
	client := &http.Client{
		Transport:     p.transport,
		CheckRedirect: p.redirectPolicy(feed.ID, target, req.Header.Clone(), &hops),
	}
	hops = 1
	resp, err := client.Do(req)
	res.Requests = hops
	if err != nil {
		return p.finishFailure(ctx, feed, decision, st, &res, err)
	}
	defer func() { _ = resp.Body.Close() }()
	res.HTTPStatus = resp.StatusCode
	p.applyServerInterval(feed, resp, &res)

	switch resp.StatusCode {
	case http.StatusNotModified:
		// EXIT CRITERION 3: a 304 reads NOTHING. The body is not touched, not
		// discarded through io.Copy, not measured — the response is closed
		// unread, which is the only version of "zero body bytes" that is true
		// rather than approximately true.
		return p.finishNotModified(ctx, feed, decision, st, &res)
	case http.StatusOK:
		return p.finishUpdated(ctx, feed, decision, st, &res, resp)
	default:
		return p.finishFailure(ctx, feed, decision, st, &res,
			fail(ErrUnexpectedStatus, "feed %q answered %s", feed.ID, resp.Status))
	}
}

// checkPollable refuses the rows that must not be polled at all. Every check is
// a fact from the feed table, which is where all of them belong.
func checkPollable(feed config.FeedConfig) error {
	if !feed.Enabled {
		return refuse(ErrFeedDisabled, "feed %q is switched off in the feed table", feed.ID)
	}
	if !feed.SyncMechanism.Valid() {
		return refuse(ErrNotPolled, "feed %q declares sync mechanism %q, which is not one of %v",
			feed.ID, string(feed.SyncMechanism), config.SyncMechanismValues())
	}
	if !feed.SyncMechanism.Polled() {
		return refuse(ErrNotPolled,
			"feed %q declares sync mechanism %q, which carries no steady-state poll",
			feed.ID, string(feed.SyncMechanism))
	}
	if feed.SyncMechanism == config.SyncGitBloblessFetch {
		return refuse(ErrMechanismNotHTTP,
			"feed %q declares %q; the blobless clone and its fetch belong to the bootstrap step, not to an HTTP poller",
			feed.ID, string(config.SyncGitBloblessFetch))
	}
	return nil
}

// parseFeedURL validates the configured endpoint. config.checkURL applies the
// same rule at parse time; this is the check for a FeedConfig assembled in Go.
func parseFeedURL(feed config.FeedConfig) (*url.URL, error) {
	if strings.TrimSpace(feed.URL) == "" {
		return nil, refuse(ErrInsecureURL, "feed %q has no url", feed.ID)
	}
	u, err := url.Parse(feed.URL)
	if err != nil {
		return nil, refuse(ErrInsecureURL, "feed %q has an unparseable url: %v", feed.ID, err)
	}
	if err := checkEndpoint(feed.ID, u); err != nil {
		return nil, err
	}
	return u, nil
}

// checkEndpoint is the scope rule applied to ONE url: https, a host, and no
// inline credentials. It runs on the configured URL and on every redirect
// target, so a hop cannot reach a shape the configured URL could not have had.
func checkEndpoint(feedID string, u *url.URL) error {
	if !strings.EqualFold(u.Scheme, "https") {
		return refuse(ErrInsecureURL,
			"feed %q uses scheme %q; feed transport is https only, so a downgrade cannot be configured or redirected into",
			feedID, u.Scheme)
	}
	if u.Host == "" {
		return refuse(ErrInsecureURL, "feed %q has no host", feedID)
	}
	if u.User != nil {
		return refuse(ErrInsecureURL,
			"feed %q carries inline credentials in its url; the only place a credential may live is the environment variable named by credential_env",
			feedID)
	}
	return nil
}

// resolveLicense runs A.4 and converts its refusal into a poll refusal that
// still satisfies license.ErrLicenseRefused, so a caller may switch on either.
//
// THE ADMISSION PATH OF THAT GATE IS NOT TRUSTWORTHY AND IT CURRENTLY ADMITS
// NOTHING: no publisher licence body has been acquired into mirror/, so every
// pin is empty and every feed is refused. That is not a bug to work around here
// — it is the fail-closed state A.6 designed, and this poller is inert until an
// operator runs license.AcquireCommand. Nothing below assumes admission.
func (p *Poller) resolveLicense(feed config.FeedConfig) (license.Decision, error) {
	metadata := ""
	if p.metadataSPDX != nil {
		metadata = p.metadataSPDX(feed)
	}
	d, err := license.Resolve(license.FromFeed(feed, metadata, p.mirror))
	if err != nil {
		return d, fmt.Errorf("%w: %w: feed %q was not admitted, so it is not fetched: %s",
			ErrPollRefused, err, feed.ID, license.AcquireCommand)
	}
	if d.Refused() {
		return d, refuse(license.ErrLicenseRefused,
			"feed %q produced a decision that is a refusal (tier %d, dir %q)", feed.ID, d.Tier.Int(), d.Dir)
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

// buildRequest assembles the conditional GET: the watermark hook, the
// conditional headers the row's sync mechanism calls for, and the credential.
//
// AUTHORIZATION IS APPLIED UNCONDITIONALLY, on this request and on every
// redirect hop, whether or not the request is expected to 304. That is
// research/06 Risk #8 and it is the whole reason this function exists rather
// than a bare http.NewRequest at the call site.
func (p *Poller) buildRequest(ctx context.Context, feed config.FeedConfig, target *url.URL, st feedState) (*http.Request, error) {
	u := target
	if feed.SyncMechanism == config.SyncWatermarkAPI {
		var err error
		u, err = p.applyWatermark(feed, st.watermark, target)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, refuse(ErrInsecureURL, "feed %q: %v", feed.ID, err)
	}
	req.Header.Set(headerUserAgent, p.userAgent)

	switch feed.SyncMechanism {
	case config.SyncConditionalGetETag:
		if st.etag != "" {
			req.Header.Set(headerIfNoneMatch, st.etag)
		}
	case config.SyncConditionalGetLastModified:
		if st.lastModified != "" {
			req.Header.Set(headerIfModifiedSince, st.lastModified)
		}
	case config.SyncWatermarkAPI:
		// The cursor is in the URL the hook built. A watermark feed that also
		// carries validators gets both, because an extra conditional header
		// costs nothing and a 304 is the cheapest possible answer.
		if st.etag != "" {
			req.Header.Set(headerIfNoneMatch, st.etag)
		}
		if st.lastModified != "" {
			req.Header.Set(headerIfModifiedSince, st.lastModified)
		}
	}

	if err := p.authorize(req, feed); err != nil {
		return nil, err
	}
	return req, nil
}

// applyWatermark runs the injected hook and re-validates its result. A hook
// that relocated the request would be a way around checkScope, so its output is
// checked exactly as a redirect target is.
func (p *Poller) applyWatermark(feed config.FeedConfig, watermark string, target *url.URL) (*url.URL, error) {
	if p.watermarks == nil {
		return nil, refuse(ErrWatermark,
			"feed %q declares %q but no watermark hook was supplied; the cursor's shape is a per-feed fact and this package does not know it",
			feed.ID, string(config.SyncWatermarkAPI))
	}
	u, err := p.watermarks.Apply(feed, watermark, cloneURL(target))
	if err != nil {
		return nil, refuse(ErrWatermark, "feed %q: watermark hook failed: %v", feed.ID, err)
	}
	if u == nil {
		return nil, refuse(ErrWatermark, "feed %q: watermark hook returned no url", feed.ID)
	}
	if err := checkEndpoint(feed.ID, u); err != nil {
		return nil, err
	}
	if err := sameOrigin(feed.ID, target, u); err != nil {
		return nil, err
	}
	return u, nil
}

// authorize applies the row's credential mechanism, and refuses the two shapes
// that must never reach the network.
//
// The secret is read here and written into a header here. It is not returned,
// not stored on the Poller, and not named in any error: every error below names
// the ENVIRONMENT VARIABLE, which is what an operator needs and what a log may
// safely carry.
func (p *Poller) authorize(req *http.Request, feed config.FeedConfig) error {
	host := req.URL.Hostname()
	switch feed.AuthMode {
	case config.AuthNone:
		// research/06 Risk #8. An unauthenticated conditional request against
		// this provider costs one of 60 an hour EVEN WHEN IT 304s, so a row
		// configured this way does not get to make the request.
		if gitHubRateLimited(host) {
			return refuse(ErrUnauthenticatedGitHub,
				"feed %q is served by a host whose 304 responses are only free when the request was authorized, but the row declares auth_mode %q; set %q and name the credential environment variable",
				feed.ID, string(config.AuthNone), string(config.AuthGitHubToken))
		}
		return nil

	case config.AuthGitHubToken:
		token, err := p.credential(feed)
		if err != nil {
			return err
		}
		req.Header.Set(headerAuthorization, bearerPrefix+token)
		return nil

	case config.AuthAPIKeyHeader:
		if feed.CredentialHeader == "" {
			return refuse(ErrMissingCredentialHeader,
				"feed %q declares auth_mode %q with no credential_header, so there is no header to carry the key",
				feed.ID, string(config.AuthAPIKeyHeader))
		}
		key, err := p.credential(feed)
		if err != nil {
			return err
		}
		req.Header.Set(feed.CredentialHeader, key)
		return nil

	default:
		return refuse(ErrUnknownAuthMode,
			"feed %q declares auth_mode %q, which is not one of %v; sending the request without a credential would be the fail-open answer",
			feed.ID, string(feed.AuthMode), config.AuthModeValues())
	}
}

// credential resolves the row's credential_env. The value is returned to
// exactly one caller and put into exactly one header.
func (p *Poller) credential(feed config.FeedConfig) (string, error) {
	if feed.CredentialEnv == "" {
		return "", refuse(ErrMissingCredential,
			"feed %q declares auth_mode %q with no credential_env, so there is nothing to read the secret from",
			feed.ID, string(feed.AuthMode))
	}
	v, ok := p.creds.Credential(feed.CredentialEnv)
	if !ok || v == "" {
		return "", refuse(ErrMissingCredential,
			"feed %q: environment variable %s is unset or empty; the credential is provisioned by the operator and is never created by Anvil",
			feed.ID, feed.CredentialEnv)
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Redirects — spine S7
// ---------------------------------------------------------------------------

// redirectPolicy builds the CheckRedirect closure for one poll.
//
// EVERY HOP IS CHECKED AGAINST THE CONFIGURED ENDPOINT, not against the
// previous hop. Checking against the previous hop would accept a chain of
// individually-legal steps that ends somewhere the feed table never named, and
// "each step looked fine" is precisely how a redirect chain becomes an SSRF.
//
// The authorization headers are re-asserted on every hop that is allowed to
// proceed. Go's client already carries them across a same-host redirect, and a
// cross-host one is refused before this line is reached — so this is belt and
// braces, and it is also what makes "every request carries Authorization"
// something poller_test.go can observe on the wire rather than infer.
func (p *Poller) redirectPolicy(feedID string, configured *url.URL, authHeaders http.Header, hops *int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > p.maxRedirects {
			return refuse(ErrTooManyRedirects,
				"feed %q: redirect chain reached %d hops, over the cap of %d", feedID, len(via), p.maxRedirects)
		}
		if err := checkEndpoint(feedID, req.URL); err != nil {
			return err
		}
		if err := sameOrigin(feedID, configured, req.URL); err != nil {
			return err
		}
		for _, name := range []string{headerAuthorization} {
			if v := authHeaders.Get(name); v != "" && req.Header.Get(name) == "" {
				req.Header.Set(name, v)
			}
		}
		for name, vals := range authHeaders {
			if name == headerAuthorization || name == headerUserAgent {
				continue
			}
			if len(vals) > 0 && req.Header.Get(name) == "" {
				req.Header.Set(name, vals[0])
			}
		}
		*hops++
		return nil
	}
}

// sameOrigin refuses any move off the configured origin: a different host, a
// different scheme, or a different effective port. Comparison is on the
// HOSTNAME and the EFFECTIVE PORT, so "example.org" and "example.org:443" are
// the same origin and "example.org" and "evil.example.org" are not.
func sameOrigin(what string, configured, next *url.URL) error {
	if !strings.EqualFold(next.Hostname(), configured.Hostname()) {
		return refuse(ErrCrossHostRedirect,
			"%s: configured host is %q and the response points at %q; a cross-host redirect is never followed",
			what, configured.Hostname(), next.Hostname())
	}
	if !strings.EqualFold(next.Scheme, configured.Scheme) {
		return refuse(ErrScopeViolation,
			"%s: configured scheme is %q and the response points at %q",
			what, configured.Scheme, next.Scheme)
	}
	if effectivePort(next) != effectivePort(configured) {
		return refuse(ErrScopeViolation,
			"%s: configured port is %q and the response points at %q",
			what, effectivePort(configured), effectivePort(next))
	}
	if next.User != nil {
		return refuse(ErrScopeViolation, "%s: the response points at a url carrying inline credentials", what)
	}
	return nil
}

// effectivePort returns the port a URL actually connects to, filling in the
// scheme default so that an explicit :443 and an absent port compare equal.
func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if p, err := net.LookupPort("tcp", u.Scheme); err == nil {
		return strconv.Itoa(p)
	}
	return ""
}

// cloneURL copies a URL so a hook cannot mutate the configured one.
func cloneURL(u *url.URL) *url.URL {
	c := *u
	if u.User != nil {
		user := *u.User
		c.User = &user
	}
	return &c
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

// finishNotModified handles a 304: the previous validators and watermark are
// re-written unchanged and last_ok_at advances.
//
// consecutive_failures is RESET, and that is a reading of exit criterion 3
// worth stating rather than burying. The criterion says a 304 must leave
// advisory/affected/advisory_fts byte-identical and "move nothing but
// last_ok_at" — which it does not: a 304 is a SUCCESSFUL poll, the feed
// answered, and leaving a stale failure streak in place would keep a healthy
// feed looking broken to whatever backs off on that counter. The three columns
// the criterion is about — the two validators and the watermark — are written
// back with the values that were already there.
func (p *Poller) finishNotModified(ctx context.Context, feed config.FeedConfig, d license.Decision, st feedState, res *PollResult) (PollResult, error) {
	now := p.now().UTC()
	next := st
	next.lastOKAt = now
	next.failures = 0

	res.Status = StatusNotModified
	res.BodyBytes = 0
	res.LastOKAt = now
	res.ConsecutiveFailures = 0

	if err := p.writeState(ctx, feed.ID, d, next); err != nil {
		res.Status = StatusFailed
		return *res, err
	}
	res.StateWritten = true
	return *res, nil
}

// finishUpdated handles a 200: read the body under a cap, sanitize the
// validators, advance the watermark, store.
func (p *Poller) finishUpdated(ctx context.Context, feed config.FeedConfig, d license.Decision, st feedState, res *PollResult, resp *http.Response) (PollResult, error) {
	body, err := readCapped(resp.Body, p.maxBody)
	res.BodyBytes = int64(len(body))
	if err != nil {
		return p.finishFailure(ctx, feed, d, st, res, err)
	}

	now := p.now().UTC()
	next := st
	next.lastOKAt = now
	next.failures = 0

	etag, ok := p.acceptHeaderValue(resp.Header.Get(headerETag), validETag, res)
	if ok {
		next.etag = etag
	} else if resp.Header.Get(headerETag) == "" {
		// A 200 with no ETag invalidates the stored one: sending the old
		// validator next time would ask about a body this response replaced.
		next.etag = ""
	}
	lastMod, ok := p.acceptHeaderValue(resp.Header.Get(headerLastModified), validHTTPDate, res)
	if ok {
		next.lastModified = lastMod
	} else if resp.Header.Get(headerLastModified) == "" {
		next.lastModified = ""
	}

	if feed.SyncMechanism == config.SyncWatermarkAPI {
		advanced, err := p.watermarks.Advance(feed, st.watermark, Response{
			StatusCode: resp.StatusCode,
			Header:     resp.Header.Clone(),
			Body:       body,
		})
		if err != nil {
			return p.finishFailure(ctx, feed, d, st, res,
				refuse(ErrWatermark, "feed %q: watermark hook could not advance the cursor: %v", feed.ID, err))
		}
		// The cursor is a string the hook derived from bytes a stranger wrote,
		// so it goes through A.3 like every other externally-sourced string
		// this package stores.
		clean, ok := p.acceptHeaderValue(advanced, anyValue, res)
		if !ok && advanced != "" {
			return p.finishFailure(ctx, feed, d, st, res,
				refuse(ErrWatermark, "feed %q: the advanced cursor did not survive the ingest sanitizer and was not stored", feed.ID))
		}
		next.watermark = clean
	}

	sum := sha256.Sum256(body)
	res.Status = StatusUpdated
	res.LastOKAt = now
	res.ConsecutiveFailures = 0
	res.ETag, res.LastModified, res.Watermark = next.etag, next.lastModified, next.watermark
	res.Payload = &Payload{decision: d, body: body, sha256: hex.EncodeToString(sum[:])}

	if err := p.writeState(ctx, feed.ID, d, next); err != nil {
		res.Status = StatusFailed
		return *res, err
	}
	res.StateWritten = true
	return *res, nil
}

// finishFailure records a poll that did not succeed: the failure streak grows
// and NOTHING ELSE MOVES. In particular the validators are left alone, because
// a failed poll is not evidence about the body they describe.
//
// A refusal that happened DURING the exchange — a cross-host redirect, an
// oversized body — lands here too. The feed did not deliver, whoever is at
// fault, and a feed that redirects off-host every time should be visible in the
// same counter as a feed that times out.
func (p *Poller) finishFailure(ctx context.Context, feed config.FeedConfig, d license.Decision, st feedState, res *PollResult, cause error) (PollResult, error) {
	if errors.Is(cause, ErrPollRefused) {
		res.Status = StatusRefused
	} else {
		res.Status = StatusFailed
		if !errors.Is(cause, ErrPollFailed) {
			cause = fail(ErrTransport, "feed %q: %v", feed.ID, cause)
		}
	}

	next := st
	next.failures = st.failures + 1
	res.ConsecutiveFailures = next.failures

	if err := p.writeState(ctx, feed.ID, d, next); err != nil {
		return *res, errors.Join(cause, err)
	}
	res.StateWritten = true
	return *res, cause
}

// readCapped reads at most limit bytes and refuses a body that has more.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return body, fail(ErrTransport, "reading the response body: %v", err)
	}
	if int64(len(body)) > limit {
		return body[:limit], refuse(ErrBodyTooLarge,
			"the response body exceeds the %d byte cap; an unbounded read against a feed is a memory-exhaustion primitive handed to whoever controls it", limit)
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// x-poll-interval
// ---------------------------------------------------------------------------

// applyServerInterval honours research/06 S2's "if a response includes an
// x-poll-interval header, wait at least that many seconds before you poll the
// same endpoint again", and Retry-After on the statuses that carry it.
//
// The rule is MAX, never replace: a server may ask us to slow down, never to
// speed up past the cadence the operator configured. And the result is capped
// by the feed's own freshness SLO where one is configured, so a server that
// answers with an absurd interval cannot silently retire a feed — the cap comes
// from the feed table, not from a constant in here.
func (p *Poller) applyServerInterval(feed config.FeedConfig, resp *http.Response, res *PollResult) {
	base := feed.Interval()
	res.NextPollAfter = base
	res.IntervalSource = IntervalFromFeedTable

	requested, source := time.Duration(0), IntervalFromFeedTable
	if d, ok := parseDeltaSeconds(resp.Header.Get(headerPollInterval)); ok {
		requested, source = d, IntervalFromServer
	} else if resp.Header.Get(headerPollInterval) != "" {
		res.HeaderRejected++
	}
	if d, ok := parseRetryAfter(resp.Header.Get(headerRetryAfter), p.now()); ok && d > requested {
		requested, source = d, IntervalFromRetryAfter
	} else if resp.Header.Get(headerRetryAfter) != "" && !ok {
		res.HeaderRejected++
	}
	res.ServerPollInterval = requested

	if requested > base {
		res.NextPollAfter = requested
		res.IntervalSource = source
	}
	if slo := feed.FreshnessSLO(); slo > 0 && res.NextPollAfter > slo {
		res.NextPollAfter = slo
		res.IntervalCapped = true
	}
}

// parseDeltaSeconds reads a non-negative integer number of seconds.
func parseDeltaSeconds(v string) (time.Duration, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// parseRetryAfter reads either form RFC 9110 allows: delta-seconds or an
// HTTP-date. A date in the past yields zero rather than a negative delay.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	if d, ok := parseDeltaSeconds(v); ok {
		return d, true
	}
	s := strings.TrimSpace(v)
	if s == "" {
		return 0, false
	}
	t, err := http.ParseTime(s)
	if err != nil {
		return 0, false
	}
	if d := t.Sub(now); d > 0 {
		return d, true
	}
	return 0, true
}

// ---------------------------------------------------------------------------
// A.3 — every externally-sourced string this package stores
// ---------------------------------------------------------------------------

// acceptHeaderValue is the ONLY route by which a value from the network reaches
// feed_state, and it is stricter than "it was passed through the sanitizer".
//
// A.3 is a MUTATING, fail-closed sanitizer: it drops unreadable code points and
// truncates at an unterminated hidden-markup opener. For prose that is exactly
// right. For a VALIDATOR it is not, because a modified ETag is not the server's
// ETag: storing it would send If-None-Match with a token the server never
// issued, and the feed would answer 200 forever while the cache recorded that
// it was tracking a validator. So the rule here is:
//
//	sanitize it; if the sanitizer changed ANYTHING, or the result does not have
//	the shape the header is supposed to have, or it is over the length cap, DROP
//	IT AND COUNT IT.
//
// Dropping a validator costs one unconditional request. Storing a mangled one
// costs every future request, silently. The count surfaces in
// PollResult.HeaderRejected so the cost is visible rather than inferred.
//
// The returned value is the Text of a record.TrustedString: A.3's Ingest is
// what stamps record.TrustUntrusted, and going through it is what stops a
// caller from sanitising a string and then forgetting to classify it. feed_state
// has no anvil_trust column — every byte in it that came from the network is
// untrusted by construction — so the stamp is a discipline here rather than a
// column, and the value bound is the stamped one.
func (p *Poller) acceptHeaderValue(raw string, shape func(string) bool, res *PollResult) (string, bool) {
	if raw == "" {
		return "", false
	}
	if len(raw) > maxStoredHeaderBytes {
		res.HeaderRejected++
		return "", false
	}
	trusted, stats := sanitize.Ingest(raw)
	res.Sanitize.Merge(stats)
	if stats.Modified() || stats.FailedClosed() {
		res.HeaderRejected++
		return "", false
	}
	if trusted.Trust != record.TrustUntrusted {
		res.HeaderRejected++
		return "", false
	}
	if err := sanitize.AssertSanitized(trusted.Text); err != nil {
		res.HeaderRejected++
		return "", false
	}
	if !shape(trusted.Text) {
		res.HeaderRejected++
		return "", false
	}
	return trusted.Text, true
}

// anyValue accepts any shape. It is used for the watermark, whose shape is a
// per-feed fact this package does not know.
func anyValue(string) bool { return true }

// validETag reports whether v is an RFC 9110 entity-tag: an optional weak
// prefix, then a quoted string of etagc characters.
//
// The shape check is not pedantry. It is what stops a feed from writing an
// arbitrary line into a header Anvil will send back on every subsequent request
// — including, without the DQUOTE requirement, a value carrying a comma that
// splits into two If-None-Match entries.
func validETag(v string) bool {
	s := strings.TrimPrefix(v, "W/")
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		c := s[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x7E) || c >= 0x80 {
			continue
		}
		return false
	}
	return true
}

// validHTTPDate reports whether v parses as one of the three date formats RFC
// 9110 permits. A Last-Modified that does not parse is not a date, and sending
// it back as If-Modified-Since would ask a question in a language the server
// does not speak.
func validHTTPDate(v string) bool {
	_, err := http.ParseTime(strings.TrimSpace(v))
	return err == nil
}

// ---------------------------------------------------------------------------
// feed_state
// ---------------------------------------------------------------------------

// feedState is one row of the A.2 cache's feed_state table, in Go.
//
// THE CADENCE IS NOT HERE and must never be added: the schema says so at the
// table's own definition, and research/06 Recommendation item 4 puts every
// interval in the feed table so an operator can dial the whole pipeline down on
// a constrained host.
type feedState struct {
	etag         string
	lastModified string
	watermark    string
	lastOKAt     time.Time
	failures     int
	found        bool
}

// readState reads one feed's polling state. NO ROW IS NOT AN ERROR: it means
// the feed has never been polled, which is the state every feed starts in and
// the state a first run must handle without a special case at the call site.
func (p *Poller) readState(ctx context.Context, feedID string) (feedState, error) {
	var (
		st                  feedState
		etag, lastMod       sql.NullString
		watermark, lastOKAt sql.NullString
		tier                int
	)
	row := p.db.QueryRowContext(ctx, cache.SelectFeedStateSQL, feedID)
	err := row.Scan(&etag, &lastMod, &watermark, &lastOKAt, &st.failures, &tier)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return feedState{}, nil
	case err != nil:
		return feedState{}, fmt.Errorf("%w: reading feed_state for %q: %w", ErrCacheWrite, feedID, err)
	}
	st.found = true
	st.etag = etag.String
	st.lastModified = lastMod.String
	st.watermark = watermark.String
	if lastOKAt.Valid && lastOKAt.String != "" {
		if t, perr := time.Parse(time.RFC3339, lastOKAt.String); perr == nil {
			st.lastOKAt = t.UTC()
		}
	}
	return st, nil
}

// writeState persists one feed's polling state.
//
// license_tier is written from the GATE'S CONCLUSION, never from the row's own
// claim: A.4's Decision.Tier is what the pinned evidence supports, and a row
// that claims a different tier is a row whose claim the gate already refused to
// act on.
func (p *Poller) writeState(ctx context.Context, feedID string, d license.Decision, st feedState) error {
	_, err := p.db.ExecContext(ctx, cache.UpsertFeedStateSQL,
		feedID,
		nullable(st.etag),
		nullable(st.lastModified),
		nullable(st.watermark),
		nullableTime(st.lastOKAt),
		st.failures,
		d.Tier.Int(),
	)
	if err != nil {
		return fmt.Errorf("%w: writing feed_state for %q: %w", ErrCacheWrite, feedID, err)
	}
	return nil
}

// nullable maps "" onto SQL NULL, so "never seen" and "seen and empty" stay
// distinguishable in the column rather than collapsing onto the empty string.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableTime renders a timestamp for storage, or NULL for the zero time.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(timeLayout)
}
