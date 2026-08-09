// Package config loads Anvil's advisory-feed table from DATA.
//
// This is step A.1 of plan/20-lane-a-ingestion-sca.md. Lane A is the
// zero-inference half of Anvil (plan/00-SPINE.md S1): a tiered conditional-GET
// poller filling one SQLite+FTS5 cache, plus two collectors feeding a version
// comparator. No model runs in this lane. The one thing that makes the lane
// operable rather than brittle is that WHICH feeds exist, WHERE they are, HOW
// OFTEN they are polled, HOW they authenticate, and UNDER WHAT LICENCE they
// arrive are all read from a file — never compiled in.
//
// # The constraint this file exists to enforce
//
// research/06 Recommendation item 4 states it directly: "Every cadence above
// lives in config, never in code. A feeds.yaml with {url, auth, interval,
// freshness_slo, on_failure} per feed satisfies the owner's
// no-hard-coded-triggers constraint and lets an operator dial the whole
// pipeline down to daily on a constrained host."
//
// internal/policy already established the same pattern for trigger policy,
// which the owner named as a hard constraint. The review rule is identical
// here and it is mechanical: a feed URL, a cadence, or a credential appearing
// as a Go literal anywhere in Lane A is a defect, and feeds_test.go asserts
// that against THIS file by parsing it and walking its string and integer
// literals. If you add "https://..." or 86400 below, the build goes red.
//
// # What this package does NOT decide
//
//   - It does not fetch anything. A.7 (poller) and A.8 (bootstrap) do that.
//     Loading a config performs no network I/O, by construction: nothing here
//     imports net/http.
//   - It does not resolve a licence. It RECORDS what each feed declares —
//     spine S8's licence gate (A.4) is the one code path that resolves a
//     declared SPDX id against a checked-in LICENSE file body and decides
//     which mirror/tier* directory a row may be written to. Duplicating a
//     share-alike SPDX list here would create exactly the second vocabulary
//     that plan/IMPLEMENTATION-PLAN.md section 6 closed ten instances of.
//   - It does not redeclare any of area 40's six frozen enums. None of them
//     describes a feed: internal/record owns anvil/state, anvil/status,
//     anvil/dastStatus, anvil/target.provenance, anvil/target.provisioning,
//     anvil/verdict and handoff.state, and A.1 emits none of those values.
//     The four enums below (AuthMode, SyncMechanism, BootstrapMechanism,
//     OnFailure) plus LicenseTier are Lane-A-local ingestion vocabulary with
//     no counterpart in the record contract.
//
// # Licence is mandatory, not decorative
//
// LicenseSPDX has no legal empty value. Spine S8 makes a feed's licence a
// gating fact, A.4 gates on it, and share-alike sources (Ubuntu OVAL/USN and
// Alpine secdb, both CC-BY-SA-4.0 per research/01 S7/S29/S31) are quarantined
// into segregated Tier 2 directories with their own LICENSE files. A feed
// whose licence cannot be stated is a feed Anvil cannot use, so Parse refuses
// the row rather than defaulting it. Where no SPDX identifier exists the row
// says so explicitly — SPDX's own reserved tokens NONE and NOASSERTION, or a
// LicenseRef- custom id — and must carry the quoted operative sentence in
// LicenseManualNote (spine S8's manual-override field).
//
// LicenseSPDX = NONE means NO GRANT OF RIGHTS EXISTS. EPSS is the worked
// example: research/01 rows S18/S19 record that it has no licence document
// and no SPDX identifier, and that "attribution is requested" is a request,
// not a grant. Such a feed is legal here only at LicenseTier3 — optional,
// opt-in, risk-accepted — and Anvil must never describe it as open licensed.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Document identity and bounds
// ---------------------------------------------------------------------------

const (
	// SchemaVersion is the only `version:` a feed table may declare. It is
	// pinned to a constant so an old daemon fails loudly on a newer file
	// instead of misreading it — the same mechanic internal/policy uses.
	SchemaVersion = 1

	// DefaultFileName is the conventional name of the operator's real feed
	// table. It is a FILE NAME, not a feed URL and not a cadence; nothing in
	// this package reads it implicitly. Load takes an explicit path.
	DefaultFileName = "feeds.yaml"

	// ExampleFileName is the checked-in rendering of the Feed Table in
	// plan/20-lane-a-ingestion-sca.md. It ships beside this file as
	// documentation and as the loader's acceptance fixture; it is never a
	// runtime default, because an operator's credential environment variable
	// names and enabled/disabled choices are theirs, not ours.
	ExampleFileName = "feeds.example.yaml"

	// MaxDocumentBytes bounds what Load will read. A feed table is an
	// operator-authored file of tens of rows; anything larger is a mistake or
	// a wrong path, and refusing is diagnosable where an OOM is not.
	MaxDocumentBytes = 1 << 20

	// MaxFeeds bounds the number of rows. research/06's budget arithmetic is
	// written for single-digit feed counts ("polling 8 feeds every 5 minutes
	// costs 96 req/hour"); this cap is three orders of margin over that and
	// exists only to make a runaway generated file a refusal.
	MaxFeeds = 512
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrInvalidDocument reports a file that is not a well-formed feed table:
	// a YAML-subset syntax error, a wrong top-level shape, an unknown key, a
	// value of the wrong type. Every structural refusal below satisfies
	// errors.Is against this, so a caller that only wants "is this file
	// usable" needs one check.
	ErrInvalidDocument = errors.New("config: invalid feeds document")

	// ErrUnsupportedVersion reports a `version:` that is not SchemaVersion.
	ErrUnsupportedVersion = errors.New("config: unsupported feeds version")

	// ErrUnknownKey reports a key this loader does not know. It is a REFUSAL,
	// never a silent skip: a typo'd `intervall_seconds` that decoded to a
	// zero interval would be a feed that never polls and never errors, which
	// is the failure mode this whole package exists to prevent.
	ErrUnknownKey = errors.New("config: unknown key")

	// ErrDuplicateFeedID reports two rows sharing an id. feed_id is the
	// primary key of the A.2 cache's feed_state table; two rows would race on
	// one etag/watermark.
	ErrDuplicateFeedID = errors.New("config: duplicate feed id")

	// ErrMissingLicenseTier reports a feed that declares no license_tier, or
	// one outside {0,1,2,3}. Named separately because A.1's stop condition
	// requires a named error for it and because the A.2 DDL's
	// CHECK (license_tier IN (0,1,2,3)) cannot accept anything else.
	ErrMissingLicenseTier = errors.New("config: missing or out-of-range license_tier")

	// ErrMissingInterval reports a polled feed with no positive
	// interval_seconds. Named separately for the same reason.
	ErrMissingInterval = errors.New("config: missing or zero interval_seconds")

	// ErrMissingLicense reports a feed that states no licence at all. Spine
	// S8: a feed whose licence cannot be stated is a feed Anvil cannot use.
	// Say NONE or NOASSERTION with a note; never leave it blank.
	ErrMissingLicense = errors.New("config: feed declares no licence")

	// ErrMissingLicenseNote reports NONE, NOASSERTION or a LicenseRef- id
	// without the quoted operative sentence spine S8 requires in
	// license_manual_note.
	ErrMissingLicenseNote = errors.New("config: licence needs a manual note")

	// ErrUndeclaredLicenseTier reports LicenseSPDX = NONE at a tier other
	// than 3. A source with no grant of rights is opt-in and risk-accepted
	// (research/01 "Tier 3 (optional, user opt-in at install time)"), never
	// part of the always-mirrored set.
	ErrUndeclaredLicenseTier = errors.New("config: undeclared licence outside tier 3")

	// ErrInvalidEnum reports a value outside one of this package's closed
	// vocabularies. The message names every legal literal, because "invalid
	// value" does not tell the author which vocabulary they were meant to
	// use — the same reasoning as record.EnumError, which this deliberately
	// does not reuse: that type is the record contract's, for the six FROZEN
	// enums, and Lane A's config vocabulary must not masquerade as one.
	ErrInvalidEnum = errors.New("config: value outside a closed vocabulary")

	// ErrInvalidURL reports a feed url that is not an absolute https URL with
	// a host — or one carrying inline credentials. A userinfo component is
	// refused outright: it is a credential literal, and the one place a
	// credential may live is an environment variable named by CredentialEnv.
	ErrInvalidURL = errors.New("config: invalid feed url")

	// ErrInvalidCredentialRef reports a credential_env that is missing, that
	// is present where no authentication is configured, or whose spelling is
	// not an environment variable NAME. The name check is not cosmetic: it is
	// what stops a pasted token — which is lower-case and punctuated — from
	// being accepted where a variable name belongs.
	ErrInvalidCredentialRef = errors.New("config: invalid credential reference")

	// ErrInconsistentSchedule reports cadences that cannot mean what they
	// say: a freshness SLO shorter than the poll interval it is measured
	// against, a reconciliation pass more frequent than the steady-state
	// poll, or a weekly baseline on a feed with no bulk archive to re-pull.
	ErrInconsistentSchedule = errors.New("config: inconsistent schedule")

	// ErrUnresolvedReference reports a derived_from naming a feed that is not
	// in this document, or itself derived, or the feed itself.
	ErrUnresolvedReference = errors.New("config: unresolved feed reference")
)

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

// AuthMode is how a feed's requests are authenticated.
//
// It names a MECHANISM. The secret itself never appears in the feed table:
// CredentialEnv names the environment variable the daemon reads it from.
type AuthMode string

const (
	// AuthNone sends no credential. Legal for feeds not hosted by a provider
	// whose rate limit punishes anonymity.
	AuthNone AuthMode = "none"

	// AuthGitHubToken sends a GitHub PAT or App installation token in the
	// Authorization header on EVERY request, including the ones expected to
	// return 304. research/06 Recommendation item 1: a 304 costs zero
	// rate-limit budget *because* the request is authorized, while
	// unauthenticated 304s consume the 60/hour limit. A.7 enforces the
	// send-side rule; this value is how a row asks for it.
	AuthGitHubToken AuthMode = "github_token"

	// AuthAPIKeyHeader sends a vendor API key in a vendor-named header,
	// which the row supplies as CredentialHeader. The header name is data
	// for the same reason the URL is: baking one vendor's spelling into the
	// poller makes the poller vendor-specific.
	AuthAPIKeyHeader AuthMode = "api_key_header"
)

// AuthModeValues returns every legal auth_mode literal, in declaration order.
func AuthModeValues() []AuthMode {
	return []AuthMode{AuthNone, AuthGitHubToken, AuthAPIKeyHeader}
}

// Valid reports whether m is a legal auth_mode literal.
func (m AuthMode) Valid() bool { return inEnum(m, AuthModeValues()) }

// SyncMechanism is how a feed's steady-state changes are detected.
//
// A.7's packet requires the poller to run against a fixture for "every sync
// mechanism in the Feed Table" without a hard-coded feed URL or cadence. That
// is only possible if the mechanism is declared per row: a poller that
// branches on feed id to decide whether to send If-None-Match has hard-coded
// the feed table in Go.
type SyncMechanism string

const (
	// SyncConditionalGetETag sends If-None-Match against a stored etag.
	SyncConditionalGetETag SyncMechanism = "conditional_get_etag"

	// SyncConditionalGetLastModified sends If-Modified-Since against a
	// stored last_modified.
	SyncConditionalGetLastModified SyncMechanism = "conditional_get_last_modified"

	// SyncGitBloblessFetch runs `git fetch` against an existing
	// --filter=blob:none clone. It pairs with BootstrapBloblessClone and
	// with nothing else: a fetch needs a clone to fetch into, and
	// research/06 Risk #7 rules out doing this on a --depth=1 clone at all.
	SyncGitBloblessFetch SyncMechanism = "git_blobless_fetch"

	// SyncWatermarkAPI advances a feed-specific cursor (a last-modified
	// window, a page token) stored in feed_state.watermark.
	SyncWatermarkAPI SyncMechanism = "watermark_api"

	// SyncDerived means the feed is NOT polled: its content arrives inside
	// another feed's payload, and DerivedFrom names that feed. CISA
	// Vulnrichment is the worked example — it is delivered inside the CVE
	// record's ADP container, so a separate poll would be a second copy of
	// the same bytes.
	SyncDerived SyncMechanism = "derived"

	// SyncNone means the feed is not polled and not derived: it exists only
	// as a bulk artifact, refreshed on BaselineIntervalSeconds if at all.
	// This is A.1's "bulk-only" case, and the one shape where a zero
	// IntervalSeconds is legal alongside SyncDerived.
	SyncNone SyncMechanism = "none"
)

// SyncMechanismValues returns every legal sync_mechanism literal.
func SyncMechanismValues() []SyncMechanism {
	return []SyncMechanism{
		SyncConditionalGetETag, SyncConditionalGetLastModified,
		SyncGitBloblessFetch, SyncWatermarkAPI, SyncDerived, SyncNone,
	}
}

// Valid reports whether s is a legal sync_mechanism literal.
func (s SyncMechanism) Valid() bool { return inEnum(s, SyncMechanismValues()) }

// Polled reports whether the daemon should schedule this feed on
// IntervalSeconds. It is false exactly for the two shapes that carry no
// steady-state poll.
func (s SyncMechanism) Polled() bool { return s != SyncDerived && s != SyncNone }

// BootstrapMechanism is how a feed's cache is first filled.
//
// A.8 dispatches on this value. research/06 Recommendation item 2 is the
// reason it is an enum rather than an implicit property of the URL:
// bootstrapping from bulk archives instead of git history is a deliberate
// choice per feed, and GHSA is the single documented exception.
type BootstrapMechanism string

const (
	// BootstrapBulkArchive downloads an archive once and streams it into
	// batched upserts.
	BootstrapBulkArchive BootstrapMechanism = "bulk_archive"

	// BootstrapBloblessClone runs `git clone --filter=blob:none` once.
	// research/06 names this "the right tool for GHSA specifically, the
	// wrong tool for cvelistV5", whose ~75,000 commits/year of tree objects
	// dominate any partial clone.
	BootstrapBloblessClone BootstrapMechanism = "blobless_clone"

	// BootstrapIncrementalAPI performs no bulk fetch at all: the feed fills
	// forward from its watermark. NVD is the worked example — supplementary
	// and deprioritised since the April 2026 enrichment collapse, and never
	// worth a bulk pull.
	BootstrapIncrementalAPI BootstrapMechanism = "incremental_api"

	// BootstrapNone means nothing bootstraps this feed on its own account:
	// either another feed carries it (SyncDerived) or the first poll fills
	// the cache from empty.
	BootstrapNone BootstrapMechanism = "none"
)

// BootstrapMechanismValues returns every legal bootstrap_mechanism literal.
func BootstrapMechanismValues() []BootstrapMechanism {
	return []BootstrapMechanism{
		BootstrapBulkArchive, BootstrapBloblessClone,
		BootstrapIncrementalAPI, BootstrapNone,
	}
}

// Valid reports whether b is a legal bootstrap_mechanism literal.
func (b BootstrapMechanism) Valid() bool { return inEnum(b, BootstrapMechanismValues()) }

// OnFailure is what the daemon does when a feed keeps failing.
//
// THERE IS DELIBERATELY NO "fail_scan" VALUE. research/06 Risk #5 is explicit
// about feed outage: "never fail the scan — serve stale data with an `as_of`
// timestamp and a `staleness_seconds` field stamped into the unified audit
// record. A scan run on 3-day-old KEV data must say so." Offering an option
// that contradicts that would let an operator configure Anvil into the
// failure mode spine S6's as_of/staleness_seconds fields exist to prevent.
type OnFailure string

const (
	// OnFailureServeStale keeps serving what the cache has, stamping as_of
	// and staleness_seconds so every downstream record carries the age of
	// the data it was decided on. This is the only legal behaviour for a
	// feed Anvil actually depends on.
	OnFailureServeStale OnFailure = "serve_stale"

	// OnFailureDisableFeed stops scheduling the feed and contributes
	// nothing. Legal only at LicenseTier3, where the feed is opt-in and
	// risk-accepted by definition and its absence changes no verdict.
	OnFailureDisableFeed OnFailure = "disable_feed"
)

// OnFailureValues returns every legal on_failure literal.
func OnFailureValues() []OnFailure {
	return []OnFailure{OnFailureServeStale, OnFailureDisableFeed}
}

// Valid reports whether o is a legal on_failure literal.
func (o OnFailure) Valid() bool { return inEnum(o, OnFailureValues()) }

// LicenseTier is research/01's four-tier licence stratification, carried per
// feed and stored as INTEGER in the A.2 cache's
// CHECK (license_tier IN (0,1,2,3)) columns.
//
// The tier is a fact about obligations, not about quality:
//
//	0  always mirrored, licence-clean, no copyleft
//	1  mirrored, attribution required — keep a NOTICE file
//	2  share-alike — SEGREGATED cache dir, own LICENSE, never merged into
//	   a Tier 0/1 output (research/01 Risk #3, spine S8)
//	3  optional, user opt-in at install time
type LicenseTier int

// The four legal licence tiers.
const (
	LicenseTier0 LicenseTier = 0
	LicenseTier1 LicenseTier = 1
	LicenseTier2 LicenseTier = 2
	LicenseTier3 LicenseTier = 3
)

// LicenseTierValues returns every legal tier, ascending.
func LicenseTierValues() []LicenseTier {
	return []LicenseTier{LicenseTier0, LicenseTier1, LicenseTier2, LicenseTier3}
}

// Valid reports whether t is one of the four legal tiers.
func (t LicenseTier) Valid() bool {
	return t >= LicenseTier0 && t <= LicenseTier3
}

// Int returns the tier as a plain int, for the A.2/A.4 call sites that store
// or compare it as one.
func (t LicenseTier) Int() int { return int(t) }

// Reserved SPDX-expression tokens a feed row may declare instead of an
// identifier. Both are SPDX's own vocabulary, not Anvil's invention.
const (
	// LicenseNone means NO LICENCE EXISTS — no grant of rights was ever
	// made. It is not "we could not find one"; that is LicenseNoAssertion.
	// A row declaring it must be LicenseTier3 and must carry the operative
	// sentence in LicenseManualNote.
	LicenseNone = "NONE"

	// LicenseNoAssertion means the metadata asserts nothing: either the
	// publisher's terms have no SPDX identifier, or an API reports
	// NOASSERTION over a real licence. Spine S8 exists because the second
	// case is common — seven artifacts in the corpus return NOASSERTION over
	// a real licence and one hides a restrictive one — so the row must carry
	// the quoted operative sentence and A.4 resolves it against a
	// checked-in LICENSE file body, never against API metadata.
	LicenseNoAssertion = "NOASSERTION"

	// LicenseRefPrefix marks an SPDX custom identifier, for terms that are
	// real and specific but have no entry on the SPDX list. Like the two
	// tokens above it requires a manual note.
	LicenseRefPrefix = "LicenseRef-"
)

// ---------------------------------------------------------------------------
// The licence-declaration predicates. ONE definition, consumed by two packages.
// ---------------------------------------------------------------------------
//
// A.4's licence gate asks the same three questions this loader asks: is this
// declaration NONE, does it need spine S8's manual note, does it resolve
// against the SPDX list. Before these existed each package answered them with
// its own inline expression, and the two answers disagreed on case: this loader
// compared with `==` while the gate compared with strings.EqualFold, so a row
// declaring `license_spdx: none` loaded clean at tier 0 here and was then
// refused as an undeclared licence there. Two definitions that agree today are
// exactly the produce/consume break plan/IMPLEMENTATION-PLAN.md section 6
// closed ten instances of, so there is now one definition and A.4 calls it.
//
// All three fold case and trim space, which is the stricter of the two
// behaviours that used to exist: `none`, `None` and ` NONE ` are all the NONE
// token, and none of them may sit at a mirrored tier.

// SPDXIsNone reports whether a declaration is the NONE token — NO GRANT OF
// RIGHTS EXISTS, as distinct from NOASSERTION's "nothing was asserted".
func SPDXIsNone(spdx string) bool {
	return strings.EqualFold(strings.TrimSpace(spdx), LicenseNone)
}

// SPDXIsNoAssertion reports whether a declaration is the NOASSERTION token.
func SPDXIsNoAssertion(spdx string) bool {
	return strings.EqualFold(strings.TrimSpace(spdx), LicenseNoAssertion)
}

// SPDXIsLicenseRef reports whether a declaration is a LicenseRef- custom id.
func SPDXIsLicenseRef(spdx string) bool {
	s := strings.TrimSpace(spdx)
	return len(s) >= len(LicenseRefPrefix) &&
		strings.EqualFold(s[:len(LicenseRefPrefix)], LicenseRefPrefix)
}

// SPDXResolvable reports whether a declaration names terms the SPDX licence
// list can resolve. NONE, NOASSERTION, a LicenseRef- custom id and the empty
// string cannot be resolved.
func SPDXResolvable(spdx string) bool {
	s := strings.TrimSpace(spdx)
	if s == "" {
		return false
	}
	return !SPDXIsNone(s) && !SPDXIsNoAssertion(s) && !SPDXIsLicenseRef(s)
}

// SPDXNeedsManualNote reports whether a declaration obliges spine S8's
// manual-override field. It is the exact negation of SPDXResolvable, named for
// the rule rather than the mechanism because that is how both call sites read.
func SPDXNeedsManualNote(spdx string) bool { return !SPDXResolvable(spdx) }

func inEnum[T ~string](v T, allowed []T) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func enumErr(field, value string, allowed []string) error {
	return fmt.Errorf("%w: %w: %q is not a legal %s; legal values are %s",
		ErrInvalidDocument, ErrInvalidEnum, value, field, strings.Join(allowed, "|"))
}

func literals[T ~string](vals []T) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = string(v)
	}
	return out
}

// ---------------------------------------------------------------------------
// FeedConfig
// ---------------------------------------------------------------------------

// FeedConfig is one row of the feed table.
//
// Every consumer in Lane A reads its per-feed behaviour from a value of this
// type: A.7 polls on Interval with AuthMode/CredentialEnv and SyncMechanism,
// A.8 dispatches on BootstrapMechanism, A.14/A.15 schedule on
// ReconcileInterval/BaselineInterval, A.4 gates on LicenseTier +
// LicenseSPDX + LicenseManualNote, and A.16/A.19 stamp staleness against
// FreshnessSLO. Nothing in that list is a Go constant anywhere in Lane A.
type FeedConfig struct {
	// ID is the feed's stable identifier and the primary key of the A.2
	// cache's feed_state table. Lower-case, digits and single hyphens.
	ID string

	// URL is the absolute https endpoint polled in steady state. Empty for
	// SyncDerived rows, which are not polled at all.
	URL string

	// Enabled is false for a feed present in the table but not scheduled —
	// how a Tier 3 opt-in row ships switched off, and how an operator
	// parks a feed without deleting its licence record. Defaults to true
	// when the key is absent.
	Enabled bool

	// AuthMode selects the credential mechanism; CredentialEnv names the
	// environment variable carrying the secret, and CredentialHeader the
	// header it goes in when AuthMode is AuthAPIKeyHeader.
	AuthMode         AuthMode
	CredentialEnv    string
	CredentialHeader string

	// SyncMechanism is how steady-state changes are detected.
	SyncMechanism SyncMechanism

	// IntervalSeconds is the steady-state poll cadence. Zero exactly when
	// SyncMechanism.Polled() is false.
	IntervalSeconds int

	// ReconcileIntervalSeconds is the cadence of a periodic reconciliation
	// pass that re-reads a larger window than the steady-state poll —
	// cvelistV5's end-of-day delta is the worked example. Zero means the
	// feed has no such pass. A.14 owns the pass; this is its clock.
	ReconcileIntervalSeconds int

	// BaselineIntervalSeconds is the cadence of the full-baseline self-heal
	// that re-pulls the bulk artifact to catch anything the delta pipeline
	// dropped. Zero means no self-heal. A.15 owns the pass; this is its
	// clock, and it is here rather than in A.15 because a weekly duration
	// written as a Go constant is precisely the hard-coded cadence this
	// package forbids.
	BaselineIntervalSeconds int

	// FreshnessSLOSeconds is the age past which this feed's data is
	// reported as stale. It feeds spine S6's staleness_seconds, and it must
	// be at least IntervalSeconds: an SLO shorter than the poll that
	// refreshes it is unmeetable by construction.
	FreshnessSLOSeconds int

	// OnFailure is the outage behaviour. See OnFailure's own note on why
	// there is no fail-the-scan option.
	OnFailure OnFailure

	// LicenseTier is research/01's tier for this source.
	LicenseTier LicenseTier

	// LicenseSPDX is the declared SPDX identifier, or one of LicenseNone /
	// LicenseNoAssertion / a LicenseRefPrefix custom id. Never empty.
	//
	// This package validates the SHAPE of the value, not its membership in
	// the SPDX list: A.4 owns resolution against checked-in LICENSE file
	// bodies, and a second SPDX list here would go stale independently.
	LicenseSPDX string

	// LicenseManualNote is spine S8's manual-override field: the quoted
	// operative sentence from the publisher's own licence text. Required
	// whenever LicenseSPDX is NONE, NOASSERTION or a LicenseRef- id, and
	// welcome on any row whose metadata and reality disagree.
	LicenseManualNote string

	// MirrorDir is the single path segment this feed's mirrored data and its
	// licence evidence live in, under its tier's directory. Parse resolves
	// it: an absent `mirror_dir` key defaults to ID, so a consumer never
	// re-derives the default and two consumers cannot disagree about it.
	//
	// IT EXISTS BECAUSE TIER 2 COULD NOT OTHERWISE BE ENTERED. The three
	// share-alike rows in the example table are `ubuntu-osv`, `alpine-secdb`
	// and `osv-merged`, and their quarantine directories are
	// mirror/tier2/{ubuntu,alpine,osv} — the id and the directory differ, so
	// with no key for it the only way to reach the quarantine was for a
	// caller to invent the mapping. A.4's own test carried that mapping for a
	// while, which meant the quarantine was reachable from a test and from
	// nowhere else, and the licence evidence a decision rested on was chosen
	// by the caller rather than bound to the feed row. It is configuration
	// for the same reason every other per-feed fact here is: a mapping
	// compiled into Go is the hard-coded feed table this package abolishes.
	MirrorDir string

	// BootstrapMechanism is how A.8 first fills this feed.
	BootstrapMechanism BootstrapMechanism

	// BootstrapURL is where the bulk artifact or git remote lives. Parse
	// resolves it: when the key is absent and the mechanism fetches
	// something, it defaults to URL, so consumers never re-derive it and
	// never disagree about the default.
	BootstrapURL string

	// DerivedFrom names the feed whose payload carries this one. Set
	// exactly when SyncMechanism is SyncDerived, and validated to resolve
	// to a non-derived row in the same document.
	DerivedFrom string
}

// Interval returns IntervalSeconds as a duration.
func (f FeedConfig) Interval() time.Duration {
	return time.Duration(f.IntervalSeconds) * time.Second
}

// ReconcileInterval returns ReconcileIntervalSeconds as a duration; zero means
// the feed has no reconciliation pass.
func (f FeedConfig) ReconcileInterval() time.Duration {
	return time.Duration(f.ReconcileIntervalSeconds) * time.Second
}

// BaselineInterval returns BaselineIntervalSeconds as a duration; zero means
// the feed has no full-baseline self-heal.
func (f FeedConfig) BaselineInterval() time.Duration {
	return time.Duration(f.BaselineIntervalSeconds) * time.Second
}

// FreshnessSLO returns FreshnessSLOSeconds as a duration.
func (f FeedConfig) FreshnessSLO() time.Duration {
	return time.Duration(f.FreshnessSLOSeconds) * time.Second
}

// LicenseDeclared reports whether the row names an actual licence, as opposed
// to NONE (no grant exists) or NOASSERTION (nothing asserted). A LicenseRef-
// custom id counts as declared: it names real terms that merely have no entry
// on the SPDX list.
//
// It is a convenience for reporting, NOT a licence gate. A.4 is the gate.
func (f FeedConfig) LicenseDeclared() bool {
	return f.LicenseSPDX != LicenseNone && f.LicenseSPDX != LicenseNoAssertion
}

// ---------------------------------------------------------------------------
// FeedSet
// ---------------------------------------------------------------------------

// FeedSet is a parsed, validated feed table.
type FeedSet struct {
	// Version is the document's declared version, always SchemaVersion.
	Version int

	// Feeds are the rows in document order. Order is preserved so that
	// diagnostics, and any consumer that iterates, are deterministic.
	Feeds []FeedConfig
}

// ByID returns the feed with the given id.
func (s FeedSet) ByID(id string) (FeedConfig, bool) {
	for _, f := range s.Feeds {
		if f.ID == id {
			return f, true
		}
	}
	return FeedConfig{}, false
}

// IDs returns every feed id in document order.
func (s FeedSet) IDs() []string {
	out := make([]string, len(s.Feeds))
	for i, f := range s.Feeds {
		out[i] = f.ID
	}
	return out
}

// EnabledFeeds returns the rows with Enabled true, in document order.
func (s FeedSet) EnabledFeeds() []FeedConfig {
	out := make([]FeedConfig, 0, len(s.Feeds))
	for _, f := range s.Feeds {
		if f.Enabled {
			out = append(out, f)
		}
	}
	return out
}

// ByTier returns the rows at the given licence tier, in document order. A.4
// uses it to enumerate what may be written under each mirror/tier* directory.
func (s FeedSet) ByTier(t LicenseTier) []FeedConfig {
	out := make([]FeedConfig, 0, len(s.Feeds))
	for _, f := range s.Feeds {
		if f.LicenseTier == t {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Load / Parse
// ---------------------------------------------------------------------------

// Load reads and parses a feed table from disk.
//
// It performs no network I/O — this package imports no HTTP client, and A.1's
// packet forbids fetching anything from this step. The only side effect is
// reading the named file.
func Load(path string) (FeedSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FeedSet{}, fmt.Errorf("config: reading %s: %w", path, err)
	}
	if info.Size() > MaxDocumentBytes {
		return FeedSet{}, fmt.Errorf("%w: %s is %d bytes, over the %d-byte limit",
			ErrInvalidDocument, path, info.Size(), MaxDocumentBytes)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return FeedSet{}, fmt.Errorf("config: reading %s: %w", path, err)
	}
	set, err := Parse(src)
	if err != nil {
		return FeedSet{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return set, nil
}

// Parse parses a feed table from bytes and validates every row.
//
// Validation is total and fail-fast in document order: the first row that
// cannot be trusted stops the load. A partially-valid feed table is worse than
// no feed table, because the missing rows are silent.
func Parse(src []byte) (FeedSet, error) {
	if len(src) > MaxDocumentBytes {
		return FeedSet{}, fmt.Errorf("%w: document is %d bytes, over the %d-byte limit",
			ErrInvalidDocument, len(src), MaxDocumentBytes)
	}

	root, err := decode(string(src))
	if err != nil {
		return FeedSet{}, err
	}
	if root == nil {
		return FeedSet{}, fmt.Errorf("%w: document is empty", ErrInvalidDocument)
	}
	if root.kind != nodeMapping {
		return FeedSet{}, fmt.Errorf("%w: line %d: the document root must be a mapping with `version` and `feeds`",
			ErrInvalidDocument, root.line)
	}

	if err := root.rejectUnknown("", []string{"version", "feeds"}); err != nil {
		return FeedSet{}, err
	}

	versionNode, ok := root.field("version")
	if !ok {
		return FeedSet{}, fmt.Errorf("%w: %w: document declares no `version`",
			ErrInvalidDocument, ErrUnsupportedVersion)
	}
	version, err := versionNode.asInt("version")
	if err != nil {
		return FeedSet{}, err
	}
	if version != SchemaVersion {
		return FeedSet{}, fmt.Errorf("%w: line %d: version %d is not %d",
			ErrUnsupportedVersion, versionNode.line, version, SchemaVersion)
	}

	feedsNode, ok := root.field("feeds")
	if !ok {
		return FeedSet{}, fmt.Errorf("%w: document declares no `feeds`", ErrInvalidDocument)
	}
	if feedsNode.kind != nodeSequence {
		return FeedSet{}, fmt.Errorf("%w: line %d: `feeds` must be a sequence of feed mappings",
			ErrInvalidDocument, feedsNode.line)
	}
	if len(feedsNode.seq) == 0 {
		return FeedSet{}, fmt.Errorf("%w: line %d: `feeds` is empty", ErrInvalidDocument, feedsNode.line)
	}
	if len(feedsNode.seq) > MaxFeeds {
		return FeedSet{}, fmt.Errorf("%w: line %d: %d feeds is over the %d-row limit",
			ErrInvalidDocument, feedsNode.line, len(feedsNode.seq), MaxFeeds)
	}

	set := FeedSet{Version: version, Feeds: make([]FeedConfig, 0, len(feedsNode.seq))}
	seen := make(map[string]bool, len(feedsNode.seq))

	for i, item := range feedsNode.seq {
		feed, err := bindFeed(item, i)
		if err != nil {
			return FeedSet{}, err
		}
		if seen[feed.ID] {
			return FeedSet{}, fmt.Errorf("%w: %w: line %d: feed id %q appears twice",
				ErrInvalidDocument, ErrDuplicateFeedID, item.line, feed.ID)
		}
		seen[feed.ID] = true
		set.Feeds = append(set.Feeds, feed)
	}

	// Second pass: cross-row references. Deliberately after every row has
	// been validated on its own, so a broken derived_from target reports as
	// a broken target rather than as a mysterious reference failure.
	for _, f := range set.Feeds {
		if f.DerivedFrom == "" {
			continue
		}
		if f.DerivedFrom == f.ID {
			return FeedSet{}, fmt.Errorf("%w: %w: feed %q derives from itself",
				ErrInvalidDocument, ErrUnresolvedReference, f.ID)
		}
		parent, ok := set.ByID(f.DerivedFrom)
		if !ok {
			return FeedSet{}, fmt.Errorf("%w: %w: feed %q derives from %q, which is not in this document",
				ErrInvalidDocument, ErrUnresolvedReference, f.ID, f.DerivedFrom)
		}
		if parent.SyncMechanism == SyncDerived {
			return FeedSet{}, fmt.Errorf("%w: %w: feed %q derives from %q, which is itself derived",
				ErrInvalidDocument, ErrUnresolvedReference, f.ID, f.DerivedFrom)
		}
	}

	return set, nil
}

// feedKeys is the complete set of keys a feed row may declare. Anything else
// is ErrUnknownKey — see that error's note on why a silent skip is not an
// option.
var feedKeys = []string{
	"id",
	"url",
	"enabled",
	"auth_mode",
	"credential_env",
	"credential_header",
	"sync_mechanism",
	"interval_seconds",
	"reconcile_interval_seconds",
	"baseline_interval_seconds",
	"freshness_slo_seconds",
	"on_failure",
	"license_tier",
	"license_spdx",
	"license_manual_note",
	"mirror_dir",
	"bootstrap_mechanism",
	"bootstrap_url",
	"derived_from",
}

func bindFeed(n *node, index int) (FeedConfig, error) {
	if n.kind != nodeMapping {
		return FeedConfig{}, fmt.Errorf("%w: line %d: feeds[%d] must be a mapping",
			ErrInvalidDocument, n.line, index)
	}
	where := fmt.Sprintf("feeds[%d]", index)
	if err := n.rejectUnknown(where, feedKeys); err != nil {
		return FeedConfig{}, err
	}

	f := FeedConfig{Enabled: true}

	str := func(key string) (string, bool, error) {
		child, ok := n.field(key)
		if !ok {
			return "", false, nil
		}
		v, err := child.asString(where + "." + key)
		return v, true, err
	}
	num := func(key string) (int, bool, error) {
		child, ok := n.field(key)
		if !ok {
			return 0, false, nil
		}
		v, err := child.asInt(where + "." + key)
		return v, true, err
	}

	var err error
	if f.ID, _, err = str("id"); err != nil {
		return FeedConfig{}, err
	}
	if f.ID == "" {
		return FeedConfig{}, fmt.Errorf("%w: line %d: %s declares no `id`",
			ErrInvalidDocument, n.line, where)
	}
	if !ValidFeedID(f.ID) {
		return FeedConfig{}, fmt.Errorf("%w: line %d: feed id %q must be lower-case letters, digits, dots and single hyphens, and must begin and end with a letter or digit",
			ErrInvalidDocument, n.line, f.ID)
	}
	// From here on the feed has a name, so errors can use it.
	where = fmt.Sprintf("feed %q", f.ID)

	if f.URL, _, err = str("url"); err != nil {
		return FeedConfig{}, err
	}
	if f.LicenseSPDX, _, err = str("license_spdx"); err != nil {
		return FeedConfig{}, err
	}
	if f.LicenseManualNote, _, err = str("license_manual_note"); err != nil {
		return FeedConfig{}, err
	}
	if f.MirrorDir, _, err = str("mirror_dir"); err != nil {
		return FeedConfig{}, err
	}
	if f.CredentialEnv, _, err = str("credential_env"); err != nil {
		return FeedConfig{}, err
	}
	if f.CredentialHeader, _, err = str("credential_header"); err != nil {
		return FeedConfig{}, err
	}
	if f.BootstrapURL, _, err = str("bootstrap_url"); err != nil {
		return FeedConfig{}, err
	}
	if f.DerivedFrom, _, err = str("derived_from"); err != nil {
		return FeedConfig{}, err
	}

	if enabledNode, ok := n.field("enabled"); ok {
		if f.Enabled, err = enabledNode.asBool(where + ".enabled"); err != nil {
			return FeedConfig{}, err
		}
	}

	authRaw, _, err := str("auth_mode")
	if err != nil {
		return FeedConfig{}, err
	}
	f.AuthMode = AuthMode(authRaw)
	if !f.AuthMode.Valid() {
		return FeedConfig{}, enumErr(where+".auth_mode", authRaw, literals(AuthModeValues()))
	}

	syncRaw, _, err := str("sync_mechanism")
	if err != nil {
		return FeedConfig{}, err
	}
	f.SyncMechanism = SyncMechanism(syncRaw)
	if !f.SyncMechanism.Valid() {
		return FeedConfig{}, enumErr(where+".sync_mechanism", syncRaw, literals(SyncMechanismValues()))
	}

	bootRaw, _, err := str("bootstrap_mechanism")
	if err != nil {
		return FeedConfig{}, err
	}
	f.BootstrapMechanism = BootstrapMechanism(bootRaw)
	if !f.BootstrapMechanism.Valid() {
		return FeedConfig{}, enumErr(where+".bootstrap_mechanism", bootRaw, literals(BootstrapMechanismValues()))
	}

	failRaw, _, err := str("on_failure")
	if err != nil {
		return FeedConfig{}, err
	}
	f.OnFailure = OnFailure(failRaw)
	if !f.OnFailure.Valid() {
		return FeedConfig{}, enumErr(where+".on_failure", failRaw, literals(OnFailureValues()))
	}

	// license_tier needs explicit presence tracking: 0 is a legal tier, so an
	// absent key and a declared `license_tier: 0` are indistinguishable in
	// the bound value and must not be indistinguishable in the error.
	tierValue, tierPresent, err := num("license_tier")
	if err != nil {
		return FeedConfig{}, err
	}
	if !tierPresent {
		return FeedConfig{}, fmt.Errorf("%w: %w: line %d: %s declares no `license_tier`",
			ErrInvalidDocument, ErrMissingLicenseTier, n.line, where)
	}
	f.LicenseTier = LicenseTier(tierValue)
	if !f.LicenseTier.Valid() {
		return FeedConfig{}, fmt.Errorf("%w: %w: line %d: %s declares license_tier %d, outside {0,1,2,3}",
			ErrInvalidDocument, ErrMissingLicenseTier, n.line, where, tierValue)
	}

	if f.IntervalSeconds, _, err = num("interval_seconds"); err != nil {
		return FeedConfig{}, err
	}
	if f.ReconcileIntervalSeconds, _, err = num("reconcile_interval_seconds"); err != nil {
		return FeedConfig{}, err
	}
	if f.BaselineIntervalSeconds, _, err = num("baseline_interval_seconds"); err != nil {
		return FeedConfig{}, err
	}
	if f.FreshnessSLOSeconds, _, err = num("freshness_slo_seconds"); err != nil {
		return FeedConfig{}, err
	}

	if err := validateFeed(&f, n.line, where); err != nil {
		return FeedConfig{}, err
	}
	return f, nil
}

// validateFeed applies every cross-field rule and resolves the one defaulted
// field (BootstrapURL). It mutates f only to resolve that default.
func validateFeed(f *FeedConfig, line int, where string) error {
	// --- Licence. Spine S8: a feed whose licence cannot be stated is a feed
	// Anvil cannot use. ---
	if f.LicenseSPDX == "" {
		return fmt.Errorf("%w: %w: line %d: %s states no `license_spdx`; say %s or %s with a `license_manual_note` rather than leaving it blank",
			ErrInvalidDocument, ErrMissingLicense, line, where, LicenseNone, LicenseNoAssertion)
	}
	if !validSPDXShape(f.LicenseSPDX) {
		return fmt.Errorf("%w: %w: line %d: %s declares license_spdx %q, which is not an SPDX identifier, %s, %s or a %s id",
			ErrInvalidDocument, ErrMissingLicense, line, where, f.LicenseSPDX,
			LicenseNone, LicenseNoAssertion, LicenseRefPrefix)
	}
	// SPDXNeedsManualNote and SPDXIsNone are the shared definitions A.4's gate
	// also calls. They are not inlined here again on purpose — see the note
	// above them.
	if SPDXNeedsManualNote(f.LicenseSPDX) && strings.TrimSpace(f.LicenseManualNote) == "" {
		return fmt.Errorf("%w: %w: line %d: %s declares license_spdx %q and must carry the quoted operative sentence in `license_manual_note`",
			ErrInvalidDocument, ErrMissingLicenseNote, line, where, f.LicenseSPDX)
	}
	if SPDXIsNone(f.LicenseSPDX) && f.LicenseTier != LicenseTier3 {
		return fmt.Errorf("%w: %w: line %d: %s declares no licence grant (%s) at tier %d; a source with no grant of rights is opt-in and risk-accepted, so it is legal only at tier %d",
			ErrInvalidDocument, ErrUndeclaredLicenseTier, line, where, LicenseNone,
			f.LicenseTier.Int(), LicenseTier3.Int())
	}

	// --- Mirror directory. Resolved here so no consumer re-derives the
	// default, and validated as one safe path segment because it becomes one:
	// a licence gate that can be pointed at ../../LICENSE reads the wrong
	// body. ---
	if f.MirrorDir == "" {
		f.MirrorDir = f.ID
	}
	if !ValidPathSegment(f.MirrorDir) {
		return fmt.Errorf("%w: line %d: %s declares mirror_dir %q; it must be one path segment of lower-case letters, digits, '.', '-' and '_', beginning and ending with a letter or digit",
			ErrInvalidDocument, line, where, f.MirrorDir)
	}

	// --- Outage behaviour. research/06 Risk #5. ---
	if f.OnFailure == OnFailureDisableFeed && f.LicenseTier != LicenseTier3 {
		return fmt.Errorf("%w: line %d: %s sets on_failure %q at tier %d; only a tier-%d opt-in feed may be dropped on failure, everything else serves stale data with a stamped staleness_seconds",
			ErrInvalidDocument, line, where, OnFailureDisableFeed, f.LicenseTier.Int(), LicenseTier3.Int())
	}

	// --- Polling shape. ---
	if f.SyncMechanism.Polled() {
		if f.IntervalSeconds <= 0 {
			return fmt.Errorf("%w: %w: line %d: %s is polled by %q and needs a positive `interval_seconds`",
				ErrInvalidDocument, ErrMissingInterval, line, where, f.SyncMechanism)
		}
	} else if f.IntervalSeconds != 0 {
		return fmt.Errorf("%w: %w: line %d: %s is not polled (sync_mechanism %q) and must declare interval_seconds 0, not %d",
			ErrInvalidDocument, ErrMissingInterval, line, where, f.SyncMechanism, f.IntervalSeconds)
	}

	if f.SyncMechanism == SyncDerived {
		if f.DerivedFrom == "" {
			return fmt.Errorf("%w: %w: line %d: %s is derived and must name the feed it arrives inside via `derived_from`",
				ErrInvalidDocument, ErrUnresolvedReference, line, where)
		}
		if f.BootstrapMechanism != BootstrapNone {
			return fmt.Errorf("%w: line %d: %s is derived, so its bootstrap_mechanism must be %q, not %q — its parent's bootstrap already carries it",
				ErrInvalidDocument, line, where, BootstrapNone, f.BootstrapMechanism)
		}
		if f.URL != "" {
			return fmt.Errorf("%w: %w: line %d: %s is derived and must declare no `url`; it is never fetched on its own account",
				ErrInvalidDocument, ErrInvalidURL, line, where)
		}
	} else if f.DerivedFrom != "" {
		return fmt.Errorf("%w: %w: line %d: %s sets derived_from but its sync_mechanism is %q, not %q",
			ErrInvalidDocument, ErrUnresolvedReference, line, where, f.SyncMechanism, SyncDerived)
	}

	if f.SyncMechanism == SyncNone && f.BootstrapMechanism == BootstrapNone {
		return fmt.Errorf("%w: line %d: %s is neither polled nor bootstrapped, so nothing would ever fill it",
			ErrInvalidDocument, line, where)
	}

	// A git fetch needs a clone to fetch into, and research/06 Risk #7 rules
	// out doing it against a shallow one, so these two travel together.
	if (f.SyncMechanism == SyncGitBloblessFetch) != (f.BootstrapMechanism == BootstrapBloblessClone) {
		return fmt.Errorf("%w: line %d: %s pairs sync_mechanism %q with bootstrap_mechanism %q; %q and %q are only meaningful together",
			ErrInvalidDocument, line, where, f.SyncMechanism, f.BootstrapMechanism,
			SyncGitBloblessFetch, BootstrapBloblessClone)
	}

	// --- URL shape. ---
	if f.SyncMechanism != SyncDerived {
		if f.URL == "" {
			return fmt.Errorf("%w: %w: line %d: %s declares no `url`",
				ErrInvalidDocument, ErrInvalidURL, line, where)
		}
		if err := checkURL(f.URL, line, where, "url"); err != nil {
			return err
		}
	}

	fetches := f.BootstrapMechanism == BootstrapBulkArchive || f.BootstrapMechanism == BootstrapBloblessClone
	switch {
	case f.BootstrapURL == "" && fetches:
		// The one defaulted field, resolved here so no consumer re-derives
		// it and no two consumers disagree about the default.
		f.BootstrapURL = f.URL
	case f.BootstrapURL != "" && !fetches:
		return fmt.Errorf("%w: %w: line %d: %s sets bootstrap_url but its bootstrap_mechanism %q fetches no artifact",
			ErrInvalidDocument, ErrInvalidURL, line, where, f.BootstrapMechanism)
	case f.BootstrapURL != "":
		if err := checkURL(f.BootstrapURL, line, where, "bootstrap_url"); err != nil {
			return err
		}
	}

	// --- Credentials. The secret is never in this file; only the name of
	// the environment variable that holds it. ---
	if f.AuthMode == AuthNone {
		if f.CredentialEnv != "" {
			return fmt.Errorf("%w: %w: line %d: %s sets credential_env with auth_mode %q",
				ErrInvalidDocument, ErrInvalidCredentialRef, line, where, AuthNone)
		}
	} else {
		if f.CredentialEnv == "" {
			return fmt.Errorf("%w: %w: line %d: %s uses auth_mode %q and must name the environment variable holding the credential in `credential_env`",
				ErrInvalidDocument, ErrInvalidCredentialRef, line, where, f.AuthMode)
		}
		if !validEnvName(f.CredentialEnv) {
			return fmt.Errorf("%w: %w: line %d: %s credential_env %q is not an environment variable NAME (A-Z, 0-9, underscore); the credential itself must never appear in this file",
				ErrInvalidDocument, ErrInvalidCredentialRef, line, where, f.CredentialEnv)
		}
	}
	if f.AuthMode == AuthAPIKeyHeader {
		if f.CredentialHeader == "" {
			return fmt.Errorf("%w: %w: line %d: %s uses auth_mode %q and must name the header the key travels in via `credential_header`",
				ErrInvalidDocument, ErrInvalidCredentialRef, line, where, AuthAPIKeyHeader)
		}
		if !validHeaderName(f.CredentialHeader) {
			return fmt.Errorf("%w: %w: line %d: %s credential_header %q is not a valid HTTP header name",
				ErrInvalidDocument, ErrInvalidCredentialRef, line, where, f.CredentialHeader)
		}
	} else if f.CredentialHeader != "" {
		return fmt.Errorf("%w: %w: line %d: %s sets credential_header with auth_mode %q; only %q carries one",
			ErrInvalidDocument, ErrInvalidCredentialRef, line, where, f.AuthMode, AuthAPIKeyHeader)
	}

	// --- Schedule coherence. ---
	if f.FreshnessSLOSeconds <= 0 {
		return fmt.Errorf("%w: %w: line %d: %s declares no positive `freshness_slo_seconds`; spine S6 stamps staleness against it on every record",
			ErrInvalidDocument, ErrInconsistentSchedule, line, where)
	}
	if f.FreshnessSLOSeconds < f.IntervalSeconds {
		return fmt.Errorf("%w: %w: line %d: %s sets freshness_slo_seconds %d below interval_seconds %d, which no poll cadence can meet",
			ErrInvalidDocument, ErrInconsistentSchedule, line, where, f.FreshnessSLOSeconds, f.IntervalSeconds)
	}
	if f.ReconcileIntervalSeconds < 0 || f.BaselineIntervalSeconds < 0 {
		return fmt.Errorf("%w: %w: line %d: %s declares a negative reconciliation or baseline cadence",
			ErrInvalidDocument, ErrInconsistentSchedule, line, where)
	}
	if f.ReconcileIntervalSeconds > 0 && f.ReconcileIntervalSeconds < f.IntervalSeconds {
		return fmt.Errorf("%w: %w: line %d: %s reconciles every %ds, more often than its %ds steady-state poll",
			ErrInvalidDocument, ErrInconsistentSchedule, line, where, f.ReconcileIntervalSeconds, f.IntervalSeconds)
	}
	if f.BaselineIntervalSeconds > 0 {
		if f.ReconcileIntervalSeconds > 0 && f.BaselineIntervalSeconds < f.ReconcileIntervalSeconds {
			return fmt.Errorf("%w: %w: line %d: %s re-baselines every %ds, more often than its %ds reconciliation pass",
				ErrInvalidDocument, ErrInconsistentSchedule, line, where, f.BaselineIntervalSeconds, f.ReconcileIntervalSeconds)
		}
		if f.BaselineIntervalSeconds < f.IntervalSeconds {
			return fmt.Errorf("%w: %w: line %d: %s re-baselines every %ds, more often than its %ds steady-state poll",
				ErrInvalidDocument, ErrInconsistentSchedule, line, where, f.BaselineIntervalSeconds, f.IntervalSeconds)
		}
		if !fetches {
			return fmt.Errorf("%w: %w: line %d: %s schedules a full-baseline self-heal but its bootstrap_mechanism %q has no artifact to re-pull",
				ErrInvalidDocument, ErrInconsistentSchedule, line, where, f.BootstrapMechanism)
		}
	}
	return nil
}

func checkURL(raw string, line int, where, key string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %w: line %d: %s %s is unparseable: %v",
			ErrInvalidDocument, ErrInvalidURL, line, where, key, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: %w: line %d: %s %s uses scheme %q; feed transport is https only, so a downgrade cannot be configured",
			ErrInvalidDocument, ErrInvalidURL, line, where, key, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: %w: line %d: %s %s has no host",
			ErrInvalidDocument, ErrInvalidURL, line, where, key)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %w: line %d: %s %s carries inline credentials; the only place a credential may live is the environment variable named by credential_env",
			ErrInvalidDocument, ErrInvalidURL, line, where, key)
	}
	return nil
}

// ValidFeedID is the ONE definition of a legal feed id. A.4's licence gate
// calls it rather than restating the rule: it used to keep its own, stricter
// rule that allowed '_' and forbade '.', so a feed id this loader accepted —
// `osv.dev`, say — was structurally refused by the gate that had to read its
// licence. Nothing in the repository should be able to answer this question
// twice.
//
// Lower-case letters, digits, dots and single (never doubled) hyphens, and the
// id must BEGIN AND END with a letter or digit. That last clause is not
// cosmetic: the id is the default value of MirrorDir and therefore becomes a
// path segment, and without it `.` and `..` were both legal feed ids.
func ValidFeedID(id string) bool {
	if id == "" {
		return false
	}
	if !isIDAlnum(rune(id[0])) || !isIDAlnum(rune(id[len(id)-1])) {
		return false
	}
	prevHyphen := false
	for _, r := range id {
		switch {
		case isIDAlnum(r), r == '.':
			prevHyphen = false
		case r == '-':
			if prevHyphen {
				return false
			}
			prevHyphen = true
		default:
			return false
		}
	}
	return true
}

// ValidPathSegment is the ONE definition of a name that may become a directory
// under mirror/. It is deliberately a SUPERSET of ValidFeedID, because
// MirrorDir defaults to the feed id and a default its own validator rejects
// would be a trap; it adds '_' and nothing else.
//
// It rejects every form of separator, `.` and `..`, and any name that does not
// begin and end with a letter or digit. A quarantine a path segment can walk
// out of is not a quarantine.
func ValidPathSegment(s string) bool {
	if s == "" || strings.ContainsAny(s, `/\`) {
		return false
	}
	if !isIDAlnum(rune(s[0])) || !isIDAlnum(rune(s[len(s)-1])) {
		return false
	}
	for _, r := range s {
		switch {
		case isIDAlnum(r), r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func isIDAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// validSPDXShape checks the SHAPE of a licence declaration, not membership in
// the SPDX licence list. A.4 owns resolution against checked-in LICENSE file
// bodies (spine S8), and a second, independently-staling SPDX list here would
// be exactly the duplicated vocabulary section 6 of the implementation plan
// closed ten instances of.
func validSPDXShape(s string) bool {
	if s == LicenseNone || s == LicenseNoAssertion {
		return true
	}
	if strings.HasPrefix(s, LicenseRefPrefix) {
		s = strings.TrimPrefix(s, LicenseRefPrefix)
		if s == "" {
			return false
		}
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '+':
		default:
			return false
		}
	}
	return s != ""
}

// validEnvName is what stops a pasted secret from being accepted where a
// variable name belongs: real tokens are lower-case and punctuated, and none
// of them survives this.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// validHeaderName accepts RFC 9110 field names (tchar).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	const tspecials = "!#$%&'*+-.^_`|~"
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(tspecials, r):
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// YAML subset decoder
// ---------------------------------------------------------------------------
//
// Anvil's module graph carries exactly one dependency (modernc.org/sqlite),
// and adding a YAML library is a licence decision the orchestrator owns, not
// one a worker packet makes on its own. internal/policy already met this and
// hand-wrote a strict subset decoder rather than reach for one; this is the
// production equivalent for the feed table, and it decodes exactly the subset
// feeds.example.yaml is written in:
//
//   - block mappings and block sequences
//   - plain, single-quoted and double-quoted scalars
//   - comments, including trailing ones
//
// Everything else — tabs in indentation, flow collections, block scalars,
// anchors, aliases, tags, multi-document streams, duplicate keys — is an
// ERROR, never a guess. A decoder that silently dropped a key would produce a
// feed that never polls and never complains, and the whole point of this
// package is that such a feed cannot exist.

type nodeKind int

const (
	nodeScalar nodeKind = iota
	nodeMapping
	nodeSequence
)

type node struct {
	kind   nodeKind
	line   int
	text   string // scalar only, already unquoted
	quoted bool   // scalar only: was it written in quotes
	seq    []*node
	keys   []string // mapping only, in document order
	vals   map[string]*node
}

func (n *node) field(key string) (*node, bool) {
	if n == nil || n.kind != nodeMapping {
		return nil, false
	}
	v, ok := n.vals[key]
	if !ok || v == nil {
		return nil, false
	}
	return v, true
}

func (n *node) rejectUnknown(where string, allowed []string) error {
	known := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		known[k] = true
	}
	for _, k := range n.keys {
		if !known[k] {
			prefix := ""
			if where != "" {
				prefix = where + ": "
			}
			return fmt.Errorf("%w: %w: line %d: %s%q; known keys are %s",
				ErrInvalidDocument, ErrUnknownKey, n.vals[k].line, prefix, k, strings.Join(allowed, ", "))
		}
	}
	return nil
}

func (n *node) asString(where string) (string, error) {
	if n.kind != nodeScalar {
		return "", fmt.Errorf("%w: line %d: %s must be a scalar", ErrInvalidDocument, n.line, where)
	}
	return n.text, nil
}

func (n *node) asInt(where string) (int, error) {
	if n.kind != nodeScalar {
		return 0, fmt.Errorf("%w: line %d: %s must be a scalar", ErrInvalidDocument, n.line, where)
	}
	if n.quoted {
		return 0, fmt.Errorf("%w: line %d: %s is %q, a quoted string where a number belongs",
			ErrInvalidDocument, n.line, where, n.text)
	}
	v, err := strconv.Atoi(n.text)
	if err != nil {
		return 0, fmt.Errorf("%w: line %d: %s is %q, which is not an integer",
			ErrInvalidDocument, n.line, where, n.text)
	}
	return v, nil
}

func (n *node) asBool(where string) (bool, error) {
	if n.kind != nodeScalar {
		return false, fmt.Errorf("%w: line %d: %s must be a scalar", ErrInvalidDocument, n.line, where)
	}
	if n.quoted {
		return false, fmt.Errorf("%w: line %d: %s is %q, a quoted string where a boolean belongs",
			ErrInvalidDocument, n.line, where, n.text)
	}
	switch n.text {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%w: line %d: %s is %q; write true or false",
		ErrInvalidDocument, n.line, where, n.text)
}

type rawLine struct {
	num    int
	indent int
	text   string
}

func decode(src string) (*node, error) {
	lines, err := scanLines(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return parseBlock(lines)
}

func scanLines(src string) ([]rawLine, error) {
	var out []rawLine
	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		text := strings.TrimSuffix(raw, "\r")

		lead := text[:len(text)-len(strings.TrimLeft(text, " \t"))]
		if strings.ContainsRune(lead, '\t') {
			return nil, fmt.Errorf("%w: line %d: tab in indentation", ErrInvalidDocument, num)
		}

		text = strings.TrimRight(stripComment(text), " ")
		trimmed := strings.TrimSpace(text)
		if trimmed == "" {
			continue
		}
		if trimmed == "---" || trimmed == "..." {
			return nil, fmt.Errorf("%w: line %d: multi-document streams are not supported",
				ErrInvalidDocument, num)
		}
		out = append(out, rawLine{
			num:    num,
			indent: len(text) - len(strings.TrimLeft(text, " ")),
			text:   strings.TrimLeft(text, " "),
		})
	}
	return out, nil
}

// stripComment removes a trailing comment. '#' starts one only outside quotes
// and only at the start of a line or after whitespace, so a value containing a
// '#' survives.
//
// It tracks backslash escapes inside double quotes. A licence note quoting a
// publisher's operative sentence contains \" pairs by construction — spine S8
// asks for exactly that — and a scanner that treated \" as a closing quote
// would mis-track quote state for the rest of the line and could truncate the
// note at a later '#'.
func stripComment(text string) string {
	var quote rune
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote == '"' && r == '\\':
			i++ // skip the escaped rune
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			if i == 0 || runes[i-1] == ' ' || runes[i-1] == '\t' {
				return string(runes[:i])
			}
		}
	}
	return text
}

func parseBlock(lines []rawLine) (*node, error) {
	base := lines[0].indent
	for _, ln := range lines {
		if ln.indent < base {
			return nil, fmt.Errorf("%w: line %d: indent %d is shallower than the block's %d",
				ErrInvalidDocument, ln.num, ln.indent, base)
		}
	}
	if isSeqItem(lines[0].text) {
		return parseSequence(lines, base)
	}
	return parseMapping(lines, base)
}

func isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func parseSequence(lines []rawLine, base int) (*node, error) {
	out := &node{kind: nodeSequence, line: lines[0].num}
	for i := 0; i < len(lines); {
		ln := lines[i]
		if ln.indent != base {
			return nil, fmt.Errorf("%w: line %d: expected a sequence item at indent %d",
				ErrInvalidDocument, ln.num, base)
		}
		if !isSeqItem(ln.text) {
			return nil, fmt.Errorf("%w: line %d: %q does not start a sequence item",
				ErrInvalidDocument, ln.num, ln.text)
		}

		end := i + 1
		for end < len(lines) && lines[end].indent > base {
			end++
		}

		after := ln.text[1:]
		rest := strings.TrimLeft(after, " ")
		restIndent := ln.indent + 1 + (len(after) - len(rest))

		var (
			item *node
			err  error
		)
		switch {
		case rest == "":
			if end == i+1 {
				return nil, fmt.Errorf("%w: line %d: empty sequence item", ErrInvalidDocument, ln.num)
			}
			item, err = parseBlock(lines[i+1 : end])
		case isMappingEntry(rest):
			sub := make([]rawLine, 0, end-i)
			sub = append(sub, rawLine{num: ln.num, indent: restIndent, text: rest})
			sub = append(sub, lines[i+1:end]...)
			item, err = parseBlock(sub)
		default:
			if end > i+1 {
				return nil, fmt.Errorf("%w: line %d: a scalar sequence item cannot have child lines",
					ErrInvalidDocument, ln.num)
			}
			item, err = parseScalar(rest, ln.num)
		}
		if err != nil {
			return nil, err
		}
		out.seq = append(out.seq, item)
		i = end
	}
	return out, nil
}

func parseMapping(lines []rawLine, base int) (*node, error) {
	out := &node{kind: nodeMapping, line: lines[0].num, vals: map[string]*node{}}
	for i := 0; i < len(lines); {
		ln := lines[i]
		if ln.indent != base {
			return nil, fmt.Errorf("%w: line %d: indent %d does not line up with the mapping's %d",
				ErrInvalidDocument, ln.num, ln.indent, base)
		}
		key, rest, ok := splitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("%w: line %d: %q is not a mapping entry",
				ErrInvalidDocument, ln.num, ln.text)
		}
		if _, dup := out.vals[key]; dup {
			return nil, fmt.Errorf("%w: line %d: duplicate key %q", ErrInvalidDocument, ln.num, key)
		}

		end := i + 1
		for end < len(lines) && lines[end].indent > base {
			end++
		}

		var (
			val *node
			err error
		)
		if rest != "" {
			if end > i+1 {
				return nil, fmt.Errorf("%w: line %d: key %q has both an inline value and child lines",
					ErrInvalidDocument, ln.num, key)
			}
			val, err = parseScalar(rest, ln.num)
		} else {
			if end == i+1 {
				return nil, fmt.Errorf("%w: line %d: key %q has no value; this loader has no implicit null",
					ErrInvalidDocument, ln.num, key)
			}
			val, err = parseBlock(lines[i+1 : end])
		}
		if err != nil {
			return nil, err
		}
		out.keys = append(out.keys, key)
		out.vals[key] = val
		i = end
	}
	return out, nil
}

func isMappingEntry(text string) bool {
	_, _, ok := splitKey(text)
	return ok
}

// splitKey splits "key: value" at the first colon outside quotes. The colon
// must end the line or be followed by a space, which keeps a scalar containing
// a colon — a URL, say — from being misread as a key.
func splitKey(text string) (key, rest string, ok bool) {
	var quote rune
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote == '"' && r == '\\':
			i++ // see stripComment: \" inside a quoted note is not a close
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ':':
			if i+1 < len(runes) && runes[i+1] != ' ' {
				return "", "", false
			}
			key = strings.TrimSpace(string(runes[:i]))
			if key == "" {
				return "", "", false
			}
			return key, strings.TrimSpace(string(runes[i+1:])), true
		}
	}
	return "", "", false
}

func parseScalar(text string, line int) (*node, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("%w: line %d: empty value", ErrInvalidDocument, line)
	}
	switch text[0] {
	case '[', '{':
		return nil, fmt.Errorf("%w: line %d: flow collections are not supported; write a block sequence or mapping",
			ErrInvalidDocument, line)
	case '|', '>':
		return nil, fmt.Errorf("%w: line %d: block scalars are not supported; quote the value on one line",
			ErrInvalidDocument, line)
	case '&', '*', '!', '%', '@', '`':
		return nil, fmt.Errorf("%w: line %d: anchors, aliases, tags and reserved indicators are not supported",
			ErrInvalidDocument, line)
	case '"':
		s, err := unquoteDouble(text, line)
		if err != nil {
			return nil, err
		}
		return &node{kind: nodeScalar, line: line, text: s, quoted: true}, nil
	case '\'':
		s, err := unquoteSingle(text, line)
		if err != nil {
			return nil, err
		}
		return &node{kind: nodeScalar, line: line, text: s, quoted: true}, nil
	}
	if strings.ContainsAny(text, "\"'") {
		return nil, fmt.Errorf("%w: line %d: a plain scalar may not contain a quote character; quote the whole value",
			ErrInvalidDocument, line)
	}
	return &node{kind: nodeScalar, line: line, text: text}, nil
}

func unquoteDouble(text string, line int) (string, error) {
	var b strings.Builder
	runes := []rune(text)
	for i := 1; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case '\\':
			if i+1 >= len(runes) {
				return "", fmt.Errorf("%w: line %d: trailing backslash in a quoted scalar", ErrInvalidDocument, line)
			}
			i++
			switch runes[i] {
			case '"':
				b.WriteRune('"')
			case '\\':
				b.WriteRune('\\')
			case 'n':
				b.WriteRune('\n')
			case 't':
				b.WriteRune('\t')
			default:
				return "", fmt.Errorf("%w: line %d: unsupported escape %q; this loader accepts \\\" \\\\ \\n \\t",
					ErrInvalidDocument, line, string(runes[i]))
			}
		case '"':
			if i != len(runes)-1 {
				return "", fmt.Errorf("%w: line %d: trailing text after a quoted scalar", ErrInvalidDocument, line)
			}
			return b.String(), nil
		default:
			b.WriteRune(r)
		}
	}
	return "", fmt.Errorf("%w: line %d: unterminated quoted scalar", ErrInvalidDocument, line)
}

func unquoteSingle(text string, line int) (string, error) {
	var b strings.Builder
	runes := []rune(text)
	for i := 1; i < len(runes); i++ {
		if runes[i] != '\'' {
			b.WriteRune(runes[i])
			continue
		}
		if i+1 < len(runes) && runes[i+1] == '\'' {
			b.WriteRune('\'')
			i++
			continue
		}
		if i != len(runes)-1 {
			return "", fmt.Errorf("%w: line %d: trailing text after a quoted scalar", ErrInvalidDocument, line)
		}
		return b.String(), nil
	}
	return "", fmt.Errorf("%w: line %d: unterminated quoted scalar", ErrInvalidDocument, line)
}
