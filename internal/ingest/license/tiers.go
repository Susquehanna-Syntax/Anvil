// Package license is Lane A's licence gate and the segregated mirror layout it
// enforces. This is step A.4 of plan/20-lane-a-ingestion-sca.md.
//
// # NO FEED IS ADMITTED BY A FRESH CLONE. THAT IS THE DESIGN.
//
// Clone this repository, run the gate, and every feed is refused. Nothing is
// broken. The publisher's own licence text is not in git — only a pin of it is
// — and until an operator deliberately acquires that text and records its
// digest, there is no evidence, and with no evidence there is no tier.
//
// The previous revision of this package did admit feeds out of a fresh clone,
// and A.6's critic found out why: every "body" it read was Anvil prose,
// committed alongside the very claim it was supposed to validate. Spine S8 says
// the gate "reads LICENSE file bodies, never API metadata", and the point of
// that rule is that THE BODY IS THE PUBLISHER'S EVIDENCE. A document Anvil
// wrote in the same commit as the feed row is not evidence of anything. It is
// worse than reading API metadata, because it looks rigorous: a reviewer sees a
// gate reading a file and stops asking who wrote the file.
//
// So the gate now rests on three artefacts, and refuses unless all three agree:
//
//	mirror/LICENSE-MANIFEST.toml       the PIN. Per feed: the canonical URL of
//	                                   the publisher's licence text, the sha256
//	                                   that text must have, and the SPDX id it
//	                                   is claimed to be. Checked into git.
//
//	<tier>/<dir>/LICENSE.full.txt      the EVIDENCE. The publisher's verbatim
//	                                   licence text, acquired deliberately and
//	                                   verified against the pin. NOT in git.
//
//	<tier>/LICENSE-NOTES.md            Anvil's RECORD: spine S8's manual
//	<tier>/<dir>/LICENSE (tier 2)      override, the quoted operative sentence,
//	                                   the provenance of the conclusion. In git,
//	                                   and deliberately NOT trusted to admit.
//
// # What Anvil's own prose is allowed to do
//
// Exactly one thing: make the gate STRICTER. The obligation a decision rests on
// is the maximum of what the publisher's verbatim text establishes and what
// Anvil's record establishes. Anvil's record can therefore raise a feed from
// notice to share-alike — which is how a hand-written provenance note saying
// "this inherits CC-BY-SA through Ubuntu" keeps working — and it can never
// lower one, and it can never supply the obligation on its own. A body Anvil
// wrote is not evidence that a feed may be mirrored; it is only ever evidence
// that Anvil already knew of a duty.
//
// # UNKNOWN IS NOT PUBLISHABLE.
//
// Tier 0 and Tier 1 are the publishable tiers: what lands there may be merged
// into an artifact Anvil ships. A body reaches them ONLY by being positively
// identified as one of a small, explicitly enumerated set of permissive licences
// — CC0, CC-BY-4.0, MIT, Apache-2.0, BSD, ISC, and the specific public-domain
// and terms-of-use cases the feed table needs. The enumeration is
// publishable.go's permissiveLicences.
//
// EVERYTHING ELSE IS QUARANTINED: share-alike, restricted, unrecognised,
// ambiguous, empty. Unknown is not publishable.
//
// That default is inverted from the previous revision, and the inversion is the
// substance of this rework. The old gate asked "is this share-alike?" and
// published when the answer was no, which made a substring table of share-alike
// wording the only thing between a reciprocal licence and publication. Two
// rounds of adversarial review defeated that table — the first with unlisted
// wording, the second with OSL-3.0's real operative sentence and with plain
// FORMATTING: hard line wrapping, NBSP, a doubled space, full-width forms. A
// substring table cannot match licence prose nobody anticipated, and text nobody
// anticipated is the only case that matters.
//
// The two questions differ exactly there. "Is it share-alike?" fails open on
// unanticipated text; "is it provably safe to publish?" fails closed on it. The
// share-alike marker table (classifierRules) is kept and still decides
// obligations, the tier-2 quarantine and the autogrep shape — it is a SECONDARY
// SIGNAL for classification and reporting. Nothing safety-critical rests on its
// completeness any more.
//
// # THE GATE FAILS CLOSED. THIS IS NOT NEGOTIABLE.
//
// A feed whose licence tier cannot be established is REFUSED — never admitted
// with a warning, never defaulted to Tier 0. Admitting it is how a share-alike
// obligation reaches Anvil's findings database silently, and once that database
// is published the mistake is unrecoverable. Every "I do not know" path returns
// an error, and every one of them returns a Decision whose Tier is NoTier:
//
//	no pinned manifest ............ ErrNoLicenseManifest
//	manifest unparseable .......... ErrInvalidLicenseManifest
//	feed absent from the pin ...... ErrUnpinnedLicenseBody
//	pin carries no sha256 ......... ErrUnpinnedLicenseBody
//	pin disagrees with the row .... ErrPinDisagreesWithRow
//	publisher text not acquired ... ErrNoLicenseBody
//	acquired text fails its pin ... ErrBodyDigestMismatch
//	no Anvil record ............... ErrNoLicenseBody
//	empty body .................... ErrNoLicenseBody
//	body matches no marker ........ ErrUnestablishedLicense
//	body not provably permissive .. ErrNotProvablyPublishable
//	body contradicts the row ...... ErrBodyContradictsDeclaration
//	share-alike outside tier 2 .... ErrShareAlikeQuarantine
//	restrictive terms ............. ErrRestrictedLicense
//	spine S5 excluded source ...... ErrExcludedSource
//
// A gate that refuses every feed until real evidence is present is correct and
// shippable. A gate that admits feeds on evidence Anvil wrote is not.
//
// # Why this is not an SPDX allowlist
//
// A.4's Forbidden actions rule out "a pure-SPDX allowlist as the sole gate", and
// the enumerated permissive set is not one. An allowlist keys on the DECLARED
// identifier — the thing a mislabelled artifact gets wrong and a registry
// reports wrongly, which is the whole of the CISA KEV case. What this gate keys
// on is the publisher's OPERATIVE TEXT, read after the marker table has had its
// say and after every refusal the marker table can produce. The declared
// identifier must agree with the text afterwards; it never substitutes for it.
//
// The gate also still resolves an OBLIGATION CLASS rather than an identity, by
// scanning for every marker it knows and taking the STRONGEST match. That is
// what defeats the autogrep shape: a text carrying both
// `SPDX-License-Identifier: Apache-2.0` and a GNU General Public License
// sentence classifies as share-alike, because share-alike outranks notice, and
// a Tier 0 route for it is refused with the reason that matters.
//
// The marker table matches OPERATIVE WORDING as well as licence names, which was
// A.6's blocker B1. Those markers stay, and they still classify: they are how a
// reciprocal text lands in tier 2 rather than merely failing to be published.
// The reciprocity markers carry no SPDX id, because "some licence with a
// share-alike duty" is the honest conclusion and guessing which one would be an
// invented licence finding.
//
// # Matching happens once, against normalised text
//
// Every marker, signature and exclusion in this package is matched against
// NormaliseForMatching's output: whitespace runs (newlines and NBSP included)
// collapsed to one space, compatibility forms folded, case folded, zero-width
// characters dropped. See normalise.go, which also records what that function
// does NOT do and why the gaps are survivable now that the default is inverted.
//
// # What this package does NOT do
//
//   - It does not fetch. Nothing here imports net/http. Acquisition is an
//     operator step run deliberately (mirror/README.md), and resolving a licence
//     against a live API is precisely the failure S8 names.
//   - It does not redeclare any of area 40's six frozen enums, and it does not
//     redeclare internal/ingest/config's vocabulary either: config.LicenseTier,
//     config.SPDXResolvable, config.SPDXIsNone, config.ValidFeedID and
//     config.ValidPathSegment are consumed, never restated. A.6's M4 found two
//     places where this package answered a question config had already
//     answered, and the two answers disagreed.
//   - It does not invent a fingerprint. anvil-fp/v1 lives in internal/record
//     and FINGERPRINT-SPEC.md defines it; the digests on a Decision are content
//     digests of licence files, are never presented as a finding identity, and
//     are never compared against a canonical fingerprint.
//   - It does not carry CIS Benchmark content, or text derived from reading one
//     (spine S5 hard exclusion).
package license

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
)

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const (
	// MirrorDirName is the root of the segregated on-disk feed mirror,
	// relative to the FS a Decision is resolved against. The tier
	// subdirectories under it are the physical separation research/01 Risk #3
	// asks for; they are directories rather than a column because a column
	// cannot stop a `cp -r`.
	MirrorDirName = "mirror"

	// NotesFileName is Anvil's per-tier licence RECORD for tiers 0, 1 and 3.
	// These tiers share one file because their sources impose no share-alike
	// obligation on each other. Each feed's record is a delimited block inside
	// it — see BodyBeginMarker.
	//
	// It is a record, not evidence. See the package doc.
	NotesFileName = "LICENSE-NOTES.md"

	// LicenseFileName is the record each TIER 2 source directory carries on
	// its own. Tier 2 does NOT share a notes file: S8's words are "segregated
	// directories with their own LICENSE files", and a shared file would be
	// one more thing that can be copied into a publishable artifact by
	// accident.
	LicenseFileName = "LICENSE"
)

// BodyBeginMarker and BodyEndMarker delimit one feed's record inside a per-tier
// LICENSE-NOTES.md.
//
// The delimiters are HTML comments so the file renders as ordinary Markdown for
// a human reader while remaining exactly parseable for the gate. The
// alternative — classifying the whole notes file — is wrong and quietly so: a
// tier 0 file that documents five sources would classify as whichever of the
// five is most restrictive, and every feed at that tier would inherit it.
func BodyBeginMarker(feedID string) string {
	return "<!-- anvil-license-body: " + feedID + " -->"
}

// BodyEndMarker returns the closing delimiter for feedID's record block.
func BodyEndMarker(feedID string) string {
	return "<!-- end anvil-license-body: " + feedID + " -->"
}

// markerNeedle is the substring both delimiters share. An extracted block
// containing it is malformed — a missing end marker would otherwise swallow
// every following block and classify them all as one body.
const markerNeedle = "anvil-license-body:"

// TierDir returns the mirror directory for a licence tier, e.g. "mirror/tier2".
// It is the ONLY place a tier number becomes a path component.
//
// An invalid tier yields the empty string rather than mirror/tier9: a tier that
// is not one of the four has no directory, and inventing one would create a
// mirror location outside the quarantine scheme. Every caller validates first.
func TierDir(t config.LicenseTier) string {
	if !t.Valid() {
		return ""
	}
	return path.Join(MirrorDirName, fmt.Sprintf("tier%d", t.Int()))
}

// NoTier is what Gate returns for the tier when it refuses.
//
// It is not 0. A.6's minor finding: tier 0 is the MOST permissive tier — always
// mirrored, publishable, no copyleft — so a caller that ignored the error got
// the single most dangerous default the type can express. NoTier is outside
// {0,1,2,3}, so config.LicenseTier(NoTier).Valid() is false and the mistake
// fails loudly wherever it is made.
const NoTier = -1

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrLicenseRefused is satisfied by errors.Is for EVERY refusal below, so
	// a caller that only needs "may I write this row" needs one check and
	// cannot accidentally treat an unrecognised refusal as success. That
	// matters more here than elsewhere: the fail-open bug in a licence gate
	// is silent and unrecoverable once published.
	ErrLicenseRefused = errors.New("license: feed refused by the licence gate")

	// ErrInvalidLicenseInfo reports a structurally unusable row: no feed id,
	// a tier outside {0,1,2,3}, an empty declared licence, or a directory
	// name that is not a single safe path segment.
	ErrInvalidLicenseInfo = errors.New("license: invalid licence info")

	// ErrNoLicenseManifest reports that mirror/LICENSE-MANIFEST.toml could not
	// be read. Without the pin there is nothing to check a licence text
	// against, so there is no evidence, so there is no admissible feed.
	ErrNoLicenseManifest = errors.New("license: no pinned licence manifest")

	// ErrInvalidLicenseManifest reports a manifest this build cannot parse
	// exactly. There is no partial load: a pin half-understood is not a pin.
	ErrInvalidLicenseManifest = errors.New("license: unparseable licence manifest")

	// ErrUnpinnedLicenseBody reports a feed the manifest does not pin, or pins
	// without a sha256.
	//
	// EVERY ENTRY IN THIS REPOSITORY IS CURRENTLY IN THAT STATE, deliberately.
	// Pinning a digest requires downloading the publisher's licence text, and
	// no download has been performed. A digest written from memory would be a
	// fabrication and a placeholder digest would admit feeds on a number
	// nobody checked, so the manifest says "unpinned" and the gate refuses.
	ErrUnpinnedLicenseBody = errors.New("license: licence body is not pinned")

	// ErrPinDisagreesWithRow reports a manifest entry whose tier, directory or
	// claimed identifier does not match the feed row being gated. The evidence
	// is bound to the feed: a row that has been re-tiered or re-homed since
	// its licence text was pinned must be re-pinned, not silently gated
	// against another feed's file.
	ErrPinDisagreesWithRow = errors.New("license: pinned manifest disagrees with the feed row")

	// ErrNoLicenseBody reports that a required licence document could not be
	// read: the publisher's verbatim text has not been acquired, the feed's
	// record block is missing from the tier's notes file, or what was found is
	// empty.
	//
	// This is the headline fail-closed path, and on a fresh clone it is the
	// expected one. A feed in this state is refused until someone acquires the
	// publisher's own licence text beside the data.
	ErrNoLicenseBody = errors.New("license: no checked-in licence body")

	// ErrBodyDigestMismatch reports an acquired licence text whose bytes do
	// not match the manifest's pin. The publisher changed their terms, the
	// fetch was tampered with, or someone edited the evidence. All three are
	// refusals and none of them is retried.
	ErrBodyDigestMismatch = errors.New("license: licence body does not match its pinned digest")

	// ErrAmbiguousLicenseBody reports a notes file whose record block for this
	// feed is duplicated, unterminated, or nested inside another.
	ErrAmbiguousLicenseBody = errors.New("license: ambiguous licence body")

	// ErrUnestablishedLicense reports a body that matched no marker at all.
	// The obligation could not be established, so the tier could not be
	// established, so the feed is refused. Admitting it with a warning is the
	// exact failure this gate exists to prevent.
	ErrUnestablishedLicense = errors.New("license: licence tier could not be established from the body")

	// ErrNotProvablyPublishable reports a body routed to a publishable tier
	// that was not positively identified as EXACTLY ONE of the enumerated
	// permissive licences — either none of them matched, or several did and
	// which terms govern the data is therefore ambiguous.
	//
	// THIS IS THE INVERTED DEFAULT, and it is the refusal that catches the case
	// two rounds of review found: a licence nobody listed. It fires for OSL-3.0,
	// for CDDL, for MS-PL, for a licence written next year, and for a permissive
	// text this package has simply never been taught — all of which are the same
	// case, "not recognised", and none of which is publishable. The fix for a
	// genuine permissive source refused here is to enumerate it in
	// publishable.go on the evidence of its text, deliberately.
	ErrNotProvablyPublishable = errors.New("license: body is not positively identified as a permissive licence, so it is not publishable")

	// ErrBodyContradictsDeclaration reports a licence text that names a
	// different licence from the row's or the pin's declared identifier. The
	// BODY WINS and the row is refused: the declaration is the thing that can
	// be wrong.
	ErrBodyContradictsDeclaration = errors.New("license: checked-in body contradicts the declared licence")

	// ErrMissingManualNote reports a row that needs spine S8's manual-override
	// field and does not carry it — a NONE/NOASSERTION/LicenseRef- identifier,
	// or metadata that disagrees with the declaration (the CISA KEV shape).
	ErrMissingManualNote = errors.New("license: licence needs the S8 manual note")

	// ErrShareAlikeQuarantine reports a share-alike source routed anywhere but
	// Tier 2, or a Tier 2 route requested for a source that carries no
	// share-alike obligation. Tier 2 is a quarantine, and a quarantine with
	// the wrong things in it is not a quarantine.
	ErrShareAlikeQuarantine = errors.New("license: share-alike source must be quarantined in tier 2")

	// ErrRestrictedLicense reports terms that forbid the redistribution Anvil
	// needs: a Commons Clause rider, non-commercial or no-derivatives terms,
	// internal-business-use-only rules, an unredistributable subscription key.
	ErrRestrictedLicense = errors.New("license: restrictive terms forbid mirroring")

	// ErrUndeclaredLicenseTier reports LicenseSPDX = NONE outside Tier 3. A
	// source with no grant of rights is opt-in and risk-accepted by
	// definition (research/01's Tier 3), never part of the always-mirrored
	// set. internal/ingest/config refuses the same shape at load time; this
	// gate refuses it again because config is not the only way a LicenseInfo
	// can be constructed.
	ErrUndeclaredLicenseTier = errors.New("license: undeclared licence outside tier 3")

	// ErrExcludedSource reports content spine S5 excludes outright — CIS
	// Benchmark material in any form, including text written by reading one.
	// It is a separate error from ErrRestrictedLicense because it is not a
	// licence conclusion: it is a hard exclusion that no manual note, tier or
	// operator flag may override.
	ErrExcludedSource = errors.New("license: spine S5 excluded source")

	// ErrTierRouting reports an output path that does not belong to the tier
	// that produced it. The case it exists for is the one research/01 Risk #3
	// names: Tier 2 content under mirror/tier0 or mirror/tier1.
	ErrTierRouting = errors.New("license: output path does not belong to this tier")
)

func refuse(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrLicenseRefused, sentinel, fmt.Sprintf(format, args...))
}

// refusal is what EVERY refusing return in Resolve goes through.
//
// It exists because returning a bare `Decision{}` beside an error was a live
// defect: Decision{}.Tier
// is config.LicenseTier(0), and tier 0 is the MOST permissive tier this system
// has — always mirrored, publishable, no copyleft. A caller that read the
// decision without checking the error got the single most dangerous value the
// type can express, out of the documented entry point. Gate had been fixed to
// return NoTier; Resolve had not, and Resolve is what callers who need the
// evidence use.
//
// NoTier is outside {0,1,2,3}, so the Tier on a refused decision fails
// config.LicenseTier.Valid() and cannot be mistaken for permission anywhere.
func refusal(err error) (Decision, error) {
	return Decision{Tier: config.LicenseTier(NoTier)}, err
}

// refusedBy builds the refusal and the refused decision together, so that the
// two cannot drift apart. Every constructed refusal in Resolve goes through it
// and there is no other way to return one.
func refusedBy(sentinel error, format string, args ...any) (Decision, error) {
	return refusal(refuse(sentinel, format, args...))
}

// ---------------------------------------------------------------------------
// Obligation — what the licence actually costs, which is what decides the tier
// ---------------------------------------------------------------------------

// Obligation is the class of duty a licence imposes on Anvil when Anvil
// redistributes the data. It is ORDERED by restrictiveness, and Classify
// returns the strongest class any marker in the text matched.
//
// The tier decision keys on this and not on the SPDX identifier, because the
// identifier is what a mislabelled artifact gets wrong. research/01's tiers map
// onto it directly: Tier 0 and Tier 1 differ by whether a NOTICE file is
// required, which is an attribution detail; Tier 2 exists for exactly one
// class, ObligationShareAlike; Tier 3 exists for the case where no grant was
// made at all.
type Obligation int

// The obligation classes, ascending in restrictiveness. ObligationUnknown must
// remain the zero value: an unclassified body is refused, and a zero value that
// meant "permissive" would make the fail-closed rule depend on remembering to
// set a field.
const (
	// ObligationUnknown means no marker matched. It is a REFUSAL, not a
	// permissive default.
	ObligationUnknown Obligation = iota

	// ObligationPublicDomain: no rights reserved, no duties. CC0-1.0 and US
	// Government works.
	ObligationPublicDomain

	// ObligationNotice: attribution and/or notice retention. MIT, Apache-2.0,
	// BSD, CC-BY-4.0, CVE-TOU, MITRE's Terms of Use. research/01's Tier 1
	// ("keep NOTICE file") is this class; Tier 0 admits it too, because
	// CVE-TOU sits at Tier 0 and requires attribution.
	ObligationNotice

	// ObligationShareAlike: redistribution of a derivative obliges the same
	// terms. CC-BY-SA-4.0, ODbL-1.0, the GPL family, MPL, EPL. This is the
	// one class that can reach Anvil's own findings database and change its
	// licence, and it is the reason Tier 2 exists.
	ObligationShareAlike

	// ObligationRestricted: terms Anvil cannot satisfy while mirroring at all.
	// Always refused, at every tier.
	ObligationRestricted
)

// String renders an obligation for diagnostics.
func (o Obligation) String() string {
	switch o {
	case ObligationPublicDomain:
		return "public-domain"
	case ObligationNotice:
		return "notice"
	case ObligationShareAlike:
		return "share-alike"
	case ObligationRestricted:
		return "restricted"
	default:
		return "unknown"
	}
}

// ShareAlike reports whether this obligation is the quarantined class.
func (o Obligation) ShareAlike() bool { return o == ObligationShareAlike }

// ---------------------------------------------------------------------------
// The classifier — the body read S8 requires
// ---------------------------------------------------------------------------

// excludedMarkers are spine S5's hard exclusions, detected in the licence text
// itself. They are checked BEFORE classification and refuse unconditionally: no
// tier, note or operator flag admits them.
//
// CIS Benchmark content is excluded "in any form, including rules written by
// reading one" (S5), which is why the publisher's name is a marker as well as
// the product name. research/12 §5 puts CIS out of Lane A's feed set entirely;
// this check exists for the day someone adds it back by mistake.
var excludedMarkers = []struct {
	marker string
	why    string
}{
	{"cis benchmark", "CIS Benchmark content — spine S5 hard exclusion, in any form"},
	{"cis benchmarks", "CIS Benchmark content — spine S5 hard exclusion, in any form"},
	{"center for internet security", "CIS-published content — spine S5 hard exclusion"},
	{"cis critical security controls", "CIS-published content — spine S5 hard exclusion"},
}

type classifierRule struct {
	marker string
	spdx   string
	ob     Obligation
}

// classifierRules is the marker table Classify scans. Every marker is written in
// the form NormaliseForMatching produces and is matched as a substring of the
// NORMALISED text — so hard wrapping, NBSP, doubled spaces and full-width forms
// no longer decide whether a marker fires.
// TestEveryMarkerIsAlreadyNormalised asserts the "already normalised" half,
// because a marker that is not can never match and would fail silently.
//
// WHAT THIS TABLE IS NOW, AND WHAT IT IS NOT. It has two jobs and neither of
// them is the one it used to fail at.
//
//   - IT CLASSIFIES. It decides the obligation a Decision reports, it routes
//     reciprocal sources into the tier-2 quarantine, and it catches the autogrep
//     shape — an Apache-2.0 identifier over a GPL sentence.
//   - IT VETOES. identity.go's otherLicenceContent reads the share-alike and
//     restricted rows below as evidence that a document claiming to be
//     permissive carries reciprocity or restriction wording as well. That use is
//     a REFUSAL trigger, so a missing marker there costs a refusal that should
//     have happened rather than an admission that should not.
//
// It is NOT what stands between a reciprocal licence and publication — that is
// the enumerated permissive set in publishable.go, which a body must match
// POSITIVELY and EXCLUSIVELY to reach tier 0 or 1. Two rounds of review defeated
// this table with wording it did not list, and the answer to that is not a
// longer table. Completeness here is a nice-to-have; before the inversion it was
// a safety property this shape of code cannot provide.
//
// THREE PROPERTIES OF THIS TABLE ARE LOAD-BEARING:
//
//  1. Classify takes the STRONGEST obligation any marker matched, not the
//     first. A text carrying an Apache-2.0 identifier over a GNU General Public
//     License sentence is share-alike, which is the autogrep shape and the
//     reason a declared-identifier allowlist is forbidden here.
//
//  2. Within one obligation class the table is ordered NAMED IDENTIFIERS FIRST,
//     because Classify reports the identifier of the first matched rule at the
//     winning rank that names one. A CC0 text that also says "public domain"
//     therefore reports CC0-1.0 rather than nothing.
//
//  3. The share-alike class matches OPERATIVE WORDING, not only names. This is
//     A.6's blocker B1. A licence text that imposes reciprocity without ever
//     calling itself share-alike — a bare "under the same license" clause, a
//     CC deed sentence, a licence URL — was previously classified as notice and
//     admitted into the publishable tier, and a share-alike obligation that
//     reaches published findings cannot be withdrawn. The reciprocity markers
//     are the operative sentences of the licences research/01 Risk #3 names.
//
// A rule with an empty spdx contributes an obligation and no identity. That is
// deliberate for the GPL family, for the reciprocity wording and for generic
// attribution language: guessing GPL-2.0-only from the words "GNU General
// Public License" would be an invented licence conclusion, and the obligation
// is the part that decides the tier anyway.
//
// FALSE POSITIVES POINT THE SAFE WAY. A permissive text wrongly read as
// share-alike is refused at tier 0/1 and an operator investigates. A share-alike
// text wrongly read as permissive is now still refused, because reaching tier
// 0/1 needs a positive permissive identification that a share-alike text does
// not have — that is the inversion. The markers below are chosen to avoid
// wording that CC-BY-4.0 and Apache-2.0 also use — "Adapted Material" and
// "Adapter's License" appear in CC-BY-4.0 and are deliberately NOT markers, and
// TestPermissiveLicenceTextsAreNotDraggedIntoQuarantine holds that line — but
// where a judgement call remains it is made in the direction of refusing.
var classifierRules = []classifierRule{
	// ---- Restricted: Anvil cannot mirror these at any tier ----
	{marker: "commons clause", ob: ObligationRestricted},
	{marker: "internal business use only", ob: ObligationRestricted},
	{marker: "not permitted to redistribute", ob: ObligationRestricted},
	{marker: "may not be redistributed", ob: ObligationRestricted},
	{marker: "non-commercial", ob: ObligationRestricted},
	{marker: "noncommercial", ob: ObligationRestricted},
	{marker: "no derivative works", ob: ObligationRestricted},
	{marker: "noderivatives", ob: ObligationRestricted},
	{marker: "licenses/by-nc", ob: ObligationRestricted},
	{marker: "licenses/by-nd", ob: ObligationRestricted},

	// ---- Share-alike, by name ----
	{marker: "cc-by-sa-4.0", spdx: "CC-BY-SA-4.0", ob: ObligationShareAlike},
	{marker: "cc-by-sa 4.0", spdx: "CC-BY-SA-4.0", ob: ObligationShareAlike},
	{marker: "cc by-sa 4.0", spdx: "CC-BY-SA-4.0", ob: ObligationShareAlike},
	{marker: "attribution-sharealike 4.0", spdx: "CC-BY-SA-4.0", ob: ObligationShareAlike},
	{marker: "attribution-share alike 4.0", spdx: "CC-BY-SA-4.0", ob: ObligationShareAlike},
	{marker: "odbl-1.0", spdx: "ODbL-1.0", ob: ObligationShareAlike},
	{marker: "odblv1", spdx: "ODbL-1.0", ob: ObligationShareAlike},
	{marker: "open database license", spdx: "ODbL-1.0", ob: ObligationShareAlike},
	{marker: "gnu affero general public license", ob: ObligationShareAlike},
	{marker: "gnu lesser general public license", ob: ObligationShareAlike},
	{marker: "gnu general public license", ob: ObligationShareAlike},
	{marker: "agpl-3.0", ob: ObligationShareAlike},
	{marker: "lgpl-2.1", ob: ObligationShareAlike},
	{marker: "gpl-2.0", ob: ObligationShareAlike},
	{marker: "gpl-3.0", ob: ObligationShareAlike},
	{marker: "mozilla public license", ob: ObligationShareAlike},
	{marker: "eclipse public license", ob: ObligationShareAlike},
	{marker: "cc-by-sa", ob: ObligationShareAlike},
	{marker: "attribution-sharealike", ob: ObligationShareAlike},
	{marker: "sharealike", ob: ObligationShareAlike},
	{marker: "share-alike", ob: ObligationShareAlike},
	{marker: "share alike", ob: ObligationShareAlike},
	{marker: "copyleft", ob: ObligationShareAlike},

	// ---- Share-alike, by licence URL. Precise, and present in the deeds and
	// legalcode of exactly the reciprocal licences. ----
	{marker: "licenses/by-sa/", ob: ObligationShareAlike},
	{marker: "opendatacommons.org/licenses/odbl", ob: ObligationShareAlike},
	{marker: "gnu.org/licenses/gpl", ob: ObligationShareAlike},
	{marker: "gnu.org/licenses/agpl", ob: ObligationShareAlike},
	{marker: "gnu.org/licenses/lgpl", ob: ObligationShareAlike},
	{marker: "mozilla.org/mpl", ob: ObligationShareAlike},

	// ---- Share-alike, by OPERATIVE WORDING. Blocker B1. A text that imposes
	// reciprocity without naming itself is still share-alike. ----
	{marker: "same license elements", ob: ObligationShareAlike},  // CC BY-SA 3(b)(1)
	{marker: "same licence elements", ob: ObligationShareAlike},  // British spelling
	{marker: "under these same terms", ob: ObligationShareAlike}, // the generic clause
	{marker: "under the same terms", ob: ObligationShareAlike},
	{marker: "under the same license", ob: ObligationShareAlike}, // CC deed wording
	{marker: "under the same licence", ob: ObligationShareAlike},
	{marker: "licensed under the same", ob: ObligationShareAlike},
	{marker: "distributed under the same", ob: ObligationShareAlike},
	{marker: "licensed as a whole at no charge", ob: ObligationShareAlike},         // GPL-2 §2(b)
	{marker: "license the entire work, as a whole", ob: ObligationShareAlike},      // GPL-3 §5(c)
	{marker: "is governed by the terms of this license", ob: ObligationShareAlike}, // MPL-2 §3.4
	{marker: "corresponding source", ob: ObligationShareAlike},                     // GPL family
	{marker: "reciprocal license", ob: ObligationShareAlike},

	// ---- Notice: attribution and/or notice retention ----
	{marker: "cc-by-4.0", spdx: "CC-BY-4.0", ob: ObligationNotice},
	{marker: "cc-by 4.0", spdx: "CC-BY-4.0", ob: ObligationNotice},
	{marker: "cc by 4.0", spdx: "CC-BY-4.0", ob: ObligationNotice},
	{marker: "creative commons attribution 4.0", spdx: "CC-BY-4.0", ob: ObligationNotice},
	{marker: "cve program terms of use", spdx: "CVE-TOU", ob: ObligationNotice},
	{marker: "cve-tou", spdx: "CVE-TOU", ob: ObligationNotice},
	{marker: "apache license, version 2.0", spdx: "Apache-2.0", ob: ObligationNotice},
	{marker: "apache-2.0", spdx: "Apache-2.0", ob: ObligationNotice},
	{marker: "permission is hereby granted, free of charge", spdx: "MIT", ob: ObligationNotice},
	{marker: "mit license", spdx: "MIT", ob: ObligationNotice},
	{marker: "must provide attribution", ob: ObligationNotice},
	{marker: "attribution is required", ob: ObligationNotice},
	{marker: "attribution required", ob: ObligationNotice},
	{marker: "with attribution", ob: ObligationNotice},
	{marker: "retain the above copyright notice", ob: ObligationNotice},
	{marker: "attribution", ob: ObligationNotice},

	// ---- Public domain ----
	{marker: "cc0-1.0", spdx: "CC0-1.0", ob: ObligationPublicDomain},
	{marker: "cc0 1.0", spdx: "CC0-1.0", ob: ObligationPublicDomain},
	{marker: "cc0 license", spdx: "CC0-1.0", ob: ObligationPublicDomain},
	{marker: "cc0", spdx: "CC0-1.0", ob: ObligationPublicDomain},
	{marker: "public domain dedication", ob: ObligationPublicDomain},
	{marker: "united states government work", ob: ObligationPublicDomain},
	{marker: "u.s. government work", ob: ObligationPublicDomain},
	{marker: "public domain", ob: ObligationPublicDomain},
}

// noGrantMarkers are the sentences a document uses to say that NO GRANT OF
// RIGHTS IS MADE. They exist for A.6's M1.
//
// Before them, a row declaring config.LicenseNone at Tier 3 was admitted on a
// body that matched nothing at all: the NONE branch returned before the
// ObligationUnknown refusal could run, so SILENCE WAS TREATED AS EVIDENCE OF
// ABSENCE. It is not. A document that says nothing about licensing is a
// document nobody has read carefully, and it is exactly what an unfetched page
// or a wrong URL produces.
//
// A NONE declaration must now be POSITIVELY evidenced: the publisher's text has
// to state that no licence is granted, or that rights are reserved, or that use
// is permitted only as a courtesy. EPSS is the worked example — research/01
// S18/S19 record no licence document and "attribution is requested", which is a
// request rather than a grant.
// The markers are deliberately POSITIVE statements. "attribution is requested"
// and "published free of charge" are NOT among them: they are the wording that
// makes a source look permissively licensed while granting nothing, and reading
// them as evidence of a NONE declaration would re-open the hole from the other
// side.
var noGrantMarkers = []string{
	"all rights reserved",
	"reserves all rights",
	"no license is granted",
	"no licence is granted",
	"no rights are granted",
	"no grant of rights",
	"no license has been granted",
	"no licence has been granted",
	"no license",
	"no licence",
	"not licensed",
}

// Classify reads a licence text and reports the strongest obligation it can
// establish, plus the SPDX identifier the text names, if it names one.
//
// Two sources are consulted and the STRONGER wins:
//
//   - classifierRules, the marker table, which is what recognises share-alike
//     and restricted terms and is the only thing that can produce those classes;
//   - permissiveLicences, the enumerated publishable set, which is what
//     recognises a permissive licence POSITIVELY rather than by the absence of a
//     copyleft marker.
//
// Taking the stronger is what keeps the autogrep shape working: an Apache-2.0
// text carrying a GPL sentence is identified as Apache-2.0 by the permissive set
// AND as share-alike by the marker table, and share-alike wins, so the
// identifier reported is the marker table's rather than Apache-2.0.
//
// It is exported because it is the substance of this gate and a critic has to be
// able to exercise it directly. It takes TEXT, never a URL and never an API
// response.
//
// AN ObligationUnknown RESULT IS NOT "PERMISSIVE"; it is "no evidence", and
// Resolve refuses it on every path. Neither is a non-Unknown result on its own
// enough to publish: tier 0/1 additionally requires IdentifyPermissive.
func Classify(body string) (spdx string, ob Obligation) {
	return classify(NormaliseForMatching(body))
}

// classify is Classify over already-normalised text.
func classify(n string) (string, Obligation) {
	best, spdx := classifyMarkers(n)

	if permSPDX, _, permOb, ok := identifyPermissive(n); ok {
		switch {
		case permOb > best:
			best, spdx = permOb, permSPDX
		case permOb == best && spdx == "":
			// The marker table established the class but named no identifier —
			// "united states government work", say. The enumerated set knows
			// which terms those are, so report them rather than nothing.
			spdx = permSPDX
		}
	}
	if best == ObligationUnknown {
		return "", ObligationUnknown
	}
	return spdx, best
}

// classifyMarkers is the marker table alone: the strongest obligation any rule
// matched, and the identifier of the first rule at that rank which names one.
//
// It is separate from classify so that a test can prove a body is invisible to
// the marker table and still refused — which is the property the B1 rewrite
// rests on, and which cannot be stated at all if the table and the enumerated
// set are only reachable together.
func classifyMarkers(n string) (Obligation, string) {
	best := ObligationUnknown
	for _, r := range classifierRules {
		if r.ob > best && containsNormalised(n, r.marker) {
			best = r.ob
		}
	}
	if best == ObligationUnknown {
		return ObligationUnknown, ""
	}
	for _, r := range classifierRules {
		if r.ob == best && r.spdx != "" && containsNormalised(n, r.marker) {
			return best, r.spdx
		}
	}
	return best, ""
}

// StatesNoGrant reports whether a text positively says that no licence was
// granted. It is what a config.LicenseNone declaration must be evidenced by.
func StatesNoGrant(body string) bool {
	hay := NormaliseForMatching(body)
	for _, m := range noGrantMarkers {
		if containsNormalised(hay, m) {
			return true
		}
	}
	return false
}

// excluded reports the first spine S5 exclusion the text trips, if any.
func excluded(text string) (string, bool) {
	hay := NormaliseForMatching(text)
	for _, e := range excludedMarkers {
		if containsNormalised(hay, e.marker) {
			return e.why, true
		}
	}
	return "", false
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// LicenseInfo — one row presented to the gate
// ---------------------------------------------------------------------------

// LicenseInfo is what a writer knows about a feed's licence before the gate
// runs. It is the gate's INPUT, and every field on it except Mirror comes from
// the operator's feed table.
type LicenseInfo struct {
	// FeedID is internal/ingest/config's FeedConfig.ID. It keys the record
	// block inside a tier's LICENSE-NOTES.md and the feed's entry in the
	// pinned manifest.
	FeedID string

	// Dir is the directory NAME (one path segment) this feed's mirrored data
	// and licence evidence live in, under its tier. Empty means FeedID.
	//
	// It comes from config.FeedConfig.MirrorDir, which is where the value is
	// configured and validated. A.6's blocker B2 was that this field used to
	// be supplied by the caller with no configured source at all: the three
	// Tier 2 rows have directories that differ from their ids, so nothing but
	// a test could reach the quarantine, and the licence evidence a decision
	// rested on was chosen by whoever called the gate rather than bound to the
	// feed row. It is now cross-checked against the pinned manifest, so a
	// caller who supplies the wrong directory is refused rather than gated
	// against another feed's licence.
	Dir string

	// DeclaredTier is the tier the feed table claims. It is a CLAIM: the gate
	// checks it against the pin and against the obligation the text
	// establishes, and refuses a route that would move a share-alike source
	// out of quarantine.
	DeclaredTier config.LicenseTier

	// DeclaredSPDX is the operator's declared identifier — an SPDX id, or one
	// of config.LicenseNone / config.LicenseNoAssertion / a
	// config.LicenseRefPrefix custom id. Never empty.
	DeclaredSPDX string

	// MetadataSPDX is what a registry or forge API reports, if anything.
	//
	// IT IS NEVER TRUSTED AND NEVER CLASSIFIED. It exists for one purpose: a
	// value that disagrees with DeclaredSPDX makes S8's manual note MANDATORY,
	// so the operator has to write down why the metadata is wrong. That is the
	// CISA KEV case — the forge says NOASSERTION, the README says CC0 — and
	// leaving the field empty simply means nobody asked a registry.
	MetadataSPDX string

	// ManualNote is spine S8's manual-override field: the quoted operative
	// sentence from the publisher's own licence text. Required whenever
	// DeclaredSPDX is not a resolvable SPDX identifier, and whenever
	// MetadataSPDX disagrees with DeclaredSPDX.
	ManualNote string

	// Mirror is the filesystem the pinned manifest and the licence bodies are
	// read from, rooted where MirrorDirName sits. Nil means os.DirFS("."),
	// i.e. the process working directory. Tests pass an fstest.MapFS; nothing
	// here ever opens a network connection.
	Mirror fs.FS
}

// FromFeed builds a LicenseInfo from a parsed feed row.
//
// There is no dir parameter. The mirror directory is config.FeedConfig.MirrorDir,
// resolved and validated by the loader, so a caller cannot choose which licence
// file a decision rests on. metadataSPDX is whatever a forge or registry
// reported, or "" if nothing did — it is recorded, never trusted.
func FromFeed(f config.FeedConfig, metadataSPDX string, mirror fs.FS) LicenseInfo {
	return LicenseInfo{
		FeedID:       f.ID,
		Dir:          f.MirrorDir,
		DeclaredTier: f.LicenseTier,
		DeclaredSPDX: f.LicenseSPDX,
		MetadataSPDX: metadataSPDX,
		ManualNote:   f.LicenseManualNote,
		Mirror:       mirror,
	}
}

// ---------------------------------------------------------------------------
// Decision — what the gate concluded, and the evidence it rests on
// ---------------------------------------------------------------------------

// Decision is a successful gate result. Every field is a conclusion the gate
// can defend from the bytes it read, which is why the file paths and digests
// are on it: a licence conclusion whose evidence cannot be re-derived is an
// assertion, and assertions are what S8 was written against.
type Decision struct {
	// FeedID echoes the row the decision is about.
	FeedID string

	// Tier is the licence tier the feed is admitted at. It equals
	// LicenseInfo.DeclaredTier — the gate never silently RE-tiers a feed, it
	// refuses a declaration the evidence contradicts, so that a wrong feed
	// table gets fixed rather than papered over.
	//
	// ON A REFUSAL IT IS NoTier (-1), WHICH IS NOT A VALID TIER. It is never 0.
	// Tier 0 is the most permissive tier this system has, so a zero-valued
	// Decision returned beside an error handed a careless caller the most
	// dangerous value the type can express. See Refused.
	Tier config.LicenseTier

	// Dir is the ONLY directory this feed's data may be written under, e.g.
	// "mirror/tier2/ubuntu". Slash-separated, relative to the mirror FS root.
	Dir string

	// LicenseFile is the PUBLISHER'S verbatim licence text the decision rests
	// on, and BodySHA256 is the digest of its exact bytes — which equals
	// PinnedSHA256, because a body that did not match its pin never produced a
	// Decision.
	LicenseFile string
	BodySHA256  string

	// PinnedSHA256 and TextURL are the manifest's pin for that file: what it
	// had to hash to, and where it came from. Carrying them makes the decision
	// auditable without re-reading the manifest.
	PinnedSHA256 string
	TextURL      string

	// NotesFile is Anvil's own record — the tier's LICENSE-NOTES.md block, or
	// the Tier 2 source's LICENSE — and NotesSHA256 is its digest.
	//
	// It is named separately from LicenseFile so that nobody can mistake the
	// two again. The record can only have made this decision STRICTER; it can
	// never have admitted the feed on its own.
	NotesFile   string
	NotesSHA256 string

	// EffectiveSPDX is the identifier the PUBLISHER'S TEXT named. When the
	// text established an obligation without naming an identifier it is
	// config.LicenseNoAssertion, never the row's declaration.
	//
	// A.6's M2: it used to fall back to the unverified YAML assertion and flow
	// straight into the A.2 cache's license_dir_manifest.spdx_id, so the
	// manifest reported a licence nobody had verified as though the gate had
	// established it. NOASSERTION is SPDX's own word for "no assertion is
	// made", and it is the truth in that case.
	EffectiveSPDX string

	// SPDXFromBody records whether EffectiveSPDX was read from the evidence.
	// False means the text established an obligation but named no identifier.
	SPDXFromBody bool

	// DeclaredSPDX is the row's own claim, carried so that a reader of the
	// decision can see the claim and the conclusion side by side without
	// either being laundered into the other.
	DeclaredSPDX string

	// Obligation is the class the evidence established, raised to Anvil's own
	// record where the record was stricter. This, not EffectiveSPDX, is what
	// decided the tier.
	Obligation Obligation

	// MetadataOverridden is true when a registry reported an identifier that
	// disagreed with the declaration and the body settled it. It is the CISA
	// KEV flag, and it is worth recording because it marks every row where a
	// pure-metadata gate would have reached a different answer.
	MetadataOverridden bool

	// NoteRequired is true when S8's manual override was mandatory for this
	// row. ManualNote is non-empty whenever it is.
	NoteRequired bool

	// ManualNote is the operative sentence carried through to the cache's
	// `advisory.license_manual_note`.
	ManualNote string
}

// ManifestRow is a row of the A.2 cache's `license_dir_manifest` table, whose
// column order is (directory, tier, license_file, spdx_id). A.4's Gate is that
// table's only writer (internal/ingest/cache/schema.go says so at the table's
// definition), so the row is built here and bound by the caller.
type ManifestRow struct {
	Directory   string
	Tier        int
	LicenseFile string
	SPDXID      string
}

// Refused reports whether this Decision is a refusal rather than an admission.
//
// It tests two things, and the second is not redundant. Every value Resolve
// returns alongside an error carries Tier = NoTier, which fails Valid. But the
// ZERO Decision — one nobody set, one a future code path forgets to fill in —
// carries Tier 0, which is valid AND is the most permissive tier this system
// has. An admitted decision always names the directory it admits to, so an
// empty Dir is the other half of "this is not permission".
func (d Decision) Refused() bool { return !d.Tier.Valid() || d.Dir == "" }

// ManifestRow projects a Decision onto the cache's licence-directory manifest.
//
// license_file names the PUBLISHER'S text, not Anvil's record, and spdx_id is
// EffectiveSPDX — so a row in that table is a claim the gate can defend from a
// pinned digest rather than a copy of the feed table's assertion.
//
// IT RETURNS AN ERROR BECAUSE A REFUSAL HAS NO ROW, and the previous signature
// could not say so. `Decision{}.ManifestRow()` returned Directory "" with Tier
// 0 — a valid tier, and the most permissive one this system has — without ever
// consulting Refused. A caller that projected before checking (or instead of
// checking) wrote tier 0 into `license_dir_manifest`, which is the A.2 cache's
// record of which directories are safe to merge. The zero Decision is the case
// that matters: it is what a future code path produces by forgetting to fill a
// field, and nothing about it looks wrong at the call site.
//
// The error satisfies ErrLicenseRefused like every other refusal in this
// package, so a caller switching on that sentinel handles it without a new arm.
func (d Decision) ManifestRow() (ManifestRow, error) {
	if d.Refused() {
		return ManifestRow{Tier: NoTier}, refuse(ErrTierRouting,
			"feed %q: this decision is a refusal (tier %d, dir %q), so it has no "+
				"license_dir_manifest row; check Refused (or the error from Resolve) before "+
				"projecting, because the zero Decision projects as tier 0 — the most permissive "+
				"tier there is",
			d.FeedID, d.Tier.Int(), d.Dir)
	}
	return ManifestRow{
		Directory:   d.Dir,
		Tier:        d.Tier.Int(),
		LicenseFile: d.LicenseFile,
		SPDXID:      d.EffectiveSPDX,
	}, nil
}

// CheckWritePath refuses any path that does not sit inside this decision's own
// directory. It is the second half of the quarantine: Gate chooses the right
// directory, and this refuses everything else.
func (d Decision) CheckWritePath(p string) error {
	clean, err := normalisePath(p)
	if err != nil {
		return err
	}
	if clean != d.Dir && !strings.HasPrefix(clean, d.Dir+"/") {
		return refuse(ErrTierRouting,
			"feed %q resolved to %s but the write path is %s", d.FeedID, d.Dir, clean)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

// Gate is the packet-named entry point and the ONLY code path any writer in A.7
// or A.8 may use to choose an output directory.
//
// It returns the licence tier and the directory the feed's data may be written
// under, or an error. Every error satisfies errors.Is(err, ErrLicenseRefused);
// there is no admitted-with-a-warning result, because a warning in a licence
// gate is a share-alike obligation reaching the findings database with a log
// line as its only trace.
//
// ON REFUSAL THE TIER IS NoTier (-1), NOT 0. Tier 0 is the most permissive tier
// this system has, so returning it alongside an error handed the most dangerous
// possible default to any caller who checked the error carelessly.
//
// Callers that need the evidence behind the answer — the licence file read, its
// digest, the resolved identifier, the manifest row — call Resolve instead.
// Gate is Resolve with the evidence dropped.
func Gate(row LicenseInfo) (tier int, dir string, err error) {
	d, err := Resolve(row)
	if err != nil {
		return NoTier, "", err
	}
	return d.Tier.Int(), d.Dir, nil
}

// Resolve runs the full gate and returns the decision with its evidence.
//
// The order of the checks below is itself a decision. Spine S5's hard exclusions
// run before any licence reasoning, because CIS Benchmark content is not a
// licence question and must not be reachable by a manual note. The pin is
// resolved before anything is read, because a body nobody pinned is not evidence
// however good it looks. The publisher's text is read before Anvil's record,
// because the record may only raise the conclusion the text establishes. And the
// share-alike quarantine check runs before the identity check, so that a
// mislabelled share-alike source is refused for the reason that actually matters.
func Resolve(info LicenseInfo) (Decision, error) {
	if err := validateInfo(info); err != nil {
		return refusal(err)
	}

	dirName := info.Dir
	if dirName == "" {
		dirName = info.FeedID
	}
	tierDir := TierDir(info.DeclaredTier)
	outDir := path.Join(tierDir, dirName)

	// Spine S5 first, on the declaration itself. Nothing has been read yet; a
	// row that names an excluded source must not even cause a read.
	if why, bad := excluded(info.FeedID + " " + info.DeclaredSPDX + " " + info.ManualNote); bad {
		return refusedBy(ErrExcludedSource, "feed %q: %s", info.FeedID, why)
	}

	fsys := info.Mirror
	if fsys == nil {
		fsys = os.DirFS(".")
	}

	// --- The pin. Without it there is no evidence, only prose. ---
	manifest, err := LoadManifest(fsys)
	if err != nil {
		return refusal(err)
	}
	pin, ok := manifest.Body(info.FeedID)
	if !ok {
		return refusedBy(ErrUnpinnedLicenseBody,
			"feed %q has no entry in %s, so no publisher licence text is pinned for it; "+
				"add the pin (canonical url, sha256, claimed spdx id) and acquire the text: %s",
			info.FeedID, ManifestFileName, AcquireCommand)
	}
	if pin.Tier != info.DeclaredTier || pin.Dir != dirName {
		return refusedBy(ErrPinDisagreesWithRow,
			"feed %q is routed to tier %d dir %q but %s pins it at tier %d dir %q; "+
				"re-pin the licence evidence rather than gating the row against another feed's file",
			info.FeedID, info.DeclaredTier.Int(), dirName,
			ManifestFileName, pin.Tier.Int(), pin.Dir)
	}
	if config.SPDXResolvable(info.DeclaredSPDX) && config.SPDXResolvable(pin.SPDXID) &&
		!strings.EqualFold(strings.TrimSpace(info.DeclaredSPDX), strings.TrimSpace(pin.SPDXID)) {
		return refusedBy(ErrPinDisagreesWithRow,
			"feed %q declares %q but %s pins its licence text as %q",
			info.FeedID, info.DeclaredSPDX, ManifestFileName, pin.SPDXID)
	}
	if !pin.Pinned() {
		return refusedBy(ErrUnpinnedLicenseBody,
			"feed %q: %s records no sha256 for %s, so nothing on disk can be shown to BE the "+
				"publisher's licence text; acquire it, read it, and record its digest (%s)",
			info.FeedID, ManifestFileName, pin.TextURL, AcquireCommand)
	}

	// --- The evidence: the publisher's verbatim licence text. ---
	verbatimPath := pin.Path()
	raw, err := fs.ReadFile(fsys, verbatimPath)
	if err != nil {
		return refusedBy(ErrNoLicenseBody,
			"feed %q: the publisher's licence text has not been acquired to %s (%v); fetch %s and verify it: %s",
			info.FeedID, verbatimPath, err, pin.TextURL, AcquireCommand)
	}
	verbatim := string(raw)
	verbatimSum := digestOf(verbatim)
	if verbatimSum != pin.SHA256 {
		return refusedBy(ErrBodyDigestMismatch,
			"feed %q: %s hashes to %s but %s pins %s; the publisher's terms changed, the fetch was "+
				"tampered with, or the evidence was edited — none of those is retried",
			info.FeedID, verbatimPath, verbatimSum, ManifestFileName, pin.SHA256)
	}
	if strings.TrimSpace(verbatim) == "" {
		return refusedBy(ErrNoLicenseBody,
			"feed %q: the acquired licence text at %s is empty", info.FeedID, verbatimPath)
	}
	if why, bad := excluded(verbatim); bad {
		return refusedBy(ErrExcludedSource,
			"feed %q: %s (found in %s)", info.FeedID, why, verbatimPath)
	}

	// --- Anvil's record. Required, and allowed only to make things stricter. ---
	notesPath := notesPathFor(info.DeclaredTier, tierDir, dirName)
	notes, err := readNotes(info, fsys, notesPath)
	if err != nil {
		return refusal(err)
	}
	if why, bad := excluded(notes); bad {
		return refusedBy(ErrExcludedSource,
			"feed %q: %s (found in %s)", info.FeedID, why, notesPath)
	}

	// Normalised once, here, and reused: the classifier and the enumerated
	// permissive set must be looking at the same bytes, and normalising twice is
	// two chances to normalise differently.
	normVerbatim := NormaliseForMatching(verbatim)
	bodySPDX, verbatimOb := classify(normVerbatim)
	obligation := verbatimOb
	if _, notesOb := Classify(notes); notesOb > obligation {
		// Anvil's record knows of a stronger duty than the publisher's text
		// states — an inherited obligation, say, as with the OSV aggregate.
		// Raising is safe and is the whole permitted influence of the record.
		obligation = notesOb
	}
	if bodySPDX != "" && config.SPDXResolvable(pin.SPDXID) &&
		!strings.EqualFold(bodySPDX, strings.TrimSpace(pin.SPDXID)) {
		return refusedBy(ErrBodyContradictsDeclaration,
			"feed %q: %s pins the text at %s as %q but the text itself states %q; the text wins",
			info.FeedID, ManifestFileName, verbatimPath, pin.SPDXID, bodySPDX)
	}

	// S8's manual override is mandatory in two situations, and both are about
	// the row's identifier being unreliable rather than about the body.
	metadataOverridden := info.MetadataSPDX != "" &&
		!strings.EqualFold(strings.TrimSpace(info.MetadataSPDX), strings.TrimSpace(info.DeclaredSPDX))
	noteRequired := config.SPDXNeedsManualNote(info.DeclaredSPDX) || metadataOverridden
	if noteRequired && strings.TrimSpace(info.ManualNote) == "" {
		reason := fmt.Sprintf("declared licence %q is not a resolvable SPDX identifier", info.DeclaredSPDX)
		if metadataOverridden {
			reason = fmt.Sprintf("registry metadata reports %q over a declared %q",
				info.MetadataSPDX, info.DeclaredSPDX)
		}
		return refusedBy(ErrMissingManualNote,
			"feed %q: %s, so the row must carry the quoted operative sentence from %s",
			info.FeedID, reason, verbatimPath)
	}

	decision := Decision{
		FeedID:             info.FeedID,
		Tier:               info.DeclaredTier,
		Dir:                outDir,
		LicenseFile:        verbatimPath,
		BodySHA256:         verbatimSum,
		PinnedSHA256:       pin.SHA256,
		TextURL:            pin.TextURL,
		NotesFile:          notesPath,
		NotesSHA256:        digestOf(notes),
		EffectiveSPDX:      bodySPDX,
		SPDXFromBody:       bodySPDX != "",
		DeclaredSPDX:       strings.TrimSpace(info.DeclaredSPDX),
		Obligation:         obligation,
		MetadataOverridden: metadataOverridden,
		NoteRequired:       noteRequired,
		ManualNote:         strings.TrimSpace(info.ManualNote),
	}
	if decision.EffectiveSPDX == "" {
		// M2: NOT the declaration. The gate did not verify it, so the gate
		// does not report it as verified.
		decision.EffectiveSPDX = config.LicenseNoAssertion
	}

	// The restricted refusal and the share-alike quarantine apply to EVERY
	// row, NONE declarations included. They are ahead of the NONE branch on
	// purpose: a row that declares no licence and whose evidence nonetheless
	// carries a reciprocity duty is a share-alike source sitting at tier 3,
	// outside the quarantine, and "the row said NONE" is not a defence.
	switch {
	case obligation == ObligationRestricted:
		return refusedBy(ErrRestrictedLicense,
			"feed %q: %s states terms Anvil cannot satisfy while mirroring", info.FeedID, verbatimPath)

	case obligation == ObligationShareAlike && info.DeclaredTier != config.LicenseTier2:
		return refusedBy(ErrShareAlikeQuarantine,
			"feed %q resolves to share-alike terms from %s but is routed to tier %d (%s); "+
				"share-alike sources are quarantined in tier 2 and never merged into a tier 0/1 artifact",
			info.FeedID, verbatimPath, info.DeclaredTier.Int(), outDir)

	case obligation != ObligationShareAlike && info.DeclaredTier == config.LicenseTier2:
		return refusedBy(ErrShareAlikeQuarantine,
			"feed %q resolves to %s terms from %s but is routed to tier 2; "+
				"tier 2 is the share-alike quarantine and admits nothing else",
			info.FeedID, obligation, verbatimPath)
	}

	// NONE means no grant of rights was ever made. It is not "we could not
	// find one" — that is NOASSERTION — and it is legal only at Tier 3, where
	// the source is opt-in and risk-accepted and changes no verdict.
	if config.SPDXIsNone(info.DeclaredSPDX) {
		// The contradiction test reads the PUBLISHER'S text alone. Anvil's
		// record describing the situation is not the publisher stating terms.
		if verbatimOb != ObligationUnknown {
			return refusedBy(ErrBodyContradictsDeclaration,
				"feed %q declares NONE (no grant of rights exists) but %s states %s terms",
				info.FeedID, verbatimPath, verbatimOb)
		}
		if info.DeclaredTier != config.LicenseTier3 {
			return refusedBy(ErrUndeclaredLicenseTier,
				"feed %q declares NONE at tier %d; a source with no grant of rights is tier 3 only",
				info.FeedID, info.DeclaredTier.Int())
		}
		// M1, THE FAIL-OPEN THIS BRANCH USED TO BE. It returned here, above
		// the ObligationUnknown refusal, so a body matching no marker at all
		// was ADMITTED whenever the row declared NONE at tier 3 — and a body
		// matching no marker is exactly what an unfetched page, a wrong URL or
		// an HTML error page produces. Silence is not evidence of absence. The
		// text has to SAY that nothing is granted.
		if !StatesNoGrant(verbatim) && !StatesNoGrant(notes) {
			return refusedBy(ErrUnestablishedLicense,
				"feed %q declares NONE but neither %s nor %s states that no licence is granted; "+
					"a document that says nothing about licensing is not evidence that nothing was licensed",
				info.FeedID, verbatimPath, notesPath)
		}
		decision.EffectiveSPDX = config.LicenseNone
		decision.SPDXFromBody = true
		return decision, nil
	}

	if obligation == ObligationUnknown {
		// THE FAIL-CLOSED CORE. No marker matched, so no obligation was
		// established, so no tier can be. Refuse.
		return refusedBy(ErrUnestablishedLicense,
			"feed %q: %s matched no licence marker, so its obligations are unknown; "+
				"check that the pinned url really is the publisher's operative text",
			info.FeedID, verbatimPath)
	}

	// ---- THE INVERTED DEFAULT ----
	//
	// Everything above this point refuses a body for something it SAID. What
	// follows refuses a body for what it did not say, and it is the only check
	// here that is not defeated by a wording nobody anticipated.
	//
	// Tier 0 and Tier 1 are the publishable tiers. To reach one, the publisher's
	// text must be POSITIVELY IDENTIFIED as one of the enumerated permissive
	// licences, and the obligation established must be one of the classes that
	// enumeration is allowed to carry. A text that is merely "not obviously
	// share-alike" gets neither. So does a text identified as SEVERAL of them:
	// a document naming more than one licence is ambiguous about which terms
	// govern the data, and ambiguous is quarantined.
	//
	// This runs after the share-alike and restricted refusals on purpose: a
	// reciprocal source must be refused for BEING RECIPROCAL, with
	// ErrShareAlikeQuarantine and the sentence that names the duty, not with the
	// generic "unrecognised". The two refusals overlap by design and the
	// specific one is worth more to whoever reads the log.
	if info.DeclaredTier == config.LicenseTier0 || info.DeclaredTier == config.LicenseTier1 {
		matches := permissiveMatches(normVerbatim)
		switch len(matches) {
		case 0:
			return refusedBy(ErrNotProvablyPublishable,
				"feed %q is routed to tier %d, which is publishable, but %s is not positively "+
					"identified as any of the permissive licences this gate enumerates (%s). "+
					"UNKNOWN IS NOT PUBLISHABLE: a body nobody recognised is quarantined, not "+
					"shipped. If these terms genuinely are safe to publish, enumerate them in "+
					"internal/ingest/license/publishable.go on the evidence of this text",
				info.FeedID, info.DeclaredTier.Int(), verbatimPath,
				strings.Join(permissiveNames(), "; "))
		case 1:
		default:
			named := make([]string, 0, len(matches))
			for _, m := range matches {
				named = append(named, m.name)
			}
			return refusedBy(ErrNotProvablyPublishable,
				"feed %q: %s is identified as %d different licences (%s), so which terms govern "+
					"the data is ambiguous; publishing on whichever signature happened to be "+
					"listed first is how a bundled reciprocal licence ships unnoticed. Split the "+
					"source, or pin the licence text that actually governs this feed",
				info.FeedID, verbatimPath, len(matches), strings.Join(named, ", "))
		}
		// HALF (b) OF IDENTITY. Everything above establishes that the document
		// CONTAINS one enumerated permissive licence. This establishes that it
		// contains nothing else, and only the two together mean the document
		// IS that licence.
		//
		// It is the third round's blocker B1: "this tree is MIT, the vendored
		// subtree under third_party/ is CDDL-1.0" satisfies the containment
		// test — the CDDL is invisible to a table of things Anvil may publish —
		// and used to publish at tier 0 and tier 1 with the reciprocal terms
		// attached. Eight bodies of that shape did — len(wrappedBodies) in
		// identity_test.go, which is the count this comment is about and which
		// it disagreed with for two revisions.
		if reasons := otherLicenceContent(normVerbatim, matches[0]); len(reasons) > 0 {
			return refusedBy(ErrNotProvablyPublishable,
				"feed %q: %s contains %s but is not ONLY %s — it also carries %s. A publishable "+
					"body must BE one permissive licence, not merely CONTAIN one: a LICENSE that "+
					"covers a vendored subtree under other terms ships those terms with the data, "+
					"and which terms govern which bytes is a question this gate cannot answer. "+
					"Split the source, or pin the licence text that actually governs this feed",
				info.FeedID, verbatimPath, matches[0].name, matches[0].name,
				strings.Join(reasons, "; "))
		}

		permName := matches[0].name
		if !publishableObligations[obligation] {
			// Unreachable today — restricted, share-alike and unknown are all
			// refused above — and deliberately not written as an assertion. A
			// class added to the Obligation enum tomorrow lands here and is
			// refused, rather than being admitted by an inequality nobody
			// revisited.
			return refusedBy(ErrNotProvablyPublishable,
				"feed %q: %s is identified as %s but the obligation established is %s, "+
					"which is not a class tier %d may carry",
				info.FeedID, verbatimPath, permName, obligation, info.DeclaredTier.Int())
		}
		// No identifier is copied out of the enumerated set here. Classify has
		// already merged it into bodySPDX where it applies, and doing it twice
		// would create a second answer to a question that must have one.
	}

	// Identity check, last and narrowest. It only fires where both sides name
	// something: a declared NOASSERTION or LicenseRef- id has nothing to
	// contradict, and its note has already been demanded above.
	if bodySPDX != "" && config.SPDXResolvable(info.DeclaredSPDX) &&
		!strings.EqualFold(bodySPDX, strings.TrimSpace(info.DeclaredSPDX)) {
		return refusedBy(ErrBodyContradictsDeclaration,
			"feed %q declares %q but %s states %q; the body wins",
			info.FeedID, info.DeclaredSPDX, verbatimPath, bodySPDX)
	}

	return decision, nil
}

// CheckWritePath refuses an output path that does not belong to the given tier.
//
// It is the standalone form of Decision.CheckWritePath, for the callers that
// hold a tier and a path but not the decision that produced them — a
// reconciliation pass walking the mirror, for instance. The case it exists for
// is research/01 Risk #3's: Tier 2 content appearing under mirror/tier0 or
// mirror/tier1, where a merged publishable artifact would pick it up.
func CheckWritePath(tier config.LicenseTier, p string) error {
	if !tier.Valid() {
		return refuse(ErrInvalidLicenseInfo, "tier %d is outside {0,1,2,3}", tier.Int())
	}
	clean, err := normalisePath(p)
	if err != nil {
		return err
	}
	want := TierDir(tier)
	if clean != want && !strings.HasPrefix(clean, want+"/") {
		return refuse(ErrTierRouting,
			"tier %d content may only be written under %s, not %s", tier.Int(), want, clean)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// notesPathFor returns Anvil's own record for a feed at a tier.
//
// Tier 2 reads a LICENSE inside the source's OWN directory, because S8 requires
// segregated directories with their own LICENSE files and a shared file is one
// more thing that can be copied into a publishable artifact. Every other tier
// reads its feed's record block out of the tier's shared LICENSE-NOTES.md.
func notesPathFor(tier config.LicenseTier, tierDir, dirName string) string {
	if tier == config.LicenseTier2 {
		return path.Join(tierDir, dirName, LicenseFileName)
	}
	return path.Join(tierDir, NotesFileName)
}

// readNotes reads Anvil's record for a feed, extracting the feed's block when
// the file is a shared per-tier notes file.
//
// Every failure here is a refusal, never an empty string: "the file was
// missing" and "the licence is permissive" must not be the same value.
func readNotes(info LicenseInfo, fsys fs.FS, notesPath string) (string, error) {
	raw, err := fs.ReadFile(fsys, notesPath)
	if err != nil {
		return "", refuse(ErrNoLicenseBody,
			"feed %q: cannot read Anvil's licence record %s: %v", info.FeedID, notesPath, err)
	}
	text := string(raw)

	if path.Base(notesPath) == NotesFileName {
		text, err = extractBlock(text, info.FeedID, notesPath)
		if err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(text) == "" {
		return "", refuse(ErrNoLicenseBody,
			"feed %q: the licence record in %s is empty", info.FeedID, notesPath)
	}
	return text, nil
}

// extractBlock pulls one feed's record out of a shared per-tier notes file.
//
// It refuses ambiguity rather than guessing: a duplicated begin marker, a
// missing end marker, or a marker of any kind surviving inside the extracted
// span all mean the file cannot be read unambiguously, and a licence gate that
// guesses is not a gate.
func extractBlock(text, feedID, notesPath string) (string, error) {
	begin := BodyBeginMarker(feedID)
	end := BodyEndMarker(feedID)

	if n := strings.Count(text, begin); n != 1 {
		if n == 0 {
			return "", refuse(ErrNoLicenseBody,
				"feed %q: %s carries no record block; expected %s",
				feedID, notesPath, begin)
		}
		return "", refuse(ErrAmbiguousLicenseBody,
			"feed %q: %s carries %d record blocks; expected exactly one", feedID, notesPath, n)
	}
	if n := strings.Count(text, end); n != 1 {
		return "", refuse(ErrAmbiguousLicenseBody,
			"feed %q: %s carries %d end markers for the record block; expected exactly one",
			feedID, notesPath, n)
	}

	start := strings.Index(text, begin) + len(begin)
	stop := strings.Index(text, end)
	if stop < start {
		return "", refuse(ErrAmbiguousLicenseBody,
			"feed %q: %s closes the record block before it opens", feedID, notesPath)
	}
	block := text[start:stop]
	if strings.Contains(block, markerNeedle) {
		return "", refuse(ErrAmbiguousLicenseBody,
			"feed %q: %s nests another record block inside this one", feedID, notesPath)
	}
	return block, nil
}

// validateInfo rejects a structurally unusable row before anything is read.
//
// The feed id and directory rules are internal/ingest/config's — ValidFeedID
// and ValidPathSegment — not this package's own. A.6's M4: these used to be
// restated here, more strictly, so a feed id the loader accepted (`osv.dev`)
// was structurally refused by the gate that had to read its licence, and a feed
// id of ".." was accepted by the loader and only caught here.
func validateInfo(info LicenseInfo) error {
	if info.FeedID == "" {
		return refuse(ErrInvalidLicenseInfo, "feed id is empty")
	}
	if !config.ValidFeedID(info.FeedID) {
		return refuse(ErrInvalidLicenseInfo,
			"feed id %q is not a legal feed id: lower-case letters, digits, dots and single "+
				"hyphens, beginning and ending with a letter or digit", info.FeedID)
	}
	if info.Dir != "" && !config.ValidPathSegment(info.Dir) {
		return refuse(ErrInvalidLicenseInfo,
			"directory %q must be one path segment of lower-case letters, digits, '.', '-' and '_', "+
				"beginning and ending with a letter or digit", info.Dir)
	}
	if !info.DeclaredTier.Valid() {
		return refuse(ErrInvalidLicenseInfo,
			"feed %q declares tier %d, which is outside {0,1,2,3}",
			info.FeedID, info.DeclaredTier.Int())
	}
	if strings.TrimSpace(info.DeclaredSPDX) == "" {
		return refuse(ErrInvalidLicenseInfo,
			"feed %q declares no licence; say NONE or NOASSERTION with the operative sentence, never nothing",
			info.FeedID)
	}
	return nil
}

// normalisePath converts a caller's path to the slash-separated, cleaned form
// the mirror layout is expressed in, refusing anything that escapes it.
//
// Backslashes are folded to slashes because Anvil builds on Windows and a
// filepath.Join there produces `mirror\tier2\ubuntu`; a quarantine that a path
// separator can walk out of is not a quarantine.
func normalisePath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", refuse(ErrTierRouting, "empty output path")
	}
	clean := path.Clean(strings.ReplaceAll(p, `\`, "/"))
	if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", refuse(ErrTierRouting,
			"output path %q must be relative to the mirror root and may not escape it", p)
	}
	return clean, nil
}
