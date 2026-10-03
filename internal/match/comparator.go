// Package match is Lane A's deterministic version comparator: step A.17 of
// plan/20-lane-a-ingestion-sca.md, and the component every other Lane A step
// feeds.
//
// ===========================================================================
// WHAT THIS PACKAGE IS
// ===========================================================================
//
// It answers exactly one question, for one package at a time:
//
//	Is this installed version inside a range some advisory says is vulnerable?
//
// plan/00-SPINE.md S1 is why the question is that small. CVE, OSV and GHSA
// describe vulnerable PACKAGE VERSIONS; a version comparator answers that
// exactly and for free, and research/12's Table A says "Should Anvil use an
// LLM? No — never" for both OS-package and dependency matching. THERE IS NO
// MODEL IN THIS PACKAGE OR ANYWHERE IN ITS CALL GRAPH, and there is no
// randomness, no clock, no network and no filesystem either. The package's
// direct imports are `context`, `sort`, `strconv`, `strings` and
// internal/record, and comparator_test.go fails if that list grows.
//
// ===========================================================================
// THE THREE RULES THAT SHAPE EVERY DECISION HERE
// ===========================================================================
//
// # 1. REFUSE WHAT YOU DO NOT UNDERSTAND
//
// A silently wrong CVE match is the worst output this lane can produce. It
// either tells an operator they are safe when they are not, or it floods them
// with false findings until they stop reading any of them — and the second
// failure destroys the first one's audience.
//
// So there is NO FALLBACK PATH. A version in a scheme this package does not
// implement is not compared as semver, not compared lexically, and not
// assumed unaffected. It produces a typed *Refusal, the refusal is counted in
// CoverageReport, and the operator can see the gap. RefusalReasons() is the
// closed allowlist of reasons; comparator_test.go asserts that every refusal
// the package can emit is in it.
//
// IMPLEMENTED SCHEMES: `deb` (dpkg_compare.go), `rpm` (rpm_compare.go),
// `apk` (apk_compare.go).
//
// TWO REFUSALS ARE NOT ABOUT THE DATA BEING BAD, AND THEY ARE THE TWO WORTH
// READING FIRST:
//
//   - RefusalEpochPresenceMismatch. An installed version spelling a non-zero
//     epoch against a range endpoint spelling none (or the reverse) is
//     refused rather than ordered. Both operands are valid versions; it is
//     the RANGE PREDICATE over them that this package will not decide. See
//     AffectedRange.checkEpochAgreement for the whole argument.
//   - RefusalUnmodelledOrdering. Two valid versions whose ORDER is decided by
//     a rule this package has not implemented and could not cite — today,
//     apk's explicit-zero-against-absence positions. See apk_compare.go rule
//     R8.
//
// # REPORTED GAPS THIS PACKAGE CANNOT CLOSE FROM INSIDE ITSELF
//
//   - A range endpoint written in a FOREIGN scheme that happens to parse in
//     the governing one is evaluated without complaint. `Fixed: "2.31.0"` on
//     a deb range is a PyPI version and also a legal Debian version, so
//     nothing here can tell them apart. Endpoints that DECLARE a differing
//     ecosystem are refused (RefusalMixedSchemeRange); undeclared ones are
//     only caught when the foreign string fails to parse.
//   - The vendor-first defence needs the CVE alias populated on BOTH the
//     vendor and the upstream row. Rows arrive from internal/ingest/cache,
//     which owns that column. Vendor rows that arrive without it are listed
//     in CoverageReport.UngroupedVendorAdvisories rather than silently
//     failing to defend.
//   - Epoch normalisation across feeds belongs to ingestion (A.14/A.16). Until
//     it exists, the epoch refusal above is how the gap stays countable.
//   - apk's ordering is IMPLEMENTED IN PART, and the part is now measured
//     rather than estimated. Against all 738 ordering rows of apk-tools'
//     own `test/unit/version.data` (transcribed in
//     corpus_transcribed_test.go), this package answers 674 correctly and
//     REFUSES 64: 58 because apk switches a numeric position with a leading
//     zero to a byte-wise string sort that apk_compare.go R7a does not model,
//     3 for the `~<commit>` suffix, and one each for an unrecognised suffix
//     word, a two-letter tail and a suffix number wider than this package's
//     bound. None is answered wrongly. dpkg and rpm answer every published
//     row of their suites except the five separator-only rpm rows, which are
//     refused by argument (see rpm_compare.go).
//
// REFUSED, EXPLICITLY: every language ecosystem — npm, pypi, golang, maven,
// nuget, cargo, gem, composer, conan, hex, pub, swift — and every OS
// ecosystem not in the three above. PEP 440, Go pseudo-versions and
// `+incompatible`, and Maven's qualifier ordering and bracket ranges are each
// a distinct algorithm with a distinct order, and none of them is implemented
// here. See ecosystemAllowlist in purl.go.
//
// SEMVER IS NOT IMPLEMENTED HERE AND IS NOT BORROWED FROM O.7.
// internal/policy/semver.go exists, and its own header states its scope: it
// parses a GIT TAG for the policy engine's `matchSemverBump`, its parser is
// unexported for exactly this reason, and it says in as many words that using
// it "to decide whether a package version falls inside a CVE's affected range
// would produce silently wrong matches". Consuming it is therefore not
// available and forking it is forbidden, so this package implements neither
// and refuses the ecosystems that would need it. That is a reported gap, not
// a hidden one.
//
// # 2. VENDOR ADVISORY WINS
//
// research/12 §3's worked example, from Trivy's own documentation:
// CVE-2023-32681 in python-requests is fixed upstream in 2.31.0, and Red Hat
// ships the fix BACKPORTED into `2.25.1-3.el9` without moving the upstream
// version. An upstream range of "< 2.31.0" therefore calls a patched host
// vulnerable — "if Trivy were to detect CVE-2023-32681 in this case, it would
// be a false positive".
//
// The cache's `affected.distro_backport` column marks a range as coming from a
// vendor/distro advisory rather than upstream. When both exist FOR THE SAME
// ADVISORY AND THE SAME PACKAGE, the vendor range decides and the upstream
// range is DISPLACED — never merged, never OR-ed. A displaced range that would
// have matched is recorded in CoverageReport.Defences, because a defence that
// leaves no trace is indistinguishable from a bug.
//
// SCOPE OF THE PRECEDENCE, AND A DELIBERATE DEVIATION FROM THE PACKET WORDING.
// A.17's Forbidden-actions line says "do not fall back to upstream-only
// version ranges when a vendor/distro advisory range exists for the same
// PACKAGE". Read literally, one vendor advisory about openssl would suppress
// every upstream advisory about openssl, including CVEs the vendor has never
// triaged — turning a false-positive defence into an unbounded false-negative
// generator, and the packet is equally clear that "a false negative is a
// missed vulnerability". The precedence is therefore scoped to the ADVISORY,
// which is the granularity at which the CVE-2023-32681 class actually occurs.
// The residue is REPORTED rather than silently kept:
// CoverageReport.UpstreamOnlyAdvisories lists every advisory decided by an
// upstream range for a package that has vendor coverage elsewhere, which is
// the package-level view the packet asked for, available for review without
// being wired to a suppression.
//
// # 3. ZERO FINDINGS IS NOT "CLEAN"
//
// Every Match call returns a CoverageReport alongside its results, and
// CoverageReport.AssertNotSilentlyClean refuses to let an empty result set be
// read as a clean host. Zero findings over zero evaluated packages is a
// collector that did not run. Zero findings with refusals outstanding is a
// partial answer. ZERO FINDINGS OVER AN EMPTY ADVISORY CACHE IS A DATABASE
// THAT DID NOT LOAD — a full inventory of well-formed packages compared
// against nothing at all, which is the shape of a deployment whose bootstrap
// has not run. All three are reported as what they are.
//
// The third one is in this list because it was NOT, and the guard named for
// preventing it did not read the field that detects it. A.18 walked 400 valid
// packages past it. "The tool ran and found nothing" and "the tool had
// nothing to compare against" are indistinguishable to a caller, and for a
// security scanner the second read as the first is the worst output
// available.
//
// WHAT THE GUARD DOES NOT DO, STATED HERE SO THE RULE IS NOT READ AS WIDER
// THAN IT IS. AssertNotSilentlyClean is not a per-package coverage check —
// PackagesWithNoAdvisoryData is tested all-or-nothing, because in a real
// advisory database most packages genuinely have no rows — and it is not a
// completeness check, because findings short-circuit it. Its full contract,
// including both limits, is on the function, and every sentence of that
// contract is asserted by
// TestAssertNotSilentlyCleanEstablishesExactlyWhatItsDocClaims.
//
// ===========================================================================
// DETERMINISM
// ===========================================================================
//
// plan/00-SPINE.md S6 requires a stable verdict. Everything in this package is
// a pure function of its inputs:
//
//   - The inventory is COPIED AND SORTED before evaluation, so two callers
//     submitting the same packages in different orders get byte-identical
//     output.
//   - Advisory ranges are sorted by a total key before evaluation, so the
//     "first matching range" that ends up in a MatchResult does not depend on
//     what order a source returned them in.
//   - No map is ever ranged over to produce output. Go re-randomises its map
//     seed PER PROCESS, so an unsorted map range is stable within one run and
//     different in the next — the exact bug that repeating a computation
//     inside one process cannot detect. comparator_test.go runs the whole
//     corpus in a SECOND OS PROCESS and compares, the way
//     internal/record's fingerprint conformance test does.
//   - There is no clock. `as_of` and `detected_at` belong to the collector
//     and to A.19's record emitter; a second time source here would be a
//     second answer to a question already owned elsewhere.
package match

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

// RefusalReason names why this package declined to answer. It is a CLOSED
// ALLOWLIST: RefusalReasons() is the census, Valid() is the membership test,
// and comparator_test.go asserts that every reason reachable from the
// package's exported surface is a member.
//
// A denylist here would be the same mistake this project has already paid for
// three times: the reason nobody listed is the one that walks through as an
// empty string and prints as "refused: ".
type RefusalReason string

const (
	// RefusalUnsupportedEcosystem: the ecosystem has no implemented
	// comparator. This is the npm/pypi/golang/maven answer.
	RefusalUnsupportedEcosystem RefusalReason = "unsupported_ecosystem"

	// RefusalUnsupportedPurlType: the purl type has no implemented
	// comparator.
	RefusalUnsupportedPurlType RefusalReason = "unsupported_purl_type"

	// RefusalNoPackageIdentity: the record carries no usable identity — no
	// ecosystem, no name, or no version. research/12 §3's false-negative
	// classes (unpackaged binaries, stripped metadata, third-party-repo
	// installs) all land here, and they are the reason CoverageReport counts
	// them separately from the other refusals.
	RefusalNoPackageIdentity RefusalReason = "no_package_identity"

	// RefusalMalformedPurl: the purl does not parse.
	RefusalMalformedPurl RefusalReason = "malformed_purl"

	// RefusalMalformedVersion: the version string is not valid in the scheme
	// it was presented under.
	RefusalMalformedVersion RefusalReason = "malformed_version"

	// RefusalIdentityConflict: two identity sources disagree — a purl whose
	// type resolves to one scheme next to an ecosystem that resolves to
	// another, or a purl name that is not the reported package name. Picking
	// a winner would be guessing which advisory feed to trust.
	RefusalIdentityConflict RefusalReason = "identity_conflict"

	// RefusalSchemeMismatch: an advisory range's ecosystem resolves to a
	// different scheme than the installed package's. Comparing an rpm EVR
	// against a Debian range is not a near miss; it is a different algorithm.
	RefusalSchemeMismatch RefusalReason = "scheme_mismatch"

	// RefusalMixedSchemeRange: the range's own endpoints declare different
	// ecosystems. "Introduced 1.2.3 (upstream semver), fixed 1.2.3-4.el9
	// (rpm)" is a real shape in real feeds, and there is no correct way to
	// guess which endpoint's scheme governs the comparison.
	RefusalMixedSchemeRange RefusalReason = "mixed_scheme_range"

	// RefusalAmbiguousUpperBound: the range names BOTH an exclusive `fixed`
	// and an inclusive `last_affected`. Those differ by exactly one version
	// and both are common in real advisories, so a range that names both is
	// a range whose author disagreed with themselves.
	RefusalAmbiguousUpperBound RefusalReason = "ambiguous_upper_bound"

	// RefusalUnboundedRange: the range names no bound at all and does not
	// set AllVersions. An empty introduced/fixed pair is what a FAILED PARSE
	// upstream of here looks like when it reaches the database, and it would
	// match every version of the package. It is refused rather than
	// evaluated; a genuine "every version is affected" advisory must set
	// AllVersions explicitly.
	RefusalUnboundedRange RefusalReason = "unbounded_range"

	// RefusalContradictoryRange: AllVersions is set alongside an explicit
	// bound. Same reasoning as RefusalAmbiguousUpperBound.
	RefusalContradictoryRange RefusalReason = "contradictory_range"

	// RefusalEpochPresenceMismatch: the installed version spells a non-zero
	// epoch and a range endpoint spells none, or the reverse. See
	// AffectedRange.checkEpochAgreement for the full argument; the short
	// version is that dpkg and rpm both read an absent epoch as zero when
	// ORDERING, and that reading is catastrophic as a RANGE PREDICATE
	// because an installed EVR carries the epoch its package manager
	// recorded and an advisory endpoint frequently does not.
	RefusalEpochPresenceMismatch RefusalReason = "epoch_presence_mismatch"

	// RefusalUnmodelledOrdering: both versions parse, but the ordering
	// BETWEEN THEM is decided by a rule this comparator has not implemented
	// and could not cite. Today this is apk's rule R8 only — an explicit
	// zero field against an absent one, whose token weight apk's published
	// grammar does not state. It is distinct from RefusalMalformedVersion
	// because nothing is malformed: the gap is in this package, not in the
	// data, and an operator reading the coverage report needs to be able to
	// tell those apart.
	RefusalUnmodelledOrdering RefusalReason = "unmodelled_ordering"
)

// refusalReasonOrder is the canonical order for RefusalReasons() and for every
// sorted report. It is a slice, not a map, so nothing that consumes it ever
// depends on map iteration order.
var refusalReasonOrder = []RefusalReason{
	RefusalUnsupportedEcosystem,
	RefusalUnsupportedPurlType,
	RefusalNoPackageIdentity,
	RefusalMalformedPurl,
	RefusalMalformedVersion,
	RefusalIdentityConflict,
	RefusalSchemeMismatch,
	RefusalMixedSchemeRange,
	RefusalAmbiguousUpperBound,
	RefusalUnboundedRange,
	RefusalContradictoryRange,
	RefusalEpochPresenceMismatch,
	RefusalUnmodelledOrdering,
}

// RefusalReasons returns the closed set of refusal reasons in canonical order.
func RefusalReasons() []RefusalReason {
	out := make([]RefusalReason, len(refusalReasonOrder))
	copy(out, refusalReasonOrder)
	return out
}

// Valid reports whether r is a member of the closed set.
func (r RefusalReason) Valid() bool {
	for _, k := range refusalReasonOrder {
		if r == k {
			return true
		}
	}
	return false
}

// Refusal is a typed declination. It implements error, so a comparator can
// return it where an error is expected, AND it is a value a CoverageReport can
// carry, so a refusal that a caller ignores is still counted.
type Refusal struct {
	Reason    RefusalReason
	Scheme    Scheme
	Ecosystem string
	Package   string
	Purl      string
	// PurlType is the purl `type` segment, in its canonical lowercase form,
	// when THAT is the token this comparator does not implement.
	//
	// IT IS A SEPARATE FIELD FROM Ecosystem ON PURPOSE. A record may carry an
	// ecosystem this comparator DOES implement next to a purl whose type it
	// does not — `{Ecosystem: "deb", Purl: "pkg:npm/lodash@4.17.20"}` is a
	// real shape when a collector fills the ecosystem column from the host and
	// the purl from a lockfile — and the refusal has to name the token that
	// was actually refused. Writing the purl type into Ecosystem would put
	// "deb" on the operator's implement-next list, which is worse than leaving
	// it empty: it would name a scheme that IS implemented.
	//
	// CoverageReport.EcosystemsRefused reads this field for the purl route and
	// Ecosystem for the ecosystem route. See refusedIdentityToken.
	PurlType string
	Version  string
	Source   string
	SourceID string
	Detail   string
}

// refusedIdentityToken returns the vocabulary token whose absence from this
// comparator's implementation caused the refusal, or "" when the refusal was
// not about an unimplemented scheme.
//
// It is the ONE place that decides what feeds
// CoverageReport.EcosystemsRefused, because that list answers a question — "what
// must Anvil implement next?" — whose answer does not depend on which of the
// two identity routes the input happened to arrive by. A refusal that arrives
// through the purl route is the same fact about coverage as one that arrives
// through the ecosystem route, and counting only the second makes the list
// quietly wrong in the direction that looks better: empty exactly when the
// input was WELL-FORMED enough to carry a purl.
func (r Refusal) refusedIdentityToken() string {
	switch r.Reason {
	case RefusalUnsupportedEcosystem:
		return r.Ecosystem
	case RefusalUnsupportedPurlType:
		return r.PurlType
	}
	return ""
}

// Error renders the refusal. It always names the reason first, so grepping a
// log for a reason constant finds every instance.
func (r *Refusal) Error() string {
	var b strings.Builder
	b.WriteString("match: refused (")
	if r.Reason.Valid() {
		b.WriteString(string(r.Reason))
	} else {
		b.WriteString("UNDECLARED REFUSAL REASON " + strconv.Quote(string(r.Reason)))
	}
	b.WriteString(")")
	if r.Ecosystem != "" {
		b.WriteString(" ecosystem=" + strconv.Quote(r.Ecosystem))
	}
	if r.Scheme != "" {
		b.WriteString(" scheme=" + r.Scheme.String())
	}
	if r.Package != "" {
		b.WriteString(" package=" + strconv.Quote(r.Package))
	}
	if r.Version != "" {
		b.WriteString(" version=" + strconv.Quote(r.Version))
	}
	if r.Purl != "" {
		b.WriteString(" purl=" + strconv.Quote(r.Purl))
	}
	if r.PurlType != "" {
		b.WriteString(" purlType=" + strconv.Quote(r.PurlType))
	}
	if r.Source != "" || r.SourceID != "" {
		b.WriteString(" advisory=" + strconv.Quote(r.Source+"/"+r.SourceID))
	}
	if r.Detail != "" {
		b.WriteString(": " + r.Detail)
	}
	return b.String()
}

// sortKey is the total order used wherever refusals are reported. Every field
// is included so two refusals that differ at all sort differently.
func (r Refusal) sortKey() string {
	return strings.Join([]string{
		string(r.Reason), string(r.Scheme), r.Ecosystem, r.Package,
		r.Purl, r.PurlType, r.Version, r.Source, r.SourceID, r.Detail,
	}, "\x00")
}

// asRefusal converts an error to a *Refusal when it is one. Every error this
// package produces internally is a *Refusal; the helper exists so a caller can
// say so at a boundary without a type switch at every call site.
func asRefusal(err error) (*Refusal, bool) {
	r, ok := err.(*Refusal)
	return r, ok
}

// ---------------------------------------------------------------------------
// The comparator front door
// ---------------------------------------------------------------------------

// Compare orders two version strings under one scheme, returning -1, 0 or +1.
//
// It NEVER falls back. An unimplemented scheme and a malformed version are
// both refusals, and the returned int is 0 in both cases only because Go
// demands a value — a caller that ignores the error and uses the 0 has said
// "equal" about two versions this package declined to order, which is why
// nothing inside this package ever does so.
func Compare(scheme Scheme, a, b string) (int, error) {
	switch scheme {
	case SchemeDebian:
		return compareDebian(a, b)
	case SchemeRPM:
		return compareRPM(a, b)
	case SchemeAPK:
		return compareAPK(a, b)
	}
	return 0, &Refusal{
		Reason: RefusalUnsupportedEcosystem,
		Scheme: scheme,
		Detail: "no comparator is implemented for this scheme; implemented schemes are " +
			joinSchemes(schemeOrder),
	}
}

// ValidVersion reports whether v parses in the given scheme, returning the
// same *Refusal Compare would.
func ValidVersion(scheme Scheme, v string) error {
	switch scheme {
	case SchemeDebian:
		_, err := parseDebian(v)
		return err
	case SchemeRPM:
		_, err := parseRPM(v)
		return err
	case SchemeAPK:
		_, err := parseAPK(v)
		return err
	}
	return &Refusal{
		Reason:  RefusalUnsupportedEcosystem,
		Scheme:  scheme,
		Version: v,
		Detail:  "no comparator is implemented for this scheme",
	}
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

// PackageRecord is one installed package to be matched. It is the union of
// what A.9's host inventory and A.10's repository SCA scan each report, and
// its field names deliberately mirror internal/ingest/cache's `finding`
// columns.
//
// FIELD MAPPING, stated here because this package does NOT import either
// collector — internal/collector/host links os/exec and internal/ingest/cache
// links a SQL driver, and neither belongs in a comparator's dependency graph:
//
//	host.Package.Ecosystem  -> Ecosystem      host.Package.Name    -> Name
//	host.Package.Version    -> Version        host.Package.Arch    -> Arch
//	host.Collector          -> Collector
//
//	repo.Finding.Ecosystem  -> Ecosystem      repo.Finding.PackageName -> Name
//	repo.Finding.InstalledVersion -> Version  repo.Finding.Purl        -> Purl
//	repo.Finding.ManifestRelPath  -> ManifestRelPath
//	repo.Finding.Collector  -> Collector
type PackageRecord struct {
	// Collector is CollectorHost or CollectorRepoSCA. It is the ONLY input
	// to RemediableByAgent for a host row (which is always false), so an
	// unrecognised value is refused rather than defaulted.
	Collector string
	// Ecosystem is "deb", "rpm" or "apk". Anything else is refused.
	Ecosystem string
	// Name is the package name as its ecosystem spells it.
	Name string
	// Version is the installed version, verbatim from the collector. It is
	// never rewritten here: a comparator that reformats a version has
	// already decided the comparison.
	Version string
	// Arch is the package architecture, empty when the source reported none.
	// It is part of the result's identity so a multi-arch host does not
	// collapse two rows into one.
	Arch string
	// Purl is the package URL, empty when the collector reported none. When
	// present it is authoritative for the scheme, and a disagreement with
	// Ecosystem is RefusalIdentityConflict.
	Purl string
	// ManifestRelPath is the repo-relative manifest that declared the
	// dependency; empty for host packages.
	ManifestRelPath string
}

// sortKey is the total order Match imposes on its input, so that output does
// not depend on the order a caller happened to assemble the inventory in.
func (p PackageRecord) sortKey() string {
	return strings.Join([]string{
		p.Ecosystem, p.Name, p.Version, p.Arch, p.Purl, p.ManifestRelPath, p.Collector,
	}, "\x00")
}

// AffectedRange is one advisory's statement about one package's versions: the
// row shape of internal/ingest/cache's `affected` table plus the range
// vocabulary OSV uses.
//
// # BOUNDARY SEMANTICS, STATED ONCE AND ENFORCED EVERYWHERE
//
//	Introduced   INCLUSIVE lower bound. Empty means unbounded below.
//	Fixed        EXCLUSIVE upper bound — "fixed in 1.2.3" means 1.2.3 is SAFE.
//	LastAffected INCLUSIVE upper bound — "affected up to 1.2.3" means 1.2.3
//	             is VULNERABLE.
//
// Fixed and LastAffected differ by exactly one version and both are common in
// real advisories. A range that names BOTH is refused
// (RefusalAmbiguousUpperBound) rather than reconciled.
//
// A range with no bounds at all is refused (RefusalUnboundedRange), because an
// empty introduced/fixed pair is what a failed parse looks like by the time it
// reaches a database column, and evaluating it would flag every version of the
// package. The genuine "every version is affected, no fix exists" advisory
// must say so by setting AllVersions.
type AffectedRange struct {
	// Source and SourceID are the advisory's identity in the cache's
	// (source, source_id) primary key. NEVER the CVE id: research/06 Risk #2.
	Source   string
	SourceID string
	// CVEID is the nullable alias. When two sources carry the same CVE, it
	// is what unites them into one precedence group — which is how a Red Hat
	// advisory displaces a GHSA advisory about the same flaw.
	CVEID string

	Ecosystem string
	Package   string
	Purl      string

	Introduced   string
	Fixed        string
	LastAffected string
	// AllVersions is the explicit "every version of this package is
	// affected" marker. It must not be combined with any bound.
	AllVersions bool

	// DistroBackport is `affected.distro_backport`: true when this range
	// came from a vendor/distro advisory rather than upstream. It is the
	// column that defeats the CVE-2023-32681 / RHSA-2023:4520 class.
	DistroBackport bool

	// IntroducedEcosystem and FixedEcosystem are OPTIONAL per-endpoint
	// ecosystem declarations, for the feeds that give an upstream version at
	// one end and a distro version at the other. When either is set and
	// disagrees with Ecosystem — or with the other — the range is refused
	// with RefusalMixedSchemeRange. There is no correct guess.
	IntroducedEcosystem string
	FixedEcosystem      string
}

// sortKey is the total order over ranges. Evaluation walks ranges in this
// order, so "the range that decided this finding" is a deterministic choice
// and not an artefact of what order a source returned rows in.
func (a AffectedRange) sortKey() string {
	return strings.Join([]string{
		a.Source, a.SourceID, a.CVEID, a.Ecosystem, a.Package, a.Purl,
		a.Introduced, a.Fixed, a.LastAffected,
		boolKey(a.AllVersions), boolKey(a.DistroBackport),
		a.IntroducedEcosystem, a.FixedEcosystem,
	}, "\x00")
}

func boolKey(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// advisoryKey is the precedence group: the CVE when there is one, and the
// (source, source_id) primary key when there is not. GHSA advisories
// frequently carry no CVE at all (research/06 Risk #2), and grouping those
// under one empty key would let an unrelated advisory displace them.
func (a AffectedRange) advisoryKey() string {
	if a.CVEID != "" {
		return "cve\x00" + a.CVEID
	}
	return "src\x00" + a.Source + "\x00" + a.SourceID
}

// Expr renders the range with its boundaries spelled out, using standard
// interval notation: a square bracket is inclusive, a parenthesis exclusive.
// This string lands in MatchResult.MatchedRange, so the human reading a
// finding can see which side of the boundary the installed version fell on.
func (a AffectedRange) Expr() string {
	if a.AllVersions {
		return "(-inf, +inf) [all versions]"
	}
	var b strings.Builder
	if a.Introduced == "" {
		b.WriteString("(-inf")
	} else {
		b.WriteString("[" + a.Introduced)
	}
	b.WriteString(", ")
	switch {
	case a.Fixed != "":
		b.WriteString(a.Fixed + ")")
	case a.LastAffected != "":
		b.WriteString(a.LastAffected + "]")
	default:
		b.WriteString("+inf)")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Range validation and evaluation
// ---------------------------------------------------------------------------

// validate checks the range's shape and scheme agreement against the scheme
// the INSTALLED package resolved to. Every failure is a *Refusal.
func (a AffectedRange) validate(pkgScheme Scheme) error {
	base := func(reason RefusalReason, detail string) error {
		return &Refusal{
			Reason:    reason,
			Scheme:    pkgScheme,
			Ecosystem: a.Ecosystem,
			Package:   a.Package,
			Purl:      a.Purl,
			Source:    a.Source,
			SourceID:  a.SourceID,
			Detail:    detail,
		}
	}

	if a.Package == "" {
		return base(RefusalNoPackageIdentity, "advisory range names no package")
	}
	if a.Source == "" || a.SourceID == "" {
		return base(RefusalNoPackageIdentity,
			"advisory range carries no (source, source_id) identity")
	}

	rangeScheme, err := SchemeForEcosystem(a.Ecosystem)
	if err != nil {
		if r, ok := asRefusal(err); ok {
			r.Package = a.Package
			r.Source = a.Source
			r.SourceID = a.SourceID
			return r
		}
		return err
	}
	if rangeScheme != pkgScheme {
		return base(RefusalSchemeMismatch,
			"advisory range is in scheme "+rangeScheme.String()+
				" but the installed package is in scheme "+pkgScheme.String())
	}

	// Per-endpoint ecosystem overrides: any disagreement is a refusal.
	for _, ep := range []struct{ name, eco string }{
		{"introduced", a.IntroducedEcosystem},
		{"fixed", a.FixedEcosystem},
	} {
		if ep.eco == "" || ep.eco == a.Ecosystem {
			continue
		}
		return base(RefusalMixedSchemeRange,
			"the "+ep.name+" endpoint declares ecosystem "+strconv.Quote(ep.eco)+
				" but the range declares "+strconv.Quote(a.Ecosystem)+
				"; this comparator refuses to guess which one governs the comparison")
	}

	if a.AllVersions {
		if a.Introduced != "" || a.Fixed != "" || a.LastAffected != "" {
			return base(RefusalContradictoryRange,
				"AllVersions is set alongside an explicit bound")
		}
		return nil
	}

	if a.Fixed != "" && a.LastAffected != "" {
		return base(RefusalAmbiguousUpperBound,
			"the range names both an exclusive fixed version ("+strconv.Quote(a.Fixed)+
				") and an inclusive last-affected version ("+strconv.Quote(a.LastAffected)+
				"); they differ by exactly one version and this comparator will not pick one")
	}
	if a.Introduced == "" && a.Fixed == "" && a.LastAffected == "" {
		return base(RefusalUnboundedRange,
			"the range names no bound and does not set AllVersions; "+
				"an empty introduced/fixed pair is what a failed parse looks like in a database column")
	}

	// Every named endpoint must parse in the governing scheme. An endpoint
	// that does not is the "endpoints in different schemes" case arriving
	// without a declaration, and it is refused for the same reason.
	for _, ep := range []struct{ name, v string }{
		{"introduced", a.Introduced},
		{"fixed", a.Fixed},
		{"last_affected", a.LastAffected},
	} {
		if ep.v == "" {
			continue
		}
		if err := ValidVersion(pkgScheme, ep.v); err != nil {
			r, ok := asRefusal(err)
			if !ok {
				return err
			}
			return base(RefusalMalformedVersion,
				"the "+ep.name+" endpoint is not a valid "+pkgScheme.String()+
					" version: "+r.Detail)
		}
	}

	// A range whose lower bound is above its upper bound describes nothing.
	// It is a data error, and evaluating it would silently produce no
	// findings for an advisory that may well apply.
	if a.Introduced != "" {
		upper, inclusive := a.Fixed, false
		if upper == "" {
			upper, inclusive = a.LastAffected, true
		}
		if upper != "" {
			c, err := Compare(pkgScheme, a.Introduced, upper)
			if err != nil {
				// Reachable with two well-formed endpoints now that Compare
				// can decline an ordering (RefusalUnmodelledOrdering); the
				// refusal has to name the row it came from.
				return a.attribute(err)
			}
			if c > 0 || (c == 0 && !inclusive) {
				return base(RefusalContradictoryRange,
					"the range is empty: introduced "+strconv.Quote(a.Introduced)+
						" is not below its upper bound "+strconv.Quote(upper))
			}
		}
	}

	return nil
}

// epochSpelling reports whether v spells an epoch, and what it spelled. The
// third result is false when v does not parse in the scheme (validate and
// identify have both already refused such a string by the time this runs) or
// when the scheme has no epoch at all, which is apk.
func epochSpelling(scheme Scheme, v string) (present bool, value int, ok bool) {
	switch scheme {
	case SchemeDebian:
		p, err := parseDebian(v)
		if err != nil {
			return false, 0, false
		}
		return p.EpochPresent, p.Epoch, true
	case SchemeRPM:
		p, err := parseRPM(v)
		if err != nil {
			return false, 0, false
		}
		return p.EpochPresent, p.Epoch, true
	}
	return false, 0, false
}

// checkEpochAgreement refuses a range whose endpoints and installed version
// disagree about whether the package's versions carry an epoch.
//
// ===========================================================================
// THE RULE, WRITTEN DOWN DELIBERATELY RATHER THAN LEFT TO PARSING
// ===========================================================================
//
// An absent epoch means ZERO when ORDERING. That is what dpkg and rpm both do
// internally, deb-version(7) says it in as many words ("It may be omitted, in
// which case zero is assumed"), and compareDebParsed and compareRPMParsed
// implement exactly that. Compare's answer is not changing and the corpus
// vectors `0:1.0 == 1.0` still hold.
//
// AN ABSENT EPOCH DOES NOT MEAN ZERO WHEN DECIDING A RANGE. The two inputs to
// a range predicate do not have the same provenance: the installed version
// comes from a package manager, which records the epoch it actually installed,
// while the endpoint comes from an advisory feed, where an epoch is routinely
// dropped in transcription. So an epoch spelled on one side and absent on the
// other is not an ordering fact — it is a DISAGREEMENT BETWEEN TWO PRODUCERS
// about how this package's versions are spelled, and reading it as an
// ordering picks a winner silently.
//
// A.18's probe P5 is what this costs when it is left to parsing: a RHEL 9
// glibc `2:2.34-60.el9` — every RHEL 9 host carries that epoch — against an
// advisory endpoint spelled `2.34-100.el9` gives `2 > 0`, so the installed
// version sorts ABOVE the fixed endpoint, the range does not contain it, and
// the run reports zero findings, zero refusals, Complete=true and a clean
// verdict on a vulnerable host. That is the false negative the package doc's
// first paragraph names as the worst output this lane can produce, on one of
// the most common shapes in the RPM world.
//
// ===========================================================================
// THE REFUSAL IS NARROWED TWICE, AND BOTH NARROWINGS ARE LOAD-BEARING
// ===========================================================================
//
// # 1. ONLY A NON-ZERO SPELLED EPOCH COUNTS
//
// `0:1.0` against `1.0` spells the same epoch two ways. The values agree, the
// comparison is unaffected, and refusing it would be noise.
//
// # 2. ONLY THE DIRECTION THAT PUSHES THE INSTALLED VERSION OUT OF THE RANGE
//
// An epoch asymmetry is not symmetric in its consequences, because the two
// bounds face opposite ways. Working through all four combinations is what
// stops this refusal from becoming its own false-negative generator:
//
//	UPPER BOUND (fixed / last_affected), installed spells N>0, endpoint does
//	not: installed sorts ABOVE the bound and falls OUT of the range —
//	reported not-affected, silently. THIS IS A.18's PROBE P5. REFUSED.
//
//	UPPER BOUND, endpoint spells N>0, installed does not: installed sorts
//	BELOW the bound and stays IN the range — reported affected. Accepted,
//	and accepting it is not a concession: if the installed epoch really is 0
//	and the fix lands at epoch 2, the host IS affected until it takes the
//	epoch-2 build, so this is the right answer rather than a tolerated wrong
//	one. If instead the collector dropped a real epoch, the result is a
//	visible finding, not a silent clearance.
//
//	LOWER BOUND (introduced), endpoint spells N>0, installed does not:
//	installed sorts BELOW the lower bound and falls OUT of the range —
//	reported not-affected, silently. `rpm -q --qf '%{VERSION}-%{RELEASE}'`
//	omits the epoch entirely, so a collector really can produce this.
//	REFUSED.
//
//	LOWER BOUND, installed spells N>0, endpoint does not: installed sorts
//	ABOVE the lower bound and stays IN the range. ACCEPTED, AND IT MUST BE:
//	`Introduced: "0"` is the universal "from the beginning" sentinel in OSV,
//	CSAF and every feed built on them, so refusing this shape would refuse
//	the lower bound of nearly every advisory about an epoch-bearing package —
//	turning a guard against silent clearance into a machine for producing
//	them, one coverage-report line at a time. A first draft of this function
//	did exactly that and swallowed the CVE-2023-4911 glibc finding it was
//	written to catch.
//
// The rule in one sentence: REFUSE WHEN THE MISSING SPELLING IS WHAT TAKES
// THE INSTALLED VERSION OUT OF THE RANGE.
//
// # THE ALTERNATIVE, AND WHY IT IS NOT TAKEN HERE
//
// Normalising epochs during ingestion would also close this, and would close
// it better — a feed's endpoints could be rewritten into the archive's own
// spelling once, rather than refused on every scan. That is A.14/A.16's
// territory, not A.17's, and this comparator must not silently assume it has
// happened. If ingestion ever guarantees it, this refusal stops firing on its
// own and costs nothing; until then it is a countable gap in CoverageReport
// instead of an invisible one.
func (a AffectedRange) checkEpochAgreement(scheme Scheme, installed string) error {
	instPresent, instEpoch, ok := epochSpelling(scheme, installed)
	if !ok {
		return nil
	}

	// check reports the refusal for one endpoint. isLower selects which side
	// of the asymmetry is the dangerous one, per the table above.
	check := func(name, v string, isLower bool) error {
		if v == "" {
			return nil
		}
		epPresent, epEpoch, ok := epochSpelling(scheme, v)
		if !ok || epPresent == instPresent {
			return nil
		}

		var spelledSide, spelledStr, unspelledSide, unspelledStr, consequence string
		if isLower {
			if !epPresent || epEpoch == 0 {
				return nil
			}
			spelledSide, spelledStr = "the "+name+" endpoint", v
			unspelledSide, unspelledStr = "the installed version", installed
			consequence = "the installed version therefore orders BELOW the lower bound and " +
				"falls outside the range, which would report this package not-affected on a " +
				"spelling difference between two producers rather than on a version difference"
		} else {
			if !instPresent || instEpoch == 0 {
				return nil
			}
			spelledSide, spelledStr = "the installed version", installed
			unspelledSide, unspelledStr = "the "+name+" endpoint", v
			consequence = "the installed version therefore orders ABOVE the upper bound and " +
				"falls outside the range, which would report this package not-affected on a " +
				"spelling difference between two producers rather than on a version difference"
		}

		return &Refusal{
			Reason:    RefusalEpochPresenceMismatch,
			Scheme:    scheme,
			Ecosystem: a.Ecosystem,
			Package:   a.Package,
			Purl:      a.Purl,
			Version:   installed,
			Source:    a.Source,
			SourceID:  a.SourceID,
			Detail: spelledSide + " spells an epoch (" + strconv.Quote(spelledStr) +
				") and " + unspelledSide + " spells none (" + strconv.Quote(unspelledStr) +
				"); an absent epoch orders as zero, so " + consequence,
		}
	}

	if err := check("introduced", a.Introduced, true); err != nil {
		return err
	}
	if err := check("fixed", a.Fixed, false); err != nil {
		return err
	}
	return check("last_affected", a.LastAffected, false)
}

// contains reports whether installed falls inside the range.
//
// The predicate, with every boundary spelled out:
//
//	AllVersions                      -> always true
//	Introduced == ""                 -> no lower bound
//	Introduced != ""                 -> installed >= Introduced   (INCLUSIVE)
//	Fixed != ""                      -> installed <  Fixed        (EXCLUSIVE)
//	LastAffected != ""               -> installed <= LastAffected (INCLUSIVE)
//	neither Fixed nor LastAffected   -> no upper bound
//
// validate must have run first; contains assumes a well-formed range and
// returns a refusal only if a comparison itself fails, or if the range's
// endpoints and the installed version disagree about whether this package's
// versions carry an epoch (checkEpochAgreement).
func (a AffectedRange) contains(scheme Scheme, installed string) (bool, error) {
	if a.AllVersions {
		// No endpoint, so no epoch to disagree about.
		return true, nil
	}
	if err := a.checkEpochAgreement(scheme, installed); err != nil {
		return false, err
	}
	if a.Introduced != "" {
		c, err := Compare(scheme, installed, a.Introduced)
		if err != nil {
			return false, a.attribute(err)
		}
		if c < 0 {
			return false, nil
		}
	}
	if a.Fixed != "" {
		c, err := Compare(scheme, installed, a.Fixed)
		if err != nil {
			return false, a.attribute(err)
		}
		return c < 0, nil
	}
	if a.LastAffected != "" {
		c, err := Compare(scheme, installed, a.LastAffected)
		if err != nil {
			return false, a.attribute(err)
		}
		return c <= 0, nil
	}
	return true, nil
}

// attribute stamps a refusal raised by Compare with the advisory it was
// evaluating.
//
// Compare knows the two version strings and nothing else, so a refusal that
// reaches CoverageReport straight from it names no package and no advisory —
// and a refusal an operator cannot trace to a row is a refusal they cannot
// act on. This is reachable now that Compare can decline two WELL-FORMED
// versions (RefusalUnmodelledOrdering, apk rule R8), where before it declined
// only strings that validate had already rejected.
func (a AffectedRange) attribute(err error) error {
	r, ok := asRefusal(err)
	if !ok {
		return err
	}
	if r.Ecosystem == "" {
		r.Ecosystem = a.Ecosystem
	}
	if r.Package == "" {
		r.Package = a.Package
	}
	if r.Purl == "" {
		r.Purl = a.Purl
	}
	if r.Source == "" {
		r.Source = a.Source
	}
	if r.SourceID == "" {
		r.SourceID = a.SourceID
	}
	return r
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

// MatchResult is one package that matched one advisory. It is A.17's Expected
// output schema — {source, source_id, package, purl, installed_version,
// matched_range, distro_backport_defended} — plus the fields A.19 needs in
// order to emit a canonical record without re-deriving anything.
//
// It carries NO FINGERPRINT. anvil-fp/v1 is defined once, in internal/record,
// and a second digest under the same name is the cross-area failure
// plan/00-SPINE.md S6 forbids. A.19 calls record.Sca with the fields below.
type MatchResult struct {
	// Source and SourceID identify the advisory in the cache's primary key.
	Source   string
	SourceID string
	// CVEID is the alias, empty when the advisory carries none.
	CVEID string

	Collector       string
	Ecosystem       string
	Scheme          Scheme
	Package         string
	Purl            string
	Arch            string
	ManifestRelPath string

	InstalledVersion string
	// MatchedRange is AffectedRange.Expr() for the range that decided this
	// result: interval notation with inclusive and exclusive boundaries
	// spelled out.
	MatchedRange string
	// FixedVersion is the range's exclusive upper bound, empty when the
	// advisory names none. It is the input to RemediableByAgent.
	FixedVersion string

	// VendorAdvisory is true when the deciding range came from a
	// vendor/distro advisory (`affected.distro_backport`).
	VendorAdvisory bool
	// DistroBackportDefended is true when the deciding range was a vendor
	// range that DISPLACED at least one upstream range for the same advisory
	// and package. A finding with this set is one where the backport policy
	// changed which range was consulted; a suppression — where the vendor
	// range said "not affected" and no finding was emitted at all — appears
	// in CoverageReport.Defences instead, because a defence that leaves no
	// trace is indistinguishable from a bug.
	DistroBackportDefended bool

	// Detector and EvidenceClass are frozen record enums, derived from the
	// collector. They are Go constants from internal/record, never literals.
	Detector      record.DetectorKind
	EvidenceClass record.EvidenceClass
	// Trust is record.TrustAnvilGenerated: the CONCLUSION is Anvil's own,
	// which is what internal/ingest/cache's FindingTrustDefault says. The
	// package name and version strings inside it remain untrusted, and A.19
	// carries that distinction into the record's per-string trust.
	Trust record.Trust
	// RemediableByAgent is false for every host row, with no code path able
	// to set it otherwise (see remediableByAgent), and true for a repository
	// dependency only when the advisory names a fixed version to move to.
	RemediableByAgent bool
}

func (m MatchResult) sortKey() string {
	return strings.Join([]string{
		m.Ecosystem, m.Package, m.Arch, m.ManifestRelPath, m.InstalledVersion,
		m.CVEID, m.Source, m.SourceID, m.MatchedRange, m.Collector,
	}, "\x00")
}

// DefenceReason names why a would-be finding was not emitted. Like
// RefusalReason it is a closed set with one member today; it is a named type
// so a second reason cannot arrive as a bare string.
type DefenceReason string

// DefenceVendorAdvisoryWins is the CVE-2023-32681 / RHSA-2023:4520 class: an
// upstream range said vulnerable, a vendor/distro range for the SAME advisory
// and package said otherwise, and the vendor range decided.
const DefenceVendorAdvisoryWins DefenceReason = "vendor_advisory_wins"

// Defence records a suppressed match. It exists because a defence that leaves
// no trace cannot be told apart from a bug — and because the operator who asks
// "why is Anvil not reporting CVE-2023-32681, Trivy does" deserves an answer
// with the two ranges in it.
type Defence struct {
	Reason DefenceReason

	Ecosystem string
	Package   string
	// Arch is carried so that two architectures of the same package do not
	// produce two rows a reader cannot tell apart. A defence that looks like
	// a duplicate is a defence somebody will delete.
	Arch             string
	Purl             string
	InstalledVersion string
	CVEID            string

	// UpstreamSource/UpstreamSourceID/UpstreamRange describe the range that
	// WOULD have produced a finding.
	UpstreamSource   string
	UpstreamSourceID string
	UpstreamRange    string

	// VendorSource/VendorSourceID/VendorRange describe the range that
	// displaced it.
	VendorSource   string
	VendorSourceID string
	VendorRange    string
}

func (d Defence) sortKey() string {
	return strings.Join([]string{
		string(d.Reason), d.Ecosystem, d.Package, d.Arch, d.InstalledVersion, d.CVEID,
		d.UpstreamSource, d.UpstreamSourceID, d.UpstreamRange,
		d.VendorSource, d.VendorSourceID, d.VendorRange,
	}, "\x00")
}

// UpstreamOnlyAdvisory is the package-level residue of the vendor-first
// policy: an advisory that was decided by an upstream range for a package
// which HAS vendor coverage for some other advisory. It is REPORTED, not
// suppressed — see the package doc's "SCOPE OF THE PRECEDENCE".
type UpstreamOnlyAdvisory struct {
	Ecosystem string
	Package   string
	Arch      string
	CVEID     string
	Source    string
	SourceID  string
}

func (u UpstreamOnlyAdvisory) sortKey() string {
	return strings.Join([]string{u.Ecosystem, u.Package, u.Arch, u.CVEID, u.Source, u.SourceID}, "\x00")
}

// UngroupedVendorAdvisory is a vendor/distro range that CANNOT participate in
// the vendor-first precedence, because it carries no CVE alias.
//
// ===========================================================================
// THE PRECONDITION THE DEFENCE DEPENDS ON, STATED WHERE IT CAN BE COUNTED
// ===========================================================================
//
// advisoryKey groups by CVE when there is one and by the cache's (source,
// source_id) primary key when there is not. That is right for the case it was
// written for — a GHSA row with no CVE must not be merged with an unrelated
// advisory under one empty key — but it has a consequence in the other
// direction that A.18 found and that nothing here said out loud: IF THE
// VENDOR ROW IS THE ONE MISSING THE ALIAS, the vendor range and the upstream
// range it was meant to displace land in two different groups, and the
// displacement never happens. The CVE-2023-32681 false positive comes back,
// silently.
//
// The alias column belongs to internal/ingest/cache, not to this package, so
// this package cannot fix it — a vendor row and an upstream row that share no
// identifier cannot be shown to be about the same flaw, and guessing that
// they are (by package name, say) is the package-scoped suppression the
// package doc rejects as an unbounded false-negative generator.
//
// What it CAN do is stop the dependence being invisible. Every vendor range
// that arrives without an alias is listed here, so "the defence did not fire"
// has a report entry instead of being indistinguishable from "there was
// nothing to defend against". Debian DSA rows in particular commonly enumerate
// several CVEs per advisory rather than carrying one alias, so this is a real
// shape and not a hypothetical one.
//
// EVERY SUCH RANGE, INCLUDING THE ONES THAT ALSO FAIL TO PARSE. The recording
// used to sit AFTER evaluatePackage's validate() early return, so a vendor row
// that lacked its alias and also carried a malformed endpoint — the case in
// which the defence most emphatically could not fire — was the one case
// omitted from the list built to surface exactly that. A report that omits the
// case it was built for is the same defect as a guard that skips, and the
// refusal recorded alongside is not a substitute: Refusals says a row could
// not be EVALUATED, this list says the vendor-first precedence could not
// APPLY, and an operator reading the second must not have to reconstruct it
// from the first. See TestAnUngroupableVendorRangeIsReportedEvenWhenItIsAlso
// Refused.
type UngroupedVendorAdvisory struct {
	Ecosystem string
	Package   string
	Arch      string
	Source    string
	SourceID  string
}

func (u UngroupedVendorAdvisory) sortKey() string {
	return strings.Join([]string{u.Ecosystem, u.Package, u.Arch, u.Source, u.SourceID}, "\x00")
}

// SourceError records an advisory-source lookup that failed. A failed lookup
// means the answer for that package is UNKNOWN, never "clean".
type SourceError struct {
	Ecosystem string
	Package   string
	Err       string
}

// CoverageReport is the answer to "was that a clean host, or did nothing
// run?". Lane A exit criterion 20 requires it on every match run including —
// especially — the zero-findings case.
type CoverageReport struct {
	// PackagesSubmitted is len(inventory).
	PackagesSubmitted int
	// PackagesEvaluated is how many had a usable identity in an implemented
	// scheme AND a parseable version. This is the denominator that makes a
	// zero-finding result mean anything.
	PackagesEvaluated int
	// PackagesUnidentifiable is research/12 §3's false-negative-risk class:
	// records with no ecosystem, no name or no version. A.17's Expected
	// output schema names this count specifically.
	PackagesUnidentifiable int
	// PackagesRefusedScheme is how many carried a usable identity in an
	// ecosystem this comparator does not implement.
	PackagesRefusedScheme int
	// PackagesRefusedVersion is how many had a supported scheme but a
	// version string that scheme could not parse.
	PackagesRefusedVersion int
	// PackagesWithNoAdvisoryData is how many were evaluated against an empty
	// set of advisory ranges. A high count here with zero findings means the
	// cache is empty, not that the host is clean.
	//
	// AssertNotSilentlyClean READS THIS FIELD. It did not until A.18, and
	// the omission meant an entirely empty advisory cache over a full,
	// well-formed inventory passed the one guard written to prevent exactly
	// that reading.
	PackagesWithNoAdvisoryData int

	// RangesConsidered and RangesRefused count range EVALUATIONS, not
	// distinct rows: one malformed `affected` row consulted for the amd64 and
	// the i386 build of the same package counts twice, because it left two
	// packages' advisories undecided. A refused range leaves its advisory
	// undecided for that package, which is why any refusal clears Complete.
	RangesConsidered int
	RangesRefused    int

	// SchemesImplemented is SchemeValues(), carried in the report so a
	// consumer reading a stored CoverageReport knows what the producing
	// build could compare without having to guess from its version.
	SchemesImplemented []Scheme
	// EcosystemsRefused is the distinct, sorted set of identity tokens that
	// were refused for an unimplemented scheme. It is the list an operator
	// uses to decide what to implement next.
	//
	// BOTH IDENTITY ROUTES FEED IT: a record refused on its `ecosystem`
	// column (RefusalUnsupportedEcosystem) contributes that column, and a
	// record refused on its purl `type` (RefusalUnsupportedPurlType)
	// contributes the type in its canonical lowercase form. The two routes
	// are the same fact about coverage, and for deb/rpm/apk the two
	// vocabularies are the same strings, so they deduplicate rather than
	// double-count.
	//
	// IT DID NOT ALWAYS DO THIS. Only the ecosystem route fed the list
	// until A.21, which meant the list was EMPTY exactly when the input was
	// well-formed enough to carry a purl — every repo-SCA finding, and what
	// every collector is encouraged to supply. PackagesRefusedScheme counted
	// them; nothing said what they were.
	EcosystemsRefused []string

	// Refusals, Defences, UpstreamOnlyAdvisories and
	// UngroupedVendorAdvisories are sorted by total keys so two runs over the
	// same input produce byte-identical reports.
	Refusals               []Refusal
	Defences               []Defence
	UpstreamOnlyAdvisories []UpstreamOnlyAdvisory
	// UngroupedVendorAdvisories lists the vendor ranges that could not
	// participate in the vendor-first precedence because they carry no CVE
	// alias. See the type's doc: it is the report entry that stops "the
	// defence did not fire" being invisible.
	UngroupedVendorAdvisories []UngroupedVendorAdvisory
	SourceErrors              []SourceError

	// Complete is true only when nothing was refused, nothing errored, at
	// least one package was evaluated AND at least one advisory range was
	// actually consulted.
	//
	// WHAT IT DOES NOT SAY. Complete is a statement about the RUN, not about
	// coverage of any particular package: a run in which 399 of 400 packages
	// had no advisory rows at all is Complete, because nothing refused and
	// something was compared. The sentence that used to be here — "the
	// single flag a caller may read to know whether no findings is an answer
	// or an absence" — promised the second thing and only ever established
	// the first, so it is deleted rather than qualified.
	//
	// THE LAST CONDITION IS THE ONE A.18 ADDED. Without it, a run over 400
	// well-formed packages against an advisory cache holding nothing at all
	// refused nothing, errored on nothing and evaluated everything — and so
	// reported Complete, which the sentence above promises means "no
	// findings is an answer". RangesConsidered == 0 says no comparison was
	// ever performed, and a run that performed no comparison has not
	// answered the question.
	Complete bool
}

// ErrSilentlyClean is returned by AssertNotSilentlyClean when a caller is
// about to read an empty result set as a clean target.
type ErrSilentlyClean struct{ Detail string }

func (e *ErrSilentlyClean) Error() string {
	return "match: refusing to report a clean result: " + e.Detail
}

// AssertNotSilentlyClean refuses to let zero findings be read as "clean".
//
// ===========================================================================
// EXACTLY WHAT THIS ESTABLISHES, AND EXACTLY WHAT IT DOES NOT
// ===========================================================================
//
// THE PROPOSITION IT ESTABLISHES, and the only one:
//
//	when it returns nil for an empty finding set, at least one advisory
//	range was compared against at least one package, no advisory-source
//	lookup failed, and nothing was refused.
//
// THREE THINGS IT DOES NOT ESTABLISH. Each is here because the doc used to
// imply it, and this project's rule is that a claim which cannot be
// demonstrated is deleted rather than qualified:
//
//  1. IT IS NOT A PER-PACKAGE COVERAGE CHECK. PackagesWithNoAdvisoryData is
//     tested ALL-OR-NOTHING, so a run in which 399 of 400 packages had no
//     advisory rows returns nil. That is deliberate — in a real advisory
//     database most packages genuinely have no rows, an inventory of 400 with
//     396 uncovered and 4 compared is the normal shape of a healthy scan, and
//     a fractional threshold would refuse constantly and be dismissed — but
//     the consequence is that this function cannot tell a caller that any
//     PARTICULAR package was covered. Nothing in this package can: that is
//     ingestion's question.
//
//  2. IT IS NOT A COMPLETENESS CHECK. Findings short-circuit every other
//     test, so a run with one finding and 4,999 refusals returns nil. The
//     question it answers is "may ZERO findings be read as clean", and a run
//     with findings is not a zero-finding run. Complete is the completeness
//     flag; Refusals is the list.
//
//  3. IT IS NOT A STATEMENT ABOUT THE HOST. nil means "an empty result set is
//     an answer here", not "this host is patched". The findings a complete
//     run produced are still bounded by what the advisory cache holds.
//
// TestAssertNotSilentlyCleanEstablishesExactlyWhatItsDocClaims asserts every
// sentence above, the negative ones included, because a limit that is only
// written down is a limit nobody has checked.
//
// plan/20 exit criterion 20 and A.17's Forbidden-actions line both require
// this check, and it is a function rather than a documented convention
// because a documented convention is what this project keeps finding
// unenforced.
//
// ===========================================================================
// THE EMPTY-CACHE CASE, AND WHY IT IS ALL-OR-NOTHING
// ===========================================================================
//
// "The tool ran and found nothing" and "the tool had nothing to compare
// against" are the same output to a caller, and for a security scanner the
// second read as the first is the worst answer available. This function used
// to branch on four things and NEVER READ PackagesWithNoAdvisoryData — the
// field whose own doc comment exists to name this exact failure. A.18's probe
// R1 walked straight through it: 400 well-formed Debian packages against a
// source holding zero rows returned Complete, zero refusals and nil from
// here. That is the state of a deployment where A.5's bootstrap has not run,
// or ran and produced nothing, or where ingestion normalised ecosystem
// strings into a vocabulary the `affected` rows do not use — which is the
// most likely failure mode of the whole lane. The same class already bit the
// SCA collector: an E2E job found Trivy could not run at all without a
// database, because every prior test had used recorded output.
//
// THE TEST IS "EVERY EVALUATED PACKAGE", NOT A FRACTION, and the distinction
// is deliberate. In a real advisory database MOST packages genuinely have no
// rows — an inventory of 400 packages with 396 uncovered and 4 compared is
// the normal shape of a healthy scan, and a fractional threshold would refuse
// it constantly and be dismissed. It is only when the count reaches ALL of
// them that no comparison happened at all, and at that point the run has not
// answered the question rather than answered it negatively.
func (c CoverageReport) AssertNotSilentlyClean(findings []MatchResult) error {
	if len(findings) > 0 {
		return nil
	}
	switch {
	case c.PackagesSubmitted == 0:
		return &ErrSilentlyClean{Detail: "no packages were submitted; nothing was scanned"}
	case c.PackagesEvaluated == 0:
		return &ErrSilentlyClean{Detail: "none of the " + strconv.Itoa(c.PackagesSubmitted) +
			" submitted packages could be evaluated (" +
			strconv.Itoa(c.PackagesUnidentifiable) + " unidentifiable, " +
			strconv.Itoa(c.PackagesRefusedScheme) + " in unimplemented ecosystems, " +
			strconv.Itoa(c.PackagesRefusedVersion) + " with unparseable versions)"}
	case c.PackagesWithNoAdvisoryData >= c.PackagesEvaluated:
		return &ErrSilentlyClean{Detail: "all " + strconv.Itoa(c.PackagesEvaluated) +
			" evaluated packages were compared against an EMPTY set of advisory ranges; " +
			"the advisory cache holds nothing for this inventory, so this is an absence " +
			"of data and not a clean target"}
	case c.RangesConsidered == 0:
		// Reachable only for a report a caller assembled or deserialised
		// rather than one Match produced (in a real run this is the case
		// above). It is here because a guard that trusts one field to imply
		// another is a guard with a seam in it.
		return &ErrSilentlyClean{Detail: "no advisory range was consulted for any of the " +
			strconv.Itoa(c.PackagesEvaluated) + " evaluated packages; nothing was compared"}
	case len(c.SourceErrors) > 0:
		return &ErrSilentlyClean{Detail: strconv.Itoa(len(c.SourceErrors)) +
			" advisory-source lookups failed; the answer for those packages is unknown, not clean"}
	case !c.Complete:
		return &ErrSilentlyClean{Detail: strconv.Itoa(len(c.Refusals)) +
			" refusals are outstanding (" + strconv.Itoa(c.RangesRefused) +
			" advisory ranges could not be evaluated); this is a partial answer"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The advisory source
// ---------------------------------------------------------------------------

// AdvisorySource supplies the `affected` rows for one package. It is an
// interface so that the comparator itself opens no database, performs no I/O
// and is testable with no fixture file — the whole package stays a pure
// function of its inputs, which is what makes the cross-process determinism
// test meaningful.
//
// An implementation MUST be a pure lookup: the same (ecosystem, package) must
// return the same set within a run. It need not return them in any order;
// Match sorts.
type AdvisorySource interface {
	AffectedRanges(ctx context.Context, ecosystem, pkg string) ([]AffectedRange, error)
}

// StaticSource is an in-memory AdvisorySource over a fixed slice of ranges. It
// is the source A.19 can use once it has read the cache, and the source the
// tests use.
type StaticSource struct {
	byPackage map[string][]AffectedRange
}

// NewStaticSource indexes ranges by (ecosystem, package). The per-key slices
// are SORTED at construction, so lookups are deterministic even though the
// index is a map — the map is never ranged over.
func NewStaticSource(ranges []AffectedRange) *StaticSource {
	s := &StaticSource{byPackage: make(map[string][]AffectedRange, len(ranges))}
	for _, r := range ranges {
		k := r.Ecosystem + "\x00" + r.Package
		s.byPackage[k] = append(s.byPackage[k], r)
	}
	for k, rs := range s.byPackage {
		sortRanges(rs)
		s.byPackage[k] = rs
	}
	return s
}

// AffectedRanges implements AdvisorySource.
func (s *StaticSource) AffectedRanges(_ context.Context, ecosystem, pkg string) ([]AffectedRange, error) {
	rs := s.byPackage[ecosystem+"\x00"+pkg]
	out := make([]AffectedRange, len(rs))
	copy(out, rs)
	return out, nil
}

func sortRanges(rs []AffectedRange) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].sortKey() < rs[j].sortKey() })
}

// ---------------------------------------------------------------------------
// The matcher
// ---------------------------------------------------------------------------

// Matcher is the comparator bound to one advisory source.
//
// A.17's Expected output schema names `Match(ctx, inventory) ([]MatchResult,
// CoverageReport, error)`. That signature has nowhere to put the advisory
// data, so the source is bound to the receiver instead of appearing as a
// parameter; the method below has exactly the named signature.
type Matcher struct {
	src AdvisorySource
}

// NewMatcher binds a source. A nil source is an error rather than a matcher
// that reports every package clean.
func NewMatcher(src AdvisorySource) (*Matcher, error) {
	if src == nil {
		return nil, errString("match: NewMatcher requires an advisory source; " +
			"a nil source would report every package clean")
	}
	return &Matcher{src: src}, nil
}

// Match evaluates every package in inventory against the bound advisory
// source.
//
// It returns findings sorted by a total key, a CoverageReport, and an error
// only for a condition that makes the whole run untrustworthy: a cancelled
// context, or an advisory-source failure. In BOTH cases the CoverageReport is
// still returned, populated as far as the run got — a caller that stops on the
// error still learns what was and was not covered.
//
// ON AN ADVISORY-SOURCE FAILURE THE FINDINGS ALREADY COMPUTED ARE RETURNED
// TOO. They are true statements about the packages they name, and discarding
// 4998 real findings because the cache dropped on package 4999 helps nobody;
// Complete is false and AssertNotSilentlyClean refuses, so the set cannot be
// read as exhaustive. A CANCELLED CONTEXT RETURNS NONE, and the asymmetry is
// deliberate: cancellation is the caller withdrawing the request, and handing
// a partial answer to a caller that asked to stop is how a partial answer gets
// stored as the answer.
//
// The inventory is copied and sorted before evaluation. Two callers submitting
// the same packages in different orders get identical output; nothing here
// ranges over a map to build a result.
func (m *Matcher) Match(ctx context.Context, inventory []PackageRecord) ([]MatchResult, CoverageReport, error) {
	cov := CoverageReport{
		PackagesSubmitted:  len(inventory),
		SchemesImplemented: SchemeValues(),
	}

	work := make([]PackageRecord, len(inventory))
	copy(work, inventory)
	sort.SliceStable(work, func(i, j int) bool { return work[i].sortKey() < work[j].sortKey() })

	var (
		results         []MatchResult
		refusedEcos     = map[string]bool{}
		defences        []Defence
		upstreamOnly    []UpstreamOnlyAdvisory
		ungrouped       []UngroupedVendorAdvisory
		anyRefusal      bool
		refusalsCollect []Refusal
	)

	finish := func(complete bool) {
		cov.Refusals = sortedRefusals(refusalsCollect)
		cov.Defences = sortedDefences(defences)
		cov.UpstreamOnlyAdvisories = sortedUpstreamOnly(upstreamOnly)
		cov.UngroupedVendorAdvisories = sortedUngroupedVendor(ungrouped)
		cov.EcosystemsRefused = sortedKeys(refusedEcos)
		cov.Complete = complete
	}

	addRefusal := func(err error) {
		anyRefusal = true
		if r, ok := asRefusal(err); ok {
			refusalsCollect = append(refusalsCollect, *r)
			if tok := r.refusedIdentityToken(); tok != "" {
				refusedEcos[tok] = true
			}
			return
		}
		refusalsCollect = append(refusalsCollect, Refusal{
			Reason: RefusalNoPackageIdentity,
			Detail: "unclassified error: " + err.Error(),
		})
	}

	for _, p := range work {
		if err := ctx.Err(); err != nil {
			// A cancelled context returns NO results, unlike the source
			// failure below. The distinction is deliberate: cancellation is
			// the CALLER withdrawing the request, and handing a partial
			// answer back to a caller that asked to stop is how a partial
			// answer gets stored as the answer. A source failure is Anvil's
			// own gap, and everything evaluated before it is still true.
			finish(false)
			return nil, cov, err
		}

		id, err := identify(p)
		if err != nil {
			addRefusal(err)
			if r, ok := asRefusal(err); ok {
				switch r.Reason {
				case RefusalNoPackageIdentity, RefusalMalformedPurl, RefusalIdentityConflict:
					cov.PackagesUnidentifiable++
				case RefusalUnsupportedEcosystem, RefusalUnsupportedPurlType:
					cov.PackagesRefusedScheme++
				case RefusalMalformedVersion:
					cov.PackagesRefusedVersion++
				default:
					cov.PackagesUnidentifiable++
				}
			} else {
				cov.PackagesUnidentifiable++
			}
			continue
		}

		cov.PackagesEvaluated++

		ranges, err := m.src.AffectedRanges(ctx, id.Ecosystem, id.Name)
		if err != nil {
			cov.SourceErrors = append(cov.SourceErrors, SourceError{
				Ecosystem: id.Ecosystem, Package: id.Name, Err: err.Error(),
			})
			finish(false)
			// The findings computed BEFORE the failure are returned with the
			// error. They are true statements about the packages they name,
			// and throwing away 4998 real findings because the cache dropped
			// on package 4999 helps nobody; Complete is false and
			// AssertNotSilentlyClean refuses, so neither the caller nor the
			// report can read the set as exhaustive.
			sort.SliceStable(results, func(i, j int) bool {
				return results[i].sortKey() < results[j].sortKey()
			})
			return results, cov, err
		}
		if len(ranges) == 0 {
			cov.PackagesWithNoAdvisoryData++
			continue
		}
		cov.RangesConsidered += len(ranges)

		pkgResults, pkgDefences, pkgUpstreamOnly, pkgUngrouped, pkgRefusals := evaluatePackage(id, p, ranges)
		results = append(results, pkgResults...)
		defences = append(defences, pkgDefences...)
		upstreamOnly = append(upstreamOnly, pkgUpstreamOnly...)
		ungrouped = append(ungrouped, pkgUngrouped...)
		for _, r := range pkgRefusals {
			cov.RangesRefused++
			addRefusal(&r)
		}
	}

	sort.SliceStable(results, func(i, j int) bool { return results[i].sortKey() < results[j].sortKey() })
	finish(!anyRefusal && len(cov.SourceErrors) == 0 &&
		cov.PackagesEvaluated > 0 && cov.RangesConsidered > 0)

	return results, cov, nil
}

// ---------------------------------------------------------------------------
// Identity resolution
// ---------------------------------------------------------------------------

// identity is a package whose scheme, ecosystem, name and version have all
// been resolved and validated.
type identity struct {
	Scheme    Scheme
	Ecosystem string
	Name      string
	Purl      string
	Version   string
}

// identify resolves a PackageRecord's identity, refusing every disagreement.
//
// Resolution order and the rules, stated so a reviewer can check them:
//
//  1. Collector must be CollectorHost or CollectorRepoSCA. An unrecognised
//     collector is refused, because RemediableByAgent is derived from it and
//     a defaulted collector would default that flag.
//
//  2. Version must be non-empty.
//
//  3. If a purl is present it is parsed and its TYPE resolves the scheme.
//     A non-empty Ecosystem must resolve to the SAME scheme, and the purl's
//     name must be the SAME NAME as the reported Name. Either disagreement is
//     RefusalIdentityConflict — two identity sources that disagree is exactly
//     the situation in which guessing attaches a finding to the wrong package.
//
//     "THE SAME NAME" MEANS: IDENTICAL AFTER ASCII CASE FOLDING, AND NOTHING
//     WEAKER. The purl specification defines deb/rpm/apk names as
//     case-insensitive with a lowercase canonical form, so `OpenSSL` and
//     `openssl` are two spellings of one name and may be canonicalised. A
//     purl naming a DIFFERENT package — `pkg:deb/debian/openssl` beside a
//     record for `curl` — is not a spelling of anything; it is the same
//     disagreement rules 3-first-half and 6 already refuse, and it is refused
//     here for the same reason rather than as an exception to them.
//
//     THE COST OF GETTING THIS WRONG RUNS IN BOTH DIRECTIONS, AND BOTH HAVE
//     BEEN LIVE IN THIS FILE:
//
//     Refusing too little — taking the purl's name unconditionally — looks up
//     `openssl`'s advisories for a record that names `curl`. `curl`'s own
//     advisories are never consulted, the run reports zero findings and
//     Complete, and a vulnerable host is clean. Note that varying the
//     REPORTED name across spellings of one package cannot detect this: every
//     such case is a case where the two names agree.
//
//     Refusing too much, or accepting without adopting, misses the other way.
//     Before A.18 the check accepted a case difference and then KEPT THE
//     REPORTED SPELLING, which Match hands verbatim to
//     AdvisorySource.AffectedRanges as the lookup key: `Name: "OpenSSL"` next
//     to `pkg:deb/debian/openssl` produced zero findings, one
//     PackagesWithNoAdvisoryData and a clean verdict (probe R2). Accepting a
//     spelling means adopting it, or the acceptance is a hole.
//
//     SO THE SURVIVING NAME IS THE CANONICAL FORM, NOT EITHER SPELLING.
//     identity.Name is asciiLower(purl name). Adopting the purl's spelling as
//     WRITTEN has the same defect one step over — `pkg:deb/debian/CURL` is a
//     legal purl whose canonical name is `curl`, and looking up `CURL` misses
//     exactly as looking up `OpenSSL` did.
//
//     THE FOLD IS EXPLICIT ASCII, NOT strings.EqualFold, AND SO IS THE
//     LOWERCASING. EqualFold performs Unicode simple case folding, so U+017F
//     (LATIN SMALL LETTER LONG S) folds to 's' and `opensſl` walked past the
//     identity guard to become a lookup key that matches nothing (probe R3).
//     Package-name strings arrive from outside Anvil and
//     internal/ingest/cache's trust model says so; the guard has to enforce a
//     canonical form, not match a spelling.
//
//  4. If no purl is present, Ecosystem and Name are both required, and the
//     reported name is used AS SPELLED. There is no second identity source to
//     canonicalise against, and rewriting a collector's spelling on its own
//     authority would put a second, undocumented identity mapping inside the
//     comparator — the same argument that keeps ecosystemAllowlist
//     exact-match. Normalisation belongs to ingestion.
//
//  5. The version must parse in the resolved scheme.
//
//  6. If the purl carries a VERSION, it must be the reported Version, byte
//     for byte. This is rule 6 and A.18's §4.4: the purl's version was
//     parsed and dropped on the floor, so a stale purl beside a fresh version
//     column — which is what a re-scanned SBOM looks like — produced a false
//     positive in one direction (probe P6: `purl@3.0.11-1` patched,
//     `Version: 1.0.0-1` vulnerable, finding emitted against the version
//     column) and a silent clean in the other. The comparison is textual on
//     purpose: this package refuses identity disagreements rather than
//     deciding which of two producers spelled the same version better.
func identify(p PackageRecord) (identity, error) {
	switch p.Collector {
	case CollectorHost, CollectorRepoSCA:
	default:
		return identity{}, &Refusal{
			Reason:    RefusalNoPackageIdentity,
			Ecosystem: p.Ecosystem,
			Package:   p.Name,
			Version:   p.Version,
			Purl:      p.Purl,
			Detail: "unrecognised collector " + strconv.Quote(p.Collector) +
				"; RemediableByAgent is derived from it and must not be defaulted",
		}
	}

	if strings.TrimSpace(p.Version) == "" {
		return identity{}, &Refusal{
			Reason:    RefusalNoPackageIdentity,
			Ecosystem: p.Ecosystem,
			Package:   p.Name,
			Purl:      p.Purl,
			Detail:    "package carries no version; it cannot be compared against any range",
		}
	}

	var (
		scheme Scheme
		eco    = p.Ecosystem
		name   = p.Name
		canon  string
	)

	if strings.TrimSpace(p.Purl) != "" {
		pu, err := ParsePurl(p.Purl)
		if err != nil {
			if r, ok := asRefusal(err); ok {
				r.Package = p.Name
				r.Ecosystem = p.Ecosystem
				r.Purl = p.Purl
				return identity{}, r
			}
			return identity{}, err
		}
		ps, err := SchemeForPurlType(pu.Type)
		if err != nil {
			if r, ok := asRefusal(err); ok {
				r.Package = p.Name
				r.Ecosystem = p.Ecosystem
				r.Purl = p.Purl
				return identity{}, r
			}
			return identity{}, err
		}
		scheme = ps
		canon = pu.String()

		if eco != "" {
			es, err := SchemeForEcosystem(eco)
			if err != nil {
				if r, ok := asRefusal(err); ok {
					r.Package = p.Name
					r.Purl = p.Purl
					return identity{}, r
				}
				return identity{}, err
			}
			if es != ps {
				return identity{}, &Refusal{
					Reason:    RefusalIdentityConflict,
					Ecosystem: eco,
					Package:   p.Name,
					Purl:      p.Purl,
					Version:   p.Version,
					Detail: "purl type " + strconv.Quote(pu.Type) + " resolves to scheme " +
						ps.String() + " but ecosystem " + strconv.Quote(eco) +
						" resolves to scheme " + es.String(),
				}
			}
		} else {
			eco = string(ps)
		}

		if name != "" && !asciiFoldEqual(name, pu.Name) {
			return identity{}, &Refusal{
				Reason:    RefusalIdentityConflict,
				Ecosystem: eco,
				Package:   name,
				Purl:      p.Purl,
				Version:   p.Version,
				Detail: "the reported package name " + strconv.Quote(name) +
					" is not the purl's name " + strconv.Quote(pu.Name) +
					"; a purl that names a DIFFERENT package than the record is two " +
					"identity sources disagreeing, not two spellings of one name",
			}
		}
		// Rule 3's other half: the surviving name is the CANONICAL FORM of
		// the purl's name, which for deb/rpm/apk is its ASCII lowercasing.
		// Not the reported spelling (A.18 §3.3: the check accepted a case
		// difference and then handed the reported spelling to the advisory
		// lookup, which matched nothing) and not the purl's spelling as
		// written either — `pkg:deb/debian/CURL` is a legal spelling of a
		// name whose canonical form is `curl`, and adopting the upper-case
		// one moves the miss from one side to the other.
		name = asciiLower(pu.Name)

		// Rule 6: the purl's version must be the reported version.
		if pu.Version != "" && pu.Version != p.Version {
			return identity{}, &Refusal{
				Reason:    RefusalIdentityConflict,
				Ecosystem: eco,
				Package:   name,
				Purl:      p.Purl,
				Version:   p.Version,
				Detail: "the purl names version " + strconv.Quote(pu.Version) +
					" but the record's version column says " + strconv.Quote(p.Version) +
					"; two identity sources disagree about the one string this lane compares",
			}
		}
	} else {
		if eco == "" || name == "" {
			return identity{}, &Refusal{
				Reason:    RefusalNoPackageIdentity,
				Ecosystem: eco,
				Package:   name,
				Version:   p.Version,
				Detail: "no purl, and " + missingIdentityDetail(eco, name) +
					"; this is research/12 §3's false-negative-risk class",
			}
		}
		es, err := SchemeForEcosystem(eco)
		if err != nil {
			if r, ok := asRefusal(err); ok {
				r.Package = name
				r.Version = p.Version
				return identity{}, r
			}
			return identity{}, err
		}
		scheme = es
	}

	if err := ValidVersion(scheme, p.Version); err != nil {
		if r, ok := asRefusal(err); ok {
			r.Ecosystem = eco
			r.Package = name
			r.Purl = p.Purl
			return identity{}, r
		}
		return identity{}, err
	}

	return identity{
		Scheme:    scheme,
		Ecosystem: eco,
		Name:      name,
		Purl:      canon,
		Version:   p.Version,
	}, nil
}

// asciiFoldEqual reports whether a and b are the same string once ASCII
// upper-case letters are folded to lower case, and NOTHING ELSE IS FOLDED.
//
// This is deliberately not strings.EqualFold. EqualFold applies Unicode
// simple case folding, under which U+017F folds to 's', U+212A (KELVIN SIGN)
// folds to 'k', and a handful of other non-ASCII runes fold onto ASCII
// letters. The purl specification's "case-insensitive with a lowercase
// canonical form" is a statement about ASCII package names; taking it as a
// licence for Unicode folding lets a name-shaped string from an untrusted
// producer be DECLARED equal to a real package name and then fail to match it
// in the advisory index — a guard that matches a spelling instead of
// enforcing a canonical form. A.18's probe R3 did exactly that.
// asciiLower folds ASCII upper-case letters to lower case and CHANGES NOTHING
// ELSE. It is the canonical form asciiFoldEqual compares under, so that "the
// two names are the same name" and "this is the name" cannot disagree: if
// asciiFoldEqual(a, b) then asciiLower(a) == asciiLower(b), by construction.
//
// strings.ToLower is deliberately not used, for the reason asciiFoldEqual does
// not use strings.EqualFold: it is Unicode-aware, and a canonical form that
// maps non-ASCII runes onto ASCII letters turns a name-shaped string from an
// untrusted producer into a lookup key that collides with a real package name.
func asciiLower(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if isASCIIUpper(s[i]) {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i := range b {
		if isASCIIUpper(b[i]) {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func asciiFoldEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if isASCIIUpper(ca) {
			ca += 'a' - 'A'
		}
		if isASCIIUpper(cb) {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func missingIdentityDetail(eco, name string) string {
	switch {
	case eco == "" && name == "":
		return "neither an ecosystem nor a package name"
	case eco == "":
		return "no ecosystem"
	default:
		return "no package name"
	}
}

// ---------------------------------------------------------------------------
// Per-package evaluation and the vendor-first policy
// ---------------------------------------------------------------------------

// evaluatePackage applies the vendor-advisory-first precedence and evaluates
// what survives it. It returns at most one MatchResult per advisory group.
//
// The steps, in order:
//
//  1. Group EVERY range by advisory (CVE when present, else the cache's
//     (source, source_id) key), and validate each against the package's
//     scheme. A range that fails validation is returned to the caller for
//     counting and BLOCKS ITS WHOLE GROUP.
//  2. Within a surviving group, if ANY range is a vendor/distro range, the
//     upstream ranges are DISPLACED. This is the CVE-2023-32681 defence.
//  3. Evaluate the deciding ranges in canonical order and collect EVERY one
//     that contains the installed version, then pick the remediation target
//     among them (chooseRemediationTarget).
//  4. If nothing decided a finding but a DISPLACED range would have, record a
//     Defence.
//
// ===========================================================================
// WHY A REFUSED RANGE BLOCKS ITS GROUP RATHER THAN JUST STANDING ASIDE
// ===========================================================================
//
// This function's contract has always been that "an unparseable range must
// not be able to decide anything, IN EITHER DIRECTION". Standing a refused
// range aside honours the first direction and breaks the second: A.18's probe
// P7 malformed the VENDOR endpoint of the CVE-2022-2068 backport fixture, the
// vendor range dropped out of the group, the upstream range was left alone in
// it — and the run emitted the exact backport false positive the vendor-first
// policy exists to defeat, on a host carrying the backported fix. The refused
// range decided the answer by being absent.
//
// So a group with any refused range is UNDECIDED: no finding, no defence, no
// residue row. Complete goes false, the refusal is in CoverageReport.Refusals
// naming the advisory, and the operator sees a gap instead of a confident
// wrong answer. The cost is real — a group can be blocked by a malformed row
// that would not have changed the outcome — and it is the correct side to err
// on for the same reason the rest of this package refuses rather than
// guesses.
func evaluatePackage(id identity, p PackageRecord, ranges []AffectedRange) (
	[]MatchResult, []Defence, []UpstreamOnlyAdvisory, []UngroupedVendorAdvisory, []Refusal,
) {
	sorted := make([]AffectedRange, len(ranges))
	copy(sorted, ranges)
	sortRanges(sorted)

	var (
		refusals   []Refusal
		groupKeys  []string
		groups     = map[string][]AffectedRange{}
		blocked    = map[string]bool{}
		anyVendor  bool
		results    []MatchResult
		defences   []Defence
		upOnly     []UpstreamOnlyAdvisory
		ungrouped  []UngroupedVendorAdvisory
		seenUngrp  = map[string]bool{}
		groupOrder = map[string]bool{}
	)

	for _, r := range sorted {
		// The group key is taken BEFORE validation, so that a refused range
		// can block the group it belongs to.
		k := r.advisoryKey()
		if !groupOrder[k] {
			groupOrder[k] = true
			groupKeys = append(groupKeys, k)
		}

		// THE UNGROUPABLE-VENDOR ROW IS RECORDED BEFORE VALIDATION, NOT
		// AFTER IT. It used to sit below the early return, so a vendor row
		// that lacked its CVE alias AND failed to parse — the case in which
		// the defence most emphatically could not fire — was the one case
		// the list left out. A report that omits the case it was built for
		// is the same defect as a guard that skips, and the refusal recorded
		// a few lines down is not a substitute: Refusals says a row could
		// not be evaluated, UngroupedVendorAdvisories says the vendor-first
		// precedence could not apply, and an operator reading the second
		// list must not have to reconstruct it from the first.
		if r.DistroBackport && r.CVEID == "" {
			// This vendor range can only ever group with rows sharing its
			// (source, source_id), so it cannot displace an upstream
			// advisory about the same flaw. See UngroupedVendorAdvisory.
			u := UngroupedVendorAdvisory{
				Ecosystem: id.Ecosystem, Package: id.Name, Arch: p.Arch,
				Source: r.Source, SourceID: r.SourceID,
			}
			// One advisory commonly carries several ranges; the report names
			// ADVISORIES, and a list with the same row twice is a list
			// somebody stops reading.
			if !seenUngrp[u.sortKey()] {
				seenUngrp[u.sortKey()] = true
				ungrouped = append(ungrouped, u)
			}
		}

		if err := r.validate(id.Scheme); err != nil {
			blocked[k] = true
			if ref, ok := asRefusal(err); ok {
				refusals = append(refusals, *ref)
			} else {
				refusals = append(refusals, Refusal{
					Reason:   RefusalUnboundedRange,
					Package:  r.Package,
					Source:   r.Source,
					SourceID: r.SourceID,
					Detail:   "unclassified range error: " + err.Error(),
				})
			}
			continue
		}
		groups[k] = append(groups[k], r)
		if r.DistroBackport {
			anyVendor = true
		}
	}

	// groupKeys is built in the canonical range order above, so it is
	// already deterministic; sorting it makes that independent of the
	// grouping step and cheap to verify.
	sort.Strings(groupKeys)

	for _, k := range groupKeys {
		if blocked[k] {
			continue
		}
		group := groups[k]
		var vendor, upstream []AffectedRange
		for _, r := range group {
			if r.DistroBackport {
				vendor = append(vendor, r)
			} else {
				upstream = append(upstream, r)
			}
		}

		deciding, displaced := upstream, []AffectedRange(nil)
		if len(vendor) > 0 {
			deciding, displaced = vendor, upstream
		}

		var (
			hits   []AffectedRange
			hitErr error
		)
		for i := range deciding {
			in, err := deciding[i].contains(id.Scheme, id.Version)
			if err != nil {
				hitErr = err
				break
			}
			if in {
				hits = append(hits, deciding[i])
			}
		}
		if hitErr != nil {
			// Same rule as a validation refusal: the group is undecided.
			if ref, ok := asRefusal(hitErr); ok {
				refusals = append(refusals, *ref)
			}
			continue
		}

		// The package-level residue. An advisory decided by an UPSTREAM
		// range, for a package that has vendor coverage somewhere else, is
		// reported whether it produced a finding or not: a range that
		// decided "not affected" decided it just as much as one that
		// matched, and listing only the half that produced findings gives an
		// operator reviewing the residue half a picture.
		if anyVendor && len(vendor) == 0 {
			seen := map[string]bool{}
			for _, r := range deciding {
				u := UpstreamOnlyAdvisory{
					Ecosystem: id.Ecosystem, Package: id.Name, Arch: p.Arch,
					CVEID: r.CVEID, Source: r.Source, SourceID: r.SourceID,
				}
				if seen[u.sortKey()] {
					continue
				}
				seen[u.sortKey()] = true
				upOnly = append(upOnly, u)
			}
		}

		if len(hits) > 0 {
			results = append(results, buildResult(id, p,
				chooseRemediationTarget(id.Scheme, hits), len(displaced) > 0))
			continue
		}

		// Nothing in the deciding set matched. Did a displaced upstream
		// range want to? That is the defence worth recording.
		gov := governingVendorRange(id.Scheme, vendor)
		var groupDefences []Defence
		defenceRefused := false
		for i := range displaced {
			in, err := displaced[i].contains(id.Scheme, id.Version)
			if err != nil {
				if ref, ok := asRefusal(err); ok {
					refusals = append(refusals, *ref)
				}
				// A displaced range this package could not evaluate leaves
				// the group undecided in the same way step 1 does, so the
				// defences already collected for it are dropped rather than
				// reported as a complete account.
				defenceRefused = true
				break
			}
			if !in {
				continue
			}
			groupDefences = append(groupDefences, Defence{
				Reason:           DefenceVendorAdvisoryWins,
				Ecosystem:        id.Ecosystem,
				Package:          id.Name,
				Arch:             p.Arch,
				Purl:             id.Purl,
				InstalledVersion: id.Version,
				CVEID:            displaced[i].CVEID,
				UpstreamSource:   displaced[i].Source,
				UpstreamSourceID: displaced[i].SourceID,
				UpstreamRange:    displaced[i].Expr(),
				VendorSource:     gov.Source,
				VendorSourceID:   gov.SourceID,
				VendorRange:      gov.Expr(),
			})
		}
		if defenceRefused {
			continue
		}
		defences = append(defences, groupDefences...)
	}

	return results, defences, upOnly, ungrouped, refusals
}

// chooseRemediationTarget picks the one range in a group that a MatchResult
// will cite, out of every range in the deciding set that contained the
// installed version.
//
// ===========================================================================
// THIS EXISTS BECAUSE THE ALPHABET WAS DECIDING IT
// ===========================================================================
//
// At most one MatchResult is emitted per advisory group, and the survivor used
// to be simply the first containing range in sortKey() order — a key that
// begins with Source. So when two feeds carried the same CVE for the same
// package, THE ALPHABETICALLY FIRST SOURCE NAME WON and the other advisory's
// fixed version was silently discarded. A.18's probe Q1 showed `cvelistv5`
// beating `ghsa` on a repo-sca row, which meant MatchResult.FixedVersion —
// the version a coding agent is dispatched to bump to — became the coarse
// upstream `9.9.9` instead of the Debian `1.1.1n-0+deb11u5` the host could
// actually install. Deterministic, and arbitrary with respect to advisory
// quality.
//
// THE ORDER OF PREFERENCE, AND THE REASON FOR EACH:
//
//  1. A VENDOR/DISTRO RANGE BEATS AN UPSTREAM ONE. The displacement step has
//     usually settled this already (a group with any vendor range decides
//     with vendor ranges only), and it is restated here so this function is
//     correct read on its own rather than correct by the caller's grace.
//  2. A RANGE THAT NAMES A FIXED VERSION BEATS ONE THAT DOES NOT. `Fixed` is
//     the remediation target; a `last_affected` or open-ended range says a
//     host is vulnerable without saying what to install, and citing it when
//     a fixed version was available in the same group throws away the only
//     actionable field on the finding.
//  3. AMONG THOSE, THE LOWEST FIXED VERSION IN THE SCHEME'S OWN ORDERING —
//     the tightest upper bound. It is the smallest claim the group's evidence
//     supports: a higher `Fixed` asserts that every version between the two
//     is still vulnerable, which the tighter advisory denies. It is also the
//     safer failure: if the other, wider range genuinely still covers the
//     bumped version, the NEXT scan reports it again and the operator sees
//     it, whereas a target the archive does not carry sends an agent after a
//     version that does not exist.
//  4. TIES BY THE FULL sortKey, so the choice remains a pure function of the
//     inputs.
func chooseRemediationTarget(scheme Scheme, hits []AffectedRange) AffectedRange {
	best := hits[0]
	for _, c := range hits[1:] {
		if betterRemediationTarget(scheme, c, best) {
			best = c
		}
	}
	return best
}

func betterRemediationTarget(scheme Scheme, cand, best AffectedRange) bool {
	if cand.DistroBackport != best.DistroBackport {
		return cand.DistroBackport
	}
	if (cand.Fixed != "") != (best.Fixed != "") {
		return cand.Fixed != ""
	}
	if cand.Fixed != "" && best.Fixed != "" {
		// Both endpoints validated in this scheme, so a comparison error
		// here is not reachable; if one ever is, fall through to the total
		// key rather than let an error pick the target.
		if c, err := Compare(scheme, cand.Fixed, best.Fixed); err == nil && c != 0 {
			return c < 0
		}
	}
	return cand.sortKey() < best.sortKey()
}

// governingVendorRange picks the vendor range a Defence cites.
//
// A defence is recorded when NO vendor range in the group contained the
// installed version, so there is no single range that "matched" — but the
// operator asking "why is Anvil not reporting this CVE" still needs one
// named, and citing vendor[0] (which is the alphabetically first source, for
// the same reason chooseRemediationTarget existed to fix) can name a range
// whose bound had nothing to do with the outcome.
//
// The one cited is the vendor range with the HIGHEST fixed version: the
// strongest claim the vendor made, and therefore the bound the installed
// version had to clear in order for the defence to apply at all. A vendor
// range naming no fixed version cannot be that bound; if none names one, the
// first in canonical order is cited, which is at least deterministic.
func governingVendorRange(scheme Scheme, vendor []AffectedRange) AffectedRange {
	if len(vendor) == 0 {
		// Unreachable from evaluatePackage: a displaced range exists only
		// when a vendor range displaced it. Total anyway, because a helper
		// that panics on an empty slice is a helper someone will later call
		// from somewhere else.
		return AffectedRange{}
	}
	best := vendor[0]
	for _, c := range vendor[1:] {
		if best.Fixed == "" && c.Fixed != "" {
			best = c
			continue
		}
		if c.Fixed == "" || best.Fixed == "" {
			continue
		}
		if cmp, err := Compare(scheme, c.Fixed, best.Fixed); err == nil && cmp > 0 {
			best = c
		}
	}
	return best
}

// buildResult assembles one MatchResult. Every derived field is derived HERE
// and nowhere else, so there is one place to read for what a finding claims.
func buildResult(id identity, p PackageRecord, r AffectedRange, displacedUpstream bool) MatchResult {
	detector, evidence := record.DetectorKindSCA, record.EvidenceClassSCA
	if p.Collector == CollectorHost {
		detector, evidence = record.DetectorKindHost, record.EvidenceClassHost
	}
	purl := id.Purl
	if purl == "" {
		purl = r.Purl
	}
	return MatchResult{
		Source:                 r.Source,
		SourceID:               r.SourceID,
		CVEID:                  r.CVEID,
		Collector:              p.Collector,
		Ecosystem:              id.Ecosystem,
		Scheme:                 id.Scheme,
		Package:                id.Name,
		Purl:                   purl,
		Arch:                   p.Arch,
		ManifestRelPath:        p.ManifestRelPath,
		InstalledVersion:       id.Version,
		MatchedRange:           r.Expr(),
		FixedVersion:           r.Fixed,
		VendorAdvisory:         r.DistroBackport,
		DistroBackportDefended: r.DistroBackport && displacedUpstream,
		Detector:               detector,
		EvidenceClass:          evidence,
		Trust:                  record.TrustAnvilGenerated,
		RemediableByAgent:      remediableByAgent(p.Collector, r.Fixed),
	}
}

// remediableByAgent is the ONE place this flag is computed.
//
// plan/00-SPINE.md S6 and S7, Lane A exit criterion 21 and
// internal/ingest/cache's `finding_host_not_remediable` CHECK all say the same
// thing: a host finding is never remediable by the coding agent, with no code
// path, flag or config key able to override it. The function takes no options
// and reads no configuration, so there is no location for such an override to
// live.
//
// For a repository dependency the answer is "is there a version to move to".
// When the advisory names no fixed version there is no bump to make, and
// claiming otherwise dispatches an agent after a patch that does not exist.
func remediableByAgent(collector, fixed string) bool {
	if collector != CollectorRepoSCA {
		return false
	}
	return fixed != ""
}

// ---------------------------------------------------------------------------
// Deterministic report assembly
// ---------------------------------------------------------------------------

func sortedRefusals(in []Refusal) []Refusal {
	if len(in) == 0 {
		return nil
	}
	out := make([]Refusal, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].sortKey() < out[j].sortKey() })
	return out
}

func sortedDefences(in []Defence) []Defence {
	if len(in) == 0 {
		return nil
	}
	out := make([]Defence, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].sortKey() < out[j].sortKey() })
	return out
}

func sortedUpstreamOnly(in []UpstreamOnlyAdvisory) []UpstreamOnlyAdvisory {
	if len(in) == 0 {
		return nil
	}
	out := make([]UpstreamOnlyAdvisory, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].sortKey() < out[j].sortKey() })
	return out
}

func sortedUngroupedVendor(in []UngroupedVendorAdvisory) []UngroupedVendorAdvisory {
	if len(in) == 0 {
		return nil
	}
	out := make([]UngroupedVendorAdvisory, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].sortKey() < out[j].sortKey() })
	return out
}

// sortedKeys is the ONLY place in this package where a map's iteration order
// could reach an output, and it sorts before returning. The other two map
// ranges — NewStaticSource sorting each bucket in place, and evaluatePackage's
// group bookkeeping, whose keys are sorted before use — are order-independent
// by construction. comparator_test.go proves the whole claim the only way it
// can be proved, by running the corpus in a second OS process with a different
// map seed and comparing.
func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
