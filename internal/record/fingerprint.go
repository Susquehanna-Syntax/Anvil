package record

// fingerprint.go — the ONE anvil-fp/v1 algorithm.
//
// ===========================================================================
// THE CONFLICT THIS FILE RESOLVES
// ===========================================================================
//
// research/07-database-design.md §3 ("Fingerprint scheme: anvil-fp/v1 — a
// four-tier cascade") and research/18-unified-audit-record.md ("Stable
// identity — the rule that makes regression checking work") each specified a
// DIFFERENT algorithm under the SAME name, `anvil-fp/v1`. They disagree on
// the field set, the separator, the digest length, and the normalization
// depth.
//
// plan/00-SPINE.md S6 states the consequence plainly: "One fingerprint
// algorithm, defined once, in the record. Two branches specified different
// /v1 algorithms under the same name; two producers emitting different hashes
// means regression matching silently fails forever." Silently is the
// operative word — nothing surfaces the failure. Every finding looks new on
// every scan, `finding.first_seen_at` never stabilises, the regression check
// `UNIQUE (target_id, fingerprint)` never fires, and "verified fixed" can
// never be proved, all without a single error being logged.
//
// plan/40-record-and-storage.md, "Fingerprint Specification", is the
// orchestrator's resolution. THAT TEXT — not either research branch verbatim
// — is what this file implements. The seven contested points and the reason
// each was decided that way:
//
//  1. SEPARATOR — research/07's explicit U+001F wins over research/18's
//     undefined "‖" glyph. A printable separator can occur inside a snippet
//     or a symbol name and silently move a field boundary: hashing
//     ("a‖b", "c") and ("a", "b‖c") would collide. U+001F cannot appear in
//     normalized source text, and Digest rejects it (and every other C0
//     control character) outright rather than trusting that claim.
//
//  2. ORDINAL — research/07's `ordinal` is adopted; research/18's SAST
//     formula lacks it. Without it, two identical macro-expanded or generated
//     call sites in one file hash identically and the second finding is lost
//     on upsert against `UNIQUE (target_id, fingerprint)`. Losing a finding
//     is worse than churning one.
//
//  3. advisory_id IS EXCLUDED from the SAST hash — research/07 includes it;
//     research/18 does not; the resolution follows research/18. Identity
//     tracks "this exact defect in this exact code". If ingestion later
//     attaches a specific advisory to a sink previously linked only to a
//     generic CWE, that reclassification must not fork the finding's
//     identity. SastInput therefore has no advisory field at all — the
//     exclusion is enforced by the type, not by discipline.
//
//  4. NO TRUNCATION — research/07 truncates to 32 hex chars "for storage".
//     The resolution does not truncate. SQLite's cost for a 64- vs
//     32-character TEXT column is negligible, and halving a cryptographic
//     digest without a forcing constraint buys nothing and adds collision
//     risk. Digest always returns FingerprintDigestHexLen (64) characters.
//
//  5. NORMALIZATION DEPTH — research/07's metavariable abstraction
//     (literals to <STR>/<NUM>, local identifiers to positional $1..$N) is
//     adopted over research/18's whitespace-and-comments-only normalization,
//     because it is the one directly modelled on Semgrep's `match_based_id`
//     — the cited, externally-verified mechanism for surviving reindentation
//     and metavariable-only edits (research/07 [S3]).
//
//  6. DAST EVIDENCE SIGNAL — research/18's `evidenceClass` (HOW the defect
//     was observed) is a real distinguishing signal absent from research/07's
//     Tier D. It is hashed ALONGSIDE research/07's injection_point/param_name
//     (WHERE the payload went in), because the two are independent facts.
//     See EvidenceSignal and InjectionPoint in contract.go.
//
//  7. HOST TIER — neither branch defined a tier for host/package findings,
//     but plan/00-SPINE.md S1 gives Lane A "dependency and host findings" and
//     S6 requires `remediable_by_agent=false` on all of them, so they need an
//     identity. research/07's Tier C is generalised by parameterising the
//     hashed detector kind over {sca, host} rather than inventing an
//     unrelated scheme.
//
// research/18's Tier B (CodeQL's `primaryLocationLineHash`) is deliberately
// NOT implemented here. It is not an anvil-fp/v1 tier; it is a separate,
// line-DEPENDENT partial fingerprint whose only purpose is GitHub code
// scanning de-duplication. It lives under
// PartialFingerprintPrimaryLocationLineHash and is owned by the GitHub
// projection (R.14). Computing it here would put a line number one import
// away from this file.
//
// ===========================================================================
// THE VERSION STRING IS NEVER HASHED
// ===========================================================================
//
// For the SCA and host tiers this is the single most load-bearing exclusion,
// and it is the reason PurlBase exists rather than the caller passing a purl
// straight through:
//
//	Bumping 1.2.3 to 1.2.4 while still inside the vulnerable range must not
//	mint a new finding.
//
// If the version were hashed, every patch-level dependency bump would resolve
// the old finding and open an identical new one. `first_seen_at` would reset,
// the age-based ranking would reset, any suppression keyed on the fingerprint
// would silently stop applying, and a maintainer bumping a version WITHOUT
// leaving the vulnerable range would see the alert disappear and reappear as
// "new" — indistinguishable from an actual fix. Resolution is proved by
// re-evaluating `advisory_affects`, never by an identity change.
//
// PurlBase enforces this defensively: it truncates a purl at the first
// version, qualifier, or subpath delimiter, so a caller who passes the full
// versioned purl by mistake still gets a version-free fingerprint. The
// ScaInput/HostInput structs also have no Version field, so there is no
// in-band way to hash one.
//
// ===========================================================================
// WHAT IS EXCLUDED BY CONSTRUCTION
// ===========================================================================
//
// The tier input structs below deliberately have NO field for anything the
// specification forbids hashing. This is a type-level guarantee, not a
// convention, and TestInputStructsCannotCarryForbiddenFields asserts it
// reflectively so a later edit cannot quietly add one:
//
//	line number, column number   — absent from SastInput entirely; any
//	                               unrelated edit above a match changes them
//	                               (research/07 §3: "the single most important
//	                               rule").
//	raw snippet text             — SastInput.Snippet is normalized before it
//	                               is hashed; the literal text never reaches
//	                               Digest.
//	advisory_id (SAST tier)      — see resolution point 3.
//	host, port, scheme (DAST)    — absent from DastInput; a redeployed
//	                               container, a rotated ephemeral port, or a
//	                               staging-to-prod move must not fork
//	                               identity.
//	payload string (DAST)        — absent from DastInput; a fuzzer varying
//	                               its payload must not create N findings for
//	                               one bug.
//	timestamps                   — absent from every input struct.
//	version string (SCA/host)    — absent, and stripped defensively by
//	                               PurlBase.
//	evidence_class (SAST tier)   — the SAST tier hashes the literal "sast",
//	                               not the evidence class, so a finding
//	                               upgraded from sast_static_only to
//	                               sast_reachable keeps its identity.
//
// ===========================================================================
// THE AUTHORITATIVE SPECIFICATION IS internal/record/FINGERPRINT-SPEC.md
// ===========================================================================
//
// R.3's CRITIQUE-01.md proved that the four-clause `normalized_match` text in
// plan/40-record-and-storage.md is NOT sufficient to reproduce this file's
// digests: a re-implementation written from that text alone emits
// 55e27b07... where the committed golden for sast-01 is 13c60ccf... . The
// orchestrator ruled (2026-08-08) that the implementation is right and the
// specification was incomplete, and that the fix is to write the
// specification down completely, IN TREE.
//
// internal/record/FINGERPRINT-SPEC.md is that document. It is the
// authoritative definition of anvil-fp/v1: every normalization step in
// NormalizeMatch in the order applied, the reserved-word list verbatim, the
// identifier-preservation rules and their reasons, the route-segment
// templating patterns and thresholds, the separator, the join order, the hash,
// and the ordinal grouping key. plan/ is gitignored; a second producer working
// from a clone can read FINGERPRINT-SPEC.md and nothing else and still emit
// byte-identical digests.
//
// fingerprint_spec_test.go keeps the document honest: it asserts that the
// reserved-word list and the algorithm constants printed in the document are
// exactly the ones in this file. A specification that can drift from the code
// silently is the same defect one level up.
//
// ===========================================================================
// CONFORMANCE (R.16)
// ===========================================================================
//
// testdata/fingerprint_corpus/*.json is the fixed corpus. Every fixture
// carries its complete ordered `hashed_fields` list and its `expected_digest`,
// so R.16's offline oracle can re-derive the digest from the fixture alone —
// join with U+001F, SHA-256, lowercase hex — without importing or reading any
// Go code. R.16 must NOT copy `expected_digest`; it must recompute it from
// FINGERPRINT-SPEC.md (NOT from plan/40-record-and-storage.md, whose algorithm
// text is a summary and was proved insufficient by CRITIQUE-01) and assert
// equality.
// That mutual check is the mechanism that would have caught research/07 and
// research/18 shipping two different /v1 algorithms under one name.
//
// Sources: plan/40-record-and-storage.md ("Fingerprint Specification");
// plan/00-SPINE.md S1, S6, S7; plan/IMPLEMENTATION-PLAN.md §6 (this file
// declares no shared enum — it consumes contract.go's DetectorKind,
// InjectionPoint and EvidenceSignal); research/07-database-design.md §3;
// research/18-unified-audit-record.md ("Stable identity").

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// Algorithm constants that R.16's independent oracle must reproduce
// ---------------------------------------------------------------------------

// The separator (FingerprintFieldSeparator, U+001F) and the digest length
// (FingerprintDigestHexLen, 64) live in contract.go, because they are wire
// contract rather than implementation. The tokens below are algorithm detail
// but must still be reproduced byte for byte by any re-implementation, so
// they are exported and named.
const (
	// NormalizedStringToken replaces every string literal in a normalized
	// SAST match. Chosen with angle brackets because they cannot appear in
	// an identifier, so a source-level `<STR>` cannot be confused with the
	// placeholder in any language Anvil scans.
	NormalizedStringToken = "<STR>"

	// NormalizedNumberToken replaces every numeric literal in a normalized
	// SAST match.
	NormalizedNumberToken = "<NUM>"

	// NormalizedMetavarPrefix prefixes the positional metavariables that
	// replace local identifiers: $1, $2, ... in first-occurrence order.
	NormalizedMetavarPrefix = "$"

	// NormalizedRouteSegmentToken replaces every volatile path segment in a
	// canonicalised DAST route template — a numeric id, a UUID, a long
	// hex/base32/base64-ish opaque token, and any segment a producer has
	// already templated in its own syntax ("{id}", ":id", "<id>").
	//
	// Angle brackets are chosen for the same reason as NormalizedStringToken:
	// RFC 3986 excludes '<' and '>' from every production a path segment can
	// use, so they must be percent-encoded to appear in a real URL. A literal
	// segment therefore cannot be confused with the placeholder, and
	// CanonicalRouteTemplate is idempotent — "<VAR>" is itself recognised as
	// an already-templated segment and maps to itself.
	NormalizedRouteSegmentToken = "<VAR>"

	// tierTokenSast and tierTokenDast are the literal tier discriminators
	// hashed in field position 2 of their tiers. They are string literals
	// rather than DetectorKind values on purpose: the SAST tier hashes
	// "sast" for BOTH sast_reachable and sast_static_only findings, so this
	// token must not be confused with the evidence class.
	tierTokenSast = "sast"
	tierTokenDast = "dast"
)

// Route-segment templating thresholds. These are part of anvil-fp/v1: changing
// either one changes every DAST digest whose route carries a segment near the
// boundary, and is therefore an anvil-fp/v2 event, not a tuning knob.
//
// The governing asymmetry, from the R.3 ruling: OVER-templating merges two
// genuinely distinct routes into one identity and silently loses a finding on
// upsert against UNIQUE (target_id, fingerprint); UNDER-templating only leaves
// a volatile route un-merged, which the DAST producer can still fix by
// emitting "{id}" itself. Under-templating is the recoverable failure, so both
// thresholds are set high enough that no plausible human-authored path segment
// reaches them.
const (
	// routeHexSegmentMinLen is the length at or above which an all-hex segment
	// is treated as an opaque identifier. 16 is chosen because the hex
	// alphabet's letters are only a-f: a 16-character English word drawn from
	// {a,b,c,d,e,f} plus digits does not exist (the longest such words —
	// "defaced", "cabbage" — are seven letters), while every hash form Anvil
	// will meet in a URL is at or above it: MD5 is 32, SHA-1 is 40, SHA-256 is
	// 64, a dash-free UUID is 32, and a short git object id is 7-12 and so is
	// deliberately NOT templated (7 hex characters is also a plausible slug).
	routeHexSegmentMinLen = 16

	// routeOpaqueSegmentMinLen is the length at or above which a mixed
	// alphanumeric segment is treated as an opaque identifier. 20 is chosen
	// against the longest plausible single-word route segments —
	// "recommendations" (15), "internationalization" (20), "misrepresentation"
	// (17) — none of which contains a digit, which is why the digit
	// requirement in isLongOpaqueRouteSegment carries most of the safety here.
	// A base64url session token is 22+ characters and a base32 token is 26+,
	// so real opaque tokens clear the bar comfortably.
	routeOpaqueSegmentMinLen = 20
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// FingerprintError reports an input that cannot be fingerprinted. It names
// the tier and the field, because a bare "invalid input" tells a producer
// nothing about which of eight positional fields it got wrong — and a
// producer that silently emits a wrong digest is exactly the failure this
// package exists to prevent, so every tier function fails loudly rather than
// hashing a degraded input.
type FingerprintError struct {
	Tier  string // "sast", "dast", "sca", "host", or "" for the shared primitive
	Field string // the specification's field name, e.g. "repo_relpath"
	Msg   string
}

func (e *FingerprintError) Error() string {
	if e.Tier == "" {
		return fmt.Sprintf("anvil-fp/v1: %s: %s", e.Field, e.Msg)
	}
	return fmt.Sprintf("anvil-fp/v1 tier %s: %s: %s", e.Tier, e.Field, e.Msg)
}

func fpErr(tier, field, msg string) error {
	return &FingerprintError{Tier: tier, Field: field, Msg: msg}
}

// fpRequire returns v, or an error naming the field if v is empty.
func fpRequire(tier, field, v string) (string, error) {
	if v == "" {
		return "", fpErr(tier, field, "must not be empty")
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// The shared primitive: join, guard, hash
// ---------------------------------------------------------------------------

// Digest joins fields with FingerprintFieldSeparator (U+001F) and returns the
// lowercase hex SHA-256 of the result: exactly FingerprintDigestHexLen (64)
// characters, never truncated.
//
// It rejects any field containing a C0 control character or DEL. U+001F is
// the important case — a field carrying the separator would silently move a
// field boundary and let two different findings collide — but the whole
// control range is rejected because none of them can legitimately appear in
// a canonicalised path, rule id, symbol path, route template, purl, advisory
// id, or normalized match, and a newline in one of those means the caller has
// passed raw, uncanonicalised text.
//
// The exported tier functions below are the only sanctioned field lists.
// Digest is exported for the store and for debugging tooling, not so callers
// can invent a fingerprint shape of their own.
func Digest(fields ...string) (string, error) {
	if len(fields) == 0 {
		return "", fpErr("", "fields", "at least one field is required")
	}
	for i, f := range fields {
		if idx := strings.IndexFunc(f, isForbiddenControl); idx >= 0 {
			what := "a C0 control character"
			if f[idx] == FingerprintFieldSeparator[0] {
				what = "the U+001F field separator"
			}
			return "", fpErr("", "fields["+strconv.Itoa(i)+"]",
				"contains "+what+"; this would move a field boundary and let two distinct findings collide")
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, FingerprintFieldSeparator)))
	return hex.EncodeToString(sum[:]), nil
}

func isForbiddenControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// ValidateDigest reports whether s is a well-formed anvil-fp/v1 digest:
// exactly 64 lowercase hexadecimal characters. Uppercase hex is rejected
// rather than folded, because a store that accepts both would hold two rows
// for one finding and defeat UNIQUE (target_id, fingerprint).
func ValidateDigest(s string) error {
	if len(s) != FingerprintDigestHexLen {
		return fpErr("", "digest",
			fmt.Sprintf("must be exactly %d hex characters, got %d (the digest is never truncated)",
				FingerprintDigestHexLen, len(s)))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return fpErr("", "digest", "must be lowercase hexadecimal; found "+strconv.QuoteRune(rune(c))+
			" at offset "+strconv.Itoa(i))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tier SAST
// ---------------------------------------------------------------------------

// SastInput is the complete input to the SAST fingerprint tier, which covers
// EvidenceClassSastReachable and EvidenceClassSastStaticOnly alike.
//
// There is no line, column, advisory, or evidence-class field here, and there
// must never be one: each of those changes for reasons unrelated to the
// defect's identity. The raw Snippet is accepted only so NormalizeMatch can
// abstract it; the literal text is never hashed.
type SastInput struct {
	// TargetID is the stable identifier of the scanned target
	// (`target.target_id` rendered as text). Required.
	TargetID string

	// RuleIDVersioned is the detector rule id including its ruleset version,
	// e.g. "opengrep.go.lang.security.audit.sqli@2026.07". Required. The
	// version component is part of identity here: a rule that changed what
	// it matches is a different rule, and conflating them would silently
	// migrate findings between rule semantics.
	RuleIDVersioned string

	// RepoRelPath is the repository-root-relative POSIX path of the file
	// containing the match. Required. Canonicalised by CanonicalRepoRelPath
	// before hashing so a Windows producer and a Linux producer agree.
	RepoRelPath string

	// EnclosingSymbolPath is the fully-qualified enclosing symbol, e.g.
	// "pkg/mod.py::ClassA.method_b". MAY be empty: a match in top-level
	// module code, a config file, or a template has no enclosing symbol, and
	// rejecting those would make them unfingerprintable. An empty value is
	// hashed as an empty field, which keeps the field count constant.
	EnclosingSymbolPath string

	// Snippet is the RAW matched source text. It is passed through
	// NormalizeMatch and only the normalized form is hashed.
	Snippet string

	// Ordinal is the 0-based index of this match among all matches of the
	// same RuleIDVersioned in the same RepoRelPath whose normalized match is
	// IDENTICAL. Use AssignSastOrdinals to compute it. Without it, two
	// identical generated or macro-expanded call sites in one file collide
	// and one finding is lost on upsert.
	Ordinal int
}

// SastFields returns the ordered field list the SAST tier hashes, exactly as
// plan/40-record-and-storage.md specifies:
//
//	target_id ␟ "sast" ␟ rule_id_versioned ␟ repo_relpath
//	          ␟ enclosing_symbol_path ␟ normalized_match ␟ ordinal
//
// Exported so a test or R.16's conformance harness can assert the field list
// itself, not merely the digest — a wrong field ORDER produces a perfectly
// valid-looking 64-hex digest that is silently incompatible.
func SastFields(in SastInput) ([]string, error) {
	const tier = "sast"

	targetID, err := fpRequire(tier, "target_id", in.TargetID)
	if err != nil {
		return nil, err
	}
	ruleID, err := fpRequire(tier, "rule_id_versioned", in.RuleIDVersioned)
	if err != nil {
		return nil, err
	}
	if in.RepoRelPath == "" {
		return nil, fpErr(tier, "repo_relpath", "must not be empty")
	}
	relPath := CanonicalRepoRelPath(in.RepoRelPath)
	if relPath == "" {
		return nil, fpErr(tier, "repo_relpath", "canonicalises to the empty string")
	}
	if in.Snippet == "" {
		return nil, fpErr(tier, "normalized_match", "snippet must not be empty")
	}
	normalized := NormalizeMatch(in.Snippet)
	if normalized == "" {
		return nil, fpErr(tier, "normalized_match",
			"snippet normalises to the empty string (comments and whitespace only); it carries no identity")
	}
	if in.Ordinal < 0 {
		return nil, fpErr(tier, "ordinal", "must not be negative")
	}

	return []string{
		targetID,
		tierTokenSast,
		ruleID,
		relPath,
		in.EnclosingSymbolPath,
		normalized,
		strconv.Itoa(in.Ordinal),
	}, nil
}

// Sast returns the anvil-fp/v1 digest for a first-party source finding.
func Sast(in SastInput) (string, error) {
	fields, err := SastFields(in)
	if err != nil {
		return "", err
	}
	return Digest(fields...)
}

// ---------------------------------------------------------------------------
// Tier SCA / HOST — one formula, parameterised by detector kind
// ---------------------------------------------------------------------------

// ScaInput is the input to the SCA tier: a repository dependency that matched
// a vulnerable version range.
//
// There is deliberately no Version field. See "THE VERSION STRING IS NEVER
// HASHED" at the top of this file.
type ScaInput struct {
	// TargetID is the scanned target's identifier. Required.
	TargetID string

	// AdvisoryID is the canonical advisory identifier as stored in
	// `advisory.advisory_id` (e.g. "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q").
	// Required, and hashed VERBATIM: advisory identifiers are not
	// case-normalised here because GHSA identifiers mix cases meaningfully
	// and folding them would fork identity against the advisory table.
	AdvisoryID string

	// Purl is the package URL. It MAY carry a version, qualifiers, or a
	// subpath; PurlBase strips all three before hashing.
	Purl string

	// ManifestRelPath is the repo-relative path of the manifest or lockfile
	// that declared the dependency, e.g. "services/api/go.mod". Required:
	// the same vulnerable package pulled in by two different manifests in a
	// monorepo is two findings with two different owners and two different
	// fixes.
	ManifestRelPath string
}

// HostInput is the input to the host tier: an operating-system package on the
// scanned host that matched a vulnerable version range.
//
// plan/00-SPINE.md S7 makes the host agent read-only, so every host finding
// carries `remediable_by_agent=false` (enforced by the `finding` table's
// CHECK constraint, not here). It still needs a stable identity so that a
// host finding can be tracked, suppressed, and reported as resolved.
type HostInput struct {
	// TargetID is the scanned target's identifier. Required.
	TargetID string

	// AdvisoryID is the canonical advisory identifier. Required, verbatim.
	AdvisoryID string

	// Purl is the package URL for the host package, e.g.
	// "pkg:deb/debian/openssl". Version, qualifiers and subpath are stripped.
	Purl string

	// PackageManager is the host package manager, e.g. "apt", "apk", "rpm",
	// "dpkg". Required. Lowercased before hashing, because "APT" and "apt"
	// are the same manager and a case difference between two scanner
	// versions would fork every host finding at once.
	PackageManager string

	// HostIdentifier is the package identity as the manager names it, e.g.
	// "openssl" or "openssl:amd64". Required, verbatim: architecture and
	// suffixes are meaningful to the manager.
	HostIdentifier string
}

// HostLocator composes the host tier's `locator` field,
// "<package_manager>:<host_identifier>" (e.g. "apt:openssl"), applying the
// documented lowercasing of the manager segment.
func HostLocator(packageManager, hostIdentifier string) string {
	return strings.ToLower(strings.TrimSpace(packageManager)) + ":" + strings.TrimSpace(hostIdentifier)
}

// packageFields is the single implementation of the shared SCA/host formula:
//
//	target_id ␟ detector_kind ␟ advisory_id ␟ purl_base ␟ locator
//
// Written once and parameterised rather than copied, so the two tiers cannot
// drift apart the way research/07 and research/18 did.
func packageFields(tier string, kind DetectorKind, targetID, advisoryID, purl, locator string) ([]string, error) {
	tid, err := fpRequire(tier, "target_id", targetID)
	if err != nil {
		return nil, err
	}
	adv, err := fpRequire(tier, "advisory_id", advisoryID)
	if err != nil {
		return nil, err
	}
	if purl == "" {
		return nil, fpErr(tier, "purl_base", "purl must not be empty")
	}
	base, err := PurlBase(purl)
	if err != nil {
		return nil, err
	}
	if locator == "" {
		return nil, fpErr(tier, "locator", "must not be empty")
	}
	return []string{tid, string(kind), adv, base, locator}, nil
}

// ScaFields returns the ordered field list the SCA tier hashes.
func ScaFields(in ScaInput) ([]string, error) {
	const tier = "sca"
	if in.ManifestRelPath == "" {
		return nil, fpErr(tier, "locator", "manifest_relpath must not be empty")
	}
	locator := CanonicalRepoRelPath(in.ManifestRelPath)
	if locator == "" {
		return nil, fpErr(tier, "locator", "manifest_relpath canonicalises to the empty string")
	}
	return packageFields(tier, DetectorKindSCA, in.TargetID, in.AdvisoryID, in.Purl, locator)
}

// Sca returns the anvil-fp/v1 digest for a repository dependency finding.
func Sca(in ScaInput) (string, error) {
	fields, err := ScaFields(in)
	if err != nil {
		return "", err
	}
	return Digest(fields...)
}

// HostFields returns the ordered field list the host tier hashes.
func HostFields(in HostInput) ([]string, error) {
	const tier = "host"
	if strings.TrimSpace(in.PackageManager) == "" {
		return nil, fpErr(tier, "locator", "package_manager must not be empty")
	}
	if strings.ContainsRune(in.PackageManager, ':') {
		return nil, fpErr(tier, "locator",
			"package_manager must not contain ':'; it is the locator's own delimiter")
	}
	if strings.TrimSpace(in.HostIdentifier) == "" {
		return nil, fpErr(tier, "locator", "host_identifier must not be empty")
	}
	return packageFields(tier, DetectorKindHost, in.TargetID, in.AdvisoryID, in.Purl,
		HostLocator(in.PackageManager, in.HostIdentifier))
}

// Host returns the anvil-fp/v1 digest for a host package finding.
func Host(in HostInput) (string, error) {
	fields, err := HostFields(in)
	if err != nil {
		return "", err
	}
	return Digest(fields...)
}

// ---------------------------------------------------------------------------
// Tier DAST
// ---------------------------------------------------------------------------

// DastInput is the input to the DAST tier.
//
// There is no host, port, scheme, payload, session token, or timestamp field,
// and there must never be one. A redeployed container, a rotated ephemeral
// port, or a staging-to-prod move must not fork identity, and a fuzzer
// varying its payload must not mint N findings for one bug.
type DastInput struct {
	// TargetID is the scanned target's identifier. Required.
	TargetID string

	// RuleIDVersioned is the detector rule id including its version, e.g.
	// "nuclei:CVE-2021-44228@a1b2c3d". Required.
	RuleIDVersioned string

	// HTTPMethod is the request method. Required; uppercased before hashing
	// (RFC 9110 methods are case-sensitive and canonically uppercase, and a
	// producer sending "get" must not fork identity from one sending "GET").
	HTTPMethod string

	// RouteTemplate is the observed request path. Required. It may be the
	// CONCRETE path the producer requested ("/api/users/12345/orders") or a
	// path the producer has already templated in any of the three common
	// syntaxes ("{id}", ":id", "<id>"); CanonicalRouteTemplate derives the
	// hashed template from either, so the caller does not have to agree with
	// any other caller about which form to use. It also strips any query
	// string or fragment — those carry concrete values, which is exactly what
	// templating exists to remove.
	//
	// Templating is deliberately NOT the producer's job. See
	// CanonicalRouteTemplate for the ruling and the reason.
	RouteTemplate string

	// InjectionPoint is WHERE the payload was injected. Required; must be a
	// legal InjectionPoint literal from contract.go.
	InjectionPoint InjectionPoint

	// ParamName is the name of the injected parameter. MAY be empty: a
	// whole-body or raw-request injection has no single named parameter, and
	// rejecting those would make them unfingerprintable. This is a parameter
	// NAME, never a parameter value.
	ParamName string

	// EvidenceSignal is HOW the vulnerability was observed — research/18's
	// contribution to this tier. Required; must be a legal EvidenceSignal
	// literal from contract.go. It is independent of InjectionPoint: an SQL
	// injection proved by a database error string and one proved by a timing
	// side channel on the same parameter are different findings with
	// different remediation evidence.
	EvidenceSignal EvidenceSignal
}

// DastFields returns the ordered field list the DAST tier hashes, exactly as
// plan/40-record-and-storage.md specifies:
//
//	target_id ␟ "dast" ␟ rule_id_versioned ␟ http_method ␟ route_template
//	          ␟ injection_point ␟ param_name ␟ evidence_class_detail
func DastFields(in DastInput) ([]string, error) {
	const tier = "dast"

	targetID, err := fpRequire(tier, "target_id", in.TargetID)
	if err != nil {
		return nil, err
	}
	ruleID, err := fpRequire(tier, "rule_id_versioned", in.RuleIDVersioned)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.HTTPMethod) == "" {
		return nil, fpErr(tier, "http_method", "must not be empty")
	}
	method := strings.ToUpper(strings.TrimSpace(in.HTTPMethod))
	if strings.ContainsFunc(method, unicode.IsSpace) {
		return nil, fpErr(tier, "http_method", "must be a single token")
	}
	if in.RouteTemplate == "" {
		return nil, fpErr(tier, "route_template", "must not be empty")
	}
	route := CanonicalRouteTemplate(in.RouteTemplate)
	if route == "" {
		return nil, fpErr(tier, "route_template", "canonicalises to the empty string")
	}
	if err := ValidateInjectionPoint(string(in.InjectionPoint)); err != nil {
		return nil, fpErr(tier, "injection_point", err.Error())
	}
	if err := ValidateEvidenceSignal(string(in.EvidenceSignal)); err != nil {
		return nil, fpErr(tier, "evidence_class_detail", err.Error())
	}

	return []string{
		targetID,
		tierTokenDast,
		ruleID,
		method,
		route,
		string(in.InjectionPoint),
		in.ParamName,
		string(in.EvidenceSignal),
	}, nil
}

// Dast returns the anvil-fp/v1 digest for a dynamically-confirmed finding.
func Dast(in DastInput) (string, error) {
	fields, err := DastFields(in)
	if err != nil {
		return "", err
	}
	return Digest(fields...)
}

// ---------------------------------------------------------------------------
// Canonicalisation helpers
// ---------------------------------------------------------------------------

// CanonicalRepoRelPath normalises a repository-relative path to the single
// POSIX form the specification assumes ("repo_relpath — POSIX,
// repo-root-relative", research/07 §3):
//
//   - backslashes become forward slashes, so a Windows producer and a Linux
//     producer scanning the same repository agree;
//   - runs of slashes collapse to one;
//   - a leading "./" or "/" is removed, so "./cmd/x.go", "/cmd/x.go" and
//     "cmd/x.go" are one path;
//   - a trailing slash is removed.
//
// It deliberately does NOT case-fold: POSIX paths are case-sensitive, and
// folding would merge two genuinely distinct files on a case-sensitive
// checkout. It also does not resolve ".." — a path escaping the repo root is
// the caller's bug and must not be silently rewritten into a different file.
func CanonicalRepoRelPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	return p
}

// CanonicalRouteTemplate DERIVES the hashed `route_template` from whatever
// route a DAST producer observed. The specification defines the field as a
// derived value — "numeric/UUID/hash path segments replaced with a placeholder
// token" — and this function is where that derivation happens.
//
// WHY IT HAPPENS HERE AND NOT IN THE PRODUCER (R.3 ruling, 2026-08-08). Area
// 40 owns the fingerprint, so area 40 canonicalises. A DAST producer emits
// whatever route it observed; if templating were the producer's job, then two
// producers seeing one defect at /api/users/12345/orders would emit
// "/api/users/12345/orders", "/api/users/{id}/orders" and
// "/api/users/:id/orders" — three digests, one defect, no error, regression
// matching silently dead. The DAST tier is the one that earns "verified fixed"
// under plan/00-SPINE.md S7, and a reproduction that cannot be matched to its
// prior finding cannot prove a fix.
//
// The steps, in order:
//
//  1. anything from the first '?' or '#' is dropped. A query string or
//     fragment in a "template" carries concrete values — the very thing
//     templating removes — and injection_point plus param_name already record
//     which query parameter was targeted;
//  2. backslashes become forward slashes;
//  3. runs of slashes collapse to one;
//  4. a leading '/' is added if absent;
//  5. a trailing '/' is removed, except on the root path "/";
//  6. every VOLATILE path segment is replaced by NormalizedRouteSegmentToken.
//     A segment is volatile when it is already templated in a producer's own
//     syntax ("{id}", ":id", "<id>"), is all ASCII digits, is a UUID, is a
//     long all-hex run, or is a long mixed alphanumeric run containing a
//     digit. See isVolatileRouteSegment for the exact predicates.
//
// Case is preserved on non-volatile segments: URL paths are case-sensitive and
// "/Search" is a different route from "/search" on most servers. The UUID and
// hex predicates are themselves case-insensitive, because the same identifier
// rendered in upper and lower hex is the same identifier.
//
// Percent-encoding is deliberately NOT decoded: decoding could introduce a '/'
// and change the segment structure, and a producer that percent-encodes a
// whole segment has emitted a different route.
func CanonicalRouteTemplate(route string) string {
	if i := strings.IndexAny(route, "?#"); i >= 0 {
		route = route[:i]
	}
	route = strings.ReplaceAll(route, "\\", "/")
	for strings.Contains(route, "//") {
		route = strings.ReplaceAll(route, "//", "/")
	}
	if route == "" {
		return ""
	}
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	if len(route) > 1 {
		route = strings.TrimSuffix(route, "/")
	}
	if route == "/" {
		return "/"
	}

	segs := strings.Split(route[1:], "/")
	for i, s := range segs {
		if isVolatileRouteSegment(s) {
			segs[i] = NormalizedRouteSegmentToken
		}
	}
	return "/" + strings.Join(segs, "/")
}

// isVolatileRouteSegment reports whether one path segment carries a concrete
// instance identifier rather than route structure, and must therefore be
// replaced by NormalizedRouteSegmentToken.
//
// Every predicate is conservative by construction — see the threshold
// constants for the asymmetry that motivates it.
func isVolatileRouteSegment(s string) bool {
	switch {
	case s == "":
		return false
	case isRoutePlaceholderSegment(s):
		return true
	case isAllASCIIDigits(s):
		return true
	case isUUIDRouteSegment(s):
		return true
	case isLongHexRouteSegment(s):
		return true
	case isLongOpaqueRouteSegment(s):
		return true
	default:
		return false
	}
}

// isRoutePlaceholderSegment recognises a segment a producer has ALREADY
// templated, in any of the three syntaxes in common use: OpenAPI/ASP.NET
// "{id}", Express/Rails/Sinatra ":id", and Flask/Werkzeug "<id>".
//
// Normalising all three onto one token is the point: a DAST crawler, an
// OpenAPI document checked into the repo, and a route table exported from a
// framework will disagree about which syntax to use for the same route, and
// that disagreement must not fork identity.
//
// The "<id>" form also makes CanonicalRouteTemplate idempotent, because
// NormalizedRouteSegmentToken is itself of that form.
func isRoutePlaceholderSegment(s string) bool {
	if len(s) < 2 {
		return false
	}
	if s[0] == '{' && s[len(s)-1] == '}' {
		return true
	}
	if s[0] == '<' && s[len(s)-1] == '>' {
		return true
	}
	return s[0] == ':'
}

func isAllASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isASCIIHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isUUIDRouteSegment recognises the canonical 8-4-4-4-12 hyphenated form,
// case-insensitively. Braced ("{...}") and URN ("urn:uuid:...") forms are not
// recognised here: the first is already caught by isRoutePlaceholderSegment
// and the second is not a bare path segment.
func isUUIDRouteSegment(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isASCIIHexDigit(s[i]) {
				return false
			}
		}
	}
	return true
}

// isLongHexRouteSegment recognises a run of at least routeHexSegmentMinLen hex
// characters: a dash-free UUID, an MD5/SHA digest, an object id.
func isLongHexRouteSegment(s string) bool {
	if len(s) < routeHexSegmentMinLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isASCIIHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// isLongOpaqueRouteSegment recognises a base32/base64-ish opaque token: at
// least routeOpaqueSegmentMinLen characters, ASCII alphanumeric throughout,
// and carrying BOTH a digit and a letter.
//
// The three restrictions each buy something specific, and dropping any of them
// over-templates:
//
//   - alphanumeric only (no '-', '_', '.') keeps slugs out. A hyphenated slug
//     like "release-notes-2026-08" is 21 characters and carries a digit; it is
//     route structure, not an identifier, and merging every dated release note
//     onto one digest would be exactly the over-templating failure the ruling
//     warns about. Base64url tokens that use '-' or '_' are therefore left
//     un-templated: under-templating is the recoverable direction.
//   - a digit is required, which is what excludes the long all-letter words
//     that do reach 20 characters ("internationalization").
//   - a letter is required, so that a purely numeric run is attributed to the
//     all-digits rule rather than this one; the outcome is the same token, but
//     the two rules stay independently testable.
func isLongOpaqueRouteSegment(s string) bool {
	if len(s) < routeOpaqueSegmentMinLen {
		return false
	}
	hasDigit, hasLetter := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetter = true
		default:
			return false
		}
	}
	return hasDigit && hasLetter
}

// PurlBase reduces a package URL to its version-free base:
// "pkg:type/namespace/name". It strips, in order, any subpath ('#'), any
// qualifiers ('?'), and any version ('@').
//
// This is the enforcement point for the rule that the version string is NEVER
// hashed. A caller passing "pkg:npm/lodash@4.17.20" and a caller passing
// "pkg:npm/lodash" produce the same fingerprint, so bumping a dependency
// inside the vulnerable range does not mint a new finding.
//
// The '@' scan starts after "pkg:" and is safe against namespaced packages:
// the purl specification requires a literal '@' inside a namespace or name to
// be percent-encoded as "%40" (as in "pkg:npm/%40angular/core@13.0.0"), so
// the first raw '@' can only be the version delimiter.
//
// The scheme and type segments are lowercased because the purl specification
// defines both as case-insensitive with a lowercase canonical form; the
// namespace and name are left alone because their case-sensitivity is
// type-dependent and folding them could merge two distinct packages.
func PurlBase(purl string) (string, error) {
	p := strings.TrimSpace(purl)
	if p == "" {
		return "", fpErr("", "purl_base", "must not be empty")
	}
	if len(p) < 4 || !strings.EqualFold(p[:4], "pkg:") {
		return "", fpErr("", "purl_base", "must be a package URL beginning with \"pkg:\", got "+strconv.Quote(purl))
	}

	rest := p[4:]
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return "", fpErr("", "purl_base", "carries no type or name after \"pkg:\": "+strconv.Quote(purl))
	}

	// Lowercase only the type segment (everything up to the first '/').
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = strings.ToLower(rest[:i]) + rest[i:]
	} else {
		return "", fpErr("", "purl_base", "carries a type but no name: "+strconv.Quote(purl))
	}

	return "pkg:" + rest, nil
}

// ---------------------------------------------------------------------------
// Ordinal assignment
// ---------------------------------------------------------------------------

// SastCandidate pairs a SastInput with the source position used ONLY to order
// identical matches deterministically. Line and Column are never hashed and
// never reach Digest; they exist because "the 0-based index of this match
// among identical matches" needs a total order, and source order is the only
// one a producer and a re-scan both agree on.
//
// KNOWN LIMITATION, inherited from the specification rather than chosen here:
// inserting a THIRD identical call site above two existing ones shifts their
// ordinals and therefore their digests. research/07 §3's matching cascade
// (exact hit, then rule+path+line_hash, then rule+symbol_hash) is what
// recovers identity in that case; the fingerprint alone cannot. The
// alternative — dropping the ordinal — silently LOSES one of the two findings
// on upsert against UNIQUE (target_id, fingerprint), which is worse.
type SastCandidate struct {
	Input  SastInput
	Line   int // ordering only; never hashed
	Column int // ordering only; never hashed
}

// AssignSastOrdinals returns a copy of cands' inputs with Ordinal set, in the
// SAME order as cands. Ordinals are assigned per
// (TargetID, RuleIDVersioned, RepoRelPath, normalized match) group in
// ascending (Line, Column, original index) order.
//
// The group key adds TargetID to the specification's (rule, path, normalized)
// key because the specification's grouping is implicitly per-target; passing
// two targets' candidates in one slice would otherwise cross-index them.
//
// Any input whose fields are invalid is returned as an error rather than
// silently given ordinal 0, because a bad ordinal is invisible in the digest.
func AssignSastOrdinals(cands []SastCandidate) ([]SastInput, error) {
	type keyed struct {
		idx int
		key string
	}

	out := make([]SastInput, len(cands))
	order := make([]keyed, 0, len(cands))

	for i, c := range cands {
		// Validate through the real field builder so an input that cannot be
		// fingerprinted is rejected here rather than at hash time.
		if _, err := SastFields(c.Input); err != nil {
			return nil, fmt.Errorf("candidate %d: %w", i, err)
		}
		out[i] = c.Input
		order = append(order, keyed{
			idx: i,
			key: strings.Join([]string{
				c.Input.TargetID,
				c.Input.RuleIDVersioned,
				CanonicalRepoRelPath(c.Input.RepoRelPath),
				NormalizeMatch(c.Input.Snippet),
			}, FingerprintFieldSeparator),
		})
	}

	sort.SliceStable(order, func(a, b int) bool {
		if order[a].key != order[b].key {
			return order[a].key < order[b].key
		}
		ca, cb := cands[order[a].idx], cands[order[b].idx]
		if ca.Line != cb.Line {
			return ca.Line < cb.Line
		}
		if ca.Column != cb.Column {
			return ca.Column < cb.Column
		}
		return order[a].idx < order[b].idx
	})

	prevKey := ""
	ordinal := 0
	for i, k := range order {
		if i == 0 || k.key != prevKey {
			ordinal = 0
			prevKey = k.key
		}
		out[k.idx].Ordinal = ordinal
		ordinal++
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// Match normalization
// ---------------------------------------------------------------------------

// NormalizeMatch abstracts a raw matched source snippet into the form the
// SAST tier hashes. It is modelled on Semgrep's `match_based_id`
// (research/07 §3 [S3]), which is the externally-verified mechanism for
// surviving reindentation and metavariable-only edits.
//
// The algorithm, in one pass, left to right. Any re-implementation (R.16)
// must reproduce it exactly:
//
//  1. CRLF and CR are folded to LF.
//  2. A whitespace run emits a single space.
//  3. A line comment ("//..." or "#..." to end of line) and a block comment
//     ("/*...*/", unterminated meaning to end of input) are dropped and emit
//     a single space in their place.
//  4. A string literal delimited by ", ' or ` emits NormalizedStringToken.
//     Backslash escapes are honoured inside " and ' but not inside `.
//  5. A token starting with an ASCII digit emits NormalizedNumberToken. It
//     consumes following letters, digits, '_' and '.', plus a '+' or '-'
//     immediately after an 'e' or 'E', so 0xFF, 1_000, 3.14f and 1e-9 are all
//     one token.
//  6. An identifier ([\p{L}_$][\p{L}\p{N}_$]*) emits:
//     a. itself, if it is a reserved word (the union list below);
//     b. itself, if the preceding non-space output ends in ".", "->" or "::"
//     — it is a member or qualified name, which is API surface, not churn;
//     c. itself, if the next non-space input is "::" — it is a namespace or
//     type qualifier, which is API surface for the same reason;
//     d. itself, if the next non-space input character is "(" — it is a
//     callee name, which is the sink the rule actually matched;
//     e. otherwise "$N", where N counts distinct such identifiers in
//     first-occurrence order, with every later occurrence of the same
//     spelling mapping to the same "$N".
//  7. Any other character is emitted verbatim.
//  8. The result is trimmed of leading and trailing spaces.
//
// WHY 6(b), 6(c) AND 6(d) EXIST — the specification says "replace LOCAL
// identifiers", and this is what "local" is taken to mean. Replacing every
// identifier would normalise `request.getParameter(userInput)` and
// `config.getName(key)` to the same string, destroying nearly all
// discriminating power and pushing the whole burden of distinguishing
// findings onto `ordinal`, which is the least stable field in the tier.
// Preserving member, qualifier and callee names keeps the sink identifiable
// while still abstracting the variable names that a refactor renames.
//
// WHY 6(c) TREATS "::" DIFFERENTLY FROM "." AND "->". The LEFT operand of
// "::" is a namespace or type name in every language that has the operator
// (C++, Rust, PHP, Ruby) — it is never a local variable, so abstracting it
// violates "replace local identifiers" outright and collapses
// `Ns::Helper(v)` and `Other::Helper(v)` — two calls into two different
// namespaces — onto one digest. The left operand of "." or "->" is usually a
// receiver bound to a local (`db.Query(q)`, `p->Field`), so it is abstracted;
// a lexer cannot tell a Go package qualifier from a receiver variable, and
// guessing wrong in the other direction would fork the digest of unchanged
// code, which is the worse failure.
//
// KNOWN, ACCEPTED LIMITATIONS. This is one language-agnostic lexer, not N
// parsers, because Anvil's SAST tier is an opengrep subprocess that returns
// text (plan/00-SPINE.md S12: opengrep "is an OCaml CLI with zero bindings in
// any language"). Determinism, not semantic perfection, is what identity
// needs — the same snippet must normalise the same way on every scan, and it
// does:
//
//   - '#' is treated as a line comment, so a C/C++ preprocessor directive or
//     a C# '#region' inside a snippet is dropped. Match snippets rarely
//     contain them.
//   - "'" is treated as a string delimiter, so a Rust lifetime ('static) or a
//     Lisp quote consumes to the next "'".
//   - the reserved-word list is a UNION across languages, so an identifier
//     named `class` in a language where it is not reserved is preserved
//     rather than abstracted.
//
// Each of these is stable under re-scan, which is the property that matters.
func NormalizeMatch(snippet string) string {
	src := strings.ReplaceAll(snippet, "\r\n", "\n")
	src = strings.ReplaceAll(src, "\r", "\n")

	in := []rune(src)
	n := len(in)
	out := make([]rune, 0, n)

	emit := func(s string) {
		out = append(out, []rune(s)...)
	}
	emitSpace := func() {
		if len(out) > 0 && out[len(out)-1] != ' ' {
			out = append(out, ' ')
		}
	}
	// endsWithSelector reports whether the output so far ends in a member or
	// qualified-name selector, ignoring trailing spaces.
	endsWithSelector := func() bool {
		end := len(out)
		for end > 0 && out[end-1] == ' ' {
			end--
		}
		if end == 0 {
			return false
		}
		if out[end-1] == '.' {
			return true
		}
		if end >= 2 && out[end-2] == '-' && out[end-1] == '>' {
			return true
		}
		if end >= 2 && out[end-2] == ':' && out[end-1] == ':' {
			return true
		}
		return false
	}

	metavars := make(map[string]string)
	nextMetavar := 1

	i := 0
	for i < n {
		c := in[i]

		switch {
		case unicode.IsSpace(c):
			for i < n && unicode.IsSpace(in[i]) {
				i++
			}
			emitSpace()

		case c == '/' && i+1 < n && in[i+1] == '/':
			for i < n && in[i] != '\n' {
				i++
			}
			emitSpace()

		case c == '#':
			for i < n && in[i] != '\n' {
				i++
			}
			emitSpace()

		case c == '/' && i+1 < n && in[i+1] == '*':
			i += 2
			for i < n {
				if in[i] == '*' && i+1 < n && in[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			emitSpace()

		case c == '"' || c == '\'' || c == '`':
			quote := c
			i++
			for i < n {
				if in[i] == '\\' && quote != '`' {
					i += 2
					continue
				}
				if in[i] == quote {
					i++
					break
				}
				i++
			}
			emit(NormalizedStringToken)

		case c >= '0' && c <= '9':
			for i < n {
				r := in[i]
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' {
					i++
					continue
				}
				if (r == '+' || r == '-') && i > 0 && (in[i-1] == 'e' || in[i-1] == 'E') {
					i++
					continue
				}
				break
			}
			emit(NormalizedNumberToken)

		case isIdentStart(c):
			j := i
			for j < n && isIdentPart(in[j]) {
				j++
			}
			word := string(in[i:j])
			i = j

			switch {
			case fingerprintReservedWords[word]:
				emit(word)
			case endsWithSelector():
				emit(word)
			case nextNonSpaceIsScopeResolution(in, i):
				emit(word)
			case nextNonSpaceIsCallOpen(in, i):
				emit(word)
			default:
				mv, ok := metavars[word]
				if !ok {
					mv = NormalizedMetavarPrefix + strconv.Itoa(nextMetavar)
					nextMetavar++
					metavars[word] = mv
				}
				emit(mv)
			}

		default:
			out = append(out, c)
			i++
		}
	}

	return strings.TrimSpace(string(out))
}

func isIdentStart(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// nextNonSpaceIsCallOpen reports whether the next non-space character at or
// after i is '(' — i.e. the identifier just consumed is a callee name.
func nextNonSpaceIsCallOpen(in []rune, i int) bool {
	for i < len(in) && unicode.IsSpace(in[i]) {
		i++
	}
	return i < len(in) && in[i] == '('
}

// nextNonSpaceIsScopeResolution reports whether the next non-space characters
// at or after i are "::" — i.e. the identifier just consumed is the namespace
// or type qualifier on the left of a scope-resolution operator. See rule 6(c)
// in NormalizeMatch's contract: that operand is never a local variable, so
// abstracting it would both violate "replace local identifiers" and merge
// calls into two different namespaces onto one digest.
func nextNonSpaceIsScopeResolution(in []rune, i int) bool {
	for i < len(in) && unicode.IsSpace(in[i]) {
		i++
	}
	return i+1 < len(in) && in[i] == ':' && in[i+1] == ':'
}

// fingerprintReservedWords is the union of keywords, literal keywords and
// primitive type names across the languages Anvil's SAST tier covers (Go,
// Java, C#, C/C++, JavaScript/TypeScript, Python, Ruby, PHP). Identifiers in
// this set are preserved verbatim rather than abstracted to $N.
//
// It is a UNION on purpose. A per-language list would require knowing the
// language at fingerprint time, which the opengrep subprocess boundary does
// not reliably give us, and a wrong language guess would change the digest of
// unchanged code. A union is a fixed, deterministic function of the token
// text alone. Adding or removing an entry CHANGES EVERY SAST FINGERPRINT and
// is therefore an anvil-fp/v2 event, not a maintenance edit.
var fingerprintReservedWords = map[string]bool{
	// Literal keywords and self-references, across all languages.
	"true": true, "false": true, "null": true, "nil": true, "none": true,
	"None": true, "True": true, "False": true, "NULL": true, "nullptr": true,
	"undefined": true, "self": true, "this": true, "super": true, "cls": true,
	"iota": true, "base": true,

	// Control flow and declaration keywords.
	"abstract": true, "and": true, "as": true, "assert": true, "async": true,
	"await": true, "begin": true, "break": true, "case": true, "catch": true,
	"chan": true, "checked": true, "class": true, "clone": true, "const": true,
	"constexpr": true, "continue": true, "debugger": true, "declare": true,
	"def": true, "default": true, "defer": true, "del": true, "delete": true,
	"do": true, "echo": true, "elif": true, "else": true, "elseif": true,
	"elsif": true, "end": true, "endforeach": true, "endif": true,
	"endwhile": true, "ensure": true, "enum": true, "except": true,
	"exit": true, "explicit": true, "export": true, "extends": true,
	"extern": true, "fallthrough": true, "final": true, "finally": true,
	"fn": true, "for": true, "foreach": true, "friend": true, "from": true,
	"func": true, "function": true, "global": true, "go": true, "goto": true,
	"if": true, "implements": true, "implicit": true, "import": true,
	"in": true, "include": true, "include_once": true, "inline": true,
	"instanceof": true, "insteadof": true, "interface": true, "internal": true,
	"is": true, "keyof": true, "lambda": true, "let": true, "lock": true,
	"match": true, "module": true, "mutable": true, "namespace": true,
	"native": true, "new": true, "nonlocal": true, "not": true,
	"operator": true, "or": true, "out": true, "override": true,
	"package": true, "params": true, "pass": true, "print": true,
	"private": true, "protected": true, "public": true, "raise": true,
	"range": true, "readonly": true, "redo": true, "ref": true,
	"register": true, "require": true, "require_once": true,
	"require_relative": true, "rescue": true, "retry": true, "return": true,
	"sealed": true, "select": true, "signed": true, "sizeof": true,
	"stackalloc": true, "static": true, "strictfp": true, "struct": true,
	"switch": true, "synchronized": true, "template": true, "throw": true,
	"throws": true, "trait": true, "transient": true, "try": true,
	"type": true, "typedef": true, "typeof": true, "unchecked": true,
	"union": true, "unless": true, "unsafe": true, "unsigned": true,
	"until": true, "use": true, "using": true, "var": true, "virtual": true,
	"volatile": true, "when": true, "while": true, "with": true, "xor": true,
	"yield": true,

	// Primitive and built-in type names.
	"any": true, "bigint": true, "bool": true, "boolean": true, "byte": true,
	"char": true, "complex64": true, "complex128": true, "decimal": true,
	"double": true, "error": true, "float": true, "float32": true,
	"float64": true, "int": true, "int8": true, "int16": true, "int32": true,
	"int64": true, "long": true, "never": true, "object": true, "rune": true,
	"sbyte": true, "short": true, "string": true, "symbol": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true,
	"uint64": true, "uintptr": true, "ulong": true, "unknown": true,
	"ushort": true, "void": true, "wchar_t": true,
}
