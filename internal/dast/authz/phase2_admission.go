// Phase 2 of the Authorization Gate Sequence: PER-TARGET ADMISSION, gates
// 8–12.
//
// Phase 1 (phase1_run.go) asked whether this RUN may start. Phase 2 asks
// whether THIS TARGET may be connected to: is the host the host the scope
// author meant, what address does it actually resolve to, is that address one
// the kernel will connect to at all, and does the site's own robots.txt remove
// paths from what scope already permitted.
//
// ===========================================================================
// THE ONE SENTENCE THAT ORGANISES THIS FILE
// ===========================================================================
//
// A NAME IS NOT A DESTINATION. Every failure Phase 2 exists to prevent is a
// version of forgetting that:
//
//	gate 8   two spellings of one name (EXAMPLE.com., %65xample.com,
//	         [::ffff:169.254.169.254]) match different scope entries, or none.
//	gate 9   the name resolved to one address when it was checked and another
//	         when it was connected to. That is DNS rebinding, and it is closed
//	         here by resolving ONCE, in the kernel, carrying the resolved
//	         address inside the Target, and handing the egress layer an
//	         AddrPort — never a hostname.
//	gate 10  the address the name resolved to is 169.254.169.254.
//	gate 11  the site said, in the one place the web has for saying it, not to.
//
// ===========================================================================
// WHAT IS REGISTERED INTO THE ADMISSION CHAIN, AND WHAT IS NOT
// ===========================================================================
//
// Gates 8, 9 and 10 are registered. Each is genuinely a function of
// (target, scope, attestation, clock) — the spine's four inputs —
// because the canonical form, the pinned address and the run's mode all live
// inside those four values. They are also three of the five gates gate 13
// re-runs on every request and every redirect hop (kernel.go's
// revalidationChain — gates 4, 5, 8, 9 and 10), so after this packet
// Revalidate is fully implemented.
//
// GATE 11 IS NOT REGISTERED AND CANNOT BE, for the same structural reason run initiation
// could not register gate 7, and the accounting is repeated here rather than
// referred to:
//
//   - robots.txt is a property of an ORIGIN and a PATH. A gateFunc receives no
//     path (a Target is scheme, host, port and pinned address) and no fetched
//     document. Widening gateFunc to carry one is a change to the kernel core's contract
//     and to the spine's safety section, and it is the same widening gate 12 exists to prevent.
//   - Threading the policy through package-level state written at run
//     initiation would make Decide a function of ambient mutable state, which
//     is a safety-section violation wearing a hat.
//   - Registering a gate 11 that permits whenever the four inputs are well
//     formed would be a gate that has never refused anything — the exact shape
//     docs/controls.md records this repository shipping twice.
//
// GATE 11 IS ENFORCED IN TWO PLACES INSTEAD, and neither is a chain position.
//
//	AT RUN INITIATION   NarrowScopeToRobots takes the sealed Scope and the
//	                    fetched robots.txt BYTES — as data, the same shape
//	                    FetchSecurityTxt takes — and returns a NARROWER Scope.
//	                    plan/design/dynamic-tier.md:1032's row says a restrictive
//	                    robots.txt "REMOVES PATHS FROM SCOPE" and a permissive
//	                    one "adds nothing", which is a scope transformation and
//	                    is implemented as one. It cannot widen: see types.go's
//	                    SCOPE NARROWING block.
//	PER REQUEST         CheckGate11RobotsDeny, called by per-request enforcement's Governor on
//	                    every request and every redirect hop with the origin's
//	                    determined policy and the path about to be requested.
//	                    This is where "we did not look" is refused.
//
// Gate 11 was previously a position in admissionChain with nothing registered,
// which made the admission chain refuse every target — fail-closed, but it also
// meant the kernel could admit nothing. kernel.go's registerInto now refuses to
// register gate 11 at all, so putting it back is not a one-line edit somebody
// can make without deciding to.
//
// GATE 12 IS NOT A GATE AND CANNOT BECOME ONE. security.txt resolves a
// reporting channel and never grants permission (RFC 9116; the spine's safety
// section). SecurityTxtResult embeds ReportingChannelOnly, appears in no signature
// reachable from Decide, and registerInto refuses to register gate 12 at all.
//
// ===========================================================================
// UNTRUSTED BYTES
// ===========================================================================
//
// robots.txt and security.txt are fetched FROM THE TARGET. The spine's record section
// marks them `anvil/trust: untrusted` and the spine's safety section names the response body "the
// highest-risk field — up to 32 KB of attacker-controlled bytes fed to a
// repo-credentialed agent". Nothing parsed out of either document is
// interpolated into a Detail string. Where an operator needs to see a value it
// goes through redactUntrusted (phase1_run.go), which keeps an allowlisted
// charset and bounds the length, and every parsed value is separately bounded
// and charset-restricted at parse time.

package authz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// REASONS — the gate-numbered tokens Phase 2 refuses with
// ---------------------------------------------------------------------------

// Gate 8 reasons. types.go already declares ReasonTargetUnconstructed
// ("gate08.target_not_constructed") and this file reuses it.
const (
	ReasonHostEmpty                Reason = "gate08.host_is_empty"
	ReasonHostTooLong              Reason = "gate08.host_exceeds_length_bound"
	ReasonHostPercentEncoding      Reason = "gate08.host_percent_encoding_malformed"
	ReasonHostDoublePercent        Reason = "gate08.host_double_percent_encoded"
	ReasonHostNotASCII             Reason = "gate08.host_is_not_an_ascii_a_label"
	ReasonHostBracketMalformed     Reason = "gate08.host_bracket_malformed"
	ReasonHostIPv6Literal          Reason = "gate08.host_is_an_ipv6_literal"
	ReasonHostCharset              Reason = "gate08.host_has_a_character_outside_the_allowlist"
	ReasonHostLabel                Reason = "gate08.host_has_a_malformed_dns_label"
	ReasonHostNumericTLD           Reason = "gate08.host_final_label_is_all_digits"
	ReasonCanonicalizeFailed       Reason = "gate08.literal_host_is_not_canonicalizable"
	ReasonCanonicalMismatch        Reason = "gate08.canonical_field_is_not_the_canonical_form"
	ReasonCanonicalDivergence      Reason = "gate08.canonical_form_diverges_from_literal"
	ReasonPortNotNormalizable      Reason = "gate08.port_is_not_normalizable"
	ReasonSchemeUnknown            Reason = "gate08.scheme_is_not_http_or_https"
	ReasonTargetCanonicalAndPinned Reason = "gate08.target_is_canonical"
)

// Gate 9 reasons.
const (
	ReasonPinTargetUnbuilt       Reason = "gate09.target_not_constructed"
	ReasonResolverMissing        Reason = "gate09.no_resolver_supplied"
	ReasonResolutionFailed       Reason = "gate09.dns_resolution_failed"
	ReasonResolutionEmpty        Reason = "gate09.dns_returned_no_addresses"
	ReasonResolutionTooManyAddrs Reason = "gate09.dns_returned_more_addresses_than_the_bound"
	ReasonPinUnspecified         Reason = "gate09.pinned_address_is_unspecified"
	ReasonPinNotUnicast          Reason = "gate09.pinned_address_is_not_unicast"
	ReasonPinDisagreesWithHost   Reason = "gate09.pinned_address_is_not_the_host_literal"
	ReasonPinDeniedByScope       Reason = "gate09.pinned_address_is_on_the_scope_deny_list"
	ReasonPinScopeUnconstructed  Reason = "gate09.no_scope_to_match_the_pinned_address_against"
	ReasonPinnedAndMatched       Reason = "gate09.address_pinned_and_matched"
)

// Gate 10 reasons.
const (
	ReasonReservedTargetUnbuilt      Reason = "gate10.target_not_constructed"
	ReasonReservedRangeExternal      Reason = "gate10.reserved_range_in_external_mode"
	ReasonReservedRangeNotEnumerated Reason = "gate10.reserved_range_not_enumerated_in_lab_scope"
	ReasonReservedScopeUnconstructed Reason = "gate10.no_scope_to_read_the_mode_from"
	ReasonAddressNotReserved         Reason = "gate10.address_is_not_in_a_reserved_range"
	ReasonReservedEnumeratedInLab    Reason = "gate10.reserved_address_enumerated_in_lab_scope"
)

// Gate 11 reasons.
const (
	ReasonRobotsTargetUnbuilt Reason = "gate11.target_not_constructed"
	ReasonRobotsNotDetermined Reason = "gate11.robots_txt_was_never_determined"
	ReasonRobotsUnavailable   Reason = "gate11.robots_txt_could_not_be_determined"
	ReasonRobotsWrongOrigin   Reason = "gate11.robots_policy_is_for_another_origin"
	ReasonRobotsPathMalformed Reason = "gate11.request_path_is_malformed"
	ReasonRobotsDisallows     Reason = "gate11.robots_txt_disallows_this_path"

	// The four refusals NarrowScopeToRobots mints at run initiation. They are
	// refusals about the NARROWING rather than about a path: each one means
	// gate 11 could not be applied, and a gate that could not be applied
	// refuses.
	ReasonRobotsScopeUnconstructed   Reason = "gate11.scope_was_never_constructed"
	ReasonRobotsDocumentOrigin       Reason = "gate11.robots_document_origin_unusable"
	ReasonRobotsDocumentInconsistent Reason = "gate11.robots_document_is_inconsistent"
	// ReasonRobotsNarrowingFailed is NOT REACHABLE THROUGH NarrowScopeToRobots
	// TODAY, and that is stated rather than left for a reader to discover.
	// Canonicalize turns out to be strictly stronger than ScopeEntry.Validate
	// for hostnames — it rejects empty labels, leading and trailing "-", "*"
	// and every byte outside [a-z0-9_-], and bounds the length below the DNS
	// limit — so every origin that survives the round-trip check above also
	// survives the deny-entry write below it. That was measured (see the
	// "a host longer than canonicalization accepts" row of
	// TestNarrowScopeToRobotsRefuses, which was written expecting this token
	// and got ReasonRobotsDocumentOrigin instead), not assumed. The branch
	// stays because a guard whose only defence is "the caller checks first" is
	// one refactor from being no guard; TestScopeNarrowingPrimitivesRefuse
	// drives removeOrigin and removePaths directly so it is exercised.
	ReasonRobotsNarrowingFailed Reason = "gate11.scope_narrowing_failed"
)

// Gate 12 reasons. They are AUDIT tokens, not rulings: gate 12 is in no chain
// and mints no Ruling. The disclosure phase writes the reporting-channel outcome to the audit
// log under one of these.
const (
	ReasonSecurityTxtAbsent    Reason = "gate12.security_txt_absent"
	ReasonSecurityTxtResolved  Reason = "gate12.reporting_channel_resolved"
	ReasonSecurityTxtExpired   Reason = "gate12.security_txt_expired"
	ReasonSecurityTxtMalformed Reason = "gate12.security_txt_malformed"
	ReasonSecurityTxtUnread    Reason = "gate12.security_txt_was_never_read"
)

// ---------------------------------------------------------------------------
// BOUNDS — coded constants, not config keys
// ---------------------------------------------------------------------------

// Every bound here is a plain const. A Cap exists so that CONFIGURATION may
// lower a coded floor; nothing about these is configurable in either
// direction, so a const is the stricter statement and the one that cannot be
// reached by a loader at all.
const (
	// maxRawHostBytes bounds the LITERAL host before canonicalization. It is
	// larger than the 253-byte DNS limit because percent-encoding inflates
	// (three bytes per character) and the decode has to happen before the
	// length can be judged honestly.
	//
	// It IS types.go's maxLiteralHostBytes rather than a second number equal
	// to it: NewTarget enforces the same bound on the literal it stores, and
	// two consts that must agree are two consts that will eventually not.
	maxRawHostBytes = maxLiteralHostBytes
	// maxCanonicalHostBytes is the DNS name limit.
	maxCanonicalHostBytes = 253
	// maxDNSLabelBytes is the DNS label limit.
	maxDNSLabelBytes = 63
	// maxResolvedAddresses bounds one DNS answer. A name that answers with
	// forty addresses is not a target, it is a way to make the kernel's
	// address filter the interesting part of the run.
	maxResolvedAddresses = 16
	// maxRobotsBytes bounds a fetched robots.txt.
	maxRobotsBytes = 64 << 10
	// maxRobotsRules bounds how many Disallow rules one policy may carry.
	maxRobotsRules = 1024
	// maxRobotsPatternBytes bounds one Disallow value.
	maxRobotsPatternBytes = 512
	// maxRequestPathBytes bounds a request path gate 11 judges.
	maxRequestPathBytes = 4096
	// maxSecurityTxtBytes bounds a fetched security.txt. The spine's safety section
	// puts the DAST response body at "up to 32 KB of attacker-controlled
	// bytes"; a reporting-channel document needs a small fraction of that.
	maxSecurityTxtBytes = 16 << 10
	// maxSecurityTxtLines and maxSecurityTxtValues bound the parse.
	maxSecurityTxtLines  = 512
	maxSecurityTxtValues = 32
	// maxSecurityTxtValueBytes bounds one field value.
	maxSecurityTxtValueBytes = 512
)

// ---------------------------------------------------------------------------
// GATE 8 — canonicalize BEFORE matching
// ---------------------------------------------------------------------------

// Canonicalize turns a host as written into the one form scope matching is
// performed against.
//
// # The six transformations, and why each one is a scope-bypass primitive
//
//	percent-decode      "%65xample.com" is example.com to a URL parser and is
//	                    a different string to a scope entry.
//	IDNA / A-label      a U-label and its A-label are the same host and
//	                    different bytes; so are homographs that are not.
//	case fold           "EXAMPLE.com" is example.com to DNS.
//	trailing-dot strip  "example.com." is example.com to DNS, and is a
//	                    different string to a scope entry.
//	IPv4-mapped unwrap  "::ffff:169.254.169.254" and "169.254.169.254" must
//	                    not compare differently against gate 10's ranges.
//	port normalization  is NormalizePort, below — a port is not part of a
//	                    host, and "no port" must become the scheme default
//	                    explicitly rather than being guessed at match time.
//
// # IDNA is an ALLOWLIST OF ASCII, not a mapping table
//
// This build does not implement IDNA/UTS-46 inside the authorization kernel.
// Gate 2's import allowlist (phase0_build.go) admits the standard library and
// internal/record only, so golang.org/x/net/idna is not reachable — and that
// is the right answer rather than an inconvenience: a Unicode mapping table
// with context-dependent rules is a large amount of parsing surface inside the
// one component that must not be surprising.
//
// So a host containing any byte outside printable ASCII is REFUSED, with a
// message telling the operator to supply the A-label. An A-label ("xn--...")
// is already ASCII and passes through as itself. The consequence, stated
// plainly: Anvil cannot be pointed at a target by its U-label. It can be
// pointed at exactly the same host by its A-label, and the A-label is what a
// scope file has to contain anyway, because ScopeEntry.Validate rejects a host
// that is not already canonical.
//
// # IPv6 literals are refused, and that is the kernel core's contract rather than a choice
//
// NewTarget rejects a canonical host containing ':' (types.go), so an IPv6
// literal cannot be carried in a Target at all. Canonicalize therefore refuses
// one here, where the message can say why, instead of letting it fail three
// layers down as "malformed canonical host". An IPv4-mapped IPv6 literal is
// NOT refused: it is unwrapped, because the unwrapped form is expressible and
// because gate 10 must see 169.254.169.254 when it is written
// "[::ffff:169.254.169.254]". Targets reachable only over IPv6 are named by
// hostname; the PINNED address may be IPv6 and gate 10 judges it as such.
func Canonicalize(raw string) (string, error) {
	if raw == "" {
		return "", canonRefuse(ReasonHostEmpty, "the host is empty. Gate 8 matches on the "+
			"canonical form and there is nothing here to canonicalize")
	}
	if len(raw) > maxRawHostBytes {
		return "", canonRefuse(ReasonHostTooLong, "the host is %d bytes and the coded bound "+
			"is %d. A hostname cannot exceed %d bytes once canonical, and a literal far "+
			"larger than that is a payload rather than a name", len(raw),
			maxRawHostBytes, maxCanonicalHostBytes)
	}

	// FIVE OF THE REFUSALS BELOW WOULD BE CAUGHT BY A LATER ONE IF THEY WERE
	// DELETED. The label-charset allowlist at step 7 refuses every byte that is
	// not [a-z0-9_.-], and the length bounds refuse anything oversized, so a
	// surviving '%', a truncated escape, a non-ASCII byte, an over-long literal
	// and an unbalanced bracket would each still be REFUSED by the general
	// checks. Mutation-testing each one against a suite that asserted only "this
	// is refused" left the suite green.
	//
	// What deleting one actually costs is the ATTRIBUTION: every refusal here
	// carries a distinct gateNN.slug token, which is a bounded, validated value
	// that reaches gate 21's audit log and can be counted and alerted on, unlike
	// the offending host itself (untrusted input, the spine's record section). An
	// operator reading "gate08.host_double_percent_encoded" learns something
	// that "gate08.host_has_a_character_outside_the_allowlist" does not tell
	// them. TestCanonicalizeRefusalsAreDistinctlyAttributed asserts the token
	// each one produces, so deleting any of the five turns the suite red.
	// 1. Percent-decode ONCE, then refuse any '%' that survives.
	//
	// Decoding repeatedly until the result stops changing is the bug: "%2525"
	// becomes "%25" becomes "%", and the number of rounds an attacker needs is
	// the number of rounds the loop is willing to run. One round, then refuse,
	// has no such parameter.
	s, err := percentDecodeOnce(raw)
	if err != nil {
		return "", canonRefuse(ReasonHostPercentEncoding, "the host contains a %q that is "+
			"not followed by two hexadecimal digits, so it is neither a literal host "+
			"nor a percent-encoded one", "%")
	}
	if strings.Contains(s, "%") {
		return "", canonRefuse(ReasonHostDoublePercent, "the host is doubly percent-encoded "+
			"— one round of decoding produced another %q. Gate 8 decodes exactly once and "+
			"refuses what is left, because a decoder that loops until the input stops "+
			"changing can always be given one more layer", "%")
	}

	// 2. Bracketed IPv6 form, "[...]". Handled before the charset allowlist
	//    because brackets and colons are not in it.
	if strings.HasPrefix(s, "[") || strings.HasSuffix(s, "]") {
		if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") || len(s) < 3 {
			return "", canonRefuse(ReasonHostBracketMalformed,
				"the host has an unbalanced %q or %q", "[", "]")
		}
		inner := s[1 : len(s)-1]
		addr, perr := netip.ParseAddr(inner)
		if perr != nil {
			return "", canonRefuse(ReasonHostBracketMalformed, "the host is bracketed, which "+
				"is the URL syntax for an IPv6 literal, and what is inside the brackets "+
				"is not an address")
		}
		s = addr.String()
	}

	// 3. ASCII only. Everything after this point may assume one byte is one
	//    character.
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return "", canonRefuse(ReasonHostNotASCII, "the host has a byte at offset %d that "+
				"is not printable ASCII. This build does not implement IDNA/UTS-46 inside "+
				"the authorization kernel (gate 2 admits the standard library and "+
				"internal/record only); supply the A-label — the \"xn--\" form — which "+
				"is what a scope file has to contain in any case", i)
		}
	}

	// 4. Case fold. ASCII-only by construction after step 3, so this is the
	//    same answer strings.ToLower gives and says what it means.
	s = asciiFold(s)

	// 5. Trailing-dot strip. Exactly one: "example.com." names the same host
	//    as "example.com", and "example.com.." has an empty label and does
	//    not.
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", canonRefuse(ReasonHostEmpty,
			"the host was nothing but the root label")
	}

	// 6. Address literals. An IPv4 literal canonicalizes to its dotted quad;
	//    an IPv4-mapped IPv6 literal UNWRAPS to the same dotted quad, so that
	//    "::ffff:169.254.169.254" and "169.254.169.254" cannot compare
	//    differently against gate 10's reserved ranges; any other IPv6 literal
	//    is refused because the kernel core's Target cannot carry one.
	if addr, perr := netip.ParseAddr(s); perr == nil {
		unmapped := addr.Unmap()
		if unmapped.Is6() {
			return "", canonRefuse(ReasonHostIPv6Literal, "the host is an IPv6 literal. A "+
				"Target's canonical host may not contain %q (types.go, NewTarget), so "+
				"an IPv6 literal cannot be carried through the kernel; name the target "+
				"by hostname. The address a hostname RESOLVES to may be IPv6, and gate "+
				"10 judges it as such", ":")
		}
		return unmapped.String(), nil
	}

	// 7. Hostname shape: an allowlisted charset and well-formed DNS labels.
	//    An allowlist rather than a denylist of dangerous characters, for the
	//    reason stated throughout this package: a denylist has to anticipate
	//    every delimiter a URL parser somewhere treats as significant
	//    ("@", "\\", "?", "#", ":", "/"), and an allowlist has to anticipate
	//    nothing.
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if label == "" {
			return "", canonRefuse(ReasonHostLabel, "the host has an empty DNS label")
		}
		if len(label) > maxDNSLabelBytes {
			return "", canonRefuse(ReasonHostLabel, "a DNS label is %d bytes and the limit "+
				"is %d", len(label), maxDNSLabelBytes)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", canonRefuse(ReasonHostLabel,
				"a DNS label starts or ends with %q", "-")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return "", canonRefuse(ReasonHostCharset, "the host has a byte at label offset "+
					"%d that is not in the allowed set [a-z0-9_-]. The set is an "+
					"allowlist: a denylist of the characters a URL parser treats as "+
					"delimiters would have to anticipate every parser", i)
			}
		}
	}

	// The final label may not be all digits. RFC 1123 section 2.1 says so, and
	// the reason is exactly gate 8's: "0177.0.0.1", "2130706433" and
	// "0x7f.0.0.1" are hostnames to a strict parser and are 127.0.0.1 to a
	// permissive resolver. netip.ParseAddr refuses all three at step 6 — it
	// rejects leading zeros and non-decimal forms — so without this rule they
	// would fall through to a DNS lookup that the platform resolver may well
	// answer with a loopback address.
	last := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", canonRefuse(ReasonHostNumericTLD, "the host's final label is entirely "+
			"digits. RFC 1123 section 2.1 forbids an all-numeric top-level label "+
			"precisely so that a hostname cannot be confused with an address; "+
			"\"0177.0.0.1\" and \"2130706433\" are the forms this refuses")
	}

	if len(s) > maxCanonicalHostBytes {
		return "", canonRefuse(ReasonHostTooLong, "the canonical host is %d bytes and the "+
			"DNS name limit is %d", len(s), maxCanonicalHostBytes)
	}
	return s, nil
}

// canonRefuse mints Canonicalize's typed refusal.
//
// It returns the kernel core's *GateFailure rather than a bare fmt.Errorf, so that the
// SPECIFIC canonicalization failure survives as a validated gateNN.slug token
// all the way to the audit row. That matters because the one thing gate 8 must
// NOT put in the audit is the offending host: it is `anvil/trust: untrusted`
// input (the spine's record section) and, per the spine's safety section, the
// response-body class of bytes is what must never reach a message an agent will
// read. A token can say what went wrong without carrying any of it.
//
// Every Detail assembled here is Anvil-authored and interpolates only lengths,
// offsets and literal punctuation — never a byte of the input.
func canonRefuse(r Reason, format string, args ...any) error {
	return &GateFailure{
		Gate:   Gate8Canonicalize,
		Reason: r,
		Detail: "canonicalize: " + fmt.Sprintf(format, args...),
		Err:    ErrRefused,
	}
}

// gate8ReasonOf recovers the specific token from a Canonicalize error, falling
// back to ReasonCanonicalizeFailed for an error this package did not mint.
//
// The fallback is the fail-closed direction: an unrecognised error still
// produces a valid gate-8 refusal token, so the audit row is writable and the
// decision is a refusal, rather than the row failing validation and the
// refusal turning into a gate-21 error about the audit.
func gate8ReasonOf(err error) Reason {
	var gf *GateFailure
	if errors.As(err, &gf) && gf != nil {
		if named, nerr := gf.Reason.Gate(); nerr == nil && named == Gate8Canonicalize {
			return gf.Reason
		}
	}
	return ReasonCanonicalizeFailed
}

// percentDecodeOnce decodes one round of percent-encoding, refusing a '%' that
// is not followed by two hexadecimal digits.
func percentDecodeOnce(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", errors.New("truncated percent-escape")
		}
		hi, ok1 := hexNibble(s[i+1])
		lo, ok2 := hexNibble(s[i+2])
		if !ok1 || !ok2 {
			return "", errors.New("percent-escape is not two hex digits")
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// asciiFold lowercases ASCII and leaves every other byte alone. Callers reach
// it only after Canonicalize has refused non-ASCII, so "leaves every other
// byte alone" is not a behaviour anything depends on — it is written this way
// so that the function cannot itself introduce a Unicode case-folding surprise
// (the Turkish dotless i, the Kelvin sign) into a hostname comparison.
func asciiFold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// foldAndStrip is the ONLY divergence between a literal host and its canonical
// form that gate 8 tolerates.
//
// plan/design/dynamic-tier.md gate 8's fail-closed behaviour is "Reject if canonical form
// diverges from literal form unexpectedly; log both". This function is what
// "unexpectedly" means, made decidable: a scope author who wrote
// "www.example.com" anticipated that "WWW.Example.com." would match it, and
// did not anticipate that "%77ww.example.com" would. So case folding and the
// trailing dot are expected; percent-decoding, bracket-unwrapping and
// IPv4-mapped unwrapping are not, and a target whose canonical form required
// any of them is refused rather than silently admitted under a name its author
// never wrote.
func foldAndStrip(literal string) string {
	return asciiFold(strings.TrimSuffix(literal, "."))
}

// DefaultPortFor returns the scheme's default port. There is no third answer
// and no configuration: an unset scheme has no default, it has an error.
func DefaultPortFor(s Scheme) (uint16, error) {
	switch s {
	case SchemeHTTP:
		return 80, nil
	case SchemeHTTPS:
		return 443, nil
	}
	return 0, fmt.Errorf("port: %w: %q is not a permitted scheme; the only two are %q and %q",
		ErrRefused, string(s), SchemeHTTP, SchemeHTTPS)
}

// NormalizePort turns the port as written into the explicit port scope
// matching uses.
//
// An ABSENT port becomes the scheme default, which is the whole of "port
// normalization": it moves the guess out of the matcher, where it would have
// to be made again on every comparison, and into one place that can be tested.
//
// It does not repair its input. "443 ", "0443" and "+443" are all refused,
// because a port that needed repairing was not a port — and "0443" in
// particular is the same octal-versus-decimal ambiguity Canonicalize refuses
// in an address literal.
func NormalizePort(scheme Scheme, raw string) (uint16, error) {
	if !scheme.Valid() {
		return 0, fmt.Errorf("port: %w: %q is not a permitted scheme, so it has no default "+
			"port to normalize an absent one to", ErrRefused, string(scheme))
	}
	if raw == "" {
		return DefaultPortFor(scheme)
	}
	if len(raw) > 5 {
		return 0, fmt.Errorf("port: %w: the port is %d characters; no TCP port is",
			ErrRefused, len(raw))
	}
	if raw[0] == '0' {
		return 0, fmt.Errorf("port: %w: the port has a leading zero. It is refused rather "+
			"than read as decimal, because a leading zero is octal to some parsers and "+
			"decimal to others and the two disagree about what was authorized", ErrRefused)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, fmt.Errorf("port: %w: the port has a byte at offset %d that is not a "+
				"digit", ErrRefused, i)
		}
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port: %w: the port is not in 1..65535", ErrRefused)
	}
	return uint16(n), nil
}

// gate8Canonicalize is gate 8 in the admission chain: the Target's canonical
// field IS the canonical form of its literal, and the divergence between the
// two is one a scope author would have anticipated.
//
// # Why it re-runs Canonicalize rather than trusting the Target
//
// NewTarget's canonical-form checks are a floor — uppercase, trailing dot,
// embedded delimiters — and they cannot tell whether the canonical field is
// the canonicalization OF THIS LITERAL or of something else entirely. A Target
// built with literal "evil.example.net" and canonical "www.example.com" passes
// every one of them. This gate closes that by computing the answer again and
// comparing, which is the only check that can.
//
// # It is also the bound on Target.literal
//
// The kernel-types review observed that Target.literal is unbounded and unvalidated, that
// every gate can read it back through Target.Literal(), and that
// the spine's safety section names the response body as "up to 32 KB of
// attacker-controlled bytes". Canonicalize bounds the literal at
// maxRawHostBytes and refuses every byte outside printable ASCII, so a Target
// carrying a 40 KB literal does not reach gate 9 — it is refused here. That
// does not repair NewTarget, which is in the kernel core's write scope and still accepts
// such a value; it means the ADMISSION PATH does not.
func gate8Canonicalize(target Target, _ Scope, _ Attestation, _ Clock) Ruling {
	if !target.Constructed() {
		return refuse(Gate8Canonicalize, ReasonTargetUnconstructed,
			"gate 8 was handed a Target that NewTarget never built, so it carries no "+
				"canonical form to check and no pinned address for gate 9 to judge")
	}
	if !target.Scheme().Valid() {
		return refuse(Gate8Canonicalize, ReasonSchemeUnknown,
			"the target names no permitted scheme. The allowlist is http and https; a "+
				"scheme nobody enumerated is not a weaker scheme, it is no scheme")
	}
	canon, err := Canonicalize(target.Literal())
	if err != nil {
		return refuse(Gate8Canonicalize, gate8ReasonOf(err),
			"the target's literal host cannot be canonicalized, so there is no form to "+
				"match it against scope with. The offending value is not reproduced here: a "+
				"target literal is `anvil/trust: untrusted` input")
	}
	if canon != target.Canonical() {
		return refuse(Gate8Canonicalize, ReasonCanonicalMismatch,
			"the Target's canonical field is not what canonicalizing its literal host "+
				"produces. Gate 8 recomputes rather than trusting the field, because a "+
				"Target whose canonical form was filled in by someone other than gate 8 is "+
				"a target matched against scope under a name its literal does not have")
	}
	if expected := foldAndStrip(target.Literal()); expected != canon {
		return refuse(Gate8Canonicalize, ReasonCanonicalDivergence,
			"the canonical form diverges from the literal form by more than case folding "+
				"and a trailing dot. Percent-encoding, bracketed address syntax and "+
				"IPv4-mapped IPv6 form all name a host that the scope author did not "+
				"write, and plan/design/dynamic-tier.md gate 8 refuses a divergence the author would "+
				"not have anticipated. Write the target the way the scope file spells it")
	}
	return permit(Gate8Canonicalize, ReasonTargetCanonicalAndPinned,
		"the target's canonical host is the canonicalization of its literal host, and the "+
			"two differ by at most case and a trailing dot")
}

// ---------------------------------------------------------------------------
// GATE 9 — resolve in the kernel, pin, and connect only to the pinned address
// ---------------------------------------------------------------------------

// The typed refusals resolveAndPinWith produces, so that PinTarget can pick a
// Reason from an error rather than by matching on message text.
var (
	errResolverMissing  = fmt.Errorf("%w: no resolver was supplied", ErrRefused)
	errResolveFailed    = fmt.Errorf("%w: dns resolution failed", ErrRefused)
	errResolveEmpty     = fmt.Errorf("%w: dns returned no addresses", ErrRefused)
	errResolveTooMany   = fmt.Errorf("%w: dns returned too many addresses", ErrRefused)
	errPinNotUnicast    = fmt.Errorf("%w: the address is not a connectable unicast address", ErrRefused)
	errPinReservedRange = fmt.Errorf("%w: the address is in a compiled-in reserved range", ErrRefused)
)

// lookupFunc is the DNS seam.
//
// It is an UNEXPORTED function type, so no package outside internal/dast/authz
// can supply a resolver — there is no exported symbol that takes one. The seam
// exists for the same reason decideWith's does: this package's own tests must
// be able to drive a rebinding fixture, and a test that needs a live DNS
// server is a test that does not run.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// systemLookup is the real resolver. It is the only DNS call in Anvil, and it
// is here rather than in the engine because gate 9 requires the kernel — not
// its caller — to be the thing that resolves.
func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ResolveAndPin resolves a canonical host inside the kernel and returns THE ONE
// ADDRESS the run is pinned to.
//
// # This function is the whole of the rebinding defence
//
// research/20 gate 9: "Pin the resolved address and connect to the pinned
// address — never re-resolve between check and connect. This closes DNS
// rebinding and TOCTOU." The mechanism is that the returned address goes into
// the Target, the Target goes into the audit row and into the Authorization,
// and PinnedDialAddress hands the egress layer a netip.AddrPort. A hostname
// never leaves this function, so there is nothing downstream that COULD
// re-resolve.
//
// # Every address in the answer is judged, not just the one that gets pinned
//
// A name that answers with one public address and one 169.254.x address is a
// rebinding fixture with the round trip removed: pick either one and the
// attacker re-orders the answer next time. So in `external` mode a single
// reserved address anywhere in the answer refuses the whole target, and the
// address that does get pinned is chosen deterministically (sorted) rather
// than by answer order, which is attacker-controlled.
//
// It returns netip.Addr rather than the net.IP in per-target admission's design
// expected-output line, because Target.pinned is a netip.Addr (the kernel core, types.go)
// and a second address type in the kernel is a second set of comparison rules —
// net.IP compares 4-byte and 16-byte forms of one address as different bytes,
// which is the exact failure the IPv4-mapped unwrap exists to prevent.
func ResolveAndPin(ctx context.Context, canonicalHost string, mode Mode) (netip.Addr, error) {
	return resolveAndPinWith(ctx, systemLookup, canonicalHost, mode)
}

// resolveAndPinWith is ResolveAndPin with the resolver supplied.
func resolveAndPinWith(ctx context.Context, lookup lookupFunc, canonicalHost string, mode Mode) (netip.Addr, error) {
	if lookup == nil {
		return netip.Addr{}, fmt.Errorf("resolve: %w: no resolver. Gate 9 requires the KERNEL "+
			"to resolve; a nil resolver is not 'resolve elsewhere', it is a refusal",
			errResolverMissing)
	}
	if !mode.Valid() {
		return netip.Addr{}, fmt.Errorf("resolve: %w: no mode was declared. Whether a reserved "+
			"address may be pinned at all depends on the run's mode (gate 10), and gate 6 "+
			"has no default and no `auto`", ErrRefused)
	}
	canon, err := Canonicalize(canonicalHost)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve: %w", err)
	}
	if canon != canonicalHost {
		return netip.Addr{}, fmt.Errorf("resolve: %w: the host handed to gate 9 is not "+
			"canonical. Gate 8 runs BEFORE gate 9 for a reason: resolving the literal form "+
			"would pin the address of a name that was never matched against scope", ErrRefused)
	}

	// An address literal resolves to itself. No DNS, and therefore no window
	// in which the answer could change.
	if addr, perr := netip.ParseAddr(canon); perr == nil {
		pinned := addr.Unmap()
		if err := checkPinnable(pinned, mode); err != nil {
			return netip.Addr{}, err
		}
		return pinned, nil
	}

	addrs, err := lookup(ctx, canon)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", errResolveFailed, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: the name answered with an empty address set, "+
			"which is not 'connect anyway'", errResolveEmpty)
	}
	if len(addrs) > maxResolvedAddresses {
		return netip.Addr{}, fmt.Errorf("%w: %d addresses, and the coded bound is %d",
			errResolveTooMany, len(addrs), maxResolvedAddresses)
	}

	candidates := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		pinned := a.Unmap()
		if !pinned.IsValid() {
			return netip.Addr{}, fmt.Errorf("%w: the answer contains an invalid address",
				errPinNotUnicast)
		}
		if err := checkPinnable(pinned, mode); err != nil {
			return netip.Addr{}, fmt.Errorf("%w (one address in the answer refuses the whole "+
				"answer: an answer mixing a routable address with a reserved one is a "+
				"rebinding fixture with the round trip removed)", err)
		}
		candidates = append(candidates, pinned)
	}
	slices.SortFunc(candidates, func(x, y netip.Addr) int { return x.Compare(y) })
	return candidates[0], nil
}

// checkPinnable is the address filter ResolveAndPin applies to EVERY address
// in an answer.
//
// It is deliberately NOT gate 10. Gate 10 is the authority on reserved ranges
// and it is the gate whose ruling reaches the audit log; this is the earlier,
// cheaper refusal that stops a reserved address from ever being pinned into a
// Target in `external` mode. In `lab` mode it defers on reserved ranges,
// because gate 10 permits them there for addresses explicitly enumerated in
// scope and this function cannot see the scope.
//
// The two refusals it makes in BOTH modes are structural rather than
// policy: the unspecified address (0.0.0.0, ::) is "whatever this host is",
// which on most stacks connects to loopback, and a multicast address is not a
// host at all. Neither is a target that a lab scope could sensibly enumerate.
func checkPinnable(addr netip.Addr, mode Mode) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: the address is not an address", errPinNotUnicast)
	}
	if addr.IsUnspecified() {
		return fmt.Errorf("%w: %s is the unspecified address, which names \"whatever this "+
			"machine is\" and connects to loopback on most stacks", errPinNotUnicast, addr)
	}
	if addr.IsMulticast() {
		return fmt.Errorf("%w: %s is a multicast address, which is a group rather than a host",
			errPinNotUnicast, addr)
	}
	if mode == ModeExternal {
		if why, reserved := AddressIsReserved(addr); reserved {
			return fmt.Errorf("%w: %s — %s", errPinReservedRange, addr, why)
		}
	}
	return nil
}

// PinTarget is gates 8 and 9 as one call: canonicalize the literal host,
// normalize the port, resolve inside the kernel, pin one address, and build the
// Target the rest of the kernel decides about.
//
// It DECIDES NOTHING. A Target it returns is a well-formed question, not an
// answer: admission is Adjudicate's, and the socket is
// RequireAuthorization's.
func PinTarget(ctx context.Context, scheme Scheme, literalHost, rawPort string, mode Mode) (Target, GateResult) {
	return pinTargetWith(ctx, systemLookup, scheme, literalHost, rawPort, mode)
}

// pinTargetWith is PinTarget with the resolver supplied. See lookupFunc.
func pinTargetWith(ctx context.Context, lookup lookupFunc, scheme Scheme, literalHost, rawPort string, mode Mode) (Target, GateResult) {
	if !scheme.Valid() {
		return Target{}, gateFailed(Gate8Canonicalize, ReasonSchemeUnknown,
			"the target names no permitted scheme. The allowlist is http and https.",
			"scheme as written: "+redactUntrusted(string(scheme)))
	}
	canon, err := Canonicalize(literalHost)
	if err != nil {
		return Target{}, gateFailed(Gate8Canonicalize, gate8ReasonOf(err),
			"the host cannot be canonicalized, so there is no form to match it against scope "+
				"with. Gate 8 canonicalizes BEFORE matching; a host that will not "+
				"canonicalize is refused rather than matched as written.",
			"host as written: "+redactUntrusted(literalHost))
	}
	if expected := foldAndStrip(literalHost); expected != canon {
		return Target{}, gateFailed(Gate8Canonicalize, ReasonCanonicalDivergence,
			"the canonical form diverges from the literal form by more than case folding and "+
				"a trailing dot. plan/design/dynamic-tier.md gate 8: reject if the canonical form "+
				"diverges from the literal form unexpectedly, and log both.",
			"literal:   "+redactUntrusted(literalHost),
			"canonical: "+redactUntrusted(canon))
	}
	port, err := NormalizePort(scheme, rawPort)
	if err != nil {
		return Target{}, gateFailed(Gate8Canonicalize, ReasonPortNotNormalizable,
			"the port is not a port. Gate 8 normalizes an absent port into the scheme default "+
				"explicitly so that scope matching never has to guess, and it does not "+
				"repair a malformed one.",
			"port as written: "+redactUntrusted(rawPort))
	}

	pinned, err := resolveAndPinWith(ctx, lookup, canon, mode)
	if err != nil {
		reason := ReasonResolutionFailed
		detail := "the kernel could not resolve this host to an address it will connect to."
		switch {
		case errors.Is(err, errResolverMissing):
			reason = ReasonResolverMissing
			detail = "no resolver was supplied to the kernel. Gate 9 requires the KERNEL " +
				"to resolve, and a nil resolver is not an instruction to resolve " +
				"somewhere else."
		case errors.Is(err, errResolveEmpty):
			reason = ReasonResolutionEmpty
			detail = "the name resolved to no addresses. An empty answer is not permission " +
				"to connect to the name."
		case errors.Is(err, errResolveTooMany):
			reason = ReasonResolutionTooManyAddrs
			detail = "the name answered with more addresses than the coded bound."
		case errors.Is(err, errPinReservedRange):
			reason = ReasonReservedRangeExternal
			detail = "the name resolves to an address in a compiled-in reserved range and " +
				"this run is in `external` mode. The list is a constant in the kernel, " +
				"not a config key."
		case errors.Is(err, errPinNotUnicast):
			reason = ReasonPinNotUnicast
			detail = "the name resolves to an address that is not a connectable unicast " +
				"host."
		}
		g := Gate9ResolveAndPin
		if reason == ReasonReservedRangeExternal {
			g = Gate10ReservedRanges
		}
		return Target{}, gateFailed(g, reason, detail,
			"host: "+redactUntrusted(canon),
			"mode: "+redactUntrusted(string(mode)))
	}

	tgt, err := NewTarget(scheme, literalHost, canon, port, pinned)
	if err != nil {
		return Target{}, gateFailed(Gate9ResolveAndPin, ReasonPinDisagreesWithHost,
			"the kernel canonicalized and pinned this target and its own Target constructor "+
				"still refused the result. That is a disagreement between gate 8's "+
				"canonical form and the kernel core's floor, and it refuses rather than being "+
				"reconciled.",
			"host: "+redactUntrusted(canon))
	}
	return tgt, gatePassed(Gate9ResolveAndPin)
}

// PinnedDialAddress is the ONLY address the egress layer may connect to, and
// the reason gate 9's "never re-resolve between check and connect" is a
// structure rather than a discipline.
//
// It returns a netip.AddrPort. There is no hostname in the return type, so
// there is nothing for a caller to hand to a resolver: a dialer built on this
// value CANNOT re-resolve, because it was never given a name. That is the
// whole mechanism.
//
// It calls RequireAuthorization first, so the address it hands back is one
// that a Decision minted an Authorization for, against this exact target,
// pinned address included.
//
// The socket itself is not constructed here. The kernel core's design forbidden
// actions are explicit — "No net.Dial, http.Client, or any socket-construction
// call anywhere in this package (that is Phase 3's job, gated)" — so Phase 2
// produces the address and per-request enforcement's request layer opens the connection to it.
func PinnedDialAddress(auth Authorization, target Target) (netip.AddrPort, error) {
	if err := RequireAuthorization(auth, target); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(target.Pinned(), target.Port()), nil
}

// gate9ResolveAndPin is gate 9 in the admission chain.
//
// # What it does NOT do, and why that is the point
//
// It does not resolve. Resolving here would be the second resolution of this
// name — the first produced the pinned address inside the Target — and a
// second resolution is by definition a check that can disagree with the
// connect. research/20 names the class: "never re-resolve between check and
// connect". So this gate judges the address ALREADY PINNED, and the only way
// an address gets pinned is ResolveAndPin.
func gate9ResolveAndPin(target Target, scope Scope, _ Attestation, _ Clock) Ruling {
	if !target.Constructed() {
		return refuse(Gate9ResolveAndPin, ReasonPinTargetUnbuilt,
			"gate 9 was handed a Target that NewTarget never built, so it carries no pinned "+
				"address")
	}
	if !scope.Constructed() {
		return refuse(Gate9ResolveAndPin, ReasonPinScopeUnconstructed,
			"gate 9 has no scope to match the pinned address against. research/20 gate 9: "+
				"hostname-in-scope is necessary but not sufficient, and with no scope at "+
				"all neither half holds")
	}
	pinned := target.Pinned().Unmap()
	if pinned.IsUnspecified() {
		return refuse(Gate9ResolveAndPin, ReasonPinUnspecified,
			"the pinned address is the unspecified address. It names \"whatever this machine "+
				"is\" rather than a destination, and on most stacks a connection to it "+
				"lands on loopback — so it is refused in `lab` as well as `external`, and "+
				"no scope entry enumerates it")
	}
	if pinned.IsMulticast() {
		return refuse(Gate9ResolveAndPin, ReasonPinNotUnicast,
			"the pinned address is multicast. A multicast group is not a host, in either "+
				"mode, whatever the scope file says")
	}

	// If the target is named by an address literal, the pin must be that
	// address. A Target reading "127.0.0.1 pinned to 93.184.216.34" — or the
	// reverse — is a target whose name and destination disagree, and gates 4
	// and 10 would then be judging two different things.
	if lit, err := netip.ParseAddr(target.Canonical()); err == nil {
		if lit.Unmap() != pinned {
			return refuse(Gate9ResolveAndPin, ReasonPinDisagreesWithHost,
				"the target is named by an address literal and the pinned address is a "+
					"different address. Gate 4 matches scope against the name and gate 10 "+
					"judges the pin; when they disagree the two gates are deciding about "+
					"different hosts")
		}
	}

	// The resolved address is matched against scope too — in the DENY
	// direction only.
	//
	// research/20 gate 9 asks for the resolved address to be "in an allowed
	// CIDR", and the kernel core's ScopeEntry carries hosts and ports and no CIDR, so the
	// allow half of that sentence is not expressible against this contract
	// (reported to the orchestrator rather than approximated). The deny half
	// is: a scope that names an address on its deny list denies every hostname
	// that resolves to it. That direction only ever REMOVES reach, so
	// implementing half of the requirement cannot accidentally grant any.
	//
	// THERE IS DELIBERATELY NO `if e.Validate() != nil { continue }` HERE, and
	// no wildcard skip either. Both would be the wrong direction on a DENY
	// list: skipping an entry this package considers malformed is how a deny
	// entry silently stops existing, which is exactly the shape the kernel-types review
	// demonstrated by mutating a deny entry's Ports through the live backing
	// array that DenyEntries hands out. An entry naming this address on this
	// port denies it whether or not the entry is otherwise well formed, and
	// TestGate9DenyEntriesAreNotSkippedForBeingMalformed is the tripwire that
	// fails if someone adds the skip back. A wildcard skip would be dead code
	// for a different reason: the comparison below is exact string equality
	// and an address literal never contains '*'.
	for _, e := range scope.DenyEntries() {
		// This walk never WRITES to e.Ports, for the reason just given.
		if e.Host == pinned.String() && portIn(e.Ports, target.Port()) {
			return refuse(Gate9ResolveAndPin, ReasonPinDeniedByScope,
				"the scope file's deny list names the address this host resolves to. Deny "+
					"beats allow unconditionally, and it beats it at the address level as "+
					"well as the name level — otherwise any name pointed at a denied "+
					"address would reach it")
		}
	}

	return permit(Gate9ResolveAndPin, ReasonPinnedAndMatched,
		"the target carries one address, pinned by the kernel's own resolver, that is a "+
			"connectable unicast address, agrees with the host when the host is a literal, "+
			"and is on no deny list. The connection is made to this address and to no "+
			"fresh resolution")
}

func portIn(ports []uint16, want uint16) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GATE 10 — the reserved-range denylist, compiled in
// ---------------------------------------------------------------------------

// The reserved ranges, as untyped string CONSTANTS.
//
// Per-target admission's forbidden actions: "The reserved-range denylist (gate
// 10) must be an unexported Go `const`/package-level slice with no
// config-loader path that can append, remove, or shadow an entry." A const is
// the strongest form Go offers — it cannot be reassigned at run time by any
// code, in this package or elsewhere, and it cannot be addressed, so nothing
// can hold a pointer to it either. reservedRanges() parses them into a FRESH
// slice on every call, so no caller can retain and mutate the list.
//
// THIS IS A DENYLIST, AND THAT IS A DELIBERATE EXCEPTION TO THIS PROJECT'S
// RULE THAT A DENYLIST LOSES. The rule holds where an allowlist is expressible;
// here it is not, because the complement of "reserved" is "every routable
// address on the internet" and Anvil cannot enumerate that. The residual risk
// is stated rather than papered over: a range that IANA reserves after this
// list was written arrives PERMITTED in `external` mode. Two things reduce it —
// AddressIsReserved consults the Go runtime's own classification as a second,
// independent layer (so a new private or link-local assignment that the
// runtime learns about is caught without an edit here), and gate 4's scope file
// is an allowlist that must independently name the host. Neither closes it.
const (
	reservedIPv4ThisNetwork = "0.0.0.0/8"      // RFC 1122 "this network"; 0.0.0.0 reaches loopback on most stacks.
	reservedIPv4Private10   = "10.0.0.0/8"     // RFC 1918.
	reservedIPv4CGNAT       = "100.64.0.0/10"  // RFC 6598 carrier-grade NAT.
	reservedIPv4Loopback    = "127.0.0.0/8"    // RFC 1122 loopback.
	reservedIPv4LinkLocal   = "169.254.0.0/16" // RFC 3927 link-local, and 169.254.169.254 cloud metadata.
	reservedIPv4Private172  = "172.16.0.0/12"  // RFC 1918.
	reservedIPv4Protocol    = "192.0.0.0/24"   // RFC 6890 IETF protocol assignments, incl. 192.0.0.170 NAT64 discovery.
	reservedIPv4Private192  = "192.168.0.0/16" // RFC 1918.
	reservedIPv4Benchmark   = "198.18.0.0/15"  // RFC 2544 benchmarking.
	reservedIPv4Multicast   = "224.0.0.0/4"    // RFC 5771 multicast.
	reservedIPv4Future      = "240.0.0.0/4"    // RFC 1112 reserved, incl. 255.255.255.255 broadcast.
	reservedIPv6Unspecified = "::/128"         // RFC 4291 unspecified.
	reservedIPv6Loopback    = "::1/128"        // RFC 4291 loopback.
	reservedIPv6NAT64       = "64:ff9b::/96"   // RFC 6052 — embeds an IPv4 address, so it is an IPv4 range in disguise.
	reservedIPv6NAT64Local  = "64:ff9b:1::/48" // RFC 8215 local-use NAT64, same reasoning.
	reservedIPv6SixToFour   = "2002::/16"      // RFC 3056 6to4 — embeds an IPv4 address, same reasoning.
	reservedIPv6ULA         = "fc00::/7"       // RFC 4193 unique local.
	reservedIPv6LinkLocal   = "fe80::/10"      // RFC 4291 link-local.
	reservedIPv6Multicast   = "ff00::/8"       // RFC 4291 multicast.
)

// reservedRange is one entry: the prefix, and the Anvil-authored sentence that
// appears in the refusal. The "why" is a field rather than a comment because it
// is printed to the operator, and a denylist whose entries cannot explain
// themselves becomes a list nobody dares to shorten.
type reservedRange struct {
	prefix netip.Prefix
	why    string
}

// reservedRanges parses the compiled-in constants into a fresh slice.
//
// It is a FUNCTION rather than a package-level var for the reason
// DefaultTriggerPolicy is (phase1_run.go): a var is assignable from anywhere in
// the package, and "the denylist was empty at the moment gate 10 ran" is a
// state that must not be reachable. It uses MustParsePrefix, which panics: a
// malformed compiled-in constant is a build defect, the panic fires at the
// first gate-10 evaluation in every test binary that links this package, and
// there is no correct way to continue with a denylist that did not assemble.
func reservedRanges() []reservedRange {
	return []reservedRange{
		{netip.MustParsePrefix(reservedIPv4ThisNetwork), "0.0.0.0/8 is \"this network\" (RFC 1122); a connection to it lands on loopback on most stacks"},
		{netip.MustParsePrefix(reservedIPv4Private10), "10.0.0.0/8 is RFC 1918 private space — the operator's own network, not a target"},
		{netip.MustParsePrefix(reservedIPv4CGNAT), "100.64.0.0/10 is RFC 6598 carrier-grade NAT space"},
		{netip.MustParsePrefix(reservedIPv4Loopback), "127.0.0.0/8 is loopback — this machine"},
		{netip.MustParsePrefix(reservedIPv4LinkLocal), "169.254.0.0/16 is link-local and contains 169.254.169.254, the cloud instance metadata endpoint that hands out credentials"},
		{netip.MustParsePrefix(reservedIPv4Private172), "172.16.0.0/12 is RFC 1918 private space"},
		{netip.MustParsePrefix(reservedIPv4Protocol), "192.0.0.0/24 is IETF protocol assignment space (RFC 6890)"},
		{netip.MustParsePrefix(reservedIPv4Private192), "192.168.0.0/16 is RFC 1918 private space"},
		{netip.MustParsePrefix(reservedIPv4Benchmark), "198.18.0.0/15 is RFC 2544 benchmarking space"},
		{netip.MustParsePrefix(reservedIPv4Multicast), "224.0.0.0/4 is multicast — a group, not a host"},
		{netip.MustParsePrefix(reservedIPv4Future), "240.0.0.0/4 is reserved (RFC 1112) and contains the broadcast address"},
		{netip.MustParsePrefix(reservedIPv6Unspecified), "::/128 is the unspecified address"},
		{netip.MustParsePrefix(reservedIPv6Loopback), "::1/128 is IPv6 loopback — this machine"},
		{netip.MustParsePrefix(reservedIPv6NAT64), "64:ff9b::/96 embeds an IPv4 address (RFC 6052 NAT64), so reaching it reaches an IPv4 destination the IPv4 ranges above would have refused"},
		{netip.MustParsePrefix(reservedIPv6NAT64Local), "64:ff9b:1::/48 is local-use NAT64 (RFC 8215) and embeds an IPv4 address"},
		{netip.MustParsePrefix(reservedIPv6SixToFour), "2002::/16 embeds an IPv4 address (RFC 3056 6to4), same reasoning as NAT64"},
		{netip.MustParsePrefix(reservedIPv6ULA), "fc00::/7 is IPv6 unique-local space (RFC 4193)"},
		{netip.MustParsePrefix(reservedIPv6LinkLocal), "fe80::/10 is IPv6 link-local (RFC 4291)"},
		{netip.MustParsePrefix(reservedIPv6Multicast), "ff00::/8 is IPv6 multicast — a group, not a host"},
	}
}

// AddressIsReserved reports whether addr is in one of the compiled-in reserved
// ranges, and the Anvil-authored sentence saying which.
//
// An INVALID address is reserved. That is the fail-closed direction and it is
// not an edge case: netip.Addr's zero value is invalid, and a zero value that
// reported "not reserved" would be a zero value that authorized something.
func AddressIsReserved(addr netip.Addr) (string, bool) {
	a := addr.Unmap()
	if !a.IsValid() {
		return "the address is not an address; an unset netip.Addr is treated as reserved, " +
			"because the alternative is a zero value that reads as \"routable\"", true
	}
	for _, r := range reservedRanges() {
		if r.prefix.Contains(a) {
			return r.why, true
		}
	}
	// The second layer: the Go runtime's own classification. It is redundant
	// against the prefix list above for every range currently listed, and it
	// is kept because it is the half that can learn about a new assignment
	// without an edit to this file. See the residual-risk note on the
	// constants.
	switch {
	case a.IsLoopback():
		return "the runtime classifies this address as loopback", true
	case a.IsPrivate():
		return "the runtime classifies this address as private (RFC 1918 / RFC 4193)", true
	case a.IsLinkLocalUnicast():
		return "the runtime classifies this address as link-local unicast", true
	case a.IsLinkLocalMulticast():
		return "the runtime classifies this address as link-local multicast", true
	case a.IsMulticast():
		return "the runtime classifies this address as multicast", true
	case a.IsUnspecified():
		return "the runtime classifies this address as unspecified", true
	}
	return "", false
}

// scopeEnumeratesAddress reports whether the scope's ALLOW list names this
// exact address as a literal, on this exact port.
//
// This is gate 10's "only for addresses explicitly enumerated in scope", and
// the word doing the work is EXPLICITLY. A wildcard entry is skipped, because
// ScopeEntry.Covers would otherwise let "*.0.0.1" cover "127.0.0.1" — the
// wildcard rule only requires that what follows "*." has at least two labels,
// which "0.0.1" does. A pattern that happens to match an address is not an
// enumeration of it.
func scopeEnumeratesAddress(scope Scope, addr netip.Addr, port uint16) bool {
	if !scope.Constructed() {
		return false
	}
	a := addr.Unmap()
	if !a.IsValid() {
		return false
	}
	literal := a.String()
	// The comparison is EXACT STRING EQUALITY and not ScopeEntry.Covers, and
	// that is the difference between "enumerated" and "matched". Covers honours
	// the wildcard rule, and "*.0.0.1" passes ScopeEntry.Validate — what
	// follows "*." has two labels — and covers "127.0.0.1". A pattern that
	// happens to match an address has not enumerated it. There is therefore no
	// explicit wildcard skip here: it would be dead code, because an address
	// literal never contains '*'.
	//
	// The Validate skip, unlike gate 9's deny walk, IS the safe direction on an
	// ALLOW list: an entry this package considers malformed must not be the
	// thing that lets a lab run reach loopback. The kernel-types review's mutation — a
	// port set to 0 through the live backing array AllowEntries hands out —
	// therefore removes reach here rather than adding it, and
	// TestGate10LabEnumerationIgnoresAMalformedAllowEntry demonstrates it.
	//
	// This walk never WRITES to e.Ports.
	for _, e := range scope.AllowEntries() {
		if e.Validate() != nil {
			continue
		}
		if e.Host == literal && portIn(e.Ports, port) {
			return true
		}
	}
	return false
}

// gate10ReservedRanges is gate 10 in the admission chain.
//
// plan/design/dynamic-tier.md gate 10: "Non-configurable reserved-range denylist in
// `external` mode... **No — a compiled constant, not a config key.** Only `lab`
// mode may reach these, only for addresses explicitly enumerated in scope."
//
// Both halves of that sentence are here. In `external` a reserved address is
// refused with no exception and no configuration. In `lab` it is refused
// UNLESS the scope file names the address itself, as a literal, on this port —
// so a lab run reaches 127.0.0.1:8080 because somebody wrote "127.0.0.1" and
// "8080" down, and reaches nothing else.
func gate10ReservedRanges(target Target, scope Scope, _ Attestation, _ Clock) Ruling {
	if !target.Constructed() {
		return refuse(Gate10ReservedRanges, ReasonReservedTargetUnbuilt,
			"gate 10 was handed a Target that NewTarget never built, so there is no pinned "+
				"address to judge")
	}
	if !scope.Constructed() {
		return refuse(Gate10ReservedRanges, ReasonReservedScopeUnconstructed,
			"gate 10 has no scope, and the scope is where the run's mode lives. Whether a "+
				"reserved address may be reached at all depends on that mode")
	}
	// There is deliberately no separate `if !mode.Valid()` branch. Scope
	// .Constructed() is true exactly when its ModeDeclaration is declared, and
	// a declared ModeDeclaration returns a valid mode — so the branch could
	// never be the only thing refusing anything, and a mutation deleting it
	// stayed green. It is gone rather than commented, the same way run initiation removed
	// two subsumed branches in phase1_run.go.
	//
	// The lab arm below is written as `mode == ModeLab` and the refusal is the
	// default arm, so the permitting path is the narrow one. That is a
	// preference about which way an unforeseen value would fall, not a control:
	// today Scope.Constructed() already guarantees the mode is one of exactly
	// two, and TestGate10RefusesWithoutATargetOrAScope records that.
	mode, _ := scope.Mode()
	pinned := target.Pinned().Unmap()
	why, reserved := AddressIsReserved(pinned)
	if !reserved {
		return permit(Gate10ReservedRanges, ReasonAddressNotReserved,
			"the pinned address is in none of the compiled-in reserved ranges")
	}

	if mode == ModeLab {
		if !scopeEnumeratesAddress(scope, pinned, target.Port()) {
			return refuse(Gate10ReservedRanges, ReasonReservedRangeNotEnumerated,
				"this run is in `lab` mode and the pinned address is in a reserved range, "+
					"which lab mode may reach ONLY for addresses explicitly enumerated in "+
					"scope. The scope file's allow list does not name this address, as a "+
					"literal, on this port. A wildcard entry that happens to match it is "+
					"not an enumeration of it: "+why)
		}
		return permit(Gate10ReservedRanges, ReasonReservedEnumeratedInLab,
			"the pinned address is in a reserved range, this run is in `lab` mode, and the "+
				"scope file enumerates this exact address on this exact port")
	}

	// The default arm. Reached for `external`, which is the only other value a
	// constructed Scope can carry.
	return refuse(Gate10ReservedRanges, ReasonReservedRangeExternal,
		"this run is not in `lab` mode and the pinned address is in a compiled-in reserved "+
			"range. There is no configuration that reaches this list — no environment "+
			"variable, no CLI flag, no config key, no model-authored value — and the scope "+
			"file's `additional_egress_allow` cannot punch through it either: that field "+
			"narrows what the scope LAYER permits within what the kernel already allows. "+
			why)
}

// ---------------------------------------------------------------------------
// GATE 11 — robots/ToS as ADDITIONAL DENIES ONLY
// ---------------------------------------------------------------------------

// RobotsDetermination records what happened when Anvil went looking for
// robots.txt.
//
// The distinction between "we looked and there was none" and "we did not
// look" is the entire reason this type exists rather than a bool.
// docs/controls.md names the shape: "a guard that vanishes
// silently when it cannot run is worse than no guard, because the green tick is
// read as an answer." A policy nobody determined permits no path.
type RobotsDetermination string

// The four determinations. Two of them permit paths; two refuse everything.
const (
	// RobotsUnset is the zero value: nobody looked. Every path is refused.
	RobotsUnset RobotsDetermination = ""
	// RobotsAbsent means the fetch completed and there is no robots.txt.
	// Nothing is removed from scope — and nothing is added to it either.
	RobotsAbsent RobotsDetermination = "absent"
	// RobotsPresent means a robots.txt was fetched and parsed.
	RobotsPresent RobotsDetermination = "present"
	// RobotsUnavailable means the fetch failed, or the document could not be
	// parsed. Every path is refused: an unreadable statement of the site's
	// wishes is not an absent one.
	RobotsUnavailable RobotsDetermination = "unavailable"
)

// RobotsPolicy is one origin's robots.txt, reduced to DENIES.
//
// # The asymmetry, which is the whole gate
//
// plan/design/dynamic-tier.md gate 11: "Robots/ToS deny signals as additional denies only.
// Restrictive `robots.txt`/no-scan statement removes paths from scope;
// permissive adds nothing. No — asymmetric by design." research/20 gives the
// reason: Van Buren fn.8 left the legal weight of non-code limits open, so a
// site's "you may" is worth nothing to Anvil and its "you may not" is worth
// everything.
//
// So this type has NO allow list. `Allow:` directives are parsed — they have to
// be, to know where a group's rules end — and then DISCARDED, and the count of
// discarded directives is kept only so that the audit can say how many were
// ignored. There is no field an Allow directive could be stored in and no
// method that would consult one.
//
// # Where this deliberately departs from RFC 9309
//
// RFC 9309 section 2.2.1 says the most specific matching user-agent group wins,
// and that a crawler MUST ignore the "*" group when a group names it. Under
// those rules a file containing
//
//	User-agent: *
//	Disallow: /
//	User-agent: anvil
//	Disallow:
//
// grants Anvil the whole site. That is a PERMISSIVE group adding reach, which
// is exactly what gate 11 says cannot happen. This implementation therefore
// takes the UNION of the Disallow rules of every group whose user-agent is "*"
// or names Anvil. The deviation is one-directional — it can only ever deny more
// than RFC 9309 would — and it is written down here rather than discovered
// later.
type RobotsPolicy struct {
	determination   RobotsDetermination
	host            string
	port            uint16
	disallow        []string
	hostFullyDenied bool
	allowsIgnored   int
	sealed          bool
}

// robotsUserAgent is the product token Anvil identifies as. It is matched
// case-insensitively as a substring of a User-agent value, which is how
// robots.txt matching works in practice.
const robotsUserAgent = "anvil"

// RobotsNotFound records that the fetch completed and there is no robots.txt
// at this origin. It removes nothing from scope and adds nothing to it.
func RobotsNotFound(canonicalHost string, port uint16) RobotsPolicy {
	return robotsPolicyFor(canonicalHost, port, RobotsAbsent)
}

// RobotsFetchFailed records that Anvil could not determine the site's
// robots.txt — a connection failure, a 5xx, a timeout, a redirect it would not
// follow. Every path is refused: gate 11 does not read "we could not ask" as
// "they did not object".
func RobotsFetchFailed(canonicalHost string, port uint16) RobotsPolicy {
	return robotsPolicyFor(canonicalHost, port, RobotsUnavailable)
}

func robotsPolicyFor(canonicalHost string, port uint16, d RobotsDetermination) RobotsPolicy {
	canon, err := Canonicalize(canonicalHost)
	if err != nil || canon != canonicalHost || port == 0 {
		// An origin that cannot be named is an origin no policy describes.
		// The zero RobotsPolicy refuses every path.
		return RobotsPolicy{}
	}
	return RobotsPolicy{determination: d, host: canon, port: port, sealed: true}
}

// ParseRobotsTxt parses a fetched robots.txt into a deny-only policy.
//
// It NEVER returns an error, and that is deliberate rather than lazy: an error
// return is a value a caller can discard, and a discarded error here would
// leave a permissive policy in a variable. Instead, every failure — an
// oversized body, a byte outside printable ASCII, a rule that cannot be
// interpreted — produces a policy whose determination is RobotsUnavailable,
// and gate 11 refuses every path against one of those.
//
// A Disallow value that is neither empty nor a path (no leading "/" and no
// leading "*") sets hostFullyDenied. The site said something restrictive that
// this parser could not interpret, and the conservative reading of an
// uninterpretable deny is that it denies everything.
func ParseRobotsTxt(canonicalHost string, port uint16, body []byte) RobotsPolicy {
	base := robotsPolicyFor(canonicalHost, port, RobotsPresent)
	if !base.sealed {
		return RobotsPolicy{}
	}
	unavailable := robotsPolicyFor(canonicalHost, port, RobotsUnavailable)

	if len(body) > maxRobotsBytes {
		return unavailable
	}
	for _, c := range body {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return unavailable
		}
	}

	// groupApplies tracks whether the group currently being read is one whose
	// rules bind Anvil. A file that opens with rules before any User-agent
	// line has no group, and those rules are ignored — RFC 9309 section 2.2.1.
	groupApplies := false
	inGroup := false
	lines := strings.Split(string(body), "\n")
	if len(lines) > maxRobotsRules*2 {
		return unavailable
	}
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			// A line that is not "field: value" is not a directive. It is
			// ignored rather than refusing the file, because robots.txt in the
			// wild carries stray text and refusing the file would refuse the
			// target — the strictest reading, but one that would make the gate
			// unusable rather than safe.
			continue
		}
		field = asciiFold(strings.TrimSpace(field))
		value = strings.TrimSpace(value)
		if len(value) > maxRobotsPatternBytes {
			return unavailable
		}

		switch field {
		case "user-agent":
			if !inGroup {
				// A new group starts. Reset the applicability, then OR in
				// this line's verdict; consecutive user-agent lines belong to
				// one group.
				groupApplies = false
				inGroup = true
			}
			folded := asciiFold(value)
			if folded == "*" || strings.Contains(folded, robotsUserAgent) {
				groupApplies = true
			}
		case "disallow":
			inGroup = false
			if !groupApplies {
				continue
			}
			if value == "" {
				// RFC 9309 section 2.2.2: an empty Disallow value allows
				// everything. It REMOVES NOTHING, and it must not be read as
				// "Disallow: /" — nor as permission, which is the same
				// mistake in the other direction.
				continue
			}
			if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "*") {
				base.hostFullyDenied = true
				continue
			}
			if len(base.disallow) >= maxRobotsRules {
				return unavailable
			}
			if value == "/" {
				base.hostFullyDenied = true
				continue
			}
			base.disallow = append(base.disallow, value)
		case "allow":
			inGroup = false
			// PARSED AND DISCARDED. See the type's doc comment: gate 11 is
			// asymmetric by design and there is no field to store this in.
			if groupApplies {
				base.allowsIgnored++
			}
		default:
			// Sitemap, Crawl-delay, and anything a future RFC adds. Not a
			// deny signal, so not this gate's business.
			inGroup = false
		}
	}
	return base
}

// clone deep-copies a policy, including the Disallow backing array.
//
// A RobotsPolicy owns a []string. Copying the struct copies the slice HEADER,
// so a policy stored inside a sealed Scope would share its patterns with
// whatever the caller still holds, and rewriting "/admin" to "/zzz" through
// that alias would put the admin tree back in scope. That is the kernel-types review aliasing
// escalation cloneScopeEntries exists for, in a different field.
func (p RobotsPolicy) clone() RobotsPolicy {
	out := p
	out.disallow = nil
	if p.disallow != nil {
		out.disallow = append([]string(nil), p.disallow...)
	}
	return out
}

// Determination returns what happened when Anvil looked for robots.txt.
func (p RobotsPolicy) Determination() RobotsDetermination {
	if !p.sealed {
		return RobotsUnset
	}
	return p.determination
}

// Determined reports whether the policy is one gate 11 will act on. False for
// the zero value and for a failed fetch.
func (p RobotsPolicy) Determined() bool {
	return p.sealed && (p.determination == RobotsAbsent || p.determination == RobotsPresent)
}

// Origin returns the canonical host and port this policy describes.
func (p RobotsPolicy) Origin() (string, uint16) { return p.host, p.port }

// AllowDirectivesIgnored returns how many `Allow:` directives in a binding
// group were parsed and discarded. It exists so that the audit log can record
// that they were ignored rather than leaving the reader to assume it.
func (p RobotsPolicy) AllowDirectivesIgnored() int { return p.allowsIgnored }

// DisallowedPatterns returns a copy of the deny patterns.
func (p RobotsPolicy) DisallowedPatterns() []string {
	if !p.sealed {
		return nil
	}
	return append([]string(nil), p.disallow...)
}

// HostFullyDenied reports whether robots.txt removes the whole origin.
func (p RobotsPolicy) HostFullyDenied() bool { return p.sealed && p.hostFullyDenied }

// PermitsPath reports whether robots.txt leaves this path in scope.
//
// It is not a grant. A true answer means "robots.txt removed nothing here";
// whether the path may be requested at all is gates 4 and 8–10's answer, and
// this one only ever subtracts from theirs.
func (p RobotsPolicy) PermitsPath(path string) bool {
	if !p.Determined() || !validRequestPath(path) {
		return false
	}
	if p.determination == RobotsAbsent {
		return true
	}
	if p.hostFullyDenied {
		return false
	}
	// The path is tested twice: as written, and percent-decoded once. RFC 9309
	// section 2.2.2 normalizes percent-encoding before comparing, and a
	// pattern written "/admin" would otherwise miss a request for
	// "/%61dmin". Testing both forms can only ever produce more denies.
	forms := []string{path}
	if decoded, err := percentDecodeOnce(path); err == nil && decoded != path {
		forms = append(forms, decoded)
	}
	for _, pattern := range p.disallow {
		for _, form := range forms {
			if robotsMatch(pattern, form) {
				return false
			}
		}
	}
	return true
}

// robotsMatch implements RFC 9309 section 2.2.2 path matching: a pattern is a
// prefix match, "*" matches any sequence of characters, and a trailing "$"
// anchors the match to the end of the path.
func robotsMatch(pattern, path string) bool {
	anchored := strings.HasSuffix(pattern, "$")
	if anchored {
		pattern = pattern[:len(pattern)-1]
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(path, parts[0]) {
		return false
	}
	pos := len(parts[0])
	if len(parts) == 1 {
		if anchored {
			return pos == len(path)
		}
		return true
	}
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(path[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}
	if anchored {
		return len(path)-len(last) >= pos && strings.HasSuffix(path, last)
	}
	return strings.Contains(path[pos:], last)
}

// validRequestPath bounds and charset-restricts a request path. A path is
// Anvil-generated or extracted from an inventory, but it reaches this gate
// alongside untrusted bytes, so it is checked here rather than assumed.
func validRequestPath(p string) bool {
	if p == "" || p[0] != '/' || len(p) > maxRequestPathBytes {
		return false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// CheckGate11RobotsDeny is gate 11: the site's own robots.txt, honoured as an
// ADDITIONAL deny.
//
// It is not registered into the admission chain and cannot be — see this file's
// header for the three ways out and why two of them are worse. Per-request enforcement calls it per
// request, with the origin's determined policy and the path about to be
// requested.
//
// Every refusal here REMOVES reach. There is no argument to this function that
// causes it to permit something the rest of the gate stack refused, and there
// is no branch that returns a pass on the strength of anything found in the
// document — the only passing return is reached when robots.txt removed
// nothing, which leaves the decision exactly where gates 4 and 8–10 left it.
func CheckGate11RobotsDeny(policy RobotsPolicy, target Target, path string) GateResult {
	const g = Gate11RobotsDeny

	if !target.Constructed() {
		return gateFailed(g, ReasonRobotsTargetUnbuilt,
			"gate 11 was handed a Target that NewTarget never built, so there is no origin to "+
				"match the robots policy against.")
	}
	if !validRequestPath(path) {
		return gateFailed(g, ReasonRobotsPathMalformed,
			"the request path is empty, does not begin with \"/\", exceeds the coded length "+
				"bound, or contains a byte outside printable ASCII. A path gate 11 cannot "+
				"compare against a Disallow pattern is refused rather than compared "+
				"loosely.")
	}
	if policy.Determination() == RobotsUnset {
		return gateFailed(g, ReasonRobotsNotDetermined,
			"no robots.txt determination was made for this origin. \"We did not look\" and "+
				"\"we looked and there was nothing\" produce the same silence and opposite "+
				"conclusions; docs/controls.md records two incidents in this "+
				"repository where the first was read as the second.")
	}
	if policy.Determination() == RobotsUnavailable {
		return gateFailed(g, ReasonRobotsUnavailable,
			"robots.txt could not be determined for this origin — the fetch failed, or the "+
				"document could not be parsed. An unreadable statement of a site's wishes "+
				"is not an absent one, so the path is refused.")
	}
	host, port := policy.Origin()
	if host != target.Canonical() || port != target.Port() {
		return gateFailed(g, ReasonRobotsWrongOrigin,
			"the robots policy describes a different origin than the target. robots.txt is "+
				"scoped to one scheme, host and port; applying one origin's policy to "+
				"another is how a permissive origin's silence becomes a restrictive "+
				"origin's permission.")
	}
	if !policy.PermitsPath(path) {
		return gateFailed(g, ReasonRobotsDisallows,
			"the site's robots.txt removes this path from scope. Gate 11 honours a "+
				"restrictive robots.txt as an ADDITIONAL deny on top of the scope file; it "+
				"is not overridable, because the point of honouring it is that the site "+
				"gets the last word on its own paths.",
			"path: "+redactUntrusted(path))
	}
	return gatePassed(g)
}

// ---------------------------------------------------------------------------
// GATE 11 AT RUN INITIATION — the scope narrowing
// ---------------------------------------------------------------------------

// RobotsFetchOutcome says what the fetch of one origin's robots.txt did.
//
// It is a four-valued enum and not a bool for the reason RobotsDetermination
// is: "we did not look", "we looked and there was nothing", "we looked and
// could not reach it" and "we looked and here are the bytes" are four facts,
// and three of them are refusals. The zero value is RobotsFetchUnset, which
// removes the origin — a Go zero value never means "permitted".
type RobotsFetchOutcome string

// The four outcomes.
const (
	// RobotsFetchUnset is the zero value: nobody looked, or a caller handed
	// in a zero RobotsDocument. The origin is removed from scope.
	RobotsFetchUnset RobotsFetchOutcome = ""
	// RobotsFetchRetrieved means a fetch completed with a 2xx and Body holds
	// what it returned.
	RobotsFetchRetrieved RobotsFetchOutcome = "retrieved"
	// RobotsFetchAbsent means the fetch completed and there is no robots.txt
	// (a 404). Nothing is removed and nothing is added.
	RobotsFetchAbsent RobotsFetchOutcome = "absent"
	// RobotsFetchUnreachable means the fetch failed — a connection failure, a
	// 5xx, a timeout, a redirect Anvil would not follow. The origin is
	// removed: "we could not ask" is not "they did not object".
	RobotsFetchUnreachable RobotsFetchOutcome = "unreachable"
)

// RobotsDocument is one origin's fetched robots.txt, AS DATA.
//
// This is deliberately the same shape per-target admission gave gate 12's SecurityTxtDocument:
// the fetch happens OUTSIDE the kernel, through the egress chokepoint, and the
// bytes arrive here as an inert value. The kernel performs no I/O, so gate 11
// does not need a widened signature, a context, an http.Client or a package
// -level cache to exist — the three routes that were rejected when gate 11 was
// last considered as a gateFunc.
//
// Body is `anvil/trust: untrusted` (the spine's record section). Nothing parsed out of
// it is interpolated into a Detail string except through redactUntrusted.
type RobotsDocument struct {
	// Host is the origin's canonical host, as Canonicalize produces it.
	Host string
	// Port is the origin's port. Zero is not a port and is refused.
	Port uint16
	// Outcome says what the fetch did. The zero value removes the origin.
	Outcome RobotsFetchOutcome
	// Body is the retrieved bytes, and is meaningful only when Outcome is
	// RobotsFetchRetrieved. A body on any other outcome is a caller
	// inconsistency and refuses the whole narrowing.
	Body []byte
}

// NarrowScopeToRobots is GATE 11: it applies the targets' own robots.txt to a
// SEALED scope and returns a NARROWER ONE.
//
// # Why this is not a gateFunc, and is not in admissionChain
//
// plan/design/dynamic-tier.md:1032's gate 11 row says a restrictive robots.txt "REMOVES
// PATHS FROM SCOPE" and a permissive one "adds nothing". That is a description
// of a scope transformation, not of an admission predicate, and the three
// things that made gate 11 unimplementable as a gateFunc all dissolve when it
// is written as one: a gateFunc receives no path (this takes the whole scope,
// which is where paths live), a gateFunc performs no I/O (this takes fetched
// bytes as data), and a gateFunc runs per target (this runs ONCE, at run
// initiation, after the scope is sealed). By the time the admission chain
// runs, the narrowing has already happened and the scope simply IS narrower —
// so Gate11RobotsDeny is no longer a position in kernel.go's admissionChain,
// and kernel.go's registerInto refuses to let anyone put it back.
//
// # The asymmetry is the gate
//
// THIS FUNCTION CANNOT RETURN A SCOPE THAT PERMITS ANYTHING THE INPUT DID NOT.
// It does not parse robots.txt into allows and denies and recompute a scope
// from them — that is the implementation that gets gate 11 exactly backwards
// and lets a file served by the target widen the scope Anvil was authorized
// for. It calls Scope.removeOrigin and Scope.removePaths, the only two
// narrowing primitives, and both are append-only over deny and robots and
// never write allow. See types.go's SCOPE NARROWING block for the field-level
// accounting and the reflection guard on it.
//
// `Allow:` directives are parsed by ParseRobotsTxt so a group's rules can be
// delimited, then DISCARDED. A robots.txt consisting of "Allow: /" therefore
// returns a scope that permits exactly what it permitted, and so does an empty
// one; a malformed one removes the origin. All three are driven by
// TestNarrowScopeToRobotsCannotWiden.
//
// # What it refuses outright
//
// A document whose origin cannot be named, or that carries a body on an
// outcome that had no fetch, refuses the WHOLE narrowing and returns the ZERO
// Scope — which permits nothing — alongside the failed GateResult. Both,
// because a caller that drops the GateResult must still not end up holding a
// usable scope. A narrowing that silently fails to apply a site's restriction
// is the one failure mode this function exists to prevent.
//
// # What it deliberately does NOT check
//
// It does not require a document for every origin in scope. An origin nobody
// fetched is left exactly as the operator scoped it here — and is then refused
// per request by CheckGate11RobotsDeny, which returns
// gate11.robots_txt_was_never_determined against an unset policy. The "did you
// look?" line is held there, per request, rather than duplicated here where a
// wildcard scope entry cannot be enumerated in the first place.
//
// # WHAT IS NOT WIRED YET, stated rather than implied
//
// NOTHING IN THE SHIPPING PATH CALLS THIS FUNCTION. InitiateRun
// (phase1_run.go) builds the sealed Scope and returns it; the narrowing is the
// caller's step between InitiateRun and Adjudicate, and no caller performs it
// today. The same is true of Scope.PermitsPath and Scope.RobotsPolicyFor: both
// are exercised by tests and by nothing else. So gate 11's run-initiation half
// is implemented and tested but NOT YET ENFORCED IN PRODUCTION, and the only
// thing enforcing robots.txt on a live run remains per-request enforcement's per-request
// CheckGate11RobotsDeny.
//
// That is a real gap and not a stylistic one — a control that runs in zero
// production paths is not a control. Closing it needs two edits outside this
// file: a robots.txt fetch through the egress chokepoint, and a call to this
// function in whatever drives a run from InitiateRun to Adjudicate.
func NarrowScopeToRobots(scope Scope, docs []RobotsDocument) (Scope, GateResult) {
	const g = Gate11RobotsDeny

	if !scope.Constructed() {
		return Scope{}, gateFailed(g, ReasonRobotsScopeUnconstructed,
			"gate 11 narrows a SEALED scope, and it was handed one that NewScope never "+
				"built. There is nothing to narrow, and the zero Scope permits nothing.")
	}

	out := scope
	for i, doc := range docs {
		canon, err := Canonicalize(doc.Host)
		if err != nil || canon != doc.Host || doc.Port == 0 {
			return Scope{}, gateFailed(g, ReasonRobotsDocumentOrigin,
				"a robots.txt document names an origin gate 11 cannot match against the "+
					"scope: the host is not in the canonical form gate 8 produces, or "+
					"the port is zero. A narrowing that cannot name its origin does not "+
					"narrow anything, and a site's restriction that silently fails to "+
					"apply is worse than one that was never fetched.",
				"document index: "+strconv.Itoa(i),
				"host: "+redactUntrusted(doc.Host))
		}
		if doc.Outcome != RobotsFetchRetrieved && len(doc.Body) > 0 {
			return Scope{}, gateFailed(g, ReasonRobotsDocumentInconsistent,
				"a robots.txt document carries a body on an outcome that records no "+
					"completed fetch. Bytes that arrived without a fetch are bytes "+
					"nobody can account for, and gate 11 will not narrow a scope by "+
					"them.",
				"document index: "+strconv.Itoa(i),
				"outcome: "+redactUntrusted(string(doc.Outcome)))
		}

		policy := robotsPolicyFromDocument(doc)
		rec := ScopeNarrowingRecord{
			Host:                   canon,
			Port:                   doc.Port,
			Determination:          policy.Determination(),
			AllowDirectivesIgnored: policy.AllowDirectivesIgnored(),
		}

		// An undetermined policy — nobody looked, the fetch failed, or the
		// document could not be parsed — removes the origin. It is the same
		// answer CheckGate11RobotsDeny gives per path, applied to the whole
		// origin at once, and it is a removal, so it narrows.
		if !policy.Determined() || policy.HostFullyDenied() {
			out, err = out.removeOrigin(canon, doc.Port, rec)
			if err != nil {
				return Scope{}, gateFailed(g, ReasonRobotsNarrowingFailed,
					"gate 11 could not remove an origin from the scope: "+err.Error())
			}
			continue
		}

		rec.PathPatternsApplied = len(policy.DisallowedPatterns())
		out, err = out.removePaths(canon, doc.Port, policy, rec)
		if err != nil {
			return Scope{}, gateFailed(g, ReasonRobotsNarrowingFailed,
				"gate 11 could not apply a robots policy to the scope: "+err.Error())
		}
	}
	return out, gatePassed(g)
}

// robotsPolicyFromDocument turns one fetched document into a policy, reusing
// the three constructors that already exist rather than adding a fourth.
//
// There is no branch here that produces a MORE permissive policy than the
// document justifies: RobotsFetchUnset and RobotsFetchUnreachable both land on
// RobotsFetchFailed, whose determination is RobotsUnavailable, which refuses
// every path.
func robotsPolicyFromDocument(doc RobotsDocument) RobotsPolicy {
	switch doc.Outcome {
	case RobotsFetchRetrieved:
		return ParseRobotsTxt(doc.Host, doc.Port, doc.Body)
	case RobotsFetchAbsent:
		return RobotsNotFound(doc.Host, doc.Port)
	default:
		// RobotsFetchUnset, RobotsFetchUnreachable, and any value a future
		// edit adds without updating this switch. The default is the strict
		// one on purpose.
		return RobotsFetchFailed(doc.Host, doc.Port)
	}
}

// ---------------------------------------------------------------------------
// GATE 12 — security.txt: a reporting channel, never a permission
// ---------------------------------------------------------------------------

// SecurityTxtLocation names which of RFC 9116's two paths a document came from.
type SecurityTxtLocation string

// The locations. RFC 9116 section 3 puts the file under /.well-known/ and
// permits /security.txt for compatibility; the well-known copy takes
// precedence when both exist.
const (
	SecurityTxtLocationUnset SecurityTxtLocation = ""
	SecurityTxtWellKnown     SecurityTxtLocation = "well_known"
	SecurityTxtLegacyRoot    SecurityTxtLocation = "legacy_root"
)

// SecurityTxtDocument is one retrieved candidate document.
//
// It embeds ReportingChannelOnly, so it satisfies excludedFromAdmission and
// kernel_test.go's closure walk would reject it if it ever appeared in Decide's
// input closure. Retrieved is a separate field from Body for the reason
// ImportGraph.walked exists: an empty body and a fetch that never happened are
// the same bytes and different facts.
type SecurityTxtDocument struct {
	ReportingChannelOnly
	// Location says which URL this came from.
	Location SecurityTxtLocation
	// Body is the retrieved bytes, `anvil/trust: untrusted`.
	Body []byte
	// Retrieved records that a fetch actually completed with a 2xx.
	Retrieved bool
}

// SecurityTxtStatus is the outcome of resolving a reporting channel.
type SecurityTxtStatus string

// The statuses. None of them is a permission and none of them is consulted by
// any gate.
const (
	// SecurityTxtStatusUnset is the zero value: nobody looked.
	SecurityTxtStatusUnset SecurityTxtStatus = ""
	// SecurityTxtStatusAbsent means the fetch completed and there is none.
	SecurityTxtStatusAbsent SecurityTxtStatus = "absent"
	// SecurityTxtStatusResolved means a reporting channel was resolved.
	SecurityTxtStatusResolved SecurityTxtStatus = "resolved"
	// SecurityTxtStatusExpired means the document's Expires field has passed.
	// RFC 9116 section 2.5.5 makes the field mandatory precisely so that a
	// stale file can be recognised; an expired file resolves no channel.
	SecurityTxtStatusExpired SecurityTxtStatus = "expired"
	// SecurityTxtStatusMalformed means the document could not be parsed
	// within the kernel's bounds.
	SecurityTxtStatusMalformed SecurityTxtStatus = "malformed"
)

// SecurityTxtResult is the resolved reporting channel.
//
// # It cannot reach the admission decision, and here is the accounting
//
//  1. It embeds ReportingChannelOnly, so it satisfies the unexported
//     excludedFromAdmission interface. kernel_test.go's
//     TestAdmissionInputClosureIsClosed walks Decide's four parameter types
//     transitively and fails on any type that satisfies it.
//  2. It appears in no function signature reachable from Decide, Adjudicate or
//     gateFunc. gateFunc's four parameters are declared in the kernel core's write scope,
//     not this one, so a Phase 2 packet cannot widen them.
//  3. registerInto (kernel.go) refuses to register gate 12 as a gate
//     implementation at all, with a message saying why.
//
// Its destination is the audit log: AuditReason and AuditEvidence render it for
// a GateRecord, and that is the only thing this type is for.
type SecurityTxtResult struct {
	ReportingChannelOnly
	status             SecurityTxtStatus
	location           SecurityTxtLocation
	contacts           []string
	policies           []string
	encryption         []string
	preferredLanguages []string
	expires            time.Time
	ignoredFields      int
	sealed             bool
}

// FetchSecurityTxt resolves a reporting channel from the candidate documents,
// applying RFC 9116's /.well-known/ precedence and refusing an expired file.
//
// # Why it takes bytes rather than fetching them
//
// The kernel core's forbidden actions bind this whole package: "No
// net.Dial, http.Client, or any socket-construction call anywhere in this
// package (that is Phase 3's job, gated)." So the HTTP GET is per-request enforcement's, and this
// function is the part that has to be right: the parse, the precedence, the
// expiry, and the bounds on a document that came from the target.
func FetchSecurityTxt(docs []SecurityTxtDocument, clock Clock) SecurityTxtResult {
	if !clock.Valid() {
		// No clock means no way to judge Expires, and RFC 9116 makes Expires
		// mandatory. A result that cannot say whether the file is stale is
		// not a resolved channel.
		return SecurityTxtResult{status: SecurityTxtStatusMalformed, sealed: true}
	}

	// RFC 9116 section 3: the well-known location wins. The loop takes the
	// well-known copy if one was retrieved and falls back to the legacy root
	// only if it was not — a legacy file cannot displace a well-known one, so
	// a target cannot serve a benign /security.txt to hide the real one.
	var chosen *SecurityTxtDocument
	for i := range docs {
		d := &docs[i]
		if !d.Retrieved || d.Location != SecurityTxtWellKnown {
			continue
		}
		chosen = d
		break
	}
	if chosen == nil {
		for i := range docs {
			d := &docs[i]
			if !d.Retrieved || d.Location != SecurityTxtLegacyRoot {
				continue
			}
			chosen = d
			break
		}
	}
	if chosen == nil {
		return SecurityTxtResult{status: SecurityTxtStatusAbsent, sealed: true}
	}
	return parseSecurityTxt(chosen.Location, chosen.Body, clock)
}

// parseSecurityTxt parses one document.
//
// Every value that survives is bounded and charset-restricted. The document is
// `anvil/trust: untrusted` (the spine's record section) and its contents reach the
// audit log, which is read by humans and by tooling and — per the spine's
// safety section — must never become a channel for attacker-authored bytes.
func parseSecurityTxt(loc SecurityTxtLocation, body []byte, clock Clock) SecurityTxtResult {
	malformed := SecurityTxtResult{status: SecurityTxtStatusMalformed, location: loc, sealed: true}
	if len(body) == 0 || len(body) > maxSecurityTxtBytes {
		return malformed
	}
	for _, c := range body {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return malformed
		}
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) > maxSecurityTxtLines {
		return malformed
	}

	out := SecurityTxtResult{location: loc, sealed: true}
	expiresSeen := 0
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			return malformed
		}
		field = asciiFold(strings.TrimSpace(field))
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maxSecurityTxtValueBytes {
			return malformed
		}

		switch field {
		case "contact":
			if !securityTxtURIOK(value, []string{"mailto:", "https:", "tel:"}) {
				return malformed
			}
			if len(out.contacts) >= maxSecurityTxtValues {
				return malformed
			}
			out.contacts = append(out.contacts, value)
		case "policy":
			if !securityTxtURIOK(value, []string{"https:"}) {
				return malformed
			}
			if len(out.policies) >= maxSecurityTxtValues {
				return malformed
			}
			out.policies = append(out.policies, value)
		case "encryption":
			if !securityTxtURIOK(value, []string{"https:", "dns:", "openpgp4fpr:"}) {
				return malformed
			}
			if len(out.encryption) >= maxSecurityTxtValues {
				return malformed
			}
			out.encryption = append(out.encryption, value)
		case "preferred-languages":
			langs := securityTxtLanguages(value)
			if langs == nil {
				return malformed
			}
			if len(out.preferredLanguages) > 0 {
				// RFC 9116 section 2.5.8: the field must appear at most once.
				return malformed
			}
			out.preferredLanguages = langs
		case "expires":
			// There is no early `if expiresSeen > 1 { return malformed }`
			// here. The count is checked once, after the loop, and that check
			// covers zero and two alike — a second branch here could never be
			// the only thing refusing anything, and a mutation deleting it
			// stayed green.
			expiresSeen++
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return malformed
			}
			out.expires = t
		default:
			// Unknown fields are permitted by RFC 9116 section 2.4 and are
			// counted rather than stored. Counting them is what lets the audit
			// row say "and eleven fields we did not read".
			out.ignoredFields++
		}
	}

	if expiresSeen != 1 {
		// RFC 9116 makes Expires mandatory. A file without one cannot be
		// known to be current, and a reporting channel that may be years stale
		// is not one Anvil will act on.
		return malformed
	}
	if len(out.contacts) == 0 {
		// RFC 9116 section 2.5.3: at least one Contact is mandatory. Without
		// one there is no channel, whatever else the file says.
		return malformed
	}
	if !clock.Instant().Before(out.expires) {
		out.status = SecurityTxtStatusExpired
		out.contacts = nil
		out.policies = nil
		out.encryption = nil
		out.preferredLanguages = nil
		return out
	}
	out.status = SecurityTxtStatusResolved
	return out
}

// securityTxtURIOK checks a value against an allowlist of schemes and the RFC
// 3986 URI charset.
//
// An allowlist of schemes, not a denylist: the set of schemes a URI parser will
// accept is open-ended (file:, javascript:, data:) and the set a reporting
// channel needs is three.
func securityTxtURIOK(value string, schemes []string) bool {
	folded := asciiFold(value)
	ok := false
	for _, s := range schemes {
		if strings.HasPrefix(folded, s) && len(value) > len(s) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~:/?#[]@!$&'()*+,;=%", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// securityTxtLanguages parses a comma-separated language-tag list, returning
// nil for anything that is not one.
func securityTxtLanguages(value string) []string {
	parts := strings.Split(value, ",")
	if len(parts) > maxSecurityTxtValues {
		return nil
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		tag := strings.TrimSpace(p)
		if tag == "" || len(tag) > 35 {
			return nil
		}
		for i := 0; i < len(tag); i++ {
			c := tag[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-'
			if !ok {
				return nil
			}
		}
		out = append(out, tag)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Status returns the resolution outcome. SecurityTxtStatusUnset for a value
// FetchSecurityTxt never produced.
func (r SecurityTxtResult) Status() SecurityTxtStatus {
	if !r.sealed {
		return SecurityTxtStatusUnset
	}
	return r.status
}

// Location returns which of RFC 9116's two paths the document came from.
func (r SecurityTxtResult) Location() SecurityTxtLocation { return r.location }

// Contacts returns a copy of the resolved reporting contacts. It is empty for
// every status but resolved.
func (r SecurityTxtResult) Contacts() []string {
	return append([]string(nil), r.contacts...)
}

// Policies returns a copy of the resolved policy URIs.
func (r SecurityTxtResult) Policies() []string {
	return append([]string(nil), r.policies...)
}

// Encryption returns a copy of the resolved encryption key locations.
func (r SecurityTxtResult) Encryption() []string {
	return append([]string(nil), r.encryption...)
}

// PreferredLanguages returns a copy of the preferred language tags.
func (r SecurityTxtResult) PreferredLanguages() []string {
	return append([]string(nil), r.preferredLanguages...)
}

// Expires returns the document's Expires instant.
func (r SecurityTxtResult) Expires() time.Time { return r.expires }

// IgnoredFields returns how many fields this parser did not read.
func (r SecurityTxtResult) IgnoredFields() int { return r.ignoredFields }

// AuditReason returns the gate-12 token this result is recorded under.
//
// It is a token in the same "gateNN.slug" form every other reason uses, so a
// GateRecord carrying it validates. It is NOT a Ruling: gate 12 rules on
// nothing, and there is no function in this package that turns a
// SecurityTxtResult into one.
func (r SecurityTxtResult) AuditReason() Reason {
	switch r.Status() {
	case SecurityTxtStatusAbsent:
		return ReasonSecurityTxtAbsent
	case SecurityTxtStatusResolved:
		return ReasonSecurityTxtResolved
	case SecurityTxtStatusExpired:
		return ReasonSecurityTxtExpired
	case SecurityTxtStatusMalformed:
		return ReasonSecurityTxtMalformed
	}
	return ReasonSecurityTxtUnread
}

// AuditEvidence renders the result for gate 21's audit row.
//
// Every string it returns passes through redactUntrusted, because every value
// in it came out of a document the target served.
func (r SecurityTxtResult) AuditEvidence() []string {
	ev := []string{
		"security.txt status: " + string(r.Status()),
		"security.txt location: " + string(r.location),
	}
	for _, c := range r.contacts {
		ev = append(ev, "contact: "+redactUntrusted(c))
	}
	for _, p := range r.policies {
		ev = append(ev, "policy: "+redactUntrusted(p))
	}
	for _, e := range r.encryption {
		ev = append(ev, "encryption: "+redactUntrusted(e))
	}
	if len(r.preferredLanguages) > 0 {
		ev = append(ev, "preferred-languages: "+redactUntrusted(strings.Join(r.preferredLanguages, ",")))
	}
	if !r.expires.IsZero() {
		ev = append(ev, "expires: "+r.expires.UTC().Format(time.RFC3339))
	}
	ev = append(ev, fmt.Sprintf("fields not read: %d", r.ignoredFields))
	return ev
}

// ---------------------------------------------------------------------------
// REGISTRATION
// ---------------------------------------------------------------------------

// init installs the three Phase 2 gates that are functions of (target, scope,
// attestation, clock).
//
// Gate 11 is absent on purpose and gate 12 cannot be registered at all. See
// this file's header for both, and kernel.go's registerInto for the refusal
// that makes the second one a compile-and-run-time fact rather than a
// convention.
//
// These three are also three of the five gates in kernel.go's
// revalidationChain, which gate 13 re-runs on every request and every redirect
// hop; the other two are gate 4 (scope membership) and gate 5 (a LIVE
// attestation), both registered by run initiation. After this packet that chain is fully
// implemented, so a redirect to a host outside scope, or to a reserved
// address, is refused on the hop rather than only on the first request —
// research/20 names that omission (ZAP issue #2546) "the single most likely way
// Anvil escapes scope".
func init() {
	register(Gate8Canonicalize, gate8Canonicalize)
	register(Gate9ResolveAndPin, gate9ResolveAndPin)
	register(Gate10ReservedRanges, gate10ReservedRanges)
}
