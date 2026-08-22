// dpkg_compare.go implements Debian's version ordering: the algorithm
// `deb-version(7)` specifies and dpkg's `lib/dpkg/version.c` implements.
//
// ---------------------------------------------------------------------------
// THE ONE RULE EVERYBODY GETS BACKWARDS
// ---------------------------------------------------------------------------
//
// deb-version(7), on the lexical comparison of a non-digit run:
//
//	"a tilde sorts before anything, even the end of a part"
//
// So `1.0~rc1` < `1.0`, and `1.0~~` < `1.0~` < `1.0`. Get that backwards and
// EVERY pre-release is misjudged in the direction that matters: a release
// candidate is reported as NEWER than the release, so an advisory saying
// "fixed in 1.0" clears a host running `1.0~rc1`, which is not fixed.
//
// The second rule in the same sentence is the one that makes `~` possible at
// all: "all the letters sort earlier than all the non-letters". That is why
// dpkg's `order()` maps a letter to its own byte value and a non-letter to its
// byte value PLUS 256 — the alphabet is pushed below the punctuation — and why
// `1.0a` < `1.0+b` even though '+' (0x2B) is below 'a' (0x61) in ASCII.
//
// ---------------------------------------------------------------------------
// THIS IS A PORT, NOT AN INTERPRETATION
// ---------------------------------------------------------------------------
//
// verrevcmp below is a line-for-line port of dpkg's function of the same name.
// It is deliberately NOT restructured into something more idiomatic: the
// interleaving of "compare the non-digit run character by character", "throw
// away leading zeros", "compare the digit runs by length then by first
// difference" is load-bearing, and every reorganisation of it that has been
// attempted in the wild has changed an ordering somewhere.
//
// The comparison corpus is in corpus_transcribed_test.go: all 43 rows of
// dpkg's own `scripts/t/Dpkg_Version.t` __DATA__ block, transcribed with the
// line number each came from, plus the rows this project AUTHORED from
// deb-version(7) where the published suite has none. It does NOT come from
// reading this file. A corpus derived from the implementation certifies the
// implementation's bugs; this project has already had a licence marker table
// validated against its own entries and it certified a defect.
//
// ---------------------------------------------------------------------------
// WHAT IS REFUSED, AND THE CLAIM THAT USED TO BE FALSE
// ---------------------------------------------------------------------------
//
// parseDebian rejects rather than repairs. An epoch that is not a number, an
// upstream version that does not start with a digit, an EMPTY REVISION after a
// trailing '-', a character outside deb-version(7)'s set — each is a *Refusal
// carrying RefusalMalformedVersion. dpkg itself refuses these, so accepting
// them here would mean comparing a string no Debian system could have produced
// against one it did.
//
// THE EMPTY REVISION IS IN THAT LIST BECAUSE THE CLAIM WAS FALSE WITHOUT IT.
// `1.0-` was accepted, split into upstream `1.0` and an empty revision, and
// then compared EQUAL to `1.0` — a repair, in the file whose header said it
// does not repair. Dpkg_Version.t line 112 says the string is invalid, and the
// consequence is not cosmetic: RANGE ENDPOINTS are validated by this same
// parser (AffectedRange.validate -> ValidVersion -> parseDebian), so a
// truncated `Fixed` endpoint was silently read as a lower bound than the
// advisory meant, and a host above it was reported clean.
//
// THAT DIRECTION OF ERROR IS THE ONE A VALIDITY CORPUS CATCHES AND AN ORDERING
// CORPUS CANNOT: dpkg will not order a string it will not parse, so no row of
// any published comparison table can contain it. dpkgValidity in
// corpus_transcribed_test.go transcribes the nine is_valid() assertions from
// Dpkg_Version.t for exactly this reason.
package match

import (
	"strconv"
	"strings"
)

// debVersion is a parsed Debian version: `[epoch:]upstream[-revision]`.
type debVersion struct {
	// Epoch defaults to 0 when absent. deb-version(7): "It may be omitted,
	// in which case zero is assumed."
	Epoch int
	// EpochPresent records whether the string SPELLED an epoch. The
	// ORDERING never branches on it — deb-version(7) is explicit that an
	// omitted epoch is zero, and compareDebParsed implements exactly that.
	// It is read by one thing only: AffectedRange.checkEpochAgreement, which
	// refuses to evaluate a RANGE whose endpoint omits an epoch the
	// installed version spells (see comparator.go,
	// RefusalEpochPresenceMismatch). Ordering and range predicates are
	// different questions and this field is where they part company.
	EpochPresent bool
	// Upstream is the upstream_version, never empty.
	Upstream string
	// Revision is the debian_revision, empty when absent. Absent and "0"
	// compare EQUAL under verrevcmp (an empty non-digit run against a digit
	// run whose only digit is a stripped leading zero), which is dpkg's own
	// behaviour and is why this field is not defaulted to "0" on parse.
	Revision string
}

// maxDebEpoch bounds the epoch so a hostile or corrupt feed cannot hand this
// package a 4000-digit integer to parse. Debian's largest epoch in the archive
// is a single digit; the bound is generous by six orders of magnitude and
// exists only to make the failure a refusal instead of an allocation.
const maxDebEpoch = 1 << 30

// parseDebian parses and validates a Debian version string.
//
// Ordering of the three splits matters and follows dpkg:
//
//  1. The epoch is everything before the FIRST ':'. dpkg requires it to be a
//     non-empty run of digits; a ':' with anything else in front of it is an
//     error, not "no epoch".
//  2. The revision is everything after the LAST '-'. Using the last hyphen is
//     what makes `1.0-beta-3` parse as upstream `1.0-beta`, revision `3`.
//  3. What is left is the upstream version, and it must start with a digit.
func parseDebian(raw string) (debVersion, error) {
	bad := func(detail string) (debVersion, error) {
		return debVersion{}, &Refusal{
			Reason:  RefusalMalformedVersion,
			Scheme:  SchemeDebian,
			Version: raw,
			Detail:  detail,
		}
	}

	s := strings.TrimSpace(raw)
	if s == "" {
		return bad("version is empty")
	}
	if s != raw {
		// A version that needed trimming came from a producer that is not
		// emitting a version field cleanly. Refuse rather than silently
		// accept, because the same producer's next field may be trimmed into
		// something that parses but is wrong.
		return bad("version has leading or trailing whitespace")
	}

	var v debVersion

	if i := strings.IndexByte(s, ':'); i >= 0 {
		e := s[:i]
		if e == "" {
			return bad("epoch is empty (a leading ':' is not a zero epoch)")
		}
		for j := 0; j < len(e); j++ {
			if !isDigit(e[j]) {
				return bad("epoch " + strconv.Quote(e) + " is not a number")
			}
		}
		if len(e) > 10 {
			return bad("epoch " + strconv.Quote(e) + " is implausibly long")
		}
		n, err := strconv.Atoi(e)
		if err != nil || n > maxDebEpoch {
			return bad("epoch " + strconv.Quote(e) + " is out of range")
		}
		v.Epoch = n
		v.EpochPresent = true
		s = s[i+1:]
	}

	if s == "" {
		return bad("version carries an epoch but no upstream version")
	}

	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.Revision = s[i+1:]
		s = s[:i]
		if v.Revision == "" {
			// dpkg's own suite states this one directly:
			//
			//	$empty = Dpkg::Version->new('1.0-');
			//	ok(! $empty->is_valid(), 'empty revision is invalid');
			//	                       -- scripts/t/Dpkg_Version.t line 112
			//
			// This is the line that made the header's "parseDebian rejects
			// rather than repairs" claim false. The trailing '-' was taken
			// as a revision split producing an EMPTY revision, which
			// debVerrevcmp then compares equal to an absent one — so `1.0-`
			// silently became `1.0`. As an installed version that is a
			// tolerated typo; as a RANGE ENDPOINT it is a truncated string
			// deciding a predicate, and a truncated upper bound reads as a
			// LOWER one, which clears a vulnerable host. Endpoints are
			// validated by this same parser (AffectedRange.validate calls
			// ValidVersion), so a repair here is a repair there.
			return bad("debian revision is empty (a trailing '-' is not an absent revision); " +
				"dpkg rejects this string")
		}
	}
	v.Upstream = s

	if v.Upstream == "" {
		return bad("upstream version is empty")
	}
	if !isDigit(v.Upstream[0]) {
		// dpkg: "version number does not start with digit". This is the
		// check that stops a semver-with-a-v-prefix ("v1.2.3") or a language
		// ecosystem's version from being compared as if it were a Debian
		// one.
		return bad("upstream version " + strconv.Quote(v.Upstream) + " does not start with a digit")
	}
	if err := checkDebChars(v.Upstream, true); err != nil {
		return bad("upstream version: " + err.Error())
	}
	if v.Revision != "" {
		if err := checkDebChars(v.Revision, false); err != nil {
			return bad("debian revision: " + err.Error())
		}
	}

	return v, nil
}

// checkDebChars enforces deb-version(7)'s character set as an ALLOWLIST.
//
// upstream_version: alphanumerics and `. + - : ~`.
// debian_revision:  alphanumerics and `. + ~`.
//
// The revision cannot contain '-' by construction (it is the text after the
// last hyphen) and must not contain ':' — a colon there would have been eaten
// by the epoch split on a well-formed version, so its presence means the
// string is not one dpkg would accept.
func checkDebChars(s string, upstream bool) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlnum(c), c == '.', c == '+', c == '~':
		case upstream && (c == '-' || c == ':'):
		default:
			return errString("illegal character " + strconv.Quote(string(c)) +
				" in " + strconv.Quote(s))
		}
	}
	return nil
}

// compareDebian orders two Debian version strings, returning -1, 0 or +1.
//
// Both operands are parsed and validated first; either being malformed is a
// refusal, never a "treat it as older" guess.
func compareDebian(a, b string) (int, error) {
	va, err := parseDebian(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseDebian(b)
	if err != nil {
		return 0, err
	}
	return compareDebParsed(va, vb), nil
}

// compareDebParsed is dpkg's dpkg_version_compare: epoch, then upstream, then
// revision, each with the first non-zero result winning.
func compareDebParsed(a, b debVersion) int {
	if a.Epoch != b.Epoch {
		if a.Epoch < b.Epoch {
			return -1
		}
		return 1
	}
	if r := debVerrevcmp(a.Upstream, b.Upstream); r != 0 {
		return r
	}
	return debVerrevcmp(a.Revision, b.Revision)
}

// debOrder is dpkg's `order()`, unchanged:
//
//	digit          -> 0
//	letter         -> the letter's own byte value (97..122, 65..90)
//	'~'            -> -1
//	end of string  -> 0
//	anything else  -> byte value + 256
//
// The +256 is what implements "all the letters sort earlier than all the
// non-letters", and the -1 is what implements "a tilde sorts before anything,
// even the end of a part". Both are quoted from deb-version(7).
//
// Note that a digit and the end of the string share the value 0. That is
// dpkg's own collision and it is safe because the enclosing loop never lets a
// digit reach this function: the loop runs only while at least one side is a
// non-digit, and returns as soon as the two orders differ.
func debOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

// debByteAt returns s[i], or 0 for an index past the end. dpkg's C original
// relies on the NUL terminator for exactly this; the Go port has to say so.
func debByteAt(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

// debVerrevcmp is dpkg's verrevcmp, ported statement for statement.
//
// The structure, and why each part is where it is:
//
//	while either side has bytes left:
//	  1. Compare the leading NON-DIGIT run character by character under
//	     debOrder. A difference here decides the whole comparison — this is
//	     where `~` beats the end of the string.
//	  2. Throw away leading zeros on both sides independently, so `01` and
//	     `1` are the same number.
//	  3. Walk the digit runs together, remembering the FIRST difference but
//	     not acting on it yet.
//	  4. Whichever digit run is still going has more digits and is therefore
//	     the larger number.
//	  5. Only if the runs were the same length does the remembered first
//	     difference decide.
//
// Steps 3–5 are how dpkg compares arbitrarily long numeric runs without ever
// converting them to an integer.
func debVerrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0

		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := debOrder(debByteAt(a, i))
			bc := debOrder(debByteAt(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}

		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}

		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}

		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

// sign normalises any integer difference to -1, 0 or +1. Every comparator in
// this package returns a normalised sign, so a caller may compare results
// across schemes without knowing which one produced them.
func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
