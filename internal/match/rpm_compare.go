// rpm_compare.go implements RPM's version ordering: `rpmvercmp` over an
// `epoch:version-release` triple, as rpm's `rpmio/rpmvercmp.c` implements it
// and `tests/rpmvercmp.at` pins it.
//
// ---------------------------------------------------------------------------
// THE RELEASE FIELD IS PART OF THE COMPARISON, AND IT IS THE POINT
// ---------------------------------------------------------------------------
//
// This is the scheme where Lane A earns its keep. research/12 §3's worked
// example is CVE-2023-32681 in python-requests: upstream says "fixed in
// 2.31.0", Red Hat ships `2.25.1-3.el9` with the fix BACKPORTED, and the
// upstream range therefore calls a patched host vulnerable. The only thing
// that distinguishes `2.25.1-3.el9` from `2.25.1-1.el9` is the RELEASE field,
// so a comparator that drops it cannot represent the vendor's answer at all,
// and a matcher built on one has no way to defeat that false-positive class.
//
// comparator.go's vendor-advisory-first precedence is the policy; this file is
// the arithmetic that makes the policy expressible.
//
// ---------------------------------------------------------------------------
// TILDE SORTS BEFORE, CARET SORTS AFTER
// ---------------------------------------------------------------------------
//
// rpm borrowed `~` from Debian (`1.0~rc1` < `1.0`) and then added `^`, which is
// its mirror image: `1.0^git1` > `1.0`. The two markers are handled by two
// almost-identical blocks in rpmvercmp, and the difference between them is one
// pair of early returns — when one side has ENDED, a tilde on the other side
// makes it smaller and a caret on the other side makes it larger. Both blocks
// are ported verbatim below rather than merged, because merging them is how
// the asymmetry gets lost.
//
// ---------------------------------------------------------------------------
// NON-ALPHANUMERICS ARE SEPARATORS, NOT DATA
// ---------------------------------------------------------------------------
//
// rpmvercmp skips every character that is not alphanumeric, `~` or `^`. That
// is why rpm's own test suite asserts `2.0` == `2_0` and `a+` == `a_`: the
// separator's identity carries no information. This is a genuine difference
// from Debian, where the separator IS compared, and it is one of the reasons
// the two comparators cannot share an implementation.
//
// ---------------------------------------------------------------------------
// CORPUS PROVENANCE
// ---------------------------------------------------------------------------
//
// THIS PARAGRAPH NO LONGER STATES A COMPLETENESS CLAIM, BECAUSE THE CLAIM
// MADE HERE HAS BEEN WRONG TWICE. It said the corpus was rpmvercmp.at
// "transcribed as written there" while the corpus stopped one row before the
// implementation's first failure; the correction then said the section ends
// with FOUR separator-only vectors, and it ends with FIVE —
// `RPMVERCMP(+, _, 0)` at line 89 was missing from the count as well as from
// the corpus. A sentence that keeps drifting away from the data underneath it
// is not fixed by rewriting the sentence.
//
// So the claim is now DATA. The transcription is rpmTranscribed in
// corpus_transcribed_test.go — generated from the fetched file, one vector per
// active RPMVERCMP line, each carrying the LINE NUMBER it came from — and its
// completeness claim is a row of transcriptionClaims carrying the NUMBER 91.
// TestTranscriptionClaimsAreTrue counts the corpus and fails if the number
// disagrees in either direction. Nothing in this file may claim more.
//
// FIVE DELIBERATE DEVIATIONS, WHICH ARE IN THE CORPUS RATHER THAN OMITTED
// FROM IT. The RhBug:178798 section ends with five vectors whose versions are
// made ENTIRELY of separators (lines 86-90: `+_` vs `+_`, `_+` vs `+_`, `_+`
// vs `_+`, `+` vs `_`, `_` vs `+`). rpm orders all five EQUAL, because
// rpmvercmp skips every non-alphanumeric byte and both sides therefore reduce
// to nothing. ANVIL DECLINES TO ORDER THEM AT ALL: parseRPM refuses a version
// segment with no alphanumeric, '~' or '^' character (see
// rpmHasComparableContent), on the grounds that such a string is not a version
// but a parse failure upstream of here, and calling two of them "equal" would
// let two unrelated corrupt rows satisfy each other's range boundaries.
//
// They carry `Refused: true` and that argument as their Note. A corpus that is
// the published suite minus the rows the implementation fails is a corpus
// filtered by the implementation, and that circularity is what this project's
// licence-marker table already paid for once.
package match

import (
	"strconv"
	"strings"
)

// rpmVersion is a parsed RPM EVR: `[epoch:]version[-release]`.
type rpmVersion struct {
	// Epoch is 0 when the string carries none. rpm treats a missing epoch as
	// zero for comparison, so `1.0` and `0:1.0` are equal.
	Epoch int
	// EpochPresent records whether the string SPELLED an epoch. The
	// ORDERING never branches on it — rpm treats a missing epoch as zero
	// and compareRPMParsed implements exactly that. It is read by one thing
	// only: AffectedRange.checkEpochAgreement, which refuses to evaluate a
	// RANGE whose endpoint omits an epoch the installed version spells (see
	// comparator.go, RefusalEpochPresenceMismatch). Ordering and range
	// predicates are different questions and this field is where they part
	// company.
	//
	// It was dead state until A.18 found what its absence cost: a RHEL
	// glibc `2:2.34-60.el9` against an advisory endpoint spelled
	// `2.34-100.el9` produced zero findings and a clean verdict on a
	// vulnerable host.
	EpochPresent bool
	// Version is the version segment, never empty.
	Version string
	// Release is the release segment, empty when absent.
	Release string
}

// maxRPMEpoch bounds the epoch for the same reason maxDebEpoch does.
const maxRPMEpoch = 1 << 30

// parseRPM splits an EVR exactly as rpm's `parseEVR` does, and then validates
// what it found.
//
// rpm's split, which this follows:
//
//	Walk leading DIGITS. If the next character is ':', everything walked is
//	the epoch (an empty run before ':' means epoch 0). Otherwise there is no
//	epoch and the ':' — if any — is part of the version.
//	The release is everything after the LAST '-'.
//
// The consequence worth knowing: `1.0:2` has NO epoch, because the digit walk
// stops at '.' and never reaches the colon. That is rpm's behaviour, not a
// simplification.
func parseRPM(raw string) (rpmVersion, error) {
	bad := func(detail string) (rpmVersion, error) {
		return rpmVersion{}, &Refusal{
			Reason:  RefusalMalformedVersion,
			Scheme:  SchemeRPM,
			Version: raw,
			Detail:  detail,
		}
	}

	if raw == "" {
		return bad("version is empty")
	}
	if strings.TrimSpace(raw) != raw {
		return bad("version has leading or trailing whitespace")
	}
	// An EVR is printable ASCII. Refusing anything else here means the
	// segment walkers below never have to reason about a multi-byte rune
	// straddling an "alphanumeric" test.
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return bad("version contains a non-printable or non-ASCII byte at offset " +
				strconv.Itoa(i))
		}
	}

	s := raw
	var v rpmVersion

	k := 0
	for k < len(s) && isDigit(s[k]) {
		k++
	}
	if k < len(s) && s[k] == ':' {
		e := s[:k]
		v.EpochPresent = true
		if e == "" {
			v.Epoch = 0
		} else {
			if len(e) > 10 {
				return bad("epoch " + strconv.Quote(e) + " is implausibly long")
			}
			n, err := strconv.Atoi(e)
			if err != nil || n > maxRPMEpoch {
				return bad("epoch " + strconv.Quote(e) + " is out of range")
			}
			v.Epoch = n
		}
		s = s[k+1:]
	}

	if s == "" {
		return bad("version carries an epoch but no version segment")
	}

	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.Release = s[i+1:]
		s = s[:i]
	}
	v.Version = s
	if v.Version == "" {
		return bad("version segment is empty")
	}
	// rpmvercmp treats every non-alphanumeric, non-'~', non-'^' byte as a
	// separator, so a segment made ENTIRELY of separators carries no
	// information at all and would compare equal to every other such
	// segment. That is not a version; it is a parse failure upstream of
	// here, and it is refused rather than compared.
	if !rpmHasComparableContent(v.Version) {
		return bad("version segment " + strconv.Quote(v.Version) +
			" contains no alphanumeric, '~' or '^' character")
	}

	return v, nil
}

// rpmHasComparableContent reports whether s carries at least one byte
// rpmvercmp would actually look at.
func rpmHasComparableContent(s string) bool {
	for i := 0; i < len(s); i++ {
		if isAlnum(s[i]) || s[i] == '~' || s[i] == '^' {
			return true
		}
	}
	return false
}

// compareRPM orders two RPM EVR strings, returning -1, 0 or +1.
//
// THE RELEASE FIELD IS ALWAYS COMPARED, including when one side omits it. An
// absent release compares as the empty string, and rpmvercmp puts the empty
// string below every non-empty one, so `1.2.3` < `1.2.3-1`. That is rpm's own
// ordering; range semantics that would be surprised by it are handled in
// comparator.go, where the inclusive/exclusive rules live.
func compareRPM(a, b string) (int, error) {
	va, err := parseRPM(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseRPM(b)
	if err != nil {
		return 0, err
	}
	return compareRPMParsed(va, vb), nil
}

func compareRPMParsed(a, b rpmVersion) int {
	if a.Epoch != b.Epoch {
		if a.Epoch < b.Epoch {
			return -1
		}
		return 1
	}
	if r := rpmvercmp(a.Version, b.Version); r != 0 {
		return r
	}
	return rpmvercmp(a.Release, b.Release)
}

// rpmvercmp is a port of rpm's function of the same name.
//
// The C original mutates its inputs (it writes NUL terminators at segment
// boundaries and restores them afterwards); this port uses index pairs
// instead, which is the only structural change. Every branch, every early
// return and every ordering decision is in the same place and the same order.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Skip separators: anything that is not alphanumeric, '~' or '^'.
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// Tilde: sorts before everything else, INCLUDING the end of the
		// string. `1.0~rc1` < `1.0`.
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		// Caret: the mirror image. It sorts AFTER the base version, so
		// `1.0^git1` > `1.0` — but a side that has ENDED is the base
		// version and therefore the SMALLER one, which is the pair of
		// returns that distinguishes this block from the tilde block above.
		aCaret := i < len(a) && a[i] == '^'
		bCaret := j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !aCaret {
				return 1
			}
			if !bCaret {
				return -1
			}
			i++
			j++
			continue
		}

		// If either side ran out, the loop is finished; the tail rules
		// below decide.
		if i >= len(a) || j >= len(b) {
			break
		}

		// Grab one completely-numeric or completely-alphabetic segment from
		// each side. THE SEGMENT KIND IS CHOSEN BY THE FIRST STRING ONLY:
		// that asymmetry is rpm's, and it is what makes the "numeric beats
		// alphabetic" rule below reachable.
		si, sj := i, j
		isNum := isDigit(a[si])
		if isNum {
			for si < len(a) && isDigit(a[si]) {
				si++
			}
			for sj < len(b) && isDigit(b[sj]) {
				sj++
			}
		} else {
			for si < len(a) && isAlpha(a[si]) {
				si++
			}
			for sj < len(b) && isAlpha(b[sj]) {
				sj++
			}
		}

		if si == i {
			// rpm's own comment says this cannot happen, and keeps the
			// return anyway. So does this port: an unreachable branch that
			// returns a defined value is better than one that falls through
			// into an infinite loop.
			return -1
		}
		if sj == j {
			// The two sides disagree about the segment kind. A numeric
			// segment is always newer than an alphabetic one.
			if isNum {
				return 1
			}
			return -1
		}

		segA := a[i:si]
		segB := b[j:sj]
		if isNum {
			// Leading zeros carry no value, and after stripping them the
			// LONGER run is the larger number. This is how rpm compares
			// digit runs too long for an int without ever parsing one.
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) > len(segB) {
				return 1
			}
			if len(segB) > len(segA) {
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return sign(c)
		}

		i, j = si, sj
	}

	// Both exhausted: equal. Otherwise the side with bytes left is larger.
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}
