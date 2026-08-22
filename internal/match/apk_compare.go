// apk_compare.go implements Alpine's version ordering.
//
// ---------------------------------------------------------------------------
// READ THIS BEFORE TRUSTING THIS FILE: IT IMPLEMENTS PART OF apk's ORDERING
// ---------------------------------------------------------------------------
//
// dpkg_compare.go and rpm_compare.go are statement-for-statement ports of
// their upstream implementations. THIS FILE IS NOT A PORT. It is a set of
// NUMBERED WRITTEN RULES below, implementing two published facts: the GRAMMAR
// in apk-tools' `src/version.c` header comment
//
//	number{.number}...{letter}{_suffix{number}}...{-r#}
//
// and the SUFFIX RANK TABLE that the same file and Alpine's own documentation
// publish:
//
//	alpha < beta < pre < rc < (no suffix) < cvs < svn < git < hg < p
//
// Where apk's tokeniser has behaviour these two do not describe — a numeric
// part with a leading zero, the `~<commit>` suffix, an unrecognised suffix
// word, the comparison of an explicit zero against an absence — THIS FILE
// REFUSES rather than guesses. A refusal is a countable gap in
// CoverageReport; a guess is a silently wrong CVE verdict. The refusals are
// enumerated in R7 and R8.
//
// EACH REFUSAL IS JUSTIFIED FROM A FILE, NOT FROM A MECHANISM INVENTED FOR
// THE OCCASION. Two of them were not, and this is the correction: R7a
// asserted a "special negative weight" that `src/version.c` does not contain,
// and R8 asserted a token kind (`TOKEN_DIGIT_OR_ZERO`) that file does not
// declare. Justifying a refusal by asserting a behaviour that is false against
// the cited source is the same error as asserting an ordering on no citation —
// it merely reads as caution. Where the mechanism IS published (R7a) it is
// quoted; where it is not (R8), the rule says plainly that the ordering is
// unmodelled and therefore refused, and rests on nothing else.
//
// WHAT HAS CHANGED SINCE A.18 CALLED THIS THE WEAKEST OF THE THREE. Its
// complaint was that not one apk vector had been diffed against apk's own
// fixture. All 738 ordering rows and all 31 validity rows of
// `test/unit/version.data` are now in corpus_transcribed_test.go: 674 pass, 64
// are refused for the R7 reasons above, and none produce a wrong ordering.
// The gaps are real and countable; they are no longer unmeasured.
//
// ---------------------------------------------------------------------------
// THE WRITTEN RULES
// ---------------------------------------------------------------------------
//
// R1. GRAMMAR. A version is
//
//	<num>(.<num>)* [<letter>] (_<suffix>[<num>])* [-r<num>]
//
// where <num> is a run of ASCII digits, <letter> is exactly one lowercase
// ASCII letter, and <suffix> is one of the ten allowlisted words in R4.
// Anything the grammar does not derive is refused (R7).
//
// R2. NUMERIC PARTS are compared left to right as unsigned integers. Where
// one side has a part the other does not, the side that HAS a NON-ZERO part
// is greater: `1.0.1` > `1.0` under every reading of apk's tokeniser, because
// a digit token outranks the end of the string in all of them.
//
// R2 STOPS THERE, AND R8 SAYS WHY. `1.0` against `1` is an EXPLICIT ZERO
// against an ABSENCE. apk decides it in the tail of
// apk_version_compare_fuzzy, comparing a token against TOKEN_END, which this
// file does not model; it is refused (R8), not called equal.
//
// R3. LETTER is compared after every numeric part. Absent sorts BELOW present,
// so `1.0` < `1.0a`; two present letters compare by byte, so `1.0a` < `1.0b`.
//
// R3 IS APPLIED BEFORE R4, AND THAT ORDERING IS UNCITED. It follows the
// grammar's own left-to-right shape, but the relative order of a version
// carrying a LETTER and one carrying a `_suffix` -- `1.0a` against `1.0_cvs1`
// -- is a consequence of this file's rule order rather than of any published
// vector. comparator_test.go therefore keeps letters and suffixes in separate
// transitivity chains and never asserts the interaction, and this paragraph is
// the record of the gap.
//
// R4. SUFFIXES are compared after the letter, left to right. Each suffix has a
// RANK, and a side with no suffix at a given position is compared at the rank
// of "no suffix":
//
//	alpha 0 . beta 1 . pre 2 . rc 3 . (none) 4 .
//	cvs 5 . svn 6 . git 7 . hg 8 . p 9
//
// So `1.0_rc1` < `1.0` < `1.0_p1`, which is the whole reason this table
// exists: four of the ten suffixes sort BEFORE the bare version and five sort
// after, and a comparator that treated them all as "extra text after the
// version" would put every release candidate on the wrong side.
//
// R5. SUFFIX NUMBERS decide within one rank. `_rc1` < `_rc2`, and an absent
// number is below any NON-ZERO number (`_rc` < `_rc1`) under both readings of
// the tokeniser. `_rc` against `_rc0` is an explicit zero against an absence
// and is refused (R8).
//
// R6. REVISION `-rN` is compared last. An absent revision is below any
// NON-ZERO revision (`1.0` < `1.0-r1`, `1.0-r0` < `1.0-r1`). `1.0` against
// `1.0-r0` is an explicit zero against an absence and is refused (R8).
//
// R7. REFUSALS. Each of these produces a *Refusal carrying
// RefusalMalformedVersion rather than an ordering:
//
// R7a. A numeric part with a leading zero and more than one digit ("00",
// "01"). REFUSED, because at that position apk stops comparing numbers and
// starts comparing bytes, and this file implements only the numeric rule.
//
// THIS JUSTIFICATION USED TO BE FALSE, AND THE FILE IT CITED SAYS SO. It read
// "apk's tokeniser gives leading-zero parts a special negative weight that the
// published grammar does not describe, and no published vector this file could
// cite pins it down". There is no such weight. apk-tools `src/version.c`,
// token_cmp():
//
//	case TOKEN_DIGIT:
//	    if (ta->value.ptr[0] == '0' || tb->value.ptr[0] == '0') {
//	        // if either of the digits have a leading zero, use
//	        // raw string comparison similar to Gentoo spec
//	        goto use_string_sort;
//	    }
//
// A leading zero does not weight the part; it switches the comparison AT THAT
// POSITION from numeric to a byte-wise string sort. That is a second ordering
// rule, and apk's own fixture publishes a row where the two rules disagree:
// `test/unit/version.data` line 735 states
//
//	8.2.0015 < 8.2.002
//
// which numeric comparison orders the other way round (15 > 2). So the
// mechanism IS published and the refusal is not "we cannot know" — it is "this
// file implements one of apk's two rules for a numeric position and will not
// apply the wrong one to an operand that needs the other". That row is in
// apkTranscribed at line 735, carrying that reason, along with the other 57
// rows R7a refuses.
//
// NOTE WHAT THIS DOES NOT AFFECT. token_cmp's branch fires on a leading '0'
// including a bare "0", but a single "0" sorts identically under both rules
// (it is the byte-least digit and the numeric-least value), so R7a is bounded
// at fields of more than one digit and no ordering this file produces depends
// on the untaken branch. The INITIAL digit field is TOKEN_INITIAL_DIGIT, which
// the branch does not cover at all.
//
// R7b. Any '~'. apk accepts a `~<commit>` suffix — TOKEN_COMMIT_HASH in
// src/version.c, a run of hex digits — and `test/unit/version.data` (lines
// 737-739, plus the validity row at line 760) confirms it is legal. What no
// published row states is where a version CARRYING one sorts relative to a
// version carrying NONE: every fixture row compares one hash against another.
// This file does not model the token and refuses rather than placing it in the
// ordering by guess.
//
// R7c. An uppercase letter anywhere. The grammar's <letter> is lowercase and
// Alpine's package versions are lowercase; an uppercase byte means the string
// came from somewhere else.
//
// R7d. A suffix word outside the ten in R4 -- an ALLOWLIST, so a suffix nobody
// anticipated is refused rather than sorted somewhere. apk agrees that such a
// word is invalid (suffix_value returns SUFFIX_INVALID) but can still reach an
// ordering, because an earlier token may decide first: `test/unit/version.data`
// line 2 orders `23_foo > 4_beta` on the initial digit. Anvil refuses the
// operand at parse time instead, which is stricter and is recorded as a
// deviation on that row.
//
// R7e. More than one letter, an empty numeric part, a '-' that is not the
// `-r` revision marker, or any other byte the grammar cannot derive.
//
// R8. AN EXPLICIT ZERO AGAINST AN ABSENCE IS REFUSED, AT WHATEVER POSITION
// DECIDES THE COMPARISON. This is a refusal from compareAPK rather than from
// parseAPK — both operands are perfectly well-formed; it is the ORDERING
// BETWEEN THEM that is not implemented — and it carries
// RefusalUnmodelledOrdering, not RefusalMalformedVersion.
//
// WHY IT EXISTS, WHICH IS THE PART A LATER READER NEEDS. A.18 found this file
// asserting `1.0 == 1`, `1.0 == 1.0-r0` and `1.0_rc == 1.0_rc0` as written
// rules, on no citation, in the one scheme where it had promised not to guess.
// The three were withdrawn and became refusals.
//
// THE REASON GIVEN FOR THE WITHDRAWAL WAS ITSELF AN INVENTION AND IS NOW GONE.
// It claimed apk gives a run of zeros "its own token kind
// (`TOKEN_DIGIT_OR_ZERO`)". There is no such token: `src/version.c` declares
// TOKEN_INITIAL_DIGIT, TOKEN_DIGIT, TOKEN_LETTER, TOKEN_SUFFIX,
// TOKEN_SUFFIX_NO, TOKEN_COMMIT_HASH, TOKEN_REVISION_NO, TOKEN_END and
// TOKEN_INVALID, and nothing else. Justifying a refusal by asserting a
// mechanism that is false against the file being cited is the same error as
// asserting an ordering on no citation — it just reads as caution.
//
// THE HONEST FORM, WHICH IS THE ONE THIS RULE NOW TAKES: apk decides these
// three positions by comparing a token against TOKEN_END in
// apk_version_compare_fuzzy's tail, this file does not model that tail,
// apk-tools' own `test/unit/version.data` contains no row for any of the three
// shapes (it compares `-rN` against `-rM` and against a higher version, never
// `-r0` against an absent revision), AND THEREFORE THE ORDERING IS UNMODELLED
// AND REFUSED. No mechanism is asserted; the refusal rests on what this file
// implements and on what the fixture does not contain, both of which a reader
// can check.
//
// R8 IS EVALUATED AT THE DECIDING POSITION, NOT STRUCTURALLY, so the cost is
// small and falls only where the answer genuinely hangs on the unmodelled
// tail. `1.2.4-r2` against `1.2.5-r0` is decided at the third numeric part and
// never reaches the revision. `1.0` against `1.0.1` is decided by a NON-ZERO
// part against an absence, which every reading agrees on. Only a comparison
// whose result would be DECIDED by "explicit zero versus nothing" is refused.
//
// ---------------------------------------------------------------------------
// CORPUS PROVENANCE
// ---------------------------------------------------------------------------
//
// THE SENTENCE THAT USED TO BE HERE SAID NO VECTOR IN THIS SCHEME HAD EVER
// BEEN DIFFED AGAINST apk-tools' OWN FIXTURE. That is no longer true, and it
// is the largest single change to this file's standing.
//
// apkTranscribed in corpus_transcribed_test.go is apk-tools'
// `test/unit/version.data`: ALL 738 of its `<` / `>` / `=` rows, each carrying
// the line it came from, under a completeness claim carrying the number 738
// that TestTranscriptionClaimsAreTrue checks. 674 of them pass. 64 are refused
// — 58 for R7a's leading zeros, 3 for R7b's commit hashes, and one each for an
// unknown suffix word, a two-letter tail (apk's own row is annotated "invalid.
// do string sort") and a suffix number wider than parseAPKNumber's bound.
// NONE produce a wrong ordering. The 16 fuzzy-operator rows below them
// (`~`, `<~`, `>~`, `!~`) state apk_version_match semantics — a MATCH
// predicate, not an ordering — which this file does not implement at all, and
// they are excluded by the claim rather than dropped silently.
//
// apkValidity transcribes the same file's 31-row validity block, where a
// leading `!` marks a string apk_version_validate rejects. Anvil agrees with
// 30 of them and deviates on one, in the safe direction: `0.1_pre2~1234abcd`
// is valid to apk and refused here by R7b.
//
// WHAT IS STILL AUTHORED RATHER THAN TRANSCRIBED, because the fixture does not
// carry it: the complete walk of the suffix rank table (the fixture exercises
// single steps of it — line 17 `1.1 > 1.1_alpha1`, line 730 `6.0_pre1 < 6.0`,
// line 732 `6.0_p1 > 6.0`), and the three R8 shapes, which appear in no row of
// it at all. Those vectors are tagged AUTHORED and name the rule they come
// from; they may not name a file, because there is no line to name.
package match

import (
	"strconv"
	"strings"
)

// apkSuffixRank is the R4 table, as an ordered ALLOWLIST. The index into
// apkSuffixNames IS the rank, and apkNoSuffixRank sits between the
// pre-release group and the post-release group.
var apkSuffixNames = []string{
	"alpha", "beta", "pre", "rc", // ranks 0..3, before the bare version
	"",                             // rank 4: the bare version itself
	"cvs", "svn", "git", "hg", "p", // ranks 5..9, after the bare version
}

// apkNoSuffixRank is rank 4 — the rank a side with no suffix at a position is
// compared at (R4).
const apkNoSuffixRank = 4

// apkSuffixRank resolves a suffix word to its rank. The empty string is NOT
// resolvable through this function: rank 4 is reachable only by ABSENCE, so an
// input containing a literal empty suffix (`1.0_`) is refused by the parser.
func apkSuffixRank(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	for i, n := range apkSuffixNames {
		if n != "" && n == name {
			return i, true
		}
	}
	return 0, false
}

// apkSuffix is one parsed `_word[number]`.
type apkSuffix struct {
	Rank int
	Num  uint64
	// NumPresent distinguishes `_rc0` from `_rc`, which Num alone cannot.
	// R8 is the only reader: those two are an explicit zero against an
	// absence and this comparator declines to order them.
	NumPresent bool
}

// apkVersion is a parsed Alpine version.
type apkVersion struct {
	// Nums are the dotted numeric parts, at least one.
	Nums []uint64
	// Letter is the single trailing lowercase letter, or 0 when absent.
	Letter byte
	// Suffixes are the `_word[number]` groups in source order.
	Suffixes []apkSuffix
	// Revision is `-rN`; RevisionPresent distinguishes "absent" from "-r0",
	// which Revision alone cannot. R8 is the only reader: those two are an
	// explicit zero against an absence and this comparator declines to
	// order them, where it once called them equal on no citation at all.
	Revision        uint64
	RevisionPresent bool
}

// maxAPKNumber bounds every numeric field. Alpine's own versions are far below
// this; the bound exists so a corrupt feed produces a refusal instead of an
// integer overflow.
const maxAPKNumber = uint64(1) << 40

// parseAPK parses an Alpine version under the R1 grammar, refusing everything
// R7 lists.
func parseAPK(raw string) (apkVersion, error) {
	bad := func(detail string) (apkVersion, error) {
		return apkVersion{}, &Refusal{
			Reason:  RefusalMalformedVersion,
			Scheme:  SchemeAPK,
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
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x21 || c > 0x7e {
			return bad("version contains a non-printable or non-ASCII byte at offset " +
				strconv.Itoa(i))
		}
		// R7b and R7c, checked before any structural parsing so the refusal
		// names the actual reason rather than a downstream symptom.
		if c == '~' {
			return bad("apk fuzzy/commit suffix '~' is not implemented; " +
				"its position in the ordering is not published and this comparator refuses rather than guesses")
		}
		if isASCIIUpper(c) {
			return bad("version contains an uppercase letter at offset " + strconv.Itoa(i) +
				"; the apk grammar's letter is lowercase")
		}
	}

	var v apkVersion
	s := raw

	// R6: split the `-rN` revision off the end first, so no later step has
	// to reason about a hyphen.
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		tail := s[i+1:]
		if len(tail) < 2 || tail[0] != 'r' {
			return bad("'-' is only legal as the revision marker \"-r<number>\", got " +
				strconv.Quote(s[i:]))
		}
		n, err := parseAPKNumber(tail[1:])
		if err != nil {
			return bad("revision: " + err.Error())
		}
		v.Revision = n
		v.RevisionPresent = true
		s = s[:i]
		if strings.IndexByte(s, '-') >= 0 {
			return bad("version carries more than one '-'; only the trailing \"-r<number>\" is legal")
		}
	}
	if s == "" {
		return bad("version is nothing but a revision")
	}

	// R4/R5: split the `_suffix` groups off, right to left is unnecessary —
	// the head is everything before the first '_'.
	parts := strings.Split(s, "_")
	head := parts[0]
	for _, sp := range parts[1:] {
		if sp == "" {
			return bad("empty suffix group (a bare '_')")
		}
		k := 0
		for k < len(sp) && isASCIILower(sp[k]) {
			k++
		}
		word := sp[:k]
		rank, ok := apkSuffixRank(word)
		if !ok {
			return bad("unknown suffix " + strconv.Quote(word) +
				"; the implemented suffixes are alpha, beta, pre, rc, cvs, svn, git, hg, p")
		}
		num := uint64(0)
		numPresent := false
		if k < len(sp) {
			n, err := parseAPKNumber(sp[k:])
			if err != nil {
				return bad("suffix " + strconv.Quote(word) + ": " + err.Error())
			}
			num = n
			numPresent = true
		}
		v.Suffixes = append(v.Suffixes, apkSuffix{Rank: rank, Num: num, NumPresent: numPresent})
	}

	// R1/R3: the head is dotted numbers with an optional single trailing
	// lowercase letter.
	if head == "" {
		return bad("version has no numeric part")
	}
	if isASCIILower(head[len(head)-1]) {
		v.Letter = head[len(head)-1]
		head = head[:len(head)-1]
		if head == "" {
			return bad("version is a bare letter with no numeric part")
		}
		if isASCIILower(head[len(head)-1]) {
			return bad("version carries more than one trailing letter; " +
				"the apk grammar allows exactly one")
		}
	}

	for _, part := range strings.Split(head, ".") {
		n, err := parseAPKNumber(part)
		if err != nil {
			return bad("numeric part: " + err.Error())
		}
		v.Nums = append(v.Nums, n)
	}
	if len(v.Nums) == 0 {
		return bad("version has no numeric part")
	}

	return v, nil
}

// parseAPKNumber parses one unsigned decimal field under R7a: digits only,
// non-empty, and no leading zero unless the whole field is the single digit
// "0".
func parseAPKNumber(s string) (uint64, error) {
	if s == "" {
		return 0, errString("numeric field is empty")
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, errString("numeric field " + strconv.Quote(s) + " is not a number")
		}
	}
	if len(s) > 1 && s[0] == '0' {
		// R7a. src/version.c's token_cmp switches a TOKEN_DIGIT position
		// whose value begins with '0' from numeric comparison to a raw
		// string sort. This function implements the numeric rule only, and
		// test/unit/version.data line 735 (`8.2.0015 < 8.2.002`) is a
		// published row where the two rules disagree — so applying the
		// numeric rule here would produce a wrong ordering, not an
		// approximate one.
		return 0, errString("numeric field " + strconv.Quote(s) +
			" has a leading zero; apk compares such a field by raw string sort and this " +
			"comparator implements only the numeric rule")
	}
	if len(s) > 12 {
		return 0, errString("numeric field " + strconv.Quote(s) + " is implausibly long")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > maxAPKNumber {
		return 0, errString("numeric field " + strconv.Quote(s) + " is out of range")
	}
	return n, nil
}

// compareAPK orders two Alpine version strings, returning -1, 0 or +1.
func compareAPK(a, b string) (int, error) {
	va, err := parseAPK(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseAPK(b)
	if err != nil {
		return 0, err
	}
	r, err := compareAPKParsed(va, vb)
	if err != nil {
		// R8's refusal is built here rather than inside compareAPKParsed so
		// that it can carry BOTH version strings; a refusal that names one
		// operand of a two-operand comparison is a refusal nobody can act
		// on.
		return 0, &Refusal{
			Reason:  RefusalUnmodelledOrdering,
			Scheme:  SchemeAPK,
			Version: a,
			Detail: "ordering " + strconv.Quote(a) + " against " + strconv.Quote(b) +
				" is decided by " + err.Error() +
				", and apk's weight for that token is not published; " +
				"see apk_compare.go rule R8",
		}
	}
	return r, nil
}

// compareAPKParsed applies R2, R3, R4/R5, R6 and R8 in that order.
//
// The error it returns is never a *Refusal — it is the NAME OF THE POSITION
// that could not be decided, which compareAPK wraps with both operands.
func compareAPKParsed(a, b apkVersion) (int, error) {
	// R2/R8: numeric parts. Where both sides have a part, compare it. Where
	// only one side has it, a NON-ZERO part decides and an explicit zero is
	// undecidable.
	n := len(a.Nums)
	if len(b.Nums) > n {
		n = len(b.Nums)
	}
	for i := 0; i < n; i++ {
		switch {
		case i < len(a.Nums) && i < len(b.Nums):
			if r := compareUint(a.Nums[i], b.Nums[i]); r != 0 {
				return r, nil
			}
		case i < len(a.Nums):
			if a.Nums[i] == 0 {
				return 0, errString("an explicit zero numeric part at position " +
					strconv.Itoa(i+1) + " against a version that has no such part")
			}
			return 1, nil
		default:
			if b.Nums[i] == 0 {
				return 0, errString("an explicit zero numeric part at position " +
					strconv.Itoa(i+1) + " against a version that has no such part")
			}
			return -1, nil
		}
	}

	// R3: absent letter sorts below a present one. This one IS published —
	// the grammar puts the letter after the numeric parts and Alpine's
	// documentation states `1.0` < `1.0a` — so it is not an R8 position.
	if a.Letter != b.Letter {
		if a.Letter == 0 {
			return -1, nil
		}
		if b.Letter == 0 {
			return 1, nil
		}
		if a.Letter < b.Letter {
			return -1, nil
		}
		return 1, nil
	}

	// R4/R5/R8: suffixes. A missing suffix is compared at apkNoSuffixRank,
	// which IS published — the rank table places the bare version between
	// `rc` and `cvs`, and that placement is the whole point of the table. A
	// missing suffix NUMBER is a different question: it is an absence, and
	// against an explicit zero it is an R8 position.
	n = len(a.Suffixes)
	if len(b.Suffixes) > n {
		n = len(b.Suffixes)
	}
	for i := 0; i < n; i++ {
		sa := apkSuffixAt(a.Suffixes, i)
		sb := apkSuffixAt(b.Suffixes, i)
		if sa.Rank != sb.Rank {
			if sa.Rank < sb.Rank {
				return -1, nil
			}
			return 1, nil
		}
		// Same rank. The numbers decide, but only one side having a NUMBER
		// at all is the absent-versus-zero question again. apkSuffix.Num is
		// 0 both when the suffix spelled `0` and when it spelled nothing, so
		// the presence flag is what distinguishes them.
		if sa.NumPresent != sb.NumPresent && sa.Num == 0 && sb.Num == 0 {
			return 0, errString("an explicit zero suffix number at suffix " +
				strconv.Itoa(i+1) + " against a suffix that spells no number")
		}
		if r := compareUint(sa.Num, sb.Num); r != 0 {
			return r, nil
		}
	}

	// R6/R8: revision. Same shape: `-r0` against no revision at all is the
	// undecidable pair; `-r0` against `-r1`, and no revision against `-r1`,
	// are both decided.
	if a.RevisionPresent != b.RevisionPresent && a.Revision == 0 && b.Revision == 0 {
		return 0, errString("an explicit \"-r0\" revision against a version that spells no revision")
	}
	return compareUint(a.Revision, b.Revision), nil
}

func apkSuffixAt(ss []apkSuffix, i int) apkSuffix {
	if i < len(ss) {
		return ss[i]
	}
	return apkSuffix{Rank: apkNoSuffixRank, Num: 0}
}

func compareUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
