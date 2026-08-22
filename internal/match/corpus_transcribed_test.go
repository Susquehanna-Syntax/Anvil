// corpus_transcribed_test.go is the TRANSCRIBED half of this package's
// ordering corpus: vectors COPIED, ROW FOR ROW, out of a named published file.
//
// ===========================================================================
// WHY THIS IS A SEPARATE FILE, AND WHY IT IS MECHANICAL
// ===========================================================================
//
// Twice now a header in comparator_test.go has claimed more transcription than
// the corpus held — first an rpm corpus that stopped one row before the first
// row the implementation fails, then a second round in the same section. Both
// times the correction was a rewritten sentence. A rewritten sentence is not a
// fix for a claim that keeps drifting away from the data underneath it; the
// pattern says the claim has to stop being prose.
//
// So the corpus is now SPLIT, and the split is enforced by the type and by
// TestEveryVectorCarriesTheProvenanceItsTagPromises:
//
//	provTranscribed — the row was copied from a named published FILE and
//	                  carries Source (the file) and Locus (the line inside
//	                  it). It may carry no Rule.
//	provAuthored    — the row was WRITTEN BY THIS PROJECT and carries the
//	                  published RULE it is derived from. It may carry no
//	                  Source and no Locus.
//
// There is no third state and no untagged vector: the test rejects a vector
// whose Prov is neither, a TRANSCRIBED vector missing Source or Locus, and an
// AUTHORED vector missing Rule.
//
// COMPLETENESS CLAIMS ARE DATA, NOT PROSE. Every claim of the form "this file
// is transcribed in full" lives in transcriptionClaims below as a (Source,
// Kind, Rows, Count) tuple, and TestTranscriptionClaimsAreTrue counts the
// vectors actually present and fails if the number disagrees. A claim cannot
// be made without carrying its number, because a transcribed vector whose
// Source appears in no claim fails the same test.
//
// THE ROWS BELOW WERE GENERATED, NOT TYPED. The three published files were
// fetched at authoring time and converted to the literals below by a one-line
// text filter each — RPMVERCMP(a, b, want) becomes one vector, "a b want"
// becomes one vector, "a <op> b" becomes one vector — so a transcription error
// would have to be an error in a filter applied uniformly to every row rather
// than a slip on one row. The Locus on every row is the LINE NUMBER in the
// fetched file, so any row can be re-checked by opening the file at that line.
//
//	rpm       tests/rpmvercmp.at        (rpm-software-management/rpm, master)
//	dpkg      scripts/t/Dpkg_Version.t  (guillemj/dpkg, main)
//	apk-tools test/unit/version.data    (alpinelinux/apk-tools, master)
//
// NO TEST IN THIS PACKAGE TOUCHES THE NETWORK. The files were fetched once,
// while this corpus was written, and what is checked in is the transcription.
// That is the honest limitation, and it is the one every offline corpus has: a
// row transcribed from a file that later changes upstream is a row about the
// old file. The mitigation is the Locus, which makes re-checking a mechanical
// diff rather than a re-derivation.
//
// A ROW THIS PACKAGE REFUSES STAYS IN, carrying Refused and a Note saying what
// the published file orders and why Anvil declines. That is the whole reason
// the transcription is complete rather than selective: a corpus that is the
// published suite minus the rows the implementation fails is a corpus filtered
// by the implementation, and this project has already paid once for a table
// validated against its own entries.
package match

// The published files this corpus transcribes from. Every TRANSCRIBED vector
// names one of these, and every one of these carries a completeness claim.
const (
	srcRPMVercmp      = "rpm tests/rpmvercmp.at"
	srcDpkgVersionT   = "dpkg scripts/t/Dpkg_Version.t"
	srcAPKVersionData = "apk-tools test/unit/version.data"
)

// transcriptionClaim is a completeness claim about one published file, stated
// as DATA so TestTranscriptionClaimsAreTrue can check the NUMBER instead of a
// reader having to trust a sentence.
//
// Kind separates the two corpora, because "every comparison row" and "every
// validity row" are different claims about the same file.
type transcriptionClaim struct {
	Source string
	Kind   string
	// Rows says, in the published file's own terms, which of its rows the
	// claim covers. Anything outside it is NOT claimed.
	Rows string
	// Count is how many vectors the claim says are present. The test fails
	// if the corpus holds a different number.
	Count int
}

const (
	kindOrdering = "ordering"
	kindValidity = "validity"
)

var transcriptionClaims = []transcriptionClaim{
	{
		Source: srcRPMVercmp,
		Kind:   kindOrdering,
		Rows: "every ACTIVE RPMVERCMP(a, b, want) line in the file. The two trailing " +
			"sections (RhBug:811992 and the non-ASCII rows) are commented out with m4 " +
			"`dnl` and are not run by rpm's own suite either, so they are not claimed.",
		Count: 91,
	},
	{
		Source: srcDpkgVersionT,
		Kind:   kindOrdering,
		Rows: "every row of the __DATA__ block, which is the comparison table the " +
			"`foreach my $case (@tests)` loop runs.",
		Count: 43,
	},
	{
		Source: srcDpkgVersionT,
		Kind:   kindValidity,
		Rows: "every explicit is_valid() assertion in the \"Handling of empty/invalid " +
			"versions\" block. The has_epoch()/has_revision() block below it asserts " +
			"structure rather than validity and is NOT claimed.",
		Count: 9,
	},
	{
		Source: srcAPKVersionData,
		Kind:   kindOrdering,
		Rows: "every row of the comparison section (lines 1-739) whose operator is " +
			"'<', '>' or '='. The 16 fuzzy-operator rows below it ('~', '<~', '>~', " +
			"'!~') state apk_version_match semantics — a MATCH predicate, not an " +
			"ordering — which this package does not implement at all, so they are " +
			"not claimed.",
		Count: 738,
	},
	{
		Source: srcAPKVersionData,
		Kind:   kindValidity,
		Rows: "every row of the validity section (lines 758-788), where a leading '!' " +
			"marks a string apk_version_validate rejects.",
		Count: 31,
	},
}

// ---------------------------------------------------------------------------
// Notes carried by the rows this package deliberately refuses
// ---------------------------------------------------------------------------

const (
	// noteRPMSeparatorOnly covers the five RhBug:178798 rows whose operands
	// are made ENTIRELY of separator bytes. rpmvercmp skips every byte that
	// is not alphanumeric, '~' or '^', so both sides reduce to nothing and
	// rpm orders them EQUAL. parseRPM refuses such a segment
	// (rpmHasComparableContent): it is not a version, it is a parse failure
	// upstream of here, and calling two of them equal would let two
	// unrelated corrupt rows satisfy each other's range boundaries.
	//
	// FIVE, NOT FOUR. rpm_compare.go's header said four for two rounds
	// running; RPMVERCMP(+, _, 0) is the fifth and it is at line 89.
	noteRPMSeparatorOnly = "rpm orders these EQUAL; parseRPM refuses a version segment with no " +
		"alphanumeric, '~' or '^' character, so Anvil declines to order them"

	// noteAPKLeadingZero is R7a's refusal, justified from the file
	// apk_compare.go cites rather than from a mechanism invented for the
	// occasion.
	//
	// apk-tools src/version.c, token_cmp():
	//
	//	case TOKEN_DIGIT:
	//	    if (ta->value.ptr[0] == '0' || tb->value.ptr[0] == '0') {
	//	        // if either of the digits have a leading zero, use
	//	        // raw string comparison similar to Gentoo spec
	//	        goto use_string_sort;
	//	    }
	//
	// A leading zero does not WEIGHT the part: it switches the comparison
	// at that position from numeric to a byte-wise string sort, which is a
	// second ordering rule. test/unit/version.data line 735 publishes the
	// consequence — 8.2.0015 < 8.2.002, which numeric comparison orders the
	// other way round. apk_compare.go implements the numeric rule only and
	// refuses the operand rather than applying the wrong one.
	noteAPKLeadingZero = "apk compares a numeric part with a leading zero by raw string sort " +
		"(src/version.c token_cmp, \"similar to Gentoo spec\"); apk_compare.go R7a models " +
		"only the numeric rule and refuses the operand rather than applying the wrong one"

	// noteAPKCommitHash is R7b. `~<hex>` is apk's commit-hash suffix; its
	// position relative to a version carrying none is not stated in the
	// grammar comment, and this file's own rows only ever compare one hash
	// against another.
	noteAPKCommitHash = "apk accepts a '~<commit>' suffix; apk_compare.go R7b does not implement " +
		"it and refuses rather than placing it in the ordering by guess"

	// noteAPKUnknownSuffix is R7d, the suffix allowlist. apk itself treats
	// `_foo` as invalid (suffix_value returns SUFFIX_INVALID) and still
	// reaches an ordering, because the initial digit decides before the
	// invalid token is reached. parseAPK refuses the operand outright.
	noteAPKUnknownSuffix = "the suffix word is outside apk_compare.go R4's allowlist; apk reaches an " +
		"ordering here on an earlier token, Anvil refuses the operand at parse time"

	// noteAPKTwoLetters is R7e. apk's own data file annotates this row
	// "# invalid. do string sort" — apk knows the operand is not a version
	// and falls back to a string comparison. Anvil refuses instead.
	noteAPKTwoLetters = "apk's own row is annotated \"invalid. do string sort\"; the apk grammar's " +
		"letter is a single character and parseAPK refuses a longer tail instead of " +
		"falling back to a string comparison"

	// noteAPKSuffixNumberWidth is the numeric-field width bound in
	// parseAPKNumber. `_pre<14-digit timestamp>` is a real Alpine shape and
	// this refusal is a genuine COVERAGE GAP rather than a deviation of
	// principle — which is why it is in the corpus instead of absent from
	// it.
	noteAPKSuffixNumberWidth = "the suffix number is wider than parseAPKNumber's bound; this is a " +
		"COVERAGE GAP in Anvil, recorded here rather than omitted"

	// noteDpkgEmptyRevision is the row that made M1 findable. Dpkg_Version.t
	// asserts `Dpkg::Version->new('1.0-')` is NOT valid — an empty revision
	// is a parse error to dpkg, not a version equal to `1.0`.
	noteDpkgEmptyRevision = "dpkg rejects an empty revision; parseDebian used to accept it and " +
		"silently compare the string as if the trailing '-' were absent"
)

// ---------------------------------------------------------------------------
// rpm: tests/rpmvercmp.at, every active RPMVERCMP line (91)
// ---------------------------------------------------------------------------

var rpmTranscribed = []vector{
	{A: "1.0", B: "1.0", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 12"},
	{A: "1.0", B: "2.0", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 13"},
	{A: "2.0", B: "1.0", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 14"},
	{A: "2.0.1", B: "2.0.1", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 16"},
	{A: "2.0", B: "2.0.1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 17"},
	{A: "2.0.1", B: "2.0", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 18"},
	{A: "2.0.1a", B: "2.0.1a", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 20"},
	{A: "2.0.1a", B: "2.0.1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 21"},
	{A: "2.0.1", B: "2.0.1a", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 22"},
	{A: "5.5p1", B: "5.5p1", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 24"},
	{A: "5.5p1", B: "5.5p2", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 25"},
	{A: "5.5p2", B: "5.5p1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 26"},
	{A: "5.5p10", B: "5.5p10", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 28"},
	{A: "5.5p1", B: "5.5p10", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 29"},
	{A: "5.5p10", B: "5.5p1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 30"},
	{A: "10xyz", B: "10.1xyz", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 32"},
	{A: "10.1xyz", B: "10xyz", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 33"},
	{A: "xyz10", B: "xyz10", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 35"},
	{A: "xyz10", B: "xyz10.1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 36"},
	{A: "xyz10.1", B: "xyz10", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 37"},
	{A: "xyz.4", B: "xyz.4", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 39"},
	{A: "xyz.4", B: "8", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 40"},
	{A: "8", B: "xyz.4", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 41"},
	{A: "xyz.4", B: "2", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 42"},
	{A: "2", B: "xyz.4", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 43"},
	{A: "5.5p2", B: "5.6p1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 45"},
	{A: "5.6p1", B: "5.5p2", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 46"},
	{A: "5.6p1", B: "6.5p1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 48"},
	{A: "6.5p1", B: "5.6p1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 49"},
	{A: "6.0.rc1", B: "6.0", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 51"},
	{A: "6.0", B: "6.0.rc1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 52"},
	{A: "10b2", B: "10a1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 54"},
	{A: "10a2", B: "10b2", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 55"},
	{A: "1.0aa", B: "1.0aa", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 57"},
	{A: "1.0a", B: "1.0aa", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 58"},
	{A: "1.0aa", B: "1.0a", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 59"},
	{A: "10.0001", B: "10.0001", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 61"},
	{A: "10.0001", B: "10.1", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 62"},
	{A: "10.1", B: "10.0001", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 63"},
	{A: "10.0001", B: "10.0039", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 64"},
	{A: "10.0039", B: "10.0001", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 65"},
	{A: "4.999.9", B: "5.0", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 67"},
	{A: "5.0", B: "4.999.9", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 68"},
	{A: "20101121", B: "20101121", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 70"},
	{A: "20101121", B: "20101122", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 71"},
	{A: "20101122", B: "20101121", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 72"},
	{A: "2_0", B: "2_0", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 74"},
	{A: "2.0", B: "2_0", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 75"},
	{A: "2_0", B: "2.0", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 76"},
	{A: "a", B: "a", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 79"},
	{A: "a+", B: "a+", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 80"},
	{A: "a+", B: "a_", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 81"},
	{A: "a_", B: "a+", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 82"},
	{A: "+a", B: "+a", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 83"},
	{A: "+a", B: "_a", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 84"},
	{A: "_a", B: "+a", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 85"},
	{A: "+_", B: "+_", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 86", Refused: true, Note: noteRPMSeparatorOnly},
	{A: "_+", B: "+_", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 87", Refused: true, Note: noteRPMSeparatorOnly},
	{A: "_+", B: "_+", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 88", Refused: true, Note: noteRPMSeparatorOnly},
	{A: "+", B: "_", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 89", Refused: true, Note: noteRPMSeparatorOnly},
	{A: "_", B: "+", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 90", Refused: true, Note: noteRPMSeparatorOnly},
	{A: "1.0~rc1", B: "1.0~rc1", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 93"},
	{A: "1.0~rc1", B: "1.0", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 94"},
	{A: "1.0", B: "1.0~rc1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 95"},
	{A: "1.0~rc1", B: "1.0~rc2", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 96"},
	{A: "1.0~rc2", B: "1.0~rc1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 97"},
	{A: "1.0~rc1~git123", B: "1.0~rc1~git123", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 98"},
	{A: "1.0~rc1~git123", B: "1.0~rc1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 99"},
	{A: "1.0~rc1", B: "1.0~rc1~git123", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 100"},
	{A: "1.0^", B: "1.0^", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 103"},
	{A: "1.0^", B: "1.0", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 104"},
	{A: "1.0", B: "1.0^", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 105"},
	{A: "1.0^git1", B: "1.0^git1", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 106"},
	{A: "1.0^git1", B: "1.0", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 107"},
	{A: "1.0", B: "1.0^git1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 108"},
	{A: "1.0^git1", B: "1.0^git2", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 109"},
	{A: "1.0^git2", B: "1.0^git1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 110"},
	{A: "1.0^git1", B: "1.01", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 111"},
	{A: "1.01", B: "1.0^git1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 112"},
	{A: "1.0^20160101", B: "1.0^20160101", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 113"},
	{A: "1.0^20160101", B: "1.0.1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 114"},
	{A: "1.0.1", B: "1.0^20160101", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 115"},
	{A: "1.0^20160101^git1", B: "1.0^20160101^git1", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 116"},
	{A: "1.0^20160102", B: "1.0^20160101^git1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 117"},
	{A: "1.0^20160101^git1", B: "1.0^20160102", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 118"},
	{A: "1.0~rc1^git1", B: "1.0~rc1^git1", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 121"},
	{A: "1.0~rc1^git1", B: "1.0~rc1", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 122"},
	{A: "1.0~rc1", B: "1.0~rc1^git1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 123"},
	{A: "1.0^git1~pre", B: "1.0^git1~pre", Want: 0, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 124"},
	{A: "1.0^git1", B: "1.0^git1~pre", Want: 1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 125"},
	{A: "1.0^git1~pre", B: "1.0^git1", Want: -1, Prov: provTranscribed, Source: srcRPMVercmp, Locus: "line 126"},
}

// ---------------------------------------------------------------------------
// dpkg: scripts/t/Dpkg_Version.t, every row of the __DATA__ block (43)
// ---------------------------------------------------------------------------

var dpkgTranscribed = []vector{
	{A: "1.0-1", B: "2.0-2", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 239"},
	{A: "2.2~rc-4", B: "2.2-1", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 240"},
	{A: "2.2-1", B: "2.2~rc-4", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 241"},
	{A: "1.0000-1", B: "1.0-1", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 242"},
	{A: "1", B: "0:1", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 243"},
	{A: "0", B: "0:0-0", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 244"},
	{A: "2:2.5", B: "1:7.5", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 245"},
	{A: "1:0foo", B: "0foo", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 246"},
	{A: "0:0foo", B: "0foo", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 247"},
	{A: "0foo", B: "0foo", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 248"},
	{A: "0foo-0", B: "0foo", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 249"},
	{A: "0foo", B: "0foo-0", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 250"},
	{A: "0foo", B: "0fo", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 251"},
	{A: "0foo-0", B: "0foo+", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 252"},
	{A: "0foo~1", B: "0foo", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 253"},
	{A: "0foo~foo+Bar", B: "0foo~foo+bar", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 254"},
	{A: "0foo~~", B: "0foo~", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 255"},
	{A: "1~", B: "1", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 256"},
	{A: "12345+that-really-is-some-ver-0", B: "12345+that-really-is-some-ver-10", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 257"},
	{A: "0foo-0", B: "0foo-01", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 258"},
	{A: "0foo.bar", B: "0foobar", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 259"},
	{A: "0foo.bar", B: "0foo1bar", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 260"},
	{A: "0foo.bar", B: "0foo0bar", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 261"},
	{A: "0foo1bar-1", B: "0foobar-1", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 262"},
	{A: "0foo2.0", B: "0foo2", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 263"},
	{A: "0foo2.0.0", B: "0foo2.10.0", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 264"},
	{A: "0foo2.0", B: "0foo2.0.0", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 265"},
	{A: "0foo2.0", B: "0foo2.10", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 266"},
	{A: "0foo2.1", B: "0foo2.10", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 267"},
	{A: "1.09", B: "1.9", Want: 0, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 268"},
	{A: "1.0.8+nmu1", B: "1.0.8", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 269"},
	{A: "3.11", B: "3.10+nmu1", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 270"},
	{A: "0.9j-20080306-4", B: "0.9i-20070324-2", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 271"},
	{A: "1.2.0~b7-1", B: "1.2.0~b6-1", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 272"},
	{A: "1.011-1", B: "1.06-2", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 273"},
	{A: "0.0.9+dfsg1-1", B: "0.0.8+dfsg1-3", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 274"},
	{A: "4.6.99+svn6582-1", B: "4.6.99+svn6496-1", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 275"},
	{A: "53", B: "52", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 276"},
	{A: "0.9.9~pre122-1", B: "0.9.9~pre111-1", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 277"},
	{A: "2:2.3.2-2+lenny2", B: "2:2.3.2-2", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 278"},
	{A: "1:3.8.1-1", B: "3.8.GA-1", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 279"},
	{A: "1.0.1+gpl-1", B: "1.0.1-2", Want: 1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 280"},
	{A: "1a", B: "1000a", Want: -1, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "__DATA__ line 281"},
}

// ---------------------------------------------------------------------------
// apk-tools: test/unit/version.data, every ordering row (738)
// ---------------------------------------------------------------------------
//
// This is the section A.18 called the weakest of the three, on the grounds that
// not one apk vector had ever been diffed against apk's own fixture. All 738 of
// them now ARE that fixture: 674 pass, 64 are refused for the reasons in the
// Note constants above, and none produce a wrong ordering.

var apkTranscribed = []vector{
	{A: "2.34", B: "0.1.0_alpha", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 1"},
	{A: "23_foo", B: "4_beta", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 2", Refused: true, Note: noteAPKUnknownSuffix},
	{A: "1.0", B: "1.0bc", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 3", Refused: true, Note: noteAPKTwoLetters},
	{A: "0.1.0_alpha", B: "0.1.0_alpha", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 4"},
	{A: "0.1.0_alpha", B: "0.1.3_alpha", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 5"},
	{A: "0.1.3_alpha", B: "0.1.0_alpha", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 6"},
	{A: "0.1.0_alpha2", B: "0.1.0_alpha", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 7"},
	{A: "0.1.0_alpha", B: "2.2.39-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 8"},
	{A: "2.2.39-r1", B: "1.0.4-r3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 9"},
	{A: "1.0.4-r3", B: "1.0.4-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 10"},
	{A: "1.0.4-r4", B: "1.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 11"},
	{A: "1.6", B: "1.0.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 12"},
	{A: "1.0.2", B: "0.7-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 13"},
	{A: "0.7-r1", B: "1.0.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 14"},
	{A: "1.0.0", B: "1.0.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 15"},
	{A: "1.0.1", B: "1.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 16"},
	{A: "1.1", B: "1.1_alpha1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 17"},
	{A: "1.1_alpha1", B: "1.2.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 18"},
	{A: "1.2.1", B: "1.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 19"},
	{A: "1.2", B: "1.3_alpha", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 20"},
	{A: "1.3_alpha", B: "1.3_alpha2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 21"},
	{A: "1.3_alpha2", B: "1.3_alpha3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 22"},
	{A: "1.3_alpha8", B: "0.6.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 23"},
	{A: "0.6.0", B: "0.6.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 24"},
	{A: "0.6.1", B: "0.7.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 25"},
	{A: "0.7.0", B: "0.8_beta1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 26"},
	{A: "0.8_beta1", B: "0.8_beta2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 27"},
	{A: "0.8_beta4", B: "4.8-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 28"},
	{A: "4.8-r1", B: "3.10.18-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 29"},
	{A: "3.10.18-r1", B: "2.3.0b-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 30"},
	{A: "2.3.0b-r1", B: "2.3.0b-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 31"},
	{A: "2.3.0b-r2", B: "2.3.0b-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 32"},
	{A: "2.3.0b-r3", B: "2.3.0b-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 33"},
	{A: "2.3.0b-r4", B: "0.12.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 34"},
	{A: "0.12.1", B: "0.12.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 35"},
	{A: "0.12.2", B: "0.12.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 36"},
	{A: "0.12.3", B: "0.12", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 37"},
	{A: "0.12", B: "0.13_beta1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 38"},
	{A: "0.13_beta1", B: "0.13_beta2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 39"},
	{A: "0.13_beta2", B: "0.13_beta3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 40"},
	{A: "0.13_beta3", B: "0.13_beta4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 41"},
	{A: "0.13_beta4", B: "0.13_beta5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 42"},
	{A: "0.13_beta5", B: "0.9.12", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 43"},
	{A: "0.9.12", B: "0.9.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 44"},
	{A: "0.9.13", B: "0.9.12", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 45"},
	{A: "0.9.12", B: "0.9.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 46"},
	{A: "0.9.13", B: "0.0.16", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 47"},
	{A: "0.0.16", B: "0.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 48"},
	{A: "0.6", B: "2.1.13-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 49"},
	{A: "2.1.13-r3", B: "2.1.15-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 50"},
	{A: "2.1.15-r2", B: "2.1.15-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 51"},
	{A: "2.1.15-r3", B: "1.2.11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 52"},
	{A: "1.2.11", B: "1.2.12.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 53"},
	{A: "1.2.12.1", B: "1.2.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 54"},
	{A: "1.2.13", B: "1.2.14-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 55"},
	{A: "1.2.14-r1", B: "0.7.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 56"},
	{A: "0.7.1", B: "0.5.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 57"},
	{A: "0.5.4", B: "0.7.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 58"},
	{A: "0.7.0", B: "1.2.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 59"},
	{A: "1.2.13", B: "1.0.8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 60"},
	{A: "1.0.8", B: "1.2.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 61"},
	{A: "1.2.1", B: "0.7-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 62"},
	{A: "0.7-r1", B: "2.4.32", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 63"},
	{A: "2.4.32", B: "2.8-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 64"},
	{A: "2.8-r4", B: "0.9.6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 65"},
	{A: "0.9.6", B: "0.2.0-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 66"},
	{A: "0.2.0-r1", B: "0.2.0-r1", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 67"},
	{A: "0.2.0-r1", B: "3.1_p16", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 68"},
	{A: "3.1_p16", B: "3.1_p17", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 69"},
	{A: "3.1_p17", B: "1.06-r6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 70", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.06-r6", B: "006", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 71", Refused: true, Note: noteAPKLeadingZero},
	{A: "006", B: "1.0.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 72", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.0.0", B: "1.2.2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 73"},
	{A: "1.2.2-r1", B: "1.2.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 74"},
	{A: "1.2.2", B: "0.3-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 75"},
	{A: "0.3-r1", B: "9.3.2-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 76"},
	{A: "9.3.2-r4", B: "9.3.4-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 77"},
	{A: "9.3.4-r2", B: "9.3.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 78"},
	{A: "9.3.4", B: "9.3.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 79"},
	{A: "9.3.2", B: "9.3.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 80"},
	{A: "9.3.4", B: "1.1.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 81"},
	{A: "1.1.3", B: "2.16.1-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 82"},
	{A: "2.16.1-r3", B: "2.16.1-r3", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 83"},
	{A: "2.16.1-r3", B: "2.1.0-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 84"},
	{A: "2.1.0-r2", B: "2.9.3-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 85"},
	{A: "2.9.3-r1", B: "0.9-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 86"},
	{A: "0.9-r1", B: "0.8-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 87"},
	{A: "0.8-r1", B: "1.0.6-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 88"},
	{A: "1.0.6-r3", B: "0.11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 89"},
	{A: "0.11", B: "0.12", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 90"},
	{A: "0.12", B: "1.2.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 91"},
	{A: "1.2.1-r1", B: "1.2.2.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 92"},
	{A: "1.2.2.1", B: "1.4.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 93"},
	{A: "1.4.1-r1", B: "1.4.1-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 94"},
	{A: "1.4.1-r2", B: "1.2.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 95"},
	{A: "1.2.2", B: "1.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 96"},
	{A: "1.3", B: "1.0.3-r6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 97"},
	{A: "1.0.3-r6", B: "1.0.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 98"},
	{A: "1.0.4", B: "2.59", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 99"},
	{A: "2.59", B: "20050718-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 100"},
	{A: "20050718-r1", B: "20050718-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 101"},
	{A: "20050718-r2", B: "3.9.8-r5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 102"},
	{A: "3.9.8-r5", B: "2.01.01_alpha10", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 103", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.01.01_alpha10", B: "0.94", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 104", Refused: true, Note: noteAPKLeadingZero},
	{A: "0.94", B: "1.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 105"},
	{A: "1.0", B: "0.99.3.20040818", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 106"},
	{A: "0.99.3.20040818", B: "0.7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 107"},
	{A: "0.7", B: "1.21-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 108"},
	{A: "1.21-r1", B: "0.13", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 109"},
	{A: "0.13", B: "0.90.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 110"},
	{A: "0.90.1-r1", B: "0.10.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 111"},
	{A: "0.10.2", B: "0.10.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 112"},
	{A: "0.10.3", B: "1.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 113"},
	{A: "1.6", B: "1.39", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 114"},
	{A: "1.39", B: "1.00_beta2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 115", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.00_beta2", B: "0.9.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 116", Refused: true, Note: noteAPKLeadingZero},
	{A: "0.9.2", B: "5.94-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 117"},
	{A: "5.94-r1", B: "6.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 118"},
	{A: "6.4", B: "2.6-r5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 119"},
	{A: "2.6-r5", B: "1.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 120"},
	{A: "1.4", B: "2.8.9-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 121"},
	{A: "2.8.9-r1", B: "2.8.9", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 122"},
	{A: "2.8.9", B: "1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 123"},
	{A: "1.1", B: "1.0.3-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 124"},
	{A: "1.0.3-r2", B: "1.3.4-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 125"},
	{A: "1.3.4-r3", B: "2.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 126"},
	{A: "2.2", B: "1.2.6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 127"},
	{A: "1.2.6", B: "7.15.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 128"},
	{A: "7.15.1-r1", B: "1.02", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 129", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.02", B: "1.03-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 130", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.03-r1", B: "1.12.12-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 131", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.12.12-r2", B: "2.8.0.6-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 132"},
	{A: "2.8.0.6-r1", B: "0.5.2.7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 133"},
	{A: "0.5.2.7", B: "4.2.52_p2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 134"},
	{A: "4.2.52_p2-r1", B: "4.2.52_p4-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 135"},
	{A: "4.2.52_p4-r2", B: "1.02.07", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 136", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.02.07", B: "1.02.10-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 137", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.02.10-r1", B: "3.0.3-r9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 138", Refused: true, Note: noteAPKLeadingZero},
	{A: "3.0.3-r9", B: "2.0.5-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 139"},
	{A: "2.0.5-r1", B: "4.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 140"},
	{A: "4.5", B: "2.8.7-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 141"},
	{A: "2.8.7-r1", B: "1.0.5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 142"},
	{A: "1.0.5", B: "8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 143"},
	{A: "8", B: "9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 144"},
	{A: "9", B: "2.18.3-r10", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 145"},
	{A: "2.18.3-r10", B: "1.05-r18", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 146", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.05-r18", B: "1.05-r19", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 147", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.05-r19", B: "2.2.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 148", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.2.5", B: "2.8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 149"},
	{A: "2.8", B: "2.20.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 150"},
	{A: "2.20.1", B: "2.20.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 151"},
	{A: "2.20.3", B: "2.31", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 152"},
	{A: "2.31", B: "2.34", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 153"},
	{A: "2.34", B: "2.38", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 154"},
	{A: "2.38", B: "20050405", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 155"},
	{A: "20050405", B: "1.8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 156"},
	{A: "1.8", B: "2.11-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 157"},
	{A: "2.11-r1", B: "2.11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 158"},
	{A: "2.11", B: "0.1.6-r3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 159"},
	{A: "0.1.6-r3", B: "0.47-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 160"},
	{A: "0.47-r1", B: "0.49", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 161"},
	{A: "0.49", B: "3.6.8-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 162"},
	{A: "3.6.8-r2", B: "1.39", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 163"},
	{A: "1.39", B: "2.43", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 164"},
	{A: "2.43", B: "2.0.6-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 165"},
	{A: "2.0.6-r1", B: "0.2-r6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 166"},
	{A: "0.2-r6", B: "0.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 167"},
	{A: "0.4", B: "1.0.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 168"},
	{A: "1.0.0", B: "10-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 169"},
	{A: "10-r1", B: "4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 170"},
	{A: "4", B: "0.7.3-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 171"},
	{A: "0.7.3-r2", B: "0.7.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 172"},
	{A: "0.7.3", B: "1.95.8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 173"},
	{A: "1.95.8", B: "1.1.19", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 174"},
	{A: "1.1.19", B: "1.1.5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 175"},
	{A: "1.1.5", B: "6.3.2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 176"},
	{A: "6.3.2-r1", B: "6.3.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 177"},
	{A: "6.3.3", B: "4.17-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 178"},
	{A: "4.17-r1", B: "4.18", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 179"},
	{A: "4.18", B: "4.19", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 180"},
	{A: "4.19", B: "4.3.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 181"},
	{A: "4.3.0", B: "4.3.2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 182"},
	{A: "4.3.2-r1", B: "4.3.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 183"},
	{A: "4.3.2", B: "0.68-r3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 184"},
	{A: "0.68-r3", B: "1.0.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 185"},
	{A: "1.0.0", B: "1.0.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 186"},
	{A: "1.0.1", B: "1.0.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 187"},
	{A: "1.0.0", B: "1.0.0", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 188"},
	{A: "1.0.0", B: "1.0.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 189"},
	{A: "1.0.1", B: "2.3.2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 190"},
	{A: "2.3.2-r1", B: "2.4.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 191"},
	{A: "2.4.2", B: "20060720", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 192"},
	{A: "20060720", B: "3.0.20060720", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 193"},
	{A: "3.0.20060720", B: "20060720", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 194"},
	{A: "20060720", B: "1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 195"},
	{A: "1.1", B: "1.1", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 196"},
	{A: "1.1", B: "1.1.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 197"},
	{A: "1.1.1-r1", B: "1.1.3-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 198"},
	{A: "1.1.3-r1", B: "1.1.3-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 199"},
	{A: "1.1.3-r2", B: "2.1.10-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 200"},
	{A: "2.1.10-r2", B: "0.7.18-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 201"},
	{A: "0.7.18-r2", B: "0.17-r6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 202"},
	{A: "0.17-r6", B: "2.6.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 203"},
	{A: "2.6.1", B: "2.6.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 204"},
	{A: "2.6.3", B: "3.1.5-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 205"},
	{A: "3.1.5-r2", B: "3.4.6-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 206"},
	{A: "3.4.6-r1", B: "3.4.6-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 207"},
	{A: "3.4.6-r2", B: "3.4.6-r2", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 208"},
	{A: "3.4.6-r2", B: "2.0.33", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 209"},
	{A: "2.0.33", B: "2.0.34", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 210"},
	{A: "2.0.34", B: "1.8.3-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 211"},
	{A: "1.8.3-r2", B: "1.8.3-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 212"},
	{A: "1.8.3-r3", B: "4.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 213"},
	{A: "4.1", B: "8.54", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 214"},
	{A: "8.54", B: "4.1.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 215"},
	{A: "4.1.4", B: "1.2.10-r5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 216"},
	{A: "1.2.10-r5", B: "4.1.4-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 217"},
	{A: "4.1.4-r3", B: "4.1.4-r3", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 218"},
	{A: "4.1.4-r3", B: "4.2.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 219"},
	{A: "4.2.1", B: "4.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 220"},
	{A: "4.1.0", B: "8.11", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 221"},
	{A: "8.11", B: "1.4.4-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 222"},
	{A: "1.4.4-r1", B: "2.1.9.200602141850", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 223"},
	{A: "2.1.9.200602141850", B: "1.6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 224"},
	{A: "1.6", B: "2.5.1-r8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 225"},
	{A: "2.5.1-r8", B: "2.5.1a-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 226"},
	{A: "2.5.1a-r1", B: "1.19.2-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 227"},
	{A: "1.19.2-r1", B: "0.97-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 228"},
	{A: "0.97-r2", B: "0.97-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 229"},
	{A: "0.97-r3", B: "1.3.5-r10", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 230"},
	{A: "1.3.5-r10", B: "1.3.5-r8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 231"},
	{A: "1.3.5-r8", B: "1.3.5-r9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 232"},
	{A: "1.3.5-r9", B: "1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 233"},
	{A: "1.0", B: "1.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 234"},
	{A: "1.1", B: "0.9.11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 235"},
	{A: "0.9.11", B: "0.9.12", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 236"},
	{A: "0.9.12", B: "0.9.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 237"},
	{A: "0.9.13", B: "0.9.14", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 238"},
	{A: "0.9.14", B: "0.9.15", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 239"},
	{A: "0.9.15", B: "0.9.16", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 240"},
	{A: "0.9.16", B: "0.3-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 241"},
	{A: "0.3-r2", B: "6.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 242"},
	{A: "6.3", B: "6.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 243"},
	{A: "6.6", B: "6.9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 244"},
	{A: "6.9", B: "0.7.2-r3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 245"},
	{A: "0.7.2-r3", B: "1.2.10", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 246"},
	{A: "1.2.10", B: "20040923-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 247"},
	{A: "20040923-r2", B: "20040401", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 248"},
	{A: "20040401", B: "2.0.0_rc3-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 249"},
	{A: "2.0.0_rc3-r1", B: "1.5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 250"},
	{A: "1.5", B: "4.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 251"},
	{A: "4.4", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 252"},
	{A: "1.0.1", B: "2.2.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 253"},
	{A: "2.2.0", B: "1.1.0-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 254"},
	{A: "1.1.0-r2", B: "0.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 255"},
	{A: "0.3", B: "20020207-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 256"},
	{A: "20020207-r2", B: "1.31-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 257"},
	{A: "1.31-r2", B: "3.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 258"},
	{A: "3.7", B: "2.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 259"},
	{A: "2.0.1", B: "2.0.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 260"},
	{A: "2.0.2", B: "0.99.163", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 261"},
	{A: "0.99.163", B: "2.6.15.20060110", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 262"},
	{A: "2.6.15.20060110", B: "2.6.16.20060323", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 263"},
	{A: "2.6.16.20060323", B: "2.6.19.20061214", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 264"},
	{A: "2.6.19.20061214", B: "0.6.2-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 265"},
	{A: "0.6.2-r1", B: "0.6.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 266"},
	{A: "0.6.3", B: "0.6.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 267"},
	{A: "0.6.5", B: "1.3.5-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 268"},
	{A: "1.3.5-r1", B: "1.3.5-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 269"},
	{A: "1.3.5-r4", B: "3.0.0-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 270"},
	{A: "3.0.0-r2", B: "021109-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 271", Refused: true, Note: noteAPKLeadingZero},
	{A: "021109-r3", B: "20060512", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 272", Refused: true, Note: noteAPKLeadingZero},
	{A: "20060512", B: "1.24", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 273"},
	{A: "1.24", B: "0.9.16-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 274"},
	{A: "0.9.16-r1", B: "3.9_pre20060124", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 275"},
	{A: "3.9_pre20060124", B: "0.01", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 276", Refused: true, Note: noteAPKLeadingZero},
	{A: "0.01", B: "0.06", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 277", Refused: true, Note: noteAPKLeadingZero},
	{A: "0.06", B: "1.1.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 278", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.1.7", B: "6b-r7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 279"},
	{A: "6b-r7", B: "1.12-r7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 280"},
	{A: "1.12-r7", B: "1.12-r8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 281"},
	{A: "1.12-r8", B: "1.1.12", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 282"},
	{A: "1.1.12", B: "1.1.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 283"},
	{A: "1.1.13", B: "0.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 284"},
	{A: "0.3", B: "0.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 285"},
	{A: "0.5", B: "3.96.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 286"},
	{A: "3.96.1", B: "3.97", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 287"},
	{A: "3.97", B: "0.10.0-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 288"},
	{A: "0.10.0-r1", B: "0.10.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 289"},
	{A: "0.10.0", B: "0.10.1_rc1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 290"},
	{A: "0.10.1_rc1", B: "0.9.11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 291"},
	{A: "0.9.11", B: "394", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 292"},
	{A: "394", B: "2.31", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 293"},
	{A: "2.31", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 294"},
	{A: "1.0.1", B: "1.0.1", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 295"},
	{A: "1.0.1", B: "1.0.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 296"},
	{A: "1.0.3", B: "1.0.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 297"},
	{A: "1.0.2", B: "1.0.2", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 298"},
	{A: "1.0.2", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 299"},
	{A: "1.0.1", B: "1.0.1", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 300"},
	{A: "1.0.1", B: "1.2.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 301"},
	{A: "1.2.2", B: "2.1.10", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 302"},
	{A: "2.1.10", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 303"},
	{A: "1.0.1", B: "1.0.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 304"},
	{A: "1.0.2", B: "3.5.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 305"},
	{A: "3.5.5", B: "1.1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 306"},
	{A: "1.1.1", B: "0.9.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 307"},
	{A: "0.9.1", B: "1.0.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 308"},
	{A: "1.0.2", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 309"},
	{A: "1.0.1", B: "1.0.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 310"},
	{A: "1.0.2", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 311"},
	{A: "1.0.1", B: "1.0.1", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 312"},
	{A: "1.0.1", B: "1.0.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 313"},
	{A: "1.0.5", B: "0.8.5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 314"},
	{A: "0.8.5", B: "0.8.6-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 315"},
	{A: "0.8.6-r3", B: "2.3.17", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 316"},
	{A: "2.3.17", B: "1.10-r5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 317"},
	{A: "1.10-r5", B: "1.10-r9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 318"},
	{A: "1.10-r9", B: "2.0.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 319"},
	{A: "2.0.2", B: "1.1a", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 320"},
	{A: "1.1a", B: "1.3a", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 321"},
	{A: "1.3a", B: "1.0.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 322"},
	{A: "1.0.2", B: "1.2.2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 323"},
	{A: "1.2.2-r1", B: "1.0-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 324"},
	{A: "1.0-r1", B: "0.15.1b", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 325"},
	{A: "0.15.1b", B: "1.0.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 326"},
	{A: "1.0.1", B: "1.06-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 327", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.06-r1", B: "1.06-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 328", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.06-r2", B: "0.15.1b-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 329", Refused: true, Note: noteAPKLeadingZero},
	{A: "0.15.1b-r2", B: "0.15.1b", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 330"},
	{A: "0.15.1b", B: "2.5.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 331"},
	{A: "2.5.7", B: "1.1.2.1-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 332"},
	{A: "1.1.2.1-r1", B: "0.0.31", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 333"},
	{A: "0.0.31", B: "0.0.50", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 334"},
	{A: "0.0.50", B: "0.0.16", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 335"},
	{A: "0.0.16", B: "0.0.25", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 336"},
	{A: "0.0.25", B: "0.17", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 337"},
	{A: "0.17", B: "0.5.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 338"},
	{A: "0.5.0", B: "1.1.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 339"},
	{A: "1.1.2", B: "1.1.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 340"},
	{A: "1.1.3", B: "1.1.20", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 341"},
	{A: "1.1.20", B: "0.9.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 342"},
	{A: "0.9.4", B: "0.9.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 343"},
	{A: "0.9.5", B: "6.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 344"},
	{A: "6.3", B: "6.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 345"},
	{A: "6.6", B: "6.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 346"},
	{A: "6.3", B: "6.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 347"},
	{A: "6.6", B: "1.2.12-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 348"},
	{A: "1.2.12-r1", B: "1.2.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 349"},
	{A: "1.2.13", B: "1.2.14", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 350"},
	{A: "1.2.14", B: "1.2.15", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 351"},
	{A: "1.2.15", B: "8.0.12", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 352"},
	{A: "8.0.12", B: "8.0.9", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 353"},
	{A: "8.0.9", B: "1.2.3-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 354"},
	{A: "1.2.3-r1", B: "1.2.4-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 355"},
	{A: "1.2.4-r1", B: "0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 356"},
	{A: "0.1", B: "0.3.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 357"},
	{A: "0.3.5", B: "1.5.22", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 358"},
	{A: "1.5.22", B: "0.1.11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 359"},
	{A: "0.1.11", B: "0.1.12", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 360"},
	{A: "0.1.12", B: "1.1.4.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 361"},
	{A: "1.1.4.1", B: "1.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 362"},
	{A: "1.1.0", B: "1.1.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 363"},
	{A: "1.1.2", B: "1.0.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 364"},
	{A: "1.0.3", B: "1.0.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 365"},
	{A: "1.0.2", B: "2.6.26", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 366"},
	{A: "2.6.26", B: "2.6.27", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 367"},
	{A: "2.6.27", B: "1.1.17", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 368"},
	{A: "1.1.17", B: "1.4.11", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 369"},
	{A: "1.4.11", B: "22.7-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 370"},
	{A: "22.7-r1", B: "22.7.3-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 371"},
	{A: "22.7.3-r1", B: "22.7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 372"},
	{A: "22.7", B: "2.1_pre20", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 373"},
	{A: "2.1_pre20", B: "2.1_pre26", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 374"},
	{A: "2.1_pre26", B: "0.2.3-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 375"},
	{A: "0.2.3-r2", B: "0.2.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 376"},
	{A: "0.2.2", B: "2.10.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 377"},
	{A: "2.10.0", B: "2.10.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 378"},
	{A: "2.10.1", B: "02.08.01b", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 379", Refused: true, Note: noteAPKLeadingZero},
	{A: "02.08.01b", B: "4.77", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 380", Refused: true, Note: noteAPKLeadingZero},
	{A: "4.77", B: "0.17", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 381"},
	{A: "0.17", B: "5.1.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 382"},
	{A: "5.1.1-r1", B: "5.1.1-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 383"},
	{A: "5.1.1-r2", B: "5.1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 384"},
	{A: "5.1.1", B: "1.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 385"},
	{A: "1.2", B: "5.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 386"},
	{A: "5.1", B: "2.02.06", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 387", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.02.06", B: "2.02.10", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 388", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.02.10", B: "2.8.5-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 389", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.8.5-r3", B: "2.8.6-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 390"},
	{A: "2.8.6-r1", B: "2.8.6-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 391"},
	{A: "2.8.6-r2", B: "2.02-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 392", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.02-r1", B: "1.5.0-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 393", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.5.0-r1", B: "1.5.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 394"},
	{A: "1.5.0", B: "0.9.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 395"},
	{A: "0.9.2", B: "8.1.2.20040524-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 396"},
	{A: "8.1.2.20040524-r1", B: "8.1.2.20050715-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 397"},
	{A: "8.1.2.20050715-r1", B: "20030215", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 398"},
	{A: "20030215", B: "3.80-r4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 399"},
	{A: "3.80-r4", B: "3.81", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 400"},
	{A: "3.81", B: "1.6d", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 401"},
	{A: "1.6d", B: "1.2.07.8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 402", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.2.07.8", B: "1.2.12.04", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 403", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.2.12.04", B: "1.2.12.05", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 404", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.2.12.05", B: "1.3.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 405", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.3.3", B: "2.6.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 406"},
	{A: "2.6.4", B: "2.5.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 407"},
	{A: "2.5.2", B: "2.6.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 408"},
	{A: "2.6.1", B: "2.6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 409"},
	{A: "2.6", B: "6.5.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 410"},
	{A: "6.5.1-r1", B: "1.1.35-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 411"},
	{A: "1.1.35-r1", B: "1.1.35-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 412"},
	{A: "1.1.35-r2", B: "0.9.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 413"},
	{A: "0.9.2", B: "1.07-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 414", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.07-r1", B: "1.07.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 415", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.07.5", B: "1.07", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 416", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.07", B: "1.19", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 417", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.19", B: "2.1-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 418"},
	{A: "2.1-r2", B: "2.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 419"},
	{A: "2.2", B: "1.0.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 420"},
	{A: "1.0.4", B: "20060811", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 421"},
	{A: "20060811", B: "20061003", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 422"},
	{A: "20061003", B: "0.1_pre20060810", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 423"},
	{A: "0.1_pre20060810", B: "0.1_pre20060817", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 424"},
	{A: "0.1_pre20060817", B: "1.0.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 425"},
	{A: "1.0.3", B: "1.0.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 426"},
	{A: "1.0.2", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 427"},
	{A: "1.0.1", B: "3.2.2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 428"},
	{A: "3.2.2-r1", B: "3.2.2-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 429"},
	{A: "3.2.2-r2", B: "3.3.17", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 430"},
	{A: "3.3.17", B: "0.59s-r11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 431"},
	{A: "0.59s-r11", B: "0.65", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 432"},
	{A: "0.65", B: "0.2.10-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 433"},
	{A: "0.2.10-r2", B: "2.01", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 434", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.01", B: "3.9.10", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 435", Refused: true, Note: noteAPKLeadingZero},
	{A: "3.9.10", B: "1.2.18", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 436"},
	{A: "1.2.18", B: "1.5.11-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 437"},
	{A: "1.5.11-r2", B: "1.5.13-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 438"},
	{A: "1.5.13-r1", B: "1.3.12-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 439"},
	{A: "1.3.12-r1", B: "2.0.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 440"},
	{A: "2.0.1", B: "2.0.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 441"},
	{A: "2.0.2", B: "2.0.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 442"},
	{A: "2.0.3", B: "0.2.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 443"},
	{A: "0.2.0", B: "5.5-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 444"},
	{A: "5.5-r2", B: "5.5-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 445"},
	{A: "5.5-r3", B: "0.25.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 446"},
	{A: "0.25.3", B: "0.26.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 447"},
	{A: "0.26.1-r1", B: "5.2.1.2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 448"},
	{A: "5.2.1.2-r1", B: "5.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 449"},
	{A: "5.4", B: "1.60-r11", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 450"},
	{A: "1.60-r11", B: "1.60-r12", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 451"},
	{A: "1.60-r12", B: "110-r8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 452"},
	{A: "110-r8", B: "0.17-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 453"},
	{A: "0.17-r2", B: "1.05-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 454", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.05-r4", B: "5.28.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 455", Refused: true, Note: noteAPKLeadingZero},
	{A: "5.28.0", B: "0.51.6-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 456"},
	{A: "0.51.6-r1", B: "1.0.6-r6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 457"},
	{A: "1.0.6-r6", B: "0.8.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 458"},
	{A: "0.8.3", B: "1.42", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 459"},
	{A: "1.42", B: "20030719", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 460"},
	{A: "20030719", B: "4.01", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 461", Refused: true, Note: noteAPKLeadingZero},
	{A: "4.01", B: "4.20", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 462", Refused: true, Note: noteAPKLeadingZero},
	{A: "4.20", B: "0.20070118", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 463"},
	{A: "0.20070118", B: "0.20070207_rc1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 464"},
	{A: "0.20070207_rc1", B: "1.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 465"},
	{A: "1.0", B: "1.13.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 466"},
	{A: "1.13.0", B: "1.13.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 467"},
	{A: "1.13.1", B: "0.21", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 468"},
	{A: "0.21", B: "0.3.7-r3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 469"},
	{A: "0.3.7-r3", B: "0.4.10", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 470"},
	{A: "0.4.10", B: "0.5.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 471"},
	{A: "0.5.0", B: "0.5.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 472"},
	{A: "0.5.5", B: "0.5.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 473"},
	{A: "0.5.7", B: "0.6.11-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 474"},
	{A: "0.6.11-r1", B: "2.3.30-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 475"},
	{A: "2.3.30-r2", B: "3.7_p1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 476"},
	{A: "3.7_p1", B: "1.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 477"},
	{A: "1.3", B: "0.10.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 478"},
	{A: "0.10.1", B: "4.3_p2-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 479"},
	{A: "4.3_p2-r1", B: "4.3_p2-r5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 480"},
	{A: "4.3_p2-r5", B: "4.4_p1-r6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 481"},
	{A: "4.4_p1-r6", B: "4.5_p1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 482"},
	{A: "4.5_p1-r1", B: "4.5_p1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 483"},
	{A: "4.5_p1", B: "4.5_p1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 484"},
	{A: "4.5_p1-r1", B: "4.5_p1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 485"},
	{A: "4.5_p1", B: "0.9.8c-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 486"},
	{A: "0.9.8c-r1", B: "0.9.8d", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 487"},
	{A: "0.9.8d", B: "2.4.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 488"},
	{A: "2.4.4", B: "2.4.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 489"},
	{A: "2.4.7", B: "2.0.6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 490"},
	{A: "2.0.6", B: "2.0.6", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 491"},
	{A: "2.0.6", B: "0.78-r3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 492"},
	{A: "0.78-r3", B: "0.3.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 493"},
	{A: "0.3.2", B: "1.7.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 494"},
	{A: "1.7.1-r1", B: "2.5.9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 495"},
	{A: "2.5.9", B: "0.1.13", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 496"},
	{A: "0.1.13", B: "0.1.15", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 497"},
	{A: "0.1.15", B: "0.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 498"},
	{A: "0.4", B: "0.9.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 499"},
	{A: "0.9.6", B: "2.2.0-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 500"},
	{A: "2.2.0-r1", B: "2.2.3-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 501"},
	{A: "2.2.3-r2", B: "013", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 502", Refused: true, Note: noteAPKLeadingZero},
	{A: "013", B: "014-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 503", Refused: true, Note: noteAPKLeadingZero},
	{A: "014-r1", B: "1.3.1-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 504", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.3.1-r1", B: "5.8.8-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 505"},
	{A: "5.8.8-r2", B: "5.1.6-r4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 506"},
	{A: "5.1.6-r4", B: "5.1.6-r6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 507"},
	{A: "5.1.6-r6", B: "5.2.1-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 508"},
	{A: "5.2.1-r3", B: "0.11.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 509"},
	{A: "0.11.3", B: "0.11.3", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 510"},
	{A: "0.11.3", B: "1.10.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 511"},
	{A: "1.10.7", B: "1.7-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 512"},
	{A: "1.7-r1", B: "0.1.20", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 513"},
	{A: "0.1.20", B: "0.1.23", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 514"},
	{A: "0.1.23", B: "5b-r9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 515"},
	{A: "5b-r9", B: "2.2.10", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 516"},
	{A: "2.2.10", B: "2.3.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 517"},
	{A: "2.3.6", B: "8.0.12", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 518"},
	{A: "8.0.12", B: "2.4.3-r16", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 519"},
	{A: "2.4.3-r16", B: "2.4.4-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 520"},
	{A: "2.4.4-r4", B: "3.0.3-r5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 521"},
	{A: "3.0.3-r5", B: "3.0.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 522"},
	{A: "3.0.6", B: "3.2.6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 523"},
	{A: "3.2.6", B: "3.2.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 524"},
	{A: "3.2.7", B: "0.3.1_rc8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 525"},
	{A: "0.3.1_rc8", B: "22.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 526"},
	{A: "22.2", B: "22.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 527"},
	{A: "22.3", B: "1.2.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 528"},
	{A: "1.2.2", B: "2.04", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 529", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.04", B: "2.4.3-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 530", Refused: true, Note: noteAPKLeadingZero},
	{A: "2.4.3-r1", B: "2.4.3-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 531"},
	{A: "2.4.3-r4", B: "0.98.6-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 532"},
	{A: "0.98.6-r1", B: "5.7-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 533"},
	{A: "5.7-r2", B: "5.7-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 534"},
	{A: "5.7-r3", B: "5.1_p4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 535"},
	{A: "5.1_p4", B: "1.0.5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 536"},
	{A: "1.0.5", B: "3.6.19-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 537"},
	{A: "3.6.19-r1", B: "3.6.19", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 538"},
	{A: "3.6.19", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 539"},
	{A: "1.0.1", B: "3.8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 540"},
	{A: "3.8", B: "0.2.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 541"},
	{A: "0.2.3", B: "1.2.15-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 542"},
	{A: "1.2.15-r3", B: "1.2.6-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 543"},
	{A: "1.2.6-r1", B: "2.6.8-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 544"},
	{A: "2.6.8-r2", B: "2.6.9-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 545"},
	{A: "2.6.9-r1", B: "1.7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 546"},
	{A: "1.7", B: "1.7b", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 547"},
	{A: "1.7b", B: "1.8.4-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 548"},
	{A: "1.8.4-r3", B: "1.8.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 549"},
	{A: "1.8.5", B: "1.8.5_p2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 550"},
	{A: "1.8.5_p2", B: "1.1.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 551"},
	{A: "1.1.3", B: "3.0.22-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 552"},
	{A: "3.0.22-r3", B: "3.0.24", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 553"},
	{A: "3.0.24", B: "3.0.24", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 554"},
	{A: "3.0.24", B: "3.0.24", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 555"},
	{A: "3.0.24", B: "4.0.2-r5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 556"},
	{A: "4.0.2-r5", B: "4.0.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 557"},
	{A: "4.0.3", B: "0.98", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 558"},
	{A: "0.98", B: "1.00", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 559", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.00", B: "4.1.4-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 560", Refused: true, Note: noteAPKLeadingZero},
	{A: "4.1.4-r1", B: "4.1.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 561"},
	{A: "4.1.5", B: "2.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 562"},
	{A: "2.3", B: "2.17-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 563"},
	{A: "2.17-r3", B: "0.1.7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 564"},
	{A: "0.1.7", B: "1.11", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 565"},
	{A: "1.11", B: "4.2.1-r11", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 566"},
	{A: "4.2.1-r11", B: "3.2.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 567"},
	{A: "3.2.3", B: "3.2.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 568"},
	{A: "3.2.4", B: "3.2.8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 569"},
	{A: "3.2.8", B: "3.2.9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 570"},
	{A: "3.2.9", B: "3.2.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 571"},
	{A: "3.2.3", B: "3.2.4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 572"},
	{A: "3.2.4", B: "3.2.8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 573"},
	{A: "3.2.8", B: "3.2.9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 574"},
	{A: "3.2.9", B: "1.4.9-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 575"},
	{A: "1.4.9-r2", B: "2.9.11_pre20051101-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 576"},
	{A: "2.9.11_pre20051101-r2", B: "2.9.11_pre20051101-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 577"},
	{A: "2.9.11_pre20051101-r3", B: "2.9.11_pre20051101", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 578"},
	{A: "2.9.11_pre20051101", B: "2.9.11_pre20061021-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 579"},
	{A: "2.9.11_pre20061021-r1", B: "2.9.11_pre20061021-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 580"},
	{A: "2.9.11_pre20061021-r2", B: "5.36-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 581"},
	{A: "5.36-r1", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 582"},
	{A: "1.0.1", B: "7.0-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 583"},
	{A: "7.0-r2", B: "2.4.5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 584"},
	{A: "2.4.5", B: "2.6.1.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 585"},
	{A: "2.6.1.2", B: "2.6.1.3-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 586"},
	{A: "2.6.1.3-r1", B: "2.6.1.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 587"},
	{A: "2.6.1.3", B: "2.6.1.3-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 588"},
	{A: "2.6.1.3-r1", B: "12.17.9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 589"},
	{A: "12.17.9", B: "1.1.12", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 590"},
	{A: "1.1.12", B: "1.1.7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 591"},
	{A: "1.1.7", B: "2.5.14", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 592"},
	{A: "2.5.14", B: "2.6.6-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 593"},
	{A: "2.6.6-r1", B: "2.6.7", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 594"},
	{A: "2.6.7", B: "2.6.9-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 595"},
	{A: "2.6.9-r1", B: "2.6.9", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 596"},
	{A: "2.6.9", B: "1.39", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 597"},
	{A: "1.39", B: "0.9", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 598"},
	{A: "0.9", B: "2.61-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 599"},
	{A: "2.61-r2", B: "4.5.14", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 600"},
	{A: "4.5.14", B: "4.09-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 601", Refused: true, Note: noteAPKLeadingZero},
	{A: "4.09-r1", B: "1.3.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 602", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.3.1", B: "1.3.2-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 603"},
	{A: "1.3.2-r3", B: "1.6.8_p12-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 604"},
	{A: "1.6.8_p12-r1", B: "1.6.8_p9-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 605"},
	{A: "1.6.8_p9-r2", B: "1.3.0-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 606"},
	{A: "1.3.0-r1", B: "3.11", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 607"},
	{A: "3.11", B: "3.20", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 608"},
	{A: "3.20", B: "1.6.11-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 609"},
	{A: "1.6.11-r1", B: "1.6.9", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 610"},
	{A: "1.6.9", B: "5.0.5-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 611"},
	{A: "5.0.5-r2", B: "2.86-r5", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 612"},
	{A: "2.86-r5", B: "2.86-r6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 613"},
	{A: "2.86-r6", B: "1.15.1-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 614"},
	{A: "1.15.1-r1", B: "8.4.9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 615"},
	{A: "8.4.9", B: "7.6-r8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 616"},
	{A: "7.6-r8", B: "3.9.4-r2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 617"},
	{A: "3.9.4-r2", B: "3.9.4-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 618"},
	{A: "3.9.4-r3", B: "3.9.5-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 619"},
	{A: "3.9.5-r2", B: "1.1.9", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 620"},
	{A: "1.1.9", B: "1.0.6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 621"},
	{A: "1.0.6", B: "5.9", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 622"},
	{A: "5.9", B: "6.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 623"},
	{A: "6.5", B: "0.40-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 624"},
	{A: "0.40-r1", B: "2.25b-r5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 625"},
	{A: "2.25b-r5", B: "2.25b-r6", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 626"},
	{A: "2.25b-r6", B: "1.0.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 627"},
	{A: "1.0.4", B: "1.0.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 628"},
	{A: "1.0.5", B: "1.4_p12-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 629"},
	{A: "1.4_p12-r2", B: "1.4_p12-r5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 630"},
	{A: "1.4_p12-r5", B: "1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 631"},
	{A: "1.1", B: "0.2.0-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 632"},
	{A: "0.2.0-r1", B: "0.2.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 633"},
	{A: "0.2.1", B: "0.9.28-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 634"},
	{A: "0.9.28-r1", B: "0.9.28-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 635"},
	{A: "0.9.28-r2", B: "0.9.28.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 636"},
	{A: "0.9.28.1", B: "0.9.28", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 637"},
	{A: "0.9.28", B: "0.9.28.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 638"},
	{A: "0.9.28.1", B: "087-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 639", Refused: true, Note: noteAPKLeadingZero},
	{A: "087-r1", B: "103", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 640", Refused: true, Note: noteAPKLeadingZero},
	{A: "103", B: "104-r11", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 641"},
	{A: "104-r11", B: "104-r9", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 642"},
	{A: "104-r9", B: "1.23-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 643"},
	{A: "1.23-r1", B: "1.23", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 644"},
	{A: "1.23", B: "1.23-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 645"},
	{A: "1.23-r1", B: "1.0.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 646"},
	{A: "1.0.2", B: "5.52-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 647"},
	{A: "5.52-r1", B: "1.2.5_rc2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 648"},
	{A: "1.2.5_rc2", B: "0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 649"},
	{A: "0.1", B: "0.71-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 650"},
	{A: "0.71-r1", B: "20040406-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 651"},
	{A: "20040406-r1", B: "2.12r-r4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 652"},
	{A: "2.12r-r4", B: "2.12r-r5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 653"},
	{A: "2.12r-r5", B: "0.0.7", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 654"},
	{A: "0.0.7", B: "1.0.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 655"},
	{A: "1.0.3", B: "1.8", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 656"},
	{A: "1.8", B: "7.0.17", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 657"},
	{A: "7.0.17", B: "7.0.174", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 658"},
	{A: "7.0.174", B: "7.0.17", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 659"},
	{A: "7.0.17", B: "7.0.174", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 660"},
	{A: "7.0.174", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 661"},
	{A: "1.0.1", B: "1.1.1-r3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 662"},
	{A: "1.1.1-r3", B: "0.3.4_pre20061029", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 663"},
	{A: "0.3.4_pre20061029", B: "0.4.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 664"},
	{A: "0.4.0", B: "0.1.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 665"},
	{A: "0.1.2", B: "1.10.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 666"},
	{A: "1.10.2", B: "2.16", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 667"},
	{A: "2.16", B: "28", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 668"},
	{A: "28", B: "0.99.4", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 669"},
	{A: "0.99.4", B: "1.13", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 670"},
	{A: "1.13", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 671"},
	{A: "1.0.1", B: "1.1.2-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 672"},
	{A: "1.1.2-r2", B: "1.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 673"},
	{A: "1.1.0", B: "1.1.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 674"},
	{A: "1.1.1", B: "1.1.1", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 675"},
	{A: "1.1.1", B: "0.6.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 676"},
	{A: "0.6.0", B: "6.6.3", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 677"},
	{A: "6.6.3", B: "1.1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 678"},
	{A: "1.1.1", B: "1.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 679"},
	{A: "1.1.0", B: "1.1.0", Want: 0, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 680"},
	{A: "1.1.0", B: "0.2.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 681"},
	{A: "0.2.0", B: "0.3.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 682"},
	{A: "0.3.0", B: "1.1.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 683"},
	{A: "1.1.1", B: "1.2.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 684"},
	{A: "1.2.0", B: "1.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 685"},
	{A: "1.1.0", B: "1.6.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 686"},
	{A: "1.6.5", B: "1.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 687"},
	{A: "1.1.0", B: "1.4.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 688"},
	{A: "1.4.2", B: "1.1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 689"},
	{A: "1.1.1", B: "2.8.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 690"},
	{A: "2.8.1", B: "1.2.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 691"},
	{A: "1.2.0", B: "4.1.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 692"},
	{A: "4.1.0", B: "0.4.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 693"},
	{A: "0.4.1", B: "1.9.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 694"},
	{A: "1.9.1", B: "2.1.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 695"},
	{A: "2.1.1", B: "1.4.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 696"},
	{A: "1.4.1", B: "0.9.1-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 697"},
	{A: "0.9.1-r1", B: "0.8.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 698"},
	{A: "0.8.1", B: "1.2.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 699"},
	{A: "1.2.1-r1", B: "1.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 700"},
	{A: "1.1.0", B: "1.2.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 701"},
	{A: "1.2.1", B: "1.1.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 702"},
	{A: "1.1.0", B: "0.1.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 703"},
	{A: "0.1.1", B: "1.2.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 704"},
	{A: "1.2.1", B: "4.1.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 705"},
	{A: "4.1.0", B: "0.2.1-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 706"},
	{A: "0.2.1-r1", B: "1.1.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 707"},
	{A: "1.1.0", B: "2.7.11", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 708"},
	{A: "2.7.11", B: "1.0.2-r6", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 709"},
	{A: "1.0.2-r6", B: "1.0.2", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 710"},
	{A: "1.0.2", B: "0.8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 711"},
	{A: "0.8", B: "1.1.1-r4", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 712"},
	{A: "1.1.1-r4", B: "222", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 713"},
	{A: "222", B: "1.0.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 714"},
	{A: "1.0.1", B: "1.2.12-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 715"},
	{A: "1.2.12-r1", B: "1.2.8", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 716"},
	{A: "1.2.8", B: "1.2.9.1-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 717"},
	{A: "1.2.9.1-r1", B: "1.2.9.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 718"},
	{A: "1.2.9.1", B: "2.31-r1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 719"},
	{A: "2.31-r1", B: "2.31", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 720"},
	{A: "2.31", B: "1.2.3-r1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 721"},
	{A: "1.2.3-r1", B: "1.2.3", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 722"},
	{A: "1.2.3", B: "4.2.5", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 723"},
	{A: "4.2.5", B: "4.3.2-r2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 724"},
	{A: "1.3-r0", B: "1.3.1-r0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 725"},
	{A: "1.3_pre1-r1", B: "1.3.2", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 726"},
	{A: "1.0_p10-r0", B: "1.0_p9-r0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 727"},
	{A: "0.1.0_alpha_pre2", B: "0.1.0_alpha", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 728"},
	{A: "1.0.0_pre20191002222144-r0", B: "1.0.0_pre20210530193627-r0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 729", Refused: true, Note: noteAPKSuffixNumberWidth},
	{A: "6.0_pre1", B: "6.0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 730"},
	{A: "6.1_pre1", B: "6.1", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 731"},
	{A: "6.0_p1", B: "6.0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 732"},
	{A: "6.1_p1", B: "6.1", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 733"},
	{A: "8.2.0", B: "8.2.001", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 734", Refused: true, Note: noteAPKLeadingZero},
	{A: "8.2.0015", B: "8.2.002", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 735", Refused: true, Note: noteAPKLeadingZero},
	{A: "1.0~1234", B: "1.0~2345", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 737", Refused: true, Note: noteAPKCommitHash},
	{A: "1.0~1234-r1", B: "1.0~2345-r0", Want: -1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 738", Refused: true, Note: noteAPKCommitHash},
	{A: "1.0~1234-r1", B: "1.0~1234-r0", Want: 1, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 739", Refused: true, Note: noteAPKCommitHash},
}

// ---------------------------------------------------------------------------
// Validity corpora: what the published suites say PARSES
// ---------------------------------------------------------------------------
//
// An ordering corpus cannot catch a parser that is too PERMISSIVE, because a
// string the upstream tool rejects never appears in an ordering table. That is
// the gap M1 lived in: dpkg_compare.go promised "parseDebian rejects rather
// than repairs", and parseDebian accepted `1.0-` — a version Dpkg_Version.t
// states plainly is invalid — by quietly treating the empty revision as an
// absent one. An advisory endpoint spelled that way then decided a range as if
// it were `1.0`, and a truncated endpoint that reads as a LOWER bound clears a
// vulnerable host.
//
// AnvilRefuses marks the reverse direction: a string the published suite calls
// VALID that this package refuses anyway. Those are deviations, they are
// deliberate, and each carries the Note saying which rule refuses it. A
// deviation in the other direction — a string the suite calls INVALID that
// this package accepts — has no field to be recorded in, because there is no
// argument for it: it is the defect M1 named.

var dpkgValidity = []validityVector{
	{V: "", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 96 (\"empty version is invalid\")"},
	{V: "-0", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 100 (\"empty upstream version is invalid\")"},
	{V: "0:-0", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 104 (\"empty upstream version with epoch is invalid\")"},
	{V: ":1.0", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 108 (\"empty epoch is invalid\")"},
	{V: "1.0-", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 112 (\"empty revision is invalid\")", Note: noteDpkgEmptyRevision},
	{V: "10a:5.2", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 114 (\"bad epoch is invalid\")"},
	{V: "5.2@3-2", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 119 (\"invalid character makes version invalid\")"},
	{V: "foo5.2", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 121 (\"version does not start with digit 1/2\")"},
	{V: "0:foo5.2", Scheme: SchemeDebian, Valid: false, Prov: provTranscribed, Source: srcDpkgVersionT, Locus: "line 123 (\"version does not start with digit 2/2\")"},
}

var apkValidity = []validityVector{
	{V: "1.2", Scheme: SchemeAPK, Valid: true, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 758"},
	{V: "0.1_pre2", Scheme: SchemeAPK, Valid: true, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 759"},
	{V: "0.1_pre2~1234abcd", Scheme: SchemeAPK, Valid: true, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 760", AnvilRefuses: true, Note: noteAPKCommitHash},
	{V: "0.1_p1_pre2", Scheme: SchemeAPK, Valid: true, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 761"},
	{V: "0.1_alpha1_pre2", Scheme: SchemeAPK, Valid: true, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 762"},
	{V: "0.1_git20240101_pre1", Scheme: SchemeAPK, Valid: true, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 763"},
	{V: "", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 764"},
	{V: "0.1bc", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 765"},
	{V: "0.1bc1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 766"},
	{V: "0.1a1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 767"},
	{V: "0.1a.1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 768"},
	{V: "0.1_pre2~", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 769"},
	{V: "0.1_pre2~1234xbcd", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 770"},
	{V: "0.1_pre2~1234abcd_pre1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 771"},
	{V: "0.1_pre2-r1~1234xbcd", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 772"},
	{V: "0.1_foobar", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 773"},
	{V: "0.1_foobar1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 774"},
	{V: "0.1-pre1.1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 775"},
	{V: "0.1-r", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 776"},
	{V: "0.1-r2_pre1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 777"},
	{V: "0.1-r2_p3_pre1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 778"},
	{V: "0.1-r2-r3", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 779"},
	{V: "0.1-r2.1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 780"},
	{V: ".1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 781"},
	{V: "a", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 782"},
	{V: "_pre1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 783"},
	{V: "-r1", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 784"},
	{V: "0.1_", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 785"},
	{V: "0.1_-r0", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 786"},
	{V: "0.1__alpha", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 787"},
	{V: "0.1_1_alpha", Scheme: SchemeAPK, Valid: false, Prov: provTranscribed, Source: srcAPKVersionData, Locus: "line 788"},
}
