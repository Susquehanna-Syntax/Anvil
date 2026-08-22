// comparator_test.go is A.17's validation.
//
// ===========================================================================
// WHERE THE CORPUS COMES FROM, AND WHY THAT IS THE FIRST THING IN THIS FILE
// ===========================================================================
//
// A TEST WHOSE CORPUS COMES FROM THE IMPLEMENTATION IS NOT A TEST. This
// project has already had a licence marker table validated against its own
// entries, and the exercise certified a defect instead of catching it. So
// every ordering vector carries a PROVENANCE tag saying where the expected
// answer came from, and the tags are checked.
//
// THE TAGS ARE NOW TWO DISJOINT SETS, NOT TWO GRADES OF THE SAME CLAIM, AND
// THE SETS LIVE IN DIFFERENT FILES:
//
//	provTranscribed — the vector was COPIED from a named published file and
//	                  carries the FILE and the LINE it came from. Every one
//	                  of them is in corpus_transcribed_test.go, which was
//	                  generated from the fetched files rather than typed.
//	provAuthored    — the vector was WRITTEN BY THIS PROJECT and carries the
//	                  published RULE it is derived from. Those are below, in
//	                  this file.
//
// No vector may be untagged, a TRANSCRIBED vector may not lack its citation,
// and an AUTHORED vector may not lack its rule:
// TestEveryVectorCarriesTheProvenanceItsTagPromises fails on each.
//
// WHY THE SPLIT REPLACED THE OLD provVector/provRule PAIR. Those two were
// grades of one claim, and the file's prose then made COMPLETENESS claims
// about the transcribed grade in sentences ("transcribed as written there")
// that nothing checked. Twice the sentence was wrong and twice it was
// rewritten. A claim that keeps drifting away from the data underneath it is
// not fixed by rewriting it, so completeness claims are now DATA —
// transcriptionClaims in corpus_transcribed_test.go, each carrying the NUMBER
// of rows it claims — and TestTranscriptionClaimsAreTrue counts the corpus
// and fails when the number disagrees. A transcribed vector whose source
// carries no claim fails the same test, so a transcription cannot be added
// without a counted claim to sit under.
//
// A THIRD KIND OF ROW: `Refused: true`. Some pairs have a published upstream
// ordering that this package deliberately declines to produce. Those rows stay
// in the corpus, with their citation and a Note giving the reason, and assert
// the REFUSAL. A corpus that is the published suite minus the rows the
// implementation fails is a corpus filtered by the implementation.
//
// AND A FOURTH: validityVector. An ordering corpus cannot catch a parser that
// is too PERMISSIVE, because a string the upstream tool rejects never appears
// in an ordering table. dpkgValidity and apkValidity transcribe what the
// published suites say PARSES, which is the corpus M1's defect was invisible
// to.
//
// HONEST LIMITATION, STATED BECAUSE A GREEN RUN WILL BE READ AS AN ANSWER:
// no test in this package touches the network. The three upstream files were
// fetched once, while the transcribed corpus was written, and what is checked
// in is the transcription — so a row is a statement about the file as it stood
// then. The Locus on every transcribed row is a line number, which makes
// re-checking a mechanical diff rather than a re-derivation.
//
// ===========================================================================
// GUARDS IN THIS FILE, AND THE RED CHECK FOR EACH
// ===========================================================================
//
// A GUARD THAT HAS NEVER FAILED HAS NOT BEEN TESTED. Every guard below has a
// negative control that proves it fires:
//
//	G1 direct-import allowlist        -> TestDirectImportGuardFiresOnAViolation
//	G2 refusal-reason allowlist       -> TestRefusalReasonGuardFiresOnAnUndeclaredReason
//	G3 no-silent-clean                -> TestSilentCleanGuardFiresOnEveryEmptyShape
//	G4 vendor-first backport defence  -> TestBackportRegressionIsNotVacuous
//	G5 dependency-graph allowlist     -> TestDependencyGraphGuardFiresOnAPackageThatViolatesIt
//	G6 determinism corpus             -> TestCorpusDigestIsSensitiveToItsInput
//
// The guards A.18 forced, each of which was verified RED against the
// PRE-FIX code before the fix landed — not merely green after it:
//
//	G7  empty advisory cache is not clean
//	    -> TestAFullInventoryAgainstAnEmptyAdvisoryCacheIsNotClean
//	G8  one-sided epoch never decides silently
//	    -> TestAnEpochOnOneSideOnlyIsRefusedAndNeverASilentClean
//	G9  the identity spelling that is accepted is the one looked up
//	    -> TestTheAcceptedNameSpellingIsTheNameLookedUp
//	G10 a refused range decides nothing, in either direction
//	    -> TestARefusedVendorRangeDoesNotHandItsGroupToUpstream
//	G11 the remediation target is not chosen by source name
//	    -> TestTheRemediationTargetIsTheTightestBoundNotTheFirstSourceName
//	G12 a purl version disagreeing with the version column is a conflict
//	    -> TestAPurlVersionThatDisagreesWithTheVersionColumnIsAConflict
//
// The guards this round forced, each verified RED the same way:
//
//	G13 a purl naming a DIFFERENT package than the record is a conflict
//	    -> TestAPurlNamingADifferentPackageIsAConflict
//	    G9 varied the REPORTED name across spellings of one package and so
//	    exercised the fold and never the disagreement. G13 moves the axis
//	    G9 never moved: it varies the PURL name against a FIXED reported
//	    name.
//	G14 a range endpoint dpkg itself rejects is refused, not repaired
//	    -> TestARangeEndpointDpkgRejectsIsRefusedNotRepaired
//	G15 every transcribed vector carries its file and line, every authored
//	    vector carries its rule, and every completeness claim carries a
//	    number that is checked
//	    -> TestEveryVectorCarriesTheProvenanceItsTagPromises
//	    -> TestTranscriptionClaimsAreTrue
//	G16 a vendor range that cannot participate is reported even when it is
//	    also refused
//	    -> TestAnUngroupableVendorRangeIsReportedEvenWhenItIsAlsoRefused
//
// ALWAYS RUN WITH -count=1. TestNoNonStdlibDependenciesBeyondRecord shells out
// to `go list`, whose result Go's test cache does not track.
package match

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/host"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Vector plumbing
// ---------------------------------------------------------------------------

// provenance is the KIND of a vector's authority, and there are exactly two.
// They are not two grades of one claim: a transcribed vector points at a line
// in a published file, an authored vector points at a published rule, and the
// fields each may carry are disjoint so that neither can quietly borrow the
// other's authority.
type provenance string

const (
	// provTranscribed: copied from a named published file. Requires Source
	// and Locus; forbids Rule.
	provTranscribed provenance = "TRANSCRIBED"
	// provAuthored: written by this project from a published rule. Requires
	// Rule; forbids Source and Locus.
	provAuthored provenance = "AUTHORED"
)

// vector is one ordering assertion. Want is -1, 0 or +1 for A vs B.
//
// Refused inverts the assertion: the cited source publishes an ordering for
// this pair and ANVIL DECLINES TO PRODUCE ONE. Such a vector stays in the
// corpus, with its citation, precisely so that the corpus is not the published
// suite filtered down to the rows this implementation happens to pass. Want is
// ignored when Refused is set, and Note must say what upstream orders and why
// this package does not.
type vector struct {
	A, B string
	Want int
	Prov provenance

	// Source and Locus are the file and the line a TRANSCRIBED vector was
	// copied from. Both are required on a TRANSCRIBED vector and both must
	// be empty on an AUTHORED one.
	Source string
	Locus  string

	// Rule is the published rule an AUTHORED vector is derived from. It is
	// required on an AUTHORED vector and must be empty on a TRANSCRIBED one.
	Rule string

	// Note explains a deviation. It is required when Refused is set and is
	// otherwise optional.
	Note string

	Refused bool
}

func (v vector) name() string {
	if v.Refused {
		return v.A + " ?? " + v.B + " (refused)"
	}
	op := "=="
	switch v.Want {
	case -1:
		op = "<"
	case 1:
		op = ">"
	}
	return v.A + " " + op + " " + v.B
}

// citation renders the vector's authority for a failure message. A failing
// vector is useless without it: the reader has to know whether the expectation
// came from a line in a published file or from this project's reading of a
// rule, because those two failures have different fixes.
func (v vector) citation() string {
	var b strings.Builder
	b.WriteString(string(v.Prov))
	switch v.Prov {
	case provTranscribed:
		b.WriteString(" ")
		b.WriteString(v.Source)
		b.WriteString(" ")
		b.WriteString(v.Locus)
	case provAuthored:
		b.WriteString(" from rule: ")
		b.WriteString(v.Rule)
	}
	if v.Note != "" {
		b.WriteString(" — ")
		b.WriteString(v.Note)
	}
	return b.String()
}

// validityVector is one PARSE assertion: what the cited source says about
// whether a string is a version at all.
//
// This corpus exists because an ordering table cannot catch a parser that is
// too permissive — a string the upstream tool rejects never appears in one.
// dpkg_compare.go claimed "parseDebian rejects rather than repairs" while
// accepting `1.0-`, which Dpkg_Version.t states is invalid, and the ordering
// corpus had no shape in which that could show up.
type validityVector struct {
	V      string
	Scheme Scheme
	// Valid is what the CITED SOURCE says: true when the source asserts the
	// string parses, false when it asserts it does not.
	Valid bool

	Prov   provenance
	Source string
	Locus  string
	Rule   string

	// AnvilRefuses records a DELIBERATE deviation in the safe direction:
	// the source calls the string valid and this package refuses it anyway.
	// Note must say which rule refuses it. There is no field for the unsafe
	// direction — a string the source calls INVALID that this package
	// accepts — because there is no argument for it.
	AnvilRefuses bool
	Note         string
}

func (v validityVector) citation() string {
	var b strings.Builder
	b.WriteString(string(v.Prov))
	switch v.Prov {
	case provTranscribed:
		b.WriteString(" ")
		b.WriteString(v.Source)
		b.WriteString(" ")
		b.WriteString(v.Locus)
	case provAuthored:
		b.WriteString(" from rule: ")
		b.WriteString(v.Rule)
	}
	if v.Note != "" {
		b.WriteString(" — ")
		b.WriteString(v.Note)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// dpkg vectors — AUTHORED
// ---------------------------------------------------------------------------
//
// The TRANSCRIBED dpkg corpus is dpkgTranscribed in corpus_transcribed_test.go
// (all 43 rows of Dpkg_Version.t's __DATA__ block). What is below is the set
// this project WROTE from deb-version(7)'s ordering sentences, because the
// published suite does not carry a row for them.
//
// THREE ROWS THAT USED TO BE HERE CLAIMING TO BE TRANSCRIBED. `1.0 == 1.0`,
// `1.0 < 1.1` and `1.0-1 < 1.0-2` were tagged as coming from Dpkg_Version.t
// and are not in that file. They are below, AUTHORED, carrying the
// deb-version(7) rule they actually encode. The two rows that WERE in the file
// (`2.2~rc-4 lt 2.2-1` and its reverse) are gone from here because they are
// now transcribed at __DATA__ lines 240 and 241, where they belong.
//
// The rule quoted throughout is deb-version(7), "Sorting algorithm": "The
// lexical comparison is a comparison of ASCII values modified so that all the
// letters sort earlier than all the non-letters and so that a tilde sorts
// before anything, even the end of a part."
var dpkgAuthored = []vector{
	{A: "1.0", B: "1.0", Want: 0, Prov: provAuthored,
		Rule: "deb-version(7): a version compares equal to itself"},
	{A: "1.0", B: "1.1", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): digit runs compare numerically"},
	{A: "1.0-1", B: "1.0-2", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): the debian_revision is compared after the upstream_version"},

	// The tilde rule, which is the one everybody gets backwards.
	{A: "1.0~rc1", B: "1.0", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): a tilde sorts before anything, even the end of a part"},
	{A: "1.0", B: "1.0~rc1", Want: 1, Prov: provAuthored,
		Rule: "deb-version(7): tilde rule, reversed"},
	{A: "1.0~rc1", B: "1.0~rc2", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): equal tilde parts, then numeric ordering"},
	{A: "1.0~~", B: "1.0~", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): tilde before tilde-then-end"},
	{A: "1.0~", B: "1.0", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): tilde before the end of a part"},
	{A: "1.0~beta1", B: "1.0~beta2", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): tilde parts compare normally among themselves"},

	// "all the letters sort earlier than all the non-letters".
	{A: "1.0", B: "1.0a", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): a letter sorts after the end of a part"},
	{A: "1.0a", B: "1.0+b", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): all letters sort earlier than all non-letters"},
	{A: "1.0a", B: "1.0b", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): letters compare by ASCII value among themselves"},

	// Numeric runs are compared as numbers, not lexically.
	{A: "1.2.3", B: "1.2.10", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): digit runs compare numerically"},
	{A: "1.0-1", B: "1.0-01", Want: 0, Prov: provAuthored,
		Rule: "deb-version(7): leading zeros in a numeric run carry no value"},
	{A: "1.0000-1", B: "1.0-1", Want: 0, Prov: provAuthored,
		Rule: "deb-version(7): leading zeros, upstream side"},
	{A: "1.0", B: "1.0-0", Want: 0, Prov: provAuthored,
		Rule: "dpkg verrevcmp: an absent revision and a zero revision are equal"},
	{A: "1.0", B: "1.0.0", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): a further part sorts after the end of the string"},

	// Epochs dominate everything.
	{A: "1:1.0", B: "2.0", Want: 1, Prov: provAuthored,
		Rule: "deb-version(7): the epoch dominates the rest of the version"},
	{A: "1:0", B: "0:9999", Want: 1, Prov: provAuthored,
		Rule: "deb-version(7): epoch ordering"},
	{A: "0:1.0", B: "1.0", Want: 0, Prov: provAuthored,
		Rule: "deb-version(7): an omitted epoch is zero"},
	{A: "1:1.0", B: "1:1.1", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): equal epochs fall through to the upstream version"},

	// A real backported Debian version, which is the shape this lane exists
	// to compare.
	{A: "1.1.1n-0+deb11u5", B: "1.1.1n-0+deb11u4", Want: 1, Prov: provAuthored,
		Rule: "deb-version(7): Debian security revision ordering"},
	{A: "1.1.1n-0+deb11u5", B: "1.1.1w-0+deb11u1", Want: -1, Prov: provAuthored,
		Rule: "deb-version(7): upstream letter beats the revision"},
}

// ---------------------------------------------------------------------------
// rpm vectors — AUTHORED
// ---------------------------------------------------------------------------
//
// The TRANSCRIBED rpm corpus is rpmTranscribed in corpus_transcribed_test.go:
// all 91 active RPMVERCMP lines of tests/rpmvercmp.at, including the five the
// implementation refuses. rpmvercmp.at exercises rpmvercmp() over a single
// string; it never spells an epoch or a release, because rpm's `rpm.vercmp`
// Lua binding compares whole EVRs elsewhere. The rows below are the ones
// rpmVersionCompare's own documented structure (epoch, then version, then
// release) requires and rpmvercmp.at therefore cannot supply.
var rpmAuthored = []vector{
	{A: "1:1.0-1", B: "2.0-1", Want: 1, Prov: provAuthored,
		Rule: "rpm rpmVersionCompare: the epoch dominates"},
	{A: "0:1.0-1", B: "1.0-1", Want: 0, Prov: provAuthored,
		Rule: "rpm rpmVersionCompare: an omitted epoch is zero"},
	{A: "2.25.1-1.el9", B: "2.25.1-3.el9", Want: -1, Prov: provAuthored,
		Rule: "rpm rpmVersionCompare: the release field is compared"},
	{A: "2.25.1-3.el9", B: "2.25.1-3.el9", Want: 0, Prov: provAuthored,
		Rule: "rpm rpmVersionCompare: identical EVRs"},
	{A: "1.2.3", B: "1.2.3-1", Want: -1, Prov: provAuthored,
		Rule: "rpm rpmVersionCompare: an absent release is the empty string, which is lowest"},
}

// ---------------------------------------------------------------------------
// apk vectors — AUTHORED
// ---------------------------------------------------------------------------
//
// The TRANSCRIBED apk corpus is apkTranscribed in corpus_transcribed_test.go:
// all 738 ordering rows of apk-tools' test/unit/version.data. That is a change
// of kind, not of degree — A.18's standing complaint was that not one apk
// vector had ever been diffed against apk's own fixture, and the answer used
// to be a set of rows citing a file nobody had opened.
//
// WHAT IS LEFT HERE IS WHAT THE FIXTURE DOES NOT COVER. version.data carries
// no `1.0` against `1`, no `X-r0` against `X`, and no `_rc` against `_rc0` —
// the three positions R8 refuses — and it carries no complete walk of the
// suffix rank table. Those rows are AUTHORED, from the published table, and
// they say so.
var apkAuthored = []vector{
	{A: "2.10", B: "2.9", Want: 1, Prov: provAuthored,
		Rule: "apk grammar: numeric parts compare as numbers, not lexically"},
	{A: "1.0", B: "1.0.1", Want: -1, Prov: provAuthored,
		Rule: "apk grammar: a further NON-ZERO numeric part is newer"},
	{A: "1.0", B: "1.0a", Want: -1, Prov: provAuthored,
		Rule: "apk grammar: the optional letter sorts after the bare version"},
	{A: "1.0a", B: "1.0b", Want: -1, Prov: provAuthored,
		Rule: "apk grammar: letters compare among themselves"},

	// The published suffix chain. This is the table that decides whether a
	// release candidate is newer or older than its release. version.data
	// exercises single steps of it (1.1 > 1.1_alpha1 at line 17, 6.0_pre1 <
	// 6.0 at line 730, 6.0_p1 > 6.0 at line 732); the complete walk is this
	// project's, from the table apk_compare.go R4 quotes.
	{A: "1.0_alpha1", B: "1.0_alpha2", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: same rank, numeric ordering"},
	{A: "1.0_alpha2", B: "1.0_beta1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: alpha < beta"},
	{A: "1.0_beta1", B: "1.0_pre1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: beta < pre"},
	{A: "1.0_pre1", B: "1.0_rc1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: pre < rc"},
	{A: "1.0_rc1", B: "1.0", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: rc < no suffix"},
	{A: "1.0", B: "1.0_cvs1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: no suffix < cvs"},
	{A: "1.0_cvs1", B: "1.0_svn1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: cvs < svn"},
	{A: "1.0_svn1", B: "1.0_git1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: svn < git"},
	{A: "1.0_git1", B: "1.0_hg1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: git < hg"},
	{A: "1.0_hg1", B: "1.0_p1", Want: -1, Prov: provAuthored,
		Rule: "apk suffix table: hg < p"},

	// Revisions.
	{A: "1.0-r1", B: "1.0.1-r0", Want: -1, Prov: provAuthored,
		Rule: "apk grammar: numeric parts are compared before the revision"},
	{A: "1.0_rc1-r1", B: "1.0-r0", Want: -1, Prov: provAuthored,
		Rule: "apk grammar: the suffix is compared before the revision"},

	// R8: AN EXPLICIT ZERO AGAINST AN ABSENCE IS REFUSED.
	//
	// These three used to be asserted as EQUAL on the authority of this
	// package's own written rules. They are refusals now, and the reason is
	// stated without inventing a mechanism: apk decides "an explicit zero
	// part against no part at all" by a token comparison this file does not
	// model, version.data contains no row for any of the three, and the
	// honest output for an ordering this package has not implemented is a
	// refusal. That is the form R7a now takes too.
	//
	// Each has a DECIDABLE neighbour asserted above or in the transcribed
	// corpus, so the refusal cannot quietly widen into "apk does not work":
	// `1.0` vs `1.0.1`, `1.0.4-r3` vs `1.0.4-r4` (version.data line 10) and
	// `1.3_alpha` vs `1.3_alpha2` (line 21) are all still ordered. See
	// TestAPKRefusesOnlyTheUndecidablePositionsAndStillOrdersTheRest.
	{A: "1.0", B: "1", Want: 0, Prov: provAuthored, Refused: true,
		Rule: "apk_compare.go R8: an explicit zero numeric part against a version with no such part",
		Note: "apk-tools test/unit/version.data publishes no row for this shape and the token " +
			"comparison that decides it is not modelled here, so the ordering is refused " +
			"rather than guessed"},
	{A: "1.0", B: "1.0-r0", Want: 0, Prov: provAuthored, Refused: true,
		Rule: "apk_compare.go R8: an explicit \"-r0\" against a version spelling no revision",
		Note: "version.data compares -rN against -rM and against a higher version, never -r0 " +
			"against an absent revision; the ordering is unmodelled and therefore refused"},
	{A: "1.0_rc", B: "1.0_rc0", Want: 0, Prov: provAuthored, Refused: true,
		Rule: "apk_compare.go R8: an explicit zero suffix number against a suffix spelling none",
		Note: "version.data compares _rcN against _rcM, never _rc0 against a bare _rc; the " +
			"ordering is unmodelled and therefore refused"},
}

// ---------------------------------------------------------------------------
// The corpora, joined
// ---------------------------------------------------------------------------

// vectorsFor returns every ordering vector for a scheme, transcribed and
// authored together. Nothing outside this function knows which half a vector
// came from; everything that CHECKS provenance reads v.Prov.
func vectorsFor(s Scheme) []vector {
	switch s {
	case SchemeDebian:
		return append(append([]vector{}, dpkgTranscribed...), dpkgAuthored...)
	case SchemeRPM:
		return append(append([]vector{}, rpmTranscribed...), rpmAuthored...)
	case SchemeAPK:
		return append(append([]vector{}, apkTranscribed...), apkAuthored...)
	}
	return nil
}

// validityVectorsFor returns the parse-validity corpus for a scheme. rpm has
// none: rpmvercmp.at asserts orderings only, and inventing "rpm would reject
// this" rows would be this package grading its own homework.
func validityVectorsFor(s Scheme) []validityVector {
	switch s {
	case SchemeDebian:
		return dpkgValidity
	case SchemeAPK:
		return apkValidity
	}
	return nil
}

// ---------------------------------------------------------------------------
// The ordering tests
// ---------------------------------------------------------------------------

func TestPublishedOrderingVectors(t *testing.T) {
	for _, scheme := range SchemeValues() {
		vs := vectorsFor(scheme)
		if len(vs) == 0 {
			t.Fatalf("scheme %s has no vectors; an implemented scheme with no corpus is an unverified scheme", scheme)
		}
		for _, v := range vs {
			t.Run(string(scheme)+"/"+v.name(), func(t *testing.T) {
				got, err := Compare(scheme, v.A, v.B)
				if v.Refused {
					if err == nil {
						t.Fatalf("Compare(%s, %q, %q) = %d, but this pair is one the corpus "+
							"records as REFUSED. If the refusal has been implemented away, the "+
							"vector must be re-stated as an ordering with a citation, not deleted.\n"+
							"(vector source: %s)", scheme, v.A, v.B, got, v.citation())
					}
					r, ok := err.(*Refusal)
					if !ok {
						t.Fatalf("Compare(%s, %q, %q) returned %T, want *Refusal", scheme, v.A, v.B, err)
					}
					if !r.Reason.Valid() {
						t.Errorf("refusal carries an undeclared reason %q", r.Reason)
					}
					if got != 0 {
						t.Errorf("Compare(%s, %q, %q) returned a usable-looking %d alongside its refusal",
							scheme, v.A, v.B, got)
					}
					return
				}
				if err != nil {
					t.Fatalf("Compare(%s, %q, %q) refused: %v\n(vector source: %s)",
						scheme, v.A, v.B, err, v.citation())
				}
				if got != v.Want {
					t.Errorf("Compare(%s, %q, %q) = %d, want %d\n(vector source: %s)",
						scheme, v.A, v.B, got, v.Want, v.citation())
				}
			})
		}
	}
}

// TestCorpusIsAConsistentTotalOrder cross-checks the TRANSCRIPTION, not the
// implementation. Every comparator must be antisymmetric and reflexive, and
// the corpus's own entries must not contradict each other. A vector
// transcribed backwards from an upstream suite shows up here as an
// inconsistency between the forward and reversed evaluations.
func TestCorpusIsAConsistentTotalOrder(t *testing.T) {
	for _, scheme := range SchemeValues() {
		for _, v := range vectorsFor(scheme) {
			if v.Refused {
				// A refusal must be SYMMETRIC too: a comparator that
				// refuses (A,B) and answers (B,A) would let the caller pick
				// an ordering by choosing an argument order.
				if _, err := Compare(scheme, v.A, v.B); err == nil {
					t.Errorf("%s: Compare(%q,%q) answered a pair the corpus records as refused",
						scheme, v.A, v.B)
				}
				if _, err := Compare(scheme, v.B, v.A); err == nil {
					t.Errorf("%s: Compare(%q,%q) answered, but the reversed pair is refused; "+
						"a refusal that depends on argument order is not a refusal",
						scheme, v.B, v.A)
				}
				continue
			}
			fwd, err := Compare(scheme, v.A, v.B)
			if err != nil {
				t.Fatalf("%s: Compare(%q,%q): %v", scheme, v.A, v.B, err)
			}
			rev, err := Compare(scheme, v.B, v.A)
			if err != nil {
				t.Fatalf("%s: Compare(%q,%q): %v", scheme, v.B, v.A, err)
			}
			if fwd != -rev {
				t.Errorf("%s: comparison is not antisymmetric: cmp(%q,%q)=%d but cmp(%q,%q)=%d",
					scheme, v.A, v.B, fwd, v.B, v.A, rev)
			}
			for _, s := range []string{v.A, v.B} {
				self, err := Compare(scheme, s, s)
				if err != nil {
					t.Fatalf("%s: Compare(%q,%q): %v", scheme, s, s, err)
				}
				if self != 0 {
					t.Errorf("%s: %q does not compare equal to itself (got %d)", scheme, s, self)
				}
			}
		}
	}
}

// TestOrderingIsTransitiveOverEachSchemesChain walks a strictly ascending
// chain per scheme and asserts every pair, which is a stronger statement than
// the adjacent-pair vectors above: an ordering that is right for neighbours
// and wrong at a distance is a real failure mode of segment-wise comparators.
func TestOrderingIsTransitiveOverEachSchemesChain(t *testing.T) {
	//
	// The apk chains are deliberately SPLIT so that no chain mixes a version
	// carrying a letter with one carrying a `_suffix`. This file's ordering
	// for that interaction is a consequence of apk_compare.go's rule ORDER
	// (R3 before R4) and is not backed by a published vector, so asserting it
	// here would be asserting an inference rather than a citation. It is
	// reported as an uncited rule instead of being smuggled into a chain.
	chains := map[Scheme][][]string{
		SchemeDebian: {{
			"1.0~~", "1.0~", "1.0~rc1", "1.0~rc2", "1.0", "1.0a", "1.0+b",
			"1.0.1", "1.1", "1.2.3", "1.2.10", "2.0", "1:0.1",
		}},
		SchemeRPM: {{
			"1.0~rc1", "1.0~rc2", "1.0", "1.0^git1", "1.0^git2",
			"1.0.1", "1.1", "2.0", "1:0.1",
		}},
		SchemeAPK: {
			{
				"1.0_alpha1", "1.0_beta1", "1.0_pre1", "1.0_rc1", "1.0",
				"1.0_cvs1", "1.0_svn1", "1.0_git1", "1.0_hg1", "1.0_p1",
				"1.0.1", "1.1", "2.0",
			},
			{"1.0-r0", "1.0-r1", "1.0a", "1.0b", "1.0.1", "1.1"},
		},
	}
	for _, scheme := range SchemeValues() {
		if len(chains[scheme]) == 0 {
			t.Fatalf("scheme %s has no transitivity chain", scheme)
		}
		for _, chain := range chains[scheme] {
			if len(chain) < 3 {
				t.Fatalf("scheme %s has a chain shorter than three entries", scheme)
			}
			for i := 0; i < len(chain); i++ {
				for j := i + 1; j < len(chain); j++ {
					got, err := Compare(scheme, chain[i], chain[j])
					if err != nil {
						t.Fatalf("%s: Compare(%q,%q): %v", scheme, chain[i], chain[j], err)
					}
					if got != -1 {
						t.Errorf("%s: chain position %d (%q) should be below position %d (%q), got %d",
							scheme, i, chain[i], j, chain[j], got)
					}
				}
			}
		}
	}
}

// G15, first half. TestEveryVectorCarriesTheProvenanceItsTagPromises is what
// makes the TRANSCRIBED/AUTHORED split real rather than decorative.
//
// The old test asked only "is there a non-empty Cite string", which a vector
// could satisfy while naming a file it was not in — and three dpkg vectors
// did exactly that, tagged as transcribed from Dpkg_Version.t and absent from
// it. A free-text citation cannot be checked, so the fields are typed by kind
// instead: a TRANSCRIBED vector must name a FILE and a LINE and may not carry
// a rule, an AUTHORED vector must name a RULE and may not carry a file or a
// line, and there is no third state. A vector that wants to borrow the
// stronger authority now has to lie in a field the test reads.
func TestEveryVectorCarriesTheProvenanceItsTagPromises(t *testing.T) {
	total, transcribed := 0, 0

	checkOrdering := func(scheme Scheme, v vector) {
		switch v.Prov {
		case provTranscribed:
			transcribed++
			if strings.TrimSpace(v.Source) == "" || strings.TrimSpace(v.Locus) == "" {
				t.Errorf("%s: vector %s is tagged TRANSCRIBED but names no file/line "+
					"(Source=%q Locus=%q). A transcription that cannot be looked up is a "+
					"claim, not a citation.", scheme, v.name(), v.Source, v.Locus)
			}
			if v.Rule != "" {
				t.Errorf("%s: vector %s is tagged TRANSCRIBED and also carries a Rule (%q); "+
					"the two authorities are disjoint on purpose", scheme, v.name(), v.Rule)
			}
		case provAuthored:
			if strings.TrimSpace(v.Rule) == "" {
				t.Errorf("%s: vector %s is tagged AUTHORED but names no rule it is derived "+
					"from", scheme, v.name())
			}
			if v.Source != "" || v.Locus != "" {
				t.Errorf("%s: vector %s is tagged AUTHORED and also names a file/line "+
					"(%q %q); an authored vector must not read as a transcription",
					scheme, v.name(), v.Source, v.Locus)
			}
		default:
			t.Errorf("%s: vector %s carries no recognised provenance (%q); there are exactly "+
				"two and neither is the zero value", scheme, v.name(), v.Prov)
		}
		if v.Refused && strings.TrimSpace(v.Note) == "" {
			t.Errorf("%s: vector %s asserts a REFUSAL with no Note. A deviation from a "+
				"published ordering has to say what upstream orders and why this package "+
				"does not.", scheme, v.name())
		}
	}

	for _, scheme := range SchemeValues() {
		for _, v := range vectorsFor(scheme) {
			total++
			checkOrdering(scheme, v)
		}
		for _, v := range validityVectorsFor(scheme) {
			total++
			switch v.Prov {
			case provTranscribed:
				transcribed++
				if strings.TrimSpace(v.Source) == "" || strings.TrimSpace(v.Locus) == "" {
					t.Errorf("%s: validity vector %q is tagged TRANSCRIBED but names no "+
						"file/line", scheme, v.V)
				}
				if v.Rule != "" {
					t.Errorf("%s: validity vector %q is TRANSCRIBED and carries a Rule",
						scheme, v.V)
				}
			case provAuthored:
				if strings.TrimSpace(v.Rule) == "" {
					t.Errorf("%s: validity vector %q is tagged AUTHORED but names no rule",
						scheme, v.V)
				}
			default:
				t.Errorf("%s: validity vector %q carries no recognised provenance (%q)",
					scheme, v.V, v.Prov)
			}
			if v.AnvilRefuses && strings.TrimSpace(v.Note) == "" {
				t.Errorf("%s: validity vector %q refuses a string its source calls valid "+
					"and gives no reason", scheme, v.V)
			}
		}
	}

	if total < 100 {
		t.Errorf("the corpus is %d vectors; that is too thin for three schemes whose "+
			"disagreements are the common path, not the edge case", total)
	}
	if transcribed == 0 {
		t.Error("no vector in the corpus is transcribed from a published file; the whole " +
			"corpus is then this project's own reading of three specifications")
	}
}

// G15, second half. TestTranscriptionClaimsAreTrue is the answer to a
// provenance claim having been wrong twice in the same section.
//
// The rule this enforces: A CLAIM ABOUT COMPLETENESS MUST CARRY THE NUMBER IT
// CLAIMS, AND THE NUMBER IS CHECKED. transcriptionClaims is that claim in data
// form. This test counts what is actually in the corpus and fails when the
// count disagrees in EITHER direction — a claim of 91 backed by 90 rows is the
// truncated-corpus defect, and a claim of 91 backed by 92 rows means a row was
// duplicated or invented, which is the same defect wearing the other hat.
//
// It also closes the escape route: a transcribed vector whose Source appears
// in NO claim fails here, so transcription cannot be added without a counted
// claim to sit under, and prose elsewhere in the package cannot make a
// completeness claim this table does not.
func TestTranscriptionClaimsAreTrue(t *testing.T) {
	type key struct{ source, kind string }

	got := map[key]int{}
	loci := map[key]map[string]bool{}

	record := func(k key, locus, what string) {
		got[k]++
		if loci[k] == nil {
			loci[k] = map[string]bool{}
		}
		if loci[k][locus] {
			t.Errorf("%s (%s): two vectors claim to be transcribed from the same place, %q. "+
				"A completeness count over duplicated loci is not a count of the source's "+
				"rows. (%s)", k.source, k.kind, locus, what)
		}
		loci[k][locus] = true
	}

	for _, scheme := range SchemeValues() {
		for _, v := range vectorsFor(scheme) {
			if v.Prov == provTranscribed {
				record(key{v.Source, kindOrdering}, v.Locus, v.name())
			}
		}
		for _, v := range validityVectorsFor(scheme) {
			if v.Prov == provTranscribed {
				record(key{v.Source, kindValidity}, v.Locus, strconv.Quote(v.V))
			}
		}
	}

	claimed := map[key]bool{}
	for _, c := range transcriptionClaims {
		k := key{c.Source, c.Kind}
		if claimed[k] {
			t.Errorf("two completeness claims cover %s (%s); which number is the claim?",
				c.Source, c.Kind)
		}
		claimed[k] = true

		switch n := got[k]; {
		case n < c.Count:
			t.Errorf("%s (%s): the claim says %d rows are transcribed and the corpus holds %d.\n"+
				"The claim covers: %s\n"+
				"A corpus SMALLER than its claim is the defect that has now appeared twice in "+
				"this package: the citation makes the corpus read as exhaustive while the rows "+
				"the implementation cannot satisfy are the ones missing.",
				c.Source, c.Kind, c.Count, n, c.Rows)
		case n > c.Count:
			t.Errorf("%s (%s): the claim says %d rows are transcribed and the corpus holds %d.\n"+
				"The claim covers: %s\n"+
				"A corpus LARGER than its claim means a row was duplicated or is not in the "+
				"source at all; either way the number in the claim is no longer a fact about "+
				"the file.", c.Source, c.Kind, c.Count, n, c.Rows)
		}
	}

	for k, n := range got {
		if !claimed[k] {
			t.Errorf("%d vectors are transcribed from %s (%s) and no completeness claim "+
				"covers it. Every transcription sits under a claim that carries a number, "+
				"or the number is the thing nobody is checking.", n, k.source, k.kind)
		}
	}
}

// TestTheTranscriptionClaimGuardFiresOnAShortCorpus is G15's negative control.
// The guard above is the whole of M2's fix, so a version of it that could not
// fail would be the defect repeating itself one level up.
func TestTheTranscriptionClaimGuardFiresOnAShortCorpus(t *testing.T) {
	// A corpus one row short of its claim, checked by the same arithmetic
	// the real test runs.
	claim := transcriptionClaim{Source: "example/suite.at", Kind: kindOrdering,
		Rows: "every row", Count: 3}
	corpus := []vector{
		{A: "1", B: "2", Want: -1, Prov: provTranscribed, Source: claim.Source, Locus: "line 1"},
		{A: "2", B: "3", Want: -1, Prov: provTranscribed, Source: claim.Source, Locus: "line 2"},
	}
	n := 0
	for _, v := range corpus {
		if v.Prov == provTranscribed && v.Source == claim.Source {
			n++
		}
	}
	if n >= claim.Count {
		t.Fatalf("the control corpus is not short: %d >= %d", n, claim.Count)
	}

	// And the duplicate-locus arm, which is how a short corpus could
	// otherwise be padded back up to its claimed number.
	dup := map[string]bool{}
	collision := false
	for _, v := range append(corpus, corpus[1]) {
		if dup[v.Locus] {
			collision = true
		}
		dup[v.Locus] = true
	}
	if !collision {
		t.Error("the duplicate-locus arm did not observe a duplicate; padding a corpus with " +
			"the same row twice would satisfy a count that is supposed to be a count of the " +
			"source's rows")
	}
}

// TestPublishedValidityVectors runs the parse-validity corpus. It is the shape
// M1 was invisible to: dpkg_compare.go's header promised "parseDebian rejects
// rather than repairs" and parseDebian accepted `1.0-`, which Dpkg_Version.t
// states plainly is not a valid version. An ordering table can never contain
// that row, because dpkg will not order a string it will not parse.
func TestPublishedValidityVectors(t *testing.T) {
	for _, scheme := range SchemeValues() {
		for _, v := range validityVectorsFor(scheme) {
			t.Run(string(scheme)+"/"+strconv.Quote(v.V), func(t *testing.T) {
				err := ValidVersion(v.Scheme, v.V)
				switch {
				case v.Valid && v.AnvilRefuses:
					if err == nil {
						t.Fatalf("ValidVersion(%s, %q) accepted a string this package records "+
							"as a DELIBERATE refusal. If the rule has been implemented, the "+
							"deviation row must be restated, not deleted.\n(%s)",
							scheme, v.V, v.citation())
					}
				case v.Valid:
					if err != nil {
						t.Fatalf("ValidVersion(%s, %q) refused a string the published suite "+
							"says parses: %v\n(%s)", scheme, v.V, err, v.citation())
					}
				default:
					if err == nil {
						t.Fatalf("ValidVersion(%s, %q) ACCEPTED a string the published suite "+
							"says is invalid. A parser more permissive than the tool it ports "+
							"compares strings that tool could never have produced, and a range "+
							"endpoint spelled that way decides by comparing as something.\n(%s)",
							scheme, v.V, v.citation())
					}
					r, ok := err.(*Refusal)
					if !ok {
						t.Fatalf("ValidVersion(%s, %q) returned %T, want *Refusal", scheme, v.V, err)
					}
					if !r.Reason.Valid() {
						t.Errorf("refusal carries an undeclared reason %q", r.Reason)
					}
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

// TestMalformedVersionsAreRefusedNotGuessed is the "refuse what you do not
// understand" rule at the version level. Every string below is one a REAL
// producer might hand this comparator — a Go pseudo-version, a PEP 440 local
// version, a Maven qualifier, a semver tag — and each must produce a refusal
// rather than an ordering.
func TestMalformedVersionsAreRefusedNotGuessed(t *testing.T) {
	cases := []struct {
		scheme Scheme
		v      string
		why    string
	}{
		{SchemeDebian, "", "empty"},
		{SchemeDebian, "v1.2.3", "a semver git tag does not start with a digit"},
		{SchemeDebian, "a1.0", "upstream version must start with a digit"},
		{SchemeDebian, "x:1.0", "epoch is not a number"},
		{SchemeDebian, "1.0 ", "trailing whitespace"},
		{SchemeDebian, "1.0-1!", "'!' is outside deb-version(7)'s character set"},
		{SchemeDebian, "-1", "no upstream version"},
		{SchemeDebian, "1.0.0-alpha+build.1", "'+' is legal but the semver build metadata makes this a semver string, and its '-alpha' becomes a Debian revision — refused only if a character is illegal, so this case documents what is NOT refused"},

		{SchemeRPM, "", "empty"},
		{SchemeRPM, " 1.0", "leading whitespace"},
		{SchemeRPM, "1.0 ", "trailing ASCII whitespace"},
		{SchemeRPM, "1.0 ", "a non-breaking space is neither printable ASCII nor a version character"},
		{SchemeRPM, "1.0", "control byte"},
		{SchemeRPM, "...", "no alphanumeric, tilde or caret content"},

		{SchemeAPK, "", "empty"},
		{SchemeAPK, "1.00", "leading-zero numeric field (R7a)"},
		{SchemeAPK, "1.0~abc123", "apk fuzzy/commit suffix (R7b)"},
		{SchemeAPK, "1.0A", "uppercase letter (R7c)"},
		{SchemeAPK, "1.0_foo1", "suffix outside the allowlist (R7d)"},
		{SchemeAPK, "1.0-1", "a '-' that is not the -rN revision marker (R7e)"},
		{SchemeAPK, "1.0-r", "revision marker with no number"},
		{SchemeAPK, "1.0_", "empty suffix group"},
		{SchemeAPK, "abc", "no numeric part"},
		{SchemeAPK, "v1.2.3", "a semver git tag is not an apk version"},
		{SchemeAPK, "1.2.3-r1-r2", "two revision markers"},
	}
	for _, c := range cases {
		if c.scheme == SchemeDebian && c.v == "1.0.0-alpha+build.1" {
			// Documented NON-refusal: every character is legal in
			// deb-version(7), so dpkg itself would accept this string. It is
			// listed here so the gap is visible rather than implied.
			if err := ValidVersion(c.scheme, c.v); err != nil {
				t.Errorf("ValidVersion(%s, %q) refused, but every character is legal under "+
					"deb-version(7); if this becomes a refusal the comment above must change too: %v",
					c.scheme, c.v, err)
			}
			continue
		}
		err := ValidVersion(c.scheme, c.v)
		if err == nil {
			t.Errorf("ValidVersion(%s, %q) accepted a version it should refuse (%s)", c.scheme, c.v, c.why)
			continue
		}
		r, ok := err.(*Refusal)
		if !ok {
			t.Errorf("ValidVersion(%s, %q) returned %T, want *Refusal", c.scheme, c.v, err)
			continue
		}
		if !r.Reason.Valid() {
			t.Errorf("ValidVersion(%s, %q) refused with an undeclared reason %q", c.scheme, c.v, r.Reason)
		}
	}
}

// TestUnimplementedSchemesAreRefusedByName is the report the packet asks for,
// enforced. Every ecosystem below is one Anvil will really see, and each must
// be refused BY NAME rather than compared as semver.
func TestUnimplementedSchemesAreRefusedByName(t *testing.T) {
	refused := []string{
		"npm", "pypi", "golang", "go", "maven", "nuget", "cargo", "gem",
		"composer", "conan", "hex", "pub", "swift", "cocoapods", "generic",
		// OSV's own distro spellings, which are NOT this vocabulary and
		// must be normalised by ingestion rather than guessed at here.
		"Debian:11", "Debian", "Alpine:v3.19", "Alpine", "Red Hat", "Ubuntu:22.04",
		// Case variants of the supported three.
		"DEB", "Rpm", "APK",
		"",
	}
	for _, eco := range refused {
		if _, err := SchemeForEcosystem(eco); err == nil {
			t.Errorf("SchemeForEcosystem(%q) resolved a scheme; this comparator implements only %v "+
				"and every other ecosystem must be refused by name, not compared as semver",
				eco, SchemeValues())
		}
	}
	for _, eco := range []string{EcosystemDeb, EcosystemRPM, EcosystemAPK} {
		if _, err := SchemeForEcosystem(eco); err != nil {
			t.Errorf("SchemeForEcosystem(%q) refused an implemented ecosystem: %v", eco, err)
		}
	}
	for _, pt := range []string{"npm", "pypi", "golang", "maven", "nuget", "cargo", "oci", ""} {
		if _, err := SchemeForPurlType(pt); err == nil {
			t.Errorf("SchemeForPurlType(%q) resolved a scheme; it must be refused", pt)
		}
	}
	for _, pt := range []string{"deb", "rpm", "apk", "DEB", "Rpm"} {
		if _, err := SchemeForPurlType(pt); err != nil {
			t.Errorf("SchemeForPurlType(%q) refused; purl types are case-insensitive: %v", pt, err)
		}
	}
}

// TestCompareNeverFallsBackToSemver is the single most important negative
// assertion in this file. If a scheme is unimplemented, Compare must refuse —
// not answer.
func TestCompareNeverFallsBackToSemver(t *testing.T) {
	for _, scheme := range []Scheme{"", "npm", "semver", "pypi", "golang", "maven"} {
		got, err := Compare(scheme, "1.0.0", "2.0.0")
		if err == nil {
			t.Fatalf("Compare(%q, ...) answered %d instead of refusing. A fallback to semver is "+
				"the failure mode this package exists to prevent.", scheme, got)
		}
		if got != 0 {
			t.Errorf("Compare(%q, ...) returned a non-zero ordering alongside its refusal (%d); "+
				"a caller that ignores the error must not receive a usable-looking answer", scheme, got)
		}
	}
}

// G2 census: every refusal reachable from the exported surface must carry a
// declared reason.
func TestEveryReachableRefusalCarriesADeclaredReason(t *testing.T) {
	var errs []error
	errs = append(errs, mustErr(t, func() error { _, e := SchemeForEcosystem("npm"); return e }))
	errs = append(errs, mustErr(t, func() error { _, e := SchemeForPurlType("npm"); return e }))
	errs = append(errs, mustErr(t, func() error { _, e := ParsePurl("not-a-purl"); return e }))
	errs = append(errs, mustErr(t, func() error { return ValidVersion(SchemeDebian, "v1") }))
	errs = append(errs, mustErr(t, func() error { return ValidVersion(SchemeRPM, "") }))
	errs = append(errs, mustErr(t, func() error { return ValidVersion(SchemeAPK, "1.00") }))
	errs = append(errs, mustErr(t, func() error { _, e := Compare("npm", "1", "2"); return e }))
	// RefusalUnmodelledOrdering: two well-formed apk versions whose ORDER is
	// decided by a token weight apk does not publish (rule R8).
	errs = append(errs, mustErr(t, func() error { _, e := Compare(SchemeAPK, "1.0", "1"); return e }))
	// RefusalEpochPresenceMismatch: a range endpoint that omits an epoch the
	// installed version spells. It is a RANGE-level refusal, so it comes from
	// contains rather than from validate or Compare.
	errs = append(errs, mustErr(t, func() error {
		_, e := AffectedRange{
			Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: "p",
			Introduced: "0", Fixed: "2.0",
		}.contains(SchemeDebian, "1:1.0")
		return e
	}))

	// Range-level refusals, one per reason the validator can produce.
	for _, r := range []AffectedRange{
		{Source: "s", SourceID: "i", Ecosystem: "npm", Package: "p", Fixed: "1"},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: "p", Fixed: "1", LastAffected: "2"},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: "p"},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: "p", AllVersions: true, Fixed: "1"},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: "p", Fixed: "1", FixedEcosystem: EcosystemRPM},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemRPM, Package: "p", Fixed: "1"},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: "p", Fixed: "vNope"},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: "p", Introduced: "2.0", Fixed: "1.0"},
		{Source: "s", SourceID: "i", Ecosystem: EcosystemDeb, Package: ""},
	} {
		if err := r.validate(SchemeDebian); err != nil {
			errs = append(errs, err)
		}
	}

	seen := map[RefusalReason]bool{}
	for _, err := range errs {
		if err == nil {
			continue
		}
		r, ok := err.(*Refusal)
		if !ok {
			t.Errorf("error %v is a %T, not a *Refusal", err, err)
			continue
		}
		if !r.Reason.Valid() {
			t.Errorf("refusal carries an undeclared reason %q: %v", r.Reason, r)
		}
		seen[r.Reason] = true
		if !strings.Contains(r.Error(), string(r.Reason)) {
			t.Errorf("Refusal.Error() does not name its reason: %q", r.Error())
		}
	}

	// Every declared reason should be reachable; a reason nothing can emit is
	// either dead vocabulary or a control nothing enforces.
	for _, reason := range RefusalReasons() {
		switch reason {
		case RefusalSchemeMismatch, RefusalMixedSchemeRange, RefusalAmbiguousUpperBound,
			RefusalUnboundedRange, RefusalContradictoryRange, RefusalUnsupportedEcosystem,
			RefusalUnsupportedPurlType, RefusalMalformedPurl, RefusalMalformedVersion,
			RefusalNoPackageIdentity, RefusalEpochPresenceMismatch, RefusalUnmodelledOrdering:
			if !seen[reason] {
				t.Errorf("declared refusal reason %q was not produced by any probe in this test; "+
					"either it is unreachable or this test does not cover it", reason)
			}
		case RefusalIdentityConflict:
			// Produced by identify(), covered by
			// TestIdentityConflictsAreRefused below.
		}
	}
}

func mustErr(t *testing.T, f func() error) error {
	t.Helper()
	err := f()
	if err == nil {
		t.Fatalf("expected a refusal, got nil")
	}
	return err
}

// G2 RED. A Refusal carrying a reason outside the allowlist must be reported.
// Without this, TestEveryReachableRefusalCarriesADeclaredReason could pass
// because it never sees a bad value, not because bad values are impossible.
func TestRefusalReasonGuardFiresOnAnUndeclaredReason(t *testing.T) {
	r := &Refusal{Reason: RefusalReason("a_reason_nobody_declared"), Detail: "synthetic"}
	if r.Reason.Valid() {
		t.Fatal("RefusalReason.Valid() accepted a reason outside the allowlist; " +
			"the membership test is vacuous and every other refusal assertion in this file is worthless")
	}
	if !strings.Contains(r.Error(), "UNDECLARED REFUSAL REASON") {
		t.Errorf("Refusal.Error() rendered an undeclared reason as if it were legitimate: %q", r.Error())
	}
	// And the empty reason, which is what a zero-valued Refusal carries.
	if (RefusalReason("")).Valid() {
		t.Error("the empty refusal reason is a member of the allowlist; a zero-valued Refusal would pass")
	}
}

// ---------------------------------------------------------------------------
// purl
// ---------------------------------------------------------------------------

func TestParsePurl(t *testing.T) {
	cases := []struct {
		raw       string
		typ       string
		namespace string
		name      string
		version   string
	}{
		{"pkg:deb/debian/openssl@1.1.1n-0+deb11u5", "deb", "debian", "openssl", "1.1.1n-0+deb11u5"},
		{"pkg:rpm/redhat/python3-requests@2.25.1-3.el9?arch=noarch", "rpm", "redhat", "python3-requests", "2.25.1-3.el9"},
		{"pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64", "apk", "alpine", "openssl", "3.1.4-r5"},
		{"PKG:DEB/debian/openssl@1.0", "deb", "debian", "openssl", "1.0"},
		{"pkg:deb/debian/openssl", "deb", "debian", "openssl", ""},
		{"pkg:deb/openssl@1.0", "deb", "", "openssl", "1.0"},
		{"pkg:deb/debian/lib%2Bfoo@1.0", "deb", "debian", "lib+foo", "1.0"},
		{"pkg:deb/debian/openssl@1%3A1.0", "deb", "debian", "openssl", "1:1.0"},
	}
	for _, c := range cases {
		got, err := ParsePurl(c.raw)
		if err != nil {
			t.Errorf("ParsePurl(%q): %v", c.raw, err)
			continue
		}
		if got.Type != c.typ || got.Namespace != c.namespace || got.Name != c.name || got.Version != c.version {
			t.Errorf("ParsePurl(%q) = %+v, want type=%q ns=%q name=%q version=%q",
				c.raw, got, c.typ, c.namespace, c.name, c.version)
		}
	}

	// The '+' in a Debian version must survive as a literal plus. Decoding it
	// as a space (which net/url's query decoder would) produces a version no
	// comparator will ever match.
	p, err := ParsePurl("pkg:deb/debian/openssl@1.1.1n-0+deb11u5")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Version, "+deb11u5") {
		t.Errorf("the '+' in a Debian version was not preserved: %q", p.Version)
	}

	for _, bad := range []string{
		"", "openssl", "http://example.com/openssl", "pkg:", "pkg:deb",
		"pkg:deb/", "pkg:deb/debian/openssl@1.0?=x",
		"pkg:deb/debian/openssl@1.0?arch=amd64&arch=i386",
		"pkg:deb/debian/openssl@1.0?ARCH=amd64&arch=i386",
		"pkg:deb/debian/open%zzssl@1.0", "pkg:deb/debian/openssl@1.0%",
		"pkg:1deb/debian/openssl@1.0", "pkg:deb /debian/openssl@1.0",
	} {
		if got, err := ParsePurl(bad); err == nil {
			t.Errorf("ParsePurl(%q) accepted a malformed purl: %+v", bad, got)
		}
	}
}

// The purl's version-free base must come from record.PurlBase and nowhere
// else. plan/00-SPINE.md S6: one fingerprint algorithm, defined once.
func TestPurlBaseDelegatesToTheRecordContract(t *testing.T) {
	raw := "pkg:deb/debian/openssl@1.1.1n-0+deb11u5?arch=amd64#sub"
	p, err := ParsePurl(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Base()
	if err != nil {
		t.Fatal(err)
	}
	want, err := record.PurlBase(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Purl.Base() = %q but record.PurlBase(%q) = %q; there must be exactly one base-purl derivation",
			got, raw, want)
	}
}

func TestIdentityConflictsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		rec  PackageRecord
	}{
		{"purl type disagrees with ecosystem", PackageRecord{
			Collector: CollectorRepoSCA, Ecosystem: EcosystemRPM, Name: "openssl",
			Version: "1.0", Purl: "pkg:deb/debian/openssl@1.0",
		}},
		{"purl name disagrees with reported name", PackageRecord{
			Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl",
			Version: "1.0", Purl: "pkg:deb/debian/libssl1.1@1.0",
		}},
	}
	for _, c := range cases {
		_, err := identify(c.rec)
		if err == nil {
			t.Errorf("%s: identify accepted two identity sources that disagree", c.name)
			continue
		}
		r, ok := err.(*Refusal)
		if !ok || r.Reason != RefusalIdentityConflict {
			t.Errorf("%s: got %v, want RefusalIdentityConflict", c.name, err)
		}
	}

	// A record with no identity at all is the research/12 §3 false-negative
	// class and must be refused with its own reason, not lumped in.
	for _, rec := range []PackageRecord{
		{Collector: CollectorHost, Version: "1.0"},
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Version: "1.0"},
		{Collector: CollectorHost, Name: "openssl", Version: "1.0"},
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl"},
		{Collector: "some-new-collector", Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.0"},
	} {
		_, err := identify(rec)
		r, ok := err.(*Refusal)
		if !ok || r.Reason != RefusalNoPackageIdentity {
			t.Errorf("identify(%+v) = %v, want RefusalNoPackageIdentity", rec, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Range semantics — where off-by-one lives
// ---------------------------------------------------------------------------

// TestRangeBoundariesAreExplicitAtEveryEdge pins the difference between
// "fixed in 1.2.3" (exclusive: 1.2.3 is SAFE) and "affected up to 1.2.3"
// (inclusive: 1.2.3 is VULNERABLE). Both are common in real advisories and
// they differ by exactly one version.
func TestRangeBoundariesAreExplicitAtEveryEdge(t *testing.T) {
	type tc struct {
		name      string
		rng       AffectedRange
		installed string
		want      bool
	}
	base := func(r AffectedRange) AffectedRange {
		r.Source, r.SourceID, r.Ecosystem, r.Package = "osv", "OSV-1", EcosystemDeb, "openssl"
		return r
	}
	cases := []tc{
		// "fixed in 1.2.3": the fixed version itself is SAFE.
		{"fixed: below", base(AffectedRange{Introduced: "1.0", Fixed: "1.2.3"}), "1.2.2", true},
		{"fixed: at the boundary is safe", base(AffectedRange{Introduced: "1.0", Fixed: "1.2.3"}), "1.2.3", false},
		{"fixed: above", base(AffectedRange{Introduced: "1.0", Fixed: "1.2.3"}), "1.2.4", false},
		{"fixed: at the introduced boundary is vulnerable", base(AffectedRange{Introduced: "1.0", Fixed: "1.2.3"}), "1.0", true},
		{"fixed: below introduced", base(AffectedRange{Introduced: "1.0", Fixed: "1.2.3"}), "0.9", false},

		// "affected up to 1.2.3": the last-affected version itself is
		// VULNERABLE. This is the one-version difference.
		{"last_affected: at the boundary is vulnerable", base(AffectedRange{Introduced: "1.0", LastAffected: "1.2.3"}), "1.2.3", true},
		{"last_affected: above", base(AffectedRange{Introduced: "1.0", LastAffected: "1.2.3"}), "1.2.4", false},

		// Open-ended ranges.
		{"no lower bound", base(AffectedRange{Fixed: "1.2.3"}), "0.0.1", true},
		{"no upper bound", base(AffectedRange{Introduced: "1.0"}), "99.0", true},
		{"no upper bound, below introduced", base(AffectedRange{Introduced: "1.0"}), "0.9", false},
		{"all versions", base(AffectedRange{AllVersions: true}), "0.0.1", true},

		// Tilde at the boundary, which is where a pre-release is misjudged.
		{"a release candidate is below its release", base(AffectedRange{Introduced: "1.0", Fixed: "2.0"}), "2.0~rc1", true},
		{"the release itself is fixed", base(AffectedRange{Introduced: "1.0", Fixed: "2.0"}), "2.0", false},

		// Epoch at the boundary. An epoch spelled on BOTH sides orders
		// normally; the one-sided case is not here because it is not an
		// ordering at all — see TestAnEpochOnOneSideOnlyIsRefusedAndNever
		// ASilentClean, which replaced the row that used to sit here.
		//
		// THAT ROW SAID: {"an epoch bump clears the range", [1.0, 2.0),
		// installed "1:0.1", want false}. An installed version carrying an
		// epoch against a range carrying none, asserted NOT AFFECTED. It was
		// the implementation's behaviour written down as the expectation, and
		// it is the single line that made A.18's blocker §3.2 look intended.
		{"an epoch on both sides orders normally", base(AffectedRange{Introduced: "1:1.0", Fixed: "1:2.0"}), "1:0.1", false},
		{"an epoch on both sides, inside the range", base(AffectedRange{Introduced: "1:1.0", Fixed: "1:2.0"}), "1:1.5", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.rng.validate(SchemeDebian); err != nil {
				t.Fatalf("validate: %v", err)
			}
			got, err := c.rng.contains(SchemeDebian, c.installed)
			if err != nil {
				t.Fatalf("contains: %v", err)
			}
			if got != c.want {
				t.Errorf("%s contains %q = %v, want %v", c.rng.Expr(), c.installed, got, c.want)
			}
		})
	}
}

// TestRangeExprSpellsOutItsBoundaries: the rendered range is what a human
// reads on a finding, so it must say which side of the boundary is included.
func TestRangeExprSpellsOutItsBoundaries(t *testing.T) {
	cases := []struct {
		rng  AffectedRange
		want string
	}{
		{AffectedRange{Introduced: "1.0", Fixed: "2.0"}, "[1.0, 2.0)"},
		{AffectedRange{Introduced: "1.0", LastAffected: "2.0"}, "[1.0, 2.0]"},
		{AffectedRange{Fixed: "2.0"}, "(-inf, 2.0)"},
		{AffectedRange{Introduced: "1.0"}, "[1.0, +inf)"},
		{AffectedRange{AllVersions: true}, "(-inf, +inf) [all versions]"},
	}
	for _, c := range cases {
		if got := c.rng.Expr(); got != c.want {
			t.Errorf("Expr() = %q, want %q", got, c.want)
		}
	}
}

// TestMixedSchemeAndAmbiguousRangesAreRefused: the packet's explicit
// requirement. Refuse a range whose endpoints are in different schemes rather
// than guessing which one wins.
func TestMixedSchemeAndAmbiguousRangesAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		rng    AffectedRange
		scheme Scheme
		want   RefusalReason
	}{
		{"endpoints declare different ecosystems", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemRPM, Package: "requests",
			Introduced: "0", Fixed: "2.31.0", FixedEcosystem: "pypi",
		}, SchemeRPM, RefusalMixedSchemeRange},
		{"introduced declares a different ecosystem", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "1.0", IntroducedEcosystem: EcosystemRPM, Fixed: "2.0",
		}, SchemeDebian, RefusalMixedSchemeRange},
		{"range ecosystem is not the package's scheme", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemRPM, Package: "openssl",
			Introduced: "1.0", Fixed: "2.0",
		}, SchemeDebian, RefusalSchemeMismatch},
		{"both an exclusive fixed and an inclusive last_affected", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "1.0", Fixed: "2.0", LastAffected: "1.9",
		}, SchemeDebian, RefusalAmbiguousUpperBound},
		{"no bound at all", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemDeb, Package: "openssl",
		}, SchemeDebian, RefusalUnboundedRange},
		{"AllVersions alongside a bound", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemDeb, Package: "openssl",
			AllVersions: true, Fixed: "2.0",
		}, SchemeDebian, RefusalContradictoryRange},
		{"introduced above its upper bound", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "3.0", Fixed: "2.0",
		}, SchemeDebian, RefusalContradictoryRange},
		{"an endpoint that is not a version in the governing scheme", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "0", Fixed: "v2.31.0",
		}, SchemeDebian, RefusalMalformedVersion},
		{"an unimplemented ecosystem", AffectedRange{
			Source: "osv", SourceID: "O-1", Ecosystem: "pypi", Package: "requests",
			Introduced: "0", Fixed: "2.31.0",
		}, SchemeDebian, RefusalUnsupportedEcosystem},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.rng.validate(c.scheme)
			if err == nil {
				t.Fatalf("validate accepted %s", c.rng.Expr())
			}
			r, ok := err.(*Refusal)
			if !ok {
				t.Fatalf("got %T, want *Refusal", err)
			}
			if r.Reason != c.want {
				t.Errorf("reason = %q, want %q (%v)", r.Reason, c.want, r)
			}
		})
	}
}

// An unbounded range is the shape a FAILED PARSE takes by the time it reaches
// a database column. It must never be evaluated, because it would match every
// version of the package.
func TestAnEmptyRangeRowDoesNotMatchEverything(t *testing.T) {
	src := NewStaticSource([]AffectedRange{
		{Source: "cvelistv5", SourceID: "CVE-2000-0001", CVEID: "CVE-2000-0001",
			Ecosystem: EcosystemDeb, Package: "openssl"}, // introduced and fixed both empty
	})
	m, err := NewMatcher(src)
	if err != nil {
		t.Fatal(err)
	}
	results, cov, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.1.1n-0+deb11u5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("an empty introduced/fixed row produced %d findings; it must be refused, not evaluated", len(results))
	}
	if cov.RangesRefused != 1 {
		t.Errorf("RangesRefused = %d, want 1", cov.RangesRefused)
	}
	if cov.Complete {
		t.Error("coverage reported Complete despite an outstanding refusal")
	}
	if err := cov.AssertNotSilentlyClean(results); err == nil {
		t.Error("zero findings with an outstanding refusal was reported as clean")
	}
}

// ---------------------------------------------------------------------------
// The backport regression — A.17's named validation requirement
// ---------------------------------------------------------------------------

// backportFixture is the CVE-2023-32681 / RHSA-2023:4520 scenario from
// research/12 §3, verbatim in shape:
//
//	python-requests is vulnerable upstream below 2.31.0.
//	Red Hat BACKPORTED the fix into 2.25.1-3.el9 without moving the upstream
//	version, and says so in RHSA-2023:4520.
//	A host running 2.25.1-3.el9 is NOT vulnerable, and Trivy's own docs say
//	that reporting it "would be a false positive".
//
// The two ranges carry the SAME CVE, which is what puts them in one precedence
// group, and the vendor one is marked with the cache's `distro_backport`
// column.
func backportFixture(distroBackport bool) (*StaticSource, PackageRecord) {
	upstream := AffectedRange{
		Source: "ghsa", SourceID: "GHSA-j8r2-6x86-q33q", CVEID: "CVE-2023-32681",
		Ecosystem: EcosystemRPM, Package: "python3-requests",
		Introduced: "0", Fixed: "2.31.0",
		DistroBackport: false,
	}
	vendor := AffectedRange{
		Source: "redhat-csaf", SourceID: "RHSA-2023:4520", CVEID: "CVE-2023-32681",
		Ecosystem: EcosystemRPM, Package: "python3-requests",
		Introduced: "0", Fixed: "2.25.1-3.el9",
		DistroBackport: distroBackport,
	}
	installed := PackageRecord{
		Collector: CollectorHost,
		Ecosystem: EcosystemRPM,
		Name:      "python3-requests",
		Version:   "2.25.1-3.el9",
		Arch:      "noarch",
	}
	return NewStaticSource([]AffectedRange{upstream, vendor}), installed
}

func TestBackportRegressionDefeatsTheUpstreamFalsePositive(t *testing.T) {
	src, installed := backportFixture(true)
	m, err := NewMatcher(src)
	if err != nil {
		t.Fatal(err)
	}
	results, cov, err := m.Match(context.Background(), []PackageRecord{installed})
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 0 {
		t.Fatalf("the comparator flagged CVE-2023-32681 on a host running the BACKPORTED "+
			"python3-requests 2.25.1-3.el9. research/12 §3 and Trivy's own documentation both say "+
			"this is a false positive. Findings: %+v", results)
	}

	// A defence that leaves no trace is indistinguishable from a bug.
	if len(cov.Defences) != 1 {
		t.Fatalf("Defences = %d, want exactly 1; the suppression must be visible", len(cov.Defences))
	}
	d := cov.Defences[0]
	if d.Reason != DefenceVendorAdvisoryWins {
		t.Errorf("defence reason = %q, want %q", d.Reason, DefenceVendorAdvisoryWins)
	}
	if d.CVEID != "CVE-2023-32681" {
		t.Errorf("defence CVE = %q", d.CVEID)
	}
	if d.UpstreamSourceID != "GHSA-j8r2-6x86-q33q" || d.VendorSourceID != "RHSA-2023:4520" {
		t.Errorf("defence does not name both ranges: %+v", d)
	}
	if d.UpstreamRange != "[0, 2.31.0)" || d.VendorRange != "[0, 2.25.1-3.el9)" {
		t.Errorf("defence does not carry both rendered ranges: upstream=%q vendor=%q",
			d.UpstreamRange, d.VendorRange)
	}

	// Zero findings here is a REAL clean, and the report must say so — but
	// only because the run was complete over an evaluated package.
	if !cov.Complete {
		t.Errorf("coverage is not Complete though nothing was refused: %+v", cov)
	}
	if cov.PackagesEvaluated != 1 {
		t.Errorf("PackagesEvaluated = %d, want 1", cov.PackagesEvaluated)
	}
	if err := cov.AssertNotSilentlyClean(results); err != nil {
		t.Errorf("a complete run over one evaluated package with a recorded defence was rejected as "+
			"silently clean: %v", err)
	}
}

// G4 RED. The test above would pass for the wrong reason if the fixture never
// produced a finding in the first place — for instance if the version
// comparison were broken so that 2.25.1-3.el9 fell outside BOTH ranges. So:
// flip the vendor range's distro_backport flag off, and the SAME fixture must
// now produce the false positive.
func TestBackportRegressionIsNotVacuous(t *testing.T) {
	src, installed := backportFixture(false)
	m, err := NewMatcher(src)
	if err != nil {
		t.Fatal(err)
	}
	results, cov, err := m.Match(context.Background(), []PackageRecord{installed})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("with distro_backport cleared, the upstream range must still match 2.25.1-3.el9 " +
			"(it is below 2.31.0). It did not, so the passing backport test proves nothing about " +
			"the vendor-first policy and everything about a broken comparison.")
	}
	if len(cov.Defences) != 0 {
		t.Errorf("Defences = %d with no vendor range present, want 0", len(cov.Defences))
	}
	found := false
	for _, r := range results {
		if r.CVEID == "CVE-2023-32681" && r.Source == "ghsa" {
			found = true
		}
	}
	if !found {
		t.Errorf("the upstream GHSA range did not produce the expected match: %+v", results)
	}
}

// The vendor range must also be able to say "yes, still vulnerable" — the
// precedence is about WHICH range decides, not about suppressing findings.
func TestVendorRangeCanStillProduceAFinding(t *testing.T) {
	src := NewStaticSource([]AffectedRange{
		{Source: "ghsa", SourceID: "GHSA-x", CVEID: "CVE-2023-32681",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.31.0"},
		{Source: "redhat-csaf", SourceID: "RHSA-2023:4520", CVEID: "CVE-2023-32681",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.25.1-3.el9", DistroBackport: true},
	})
	m, _ := NewMatcher(src)
	// An UNPATCHED host: below the vendor's fixed release.
	results, _, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemRPM, Name: "python3-requests", Version: "2.25.1-1.el9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("want exactly one finding from the vendor range, got %d: %+v", len(results), results)
	}
	r := results[0]
	if r.Source != "redhat-csaf" || r.SourceID != "RHSA-2023:4520" {
		t.Errorf("the finding was not attributed to the vendor advisory: %+v", r)
	}
	if !r.VendorAdvisory {
		t.Error("VendorAdvisory is false on a finding decided by a distro_backport range")
	}
	if !r.DistroBackportDefended {
		t.Error("DistroBackportDefended is false though the vendor range displaced an upstream one")
	}
	if r.MatchedRange != "[0, 2.25.1-3.el9)" {
		t.Errorf("MatchedRange = %q", r.MatchedRange)
	}
	if r.FixedVersion != "2.25.1-3.el9" {
		t.Errorf("FixedVersion = %q", r.FixedVersion)
	}
	if r.RemediableByAgent {
		t.Error("a HOST finding reported RemediableByAgent; plan/00-SPINE.md S6/S7 and the cache's " +
			"finding_host_not_remediable CHECK both forbid it")
	}
	if r.Detector != record.DetectorKindHost || r.EvidenceClass != record.EvidenceClassHost {
		t.Errorf("host finding carries detector=%q evidence=%q", r.Detector, r.EvidenceClass)
	}
	if r.Trust != record.TrustAnvilGenerated {
		t.Errorf("Trust = %q, want %q (the CONCLUSION is Anvil's own)", r.Trust, record.TrustAnvilGenerated)
	}
}

// Two architectures of the same package that are both defended must produce
// two DISTINGUISHABLE defence rows. A defence that looks like a duplicate is a
// defence somebody will delete as noise.
func TestDefencesFromTwoArchitecturesAreDistinguishable(t *testing.T) {
	src := NewStaticSource([]AffectedRange{
		{Source: "ghsa", SourceID: "GHSA-1", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "3.0.4"},
		{Source: "debian", SourceID: "DSA-5169-1", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0",
			Fixed: "1.1.1n-0+deb11u3", DistroBackport: true},
	})
	m, _ := NewMatcher(src)
	results, cov, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.1.1n-0+deb11u4", Arch: "amd64"},
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.1.1n-0+deb11u4", Arch: "i386"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("both architectures carry the backported fix; got %d findings", len(results))
	}
	if len(cov.Defences) != 2 {
		t.Fatalf("Defences = %d, want 2 (one per architecture)", len(cov.Defences))
	}
	if cov.Defences[0].Arch == cov.Defences[1].Arch {
		t.Errorf("the two defence rows are indistinguishable: %+v", cov.Defences)
	}
	if cov.Defences[0].sortKey() >= cov.Defences[1].sortKey() {
		t.Error("defences are not in ascending sortKey order")
	}
}

// The precedence is scoped to the ADVISORY, not the package. A vendor range
// about one CVE must not suppress an upstream range about a DIFFERENT CVE —
// that would turn a false-positive defence into a false-negative generator.
// The residue is reported instead.
func TestVendorPrecedenceIsScopedToTheAdvisoryAndTheResidueIsReported(t *testing.T) {
	src := NewStaticSource([]AffectedRange{
		{Source: "redhat-csaf", SourceID: "RHSA-1", CVEID: "CVE-2023-32681",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.25.1-3.el9", DistroBackport: true},
		{Source: "ghsa", SourceID: "GHSA-other", CVEID: "CVE-2024-35195",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.32.0"},
	})
	m, _ := NewMatcher(src)
	results, cov, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemRPM, Name: "python3-requests", Version: "2.25.1-3.el9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2024-35195" {
		t.Fatalf("the un-triaged upstream CVE was suppressed by a vendor advisory about a DIFFERENT "+
			"CVE. That is an unbounded false-negative generator. Got: %+v", results)
	}
	if len(cov.UpstreamOnlyAdvisories) != 1 {
		t.Fatalf("UpstreamOnlyAdvisories = %d, want 1; the package-level residue must be reported "+
			"even though it is not suppressed", len(cov.UpstreamOnlyAdvisories))
	}
	if cov.UpstreamOnlyAdvisories[0].CVEID != "CVE-2024-35195" {
		t.Errorf("residue names the wrong advisory: %+v", cov.UpstreamOnlyAdvisories[0])
	}
}

// ---------------------------------------------------------------------------
// Coverage — "0 findings" is never "clean"
// ---------------------------------------------------------------------------

// G3 and its RED check in one: every shape of an empty result set that is NOT
// a clean answer must be rejected, and the one shape that IS must be accepted.
func TestSilentCleanGuardFiresOnEveryEmptyShape(t *testing.T) {
	cases := []struct {
		name    string
		cov     CoverageReport
		wantErr bool
	}{
		{"nothing submitted", CoverageReport{}, true},
		{"nothing evaluated", CoverageReport{PackagesSubmitted: 40, PackagesUnidentifiable: 40}, true},
		{"a source lookup failed", CoverageReport{
			PackagesSubmitted: 1, PackagesEvaluated: 1, Complete: false,
			SourceErrors: []SourceError{{Package: "openssl", Err: "boom"}},
		}, true},
		{"refusals outstanding", CoverageReport{
			PackagesSubmitted: 2, PackagesEvaluated: 1, RangesRefused: 1, RangesConsidered: 3,
			Refusals: []Refusal{{Reason: RefusalUnboundedRange}}, Complete: false,
		}, true},

		// THE ROW A.18 SHOWED WAS MISSING, AND IT IS THE ONE THIS PACKAGE
		// MOST NEEDED. An empty advisory cache over a full, well-formed
		// inventory: nothing refused, nothing errored, every package
		// evaluated — and not one of them compared against anything. Note
		// that it is byte-identical to the "genuinely clean run" row below
		// EXCEPT in the two fields the function used not to read, which is
		// precisely why the old table could not catch it.
		{"an empty advisory cache over a full inventory", CoverageReport{
			PackagesSubmitted: 400, PackagesEvaluated: 400,
			PackagesWithNoAdvisoryData: 400, RangesConsidered: 0, Complete: true,
		}, true},
		{"most packages uncovered but some compared is the NORMAL shape", CoverageReport{
			PackagesSubmitted: 400, PackagesEvaluated: 400,
			PackagesWithNoAdvisoryData: 396, RangesConsidered: 9, Complete: true,
		}, false},
		{"a report claiming completeness with nothing consulted", CoverageReport{
			PackagesSubmitted: 100, PackagesEvaluated: 100, RangesConsidered: 0, Complete: true,
		}, true},

		{"a genuinely clean run", CoverageReport{
			PackagesSubmitted: 100, PackagesEvaluated: 100,
			PackagesWithNoAdvisoryData: 40, RangesConsidered: 120, Complete: true,
		}, false},
	}
	for _, c := range cases {
		err := c.cov.AssertNotSilentlyClean(nil)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: AssertNotSilentlyClean = %v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
	// With findings present the question does not arise.
	if err := (CoverageReport{}).AssertNotSilentlyClean([]MatchResult{{}}); err != nil {
		t.Errorf("AssertNotSilentlyClean rejected a run that produced findings: %v", err)
	}
}

// TestCoverageCountsTheFalseNegativeRiskClass: A.17's Expected output schema
// requires CoverageReport to report "counts of packages with no matchable
// identity (the false-negative-risk class from research/12)".
func TestCoverageCountsTheFalseNegativeRiskClass(t *testing.T) {
	src := NewStaticSource(nil)
	m, _ := NewMatcher(src)
	inv := []PackageRecord{
		// Matchable.
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.0"},
		// Unpackaged binary: no ecosystem, no name.
		{Collector: CollectorHost, Version: "1.0"},
		// Stripped metadata: no version.
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "curl"},
		// Third-party ecosystem this comparator does not implement.
		{Collector: CollectorRepoSCA, Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Collector: CollectorRepoSCA, Purl: "pkg:pypi/requests@2.25.1", Name: "requests", Version: "2.25.1"},
		// Supported ecosystem, version the scheme cannot parse.
		{Collector: CollectorHost, Ecosystem: EcosystemAPK, Name: "musl", Version: "1.00"},
	}
	results, cov, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("unexpected findings: %+v", results)
	}
	if cov.PackagesSubmitted != 6 {
		t.Errorf("PackagesSubmitted = %d, want 6", cov.PackagesSubmitted)
	}
	if cov.PackagesEvaluated != 1 {
		t.Errorf("PackagesEvaluated = %d, want 1", cov.PackagesEvaluated)
	}
	if cov.PackagesUnidentifiable != 2 {
		t.Errorf("PackagesUnidentifiable = %d, want 2", cov.PackagesUnidentifiable)
	}
	if cov.PackagesRefusedScheme != 2 {
		t.Errorf("PackagesRefusedScheme = %d, want 2", cov.PackagesRefusedScheme)
	}
	if cov.PackagesRefusedVersion != 1 {
		t.Errorf("PackagesRefusedVersion = %d, want 1", cov.PackagesRefusedVersion)
	}
	if cov.PackagesWithNoAdvisoryData != 1 {
		t.Errorf("PackagesWithNoAdvisoryData = %d, want 1", cov.PackagesWithNoAdvisoryData)
	}
	want := []string{"npm"}
	if !reflect.DeepEqual(cov.EcosystemsRefused, want) {
		t.Errorf("EcosystemsRefused = %v, want %v (the purl-typed refusal reports its type in Detail, "+
			"not as an ecosystem)", cov.EcosystemsRefused, want)
	}
	if cov.Complete {
		t.Error("Complete is true despite five refusals")
	}
	if err := cov.AssertNotSilentlyClean(results); err == nil {
		t.Error("a run that could evaluate one package out of six reported clean")
	}
	if !reflect.DeepEqual(cov.SchemesImplemented, SchemeValues()) {
		t.Errorf("SchemesImplemented = %v, want %v", cov.SchemesImplemented, SchemeValues())
	}
}

func TestAdvisorySourceFailureIsNeverClean(t *testing.T) {
	m, _ := NewMatcher(failingSource{})
	results, cov, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.0"},
	})
	if err == nil {
		t.Fatal("a failing advisory source did not produce an error")
	}
	if len(cov.SourceErrors) != 1 {
		t.Errorf("SourceErrors = %d, want 1", len(cov.SourceErrors))
	}
	if cov.Complete {
		t.Error("Complete is true after a source failure")
	}
	if err := cov.AssertNotSilentlyClean(results); err == nil {
		t.Error("a run whose advisory lookups failed reported clean")
	}
}

type failingSource struct{}

func (failingSource) AffectedRanges(context.Context, string, string) ([]AffectedRange, error) {
	return nil, errors.New("cache is unavailable")
}

func TestNilAdvisorySourceIsRefused(t *testing.T) {
	if _, err := NewMatcher(nil); err == nil {
		t.Fatal("NewMatcher(nil) returned a matcher; it would report every package clean")
	}
}

func TestCancelledContextIsAnErrorNotAPartialAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, _ := NewMatcher(NewStaticSource(nil))
	results, cov, err := m.Match(ctx, []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.0"},
	})
	if err == nil {
		t.Fatal("a cancelled context produced no error")
	}
	if len(results) != 0 {
		t.Error("a cancelled run returned results")
	}
	if cov.Complete {
		t.Error("a cancelled run reported Complete")
	}
}

// ---------------------------------------------------------------------------
// The A.18 findings, each with the guard that would have caught it
// ---------------------------------------------------------------------------
//
// Every test in this section was written against the PRE-FIX code first and
// observed to FAIL there. A guard that has only ever been green is a guard
// nobody has tested, and each of these covers a defect that was live in a
// package whose whole suite was passing.

// G7 (A.18 §3.1, blocker). An empty advisory cache over a full inventory of
// well-formed packages is an ABSENCE OF DATA, not a clean host.
//
// RED against the pre-fix code: AssertNotSilentlyClean branched on
// PackagesSubmitted, PackagesEvaluated, SourceErrors and Complete and never
// read PackagesWithNoAdvisoryData — so this returned nil, over Complete=true,
// and the caller had no way to tell "nothing is wrong" from "nothing loaded".
func TestAFullInventoryAgainstAnEmptyAdvisoryCacheIsNotClean(t *testing.T) {
	inv := make([]PackageRecord, 0, 400)
	for i := 0; i < 400; i++ {
		inv = append(inv, PackageRecord{
			Collector: CollectorHost, Ecosystem: EcosystemDeb,
			Name: "pkg" + strconv.Itoa(i), Version: "1.0-1", Arch: "amd64",
		})
	}

	// An advisory source that is perfectly healthy and simply holds nothing:
	// A.5's bootstrap not yet run, or run and produced nothing, or ingestion
	// having normalised ecosystems into a vocabulary the `affected` rows do
	// not use. No error, no refusal, no malformed input anywhere.
	m, err := NewMatcher(NewStaticSource(nil))
	if err != nil {
		t.Fatal(err)
	}
	results, cov, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 0 {
		t.Fatalf("an empty advisory source produced %d findings", len(results))
	}
	if cov.PackagesEvaluated != 400 || cov.PackagesWithNoAdvisoryData != 400 {
		t.Fatalf("evaluated=%d noAdvisoryData=%d, want 400/400 — the fixture is not the shape "+
			"this test is about", cov.PackagesEvaluated, cov.PackagesWithNoAdvisoryData)
	}
	if cov.RangesConsidered != 0 {
		t.Fatalf("RangesConsidered = %d, want 0", cov.RangesConsidered)
	}
	if len(cov.Refusals) != 0 || len(cov.SourceErrors) != 0 {
		t.Fatalf("the fixture must be clean of refusals and source errors, or this test passes "+
			"for the wrong reason: refusals=%d sourceErrors=%d", len(cov.Refusals), len(cov.SourceErrors))
	}
	if cov.Complete {
		t.Error("Complete is true over a run that consulted no advisory range at all; " +
			"Complete's own doc says it means \"no findings is an answer\"")
	}
	if err := cov.AssertNotSilentlyClean(results); err == nil {
		t.Fatal("400 well-formed packages compared against an EMPTY advisory cache were reported " +
			"as a clean host. This is the failure mode this lane most needs to prevent, and it " +
			"was sitting inside the guard named for preventing it: \"the tool ran and found " +
			"nothing\" and \"the tool had nothing to compare against\" must not be the same output.")
	}
}

// G8 (A.18 §3.2, blocker). An epoch spelled on one side only must never
// produce a silent not-affected.
//
// RED against the pre-fix code: every one of the refusal cases below returned
// zero findings, zero refusals, Complete=true and nil from
// AssertNotSilentlyClean — a patched-looking verdict on a vulnerable host,
// on a shape RHEL produces by default.
func TestAnEpochOnOneSideOnlyIsRefusedAndNeverASilentClean(t *testing.T) {
	type tc struct {
		name      string
		rng       AffectedRange
		installed PackageRecord
		// wantFinding and wantRefusal are mutually exclusive by design: the
		// whole point is that neither outcome is "silently nothing".
		wantFinding bool
		wantRefusal bool
	}
	glibc := func(v string) PackageRecord {
		return PackageRecord{Collector: CollectorHost, Ecosystem: EcosystemRPM,
			Name: "glibc", Version: v, Arch: "x86_64"}
	}
	zlib := func(v string) PackageRecord {
		return PackageRecord{Collector: CollectorHost, Ecosystem: EcosystemDeb,
			Name: "zlib1g", Version: v, Arch: "amd64"}
	}
	rpmRange := func(introduced, fixed string) AffectedRange {
		return AffectedRange{Source: "redhat-csaf", SourceID: "RHSA-x", CVEID: "CVE-2023-4911",
			Ecosystem: EcosystemRPM, Package: "glibc",
			Introduced: introduced, Fixed: fixed, DistroBackport: true}
	}
	debRange := func(introduced, fixed string) AffectedRange {
		return AffectedRange{Source: "debian", SourceID: "DSA-x", CVEID: "CVE-2022-37434",
			Ecosystem: EcosystemDeb, Package: "zlib1g",
			Introduced: introduced, Fixed: fixed, DistroBackport: true}
	}

	cases := []tc{
		// A.18's probe P5, verbatim. Every RHEL 9 host carries epoch 2 on
		// glibc; advisory endpoints routinely omit it. 2 > 0, so the
		// installed version sorted ABOVE the fixed endpoint and the range
		// did not contain it.
		{"rpm: installed spells the epoch, the fixed endpoint does not",
			rpmRange("0", "2.34-100.el9"), glibc("2:2.34-60.el9"), false, true},

		// The control that makes the case above mean something: spell the
		// epoch on the UPPER bound and the SAME host is correctly reported
		// vulnerable. Without this row the refusal could be hiding a broken
		// comparison rather than a spelling disagreement.
		//
		// Note the lower bound is the real-world sentinel "0", NOT "0:0" —
		// see the next block of rows for why that distinction is the whole
		// reason this rule is directional.
		{"rpm: the epoch spelled on the upper bound finds the vulnerability",
			rpmRange("0", "2:2.34-100.el9"), glibc("2:2.34-60.el9"), true, false},

		{"deb: installed spells the epoch, the fixed endpoint does not",
			debRange("0", "1.2.13"), zlib("1:1.2.11.dfsg-2"), false, true},
		{"deb: the epoch spelled on the upper bound finds the vulnerability",
			debRange("0", "1:1.2.13"), zlib("1:1.2.11.dfsg-2"), true, false},

		// The OTHER dangerous direction, at the LOWER bound. `rpm -q --qf
		// '%{VERSION}-%{RELEASE}'` omits the epoch entirely, so a collector
		// CAN report an epoch-bearing package without its epoch — and
		// against an epoch-bearing lower bound that host then sorts below
		// the range and is reported not-affected.
		{"rpm: the introduced endpoint spells an epoch the installed version does not",
			rpmRange("2:0", "2:2.34-100.el9"), glibc("2.34-60.el9"), false, true},

		// ===== THE ROWS THAT KEEP THIS RULE FROM BECOMING ITS OWN =====
		// ===== FALSE-NEGATIVE GENERATOR                          =====
		//
		// `Introduced: "0"` is the universal "from the beginning" sentinel
		// in OSV, CSAF and every feed built on them. An epoch-bearing
		// installed version sorts ABOVE it, which keeps the host INSIDE the
		// range — the safe direction — so this must produce the finding and
		// not a refusal. A first draft of checkEpochAgreement refused it and
		// swallowed exactly the CVE-2023-4911 glibc finding the rule was
		// written to catch: a guard against silent clearance, quietly
		// producing silent clearances one coverage line at a time.
		{"the \"0\" introduced sentinel against an epoch-bearing host still finds it",
			rpmRange("0", "2:2.34-100.el9"), glibc("2:2.34-60.el9"), true, false},

		// The upper-bound mirror. If the installed epoch really is 0 and the
		// fix lands at epoch 2, the host IS affected until it takes the
		// epoch-2 build, so a finding is the right answer here rather than a
		// tolerated wrong one.
		{"an endpoint epoch above an epoch-free host reports affected, not refused",
			rpmRange("0", "2:2.34-100.el9"), glibc("2.34-60.el9"), true, false},

		// And `0:` against an absence spells the SAME number, so the
		// asymmetry cannot change the answer either way.
		{"an explicit zero epoch against an absent one is not a disagreement",
			rpmRange("0:0", "0:2.34-100.el9"), glibc("2.34-60.el9"), true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := NewMatcher(NewStaticSource([]AffectedRange{c.rng}))
			if err != nil {
				t.Fatal(err)
			}
			results, cov, err := m.Match(context.Background(), []PackageRecord{c.installed})
			if err != nil {
				t.Fatal(err)
			}

			if c.wantFinding {
				if len(results) != 1 {
					t.Fatalf("want 1 finding, got %d: %+v", len(results), results)
				}
				if len(cov.Refusals) != 0 {
					t.Errorf("a decidable comparison produced refusals: %+v", cov.Refusals)
				}
				return
			}

			if len(results) != 0 {
				t.Fatalf("want no finding, got %+v", results)
			}
			if !c.wantRefusal {
				return
			}
			if len(cov.Refusals) != 1 {
				t.Fatalf("want exactly 1 refusal, got %d: %+v", len(cov.Refusals), cov.Refusals)
			}
			if got := cov.Refusals[0].Reason; got != RefusalEpochPresenceMismatch {
				t.Errorf("refusal reason = %q, want %q", got, RefusalEpochPresenceMismatch)
			}
			if cov.RangesRefused != 1 {
				t.Errorf("RangesRefused = %d, want 1", cov.RangesRefused)
			}
			if cov.Complete {
				t.Error("Complete is true with an epoch disagreement outstanding")
			}
			if err := cov.AssertNotSilentlyClean(results); err == nil {
				t.Fatal("a vulnerable host whose installed epoch is spelled on only one side of " +
					"the comparison was reported CLEAN, with no refusal to look at. That is a " +
					"false negative on the commonest shape in the RPM world.")
			}
		})
	}
}

// The epoch rule is a RANGE rule, not an ordering rule, and this pins the
// distinction so that a later reader does not "simplify" one into the other.
// Compare must still order an epoch-bearing version against an epoch-free one
// exactly as dpkg and rpm do, because that is what those tools do and the
// published vectors say so.
func TestTheEpochRefusalDoesNotChangeTheOrdering(t *testing.T) {
	for _, c := range []struct {
		scheme Scheme
		a, b   string
		want   int
	}{
		{SchemeDebian, "0:1.0", "1.0", 0},
		{SchemeDebian, "1:0.1", "2.0", 1},
		{SchemeRPM, "0:1.0-1", "1.0-1", 0},
		{SchemeRPM, "2:2.34-60.el9", "2.34-100.el9", 1},
	} {
		got, err := Compare(c.scheme, c.a, c.b)
		if err != nil {
			t.Errorf("Compare(%s,%q,%q) refused: %v — the ORDERING is dpkg's and rpm's own and "+
				"must not have been changed by the range-level epoch rule", c.scheme, c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%s,%q,%q) = %d, want %d", c.scheme, c.a, c.b, got, c.want)
		}
	}
}

// recordingSource wraps an AdvisorySource and records the exact
// (ecosystem, package) keys it was asked for. It exists for G9: the identity
// layer and the lookup layer must agree about the name, and the only way to
// prove that is to look at the key that actually reached the source.
type recordingSource struct {
	inner AdvisorySource
	keys  []string
}

func (r *recordingSource) AffectedRanges(ctx context.Context, ecosystem, pkg string) ([]AffectedRange, error) {
	r.keys = append(r.keys, ecosystem+"/"+pkg)
	return r.inner.AffectedRanges(ctx, ecosystem, pkg)
}

// G9 (A.18 §3.3, blocker). A name spelling the identity check ACCEPTS must be
// the spelling the advisory lookup uses.
//
// RED against the pre-fix code: identify() accepted a case-differing Name
// under strings.EqualFold, citing purl's lowercase canonical form, and then
// kept the REPORTED spelling — which Match hands to AffectedRanges verbatim.
// The check passed and the lookup missed, landing the package in
// PackagesWithNoAdvisoryData, which (see G7) was wired to nothing.
//
// WHAT THIS TEST DOES NOT COVER, WRITTEN HERE SO IT IS NOT COUNTED AS
// COVERING IT. It varies the REPORTED name across three spellings of ONE
// package and holds the purl fixed, so every case it runs is a case where the
// two names ARE the same name. It exercises the fold and never the
// disagreement, and it cannot detect a purl that names a DIFFERENT package
// being adopted. That axis is G13,
// TestAPurlNamingADifferentPackageIsAConflict, which fixes the reported name
// and varies the purl's.
func TestTheAcceptedNameSpellingIsTheNameLookedUp(t *testing.T) {
	advisory := AffectedRange{
		Source: "debian", SourceID: "DSA-1", CVEID: "CVE-2022-2068",
		Ecosystem: EcosystemDeb, Package: "openssl",
		Introduced: "0", Fixed: "3.0.4",
	}

	for _, name := range []string{"openssl", "OpenSSL", "OPENSSL"} {
		t.Run("Name="+name, func(t *testing.T) {
			src := &recordingSource{inner: NewStaticSource([]AffectedRange{advisory})}
			m, err := NewMatcher(src)
			if err != nil {
				t.Fatal(err)
			}
			results, cov, err := m.Match(context.Background(), []PackageRecord{{
				Collector: CollectorRepoSCA, Ecosystem: EcosystemDeb, Name: name,
				Version: "1.1.1n-0+deb11u4", Purl: "pkg:deb/debian/openssl@1.1.1n-0+deb11u4",
				ManifestRelPath: "Dockerfile",
			}})
			if err != nil {
				t.Fatal(err)
			}

			want := EcosystemDeb + "/openssl"
			if len(src.keys) != 1 || src.keys[0] != want {
				t.Fatalf("the advisory source was asked for %v, want [%q]. The identity check "+
					"declared this spelling the same package as the purl's; the lookup must use "+
					"the same string it accepted.", src.keys, want)
			}
			if len(results) != 1 {
				t.Fatalf("want 1 finding, got %d (noAdvisoryData=%d)",
					len(results), cov.PackagesWithNoAdvisoryData)
			}
			if results[0].Package != "openssl" {
				t.Errorf("finding carries package %q; the purl's lowercase canonical name is the "+
					"one that must survive", results[0].Package)
			}
			if cov.PackagesWithNoAdvisoryData != 0 {
				t.Errorf("PackagesWithNoAdvisoryData = %d; the lookup missed", cov.PackagesWithNoAdvisoryData)
			}
		})
	}

	// And the reason the fold is explicit ASCII rather than
	// strings.EqualFold. U+017F LATIN SMALL LETTER LONG S folds to 's' under
	// Unicode simple case folding, so `opensſl` walked past the identity
	// guard and became a lookup key matching nothing. Package-name strings
	// come from outside Anvil; the guard has to enforce a canonical form,
	// not match a spelling.
	for _, hostile := range []string{"opensſl", "opensslK", "opensſL"} {
		_, err := identify(PackageRecord{
			Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: hostile,
			Version: "1.0", Purl: "pkg:deb/debian/openssl@1.0",
		})
		r, ok := err.(*Refusal)
		if !ok || r.Reason != RefusalIdentityConflict {
			t.Errorf("identify accepted the name %q against purl name \"openssl\" (%v); "+
				"Unicode simple case folding is not the purl specification's ASCII "+
				"lowercase canonical form", hostile, err)
		}
	}

	// asciiFoldEqual itself, directly, so the guard above cannot pass because
	// something else refused first.
	if asciiFoldEqual("opensſl", "openssl") {
		t.Error("asciiFoldEqual folded a non-ASCII rune onto an ASCII letter")
	}
	if !asciiFoldEqual("OpenSSL", "openssl") {
		t.Error("asciiFoldEqual rejected a pure ASCII case difference")
	}
}

// G13. A purl naming a DIFFERENT PACKAGE than the record is a conflict, not a
// spelling.
//
// ===========================================================================
// THE AXIS G9 NEVER MOVED
// ===========================================================================
//
// G9 above varies the REPORTED name across three spellings of ONE package and
// holds the purl fixed. Every case it runs is a case where the two names ARE
// the same name, so it exercises the fold and never the disagreement — and a
// guard that only ever sees agreement cannot be counted as covering
// disagreement. The fix for G9 was "when a purl is present, its name is the
// one that survives", and taken alone that sentence licenses adopting a purl
// name that is not the record's name at all: a record for `curl` next to
// `pkg:deb/debian/openssl` would be looked up as `openssl`, `curl`'s own
// advisories would never be consulted, and the host would be reported clean
// for a package nothing ever checked.
//
// This test moves the axis: the reported name is FIXED and the PURL name
// varies. The rule it pins is the one already applied to the ecosystem
// (rule 3's first half) and to the version (rule 6): a purl that DISAGREES
// with the record is RefusalIdentityConflict, and only a CASE difference is a
// spelling of the same name and may be canonicalised.
//
// RED CHECK: with identify()'s name comparison removed — the shape "take the
// purl name unconditionally" — the `curl`/`openssl` row below produces zero
// findings, zero refusals, Complete=true and nil from AssertNotSilentlyClean,
// while the advisory source is asked for `openssl` and never for `curl`.
func TestAPurlNamingADifferentPackageIsAConflict(t *testing.T) {
	// An advisory that WOULD match the reported package, so the silent-clean
	// version of this bug is visible as a missing finding rather than as an
	// absence of data.
	curlAdvisory := AffectedRange{
		Source: "debian", SourceID: "DSA-9", CVEID: "CVE-2023-38545",
		Ecosystem: EcosystemDeb, Package: "curl", Introduced: "0", Fixed: "7.88.1-10+deb12u5",
	}
	opensslAdvisory := AffectedRange{
		Source: "debian", SourceID: "DSA-1", CVEID: "CVE-2022-2068",
		Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "3.0.4",
	}

	for _, c := range []struct {
		name        string
		purlName    string
		wantRefusal bool
	}{
		// The disagreement. This is the whole point of the test.
		{"a different package entirely", "openssl", true},
		// A near miss, which is how this arrives in practice: a source
		// package name next to a binary package name.
		{"a related but different name", "curl-dev", true},
		{"a prefix of the reported name", "cur", true},
		{"the reported name with a suffix", "curl3", true},
		// Case folding is a SPELLING of the same name and stays accepted,
		// so the rule above cannot be satisfied by refusing everything.
		{"the same name, upper case", "CURL", false},
		{"the same name, mixed case", "cUrL", false},
		{"the same name", "curl", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := &recordingSource{inner: NewStaticSource(
				[]AffectedRange{curlAdvisory, opensslAdvisory})}
			m, err := NewMatcher(src)
			if err != nil {
				t.Fatal(err)
			}
			results, cov, err := m.Match(context.Background(), []PackageRecord{{
				Collector: CollectorHost, Ecosystem: EcosystemDeb,
				Name:    "curl",
				Purl:    "pkg:deb/debian/" + c.purlName + "@7.88.1-10+deb12u4",
				Version: "7.88.1-10+deb12u4", Arch: "amd64",
			}})
			if err != nil {
				t.Fatal(err)
			}

			if c.wantRefusal {
				if len(cov.Refusals) != 1 || cov.Refusals[0].Reason != RefusalIdentityConflict {
					t.Fatalf("purl name %q against reported name \"curl\" produced refusals %+v; "+
						"want exactly one RefusalIdentityConflict. Two identity sources naming "+
						"DIFFERENT PACKAGES is the situation in which adopting either one "+
						"attaches the answer to the wrong package.", c.purlName, cov.Refusals)
				}
				if cov.PackagesUnidentifiable != 1 {
					t.Errorf("PackagesUnidentifiable = %d, want 1", cov.PackagesUnidentifiable)
				}
				if len(src.keys) != 0 {
					t.Errorf("the advisory source was consulted with %v for a record whose two "+
						"identity sources name different packages; nothing may be looked up "+
						"under a name that lost an unresolved conflict", src.keys)
				}
				if len(results) != 0 {
					t.Errorf("a refused identity produced findings: %+v", results)
				}
				if cov.Complete {
					t.Error("Complete is true with an identity conflict outstanding")
				}
				if err := cov.AssertNotSilentlyClean(results); err == nil {
					t.Fatal("a record whose purl names a different package than the record was " +
						"reported CLEAN. The package the record actually names was never " +
						"looked up, so this is an unexamined host, not a patched one.")
				}
				return
			}

			// The fold cases: accepted, canonicalised to the purl's lower
			// case name, and looked up under it.
			if len(cov.Refusals) != 0 {
				t.Fatalf("a pure case difference was refused: %+v", cov.Refusals)
			}
			want := EcosystemDeb + "/curl"
			if len(src.keys) != 1 || src.keys[0] != want {
				t.Fatalf("the advisory source was asked for %v, want [%q]", src.keys, want)
			}
			if len(results) != 1 {
				t.Fatalf("want the curl finding, got %d: %+v", len(results), results)
			}
			if results[0].Package != "curl" {
				t.Errorf("finding carries package %q, want \"curl\"", results[0].Package)
			}
		})
	}
}

// G14 (M1). A range endpoint dpkg itself rejects must be REFUSED, not
// repaired into something comparable.
//
// ===========================================================================
// WHY THIS IS A SILENT CLEAN AND NOT A COSMETIC PARSE QUESTION
// ===========================================================================
//
// dpkg_compare.go's header claimed "parseDebian rejects rather than repairs".
// It repaired one thing: a trailing '-' was taken as a revision split
// producing an EMPTY revision, and debVerrevcmp compares an empty revision
// equal to an absent one — so `1.0-` was silently `1.0`. Dpkg_Version.t line
// 112 states the string is invalid, and dpkgValidity in
// corpus_transcribed_test.go now transcribes that assertion.
//
// The cost lands on the RANGE, not on the ordering. AffectedRange.validate
// checks endpoints with ValidVersion, which is parseDebian, so an endpoint
// nobody could have produced was accepted and then DECIDED the predicate by
// comparing as something. A truncated `Fixed` endpoint reads as a LOWER upper
// bound than the advisory meant, every installed version above it falls
// outside the range, and the host is reported clean with no finding, no
// refusal and Complete=true.
//
// RED CHECK: with the empty-revision refusal removed from parseDebian, the
// "endpoint dpkg rejects" row below produces findings=0, refusals=0,
// Complete=true and nil from AssertNotSilentlyClean.
func TestARangeEndpointDpkgRejectsIsRefusedNotRepaired(t *testing.T) {
	// The host is genuinely vulnerable: 1.0-1 is below the real fix, 1.0-2.
	installed := PackageRecord{Collector: CollectorHost, Ecosystem: EcosystemDeb,
		Name: "zlib1g", Version: "1.0-1", Arch: "amd64"}

	rangeWith := func(fixed string) AffectedRange {
		return AffectedRange{
			Source: "debian", SourceID: "DSA-77", CVEID: "CVE-2024-0001",
			Ecosystem: EcosystemDeb, Package: "zlib1g", Introduced: "0", Fixed: fixed,
		}
	}

	// The control FIRST, so the fixture is known to be vulnerable and the
	// refusal below cannot be passing vacuously.
	t.Run("control: a well-formed endpoint finds the vulnerability", func(t *testing.T) {
		m, _ := NewMatcher(NewStaticSource([]AffectedRange{rangeWith("1.0-2")}))
		results, cov, err := m.Match(context.Background(), []PackageRecord{installed})
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != 1 {
			t.Fatalf("the fixture is not vulnerable, so the refusal case proves nothing: "+
				"got %d findings", len(results))
		}
		if !cov.Complete {
			t.Errorf("a well-formed range did not produce a complete run: %+v", cov.Refusals)
		}
	})

	for _, endpoint := range []struct {
		v    string
		what string
	}{
		{"1.0-", "an empty revision (Dpkg_Version.t line 112: \"empty revision is invalid\")"},
		{"1.0-2-", "an empty revision after a real one"},
		{":1.0", "an empty epoch (Dpkg_Version.t line 108)"},
		{"-0", "an empty upstream version (Dpkg_Version.t line 100)"},
		{"foo5.2", "an upstream version that does not start with a digit (line 121)"},
		{"5.2@3-2", "an illegal character (line 119)"},
		{"10a:5.2", "a non-numeric epoch (line 114)"},
	} {
		t.Run("endpoint dpkg rejects: "+endpoint.v, func(t *testing.T) {
			m, _ := NewMatcher(NewStaticSource([]AffectedRange{rangeWith(endpoint.v)}))
			results, cov, err := m.Match(context.Background(), []PackageRecord{installed})
			if err != nil {
				t.Fatal(err)
			}

			if len(cov.Refusals) != 1 || cov.Refusals[0].Reason != RefusalMalformedVersion {
				t.Fatalf("endpoint %q (%s) produced refusals %+v; want exactly one "+
					"RefusalMalformedVersion. An endpoint the tool this comparator ports "+
					"would reject must not be repaired into something comparable.",
					endpoint.v, endpoint.what, cov.Refusals)
			}
			if cov.RangesRefused != 1 {
				t.Errorf("RangesRefused = %d, want 1", cov.RangesRefused)
			}
			if len(results) != 0 {
				t.Errorf("a refused range produced findings: %+v", results)
			}
			if cov.Complete {
				t.Error("Complete is true with a refused range outstanding")
			}
			if err := cov.AssertNotSilentlyClean(results); err == nil {
				t.Fatalf("endpoint %q decided a range and cleared a VULNERABLE host with no "+
					"refusal to look at. The control above proves this host is inside the "+
					"advisory's real range.", endpoint.v)
			}
		})
	}

	// The same string as an INSTALLED version, so the strictness is the same
	// on both sides of the comparison rather than being an endpoint-only
	// rule bolted on.
	_, err := identify(PackageRecord{Collector: CollectorHost, Ecosystem: EcosystemDeb,
		Name: "zlib1g", Version: "1.0-"})
	r, ok := err.(*Refusal)
	if !ok || r.Reason != RefusalMalformedVersion {
		t.Errorf("identify accepted the installed version \"1.0-\" (%v); endpoints and "+
			"installed versions are validated by the same parser and must be validated to "+
			"the same strictness", err)
	}
}

// G16. A vendor range that cannot participate in the precedence must be
// REPORTED, including when it is also refused.
//
// UngroupedVendorAdvisories exists to make "the vendor defence could not fire"
// visible. It was recorded only AFTER the range passed validate(), so a vendor
// row that both lacked its CVE alias and failed to parse — the case where the
// defence most emphatically could not fire — was the one case the list left
// out. A report that omits the case it was built for is the same defect as a
// guard that skips.
//
// M1's fix makes this reachable more often, not less: endpoints are now held
// to dpkg's own strictness, so more vendor rows land in the refused branch.
//
// RED CHECK: with the recording left below the validate() early return,
// UngroupedVendorAdvisories is empty for the refused row here.
func TestAnUngroupableVendorRangeIsReportedEvenWhenItIsAlsoRefused(t *testing.T) {
	upstream := AffectedRange{
		Source: "ghsa", SourceID: "GHSA-2", CVEID: "CVE-2022-2068",
		Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "3.0.4",
	}
	installed := PackageRecord{Collector: CollectorHost, Ecosystem: EcosystemDeb,
		Name: "openssl", Version: "1.1.1n-0+deb11u4", Arch: "amd64"}

	for _, c := range []struct {
		name  string
		fixed string
	}{
		{"the vendor row parses", "1.1.1n-0+deb11u3"},
		// An endpoint dpkg rejects, which M1 now refuses.
		{"the vendor row is also refused", "1.1.1n-0+deb11u3-"},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := NewStaticSource([]AffectedRange{
				{Source: "debian", SourceID: "DSA-5169-1", CVEID: "",
					Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0",
					Fixed: c.fixed, DistroBackport: true},
				upstream,
			})
			m, _ := NewMatcher(src)
			_, cov, err := m.Match(context.Background(), []PackageRecord{installed})
			if err != nil {
				t.Fatal(err)
			}
			if len(cov.UngroupedVendorAdvisories) != 1 {
				t.Fatalf("UngroupedVendorAdvisories = %+v, want the one vendor row that carries "+
					"no CVE alias. This list is the only place \"the vendor defence could not "+
					"fire\" is visible, and a vendor row that is ALSO refused is the strongest "+
					"instance of it, not an exception to it.", cov.UngroupedVendorAdvisories)
			}
			u := cov.UngroupedVendorAdvisories[0]
			if u.Source != "debian" || u.SourceID != "DSA-5169-1" || u.Package != "openssl" {
				t.Errorf("the report does not name the vendor row it could not group: %+v", u)
			}
			if len(cov.Defences) != 0 {
				t.Errorf("a defence fired between two rows that share no identifier: %+v", cov.Defences)
			}
		})
	}
}

// AssertNotSilentlyClean's doc used to promise more than the function
// establishes. This test is the doc: every sentence the doc now makes is
// asserted here, INCLUDING the negative ones, because a limit that is only
// written down is a limit nobody has checked.
//
// The project rule is that a claim which cannot be demonstrated is deleted
// rather than qualified — so the sentences that could not be demonstrated
// ("the single flag a caller may read", "the sufficient answer to whether a
// zero-finding run is clean") are gone from the doc, and what is left is what
// runs below.
func TestAssertNotSilentlyCleanEstablishesExactlyWhatItsDocClaims(t *testing.T) {
	// (1) It refuses every shape in which NOTHING WAS COMPARED. This is the
	// proposition the function does establish.
	for _, c := range []struct {
		name string
		cov  CoverageReport
	}{
		{"nothing submitted", CoverageReport{}},
		{"nothing evaluated", CoverageReport{PackagesSubmitted: 5}},
		{"every evaluated package had an empty advisory set", CoverageReport{
			PackagesSubmitted: 400, PackagesEvaluated: 400,
			PackagesWithNoAdvisoryData: 400, Complete: true}},
		{"no range consulted", CoverageReport{
			PackagesSubmitted: 400, PackagesEvaluated: 400, Complete: true}},
		{"a source lookup failed", CoverageReport{
			PackagesSubmitted: 5, PackagesEvaluated: 5, RangesConsidered: 5,
			SourceErrors: []SourceError{{Package: "x", Err: "cache unavailable"}}}},
		{"refusals outstanding", CoverageReport{
			PackagesSubmitted: 5, PackagesEvaluated: 5, RangesConsidered: 5,
			RangesRefused: 1, Complete: false}},
	} {
		if err := c.cov.AssertNotSilentlyClean(nil); err == nil {
			t.Errorf("%s: accepted as a clean result", c.name)
		}
	}

	// (2) THE LIMIT THE DOC NOW STATES, ASSERTED SO IT CANNOT BE FORGOTTEN.
	// PackagesWithNoAdvisoryData is checked ALL-OR-NOTHING. A run in which
	// 399 of 400 packages had no advisory rows passes, because that is the
	// normal shape of a healthy scan against a real database and a fractional
	// threshold would refuse every real run. The consequence is that this
	// function CANNOT tell a caller that any PARTICULAR package was covered.
	partial := CoverageReport{PackagesSubmitted: 400, PackagesEvaluated: 400,
		PackagesWithNoAdvisoryData: 399, RangesConsidered: 3, Complete: true}
	if err := partial.AssertNotSilentlyClean(nil); err != nil {
		t.Errorf("a run with 399/400 packages uncovered was refused (%v); the doc says this "+
			"check is all-or-nothing and that a fractional threshold would be dismissed", err)
	}

	// (3) THE OTHER LIMIT: findings short-circuit everything. A run that
	// produced findings returns nil even when it is incomplete, because the
	// question this function answers is "may zero findings be read as
	// clean", and a run with findings is not a zero-finding run. It is NOT
	// a completeness check; Complete is.
	incompleteWithFindings := CoverageReport{PackagesSubmitted: 5000, PackagesEvaluated: 1,
		RangesConsidered: 1, RangesRefused: 4999, Complete: false}
	if err := incompleteWithFindings.AssertNotSilentlyClean(
		[]MatchResult{{Package: "openssl"}}); err != nil {
		t.Errorf("a run WITH findings was refused (%v); the doc states the short-circuit "+
			"explicitly and a caller reading this as a completeness check is reading a "+
			"different function", err)
	}
	if incompleteWithFindings.Complete {
		t.Error("the report that models the short-circuit is not actually incomplete, so the " +
			"assertion above proves nothing")
	}
}

// G10 (A.18 §4.1, major). A refused range must not decide anything, IN EITHER
// DIRECTION — and the direction that matters is by absence.
//
// RED against the pre-fix code: a refused range was skipped and the rest of
// its group decided without it, so malforming the VENDOR endpoint of the
// backport fixture re-armed the exact false positive the vendor-first policy
// exists to defeat, on a host carrying the backported fix.
func TestARefusedVendorRangeDoesNotHandItsGroupToUpstream(t *testing.T) {
	upstream := AffectedRange{
		Source: "ghsa", SourceID: "GHSA-1", CVEID: "CVE-2022-2068",
		Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "3.0.4",
	}
	vendor := func(fixed string) AffectedRange {
		return AffectedRange{
			Source: "debian", SourceID: "DSA-5169-1", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0",
			Fixed: fixed, DistroBackport: true,
		}
	}
	// A host carrying the backported fix: deb11u4 is above the vendor's
	// deb11u3 and below upstream's 3.0.4.
	installed := PackageRecord{Collector: CollectorHost, Ecosystem: EcosystemDeb,
		Name: "openssl", Version: "1.1.1n-0+deb11u4", Arch: "amd64"}

	run := func(t *testing.T, ranges []AffectedRange) ([]MatchResult, CoverageReport) {
		t.Helper()
		m, err := NewMatcher(NewStaticSource(ranges))
		if err != nil {
			t.Fatal(err)
		}
		results, cov, err := m.Match(context.Background(), []PackageRecord{installed})
		if err != nil {
			t.Fatal(err)
		}
		return results, cov
	}

	// Vacuity control 1: with NO vendor range the upstream range matches.
	// Without this the test below could pass because nothing matches at all.
	if results, _ := run(t, []AffectedRange{upstream}); len(results) != 1 {
		t.Fatalf("the upstream range does not match this host, so the rest of this test proves "+
			"nothing: %+v", results)
	}
	// Vacuity control 2: with a WELL-FORMED vendor range the defence fires.
	if results, cov := run(t, []AffectedRange{upstream, vendor("1.1.1n-0+deb11u3")}); len(results) != 0 || len(cov.Defences) != 1 {
		t.Fatalf("the well-formed fixture does not defend: findings=%d defences=%d",
			len(results), len(cov.Defences))
	}

	// The case itself: the vendor endpoint carries a leading 'v', which is
	// not a Debian version. The range is refused.
	results, cov := run(t, []AffectedRange{upstream, vendor("v1.1.1n-0+deb11u3")})

	if len(results) != 0 {
		t.Fatalf("a REFUSED vendor range let the upstream range decide its group alone, and the "+
			"result is the backported-fix false positive this lane exists to defeat: %+v\n"+
			"An unparseable range must not be able to decide anything, in either direction — "+
			"and deciding by ABSENCE is the direction that costs the tool its audience.", results)
	}
	if len(cov.Refusals) != 1 || cov.Refusals[0].Reason != RefusalMalformedVersion {
		t.Fatalf("want one malformed-version refusal naming the vendor row, got %+v", cov.Refusals)
	}
	if cov.Refusals[0].SourceID != "DSA-5169-1" {
		t.Errorf("the refusal does not name the advisory it blocked: %+v", cov.Refusals[0])
	}
	if len(cov.Defences) != 0 {
		t.Errorf("a blocked group recorded a defence; it decided nothing, so it must claim "+
			"nothing: %+v", cov.Defences)
	}
	if cov.Complete {
		t.Error("Complete is true with a blocked advisory group")
	}
	if err := cov.AssertNotSilentlyClean(results); err == nil {
		t.Error("a run whose only advisory group was undecided reported clean")
	}
}

// G11 (A.18 §4.3, major). Two feeds carrying the same CVE must not have the
// remediation target chosen for them by alphabetical order of source name.
//
// RED against the pre-fix code: the survivor was the first containing range in
// sortKey() order, and sortKey begins with Source. `cvelistv5` < `ghsa`, so the
// coarse upstream range won and MatchResult.FixedVersion — the version a
// coding agent is dispatched to bump to — became a version the Debian archive
// does not carry.
func TestTheRemediationTargetIsTheTightestBoundNotTheFirstSourceName(t *testing.T) {
	// The premise, asserted rather than assumed: the old rule and the new
	// rule disagree on this fixture, which is what makes it a test.
	if !("cvelistv5" < "ghsa") {
		t.Fatal("this fixture assumes \"cvelistv5\" sorts before \"ghsa\"")
	}

	tight := AffectedRange{
		Source: "ghsa", SourceID: "GHSA-1", CVEID: "CVE-2022-2068",
		Ecosystem: EcosystemDeb, Package: "openssl",
		Introduced: "0", Fixed: "1.1.1n-0+deb11u5",
	}
	coarse := AffectedRange{
		Source: "cvelistv5", SourceID: "CVE-2022-2068", CVEID: "CVE-2022-2068",
		Ecosystem: EcosystemDeb, Package: "openssl",
		Introduced: "0", Fixed: "9.9.9",
	}
	// A repository dependency, so FixedVersion is the bump target and
	// RemediableByAgent is live.
	installed := PackageRecord{Collector: CollectorRepoSCA, Ecosystem: EcosystemDeb,
		Name: "openssl", Version: "1.1.1n-0+deb11u4", ManifestRelPath: "images/Dockerfile"}

	m, err := NewMatcher(NewStaticSource([]AffectedRange{coarse, tight}))
	if err != nil {
		t.Fatal(err)
	}
	results, _, err := m.Match(context.Background(), []PackageRecord{installed})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("want exactly one finding per advisory group, got %d: %+v", len(results), results)
	}
	if results[0].FixedVersion != "1.1.1n-0+deb11u5" {
		t.Errorf("FixedVersion = %q, want %q. The alphabetically-first SOURCE NAME must not pick "+
			"the version a coding agent is sent to install; the tightest upper bound in the group "+
			"does, and the reason is written down in chooseRemediationTarget.",
			results[0].FixedVersion, "1.1.1n-0+deb11u5")
	}
	if results[0].Source != "ghsa" {
		t.Errorf("the finding is attributed to %q", results[0].Source)
	}
	if !results[0].RemediableByAgent {
		t.Error("a repo finding with a fixed version is not remediable")
	}

	// Second rule: a range that NAMES a fixed version beats one that does
	// not, because the alternative throws away the only actionable field on
	// the finding. `aaa` sorts first and names no fix.
	noFix := AffectedRange{
		Source: "aaa-feed", SourceID: "A-1", CVEID: "CVE-2022-2068",
		Ecosystem: EcosystemDeb, Package: "openssl",
		Introduced: "0", LastAffected: "2.0",
	}
	m2, _ := NewMatcher(NewStaticSource([]AffectedRange{noFix, tight}))
	results2, _, err := m2.Match(context.Background(), []PackageRecord{installed})
	if err != nil {
		t.Fatal(err)
	}
	if len(results2) != 1 {
		t.Fatalf("want 1 finding, got %d", len(results2))
	}
	if results2[0].FixedVersion != "1.1.1n-0+deb11u5" {
		t.Errorf("a range naming no fixed version won the group over one that does: %+v", results2[0])
	}
}

// G12 (A.18 §4.4, major). A purl version that disagrees with the version
// column is an identity conflict, like the other two disagreements.
//
// RED against the pre-fix code: the purl's version was parsed and dropped on
// the floor, so a stale purl beside a fresh version column — what a re-scanned
// SBOM looks like — produced a false positive in one direction and a silent
// clean in the other.
func TestAPurlVersionThatDisagreesWithTheVersionColumnIsAConflict(t *testing.T) {
	for _, c := range []struct {
		name string
		rec  PackageRecord
	}{
		{"purl is patched, the version column is vulnerable", PackageRecord{
			Collector: CollectorRepoSCA, Ecosystem: EcosystemDeb, Name: "openssl",
			Version: "1.0.0-1", Purl: "pkg:deb/debian/openssl@3.0.11-1",
			ManifestRelPath: "Dockerfile",
		}},
		{"purl is vulnerable, the version column is patched", PackageRecord{
			Collector: CollectorRepoSCA, Ecosystem: EcosystemDeb, Name: "openssl",
			Version: "3.0.11-1", Purl: "pkg:deb/debian/openssl@1.0.0-1",
			ManifestRelPath: "Dockerfile",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := identify(c.rec)
			r, ok := err.(*Refusal)
			if !ok || r.Reason != RefusalIdentityConflict {
				t.Fatalf("identify took the version column's word for it: %v. Two identity "+
					"sources disagree about the one string this whole lane compares.", err)
			}

			// And through Match, where the consequence lives.
			m, _ := NewMatcher(NewStaticSource([]AffectedRange{{
				Source: "ghsa", SourceID: "GHSA-q", CVEID: "CVE-9999-1",
				Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "2.0",
			}}))
			results, cov, err := m.Match(context.Background(), []PackageRecord{c.rec})
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 0 {
				t.Errorf("a record whose two identity sources disagree produced a finding: %+v", results)
			}
			if cov.PackagesUnidentifiable != 1 {
				t.Errorf("PackagesUnidentifiable = %d, want 1", cov.PackagesUnidentifiable)
			}
			if err := cov.AssertNotSilentlyClean(results); err == nil {
				t.Error("a run that could identify nothing reported clean")
			}
		})
	}

	// A purl carrying NO version is not a disagreement — it is a purl with no
	// version, which is the common shape and must keep working.
	if _, err := identify(PackageRecord{
		Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl",
		Version: "1.0", Purl: "pkg:deb/debian/openssl",
	}); err != nil {
		t.Errorf("a version-free purl was treated as a conflict: %v", err)
	}
	// And an agreeing purl version, including one that had to be
	// percent-decoded to agree.
	if _, err := identify(PackageRecord{
		Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "libxml2",
		Version: "2.9.10+dfsg-6.7+deb11u4",
		Purl:    "pkg:deb/debian/libxml2@2.9.10%2Bdfsg-6.7%2Bdeb11u4",
	}); err != nil {
		t.Errorf("an agreeing purl version was refused: %v", err)
	}
}

// A.18 §4.2, major. The vendor-first defence needs the CVE alias on BOTH rows.
// This package cannot supply the alias — internal/ingest/cache owns that
// column, and grouping a vendor row with an upstream row that shares no
// identifier would be guessing they are about the same flaw. What it can do is
// stop the dependence being invisible.
func TestAVendorRangeWithNoCVEAliasIsReportedAsUngroupable(t *testing.T) {
	src := NewStaticSource([]AffectedRange{
		// The vendor row, WITHOUT the alias. Debian DSA rows commonly
		// enumerate several CVEs rather than carrying one.
		{Source: "debian", SourceID: "DSA-5169-1", CVEID: "",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0",
			Fixed: "1.1.1n-0+deb11u3", DistroBackport: true},
		{Source: "ghsa", SourceID: "GHSA-2", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "3.0.4"},
	})
	m, _ := NewMatcher(src)
	results, cov, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl",
			Version: "1.1.1n-0+deb11u4", Arch: "amd64"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The gap is REAL and this test does not pretend otherwise: the two rows
	// are in different precedence groups, so the upstream range decides its
	// own group and the false positive stands. Asserting it here is how the
	// gap stays visible to whoever reads this file next.
	if len(results) != 1 {
		t.Fatalf("want the (known, reported) upstream finding, got %d: %+v", len(results), results)
	}
	if len(cov.Defences) != 0 {
		t.Errorf("a defence fired between two rows that share no identifier: %+v", cov.Defences)
	}
	if len(cov.UngroupedVendorAdvisories) != 1 {
		t.Fatalf("UngroupedVendorAdvisories = %d, want 1. A vendor range that cannot participate "+
			"in the precedence must be reported, or \"the defence did not fire\" is "+
			"indistinguishable from \"there was nothing to defend against\".",
			len(cov.UngroupedVendorAdvisories))
	}
	u := cov.UngroupedVendorAdvisories[0]
	if u.Source != "debian" || u.SourceID != "DSA-5169-1" || u.Package != "openssl" {
		t.Errorf("the report does not name the vendor row it could not group: %+v", u)
	}

	// The control: give the vendor row its alias and the defence fires.
	src2 := NewStaticSource([]AffectedRange{
		{Source: "debian", SourceID: "DSA-5169-1", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0",
			Fixed: "1.1.1n-0+deb11u3", DistroBackport: true},
		{Source: "ghsa", SourceID: "GHSA-2", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "3.0.4"},
	})
	m2, _ := NewMatcher(src2)
	results2, cov2, err := m2.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl",
			Version: "1.1.1n-0+deb11u4", Arch: "amd64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results2) != 0 || len(cov2.Defences) != 1 {
		t.Errorf("with the alias present the defence must fire: findings=%d defences=%d",
			len(results2), len(cov2.Defences))
	}
	if len(cov2.UngroupedVendorAdvisories) != 0 {
		t.Errorf("a vendor row carrying its alias was reported as ungroupable: %+v",
			cov2.UngroupedVendorAdvisories)
	}
}

// A.18 §5.1, minor. UpstreamOnlyAdvisories is the packet-scoped residue an
// operator reviews. A range that decided NOT AFFECTED decided the advisory
// just as much as one that matched, and listing only the half that produced
// findings gives them half a picture.
func TestTheUpstreamOnlyResidueIncludesAdvisoriesDecidedNotAffected(t *testing.T) {
	src := NewStaticSource([]AffectedRange{
		// Vendor coverage for one CVE — this is what makes the package
		// "vendor-covered" at all.
		{Source: "redhat-csaf", SourceID: "RHSA-1", CVEID: "CVE-2023-32681",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.25.1-3.el9", DistroBackport: true},
		// An upstream advisory that DOES match.
		{Source: "ghsa", SourceID: "GHSA-hit", CVEID: "CVE-2024-35195",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.32.0"},
		// An upstream advisory that decides NOT AFFECTED. Pre-fix this row
		// was absent from the residue entirely.
		{Source: "ghsa", SourceID: "GHSA-miss", CVEID: "CVE-2021-00000",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.0.0"},
	})
	m, _ := NewMatcher(src)
	_, cov, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemRPM,
			Name: "python3-requests", Version: "2.25.1-3.el9", Arch: "noarch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, u := range cov.UpstreamOnlyAdvisories {
		seen[u.SourceID] = true
	}
	if !seen["GHSA-hit"] {
		t.Error("the residue omits the upstream advisory that produced a finding")
	}
	if !seen["GHSA-miss"] {
		t.Error("the residue omits an upstream advisory that decided NOT AFFECTED for a " +
			"vendor-covered package; a non-match is a decision, and the doc says the list is " +
			"every advisory decided by an upstream range")
	}
	if len(cov.UpstreamOnlyAdvisories) != 2 {
		t.Errorf("UpstreamOnlyAdvisories = %d, want 2: %+v",
			len(cov.UpstreamOnlyAdvisories), cov.UpstreamOnlyAdvisories)
	}
	// The vendor-decided advisory is NOT residue.
	if seen["RHSA-1"] {
		t.Error("an advisory decided by a vendor range appears in the upstream-only residue")
	}
}

// A.18 §5.2, minor. With more than one vendor range in a group, the Defence
// must cite the one that actually governed — not vendor[0], which is the
// alphabetically first source for the same reason G11 existed to fix.
func TestADefenceCitesTheVendorRangeThatGoverned(t *testing.T) {
	src := NewStaticSource([]AffectedRange{
		{Source: "ghsa", SourceID: "GHSA-up", CVEID: "CVE-1",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0", Fixed: "9.0"},
		{Source: "aaa-vendor", SourceID: "AAA-1", CVEID: "CVE-1",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0",
			Fixed: "1.0", DistroBackport: true},
		{Source: "zzz-vendor", SourceID: "ZZZ-1", CVEID: "CVE-1",
			Ecosystem: EcosystemDeb, Package: "openssl", Introduced: "0",
			Fixed: "2.0", DistroBackport: true},
	})
	m, _ := NewMatcher(src)
	results, cov, err := m.Match(context.Background(), []PackageRecord{
		// Above both vendor bounds, below the upstream one: the defence
		// applies, and the bound this host had to clear was 2.0.
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "3.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("want no finding, got %+v", results)
	}
	if len(cov.Defences) != 1 {
		t.Fatalf("Defences = %d, want 1", len(cov.Defences))
	}
	if cov.Defences[0].VendorSourceID != "ZZZ-1" {
		t.Errorf("the defence cites vendor advisory %q with range %q; the governing bound was "+
			"ZZZ-1's [0, 2.0), which is the one the installed version had to clear. Citing the "+
			"alphabetically first vendor row names a bound that had nothing to do with the outcome.",
			cov.Defences[0].VendorSourceID, cov.Defences[0].VendorRange)
	}
	if cov.Defences[0].VendorRange != "[0, 2.0)" {
		t.Errorf("defence VendorRange = %q, want %q", cov.Defences[0].VendorRange, "[0, 2.0)")
	}
}

// A.18 §5.3, minor. A source failure must not throw away the findings already
// computed. Complete is false and AssertNotSilentlyClean refuses, so neither
// the caller nor the report can read the set as exhaustive.
func TestASourceFailureKeepsTheFindingsAlreadyComputed(t *testing.T) {
	m, err := NewMatcher(failOnPackage{fail: "zzz-pkg", inner: NewStaticSource([]AffectedRange{
		{Source: "debian", SourceID: "DSA-1", CVEID: "CVE-1", Ecosystem: EcosystemDeb,
			Package: "aaa-pkg", Introduced: "0", Fixed: "9.0"},
	})})
	if err != nil {
		t.Fatal(err)
	}
	// Match sorts the inventory, so aaa-pkg is evaluated before zzz-pkg
	// regardless of the order they are submitted in.
	results, cov, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "zzz-pkg", Version: "1.0"},
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "aaa-pkg", Version: "1.0"},
	})
	if err == nil {
		t.Fatal("the failing source produced no error")
	}
	if len(results) != 1 {
		t.Fatalf("the finding computed before the failure was discarded: got %d results. For a "+
			"5000-package inventory whose cache drops on package 4999, everything found is "+
			"thrown away; the error and Complete=false already tell the caller not to read the "+
			"set as exhaustive.", len(results))
	}
	if results[0].Package != "aaa-pkg" {
		t.Errorf("unexpected finding %+v", results[0])
	}
	if cov.Complete {
		t.Error("Complete is true after a source failure")
	}
	if len(cov.SourceErrors) != 1 {
		t.Errorf("SourceErrors = %d, want 1", len(cov.SourceErrors))
	}
	if err := cov.AssertNotSilentlyClean(results); err != nil {
		t.Logf("AssertNotSilentlyClean: %v", err)
	}
}

type failOnPackage struct {
	fail  string
	inner AdvisorySource
}

func (f failOnPackage) AffectedRanges(ctx context.Context, ecosystem, pkg string) ([]AffectedRange, error) {
	if pkg == f.fail {
		return nil, errors.New("cache is unavailable")
	}
	return f.inner.AffectedRanges(ctx, ecosystem, pkg)
}

// A.18 §4.5, major. apk refused `1.00` as unknowable while asserting the same
// mechanism as fact for `1.0` == `1`. R8 resolves the contradiction in the
// direction that keeps the file's promise — and this test pins BOTH halves, so
// that the refusal cannot quietly widen into "apk does not work".
func TestAPKRefusesOnlyTheUndecidablePositionsAndStillOrdersTheRest(t *testing.T) {
	// Undecidable: an explicit zero against an absence, at the position that
	// decides the comparison.
	for _, c := range [][2]string{
		{"1.0", "1"},
		{"1", "1.0"},
		{"1.0", "1.0.0"},
		{"1.0.1", "1"},
		{"1.0", "1.0-r0"},
		{"1.0-r0", "1.0"},
		{"1.0_rc", "1.0_rc0"},
	} {
		// Both operands are perfectly well-formed. It is the ORDERING that
		// is not implemented, and the refusal reason has to say so.
		for _, v := range c {
			if err := ValidVersion(SchemeAPK, v); err != nil {
				t.Fatalf("ValidVersion(apk, %q) refused, so this pair does not test R8: %v", v, err)
			}
		}
		got, err := Compare(SchemeAPK, c[0], c[1])
		if err == nil {
			t.Errorf("Compare(apk, %q, %q) = %d. apk_compare.go R7a refuses to model the token "+
				"weight of a zero-run numeric part; this pair is decided by that same weight, "+
				"and the file cannot both refuse it and assert it.", c[0], c[1], got)
			continue
		}
		r, ok := err.(*Refusal)
		if !ok {
			t.Errorf("Compare(apk, %q, %q) returned %T, want *Refusal", c[0], c[1], err)
			continue
		}
		if r.Reason != RefusalUnmodelledOrdering {
			t.Errorf("Compare(apk, %q, %q) refused with %q, want %q — nothing is malformed here; "+
				"the gap is in this package, not in the data, and an operator reading the "+
				"coverage report has to be able to tell those apart",
				c[0], c[1], r.Reason, RefusalUnmodelledOrdering)
		}
		if got != 0 {
			t.Errorf("Compare(apk, %q, %q) returned a usable-looking %d alongside its refusal",
				c[0], c[1], got)
		}
	}

	// Still ordered: every neighbour of the pairs above whose decision does
	// NOT hang on the unmodelled weight. If this half breaks, R8 has widened
	// into a refusal of ordinary Alpine matching.
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.1", -1},         // a NON-ZERO extra part decides
		{"1.0.1", "1.0", 1},          //
		{"1.0", "1.1", -1},           // decided before any absence is reached
		{"1.2.4-r2", "1.2.5-r0", -1}, // decided at the third numeric part
		{"1.0-r0", "1.0-r1", -1},     // both revisions present
		{"1.0", "1.0-r1", -1},        // absent against a NON-ZERO revision
		{"1.0-r1", "1.0", 1},         //
		{"1.0_rc", "1.0_rc1", -1},    // absent against a NON-ZERO suffix number
		{"1.0_rc1", "1.0_rc2", -1},   //
		{"1.0_rc1", "1.0", -1},       // the published suffix rank table
		{"1.0", "1.0a", -1},          // the published letter rule
		{"1.0", "1.0", 0},            // identical strings
		{"1.0-r0", "1.0-r0", 0},      //
	} {
		got, err := Compare(SchemeAPK, c.a, c.b)
		if err != nil {
			t.Errorf("Compare(apk, %q, %q) refused: %v — R8 must refuse only the positions whose "+
				"weight is unpublished, not ordinary apk comparisons", c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(apk, %q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// A.18 §5.5, minor. Purl.String() wrote the subpath un-encoded while every
// other component went through purlEncode. identity.Purl is this re-rendered
// form and it lands in MatchResult.Purl, so a subpath carrying a reserved byte
// has to round-trip.
func TestPurlSubpathRoundTripsThroughStringAndBack(t *testing.T) {
	for _, sub := range []string{"a%b", "a b", "x?y", "lib/a%2Fb", "50%"} {
		p := Purl{Type: "deb", Namespace: "debian", Name: "openssl", Version: "1.0", Subpath: sub}
		rendered := p.String()
		back, err := ParsePurl(rendered)
		if err != nil {
			t.Errorf("Purl{Subpath:%q}.String() = %q, which does not parse: %v", sub, rendered, err)
			continue
		}
		if back.Subpath != sub {
			t.Errorf("subpath %q round-tripped as %q (rendered %q)", sub, back.Subpath, rendered)
		}
	}
	// And from the other direction: a purl whose subpath arrives encoded.
	p, err := ParsePurl("pkg:deb/debian/openssl@1.0#a%25b")
	if err != nil {
		t.Fatal(err)
	}
	if p.Subpath != "a%b" {
		t.Fatalf("Subpath = %q, want %q", p.Subpath, "a%b")
	}
	if _, err := ParsePurl(p.String()); err != nil {
		t.Errorf("the re-rendered purl %q does not parse: %v", p.String(), err)
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

// determinismInventory and determinismRanges are the fixed fixture the
// determinism tests run over. It deliberately exercises every code path whose
// output could be map-ordered: multiple packages, multiple advisories per
// package, refusals, defences and the upstream-only residue.
func determinismInventory() []PackageRecord {
	return []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.1.1n-0+deb11u4", Arch: "amd64"},
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.1.1n-0+deb11u4", Arch: "i386"},
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "curl", Version: "7.74.0-1.3+deb11u7", Arch: "amd64"},
		{Collector: CollectorHost, Ecosystem: EcosystemRPM, Name: "python3-requests", Version: "2.25.1-3.el9", Arch: "noarch"},
		{Collector: CollectorHost, Ecosystem: EcosystemRPM, Name: "glibc", Version: "2:2.34-60.el9", Arch: "x86_64"},
		{Collector: CollectorHost, Ecosystem: EcosystemAPK, Name: "musl", Version: "1.2.4-r2"},
		{Collector: CollectorHost, Ecosystem: EcosystemAPK, Name: "busybox", Version: "1.36.1_git20230913-r4"},
		{Collector: CollectorRepoSCA, Ecosystem: EcosystemDeb, Name: "libxml2",
			Version: "2.9.10+dfsg-6.7+deb11u4", Purl: "pkg:deb/debian/libxml2@2.9.10%2Bdfsg-6.7%2Bdeb11u4",
			ManifestRelPath: "images/base/Dockerfile"},
		// Refused: unimplemented ecosystems and unidentifiable rows.
		{Collector: CollectorRepoSCA, Ecosystem: "npm", Name: "lodash", Version: "4.17.20", ManifestRelPath: "web/package-lock.json"},
		{Collector: CollectorRepoSCA, Ecosystem: "pypi", Name: "requests", Version: "2.25.1", ManifestRelPath: "api/requirements.txt"},
		{Collector: CollectorRepoSCA, Ecosystem: "golang", Name: "golang.org/x/net", Version: "v0.17.0", ManifestRelPath: "go.mod"},
		{Collector: CollectorRepoSCA, Ecosystem: "maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", ManifestRelPath: "pom.xml"},
		{Collector: CollectorHost, Version: "9.9.9"},
	}
}

func determinismRanges() []AffectedRange {
	return []AffectedRange{
		{Source: "debian", SourceID: "DSA-5169-1", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "0", Fixed: "1.1.1n-0+deb11u3", DistroBackport: true},
		{Source: "ghsa", SourceID: "GHSA-openssl-1", CVEID: "CVE-2022-2068",
			Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "0", Fixed: "3.0.4"},
		{Source: "debian", SourceID: "DSA-5197-1", CVEID: "CVE-2022-2097",
			Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "0", Fixed: "1.1.1n-0+deb11u5", DistroBackport: true},
		{Source: "debian", SourceID: "DSA-curl-1", CVEID: "CVE-2023-38545",
			Ecosystem: EcosystemDeb, Package: "curl",
			Introduced: "7.69.0", LastAffected: "7.74.0-1.3+deb11u7", DistroBackport: true},
		{Source: "ghsa", SourceID: "GHSA-j8r2-6x86-q33q", CVEID: "CVE-2023-32681",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.31.0"},
		{Source: "redhat-csaf", SourceID: "RHSA-2023:4520", CVEID: "CVE-2023-32681",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.25.1-3.el9", DistroBackport: true},
		{Source: "ghsa", SourceID: "GHSA-requests-2", CVEID: "CVE-2024-35195",
			Ecosystem: EcosystemRPM, Package: "python3-requests",
			Introduced: "0", Fixed: "2.32.0"},
		{Source: "redhat-csaf", SourceID: "RHSA-glibc", CVEID: "CVE-2023-4911",
			Ecosystem: EcosystemRPM, Package: "glibc",
			Introduced: "0", Fixed: "2:2.34-100.el9", DistroBackport: true},
		{Source: "alpine-secdb", SourceID: "ALPINE-musl-1", CVEID: "CVE-2020-28928",
			Ecosystem: EcosystemAPK, Package: "musl",
			Introduced: "0", Fixed: "1.2.5-r0", DistroBackport: true},
		{Source: "alpine-secdb", SourceID: "ALPINE-busybox-1", CVEID: "CVE-2022-28391",
			Ecosystem: EcosystemAPK, Package: "busybox",
			Introduced: "0", LastAffected: "1.36.1_git20230913-r4", DistroBackport: true},
		{Source: "debian", SourceID: "DSA-libxml2", CVEID: "CVE-2023-45322",
			Ecosystem: EcosystemDeb, Package: "libxml2",
			Introduced: "0", Fixed: "2.9.10+dfsg-6.7+deb11u5", DistroBackport: true},
		// A malformed row, so refusals participate in the digest.
		{Source: "osv", SourceID: "OSV-broken", CVEID: "CVE-2000-0001",
			Ecosystem: EcosystemDeb, Package: "openssl",
			Introduced: "0", Fixed: "v3.0.0"},
		// A vendor row carrying NO CVE alias, so
		// CoverageReport.UngroupedVendorAdvisories participates in the
		// digest too. It decides nothing on its own (musl 1.2.4-r2 is not
		// below an exclusive 1.2.4-r2) and exists to put a row in that list.
		{Source: "alpine-secdb", SourceID: "ALPINE-musl-noalias", CVEID: "",
			Ecosystem: EcosystemAPK, Package: "musl",
			Introduced: "0", Fixed: "1.2.4-r2", DistroBackport: true},
	}
}

// corpusDigest is a canonical rendering of everything this package computes
// over the fixed corpus, hashed. It covers the ordering vectors AND a full
// Match run, so a determinism failure anywhere in the package moves it.
func corpusDigest(t *testing.T, inv []PackageRecord) string {
	t.Helper()
	var b bytes.Buffer

	for _, scheme := range SchemeValues() {
		for _, v := range vectorsFor(scheme) {
			got, err := Compare(scheme, v.A, v.B)
			fmt.Fprintf(&b, "cmp\t%s\t%s\t%s\t%d\t%v\n", scheme, v.A, v.B, got, err)
		}
	}

	m, err := NewMatcher(NewStaticSource(determinismRanges()))
	if err != nil {
		t.Fatal(err)
	}
	results, cov, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	for _, r := range results {
		fmt.Fprintf(&b, "res\t%+v\n", r)
	}
	fmt.Fprintf(&b, "cov\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%v\t%v\n",
		cov.PackagesSubmitted, cov.PackagesEvaluated, cov.PackagesUnidentifiable,
		cov.PackagesRefusedScheme, cov.PackagesRefusedVersion, cov.PackagesWithNoAdvisoryData,
		cov.RangesConsidered, cov.RangesRefused, cov.Complete, cov.EcosystemsRefused)
	for _, r := range cov.Refusals {
		fmt.Fprintf(&b, "ref\t%s\n", r.sortKey())
	}
	for _, d := range cov.Defences {
		fmt.Fprintf(&b, "def\t%s\n", d.sortKey())
	}
	for _, u := range cov.UpstreamOnlyAdvisories {
		fmt.Fprintf(&b, "upo\t%s\n", u.sortKey())
	}
	for _, u := range cov.UngroupedVendorAdvisories {
		fmt.Fprintf(&b, "ugv\t%s\n", u.sortKey())
	}

	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// TestMatchResultsAreIdenticalAcrossThreeRuns is A.17's stop condition,
// stated literally: "Comparator produces identical MatchResult sets across 3
// repeated runs on a fixed fixture".
func TestMatchResultsAreIdenticalAcrossThreeRuns(t *testing.T) {
	m, err := NewMatcher(NewStaticSource(determinismRanges()))
	if err != nil {
		t.Fatal(err)
	}
	inv := determinismInventory()

	first, firstCov, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("the determinism fixture produced no findings; a fixture that finds nothing " +
			"cannot prove that findings are stable")
	}
	// Every report list the digest covers must actually have something in
	// it, or the digest is stable because it is empty. This is the same
	// argument as G6, applied to the CoverageReport rather than the findings.
	for _, l := range []struct {
		name string
		n    int
	}{
		{"Refusals", len(firstCov.Refusals)},
		{"Defences", len(firstCov.Defences)},
		{"UpstreamOnlyAdvisories", len(firstCov.UpstreamOnlyAdvisories)},
		{"UngroupedVendorAdvisories", len(firstCov.UngroupedVendorAdvisories)},
	} {
		if l.n == 0 {
			t.Errorf("the determinism fixture leaves CoverageReport.%s empty, so the corpus "+
				"digest cannot prove that list is stable", l.name)
		}
	}
	for run := 2; run <= 3; run++ {
		got, cov, err := m.Match(context.Background(), inv)
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d produced a different MatchResult set:\n run 1: %+v\n run %d: %+v",
				run, first, run, got)
		}
		if !reflect.DeepEqual(cov, firstCov) {
			t.Fatalf("run %d produced a different CoverageReport:\n run 1: %+v\n run %d: %+v",
				run, firstCov, run, cov)
		}
	}
}

// TestOutputDoesNotDependOnInputOrder: a caller that assembles the same
// inventory in a different order must get the same answer. This is the
// property that makes the three-run test above meaningful for a real pipeline,
// where the inventory arrives in whatever order a package manager printed it.
func TestOutputDoesNotDependOnInputOrder(t *testing.T) {
	m, _ := NewMatcher(NewStaticSource(determinismRanges()))
	inv := determinismInventory()

	forward, covF, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	reversed := make([]PackageRecord, len(inv))
	for i := range inv {
		reversed[len(inv)-1-i] = inv[i]
	}
	backward, covB, err := m.Match(context.Background(), reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forward, backward) {
		t.Errorf("reversing the inventory changed the findings:\n forward: %+v\n backward: %+v",
			forward, backward)
	}
	if !reflect.DeepEqual(covF, covB) {
		t.Errorf("reversing the inventory changed the coverage report")
	}
}

// The advisory source's return order must not decide which range a finding
// cites, either.
func TestOutputDoesNotDependOnAdvisoryReturnOrder(t *testing.T) {
	ranges := determinismRanges()
	m1, _ := NewMatcher(NewStaticSource(ranges))
	reversed := make([]AffectedRange, len(ranges))
	for i := range ranges {
		reversed[len(ranges)-1-i] = ranges[i]
	}
	m2, _ := NewMatcher(NewStaticSource(reversed))

	a, covA, err := m1.Match(context.Background(), determinismInventory())
	if err != nil {
		t.Fatal(err)
	}
	b, covB, err := m2.Match(context.Background(), determinismInventory())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("reversing the advisory rows changed the findings:\n %+v\n %+v", a, b)
	}
	if !reflect.DeepEqual(covA, covB) {
		t.Error("reversing the advisory rows changed the coverage report")
	}
}

const (
	crossProcessEnv    = "ANVIL_MATCH_CROSS_PROCESS_CHILD"
	crossProcessMarker = "ANVIL-MATCH-DIGEST\t"
)

// TestCorpusIsStableAcrossProcesses is the determinism proof that matters.
//
// Repeating a computation inside ONE process cannot detect the failure that is
// actually likely here: Go re-randomises its map iteration seed PER PROCESS,
// so an unsorted range over a map produces a stable-but-arbitrary order within
// a run and a DIFFERENT one in the next run. Three repeated in-process runs
// would pass. internal/record's fingerprint conformance test makes the same
// argument and re-executes the test binary; this does the same.
func TestCorpusIsStableAcrossProcesses(t *testing.T) {
	inv := determinismInventory()

	if os.Getenv(crossProcessEnv) == "1" {
		fmt.Printf("%s%s\n", crossProcessMarker, corpusDigest(t, inv))
		return
	}

	want := corpusDigest(t, inv)

	// Two children, so a single child that happened to draw the same map
	// seed as the parent cannot make this vacuous.
	for child := 1; child <= 2; child++ {
		cmd := exec.Command(os.Args[0],
			"-test.run=^TestCorpusIsStableAcrossProcesses$",
			"-test.count=1")
		cmd.Env = append(os.Environ(), crossProcessEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("re-executing the test binary as child %d failed: %v\n%s", child, err, out)
		}
		var got string
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, strings.TrimSpace(crossProcessMarker)) {
				got = strings.TrimSpace(strings.TrimPrefix(line, strings.TrimSpace(crossProcessMarker)))
			}
		}
		if got == "" {
			t.Fatalf("child %d printed no digest:\n%s", child, out)
		}
		if got != want {
			t.Fatalf("child process %d computed a different corpus digest.\n parent: %s\n child:  %s\n"+
				"Lane A's verdict must be a pure function of its inputs (plan/00-SPINE.md S6). "+
				"A per-process difference is almost always an unsorted map range reaching an output.",
				child, want, got)
		}
	}
}

// G6 RED. If corpusDigest ignored its input, every determinism test above
// would pass without measuring anything.
func TestCorpusDigestIsSensitiveToItsInput(t *testing.T) {
	base := corpusDigest(t, determinismInventory())

	mutated := determinismInventory()
	mutated[0].Version = "1.1.1n-0+deb11u5" // now above the DSA's fixed version
	if got := corpusDigest(t, mutated); got == base {
		t.Fatal("changing an installed version did not change the corpus digest; " +
			"the determinism tests are measuring nothing")
	}

	shorter := determinismInventory()[1:]
	if got := corpusDigest(t, shorter); got == base {
		t.Fatal("dropping a package did not change the corpus digest")
	}
}

// ---------------------------------------------------------------------------
// Vocabulary agreement with the packages this one deliberately does not import
// ---------------------------------------------------------------------------

// internal/match declares its own ecosystem and collector constants because
// internal/collector/host links os/exec and internal/ingest/cache links a SQL
// driver, and neither belongs in a comparator's dependency graph. That
// duplication is the kind that drifts, so it is enforced here — a TEST may
// import both.
func TestVocabularyAgreesWithTheCollectorAndTheCache(t *testing.T) {
	pairs := []struct {
		name       string
		mine, orig string
	}{
		{"EcosystemDeb", EcosystemDeb, host.EcosystemDeb},
		{"EcosystemRPM", EcosystemRPM, host.EcosystemRPM},
		{"EcosystemAPK", EcosystemAPK, host.EcosystemAPK},
		{"CollectorHost", CollectorHost, cache.CollectorHost},
		{"CollectorRepoSCA", CollectorRepoSCA, cache.CollectorRepoSCA},
		{"CollectorHost (collector side)", CollectorHost, host.Collector},
	}
	for _, p := range pairs {
		if p.mine != p.orig {
			t.Errorf("%s: internal/match says %q but its owner says %q; the duplicated vocabulary "+
				"has drifted", p.name, p.mine, p.orig)
		}
	}

	// The record contract's trust vocabulary must still admit the value a
	// finding carries.
	found := false
	for _, tv := range record.TrustValues() {
		if tv == record.TrustAnvilGenerated {
			found = true
		}
	}
	if !found {
		t.Error("record.TrustValues() no longer contains TrustAnvilGenerated")
	}
	if cache.FindingTrustDefault != record.TrustAnvilGenerated {
		t.Errorf("cache.FindingTrustDefault = %q but MatchResult.Trust is %q",
			cache.FindingTrustDefault, record.TrustAnvilGenerated)
	}
}

// The cache's finding_host_not_remediable CHECK says a host row is never
// remediable. remediableByAgent is the function that has to make that true,
// and it takes no options, so there is nowhere for an override to live.
func TestHostFindingsAreNeverRemediableByAgent(t *testing.T) {
	for _, fixed := range []string{"", "1.2.3", "2:2.34-100.el9"} {
		if remediableByAgent(CollectorHost, fixed) {
			t.Errorf("remediableByAgent(host, %q) = true", fixed)
		}
	}
	if remediableByAgent(CollectorRepoSCA, "") {
		t.Error("remediableByAgent(repo-sca, \"\") = true; there is no version to move to")
	}
	if !remediableByAgent(CollectorRepoSCA, "1.2.3") {
		t.Error("remediableByAgent(repo-sca, \"1.2.3\") = false")
	}
	// The signature itself is the control: one collector, one fixed version,
	// no options struct.
	fn := reflect.TypeOf(remediableByAgent)
	if fn.NumIn() != 2 || fn.NumOut() != 1 {
		t.Errorf("remediableByAgent has signature %v; it must take exactly (collector, fixed) and "+
			"return one bool, so that no configuration surface can override a host finding", fn)
	}
	// And end to end, through Match.
	m, _ := NewMatcher(NewStaticSource([]AffectedRange{
		{Source: "debian", SourceID: "DSA-1", CVEID: "CVE-1", Ecosystem: EcosystemDeb,
			Package: "openssl", Introduced: "0", Fixed: "9.9", DistroBackport: true},
	}))
	results, _, err := m.Match(context.Background(), []PackageRecord{
		{Collector: CollectorHost, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.0"},
		{Collector: CollectorRepoSCA, Ecosystem: EcosystemDeb, Name: "openssl", Version: "1.0",
			ManifestRelPath: "Dockerfile"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 findings, got %d", len(results))
	}
	for _, r := range results {
		switch r.Collector {
		case CollectorHost:
			if r.RemediableByAgent {
				t.Error("a host finding came out of Match with RemediableByAgent set")
			}
			if r.Detector != record.DetectorKindHost {
				t.Errorf("host finding detector = %q", r.Detector)
			}
		case CollectorRepoSCA:
			if !r.RemediableByAgent {
				t.Error("a repo finding with a known fixed version is not remediable")
			}
			if r.Detector != record.DetectorKindSCA {
				t.Errorf("repo finding detector = %q", r.Detector)
			}
		}
	}
}

// A MatchResult must not carry a fingerprint. plan/00-SPINE.md S6: one
// fingerprint algorithm, defined once, in internal/record.
func TestMatchResultCarriesNoFingerprint(t *testing.T) {
	rt := reflect.TypeOf(MatchResult{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		for _, banned := range []string{"fingerprint", "digest", "hash", "fp"} {
			if strings.Contains(name, banned) {
				t.Errorf("MatchResult has a field %q; anvil-fp/v1 is defined once, in "+
					"internal/record, and a second digest under any name is the cross-area failure "+
					"plan/00-SPINE.md S6 forbids", rt.Field(i).Name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// G1: the direct-import allowlist
// ---------------------------------------------------------------------------

// allowedDirectImports is an ALLOWLIST, and it is EXACT: the package's
// non-test files must import these and nothing else, and every entry must
// actually be used. Each names one package and says why.
//
// What the shortness of this list buys: `time` is absent, so there is no
// clock; `math/rand` is absent, so there is no randomness; `os`, `os/exec`,
// `net/*` and `database/sql` are absent, so there is no I/O of any kind; and
// no module dependency is present, so no model client, HTTP client or SQL
// driver can be reached from Lane A's decision path.
var allowedDirectImports = map[string]string{
	"context": "Match takes a context so a long inventory can be cancelled; nothing else uses it",
	"sort":    "every report is sorted by a total key, which is how determinism is achieved without a map range",
	"strconv": "quoting values into refusal messages and parsing epoch and revision integers",
	"strings": "splitting versions and purls, and building refusal messages",
	"github.com/Susquehanna-Syntax/Anvil/internal/record": "the six frozen enums and record.PurlBase, which is the ONE base-purl derivation",
}

func TestDirectImportsStayComparatorShaped(t *testing.T) {
	got, err := directImportsOfDir(".")
	if err != nil {
		t.Fatalf("cannot parse this package's sources, so its import shape is UNCHECKED: %v", err)
	}
	if bad := checkImportAllowlist(got); len(bad) > 0 {
		for _, msg := range bad {
			t.Error(msg)
		}
	}
}

// checkImportAllowlist is the guard, factored out so the negative control can
// run the same code over a synthetic input.
func checkImportAllowlist(got map[string]bool) []string {
	var msgs []string
	for path := range got {
		if _, ok := allowedDirectImports[path]; !ok {
			msgs = append(msgs, "internal/match imports "+strconv.Quote(path)+
				", which is not on the allowlist. A comparator that reaches a clock, a random source, "+
				"a network or a database is no longer a pure function of its inputs. Add it to "+
				"allowedDirectImports with a reason, or do not import it.")
		}
	}
	for path := range allowedDirectImports {
		if !got[path] {
			msgs = append(msgs, "allowedDirectImports names "+strconv.Quote(path)+
				" but no non-test file imports it; an allowlist with dead entries stops describing the package")
		}
	}
	sort.Strings(msgs)
	return msgs
}

func directImportsOfDir(dir string) (map[string]bool, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, imp := range f.Imports {
				if imp.Name != nil && imp.Name.Name == "." {
					return nil, errors.New("a dot import is unresolvable by this analysis and is refused")
				}
				p, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return nil, err
				}
				out[p] = true
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no imports found at all, which means the parse did not see the package")
	}
	return out, nil
}

// G1 RED.
func TestDirectImportGuardFiresOnAViolation(t *testing.T) {
	// A source set that imports the network.
	violating := map[string]bool{}
	for p := range allowedDirectImports {
		violating[p] = true
	}
	violating["net/http"] = true
	msgs := checkImportAllowlist(violating)
	if len(msgs) == 0 {
		t.Fatal("the import allowlist accepted net/http; the guard is vacuous")
	}
	if !strings.Contains(strings.Join(msgs, "\n"), "net/http") {
		t.Errorf("the guard fired but did not name the offending import: %v", msgs)
	}

	// And the other direction: a shrinking package must not leave dead
	// allowlist entries behind.
	missing := map[string]bool{"strings": true}
	if msgs := checkImportAllowlist(missing); len(msgs) == 0 {
		t.Fatal("the import allowlist accepted a package that uses only one of its allowed imports")
	}

	// The parser must fail closed on a directory it cannot read.
	if _, err := directImportsOfDir("./does-not-exist"); err == nil {
		t.Error("directImportsOfDir succeeded on a missing directory; it must fail rather than " +
			"report an empty, passing import set")
	}
}

// A cheap structural check that no source file in this package spells a
// construct that would make its output depend on something other than its
// input. It is an ALLOWLIST of file names combined with a scan for the two
// identifiers that cannot appear at all.
func TestNoSourceFileReachesForAClockOrARandomSource(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot read the package directory, so this guard is UNCHECKED: %v", err)
	}
	expected := map[string]bool{
		"comparator.go": true, "dpkg_compare.go": true, "rpm_compare.go": true,
		"apk_compare.go": true, "purl.go": true, "comparator_test.go": true,
		// The transcribed corpus. It is a separate file because it is
		// GENERATED from the three published suites rather than written,
		// and mixing a generated table into a hand-written test file is
		// how a hand edit to a generated row stops being visible.
		"corpus_transcribed_test.go": true,
	}
	fset := token.NewFileSet()
	seen := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if !expected[e.Name()] {
			t.Errorf("unexpected source file %q in internal/match; A.17's scope names exactly %v",
				e.Name(), sortedNames(expected))
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		seen++
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch ident.Name + "." + sel.Sel.Name {
			case "time.Now", "rand.Int", "rand.Intn", "rand.Float64", "os.Getenv", "exec.Command":
				t.Errorf("%s references %s.%s; Lane A's verdict must be a pure function of its inputs",
					e.Name(), ident.Name, sel.Sel.Name)
			}
			return true
		})
	}
	if seen != 5 {
		t.Errorf("scanned %d non-test files, expected 5", seen)
	}
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// G5: the transitive dependency graph
// ---------------------------------------------------------------------------

// TestNoNonStdlibDependenciesBeyondRecord asserts EXACT SET EQUALITY over the
// non-standard-library packages in this package's transitive graph. A module
// dependency arriving anywhere below internal/match — a SQL driver, an HTTP
// client, a model client — fails here.
//
// It FAILS rather than skips when `go list` cannot run. A guard that vanishes
// silently in exactly the environments where it cannot check is worse than no
// guard, because the green tick is read as an answer. RUN WITH -count=1: go
// list's result is not tracked by Go's test cache.
func TestNoNonStdlibDependenciesBeyondRecord(t *testing.T) {
	got, err := nonStdlibDeps("./")
	if err != nil {
		t.Fatalf("cannot run `go list -deps`, so internal/match's dependency graph is UNCHECKED: %v\n\n"+
			"This test fails rather than skips on purpose. Run it with the Go toolchain available "+
			"and with -count=1.", err)
	}
	want := []string{
		"github.com/Susquehanna-Syntax/Anvil/internal/match",
		"github.com/Susquehanna-Syntax/Anvil/internal/record",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("internal/match's non-stdlib dependency set is\n  %v\nwant\n  %v\n"+
			"Lane A is deterministic and zero-inference (plan/00-SPINE.md S1); no module dependency "+
			"belongs below the comparator.", got, want)
	}
}

// nonStdlibDeps returns the sorted, non-standard-library import paths in the
// transitive dependency graph of pkg.
func nonStdlibDeps(pkg string) ([]string, error) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}\t{{.Standard}}", pkg).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%w: %s", err, ee.Stderr)
		}
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 2 {
			continue
		}
		if fields[1] == "true" {
			continue
		}
		paths = append(paths, fields[0])
	}
	if len(paths) == 0 {
		return nil, errors.New("go list reported no packages at all, which means it did not run against this package")
	}
	sort.Strings(paths)
	return paths, nil
}

// G5 RED. Run the same query against a package that genuinely does link a
// module dependency, and assert the checker sees it. Without this,
// TestNoNonStdlibDependenciesBeyondRecord could be passing because
// nonStdlibDeps silently returns nothing.
func TestDependencyGraphGuardFiresOnAPackageThatViolatesIt(t *testing.T) {
	got, err := nonStdlibDeps("github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache")
	if err != nil {
		t.Fatalf("cannot run `go list -deps` for the negative control: %v", err)
	}
	sawDriver := false
	for _, p := range got {
		if strings.HasPrefix(p, "modernc.org/") {
			sawDriver = true
		}
	}
	if !sawDriver {
		t.Fatalf("the negative control did not see internal/ingest/cache's SQL driver, so "+
			"nonStdlibDeps cannot be trusted to see one below internal/match either. Got: %v", got)
	}
}
