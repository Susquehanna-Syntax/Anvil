// Package invisible_test is deliberately an EXTERNAL test package.
//
// It can therefore import the two consumers — internal/ingest/sanitize and
// internal/ingest/license — and assert the property this package exists for:
// that they agree. An internal test could not, and an agreement asserted from
// inside one consumer is the drift it is supposed to detect.
package invisible_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/invisible"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// THE ORACLE, AND WHAT IT IS AND IS NOT INDEPENDENT OF
// ---------------------------------------------------------------------------
//
// Three rounds of review have now landed the same complaint: "the test oracle
// names the same literals the implementation does". So this file states, once
// and without softening, exactly how much of the class each assertion below
// checks independently.
//
//	THE DERIVED FOUR-FIFTHS — Cf, the TAG block, the zero-width/bidi block,
//	Variation_Selector and Other_Default_Ignorable — are
//	checked by derivedInvisible below, which reads unicode.Properties and
//	unicode.Cf at TEST TIME and shares no table, no literal and no function
//	with invisible.go. A range that invisible.go wrote down wrongly, or a
//	written-out table that has drifted from the property it claims to mirror,
//	fails here. What this oracle does NOT do is escape the PROPERTY: if
//	Unicode itself declines to mark a code point default-ignorable, the oracle
//	does not know about it either. That is the shared blind spot, and it is
//	the reason a supplement exists at all.
//
//	THE SUPPLEMENT — the eight blank glyphs — IS NOT INDEPENDENTLY VERIFIED,
//	and TestSupplementMembershipIsNotIndependentlyVerified says so in its name
//	so that no reader can mistake a green run for coverage. Deciding "does
//	this glyph draw anything" needs a font, a width table or a Unicode name
//	table; Go ships none of the three and this repository takes no
//	dependencies and makes no network calls. What that test DOES check
//	independently is the supplement's NECESSITY and its BOUND: every member
//	must still be missed by every property the toolchain ships (otherwise it
//	belongs in a derived arm and the list must shrink), and nothing outside
//	the derived union and the supplement may be in the class at all.
//
//	THE AGREEMENT between the two consumers is checked over the whole code
//	space with no list on either side — but it is checked in HALVES, under
//	three names, and only two of the three are green. Read the block above
//	TestBothConsumersAgree before citing any of them. The short version:
//	"every member of the class is dropped by both" holds over the entire code
//	space with no exclusion; "no visible code point is dropped by either"
//	holds over every graphic non-separator code point; and the unrestricted
//	claim that the two consumers agree EVERYWHERE is false by 959,049 code
//	points and its test is SKIPPED rather than narrowed.

// derivedInvisible is the independent oracle for the derived components. It
// answers "do the unicode tables say this renders as nothing?" using only
// unicode, and returns the reason so a failure names it.
//
// It reads the properties freshly rather than through invisible.Of, and its
// arms are written from the Unicode definitions rather than copied from
// invisible.go's arms — that is the whole of its independence, and its limit
// is stated in the block comment above.
func derivedInvisible(r rune) (string, bool) {
	odi := unicode.Properties["Other_Default_Ignorable_Code_Point"]
	vs := unicode.Properties["Variation_Selector"]
	switch {
	case unicode.Is(unicode.Cf, r):
		return "format (Cf)", true
	case vs != nil && unicode.Is(vs, r):
		return "Variation_Selector", true
	case odi != nil && unicode.Is(odi, r):
		// THE WHOLE PROPERTY, graphic members and reserved members alike. This
		// arm used to carry `&& unicode.IsGraphic(r)`, which made the oracle
		// agree with the implementation's narrowing instead of checking it, and
		// the 3,738 reserved default-ignorables were invisible to both.
		return "Other_Default_Ignorable_Code_Point", true
	}
	return "", false
}

// derivableAsNonText is the WIDER independent oracle used for the containment
// bound. It answers "is there a table-backed reason this code point puts
// nothing in front of a reader?" and adds one arm to derivedInvisible: a code
// point unicode does not call GRAPHIC has no glyph to draw at all — that covers
// the reserved members of the TAG block, which the class carries as whole
// ranges rather than as their currently-assigned subset.
//
// It is deliberately NOT used for the "must be in the class" direction. Being
// non-graphic is a reason a consumer may remove a code point; it is not a
// reason this package has to claim it, and controls, private use and unassigned
// code space are each consumer's own business from the unicode categories.
func derivableAsNonText(r rune) (string, bool) {
	if why, ok := derivedInvisible(r); ok {
		return why, true
	}
	if !unicode.IsGraphic(r) {
		return "not graphic (no glyph to draw)", true
	}
	return "", false
}

// ignorabilityProperties are the properties a reader might reasonably expect to
// stand in for "renders as nothing". The supplement's necessity is measured
// against these rather than against every property the toolchain ships:
// U+2800 carries Pattern_Syntax and U+16FE4 carries Ideographic, and neither
// says anything at all about whether a glyph is drawn.
var ignorabilityProperties = []string{
	"Other_Default_Ignorable_Code_Point",
	"Variation_Selector",
	"Noncharacter_Code_Point",
	"Join_Control",
	"Bidi_Control",
	"White_Space",
	"Pattern_White_Space",
	"Deprecated",
}

func supplementSet() map[rune]bool {
	m := map[rune]bool{}
	for _, r := range invisible.SupplementMembers() {
		m[r] = true
	}
	return m
}

// TestDerivedComponentsMatchTheUnicodeTables sweeps the whole code space and
// requires invisible.Is to agree with the independent property oracle wherever
// that oracle has an opinion.
//
// MEASURED: with defaultIgnorableGraphicExplicit's U+3164 entry deleted AND the
// property lookup nil'd, this reports U+3164 and its six neighbours. With the
// tables intact and the property present it reports nothing, because the
// written-out tables are a subset of the properties by construction.
func TestDerivedComponentsMatchTheUnicodeTables(t *testing.T) {
	if unicode.Properties["Other_Default_Ignorable_Code_Point"] == nil ||
		unicode.Properties["Variation_Selector"] == nil {
		t.Fatal("this toolchain ships neither property, so the derived arms of the class rest " +
			"entirely on the written-out tables and this oracle can check nothing; that is a " +
			"material change and must not pass silently")
	}
	derived, classified := 0, 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		why, want := derivedInvisible(r)
		if want {
			derived++
			if !invisible.Is(r) {
				t.Errorf("U+%04X is %s but invisible.Is reports it visible", r, why)
			}
		}
		if invisible.Is(r) {
			classified++
		}
	}
	if derived < 100 {
		t.Fatalf("the oracle only found %d derived-invisible code points, which cannot be right; "+
			"it is broken and this test is asserting nothing", derived)
	}
	t.Logf("oracle: %d derived-invisible code points; invisible.Is: %d in the class", derived, classified)
}

// TestClassIsTheDerivedUnionPlusTheDeclaredSupplement bounds the hand-written
// part from the outside.
//
// The failure this catches is a member quietly added to a table in
// invisible.go that no property backs and that the supplement does not
// declare: the class would grow without the growth being visible where the
// cost of hand-written membership is documented. Every code point in the class
// must be either derived or an OPENLY declared supplement member.
func TestClassIsTheDerivedUnionPlusTheDeclaredSupplement(t *testing.T) {
	supp := supplementSet()
	var undeclared []string
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		if !invisible.Is(r) {
			continue
		}
		if _, ok := derivableAsNonText(r); ok {
			continue
		}
		if supp[r] {
			continue
		}
		undeclared = append(undeclared, fmt.Sprintf("U+%04X", r))
	}
	if len(undeclared) > 0 {
		t.Errorf("these code points are in the invisible class but are neither derived from a "+
			"unicode property nor declared in the supplement, so the cost of naming them is "+
			"paid without being recorded: %s", strings.Join(undeclared, ", "))
	}
}

// TestSupplementMembershipIsNotIndependentlyVerified is named the way it is on
// purpose. THIS TEST DOES NOT PROVE THE SUPPLEMENT IS COMPLETE OR EVEN
// CORRECT. It cannot: deciding whether a glyph draws anything needs a font, a
// rendering width table or the Unicode character names, and Go ships none of
// the three, this repository takes no dependencies and this test makes no
// network call. A blank code point nobody has named is invisible to the
// implementation AND to every oracle in this file.
//
// What it does prove, independently of invisible.go, is the two things that
// keep the list honest:
//
//	NECESSITY — every member must be graphic AND missed by every property the
//	toolchain ships. A member that a property already covers belongs in a
//	derived arm, and leaving it here would overstate how much hand-written
//	membership the class actually needs. The day a Unicode revision adopts one
//	of these, this test goes red and the supplement is told to shrink.
//
//	SIZE — the list is small enough to read. A supplement that grows without
//	bound is the thirteen-character list this package replaced, wearing a
//	different name.
func TestSupplementMembershipIsNotIndependentlyVerified(t *testing.T) {
	members := invisible.SupplementMembers()
	if len(members) == 0 {
		t.Fatal("the supplement is empty; either the class is now fully derived — in which case " +
			"say so and delete it — or SupplementMembers has stopped reporting")
	}
	if len(members) > 24 {
		t.Errorf("the supplement holds %d code points. It is a hand list with no oracle behind "+
			"it; at this size it has become the failure mode it was introduced to bound, and the "+
			"answer is a derivation rather than more names", len(members))
	}
	if !sort.SliceIsSorted(members, func(i, j int) bool { return members[i] < members[j] }) {
		t.Error("SupplementMembers is not sorted, so two readings of it cannot be diffed")
	}
	for _, r := range members {
		if !unicode.IsGraphic(r) {
			t.Errorf("U+%04X is not graphic, so a derived arm already removes it and it does not "+
				"need a hand-written entry", r)
		}
		if why, ok := derivedInvisible(r); ok {
			t.Errorf("U+%04X is now covered by %s, so the supplement must shrink by one: the "+
				"hand-written entry is no longer necessary", r, why)
		}
		for _, name := range ignorabilityProperties {
			tab := unicode.Properties[name]
			if tab != nil && unicode.Is(tab, r) {
				t.Errorf("U+%04X now carries the property %q, so it can be derived and does not "+
					"belong in an unbacked list", r, name)
			}
		}
		if !invisible.Is(r) {
			t.Errorf("U+%04X is declared a supplement member but invisible.Is says it is visible", r)
		}
	}
	t.Logf("NOT INDEPENDENTLY VERIFIED: the membership of these %d code points is asserted by "+
		"invisible.go and by nothing else. This test checked that each is still un-derivable, "+
		"not that each renders as nothing, and not that no other code point does.", len(members))
}

// TestKindsPartitionTheClass checks the counting contract the sanitizer's
// stats rest on: every member of the class has exactly one Kind, no member has
// KindNone, and no non-member has a Kind.
func TestKindsPartitionTheClass(t *testing.T) {
	seen := map[invisible.Kind]int{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		k := invisible.Of(r)
		if (k == invisible.KindNone) == invisible.Is(r) {
			t.Fatalf("U+%04X: Of reports %v but Is reports %v; the two disagree", r, k, invisible.Is(r))
		}
		if k != invisible.KindNone {
			seen[k]++
		}
	}
	for _, k := range []invisible.Kind{
		invisible.KindZeroWidthBidi, invisible.KindTagChar, invisible.KindVariationSelector,
		invisible.KindDefaultIgnorable, invisible.KindBlankGlyph, invisible.KindFormat,
	} {
		if seen[k] == 0 {
			t.Errorf("no code point has Kind %v, so a consumer counter for it can never be "+
				"non-zero and the arm is dead", k)
		}
	}
	if invisible.KindNone.String() != "visible" {
		t.Errorf("KindNone.String() = %q, want %q", invisible.KindNone.String(), "visible")
	}
}

// TestSpaceSeparatorsAreNotInTheClass pins the boundary the package comment
// draws. A space separator renders as a space, so DELETING it produces a third
// string that is still unequal to the one the reader believes they read; it is
// folded, not removed, and it must therefore never be reported as invisible.
func TestSpaceSeparatorsAreNotInTheClass(t *testing.T) {
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.Is(unicode.Zs, r) {
			continue
		}
		n++
		if r == ' ' {
			if invisible.IsSpaceSeparator(r) {
				t.Error("U+0020 is the fold TARGET and must not report as a separator to fold")
			}
			continue
		}
		if !invisible.IsSpaceSeparator(r) {
			t.Errorf("U+%04X is Zs but IsSpaceSeparator says no", r)
		}
		if invisible.Is(r) {
			t.Errorf("U+%04X is a space separator and must not be in the invisible class; "+
				"deleting it is what breaks matching integrity", r)
		}
	}
	if n < 10 {
		t.Fatalf("only %d Zs code points found; the sweep is broken", n)
	}
}

// ---------------------------------------------------------------------------
// THE POINT OF THE PACKAGE: the two consumers agree
// ---------------------------------------------------------------------------

// ===========================================================================
// THE SWEEP, AND THE EXCLUSION THAT USED TO BE INSIDE IT
// ===========================================================================
//
// There was ONE test here called TestBothConsumersAgree. It claimed to sweep
// the entire Unicode code space and prove that internal/ingest/sanitize and
// internal/ingest/license share one definition of "renders as nothing". It was
// green, and the claim was not true, because the loop carried two `continue`
// statements that skipped exactly the code points where the two consumers
// answer differently:
//
//	continue on 0xD800-0xDFFF ......... legitimate, and it is still here. Go
//	                                    cannot put a lone surrogate in a
//	                                    string: string(rune(0xD800)) is
//	                                    U+FFFD, so the probe would test the
//	                                    replacement character rather than the
//	                                    surrogate. There is no assertion to
//	                                    make and no disagreement being hidden.
//	continue on !unicode.IsGraphic ... NOT legitimate. Removing it takes the
//	                                    test from green to 959,049 reported
//	                                    disagreements.
//
// A TEST THAT EXCLUDES WHAT IT CANNOT HANDLE ASSERTS AGREEMENT BY EXCLUDING THE
// DISAGREEMENT. This project has now shipped that shape three times — a guard
// that whitelisted its own return types, a marker table that validated itself,
// and this — so the exclusion is not being narrowed or re-justified. It is
// split out, named, measured and skipped, and the two claims that ARE true over
// their whole domain are asserted separately under names that say what their
// domain is.
//
// WHAT WAS FIXED RATHER THAN RECORDED. The first measurement of the unexcluded
// sweep was 962,787. 3,738 of those were a genuine hole in this package rather
// than a difference between its consumers: invisible.Of returned KindNone for
// the RESERVED half of Other_Default_Ignorable_Code_Point — U+2065,
// U+FFF0-U+FFF8, U+E0080-U+E00FF and U+E01F0-U+E0FFF — which the sanitizer
// removed as unassigned and the licence normaliser, having no unassigned arm,
// KEPT. "share" U+2065 "alike" did not normalise to "sharealike". Of now takes
// the whole property; see invisible.go. TestTheReservedDefaultIgnorablesAreInTheClass
// is the regression.

// TestBothConsumersDropEveryMemberOfTheClass is the claim this package exists
// to make, over its whole domain, with NO exclusion.
//
// Every code point in the class is dropped by internal/ingest/sanitize AND by
// internal/ingest/license's NormaliseForMatching. Two hand lists that drift
// apart is the defect class plan/IMPLEMENTATION-PLAN.md §6 closed ten instances
// of, and this is what makes the drift impossible to reintroduce quietly:
// adding a member to one consumer and not the other is not something a
// contributor CAN do any more, and if someone reintroduces a private list in
// either package, the sweep finds the disagreement wherever it is.
//
// MEASURED, one consumer at a time, against the rule each of them had before
// this package existed:
//
//	licence normaliser, restored to its `unicode.Is(unicode.Cf, r)` rule and
//	with the control arm removed: 306 disagreements, starting with U+034F,
//	U+115F, U+1160, U+17B4, U+17B5, U+3164, U+FFA0, U+2800, U+303F and running
//	through every variation selector.
//
//	sanitizer: restoring the blank-glyph supplement to the four members it held
//	before this round takes U+303F, U+13440, U+13441 and U+13442 OUT of the
//	class, so they stop being disagreements here and turn up in
//	TestTheAdversarialCorpusIsClosed and in the sanitizer's own sweep instead.
//	That is the shape of the defect this package removes: while each consumer
//	owned its own list, a code point one of them had never heard of was not a
//	disagreement, it was simply invisible to both.
//
// WHAT A GREEN RUN HERE DOES NOT PROVE: that the class is complete. It proves
// the two consumers read the same class, not that the class names every code
// point that renders as nothing. See TestSupplementMembershipIsNotIndependentlyVerified.
func TestBothConsumersDropEveryMemberOfTheClass(t *testing.T) {
	checked, reported := 0, 0
	report := func(format string, args ...any) {
		reported++
		if reported <= 25 {
			t.Errorf(format, args...)
		}
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // see the block above: Go cannot probe a lone surrogate
		}
		if !invisible.Is(r) {
			continue
		}
		checked++
		probe := "a" + string(r) + "b"
		if got, _ := sanitize.Sanitize(probe); got != "ab" {
			report("U+%04X (%v) is in the invisible class but sanitize.Sanitize kept it: %q",
				r, invisible.Of(r), got)
		}
		if got := license.NormaliseForMatching(probe); got != "ab" {
			report("U+%04X (%v) is in the invisible class but license.NormaliseForMatching "+
				"kept it: %q — a marker split by it can never fire", r, invisible.Of(r), got)
		}
	}
	if reported > 25 {
		t.Errorf("... and %d further disagreements", reported-25)
	}
	if checked < 4000 {
		t.Fatalf("the sweep checked %d members of the class, which cannot be right; the class "+
			"holds the whole of Cf, the TAG block, every variation selector and the whole of "+
			"Other_Default_Ignorable, so this test is asserting almost nothing", checked)
	}
	t.Logf("both consumers dropped all %d members of the class", checked)
}

// TestNoVisibleCodePointIsDroppedByEitherConsumer is the converse, and its name
// carries its domain: VISIBLE here means unicode.IsGraphic and not a space
// separator. That is a restriction, it is stated rather than buried in a
// `continue`, and the code points it leaves out are the subject of
// TestBothConsumersAgree below — which is skipped, because they disagree.
//
// The restriction is not arbitrary. A non-graphic code point has no glyph, so
// "was it dropped although a reader could see it" is not a question about it;
// what happens to controls, private use, noncharacters and unassigned code
// space is each consumer's own policy, decided from the unicode categories, and
// the two consumers have deliberately different policies there.
func TestNoVisibleCodePointIsDroppedByEitherConsumer(t *testing.T) {
	checked, reported := 0, 0
	report := func(format string, args ...any) {
		reported++
		if reported <= 25 {
			t.Errorf(format, args...)
		}
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		if invisible.Is(r) || !unicode.IsGraphic(r) || invisible.IsSpaceSeparator(r) {
			continue
		}
		checked++
		probe := "a" + string(r) + "b"
		if got, _ := sanitize.Sanitize(probe); got != probe {
			report("U+%04X is visible but sanitize.Sanitize changed %q to %q", r, probe, got)
		}
		if got := license.NormaliseForMatching(probe); got == "ab" {
			report("U+%04X is visible but license.NormaliseForMatching deleted it", r)
		}
	}
	if reported > 25 {
		t.Errorf("... and %d further disagreements", reported-25)
	}
	if checked < 100000 {
		t.Fatalf("the sweep checked %d visible code points, which cannot be right; it is "+
			"asserting almost nothing", checked)
	}
	t.Logf("neither consumer dropped any of %d visible code points", checked)
}

// TestBothConsumersAgree IS SKIPPED, AND THE SKIP IS THE POINT.
//
// This is the unrestricted claim the old green test appeared to make: over the
// WHOLE code space, a code point is dropped by internal/ingest/sanitize if and
// only if it is dropped by internal/ingest/license. It is false, it is left
// here in its unexcluded form so that deleting one line reproduces the failure,
// and it is skipped rather than narrowed so that nobody can cite a green run
// for the broad claim.
//
// MEASURED on 2026-08-09, after the reserved default-ignorables were closed.
// 959,049 code points, EVERY ONE OF THEM IN THE SAME DIRECTION — the sanitizer
// removes them, the licence normaliser does not:
//
//	unassigned .............. 821,510   the fail-closed default arm of
//	                                    sanitize.classify; the normaliser has
//	                                    no unassigned arm at all
//	private use (Co) ........ 137,468   same
//	noncharacter ............      66   same
//	Cc control ..............       3   U+000B, U+000C and U+0085, which the
//	                                    normaliser FOLDS TO A SPACE (they are
//	                                    unicode.IsSpace) while the sanitizer
//	                                    removes them
//	Zl/Zp ...................       2   U+2028 and U+2029, same fold
//
//	the range spanned .......  U+000B through U+10FFFF
//
// WHY IT IS NOT CLOSED. The two consumers are answering different questions
// outside the class and they are supposed to. sanitize.Sanitize decides what may
// be STORED, and its default arm removes anything it does not recognise —
// that is A.5's fail-closed hinge and shrinking it would be a regression.
// NormaliseForMatching decides what a licence marker is MATCHED against, and an
// unassigned or private-use code point renders as a .notdef box in a
// conforming renderer, so a reader of "share<box>alike" can SEE that something
// is wrong; deleting it would also make every permissive signature easier to
// fire, which is the admission direction, and this gate's admission path is the
// one that is already untrustworthy (see internal/ingest/license's KNOWN LIMITS).
// Closing this gap is a decision about the normaliser's policy, taken with that
// trade-off in front of it. It is not a bug fix, so it is not done here.
//
// WHAT THAT MEANS FOR A READER: the class is shared and both consumers honour
// it — that is the two tests above, and it is the property this package was
// built for. "The two packages treat all text identically" is NOT true and was
// never tested.
func TestBothConsumersAgree(t *testing.T) {
	t.Skip("SKIPPED BECAUSE IT FAILS. 959,049 code points are dropped by " +
		"internal/ingest/sanitize and kept by internal/ingest/license: 821,510 unassigned, " +
		"137,468 private use, 66 noncharacters, plus U+000B, U+000C, U+0085, U+2028 and " +
		"U+2029 which the normaliser folds to a space instead of removing. Spanning " +
		"U+000B-U+10FFFF. The two consumers agree about the invisible CLASS — see " +
		"TestBothConsumersDropEveryMemberOfTheClass and " +
		"TestNoVisibleCodePointIsDroppedByEitherConsumer, both of which are green over their " +
		"whole domain — and they deliberately differ about non-graphic code space. Delete " +
		"this line to see the failure.")

	reported := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		probe := "a" + string(r) + "b"
		san, _ := sanitize.Sanitize(probe)
		norm := license.NormaliseForMatching(probe)
		if (san == "ab") != (norm == "ab") {
			reported++
			if reported <= 25 {
				t.Errorf("U+%04X: sanitize gave %q, NormaliseForMatching gave %q", r, san, norm)
			}
		}
	}
	if reported > 25 {
		t.Errorf("... and %d further disagreements", reported-25)
	}
}

// TestTheReservedDefaultIgnorablesAreInTheClass is the regression for the hole
// the unexcluded sweep exposed.
//
// U+2065, U+FFF0-U+FFF8, U+E0080-U+E00FF and U+E01F0-U+E0FFF are reserved
// default-ignorables: Unicode has set them aside so that a renderer draws
// nothing for them. invisible.Of used to return KindNone for all 3,738, because
// its Other_Default_Ignorable arm was conditioned on unicode.IsGraphic. The
// sanitizer removed them anyway, as unassigned. The licence normaliser has no
// unassigned arm, so it kept them, and any one of them splits a licence marker
// while rendering as nothing.
//
// This test drives the property, not a list, so a code point a later Unicode
// revision adds to it is covered without an edit here.
func TestTheReservedDefaultIgnorablesAreInTheClass(t *testing.T) {
	odi := unicode.Properties["Other_Default_Ignorable_Code_Point"]
	if odi == nil {
		t.Skip("this toolchain does not ship Other_Default_Ignorable_Code_Point, so the " +
			"reserved half of the class rests on nothing this test can read")
	}
	reserved := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF || !unicode.Is(odi, r) {
			continue
		}
		if !invisible.Is(r) {
			t.Errorf("U+%04X carries Other_Default_Ignorable_Code_Point but invisible.Is reports "+
				"it visible", r)
			continue
		}
		if unicode.IsGraphic(r) {
			continue
		}
		reserved++
		if got := license.NormaliseForMatching("share" + string(r) + "alike"); got != "sharealike" {
			t.Errorf("U+%04X: NormaliseForMatching = %q, so the share-alike marker does not fire",
				r, got)
		}
	}
	if reserved < 3000 {
		t.Errorf("only %d reserved (non-graphic) default-ignorables were swept; there were 3,738 "+
			"when this was measured, so either the property has changed shape or this test has "+
			"stopped finding them", reserved)
	}
}

// TestTheAdversarialCorpusIsClosed drives the class from a corpus whose
// provenance is the REVIEW ROUNDS rather than invisible.go.
//
// Its independence is a matter of provenance and nothing else: each code point
// below was supplied by a reviewer as a working defeat of the code as it then
// stood, before the entry that now covers it existed. That makes it a
// regression corpus, not an oracle — it proves the known defeats are closed and
// says nothing about the unknown ones. It is recorded here rather than folded
// into the sweep so that a future edit that shrinks the class has to delete a
// named defeat to go green.
func TestTheAdversarialCorpusIsClosed(t *testing.T) {
	corpus := []struct {
		r     rune
		round string
	}{
		{0x2800, "round 1, against the thirteen-character hand list"},
		{0x16FE4, "round 2, against Other_Default_Ignorable alone"},
		{0xFFFC, "round 2, against Other_Default_Ignorable alone"},
		{0x1D159, "round 2, against Other_Default_Ignorable alone"},
		{0x034F, "round 3, against the licence normaliser's Cf-only rule"},
		{0x3164, "round 3, against the licence normaliser's Cf-only rule"},
		{0x115F, "round 3, against the licence normaliser's Cf-only rule"},
		{0xFFA0, "round 3, against the licence normaliser's Cf-only rule"},
		{0x17B4, "round 3, against the licence normaliser's Cf-only rule"},
		{0x13440, "round 3, against the sanitizer's blank-glyph list"},
		{0x13441, "round 3, against the sanitizer's blank-glyph list"},
		{0x13442, "round 3, against the sanitizer's blank-glyph list"},
		{0x303F, "round 3, against the sanitizer's blank-glyph list"},
	}
	for _, tc := range corpus {
		if !invisible.Is(tc.r) {
			t.Errorf("U+%04X (%s) is out of the class again", tc.r, tc.round)
			continue
		}
		// The two defeats these characters were actually used for: splitting a
		// licence marker so it cannot fire, and splitting a package name so the
		// comparator never matches.
		if got := license.NormaliseForMatching("share" + string(tc.r) + "alike"); got != "sharealike" {
			t.Errorf("U+%04X (%s): NormaliseForMatching = %q, so the share-alike marker does not "+
				"fire", tc.r, tc.round, got)
		}
		if got, st := sanitize.Sanitize("lib" + string(tc.r) + "foo"); got != "libfoo" || st.Removed() != 1 {
			t.Errorf("U+%04X (%s): Sanitize = %q removed=%d, want %q removed=1",
				tc.r, tc.round, got, st.Removed(), "libfoo")
		}
	}
}
