// Package invisible is THE definition of "renders as nothing" for Lane A.
//
// ===========================================================================
// WHY THIS PACKAGE EXISTS AT ALL
// ===========================================================================
//
// Two packages in this tree had to answer the same question — "does this code
// point put anything in front of a human reader?" — and each answered it from
// its own hand-written list:
//
//	internal/ingest/sanitize   removed a set derived from
//	                           Other_Default_Ignorable_Code_Point plus four
//	                           named blank glyphs;
//	internal/ingest/license    dropped unicode.Cf and nothing else, so
//	                           NormaliseForMatching("share" U+3164 "alike")
//	                           was not "sharealike" and a share-alike marker
//	                           did not fire.
//
// Both lists were defeated, in the same review round, by code points outside
// them — U+034F, U+3164, U+115F, U+FFA0, U+2800, U+17B4, U+16FE4 and U+FFFC
// against the licence normaliser; U+13440, U+13441, U+13442 and U+303F against
// the sanitizer. NEITHER DEFEAT WAS A NEW IDEA. They were the same idea aimed
// at whichever list happened not to name the character.
//
// plan/IMPLEMENTATION-PLAN.md §6 closed ten instances of exactly this class:
// two areas naming the same vocabulary from their own side and drifting apart.
// The fix there was one owner per definition, and it is the fix here. This
// package is the owner. internal/ingest/sanitize and internal/ingest/license
// consume it and declare no membership of their own;
// TestBothConsumersDropEveryMemberOfTheClass in this package's test sweeps the
// whole code space, with no exclusions, and fails if either consumer ever stops
// honouring a member.
//
// WHAT THAT SWEEP DOES NOT SAY, because a test here once said it and was wrong:
// the two consumers do NOT agree about all text. Outside the class they answer
// different questions and give different answers for 959,049 non-graphic code
// points — the sanitizer removes unassigned, private-use and noncharacter code
// space, the licence normaliser has no arm for any of it. The test that claimed
// otherwise, TestBothConsumersAgree, is kept unexcluded and SKIPPED with that
// count in its skip message.
//
// ===========================================================================
// THE CLASS, AND HOW MUCH OF IT IS DERIVED
// ===========================================================================
//
// A code point is in the class when a conforming renderer draws NOTHING for
// it and it therefore carries no text a reader can read. The class has five
// components, and four of them are DERIVED from tables the toolchain ships:
//
//	KindZeroWidthBidi ....... U+200B-U+200F, U+202A-U+202E, U+2066-U+2069.
//	                          A subset of Cf, split out because a consumer
//	                          counts it separately; membership is a range, not
//	                          a judgement.
//	KindTagChar ............. U+E0000-U+E007F, the Unicode TAG block. Also a
//	                          subset of Cf, also split out for counting.
//	KindVariationSelector ... unicode.Properties["Variation_Selector"], plus
//	                          the block written out so a nil property map
//	                          cannot turn the rule off silently.
//	KindDefaultIgnorable .... ALL of unicode.Properties["Other_Default_
//	                          Ignorable_Code_Point"], plus the same written-out
//	                          belt-and-braces for its graphic members.
//	KindFormat .............. all remaining unicode.Cf.
//
// THE DEFAULT-IGNORABLE ARM USED TO BE RESTRICTED TO THE GRAPHIC MEMBERS, on
// the reasoning that the rest are Cf or unassigned and another arm covers them.
// That reasoning was wrong about the unassigned half and the error was worth
// 3,738 code points: U+2065, U+FFF0-U+FFF8, U+E0080-U+E00FF and U+E01F0-U+E0FFF
// are RESERVED default-ignorables — Unicode has set them aside so that a
// renderer draws nothing for them — and they are not Cf, not graphic and not in
// any other arm. Of() returned KindNone, so the licence normaliser kept them and
// "share" U+2065 "alike" was not "sharealike". That is the same marker-splitting
// defeat the package was built to end, sitting in the one part of the property
// the package had declined to take.
//
// The fifth is NOT derived and cannot be:
//
//	KindBlankGlyph .......... code points that are graphic, that render as
//	                          nothing, and that carry NO property saying so in
//	                          any table Go ships. See blankGlyphSupplement.
//
// WHAT IS DELIBERATELY NOT IN THE CLASS. Space separators (unicode.Zs) render
// as a space, not as nothing, and deleting one BREAKS the property the class
// exists to restore — "lib" U+00A0 "foo" deleted is "libfoo", a third string.
// They are exposed as IsSpaceSeparator so that both consumers fold rather than
// delete them, and they are not part of Is. Controls (Cc), private use (Co),
// surrogates (Cs) and unassigned code space are not here either: they are not
// "renders as nothing", they are "is not text at all", and each consumer
// already handles them from the unicode categories directly — DIFFERENTLY, and
// on purpose. That is the 959,049-code-point disagreement named above.
//
// The one exception is stated because it looks like a contradiction: the
// RESERVED members of Other_Default_Ignorable_Code_Point are unassigned AND in
// the class. They are in it because Unicode has said in a published property
// that a renderer must draw nothing for them, which is the class's question
// answered from a table. An unassigned code point with no such property draws a
// .notdef box, which is visible residue, and stays out.
package invisible

import "unicode"

// ---------------------------------------------------------------------------
// The derived tables
// ---------------------------------------------------------------------------

// zeroWidthBidiTable is the block plan/10-lane-a-*.md A.3 names: U+200B-U+200F
// (zero-width space, ZWNJ, ZWJ, LRM, RLM), U+202A-U+202E (the legacy bidi
// embedding and override controls, of which U+202E RIGHT-TO-LEFT OVERRIDE is
// the classic "Trojan Source" character) and U+2066-U+2069 (the isolate
// controls that replaced them).
//
// Every member is also Cf, so KindFormat would catch them. They are a separate
// Kind because a consumer counts them separately: a spike in this bucket across
// a feed is a signal about that feed, and a signal folded into a general
// "format characters" bucket is not a signal.
var zeroWidthBidiTable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x200B, Hi: 0x200F, Stride: 1},
		{Lo: 0x202A, Hi: 0x202E, Stride: 1},
		{Lo: 0x2066, Hi: 0x2069, Stride: 1},
	},
}

// tagCharTable is the Unicode TAG block, U+E0000-U+E007F. U+E0020-U+E007F
// mirror printable ASCII one-for-one and render as nothing, which makes them
// the cleanest known channel for smuggling an entire instruction sentence past
// a review that reads rendered text. Cf, and split out for the same
// counting reason as the bidi block.
var tagCharTable = &unicode.RangeTable{
	R32: []unicode.Range32{
		{Lo: 0xE0000, Hi: 0xE007F, Stride: 1},
	},
}

// variationSelectorsExplicit is the written-out form of the Variation_Selector
// property. It is checked BEFORE the property so that a toolchain which drops
// the property cannot turn the rule off silently, and the property is checked
// after so that a code point added by a later Unicode revision is covered
// without an edit here.
var variationSelectorsExplicit = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x180B, Hi: 0x180F, Stride: 1}, // Mongolian FVS1-3 + FVS4/MVS neighbourhood
		{Lo: 0xFE00, Hi: 0xFE0F, Stride: 1}, // VS1-VS16
	},
	R32: []unicode.Range32{
		{Lo: 0xE0100, Hi: 0xE01EF, Stride: 1}, // VS17-VS256
	},
}

// defaultIgnorableGraphicExplicit is the written-out form of the GRAPHIC half
// of Other_Default_Ignorable_Code_Point — the members unicode.IsGraphic
// reports as graphic, which is the half a "keep everything graphic" rule would
// otherwise let through:
//
//	U+034F  COMBINING GRAPHEME JOINER      Mn
//	U+115F  HANGUL CHOSEONG FILLER         Lo
//	U+1160  HANGUL JUNGSEONG FILLER        Lo
//	U+17B4  KHMER VOWEL INHERENT AQ        Mn
//	U+17B5  KHMER VOWEL INHERENT AA        Mn
//	U+3164  HANGUL FILLER                  Lo
//	U+FFA0  HALFWIDTH HANGUL FILLER        Lo
//
// U+3164 is the canonical "invisible character" — it is what makes blank
// Discord and Twitter names work. U+034F is the one that matters most to Lane
// A: inserted into a package name it renders identically and compares unequal,
// and Lane A's entire value is a deterministic comparator.
//
// Same belt-and-braces discipline as the variation selectors: this table is
// checked first, the property second.
var defaultIgnorableGraphicExplicit = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x034F, Hi: 0x034F, Stride: 1},
		{Lo: 0x115F, Hi: 0x1160, Stride: 1},
		{Lo: 0x17B4, Hi: 0x17B5, Stride: 1},
		{Lo: 0x3164, Hi: 0x3164, Stride: 1},
		{Lo: 0xFFA0, Hi: 0xFFA0, Stride: 1},
	},
}

// ---------------------------------------------------------------------------
// The one part that is NOT derived
// ---------------------------------------------------------------------------

// blankGlyphSupplement is A SUPPLEMENT, and this comment says so because the
// property alone is insufficient and a reader has to know exactly where the
// derivation stops.
//
// WHY A SUPPLEMENT IS UNAVOIDABLE. The question the class asks is a RENDERING
// question: how wide is the glyph? Unicode does not publish that as a property,
// and Go ships no width table, no Unicode name table and no glyph metrics. The
// nearest published property, Other_Default_Ignorable_Code_Point, answers a
// different question — "should a renderer skip this if it cannot handle it" —
// and Unicode has repeatedly declined to add members to it that nonetheless
// draw nothing. U+16FE4 KHITAN SMALL SCRIPT FILLER is the proof: Unicode 13
// added a FILLER, exactly like the Hangul fillers in the derived table above,
// and did not add it to the property. So there is no table to fall back on,
// and the alternative to naming these is keeping them.
//
// EVERY MEMBER, WITH THE REASON IT IS ONE:
//
//	U+2800  BRAILLE PATTERN BLANK          So. The dotless Braille cell. Blank
//	        in every renderer; being blank is the whole point of the character.
//	U+303F  IDEOGRAPHIC HALF FILL SPACE    So. Defined as a fill space for a
//	        half-width position that a renderer is not required to draw, and
//	        which no common font draws.
//	U+FFFC  OBJECT REPLACEMENT CHARACTER   So. A placeholder for an embedded
//	        object. There is no embedded object in an advisory string or a
//	        licence file, so there is nothing to draw.
//	U+13440 EGYPTIAN HIEROGLYPH MIRROR VERTICAL  Mn. Unicode 14's hieroglyph
//	        format controls. U+13430-U+1343F are Cf and covered by KindFormat;
//	        this one was given a mark category instead and so is graphic.
//	U+13441 EGYPTIAN HIEROGLYPH FULL BLANK Lo. Named BLANK, is blank, and is
//	        a letter as far as unicode.IsGraphic is concerned.
//	U+13442 EGYPTIAN HIEROGLYPH HALF BLANK Lo. As above.
//	U+16FE4 KHITAN SMALL SCRIPT FILLER     Mn. See above; the code point that
//	        proved a declared limit was a hole.
//	U+1D159 MUSICAL SYMBOL NULL NOTEHEAD   So. Defined as a notehead that is
//	        not drawn.
//
// THE COST, STATED. A code point of this kind that nobody has named is KEPT,
// silently, by every consumer of this package. That is the failure mode the
// derived arms exist to bound and this list cannot escape. Its test says so
// plainly rather than implying coverage: the membership of this table is the
// one thing in this package no independent oracle checks, because no
// independent source of the answer exists offline. What the test DOES check
// independently is that every member is still outside every property Go ships
// — so the day a Unicode revision adopts one, the supplement is told to shrink.
//
// U+13443-U+13446 (the LOST SIGN family) are deliberately absent: they are
// drawn, as a hatched or shaded box, so they are visible residue rather than
// invisible text and a reader can see something is wrong.
var blankGlyphSupplement = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x2800, Hi: 0x2800, Stride: 1},
		{Lo: 0x303F, Hi: 0x303F, Stride: 1},
		{Lo: 0xFFFC, Hi: 0xFFFC, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x13440, Hi: 0x13442, Stride: 1},
		{Lo: 0x16FE4, Hi: 0x16FE4, Stride: 1},
		{Lo: 0x1D159, Hi: 0x1D159, Stride: 1},
	},
}

// variationSelectorProp and defaultIgnorableProp are hoisted map lookups.
// Either may be nil on a toolchain that drops the property; neither being
// present is required for correctness, only for coverage of code points added
// after the written-out tables above were last read.
var (
	variationSelectorProp = unicode.Properties["Variation_Selector"]
	defaultIgnorableProp  = unicode.Properties["Other_Default_Ignorable_Code_Point"]
)

// ---------------------------------------------------------------------------
// The exported definition
// ---------------------------------------------------------------------------

// Kind is which component of the class a code point belongs to. It exists so
// that a consumer can COUNT the components separately without owning their
// membership: internal/ingest/sanitize reports one counter per Kind, and
// plan/10-lane-a-*.md A.3 forbids dropping a rune without a count.
type Kind int

const (
	// KindNone means the code point is not in the class. It is the zero value
	// on purpose: a consumer that forgets to handle a Kind treats the rune as
	// visible, which is the conservative direction for a REMOVAL rule.
	KindNone Kind = iota

	// KindZeroWidthBidi is the zero-width and bidi-control block.
	KindZeroWidthBidi
	// KindTagChar is the Unicode TAG block.
	KindTagChar
	// KindVariationSelector is Variation_Selector.
	KindVariationSelector
	// KindDefaultIgnorable is the graphic half of
	// Other_Default_Ignorable_Code_Point.
	KindDefaultIgnorable
	// KindBlankGlyph is the undevised supplement — see blankGlyphSupplement.
	KindBlankGlyph
	// KindFormat is every remaining Cf.
	KindFormat
)

// String names a Kind for diagnostics. The names are written for an error
// message a reviewer reads, not for a machine.
func (k Kind) String() string {
	switch k {
	case KindZeroWidthBidi:
		return "zero-width or bidi control"
	case KindTagChar:
		return "Unicode tag character"
	case KindVariationSelector:
		return "variation selector"
	case KindDefaultIgnorable:
		return "default-ignorable (graphic, renders as nothing)"
	case KindBlankGlyph:
		return "blank glyph (graphic, renders as nothing, no property says so)"
	case KindFormat:
		return "format (Cf)"
	default:
		return "visible"
	}
}

// Of reports which component of the class r belongs to, or KindNone.
//
// THE ARM ORDER IS PART OF THE ANSWER. The two counted subsets come first so
// that they are not swallowed by KindFormat. The blank-glyph arm is conditioned
// on unicode.IsGraphic because the supplement is a claim about GLYPHS and a
// non-graphic code point has none.
//
// Other_Default_Ignorable is NOT so conditioned, and the arm sits after Cf on
// purpose. Taking the whole property is what covers the reserved half — U+2065,
// U+FFF0-U+FFF8, U+E0080-U+E00FF, U+E01F0-U+E0FFF, 3,738 code points that used
// to fall through to KindNone and survive the licence normaliser. Sitting after
// Cf keeps the counters meaning what they meant: the property's few Cf members
// (U+E0000 and the unassigned TAG interior) are already claimed by the tag arm
// or by KindFormat, so no code point changes bucket, and only code points that
// had NO bucket are added.
func Of(r rune) Kind {
	switch {
	case unicode.Is(zeroWidthBidiTable, r):
		return KindZeroWidthBidi
	case unicode.Is(tagCharTable, r):
		return KindTagChar
	case isVariationSelector(r):
		return KindVariationSelector
	case unicode.IsGraphic(r) && isOtherDefaultIgnorable(r):
		return KindDefaultIgnorable
	case unicode.IsGraphic(r) && isBlankGlyph(r):
		return KindBlankGlyph
	case unicode.Is(unicode.Cf, r):
		return KindFormat
	case isOtherDefaultIgnorable(r):
		// The reserved, non-graphic half of the property. A renderer draws
		// nothing for these, which is the whole of the class's question.
		return KindDefaultIgnorable
	}
	return KindNone
}

// Is reports whether r renders as nothing: the single predicate a consumer
// that does not need the breakdown should call.
//
// It is NOT true of the space separators. See IsSpaceSeparator.
func Is(r rune) bool { return Of(r) != KindNone }

// IsSpaceSeparator reports whether r is a unicode.Zs SPACE SEPARATOR other
// than U+0020 itself.
//
// It lives here because it is the OTHER half of the same problem and the two
// halves must not be solved in different places: a code point that renders as
// a space is not in the invisible class, and DELETING it is what breaks the
// property removal exists to restore.
//
//	"lib" U+00A0 "foo"   reads identical to   "lib foo"
//	delete the U+00A0 -> "libfoo"             a THIRD string, still unequal
//	fold  it to space -> "lib foo"            equal; property restored
//
// U+0020 is excluded because it is the fold TARGET. Tab, newline and carriage
// return are Cc rather than Zs, so this predicate cannot touch line structure.
// Membership is unicode.Zs and nothing else, so a seventeenth separator added
// by a later revision is covered without an edit.
func IsSpaceSeparator(r rune) bool {
	return r != ' ' && unicode.Is(unicode.Zs, r)
}

func isVariationSelector(r rune) bool {
	if unicode.Is(variationSelectorsExplicit, r) {
		return true
	}
	return variationSelectorProp != nil && unicode.Is(variationSelectorProp, r)
}

// isOtherDefaultIgnorable reports whether r carries the
// Other_Default_Ignorable_Code_Point property — the whole of it, graphic
// members and reserved members alike.
//
// ON "THE CLASS, NOT A LIST". Unicode's full Default_Ignorable_Code_Point
// property is (roughly) Other_Default_Ignorable u Cf u Variation_Selector minus
// a handful of exceptions. Go ships only the Other_ half, and Of returns a Kind
// for ALL of Cf and for ALL variation selectors on their own arms, so the three
// components together are the property.
//
// The written-out table is checked first and covers only the GRAPHIC members,
// because those are the ones a keep-if-graphic rule lets through and therefore
// the ones a dropped property would silently un-cover in the dangerous
// direction. The reserved members depend on the property being present; if a
// toolchain ever drops it, TestTheReservedDefaultIgnorablesAreInTheClass goes
// red rather than the coverage going quiet.
func isOtherDefaultIgnorable(r rune) bool {
	if unicode.Is(defaultIgnorableGraphicExplicit, r) {
		return true
	}
	return defaultIgnorableProp != nil && unicode.Is(defaultIgnorableProp, r)
}

// isBlankGlyph reports whether r is in the supplement. It is a list, it is
// documented as a list on blankGlyphSupplement, and its test says out loud
// that its membership is not independently verified.
func isBlankGlyph(r rune) bool { return unicode.Is(blankGlyphSupplement, r) }

// SupplementMembers returns the code points in the non-derived supplement, in
// ascending order.
//
// It is exported for ONE purpose: a test that wants to assert something about
// the supplement — that every member is still missed by every property the
// toolchain ships, say — should not have to re-type the list and thereby build
// an oracle out of the implementation. A caller that wants to know whether a
// particular rune is in the class calls Is.
func SupplementMembers() []rune {
	out := make([]rune, 0, 8)
	// A zero stride would be a table typo rather than a range, and walking one
	// never terminates. Treating it as 1 keeps a typo a wrong answer instead of
	// a hang, and the test that reads this reports the wrong answer.
	step := func(s uint32) rune {
		if s == 0 {
			return 1
		}
		return rune(s)
	}
	for _, r16 := range blankGlyphSupplement.R16 {
		for c := rune(r16.Lo); c <= rune(r16.Hi); c += step(uint32(r16.Stride)) {
			out = append(out, c)
		}
	}
	for _, r32 := range blankGlyphSupplement.R32 {
		for c := rune(r32.Lo); c <= rune(r32.Hi); c += step(r32.Stride) {
			out = append(out, c)
		}
	}
	return out
}
