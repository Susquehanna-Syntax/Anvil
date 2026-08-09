package license

import (
	"strings"
	"unicode"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/invisible"
)

// ---------------------------------------------------------------------------
// Normalisation — ONE function, run before ANY marker is matched
// ---------------------------------------------------------------------------
//
// The second re-verification of this gate did not defeat the marker table with
// exotic licences. It defeated it with FORMATTING:
//
//	hard line wrapping ....... the normal shape of a checked-in LICENSE file,
//	                           which splits "under the same license" across a
//	                           newline and past a substring match;
//	NBSP (U+00A0) ............ the normal shape of HTML-sourced text, and three
//	                           of the pinned text_urls in
//	                           mirror/LICENSE-MANIFEST.toml ARE html pages;
//	a doubled space .......... a typo, or a justified paragraph;
//	full-width forms ......... ＳｈａｒｅＡｌｉｋｅ, which reads identically to a
//	                           human and shares not one byte with the marker.
//
// None of those is an attack. Every one of them is what real licence text looks
// like, and a gate that a line break defeats was never matching licence prose in
// the first place — it was matching the handful of unwrapped strings its own
// tests happened to contain.
//
// So matching happens exactly once, against normalised text, and the marker
// tables are written in the normalised form. TestEveryMarkerIsAlreadyNormalised
// asserts that last part rather than trusting it: a marker that is not already
// normalised can never match anything, and it would fail silently.
//
// # What this is NOT
//
// It is not a complete NFKC implementation. Go's standard library has no
// Unicode normaliser, golang.org/x/text is a dependency this repository does not
// take, and hand-writing the full decomposition tables would be a large amount
// of unreviewable data. What is implemented is the compatibility folding that
// occurs in licence prose — the full-width block, the ligatures, the dash and
// quote families — plus the whitespace collapse and the case fold.
//
// THAT GAP IS SURVIVABLE ONLY BECAUSE THE DEFAULT IS INVERTED. A compatibility
// form this function does not fold is a form that fails to match a PERMISSIVE
// signature, and a body that matches no permissive signature is quarantined, not
// published (see publishable.go). Under the previous design — publish unless a
// share-alike marker fires — every hole in this function was a publication.
//
// # "Renders as nothing" is not defined here
//
// It used to be, and the definition was `unicode.Is(unicode.Cf, r)` — one
// component of the class, applied as though it were all of it. Eight code
// points outside Cf defeated it: U+034F COMBINING GRAPHEME JOINER, U+3164
// HANGUL FILLER, U+115F HANGUL CHOSEONG FILLER, U+FFA0 HALFWIDTH HANGUL FILLER,
// U+17B4 KHMER VOWEL INHERENT AQ, U+2800 BRAILLE PATTERN BLANK, U+16FE4 KHITAN
// SMALL SCRIPT FILLER and U+FFFC OBJECT REPLACEMENT CHARACTER. Every one of
// them splits `sharealike` into something the marker table cannot see while
// rendering exactly as the licence a human read.
//
// internal/ingest/sanitize had the same problem, a separate hand list, and four
// defeats of its own. Two lists solving one problem is the defect class
// plan/IMPLEMENTATION-PLAN.md §6 closed ten instances of, so the definition now
// lives once, in internal/ingest/invisible, and both packages consume it. That
// package's TestBothConsumersDropEveryMemberOfTheClass sweeps the whole code
// space, with no exclusions, and fails if this file or the sanitizer ever stops
// honouring a member of the class.
//
// IT DOES NOT SAY THE TWO PACKAGES TREAT ALL TEXT ALIKE, and a test there once
// implied that while excluding the range where they differ. They differ on
// 959,049 non-graphic code points: the sanitizer's fail-closed default removes
// unassigned, private-use and noncharacter code space, and THIS FILE HAS NO ARM
// FOR ANY OF IT. So "share" U+0378 "alike", "share" U+E000 "alike" and "share"
// U+FDD0 "alike" do not normalise to "sharealike" and a marker split by one of
// them does not fire. That is a third known limit, alongside the two below, and
// it is recorded rather than closed: those code points render as a .notdef box,
// so a reader sees residue, and dropping them here would also make every
// PERMISSIVE signature easier to fire — the admission direction, which is the
// one already documented as untrustworthy in known_limits_test.go.
//
// Two known limits, recorded rather than papered over:
//
//   - HTML TAGS ARE NOT REMOVED. `same<br>license` does not match `same
//     license`. Only the named and numeric character references for the space
//     characters are folded, because three pinned licence texts are html pages
//     and `&nbsp;` is how those pages spell a space. A marker broken by a tag
//     fails to match, so an html-sourced permissive text can be refused; the
//     answer to that is for the operator to read the acquired text, not to
//     loosen this file.
//   - Compatibility decompositions outside the ranges below — circled letters,
//     the mathematical alphanumerics, superscripts — are not folded. Same safe
//     direction.

// spaceReferences folds the character references that spell a space in html
// into an actual space, before the rune loop runs.
//
// It is deliberately tiny and deliberately not an html parser: nothing else
// about html is interpreted, no other entity is decoded, and no tag is removed.
// It exists because mirror/LICENSE-MANIFEST.toml pins three text_urls that are
// html pages (the SPDX CVE-TOU transcription, MITRE's CWE terms of use, and the
// NVD General FAQs), and in an html page a non-breaking space is six ASCII
// characters rather than U+00A0.
var spaceReferences = strings.NewReplacer(
	"&nbsp;", " ", "&NBSP;", " ",
	"&#160;", " ", "&#xa0;", " ", "&#xA0;", " ", "&#X0A0;", " ",
	"&ensp;", " ", "&emsp;", " ", "&thinsp;", " ",
	"&#8194;", " ", "&#8195;", " ", "&#8201;", " ",
	"&#8203;", " ", "&zwnj;", " ", "&shy;", "",
)

// ligatureFoldings are the NFKC decompositions of the Alphabetic Presentation
// Forms block that appears in typeset licence text, U+FB00 through U+FB06.
var ligatureFoldings = [...]string{"ff", "fi", "fl", "ffi", "ffl", "st", "st"}

// NormaliseForMatching reduces a licence text to the single form every marker in
// this package is matched against: whitespace runs collapsed to one space,
// compatibility forms folded, case folded, and every member of
// internal/ingest/invisible's class — plus the non-whitespace controls —
// dropped.
//
// NOT "every code point that renders as nothing". That is what this comment used
// to say and it was a claim nobody can make offline: the class is a named union
// of Unicode properties plus a declared supplement, and a combining mark, an
// unassigned or private-use code point and an html tag all still split a marker.
// See the block above and known_limits_test.go.
//
// It is exported for the same reason Classify is: a reviewer has to be able to
// hand it a defeat and watch it fail or hold, without reading the gate.
func NormaliseForMatching(s string) string {
	if s == "" {
		return ""
	}
	if strings.Contains(s, "&") {
		s = spaceReferences.Replace(s)
	}

	var b strings.Builder
	b.Grow(len(s))
	pendingSpace := false

	for _, r := range s {
		switch {
		case isMatchingSpace(r):
			// Newlines included: hard wrapping is the normal shape of a licence
			// file and it must not decide a licence conclusion. A leading run is
			// dropped rather than emitted, so the result never begins with a
			// space.
			pendingSpace = b.Len() > 0
			continue

		case invisible.Is(r):
			// EVERYTHING THAT RENDERS AS NOTHING, from the one package that
			// defines it. This arm used to read `unicode.Is(unicode.Cf, r)`,
			// which is a strictly smaller class, and the difference was eight
			// working defeats: U+034F, U+3164, U+115F, U+FFA0, U+2800, U+17B4,
			// U+16FE4 and U+FFFC all split a marker in half while rendering
			// identically to the licence a human read. Cf is now one of five
			// components of the class rather than the whole of it; see
			// internal/ingest/invisible.
			continue

		case unicode.Is(unicode.Cc, r):
			// The C0/C1 controls that are not whitespace — isMatchingSpace has
			// already taken \t, \n, \v, \f, \r and U+0085. A NUL or an ESC in
			// the middle of a marker is the same defeat by a cruder route, and
			// it is a category rather than a list.
			continue
		}

		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		writeFolded(&b, r)
	}
	return b.String()
}

// isMatchingSpace reports whether a rune is whitespace for matching purposes.
//
// unicode.IsSpace already covers the newline family, the Zs category (which is
// where U+00A0 NO-BREAK SPACE, U+202F NARROW NO-BREAK SPACE and U+3000
// IDEOGRAPHIC SPACE live), U+0085 and the line/paragraph separators. U+00A0 is
// named again below so that the NBSP case — the one the re-verifier used — is
// visible at the point it is handled rather than implied by a category.
func isMatchingSpace(r rune) bool {
	return r == ' ' || unicode.IsSpace(r)
}

// writeFolded writes one rune in its folded, case-folded form.
func writeFolded(b *strings.Builder, r rune) {
	switch {
	case r >= 0xFF01 && r <= 0xFF5E:
		// The full-width ASCII block. NFKC maps it onto ASCII by subtracting
		// 0xFEE0, which is the whole of the full-width defeat.
		r -= 0xFEE0

	case r >= 0xFB00 && r <= 0xFB06:
		b.WriteString(ligatureFoldings[r-0xFB00])
		return

	case r >= '‐' && r <= '―', r == '−':
		// The dash family (hyphen, non-breaking hyphen, figure dash, en dash,
		// em dash, horizontal bar, minus sign) folded onto ASCII '-'. NFKC folds
		// only the non-breaking hyphen this far; folding the rest is
		// DELIBERATELY wider than NFKC, because an en dash is how a typesetter
		// writes the hyphen in an identifier this package matches.
		r = '-'

	case r == '‘', r == '’', r == '‚', r == '‛':
		r = '\''

	case r == '“', r == '”', r == '„', r == '‟':
		r = '"'
	}
	b.WriteRune(unicode.ToLower(r))
}

// containsNormalised reports whether an ALREADY NORMALISED haystack contains an
// ALREADY NORMALISED needle.
//
// It is a named function rather than a bare strings.Contains so that every
// marker match in this package reads as what it is — a match against normalised
// text — and so that a call site which forgot to normalise is visible.
func containsNormalised(hay, needle string) bool {
	return strings.Contains(hay, needle)
}

// containsAllNormalised reports whether every needle is present. It is how a
// multi-phrase permissive signature is evaluated: ALL of the phrases, not any.
func containsAllNormalised(hay string, needles []string) bool {
	for _, n := range needles {
		if !containsNormalised(hay, n) {
			return false
		}
	}
	return len(needles) > 0
}
