package license

import (
	"strings"
	"testing"
)

// ===========================================================================
// KNOWN LIMITS OF THE LICENCE GATE — READ BEFORE YOU TRUST A GREEN RUN
// Dated 2026-08-09. Every vector below is OPEN.
// ===========================================================================
//
// THE REFUSAL PATH IS TRUSTWORTHY. THE ADMISSION PATH IS NOT. That is the one
// sentence to carry away from this file, and everything below is its detail.
//
//	A REFUSAL is sound by construction. Nothing this package refuses can be
//	published, whatever the refusal's reason was and whether or not the reason
//	was a good one. The cost of a wrong refusal is an operator investigating a
//	feed that would have been fine. Refusals are also the default: unknown,
//	ambiguous, unrecognised and empty all refuse, and a body must PROVE
//	something to escape. See publishable.go.
//
//	AN ADMISSION IS A SUBSTRING JUDGEMENT WEARING THE WORD "IDENTIFIED". The
//	gate admits when a body matches an enumerated permissive signature and no
//	entry in three tables of strings fires against it. It has no model of what
//	a licence IS. It cannot tell a licence from a document ABOUT a licence, it
//	cannot recognise a licence name it has not been given verbatim, and it
//	cannot see a second set of terms expressed in words nobody listed. Three
//	adversarial rounds have run against it and each round found new ways
//	through after the previous round was called closed.
//
// ===========================================================================
// THE VECTORS, EACH WITH A WORKING EXAMPLE
// ===========================================================================
//
// Every one of these is DEMONSTRATED by TestTheAdmissionPathIsNotTrustworthy
// below, which drives the body through IdentifyPermissive and requires that it
// publishes. The test exists so this section cannot rot into a wish list: if
// somebody closes a vector, the test goes red and the closer has to come here
// and say so.
//
// V1 — ABBREVIATION. licenceNameMarkers holds "gnu general public license" and
// "gpl-2.0"; it does not hold "the GPL", "the LGPL" or "the AGPL", and it
// cannot, because bare "gpl" is a substring of ordinary prose. An MIT LICENSE
// that ends "The scripts in scripts/ are under the GPL." publishes at tier 0
// and tier 1 with a copyleft subtree attached.
//
// V2 — BRITISH SPELLING. Every marker is spelled "license". "Eclipse Public
// Licence" and "Mozilla Public Licence 2.0" match nothing. The British form is
// not exotic: it is how a large fraction of the English-speaking world writes
// the word, and this repository's own prose uses it.
//
// V3 — THE FAMILY EXEMPTION OVER-FIRES. otherLicenceContent skips any name
// marker whose family equals the identified licence's family, so that a licence
// naming ITSELF is not read as a second licence. The families are coarser than
// the licences. An Apache-2.0 file that also says "The bundled xerces build is
// covered by the Apache License, Version 1.1, which additionally requires that
// all advertising materials mention this product" publishes: the marker
// "apache license" carries family "apache-2.0" and is skipped, even though
// Apache-1.1 is a materially different licence with an advertising clause.
// The same hole exists across the "bsd" family.
//
// V4 — DUAL-LICENCE WORDING. secondTermsMarkers holds "licensed under either"
// and "at your option, either". "You may use this work under either the MIT
// License or the GPL, at your choosing" matches neither, and neither does
// "released under the MIT License or, alternatively, the GPL version 3". The
// disjunction is the ordinary way a dual-licensed project states its terms.
//
// V5 — TITLE COLLISION. A signature is a phrase in the text, not a statement
// about the document. A commentary whose first line is "Apache License,
// Version 2.0 — A Practical Commentary" and whose body is "This commentary
// explains the licence clause by clause. It is copyright ACME and all rights
// are reserved" is identified as Apache-2.0 and admitted. The document is not
// a licence at all.
//
// V6 — LICENCE QUOTED IN PROSE. Same defect from the other side. A CHANGELOG
// that says "Relicensed the parser. The new header reads: Permission is hereby
// granted, free of charge, to any person obtaining a copy of this software."
// carries a complete MIT signature and is identified as MIT, while the sentence
// after it says the rest of the repository is proprietary.
//
// V7 — NEGATION BEYOND THE 96-BYTE WINDOW. negatedBefore looks back
// negationWindow = 96 normalised bytes for a cue. A document that denies the
// licence in its opening paragraph and states the grant text 300 bytes later is
// admitted: the denial is out of range. Lengthening the window does not fix
// this, it moves it — the cue can always be pushed one byte further back — and
// a longer window makes false refusals more likely.
//
// V8 — INVISIBLE-CHARACTER SPLITTING, WHAT IS LEFT OF IT. The class in
// internal/ingest/invisible is dropped before matching, so U+200B, U+00AD,
// U+2065 and the other 4,211 members no longer split a marker. What still does:
//
//	a COMBINING MARK. "Mozilla Pub" U+0301 "lic License" renders as an acute
//	accent over a letter — visible if you look, invisible if you skim — and
//	matches no marker.
//	an UNASSIGNED, PRIVATE-USE or NONCHARACTER code point. U+0378, U+E000 and
//	U+FDD0 all survive NormaliseForMatching, which has no arm for them. They
//	render as a .notdef box in a conforming renderer, which is why the
//	normaliser does not drop them, and internal/ingest/invisible's
//	TestBothConsumersAgree is SKIPPED over exactly this 959,049-code-point
//	region for exactly this reason.
//	an HTML TAG. "Mozilla Pub<b></b>lic License" renders as the licence name
//	and matches nothing. normalise.go records this as a declared limit; three
//	of the pinned text_urls are html pages.
//
// ===========================================================================
// WHAT A GREEN RUN OF THIS PACKAGE DOES NOT PROVE
// ===========================================================================
//
// It does not prove that an admitted body is the licence it was admitted as.
// It does not prove that an admitted body contains no second set of terms.
// It does not prove that a share-alike or reciprocal licence cannot reach
// tier 0 or tier 1. It does not prove that the marker tables are complete, and
// completeness is not achievable by adding rows: every vector above is a
// counter-example to a table, and the fix for each one individually creates the
// next one.
//
// What a green run DOES prove: that the specific bodies the tests carry —
// four rounds of adversarial fixtures, the enumerated licences' own texts, the
// eight wrapped bodies, the formatting evasions — behave as recorded, and that
// nothing this package refuses gets published.
//
// ===========================================================================
// THE REAL FIX, WHICH IS NOT MORE SUBSTRINGS
// ===========================================================================
//
// A licence IDENTIFIER over a real corpus: a normalised full-text comparison
// against the SPDX licence list with a similarity threshold, the way askalono
// (sorensen-dice over the SPDX corpus) and licensee (a hashed-token match with
// a confidence score) do it. That answers "which licence IS this document, and
// how sure are we" — a question no table of substrings can be asked. It also
// answers the vectors above uniformly rather than one at a time: an
// abbreviation, a British spelling and a dual-licence disjunction are all just
// text that does not match the corpus well enough.
//
// That is a real decision with real costs — a licence corpus checked into this
// repository, a scoring function, a threshold somebody has to defend, and the
// dependency question A.4 is strict about — and it is deliberately NOT taken
// here. What is taken here is the honesty: the substring gate is what ships,
// and this file says what it is worth.
//
// ===========================================================================
// THIS LIST IS NOT A CENSUS
// ===========================================================================
//
// ASSUME THERE ARE MORE VECTORS THAN THESE. Three review rounds have run on
// this gate. Round one defeated the share-alike marker table with a licence it
// did not list. Round two defeated it with ordinary FORMATTING — a line wrap, a
// non-breaking space, a full-width character. Round three defeated the
// containment test with a vendored subtree, and then defeated the identity
// check that replaced it with the eight vectors above. EACH ROUND FOUND NEW
// VECTORS AFTER THE PREVIOUS ROUND HAD BEEN CALLED CLOSED. There is no reason
// to believe round four would not.
//
// The same warning, in the same words, is on internal/record/readpath_test.go's
// KNOWN LIMITS section, and for the same reason: a limits section that reads as
// complete is a worse trap than no limits section at all, because it tells the
// next reader to stop checking.
//
// ===========================================================================
// WHY THE SHIPPED STATE IS SAFE ANYWAY
// ===========================================================================
//
// EVERY VECTOR ABOVE IS DOWNSTREAM OF AN ACQUISITION STEP NOBODY HAS RUN.
//
//	No licence body is checked into this repository. mirror/tier0/,
//	mirror/tier1/ and mirror/tier2/ hold Anvil's own LICENSE notes and nothing
//	else, and those notes cannot admit a feed — the gate reads LICENSE.full.txt,
//	which is not in git.
//	Every sha256 in mirror/LICENSE-MANIFEST.toml is EMPTY. A row with an empty
//	digest cannot be satisfied by any file.
//	Therefore A FRESH CLONE ADMITS NO FEED AT ALL. TestFreshCloneAdmitsNoFeed
//	and TestAnvilProseAloneCannotAdmitAnyFeed assert exactly that.
//
// So the danger here is not the code. It is a reader believing the gate is
// trustworthy and acquiring bodies on that belief. An operator who runs
// mirror/acquire-license-bodies.sh, fills in the digests and switches feeds on
// is taking on every obligation in this file personally, and must READ each
// acquired licence text. The gate is a second pair of eyes with the limits
// written above, not a first pair.

// admissionVectors are the working defeats of the admission path, each recorded
// with the section of the KNOWN LIMITS block it demonstrates.
//
// THEY ARE ASSERTED TO PUBLISH. That is deliberate and it is not an endorsement:
// it is what keeps the prose above honest. A vector that stops publishing is a
// vector somebody closed, and the response is to come here, delete the case and
// delete the paragraph — never to delete the assertion and leave the paragraph.
var admissionVectors = []struct {
	vector string
	body   string
	as     string
}{
	{
		vector: "V1 abbreviation: an MIT LICENSE with a GPL subtree, named only as \"the GPL\"",
		body: mitGrant +
			"The scripts in scripts/ are under the GPL.",
		as: "MIT",
	},
	{
		vector: "V1 abbreviation: \"the LGPL\" and \"the AGPL\"",
		body: mitGrant +
			"Some files here are under the LGPL and the AGPL.",
		as: "MIT",
	},
	{
		vector: "V2 British spelling: \"Eclipse Public Licence\"",
		body: mitGrant +
			"The bundled parser is under the Eclipse Public Licence.",
		as: "MIT",
	},
	{
		vector: "V2 British spelling: \"Mozilla Public Licence 2.0\"",
		body: mitGrant +
			"Parts are under the Mozilla Public Licence 2.0.",
		as: "MIT",
	},
	{
		vector: "V3 family exemption: Apache-1.1's advertising clause inside an Apache-2.0 file",
		body: "Apache License, Version 2.0\n\nLicensed under the Apache License, Version 2.0 " +
			"(the \"License\"); you may not use this file except in compliance with the " +
			"License.\n\nThe bundled xerces build is covered by the Apache License, Version 1.1, " +
			"which additionally requires that all advertising materials mention this product.",
		as: "Apache-2.0",
	},
	{
		vector: "V4 dual licence: \"under either the MIT License or the GPL\"",
		body: mitGrant +
			"You may use this work under either the MIT License or the GPL, at your choosing.",
		as: "MIT",
	},
	{
		vector: "V4 dual licence: \"or, alternatively, the GPL version 3\"",
		body: mitGrant +
			"This is released under the MIT License or, alternatively, the GPL version 3.",
		as: "MIT",
	},
	{
		vector: "V5 title collision: a commentary titled \"Apache License, Version 2.0\"",
		body: "Apache License, Version 2.0 — A Practical Commentary\n\nThis commentary explains " +
			"the licence clause by clause. It is copyright ACME and all rights are reserved.",
		as: "Apache-2.0",
	},
	{
		vector: "V6 licence quoted in prose: a CHANGELOG carrying the MIT grant sentence",
		body: "CHANGELOG\n\n2026-03-01 Relicensed the parser. The new header reads: Permission " +
			"is hereby granted, free of charge, to any person obtaining a copy of this " +
			"software.\n\nAll other content in this repository remains proprietary.",
		as: "MIT",
	},
	{
		vector: "V7 negation beyond the 96-byte window",
		body: "ACME DATA LICENCE\n\nThis dataset is not distributed under any open source " +
			"licence whatsoever, and in particular the terms below are reproduced only for " +
			"comparison purposes and do not apply to this dataset at all, as explained at " +
			"length in the preceding paragraphs of this notice.\n\nPermission is hereby " +
			"granted, free of charge, to any person obtaining a copy of this software.",
		as: "MIT",
	},
	{
		vector: "V8 splitting with a combining mark (U+0301) — visible only if you look",
		body: mitGrant +
			"Portions are under the Mozilla Pub́lic License.",
		as: "MIT",
	},
	{
		vector: "V8 splitting with an unassigned code point (U+0378)",
		body: mitGrant +
			"Portions are under the Mozilla Pub͸lic License.",
		as: "MIT",
	},
	{
		vector: "V8 splitting with a private-use code point (U+E000)",
		body: mitGrant +
			"Portions are under the Mozilla Public License.",
		as: "MIT",
	},
	{
		vector: "V8 splitting with a noncharacter (U+FDD0)",
		body: mitGrant +
			"Portions are under the Mozilla Pub﷐lic License.",
		as: "MIT",
	},
	{
		vector: "V8 splitting with an html tag",
		body: mitGrant +
			"Portions are under the Mozilla Pub<b></b>lic License.",
		as: "MIT",
	},
}

// mitGrant is the operative sentence of the MIT licence, used as the carrier for
// the vectors that need a body which really is positively identified.
const mitGrant = "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
	"obtaining a copy of this software and associated documentation files (the \"Software\"), " +
	"to deal in the Software without restriction.\n\n"

// TestTheAdmissionPathIsNotTrustworthy is the demonstration behind the KNOWN
// LIMITS block above. It is named for what it establishes, not for what it
// asserts, because a reader scanning test names is the reader this file is for.
//
// It requires each recorded vector to be ADMITTED. A failure here means a
// vector was closed — which is good news and a documentation bug: update the
// block comment, then delete the case. Do NOT delete the assertion and leave
// the paragraph standing; four revisions of the tier 2 LICENSE files were
// wrong in exactly that way.
func TestTheAdmissionPathIsNotTrustworthy(t *testing.T) {
	for _, tc := range admissionVectors {
		t.Run(tc.vector, func(t *testing.T) {
			spdx, _, _, ok := IdentifyPermissive(tc.body)
			if !ok {
				n := NormaliseForMatching(tc.body)
				why := "not positively identified"
				if m := permissiveMatches(n); len(m) == 1 {
					why = strings.Join(otherLicenceContent(n, m[0]), "; ")
				} else if len(m) > 1 {
					why = "identified as several licences"
				}
				t.Fatalf("this vector no longer publishes (%s). That is an IMPROVEMENT and a "+
					"documentation bug: update the KNOWN LIMITS block at the top of this file "+
					"and delete this case, rather than deleting the assertion", why)
			}
			if spdx != tc.as {
				t.Errorf("admitted as %q, but the KNOWN LIMITS block records %q; the block is "+
					"now wrong about what this vector produces", spdx, tc.as)
			}
		})
	}
}

// TestTheRefusalPathAdmitsNothing is the other half of the sentence at the top:
// a refusal cannot publish.
//
// It is a narrow assertion and deliberately so. It does not claim the refusals
// are correct or complete — the whole of this file is about how they are not.
// It claims the one thing that makes a refusal worth trusting: a Decision that
// reports itself refused projects onto no manifest row, so nothing downstream
// can read permission out of it.
func TestTheRefusalPathAdmitsNothing(t *testing.T) {
	for _, body := range []string{
		"",
		"All rights reserved. No licence is granted.",
		"GNU GENERAL PUBLIC LICENSE Version 3",
		mitGrant + "The components under third_party/ are distributed under the CDDL Version 1.0.",
	} {
		if _, _, _, ok := IdentifyPermissive(body); ok {
			t.Errorf("IdentifyPermissive admitted %q", body)
		}
	}
	d := Decision{}
	if !d.Refused() {
		t.Fatal("the zero Decision does not report itself refused")
	}
	if row, err := d.ManifestRow(); err == nil {
		t.Fatalf("a refusal projected onto a manifest row without complaint: %+v", row)
	}
}
