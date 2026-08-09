package license

import "strings"

// ---------------------------------------------------------------------------
// THE INVERTED DEFAULT: what a body must PROVE in order to be published
// ---------------------------------------------------------------------------
//
// Two rounds of adversarial review defeated the share-alike marker table in
// classifierRules, and the second round did it with ordinary licence prose and
// ordinary formatting rather than with anything clever. That is not a bug in
// the table. It is the table being asked the wrong question.
//
// The old gate asked "is this share-alike?" and PUBLISHED when the answer was
// no. A substring table cannot answer that question about text nobody
// anticipated, and text nobody anticipated is the only case that matters: every
// wording already in the table is a wording somebody already thought of.
//
// This file asks the other question. Tier 0 and Tier 1 — the publishable tiers,
// the ones whose contents can be merged into an artifact Anvil ships — are
// reachable ONLY by a body positively identified as one of the licences
// enumerated below. Everything else is refused: share-alike, restricted,
// unrecognised, ambiguous, empty. UNKNOWN IS NOT PUBLISHABLE.
//
// ===========================================================================
// BEFORE YOU TRUST ANY OF WHAT FOLLOWS: known_limits_test.go
// ===========================================================================
//
// THE REFUSAL PATH IS TRUSTWORTHY. THE ADMISSION PATH IS NOT. "Positively
// identified" below means "matched a substring signature and tripped none of
// three tables of strings", and eight working ways through it are recorded,
// each with a body that publishes today, in this package's KNOWN LIMITS section
// at the top of known_limits_test.go. Read it before citing this file as a
// control. Nothing in this comment is a claim that identification is sound; it
// is a claim about which question the gate asks.
//
// ===========================================================================
// THE THIRD ROUND: IDENTITY, NOT CONTAINMENT
// ===========================================================================
//
// The first version of this file got the question right and the PROPOSITION
// wrong, twice over. Both defects have the same shape — a test that proves
// something weaker than the thing it is standing in for — and both are fixed
// here rather than patched.
//
// DEFECT ONE: permissiveMatches proved that the document CONTAINS a permissive
// licence, and the gate read that as "the document IS one". Those are different
// documents. A project LICENSE reading "this tree is MIT; the vendored subtree
// under third_party/ is CDDL-1.0" contains exactly one ENUMERATED permissive
// licence, so the ambiguity branch never fired — the CDDL is invisible to a
// table that only knows the licences it may publish — and the whole file
// published at tier 0 and tier 1 with the reciprocal terms attached. Eight such
// bodies did — the count is len(wrappedBodies) in identity_test.go, and this
// comment said "seven" for two revisions after the eighth was added.
// The vendored-subtree case is not exotic; it is the ordinary shape
// of a checked-in LICENSE, and it is the case the ambiguity refusal was written
// FOR. The intent was right and the implementation asked containment.
//
// So identification now requires BOTH halves:
//
//	(a) EXACTLY ONE enumerated permissive licence is identified, and
//	(b) NOTHING ELSE licence-like appears anywhere in the document — no other
//	    licence name, no reciprocity wording, no restriction wording, no
//	    "portions of this are under…" scoping.
//
// Half (b) is what otherLicenceContent does, and the marker table is one of its
// detectors: classifierRules is wired as a VETO here rather than as a
// classifier. A document that is purely one permissive licence is the only
// thing that publishes.
//
// DEFECT TWO: a signature was a set of terms required to appear ANYWHERE in the
// document, so {"apache license", "version 2.0"} identified a 12 KB file titled
// "ACME DATA LICENCE, Version 2.0" that said "This dataset is NOT distributed
// under the Apache License". Two words in the same file is not a phrase. Every
// signature is now a CONTIGUOUS PHRASE in the normalised text, or a small set
// of phrases required within a BOUNDED WINDOW of one another, and every one is
// additionally checked for explicit negation in the run-up to the match. See
// the signature type.
//
// ===========================================================================
// THE TENSION, AND HOW IT IS RESOLVED DELIBERATELY
// ===========================================================================
//
// A veto that is too eager is not "safe". A gate that quarantines everything is
// as useless as one that publishes everything, and three of the feeds this
// system exists to mirror — ghsa, redhat-csaf and osv-pypi — carry the real
// CC-BY-4.0 legalcode, whose footer says:
//
//	"The text of the Creative Commons public licenses is dedicated to the
//	 public domain under the CC0 Public Domain Dedication."
//
// That sentence NAMES A SECOND LICENCE, in the licence text of a feed that must
// publish. A veto keyed on the token "cc0" quarantines all three feeds. The
// resolution is not a special case bolted on afterwards; it is a rule about
// what a licence NAME is worth as evidence:
//
//	A veto marker must be a name at OPERATIVE STRENGTH — the string a document
//	uses when it is placing material under those terms, not the string it uses
//	when it is talking ABOUT them.
//
// So the CC0 entries in licenceNameMarkers are "cc0 1.0 universal", "cc0-1.0"
// and "creative commons zero" — the forms a document uses to license something
// under CC0 — and the bare token "cc0" is deliberately absent, with the reason
// written down at the table. The CC legalcode footer is a statement about the
// copyright status of the LICENCE TEXT ITSELF, made by Creative Commons about
// its own prose; it places none of the licensed material under CC0. Both
// directions of that judgement are tested:
// TestAPermissiveBodyThatMerelyNamesAnotherLicenceStillPublishes drives the
// legalcode footer through the gate and requires admission, and
// TestAPermissiveLicenceWrappedAroundASecondOneIsRefused drives eight
// vendored-subtree bodies through it and requires refusal.
//
// # This does not make classifierRules dead code
//
// The marker table is still read, and it now has two jobs rather than one. It
// classifies for the tier-2 quarantine and supplies the obligation a Decision
// reports; and it VETOES, here, as one of the detectors for half (b). What it
// is still not is the thing standing between a reciprocal licence and
// publication — that is the positive identification, which a reciprocal text
// simply does not have. Completeness of the table remains a nice-to-have on the
// classification side and, on the veto side, one contributor among several to a
// check whose failure mode is refusal.
//
// # Why an enumerated set is not the forbidden SPDX allowlist
//
// A.4's Forbidden actions rule out "a pure-SPDX allowlist as the sole gate", and
// this is not one. An allowlist keys on the DECLARED identifier — the thing a
// mislabelled artifact gets wrong, and the thing the CISA KEV case proves a
// registry gets wrong. What follows keys on the OPERATIVE TEXT the publisher
// wrote, is only ever consulted after the marker table has had its say, and
// cannot admit anything the marker table has classified as share-alike or
// restricted, because those refusals run first and independently. The declared
// identifier still has to agree with the text afterwards; it never substitutes
// for it.

// ---------------------------------------------------------------------------
// Signatures — phrases, not document-wide conjunctions
// ---------------------------------------------------------------------------

// signature is one way of recognising a licence in normalised text.
//
// A signature with ONE phrase is a contiguous match: the phrase, as written,
// present in the normalised document. Normalisation has already collapsed hard
// wrapping, NBSP, doubled spaces and full-width forms, so "apache license
// version 2.0" is a contiguous phrase in the real Apache-2.0 header even though
// the header puts a newline and thirty spaces in the middle of it.
//
// A signature with SEVERAL phrases requires all of them WITHIN A BOUNDED WINDOW
// of the first — window normalised bytes either side of it. That is the only
// concession to non-contiguity, and it is bounded because the alternative is
// the defect this shape replaces: two terms anywhere in a 12 KB file, which is
// a property of the file's SIZE rather than of anything it says.
//
// window MUST be zero when there is one phrase and non-zero when there are
// several; TestEverySignatureIsAPhraseOrABoundedWindow enforces both halves,
// because a multi-phrase signature with a zero window silently matches nothing
// and a single-phrase signature with a window silently claims a looseness it
// does not have.
type signature struct {
	phrases []string
	window  int
}

// phrase builds a contiguous single-phrase signature.
func phrase(p string) signature { return signature{phrases: []string{p}} }

// within builds a bounded-window signature. The first phrase is the ANCHOR; the
// rest must appear within window normalised bytes either side of it.
func within(window int, phrases ...string) signature {
	return signature{phrases: phrases, window: window}
}

// matches reports whether an already-normalised text carries this signature.
//
// Every candidate occurrence of the anchor is tested, and a match is accepted
// only if at least one occurrence is UN-NEGATED — see negatedBefore. Testing
// every occurrence rather than the first is what keeps the negation check from
// refusing a licence that happens to disclaim something about itself early on:
// the CC legalcodes all open with "Creative Commons Corporation … is not an
// authorized legal services organization".
func (s signature) matches(n string) bool {
	if len(s.phrases) == 0 || n == "" {
		return false
	}
	anchor := s.phrases[0]
	if anchor == "" {
		return false
	}
	for from := 0; from <= len(n)-len(anchor); {
		i := strings.Index(n[from:], anchor)
		if i < 0 {
			return false
		}
		at := from + i
		from = at + 1
		if _, negated := negatedBefore(n, at); negated {
			continue
		}
		if len(s.phrases) == 1 {
			return true
		}
		lo := at - s.window
		if lo < 0 {
			lo = 0
		}
		hi := at + len(anchor) + s.window
		if hi > len(n) {
			hi = len(n)
		}
		region := n[lo:hi]
		ok := true
		for _, p := range s.phrases[1:] {
			if !containsNormalised(region, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// negationCues are the phrases a document uses to say that it is NOT under the
// licence it is about to name.
//
// They are deliberately anchored on a LICENSING VERB or a substitution phrase
// rather than on a bare "not". "is not a" and "is not an" are absent on
// purpose: every Creative Commons legalcode opens with "Creative Commons
// Corporation … is not an authorized legal services organization", and a cue
// that broad would make a run of prose near the top of a real licence file
// suppress the identification of that same file.
//
// A false negation is a refusal, which is the safe direction — but it is still
// a refusal of a feed this system needs, so the list is kept precise and
// TestPermissiveLicenceTextsAreNotDraggedIntoQuarantine is what holds that line.
var negationCues = []string{
	"not licensed under",
	"not distributed under",
	"not released under",
	"not offered under",
	"not made available under",
	"not available under",
	"not provided under",
	"not published under",
	"not governed by",
	"not covered by",
	"not subject to the terms of",
	"not under the",
	"not under a",
	"is not the",
	"are not the",
	"rather than the",
	"instead of the",
	"other than the",
	"does not apply",
}

// negationWindow is how far back from a candidate match a negation cue is
// looked for, in normalised bytes.
//
// 96 is about one and a half lines of prose: long enough for "This dataset is
// NOT distributed under the Apache License, Version 2.0" with a clause in
// between, short enough that a "not" belonging to the previous sentence does
// not reach.
const negationWindow = 96

// negatedBefore reports whether an explicit negation cue sits within
// negationWindow bytes before the offset at, and which cue it was.
func negatedBefore(n string, at int) (string, bool) {
	lo := at - negationWindow
	if lo < 0 {
		lo = 0
	}
	ctx := n[lo:at]
	for _, cue := range negationCues {
		if containsNormalised(ctx, cue) {
			return cue, true
		}
	}
	return "", false
}

// permissiveLicence is one member of the enumerated publishable set: a licence
// whose obligations Anvil can discharge inside a tier 0/1 artifact, together
// with the wording that identifies it.
type permissiveLicence struct {
	// spdx is the identifier a Decision reports when this licence is what the
	// body says. EMPTY IS ALLOWED and means "these terms have no SPDX list
	// identifier and this package will not invent one" — the same discipline
	// classifierRules applies to the GPL family. LicenseRef- ids are used where
	// the feed table already declares one, so that the pin, the row and the
	// conclusion can be compared.
	spdx string

	// name is for diagnostics. A refusal that says which licences WOULD have
	// been accepted is a refusal an operator can act on.
	name string

	// family groups entries that are the same licence at different precisions,
	// so that identifying a text as both is not treated as a document naming two
	// licences. BSD-3-Clause and BSD-2-Clause are the case it exists for: the
	// 2-clause signature is a prefix of the 3-clause text and always co-fires.
	//
	// It is also the key licenceNameMarkers is exempted by: a marker whose
	// family equals the identified licence's family is that licence naming
	// itself, which is not evidence of a second one.
	//
	// Entries in DIFFERENT families that both match make a text AMBIGUOUS, and
	// ambiguous is quarantined — see permissiveMatches.
	family string

	// ob is the obligation this licence imposes. Only ObligationPublicDomain and
	// ObligationNotice may appear here; publishableObligations enforces it and
	// TestEveryEnumeratedPermissiveLicenceIsActuallyPermissive asserts it.
	ob Obligation

	// signatures identify the licence. The licence is identified if ANY of them
	// matches; each is a contiguous phrase or a bounded window. Phrases are
	// written in the form NormaliseForMatching produces.
	signatures []signature
}

// permissiveLicences is THE ENUMERATED SET. A body that matches nothing here
// does not reach tier 0 or tier 1, whatever it says about itself and whatever
// the feed table declares.
//
// Adding an entry is a licence decision, not a bug fix. The question it answers
// is "can Anvil discharge these obligations inside an artifact it publishes",
// and the evidence for the answer belongs in research/01 and in the feed's
// record before it belongs here.
//
// SOME SIGNATURES BELOW ARE PROVISIONAL, AND WHICH ONES IS RECORDED. Three of
// the pinned text_urls in mirror/LICENSE-MANIFEST.toml are html pages that
// nobody has fetched — SPDX's CVE-TOU transcription, MITRE's CWE terms of use,
// and the NVD General FAQs — so the phrases for those three are drawn from the
// sentences research/01 quotes rather than from an acquired document. If an
// acquired text does not match, THE FEED IS REFUSED. That is the correct
// direction, and the correct response to it is to read the acquired text and
// record its operative wording here. It is never to widen a signature until
// something passes.
var permissiveLicences = []permissiveLicence{
	{
		spdx:   "CC0-1.0",
		family: "cc0",
		name:   "CC0 1.0 Universal (public domain dedication)",
		ob:     ObligationPublicDomain,
		signatures: []signature{
			phrase("cc0 1.0 universal"),
			phrase("cc0-1.0"),
			phrase("creative commons zero"),
			phrase("creativecommons.org/publicdomain/zero/1.0"),
			// The CC0 legalcode's operative sentence and the deed's.
			phrase("has waived all copyright and related or neighboring rights"),
			phrase("waiving all rights to the work worldwide"),
			// The pair {"cc0", "public domain dedication"} USED TO BE A
			// SIGNATURE, and it fired on the CC-BY-4.0 legalcode: every
			// Creative Commons licence text ends by saying its own prose is
			// "dedicated to the public domain under the CC0 Public Domain
			// Dedication". So the CC-BY-4.0 feeds identified as TWO licences
			// and quarantined. The phrases above are the forms a document uses
			// when it is placing material under CC0, which is the only use of
			// the name that is evidence about the material.
		},
	},
	{
		spdx:   "CC-BY-4.0",
		family: "cc-by-4.0",
		name:   "Creative Commons Attribution 4.0 International",
		ob:     ObligationNotice,
		signatures: []signature{
			phrase("creative commons attribution 4.0 international"),
			phrase("cc-by-4.0"),
			phrase("cc-by 4.0"),
			phrase("cc by 4.0"),
			phrase("creativecommons.org/licenses/by/4.0"),
			// The legalcode's own title line, which normalisation joins:
			// "Attribution 4.0 International" over
			// "=======================" is not contiguous, but the agreement
			// sentence is.
			within(80, "attribution 4.0 international", "public license"),
		},
	},
	{
		spdx:   "MIT",
		family: "mit",
		name:   "MIT License",
		ob:     ObligationNotice,
		signatures: []signature{
			phrase("permission is hereby granted, free of charge"),
			within(200, "mit license", "permission is hereby granted"),
		},
	},
	{
		spdx:   "Apache-2.0",
		family: "apache-2.0",
		name:   "Apache License, Version 2.0",
		ob:     ObligationNotice,
		signatures: []signature{
			// THE B2 CASE. This used to be {"apache license", "version 2.0"},
			// two terms anywhere in the document, and it identified a file
			// titled "ACME DATA LICENCE, Version 2.0" that said it was NOT
			// under the Apache License. Both forms below are contiguous in the
			// real header once normalisation has collapsed the line break and
			// the thirty spaces of centring between the two lines.
			phrase("apache license, version 2.0"),
			phrase("apache license version 2.0"),
			phrase("apache-2.0"),
			phrase("apache.org/licenses/license-2.0"),
		},
	},
	{
		spdx:   "BSD-3-Clause",
		family: "bsd",
		name:   "BSD 3-Clause License",
		ob:     ObligationNotice,
		signatures: []signature{
			// The grant and the endorsement clause are separated by clause 2 of
			// the licence, which is about 400 normalised bytes. 2500 is longer
			// than the whole of BSD-3-Clause and much shorter than a document
			// that quotes a grant in one place and an unrelated endorsement
			// clause somewhere else.
			within(2500,
				"redistribution and use in source and binary forms",
				"endorse or promote products"),
			phrase("bsd-3-clause"),
		},
	},
	{
		spdx:   "BSD-2-Clause",
		family: "bsd",
		name:   "BSD 2-Clause License",
		ob:     ObligationNotice,
		signatures: []signature{
			phrase("redistribution and use in source and binary forms"),
			phrase("bsd-2-clause"),
		},
	},
	{
		spdx:   "ISC",
		family: "isc",
		name:   "ISC License",
		ob:     ObligationNotice,
		signatures: []signature{
			phrase("permission to use, copy, modify, and/or distribute this software for any purpose"),
			phrase("isc license"),
		},
	},

	// ---- The specific public-domain and terms-of-use cases the feed table
	// needs. Each is here because a row in mirror/LICENSE-MANIFEST.toml routes
	// a feed to tier 0 on it, and without it that feed can never be admitted.

	{
		spdx:   "CVE-TOU",
		family: "cve-tou",
		name:   "CVE Program Terms of Use (feed cvelistv5)",
		ob:     ObligationNotice,
		signatures: []signature{
			phrase("cve program terms of use"),
			phrase("cve-tou"),
		},
	},
	{
		spdx:   "LicenseRef-MITRE-CWE-ToU",
		family: "mitre-cwe-tou",
		name:   "MITRE CWE Terms of Use (feed cwe)",
		ob:     ObligationNotice,
		signatures: []signature{
			// PROVISIONAL: cwe.mitre.org/about/termsofuse.html has not been
			// fetched. This used to be {"cwe", "mitre", "terms of use"} —
			// three terms anywhere in the document, which any MITRE page
			// mentioning CWE satisfies, including one that is not a licence at
			// all. It is now a heading-sized window: the three terms have to
			// occur together, in one sentence's worth of text.
			within(120, "terms of use", "cwe", "mitre"),
			phrase("cwe terms of use"),
		},
	},
	{
		spdx:   "LicenseRef-US-Gov-Public-Domain",
		family: "us-gov-public-domain",
		name:   "United States Government work, public domain (feed nvd)",
		ob:     ObligationPublicDomain,
		signatures: []signature{
			phrase("united states government work"),
			phrase("u.s. government work"),
			phrase("work of the united states government"),
			// PROVISIONAL: the NVD General FAQs have not been fetched. The
			// phrase is the sentence research/01 S5 quotes.
			phrase("publications are available in the public domain"),
			phrase("not subject to copyright protection in the united states"),
		},
	},
}

// publishableObligations is the second half of the inverted default, and it is
// the half that survives someone adding a class to the Obligation enum.
//
// Tier 0/1 admits these classes and no others. It is an explicit set rather than
// a `!= ObligationShareAlike` test on purpose: a new class added tomorrow —
// ObligationPatentRetaliation, say — is refused by default here, whereas an
// inequality would have admitted it and nobody would have noticed.
var publishableObligations = map[Obligation]bool{
	ObligationPublicDomain: true,
	ObligationNotice:       true,
}

// IdentifyPermissive reports whether a licence text IS one of the enumerated
// permissive licences, and which.
//
// IS, NOT CONTAINS. Both halves have to hold: exactly one enumerated licence is
// identified, and nothing else licence-like appears anywhere in the document.
// It is the question tier 0 and tier 1 turn on, and it is exported for the same
// reason Classify is: the next reviewer must be able to hand it a licence and
// watch it answer, without reading Resolve.
//
// A false result is not "probably fine". It is one of "this text was not
// recognised", "this text names several enumerated licences" or "this text is
// one permissive licence with something else wrapped around it", and none of
// the three is publishable.
func IdentifyPermissive(body string) (spdx, name string, ob Obligation, ok bool) {
	return identifyPermissive(NormaliseForMatching(body))
}

// identifyPermissive is IdentifyPermissive over already-normalised text.
func identifyPermissive(n string) (spdx, name string, ob Obligation, ok bool) {
	m := permissiveMatches(n)
	if len(m) != 1 {
		return "", "", ObligationUnknown, false
	}
	if len(otherLicenceContent(n, m[0])) > 0 {
		return "", "", ObligationUnknown, false
	}
	return m[0].spdx, m[0].name, m[0].ob, true
}

// permissiveMatches returns the distinct enumerated licences a NORMALISED text
// matches, one per family, in table order.
//
// IT ANSWERS CONTAINMENT, AND CONTAINMENT IS NOT IDENTITY. It is the first of
// the two halves identifyPermissive requires and it is exported to no one; a
// caller that wants to know what a document IS calls IdentifyPermissive. The
// count is the answer in two of the three cases, and Resolve says which in its
// refusal:
//
//	0 .... unrecognised. Not publishable.
//	1 .... one enumerated licence is present. Necessary, NOT sufficient.
//	2+ ... AMBIGUOUS, and refused. A document that names several ENUMERATED
//	       licences is a document nobody has read carefully enough to publish
//	       from.
//
// The family grouping is what keeps case 2 from firing on BSD-3-Clause, whose
// text necessarily satisfies the BSD-2-Clause signature too.
func permissiveMatches(n string) []permissiveLicence {
	if n == "" {
		return nil
	}
	var out []permissiveLicence
	seen := map[string]bool{}
	for _, l := range permissiveLicences {
		if seen[l.family] {
			continue
		}
		for _, sig := range l.signatures {
			if sig.matches(n) {
				seen[l.family] = true
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// permissiveNames lists the enumerated set for a refusal message, so that an
// operator reading "not positively identified" can see what identification
// would have looked like.
func permissiveNames() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(permissiveLicences))
	for _, l := range permissiveLicences {
		if seen[l.name] {
			continue
		}
		seen[l.name] = true
		out = append(out, l.name)
	}
	return out
}
