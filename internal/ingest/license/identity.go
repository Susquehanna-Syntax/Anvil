package license

import "fmt"

// ---------------------------------------------------------------------------
// THE VETO — half (b) of identity: nothing else licence-like is in here
// ---------------------------------------------------------------------------
//
// publishable.go establishes that a document CONTAINS exactly one enumerated
// permissive licence. This file establishes that it contains nothing else, and
// the two together are what "this document IS a permissive licence" means.
//
// WHY A SEPARATE DETECTOR AND NOT A LONGER ENUMERATION. The vendored-subtree
// case is the one that matters, and the second licence in it is by definition
// one the publishable set does not list — a set of things Anvil may publish
// cannot recognise the things it may not. So the veto is quantified over a
// DIFFERENT population from the enumeration: every licence anyone might have
// bundled, whether or not Anvil could ever publish it.
//
// THE FAILURE MODES POINT IN OPPOSITE DIRECTIONS AND THAT IS THE DESIGN.
// A name missing from these tables is a document that publishes when it should
// not — the residual, recorded in KNOWN LIMITS below. A name that is here but
// should not be is a feed that quarantines when it could have shipped, which
// costs an operator an investigation and costs the published artifact nothing.
// Every judgement call below is made in the second direction, and the boundary
// case is written down where it was decided rather than inferred later.
//
// ===========================================================================
// KNOWN LIMITS OF THE VETO — READ BEFORE TREATING A GREEN RUN AS A CONTROL
// Dated 2026-08-09. All five items are OPEN.
//
// THIS IS THE SHORT LIST AND IT IS THE VETO'S OWN. The package-level list —
// eight vectors, each with a body that publishes today, plus what a green run
// does not prove and why the real fix is a licence identifier rather than more
// substrings — is the KNOWN LIMITS section at the top of known_limits_test.go.
// Limits C, D and E below are named there as V1, V2 and V3.
// ===========================================================================
//
// LIMIT A — A SECOND LICENCE THAT NAMES ITSELF NOWHERE, USES NONE OF THE
// RECIPROCITY WORDINGS BELOW AND IS INTRODUCED BY NONE OF THE SCOPING PHRASES
// IS NOT DETECTED. That is a real hole and it is the same hole in a new place:
// this is a table of strings, and a table of strings recognises the strings it
// lists. What has changed is what rests on it. Before the inversion, a missing
// share-alike wording was a PUBLICATION. Now a missing veto marker is a
// publication only for a document that ALSO carries a complete, un-negated
// permissive signature and passes the share-alike and restricted refusals — a
// much smaller population, and one where the document really does look like a
// single permissive licence to any reader.
//
// LIMIT B — THE THREE HTML-PAGE PINS ARE THE MOST LIKELY FALSE VETOES. The
// SPDX CVE-TOU transcription, MITRE's CWE terms of use and the NVD General FAQs
// are web pages, and a web page carries navigation, footers and boilerplate
// that a plain licence file does not. If an acquired page trips a marker here,
// the feed is refused. THE ANSWER IS TO RE-PIN A PLAIN OPERATIVE TEXT, never to
// delete a marker until the page passes: a veto weakened to admit a page is a
// veto weakened for every feed.
//
// LIMIT C — ABBREVIATIONS ARE NOT MATCHED, AND CANNOT BE. licenceNameMarkers
// holds "gnu general public license" and "gpl-3.0". It does not hold "the GPL",
// and a bare "gpl" entry would fire on any prose that mentions the licence. An
// MIT LICENSE ending "The scripts in scripts/ are under the GPL." publishes.
// Demonstrated as V1 in known_limits_test.go.
//
// LIMIT D — EVERY MARKER IS SPELLED "LICENSE". "Eclipse Public Licence" and
// "Mozilla Public Licence 2.0" match nothing here. Doubling the table with
// British spellings would close these two strings and not the class; the class
// is "the name was written in a form nobody listed". Demonstrated as V2.
//
// LIMIT E — THE FAMILY EXEMPTION IS COARSER THAN THE LICENCES IT EXEMPTS. A
// marker whose family equals the identified licence's family is skipped, so
// that a licence naming itself is not read as a second one. "apache license"
// carries family "apache-2.0", so an Apache-2.0 body that also bundles code
// under the Apache License, Version 1.1 — a different licence, with an
// advertising clause — is not vetoed. The same holds across the "bsd" family.
// Demonstrated as V3.

// licenceNameMarker is the name of a licence, matched against normalised text
// and used ONLY as a veto. It never contributes an obligation and never
// identifies anything.
type licenceNameMarker struct {
	// marker is the name, in the form NormaliseForMatching produces.
	marker string

	// family is the permissiveLicence family this is the name OF, or "" when
	// it names a licence outside the enumerated set. A marker whose family
	// equals the identified licence's family is that licence naming itself,
	// which is not evidence of a second one.
	family string
}

// licenceNameMarkers is the veto index: licence names at OPERATIVE STRENGTH.
//
// ON "OPERATIVE STRENGTH", WHICH IS THE WHOLE OF THE CALIBRATION. A marker here
// must be the string a document uses when it is PLACING MATERIAL under those
// terms, not the string it uses when it is talking about them. The case that
// forced the distinction is the footer every Creative Commons legalcode carries:
//
//	"The text of the Creative Commons public licenses is dedicated to the
//	 public domain under the CC0 Public Domain Dedication."
//
// That sentence is Creative Commons describing the copyright status of its own
// PROSE. It places none of the licensed material under CC0. A veto keyed on the
// bare token "cc0" reads it as a second licence and quarantines ghsa,
// redhat-csaf and osv-pypi — the three CC-BY-4.0 feeds this system exists to
// mirror. So the CC0 entries below are "cc0 1.0 universal", "cc0-1.0" and
// "creative commons zero", and BARE "cc0" IS DELIBERATELY ABSENT.
//
// The same reasoning excludes bare "creative commons" (in every CC text of
// every flavour), bare "mpl" (a substring of "implementation"), bare "epl" (a
// substring of "deploy") and bare "bsd"/"mit" as words.
//
// TestTheVetoIndexDoesNotFireOnItsOwnLicences is what holds this line: it
// drives every enumerated licence's own canonical text through the veto and
// requires silence.
var licenceNameMarkers = []licenceNameMarker{
	// ---- Names of the enumerated permissive licences. A veto only when the
	// identified licence is a DIFFERENT one: MIT text that also names Apache is
	// two licences in one file. ----
	{marker: "mit license", family: "mit"},
	{marker: "the expat license", family: "mit"},
	{marker: "apache license", family: "apache-2.0"},
	{marker: "apache-2.0", family: "apache-2.0"},
	{marker: "apache software license", family: "apache-2.0"},
	{marker: "apache.org/licenses/license-2.0", family: "apache-2.0"},
	{marker: "bsd license", family: "bsd"},
	{marker: "bsd-2-clause", family: "bsd"},
	{marker: "bsd-3-clause", family: "bsd"},
	{marker: "isc license", family: "isc"},
	{marker: "cc0 1.0 universal", family: "cc0"},
	{marker: "cc0-1.0", family: "cc0"},
	{marker: "creative commons zero", family: "cc0"},
	{marker: "creativecommons.org/publicdomain/zero", family: "cc0"},
	{marker: "creative commons attribution 4.0", family: "cc-by-4.0"},
	{marker: "cc-by-4.0", family: "cc-by-4.0"},
	{marker: "cc-by 4.0", family: "cc-by-4.0"},
	{marker: "creativecommons.org/licenses/by/4.0", family: "cc-by-4.0"},
	{marker: "cve program terms of use", family: "cve-tou"},
	{marker: "cve-tou", family: "cve-tou"},

	// ---- Licences outside the enumerated set. ALWAYS a veto: Anvil has never
	// decided it can discharge these, so a document carrying one is a document
	// carrying terms nobody has read. ----

	// Reciprocal and weak-copyleft families.
	{marker: "common development and distribution license"},
	{marker: "cddl"},
	{marker: "eclipse public license"},
	{marker: "eclipse distribution license"},
	{marker: "epl-1.0"},
	{marker: "epl-2.0"},
	{marker: "mozilla public license"},
	{marker: "mpl-2.0"},
	{marker: "mpl 2.0"},
	{marker: "mozilla.org/mpl"},
	{marker: "open software license"},
	{marker: "osl-3.0"},
	{marker: "academic free license"},
	{marker: "common public license"},
	{marker: "ibm public license"},
	{marker: "sun public license"},
	{marker: "reciprocal public license"},
	{marker: "q public license"},
	{marker: "european union public licence"},
	{marker: "european union public license"},
	{marker: "eupl-1.2"},
	{marker: "cecill"},
	{marker: "gnu general public license"},
	{marker: "gnu lesser general public license"},
	{marker: "gnu affero general public license"},
	{marker: "gpl-2.0"},
	{marker: "gpl-3.0"},
	{marker: "lgpl-2.1"},
	{marker: "lgpl-3.0"},
	{marker: "agpl-3.0"},
	{marker: "gnu.org/licenses"},

	// Permissive and public-domain licences Anvil has NOT enumerated. They are
	// vetoes for the same reason the reciprocal ones are: the question is not
	// "is the second licence dangerous", it is "has anybody read it".
	{marker: "microsoft public license"},
	{marker: "microsoft reciprocal license"},
	{marker: "ms-pl"},
	{marker: "ms-rl"},
	{marker: "boost software license"},
	{marker: "artistic license"},
	{marker: "zlib license"},
	{marker: "zlib/libpng license"},
	{marker: "python software foundation license"},
	{marker: "sleepycat license"},
	{marker: "openssl license"},
	{marker: "unicode terms of use"},
	{marker: "unicode license"},
	{marker: "the unlicense"},
	{marker: "wtfpl"},
	{marker: "do what the fuck you want to public license"},
	{marker: "bsd-4-clause"},
	{marker: "university of illinois/ncsa"},
	{marker: "vim license"},
	{marker: "postgresql license"},
	{marker: "curl license"},

	// Source-available and data licences. None is publishable and all appear
	// in bundled LICENSE files.
	{marker: "server side public license"},
	{marker: "sspl-1.0"},
	{marker: "business source license"},
	{marker: "elastic license"},
	{marker: "commons clause"},
	{marker: "open database license"},
	{marker: "odbl-1.0"},
	{marker: "open data commons"},
	{marker: "community data license agreement"},

	// The Creative Commons flavours Anvil does not publish. "cc-by-sa" and its
	// relatives are also classifierRules markers; naming them here too costs
	// nothing and means the veto does not depend on the classifier's ordering.
	{marker: "creative commons attribution-sharealike"},
	{marker: "creative commons attribution-noncommercial"},
	{marker: "creative commons attribution-noderivatives"},
	{marker: "attribution-sharealike"},
	{marker: "cc-by-sa"},
	{marker: "cc by-sa"},
	{marker: "cc-by-nc"},
	{marker: "cc-by-nd"},
	{marker: "licenses/by-sa/"},
	{marker: "licenses/by-nc"},
	{marker: "licenses/by-nd"},
	{marker: "creative commons attribution 3.0"},
	{marker: "creative commons attribution 2.0"},
}

// secondTermsMarker is wording that introduces a SECOND set of terms without
// necessarily naming a licence. It is the other detector for half (b).
type secondTermsMarker struct {
	marker string
	why    string
}

// secondTermsMarkers is the scoping-and-reciprocity half of the veto.
//
// TWO KINDS OF WORDING ARE HERE, AND THEY CATCH DIFFERENT DOCUMENTS.
//
// SCOPING: "the components under third_party/ are …". A document that scopes
// terms to a SUBSET of the material it covers is a document with more than one
// set of terms in it, whether or not it names the second one. This is the
// vendored-subtree shape, and it is the one the ambiguity refusal was written
// for.
//
// RECIPROCITY WITHOUT A NAME: the EPL-2.0 §3.2, CDDL-1.0 §3.1, MS-PL §3(D) and
// OSL-3.0 §1(c) shapes — a reciprocal duty imposed by a clause that calls the
// licence "this Agreement" or "this License" and never names it. These are
// DELIBERATELY NOT ADDED TO classifierRules: that table's corpus test asserts
// it cannot see these four wordings, which is what makes the inverted default's
// property test non-vacuous, and moving them there would satisfy the test by
// changing the thing it measures. Here they are a veto and nothing else.
//
// EVERY ENTRY WAS CHECKED AGAINST THE ENUMERATED LICENCES' OWN TEXTS.
// The near misses are worth recording because they are where the next
// contributor will be tempted:
//
//	"additional license terms" is ABSENT because Apache-2.0 §4 says "additional
//	or different license terms and conditions", and CC-BY-4.0 §2(a)(5)(C) says
//	"additional or different terms or conditions". Both would self-veto.
//	Bare "third party" is ABSENT for the same reason — it is ordinary licence
//	prose — and only the SCOPING forms are listed.
var secondTermsMarkers = []secondTermsMarker{
	// Scoping: terms that apply to part of the material only.
	{marker: "third_party", why: "a vendored-subtree path"},
	{marker: "third-party licenses", why: "a second licence set, scoped"},
	{marker: "third party licenses", why: "a second licence set, scoped"},
	{marker: "third-party license", why: "a second licence, scoped"},
	{marker: "third party license", why: "a second licence, scoped"},
	{marker: "third-party notices", why: "a bundled-components notice file"},
	{marker: "third party notices", why: "a bundled-components notice file"},
	{marker: "third-party components", why: "bundled components with their own terms"},
	{marker: "third party components", why: "bundled components with their own terms"},
	{marker: "vendored", why: "a vendored subtree"},
	{marker: "bundled dependencies", why: "bundled components with their own terms"},
	{marker: "portions of this software", why: "terms scoped to part of the material"},
	{marker: "portions of this product", why: "terms scoped to part of the material"},
	{marker: "portions of the software", why: "terms scoped to part of the material"},
	{marker: "respective licenses", why: "several licences, one per component"},
	{marker: "respective licences", why: "several licences, one per component"},
	{marker: "their own license", why: "several licences, one per component"},
	{marker: "their own licence", why: "several licences, one per component"},
	{marker: "subject to the following licenses", why: "an explicit second licence set"},
	{marker: "the following licenses apply", why: "an explicit second licence set"},
	{marker: "the following licences apply", why: "an explicit second licence set"},
	{marker: "dual licensed", why: "two licences govern this material"},
	{marker: "dual-licensed", why: "two licences govern this material"},
	{marker: "licensed under either", why: "two licences govern this material"},
	{marker: "at your option, either", why: "two licences govern this material"},

	// Reciprocity imposed without naming the licence.
	{marker: "only under the terms of this license", why: "a reciprocal duty (CDDL-1.0 §3.1 shape)"},
	{marker: "only under this license", why: "a reciprocal duty (MS-PL §3(D) shape)"},
	{marker: "must also be made available in source code form", why: "a reciprocal duty (CDDL-1.0 §3.1 shape)"},
	{marker: "made available under this agreement", why: "a reciprocal duty (EPL-2.0 §3.2 shape)"},
	{marker: "available under this agreement, in source code form", why: "a reciprocal duty (EPL-2.0 §3.2 shape)"},
	{marker: "shall be licensed under this", why: "a reciprocal duty (OSL-3.0 §1(c) shape)"},
	{marker: "must be licensed under this", why: "a reciprocal duty"},
	{marker: "you must license the whole", why: "a reciprocal duty"},
}

// otherLicenceContent reports every piece of licence-like content in an already
// normalised document that is NOT part of the licence it has been identified
// as. An empty result is half (b) of identity holding.
//
// THREE DETECTORS RUN, AND THE MARKER TABLE IS ONE OF THEM. classifierRules is
// consulted here as a VETO — any rule at share-alike or restricted strength
// that fires is a reciprocity or restriction wording in a document claiming to
// be permissive — which is a different use from the classification it does in
// Classify. It is listed first because it is the detector with the most
// wordings behind it.
func otherLicenceContent(n string, identified permissiveLicence) []string {
	if n == "" {
		return nil
	}
	var reasons []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			reasons = append(reasons, s)
		}
	}

	// 1. The marker table, as a veto. Only the two classes that can never be
	// part of a permissive licence: a NOTICE-class marker firing is exactly
	// what a permissive licence looks like and vetoing on it would refuse
	// everything.
	for _, r := range classifierRules {
		if r.ob != ObligationShareAlike && r.ob != ObligationRestricted {
			continue
		}
		if containsNormalised(n, r.marker) {
			what := r.spdx
			if what == "" {
				what = r.ob.String() + " wording"
			}
			add(fmt.Sprintf("%s content (%q)", what, r.marker))
		}
	}

	// 2. Other licences by name.
	for _, m := range licenceNameMarkers {
		if m.family != "" && m.family == identified.family {
			continue // the identified licence naming itself
		}
		if containsNormalised(n, m.marker) {
			add(fmt.Sprintf("the name of another licence (%q)", m.marker))
		}
	}

	// 3. A second set of terms, scoped or reciprocal, that names no licence.
	for _, m := range secondTermsMarkers {
		if containsNormalised(n, m.marker) {
			add(fmt.Sprintf("%s (%q)", m.why, m.marker))
		}
	}

	return reasons
}
