package license

import (
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
)

// ---------------------------------------------------------------------------
// B1: IDENTITY, NOT CONTAINMENT — and both directions of it
// ---------------------------------------------------------------------------
//
// The two tests in this file are a matched pair and neither is meaningful
// alone. A veto that quarantines everything passes the first and fails the
// second; the gate that shipped before this round passes the second and fails
// the first. THE TENSION BETWEEN THEM IS THE ACTUAL DIFFICULTY OF B1, and it is
// concentrated in one sentence of real licence text — see ccBY40Legalcode.

// ccBY40Legalcode is a RECONSTRUCTION of creativecommons.org/licenses/by/4.0/
// legalcode.txt, which is the pinned text_url for redhat-csaf and osv-pypi and
// the substance of the LICENSE.md ghsa ships.
//
// IT IS A RECONSTRUCTION AND NOT THE PINNED BYTES, and that is stated here
// rather than left to be discovered. mirror/LICENSE-MANIFEST.toml records
// sha256 = "" for every entry: no licence body has been acquired, this
// repository makes no network calls, and a fixture cannot be the evidence. What
// this fixture is for is the SHAPE — specifically the two features of the real
// document that decide whether the three CC-BY-4.0 feeds can ever publish:
//
//  1. THE FOOTER NAMES A SECOND LICENCE. "The text of the Creative Commons
//     public licenses is dedicated to the public domain under the CC0 Public
//     Domain Dedication." A veto keyed on the token "cc0" reads that as a
//     bundled second licence and quarantines ghsa, redhat-csaf and osv-pypi.
//     It is not one: it is a statement by Creative Commons about the copyright
//     status of its own prose, and it places none of the licensed material
//     under CC0.
//
//  2. THE PREAMBLE AND SECTION 2(b) BOTH SAY "not licensed under". A negation
//     rule that scanned the whole document, or one that gave up on the first
//     negated occurrence of a phrase, would refuse to identify the licence
//     inside its own legalcode.
//
// When the operator acquires the real bytes, the gate reads THOSE. If they trip
// something here, the feed is refused and the answer is to read the acquired
// text — never to weaken a marker until it passes.
const ccBY40Legalcode = `Attribution 4.0 International

=======================================================================

Creative Commons Corporation ("Creative Commons") is not an authorized
legal services organization and does not provide legal services or legal
advice. Distribution of Creative Commons public licenses does not create
a lawyer-client or other relationship. Creative Commons makes its
licenses and related information available on an "as-is" basis. Creative
Commons gives no warranties regarding its licenses, any material
licensed under their terms and conditions, or any related information.
Creative Commons disclaims all liability for damages resulting from
their use to the fullest extent possible.

Using Creative Commons Public Licenses

Creative Commons public licenses provide a standard set of terms and
conditions that creators and other rights holders may use to share
original works of authorship and other material subject to copyright
and certain other rights specified in the public license below.

     Considerations for licensors: Our public licenses are intended for
     use by those authorized to give the public permission to use
     material in ways otherwise restricted by copyright and certain
     other rights. Licensors should also clearly mark any material not
     subject to the license.

     Considerations for the public: By using one of our public licenses,
     a licensor grants the public permission to use the licensed
     material under specified terms and conditions. Our licenses grant
     only permissions under copyright and certain other rights that a
     licensor has authority to grant.

=======================================================================

Creative Commons Attribution 4.0 International Public License

By exercising the Licensed Rights (defined below), You accept and agree
to be bound by the terms and conditions of this Creative Commons
Attribution 4.0 International Public License ("Public License"). To the
extent this Public License may be interpreted as a contract, You are
granted the Licensed Rights in consideration of Your acceptance of these
terms and conditions.

Section 1 -- Definitions.

  a. Adapted Material means material subject to Copyright and Similar
     Rights that is derived from or based upon the Licensed Material.

  b. Adapter's License means the license You apply to Your Copyright and
     Similar Rights in Your contributions to Adapted Material.

Section 2 -- Scope.

  a. License grant.

       1. Subject to the terms and conditions of this Public License,
          the Licensor hereby grants You a worldwide, royalty-free,
          non-sublicensable, non-exclusive, irrevocable license to
          exercise the Licensed Rights in the Licensed Material to
          reproduce and Share the Licensed Material, in whole or in
          part, and to produce, reproduce, and Share Adapted Material.

       5. Downstream recipients.

            a. Offer from the Licensor -- Licensed Material. Every
               recipient of the Licensed Material automatically
               receives an offer from the Licensor to exercise the
               Licensed Rights under the terms and conditions of this
               Public License.

            b. Additional offer from the Licensor -- Adapted Material.
               Every recipient of Adapted Material from You
               automatically receives an offer from the Licensor to
               exercise the Licensed Rights in the Adapted Material
               under the conditions of the Adapter's License You apply.

            c. No downstream restrictions. You may not offer or impose
               any additional or different terms or conditions on, or
               apply any Effective Technological Measures to, the
               Licensed Material if doing so restricts exercise of the
               Licensed Rights by any recipient of the Licensed
               Material.

  b. Other rights.

       1. Moral rights, such as the right of integrity, are not
          licensed under this Public License, nor are publicity,
          privacy, and/or other similar personality rights.

       2. Patent and trademark rights are not licensed under this
          Public License.

Section 3 -- License Conditions.

  a. Attribution.

       1. If You Share the Licensed Material, You must retain
          identification of the creator, a copyright notice, a notice
          that refers to this Public License, a notice that refers to
          the disclaimer of warranties, and a URI or hyperlink to the
          Licensed Material; and indicate if You modified the Licensed
          Material and retain an indication of any previous
          modifications.

Section 4 -- Sui Generis Database Rights.

Section 5 -- Disclaimer of Warranties and Limitation of Liability.

Section 6 -- Term and Termination.

Section 7 -- Other Terms and Conditions.

Section 8 -- Interpretation.

=======================================================================

Creative Commons is not a party to its public licenses. Notwithstanding,
Creative Commons may elect to apply one of its public licenses to
material it publishes and in those instances will be considered the
"Licensor." The text of the Creative Commons public licenses is
dedicated to the public domain under the CC0 Public Domain Dedication.
Except for the limited purpose of indicating that material is shared
under a Creative Commons public license or as otherwise permitted by the
Creative Commons policies published at creativecommons.org/policies,
Creative Commons does not authorize the use of the trademark "Creative
Commons" or any other trademark or logo of Creative Commons without its
prior written consent.

Creative Commons may be contacted at creativecommons.org.`

// TestAPermissiveBodyThatMerelyNamesAnotherLicenceStillPublishes is the half of
// B1 that a too-eager veto fails, and it is not optional: a gate that
// quarantines everything is as useless as one that publishes everything, and
// three of the eleven pinned feeds carry the text below.
//
// It asserts the whole chain — identification, obligation, and admission
// through the real gate at the declared tier — for ghsa, redhat-csaf and
// osv-pypi, and then names the exact sentence that makes it hard.
//
// MEASURED against a veto that lists the bare token "cc0": all three feeds are
// refused with ErrNotProvablyPublishable naming the CC0 Public Domain
// Dedication, and the CC-BY-4.0 half of Lane A's feed set stops working.
func TestAPermissiveBodyThatMerelyNamesAnotherLicenceStillPublishes(t *testing.T) {
	n := NormaliseForMatching(ccBY40Legalcode)

	// The fixture has to actually contain the hard sentence, or the test is
	// about something easier than the real document.
	if !strings.Contains(n, "cc0 public domain dedication") {
		t.Fatal("fixture error: the reconstruction has lost the Creative Commons trademark " +
			"footer, which is the sentence that names a second licence and the only reason " +
			"this test is difficult")
	}
	if !strings.Contains(n, "are not licensed under this public license") {
		t.Fatal("fixture error: the reconstruction has lost Section 2(b)'s \"not licensed " +
			"under\" sentences, which are what a whole-document negation rule trips on")
	}

	matches := permissiveMatches(n)
	if len(matches) != 1 {
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.name)
		}
		t.Fatalf("permissiveMatches found %d licences (%s), want 1; the CC0 signatures must not "+
			"fire on the Creative Commons trademark footer", len(matches), strings.Join(names, ", "))
	}
	if reasons := otherLicenceContent(n, matches[0]); len(reasons) > 0 {
		t.Fatalf("the veto fired on the CC-BY-4.0 legalcode itself: %s. That quarantines ghsa, "+
			"redhat-csaf and osv-pypi — the whole CC-BY-4.0 half of the feed set",
			strings.Join(reasons, "; "))
	}

	spdx, name, ob, ok := IdentifyPermissive(ccBY40Legalcode)
	if !ok {
		t.Fatal("IdentifyPermissive did not recognise the CC-BY-4.0 legalcode")
	}
	if spdx != "CC-BY-4.0" || ob != ObligationNotice {
		t.Errorf("IdentifyPermissive = %q/%v (%s), want CC-BY-4.0/notice", spdx, ob, name)
	}

	for _, feedID := range []string{"ghsa", "redhat-csaf", "osv-pypi"} {
		t.Run(feedID, func(t *testing.T) {
			info := LicenseInfo{
				FeedID:       feedID,
				DeclaredTier: config.LicenseTier1,
				DeclaredSPDX: "CC-BY-4.0",
				Mirror: buildMirror(t, feedFixture{
					feedID: feedID, tier: config.LicenseTier1, pinSPDX: "CC-BY-4.0",
					verbatim: ccBY40Legalcode,
					notes:    "Anvil record: CC-BY-4.0, attribution required, NOTICE entry kept.",
				}),
			}
			d, err := Resolve(info)
			if err != nil {
				t.Fatalf("the gate refused a real permissive feed: %v", err)
			}
			if d.Refused() || d.Tier != config.LicenseTier1 {
				t.Fatalf("decision does not admit at tier 1: %+v", d)
			}
			if d.EffectiveSPDX != "CC-BY-4.0" || !d.SPDXFromBody {
				t.Errorf("EffectiveSPDX = %q (from body %v), want CC-BY-4.0 read from the text",
					d.EffectiveSPDX, d.SPDXFromBody)
			}
		})
	}
}

// wrappedBodies are permissive licences with a SECOND set of terms wrapped
// around them: the vendored-subtree shape publishable.go's ambiguity refusal
// was written for and did not catch.
//
// NONE OF THE SECOND LICENCES IS IN permissiveLicences, which is the point: a
// set of things Anvil may publish cannot recognise the things it may not, so
// the containment test saw one licence and published. Each entry records what
// the pre-fix gate did with it.
var wrappedBodies = map[string]struct {
	body string
	// preFix is what the gate identified this body as before B1. It is
	// recorded so that a reader can see the test is measuring a real change.
	preFix string
}{
	"mit with a cddl-1.0 vendored subtree": {
		body: "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
			"obtaining a copy of this software, to deal in the Software without restriction.\n\n" +
			"The components under third_party/ are distributed under the COMMON DEVELOPMENT " +
			"AND DISTRIBUTION LICENSE (CDDL) Version 1.0.",
		preFix: "MIT",
	},
	"mit with an unnamed cddl reciprocity clause": {
		// The second licence NAMES ITSELF NOWHERE. It is caught by the
		// reciprocity wording rather than by a name, which is the case that
		// decides whether the veto is a name lookup or a proposition.
		body: "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
			"obtaining a copy of this software.\n\n" +
			"3.1. Availability of Source Code. Any Covered Software that You distribute or " +
			"otherwise make available in Executable form must also be made available in Source " +
			"Code form and that Source Code form must be distributed only under the terms of " +
			"this License.",
		preFix: "MIT",
	},
	"mit with an unnamed eclipse reciprocity clause": {
		body: "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
			"obtaining a copy of this software.\n\n" +
			"3.2 When the Program is Distributed in Source Code form: a) it must be made " +
			"available under this Agreement, in Source Code form; and b) a copy of this " +
			"Agreement must be included with each copy of the Program.",
		preFix: "MIT",
	},
	"mit with a microsoft public license section": {
		body: "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
			"obtaining a copy of this software.\n\n" +
			"Portions of this software are provided under the Microsoft Public License.",
		preFix: "MIT",
	},
	"mit with an open software license subtree": {
		body: "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
			"obtaining a copy of this software.\n\n" +
			"The vendored tooling is licensed under the Open Software License 3.0.",
		preFix: "MIT",
	},
	"isc with a bundled boost licence": {
		body: "ISC License\n\nPermission to use, copy, modify, and/or distribute this software " +
			"for any purpose with or without fee is hereby granted.\n\n" +
			"The bundled headers are under the Boost Software License 1.0.",
		preFix: "ISC",
	},
	"cc0 with an artistic-licensed script directory": {
		body: "CC0 1.0 Universal\n\nThe person who associated a work with this deed has " +
			"dedicated the work to the public domain by waiving all rights to the work " +
			"worldwide under copyright law.\n\n" +
			"The scripts under third_party/ remain under the Artistic License 2.0.",
		preFix: "CC0-1.0",
	},
	"bsd-3-clause with a cddl vendor tree": {
		body: "Redistribution and use in source and binary forms, with or without modification, " +
			"are permitted provided that the following conditions are met. Neither the name of " +
			"the copyright holder nor the names of its contributors may be used to endorse or " +
			"promote products derived from this software.\n\n" +
			"src/vendor is under the Common Development and Distribution License.",
		preFix: "BSD-3-Clause",
	},
}

// TestAPermissiveLicenceWrappedAroundASecondOneIsRefused is the half of B1 that
// the shipped gate failed, and it asserts the PROPOSITION rather than the
// instances: a document that contains a permissive licence AND anything else
// licence-like is not that licence, and does not publish.
//
// MEASURED with the veto disabled, which is the pre-fix behaviour of this
// check: all eight bodies below are positively identified as the licence named
// in preFix, and all eight are ADMITTED at tier 0 AND tier 1 by Gate. Not one
// of them is caught by the share-alike quarantine, the ambiguity branch or the
// identity check — every second licence here is either absent from
// classifierRules or, in the two "unnamed" cases, present in the document only
// as a clause that never says which licence it belongs to.
func TestAPermissiveLicenceWrappedAroundASecondOneIsRefused(t *testing.T) {
	for name, tc := range wrappedBodies {
		t.Run(name, func(t *testing.T) {
			n := NormaliseForMatching(tc.body)

			// The fixture must still CONTAIN exactly one enumerated permissive
			// licence, or it is testing the ambiguity branch instead and the
			// containment/identity distinction is not exercised at all.
			matches := permissiveMatches(n)
			if len(matches) != 1 {
				t.Fatalf("fixture error: permissiveMatches found %d enumerated licences, want "+
					"exactly 1; the second licence must be one this gate does NOT enumerate, "+
					"or this case is about ambiguity rather than about containment", len(matches))
			}
			if matches[0].spdx != tc.preFix {
				t.Fatalf("fixture error: contains %q, but the pre-fix behaviour was recorded "+
					"as %q", matches[0].spdx, tc.preFix)
			}

			if reasons := otherLicenceContent(n, matches[0]); len(reasons) == 0 {
				t.Fatal("the veto found no second set of terms in a document that carries one")
			}
			if _, _, _, ok := IdentifyPermissive(tc.body); ok {
				t.Fatal("IdentifyPermissive accepted a document that CONTAINS a permissive " +
					"licence rather than one that IS one")
			}

			for _, tier := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
				info := LicenseInfo{
					FeedID:       "wrapped",
					DeclaredTier: tier,
					DeclaredSPDX: config.LicenseNoAssertion,
					ManualNote:   "vendor ships one LICENSE file covering more than one licence",
					Mirror: buildMirror(t, feedFixture{
						feedID: "wrapped", tier: tier, pinSPDX: config.LicenseNoAssertion,
						verbatim: tc.body, notes: "Anvil record: vendor claims " + tc.preFix + ".",
					}),
				}
				d, err := Resolve(info)
				if err == nil {
					t.Fatalf("tier %d: ADMITTED a %s licence with a second set of terms wrapped "+
						"around it; those terms ship with the data and cannot be withdrawn: %+v",
						tier.Int(), tc.preFix, d)
				}
				if !d.Refused() || d.Tier.Valid() {
					t.Errorf("tier %d: the refusal carries the valid tier %d", tier.Int(), d.Tier.Int())
				}
				gotTier, dir, gateErr := Gate(info)
				if gateErr == nil || gotTier != NoTier || dir != "" {
					t.Errorf("tier %d: Gate returned (%d, %q, %v)", tier.Int(), gotTier, dir, gateErr)
				}
			}
		})
	}
}

// TestTheVetoIndexDoesNotFireOnItsOwnLicences is the guard that keeps the veto
// index from growing into a self-refusal.
//
// Every marker added to licenceNameMarkers or secondTermsMarkers is a string
// somebody believed no permissive licence contains, and the enumerated
// licences' own texts are where that belief is cheapest to check. A marker that
// fires here would quarantine the feed it was meant to protect — silently,
// because a refusal reads the same whatever caused it.
func TestTheVetoIndexDoesNotFireOnItsOwnLicences(t *testing.T) {
	own := map[string]string{
		"cc-by-4.0 legalcode": ccBY40Legalcode,
		"cc0 legalcode": "Creative Commons Legal Code\n\nCC0 1.0 Universal\n\n" +
			"Statement of Purpose\n\nThe laws of most jurisdictions throughout the world " +
			"automatically confer exclusive Copyright and Related Rights upon the creator of " +
			"an original work of authorship. To that end, Affirmer has waived all copyright " +
			"and related or neighboring rights to the Work.",
		"apache-2.0 header and grant": "Apache License\nVersion 2.0, January 2004\n" +
			"http://www.apache.org/licenses/\n\n2. Grant of Copyright License. Subject to the " +
			"terms and conditions of this License, each Contributor hereby grants to You a " +
			"perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable " +
			"copyright license to reproduce, prepare Derivative Works of, publicly display, " +
			"publicly perform, sublicense, and distribute the Work.\n\n" +
			"4. Redistribution. You may add Your own copyright statement to Your modifications " +
			"and may provide additional or different license terms and conditions for use, " +
			"reproduction, or distribution of Your Derivative Works.",
		"mit": "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
			"obtaining a copy of this software and associated documentation files (the " +
			"\"Software\"), to deal in the Software without restriction.",
		"bsd-3-clause": "Redistribution and use in source and binary forms, with or without " +
			"modification, are permitted provided that the following conditions are met. " +
			"Neither the name of the copyright holder nor the names of its contributors may be " +
			"used to endorse or promote products derived from this software without specific " +
			"prior written permission.",
		"isc": "ISC License\n\nPermission to use, copy, modify, and/or distribute this software " +
			"for any purpose with or without fee is hereby granted, provided that the above " +
			"copyright notice and this permission notice appear in all copies.",
		"cve programme terms of use": "CVE Program Terms of Use\n\nCVE Records may be " +
			"reproduced, published and used to prepare derivative works, provided that the CVE " +
			"Program is credited as the source. Attribution is required.",
		"nvd public domain faq": "NVD General FAQs\n\nAll NIST publications are available in " +
			"the public domain according to Title 17 of the United States Code. " +
			"Acknowledgement of the NVD as the source is requested.",
	}
	for name, body := range own {
		t.Run(name, func(t *testing.T) {
			n := NormaliseForMatching(body)
			matches := permissiveMatches(n)
			if len(matches) != 1 {
				t.Fatalf("this licence is identified as %d enumerated licences, want 1", len(matches))
			}
			if reasons := otherLicenceContent(n, matches[0]); len(reasons) > 0 {
				t.Fatalf("the veto fired on %s's own text: %s. A marker that a licence's own "+
					"text contains quarantines every feed under that licence",
					matches[0].name, strings.Join(reasons, "; "))
			}
		})
	}
}

// TestAnExplicitDenialIsNotAnIdentification is the second half of B2.
//
// A signature that matches a phrase inside "this is NOT under X" identifies the
// document as X. The ACME case is the one the reviewer supplied: a 12 KB file
// titled "ACME DATA LICENCE, Version 2.0" that says it is NOT distributed under
// the Apache License, and which the pre-fix gate identified as Apache-2.0 and
// admitted at tier 0 and tier 1 on the strength of {"apache license", "version
// 2.0"} appearing SOMEWHERE in it.
//
// The refusal that follows is the plain one — the document is not any
// enumerated licence — and that is the right answer: it is not Apache, and
// nobody has said what it is.
func TestAnExplicitDenialIsNotAnIdentification(t *testing.T) {
	cases := map[string]struct {
		body string
		// wouldMatch is the enumerated licence the body must NOT be identified
		// as. It is named so a failure says which signature leaked.
		wouldMatch string
	}{
		"acme data licence that denies apache": {
			body: "ACME DATA LICENCE, Version 2.0\n\n" +
				"This dataset is NOT distributed under the Apache License, Version 2.0. " +
				"You may use it only as described below, and attribution is required.\n\n" +
				strings.Repeat("Clause text that pads this document to the size of a real "+
					"licence file so that a document-wide conjunction has room to succeed. ", 120),
			wouldMatch: "Apache-2.0",
		},
		"a notice that the data is not mit": {
			body: "ACME DATA TERMS\n\nThis data is not licensed under the MIT License and no " +
				"permission is hereby granted, free of charge, to redistribute it.",
			wouldMatch: "MIT",
		},
		"a notice that the data is not cc-by-4.0": {
			body: "ACME DATA TERMS\n\nThe dataset is not covered by the Creative Commons " +
				"Attribution 4.0 International Public License; attribution is required under " +
				"these terms instead.",
			wouldMatch: "CC-BY-4.0",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			n := NormaliseForMatching(tc.body)
			for _, m := range permissiveMatches(n) {
				if m.spdx == tc.wouldMatch {
					t.Fatalf("the document says it is NOT under %s and the gate identified it "+
						"as %s anyway", tc.wouldMatch, m.spdx)
				}
			}
			if spdx, _, _, ok := IdentifyPermissive(tc.body); ok && spdx == tc.wouldMatch {
				t.Fatalf("IdentifyPermissive = %q on a document that denies it", spdx)
			}
			for _, tier := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
				_, _, err := Gate(LicenseInfo{
					FeedID:       "denies",
					DeclaredTier: tier,
					DeclaredSPDX: config.LicenseNoAssertion,
					ManualNote:   "the publisher states its own terms and denies the SPDX one",
					Mirror: buildMirror(t, feedFixture{
						feedID: "denies", tier: tier, pinSPDX: config.LicenseNoAssertion,
						verbatim: tc.body, notes: "Anvil record: bespoke publisher terms.",
					}),
				})
				if err == nil {
					t.Fatalf("tier %d: admitted a document whose only licence identification "+
						"came from a sentence denying it", tier.Int())
				}
			}
		})
	}
}

// TestASignatureIsAPhraseAndNotTwoWordsInAFile is the mechanism half of B2,
// asserted directly on the matcher so that a failure points at the signature
// shape rather than at a gate refusal three layers away.
//
// MEASURED: with signatures restored to the old "all terms present anywhere"
// form, every case below matches.
func TestASignatureIsAPhraseAndNotTwoWordsInAFile(t *testing.T) {
	filler := strings.Repeat("Ordinary prose about the dataset and its provenance. ", 200)

	cases := map[string]struct {
		text string
		spdx string
	}{
		"apache terms scattered across a file": {
			text: "ACME DATA LICENCE, Version 2.0\n" + filler +
				"Nothing in these terms is derived from the Apache License." + filler,
			spdx: "Apache-2.0",
		},
		"mit terms scattered across a file": {
			text: "The MIT License is discussed in our FAQ." + filler +
				"Permission is hereby granted to registered partners only." + filler,
			spdx: "MIT",
		},
		"cwe and mitre mentioned in different sections": {
			text: "Terms of Use for the ACME catalogue." + filler +
				"Our mappings reference CWE identifiers." + filler +
				"MITRE is not affiliated with ACME." + filler,
			spdx: "LicenseRef-MITRE-CWE-ToU",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			n := NormaliseForMatching(tc.text)
			for _, m := range permissiveMatches(n) {
				if m.spdx == tc.spdx {
					t.Fatalf("identified as %s from terms that appear in different parts of the "+
						"document; a signature must be a contiguous phrase or a bounded window, "+
						"not a conjunction over the whole file", tc.spdx)
				}
			}
		})
	}

	// The other direction: the real headers, where the terms ARE contiguous
	// once normalisation has collapsed the line break and the centring spaces,
	// must still match. A window rule that refused these would refuse
	// Apache-2.0 outright.
	apacheHeader := "                                 Apache License\n" +
		"                           Version 2.0, January 2004\n" +
		"                        http://www.apache.org/licenses/"
	found := false
	for _, m := range permissiveMatches(NormaliseForMatching(apacheHeader)) {
		if m.spdx == "Apache-2.0" {
			found = true
		}
	}
	if !found {
		t.Error("the real Apache-2.0 header is no longer identified; the phrase rule has been " +
			"tightened past the document it exists to match")
	}
}
