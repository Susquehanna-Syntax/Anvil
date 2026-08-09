# Tier 0 — always mirrored, licence-clean, no copyleft

This directory holds Anvil's mirror of the Tier 0 advisory feeds enumerated in
`research/01-vuln-data-sources-and-licensing.md` ("The concrete stack I'd
build"). Tier 0 is the set whose terms impose no copyleft and no share-alike
duty on anything Anvil publishes: attribution and notice duties are fine here —
CVE-TOU sits at Tier 0 and requires attribution — but a duty that would attach
to Anvil's own findings database does not.

## What this file is, and why the gate reads it

**This file is Anvil's RECORD, not the publisher's evidence.** The distinction
is the whole of A.6's central finding and it is worth being blunt about: every
block below was written by Anvil, in the same commit as the feed row it
describes. A document Anvil wrote is not evidence of a licence, and a gate that
admitted feeds on one would be validating a claim against a document authored
by the same commit. That is circular, and it is worse than reading API metadata
because it looks rigorous.

`plan/00-SPINE.md` S8 requires a licence gate that reads **LICENSE file bodies,
never API metadata**, with a manual-override field carrying the quoted operative
sentence. The body S8 means is the PUBLISHER'S. `internal/ingest/license` (step
A.4) therefore reads three things and refuses unless all three agree:

- `mirror/LICENSE-MANIFEST.toml` — the pin: per feed, the canonical URL of the
  publisher's licence text, the sha256 it must have, and the SPDX id it is
  claimed to be;
- `mirror/tier0/<feed>/LICENSE.full.txt` — the evidence: that publisher text,
  acquired deliberately by an operator and verified against the pin. It is not
  in git;
- this file — the record: provenance, the S8 manual override, the reasoning.

**No feed in this tier is admitted by a fresh clone**, because the second item
is absent until someone runs `sh mirror/acquire-license-bodies.sh`, reads what
arrives, and records its digest. That is deliberate. See `mirror/README.md`.

What a block below CAN do is make the gate stricter: the obligation a decision
rests on is the maximum of what the publisher's text establishes and what the
block establishes. It can raise a feed into the share-alike quarantine. It can
never lower an obligation and it can never supply one on its own.

**Tier 0 is publishable, so a body must EARN it.** The acquired publisher text
has to be positively identified as one of the permissive licences enumerated in
`internal/ingest/license/publishable.go` — for the feeds below that means CC0-1.0
(vulnrichment, KEV), the CVE Program Terms of Use (`cvelistv5`), MITRE's CWE
Terms of Use (`cwe`), and United States Government public-domain status (`nvd`).
A text that is merely "not obviously copyleft" does not qualify: unrecognised is
refused, exactly like share-alike is. See `mirror/README.md`, "Unknown is not
publishable".

**"Positively identified" is weaker than it sounds, and how much weaker is
written down.** It means the acquired text matched a substring signature and
tripped none of three tables of strings. It does not establish that the document
IS that licence, or that it carries no second set of terms. Eight working ways
past that check — an abbreviated name (*"the GPL"*), a British spelling
(*"Licence"*), the family exemption over-firing, dual-licence wording, a
commentary carrying a licence title, a licence quoted in prose, a denial more
than 96 bytes from the grant, and character splitting — are recorded, each with a
body that publishes today, in the *KNOWN LIMITS* section at the top of
`internal/ingest/license/known_limits_test.go`. That list is not a census. **The
operator reads every acquired licence text**; the gate is a second pair of eyes.

Three of those four are pinned to **HTML pages** in
`mirror/LICENSE-MANIFEST.toml`, and the phrases that identify them were drawn
from the sentences `research/01` quotes rather than from a fetched document. If
an acquired page does not match, the feed is refused and the test that names the
file is `TestPinnedLicenceBodiesMatchTheirPins`. The response to that refusal is
to read the acquired text and record its operative wording in `publishable.go` —
not to widen a signature until something passes.

Registry and forge metadata is **not** evidence either. Seven artifacts in the
corpus report `NOASSERTION` over a real licence and one reports a permissive tag
over restrictive content, so the gate never asks an API what a licence is. The
CISA KEV block below is the worked example: the GitHub API reports `NOASSERTION`
for `cisagov/kev-data`, and the repository's own README says CC0. Because the
metadata disagrees with the feed table's declaration the row must carry the
operative sentence in `license_manual_note`.

## Editing rules

- One `<!-- anvil-license-body: <feed-id> -->` … `<!-- end anvil-license-body:
  <feed-id> -->` block per feed. Exactly one of each marker per feed; the gate
  refuses a duplicated or unterminated block rather than guessing.
- Inside a block, write only the identifier that applies and the publisher's
  operative sentence. Anvil's own policy prose belongs outside the blocks,
  because the gate classifies the block text and nothing else — and because a
  block that mentions a term it is explaining will be classified as carrying it.
- Quote the publisher's own sentence. A paraphrase is an assertion; a quotation
  is at least a citation. Neither is the evidence: the evidence is
  `LICENSE.full.txt`, and every block below names where that text comes from
  through its entry in `mirror/LICENSE-MANIFEST.toml`.

---

## CVE List V5 — `cvelistv5`

<!-- anvil-license-body: cvelistv5 -->
SPDX-License-Identifier: CVE-TOU

CVE Program Terms of Use. The SPDX-published grant for `cve-tou` permits
users to "reproduce, publish and prepare derivative works" of CVE Records.

Attribution required: credit the CVE Program as the source of every CVE
Record redistributed from this mirror.

Anvil's applied reading, recorded because the corpus found the published
grant and the CVE Program FAQ in tension (research/01 Risk #2): store CVE
Records byte-verbatim, keep every Anvil-derived field in a sidecar, and never
publish an edited record under CVE branding.
<!-- end anvil-license-body: cvelistv5 -->

Source: `research/01-vuln-data-sources-and-licensing.md` S1/S2/S13/S45.

---

## CISA Vulnrichment — `cisa-vulnrichment`

<!-- anvil-license-body: cisa-vulnrichment -->
SPDX-License-Identifier: CC0-1.0

CC0 1.0 Universal. The publisher has dedicated this data to the public
domain, waiving copyright and related rights worldwide to the extent allowed
by law.

CC0 imposes no conditions on reuse, redistribution or modification.
<!-- end anvil-license-body: cisa-vulnrichment -->

Source: `research/01-vuln-data-sources-and-licensing.md` S14/S15. Vulnrichment
arrives inside the CVE record's ADP container rather than as a separate fetch,
but its licence differs from its carrier's, so it is gated on its own account.

---

## CISA KEV — `cisa-kev`

**This is spine S8's worked example.** The GitHub API reports `NOASSERTION`
for `cisagov/kev-data`. A gate that trusted that metadata would reject a
public-domain feed. The body below is what the gate reads instead.

<!-- anvil-license-body: cisa-kev -->
SPDX-License-Identifier: CC0-1.0

Quoted from the `cisagov/kev-data` README: "This data repository is licensed
under the CC0 license, which allows for universal public domain use of the
information here."

Registry metadata for the same repository reports no identifier. That
metadata is recorded and disregarded; this sentence is the operative grant.
<!-- end anvil-license-body: cisa-kev -->

Source: `research/06-ingestion-and-scraping.md` S16;
`research/01-vuln-data-sources-and-licensing.md` S16/S17.

---

## CWE 4.20 — `cwe`

<!-- anvil-license-body: cwe -->
SPDX-License-Identifier: LicenseRef-MITRE-CWE-ToU

MITRE CWE Terms of Use. Use and redistribution of the CWE List is permitted,
including for commercial purposes, with attribution required: identify CWE as
the source and reproduce MITRE's copyright notice with any redistributed
material.

No SPDX list identifier exists for these terms, which is why the feed row
declares a LicenseRef- custom identifier and carries the operative sentence
as its manual note.

STALE-RISK, recorded rather than resolved: the terms document the corpus read
is dated 2023-07-20. Re-verify before a 1.0 release.
<!-- end anvil-license-body: cwe -->

Source: `research/01-vuln-data-sources-and-licensing.md` S20/S21.

---

## NVD CVE API 2.0 — `nvd`

Shipped disabled in `feeds.example.yaml` and supplementary in any case: since
2026-04-15 NIST enriches only KEV, federal-use and EO-14028-critical CVEs.
The block exists so that an operator who switches it on is gated like every
other feed.

<!-- anvil-license-body: nvd -->
SPDX-License-Identifier: LicenseRef-US-Gov-Public-Domain

Quoted from the NVD General FAQs: "All NIST publications are available in the
public domain."

Two further terms from the same page, recorded because the earlier version of
this block omitted both: NIST requests the notice "This product uses data from
the NVD API but is not endorsed or certified by the NVD", and the NVD name may
not be used to imply endorsement.

No SPDX list identifier expresses that status, so the feed row declares a
LicenseRef- custom identifier and carries this statement as its manual note.
<!-- end anvil-license-body: nvd -->

Source: `research/01-vuln-data-sources-and-licensing.md` **S5** (NVD General
FAQs, https://nvd.nist.gov/general/FAQ-Sections/General-FAQs);
`plan/20-lane-a-ingestion-sca.md` Feed Table.

CITATION CORRECTED. This block previously cited `research/01` **S6**. S6 is
NIST's April 2026 announcement about record CVE growth and enrichment
prioritisation; it says nothing whatever about licensing, and the "United
States Government work" wording it was attached to appears nowhere in it. A
wrong citation is worse than no citation, because the next reviewer follows it,
finds the claim unsupported, and cannot tell whether the claim or the pointer
is the error. The licence statement is S5.
