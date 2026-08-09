# Tier 1 — mirrored, attribution required, keep a NOTICE file

This directory holds Anvil's mirror of the Tier 1 advisory feeds enumerated in
`research/01-vuln-data-sources-and-licensing.md` ("The concrete stack I'd
build"). Tier 1 differs from Tier 0 in exactly one respect: these sources
require attribution, so redistributing them obliges Anvil to carry a NOTICE
entry naming each publisher. Neither tier carries a share-alike duty, which is
what makes both of them publishable in a merged artifact.

**Every publisher named in a block below must appear in the repository's
top-level `NOTICE`.** Attribution is the whole of the Tier 1 obligation, so an
un-attributed Tier 1 source is an unlicensed one.

## What this file is, and why the gate reads it

**This file is Anvil's RECORD, not the publisher's evidence** — identical in
kind to `mirror/tier0/LICENSE-NOTES.md`, and its longer explanation applies
here unchanged. Every block below was written by Anvil in the same commit as
the feed row it describes, so no block below can admit a feed.

`plan/00-SPINE.md` S8's "LICENSE file bodies, never API metadata" means the
PUBLISHER'S body. `internal/ingest/license` reads the pin in
`mirror/LICENSE-MANIFEST.toml`, the acquired publisher text at
`mirror/tier1/<feed>/LICENSE.full.txt`, and this record — and refuses the feed
unless all three agree. The acquired text is not in git, so **no feed in this
tier is admitted by a fresh clone** until an operator runs
`sh mirror/acquire-license-bodies.sh`, reads what arrives, and pins its digest.
See `mirror/README.md`.

**This tier is publishable, so a body must EARN it.** Tier 1 is admitted only
for a licence text positively identified as one of the permissive licences
enumerated in `internal/ingest/license/publishable.go` — for every feed below,
CC-BY-4.0. A text that is merely "not obviously copyleft" does not qualify:
unrecognised is refused, exactly like share-alike is. See `mirror/README.md`,
"Unknown is not publishable", for why that default was inverted.

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

Within that, the gate still takes the **strongest** obligation any marker
establishes, not the first one it finds, and it takes that maximum across the
publisher's text and this record together. That is what catches the failure mode
this project has already seen in the wild: a permissive identifier sitting at the
top of an artifact whose actual content carries a stronger duty. A feed whose
evidence carries a reciprocity term Anvil recognises is classified as Tier 2
material and refused a Tier 1 route however it is labelled — and one carrying a
reciprocity term Anvil does **not** recognise is refused too, for not being
identifiable, which is the case the recognition list can never be trusted to
cover on its own.

## Editing rules

Identical to `mirror/tier0/LICENSE-NOTES.md`: one delimited block per feed,
identifier and publisher's operative sentence only inside it, Anvil's own policy
prose outside it, and a quotation rather than a paraphrase.

---

## GitHub Security Advisories — `ghsa`

<!-- anvil-license-body: ghsa -->
SPDX-License-Identifier: CC-BY-4.0

Quoted from the `github/advisory-database` repository: "This project is
licensed under the terms of the CC-BY 4.0 open source license."

Redistribution requires credit to GitHub, Inc. as the source of the advisory
data, a link to the licence, and an indication of any changes made.
<!-- end anvil-license-body: ghsa -->

Source: `research/06-ingestion-and-scraping.md` S15;
`research/01-vuln-data-sources-and-licensing.md` S11/S12.
NOTICE entry: GitHub Security Advisory Database, GitHub, Inc.

---

## Red Hat CSAF/VEX — `redhat-csaf`

<!-- anvil-license-body: redhat-csaf -->
SPDX-License-Identifier: CC-BY-4.0

Quoted from Red Hat's own statement on the security data feeds: "Licensed
under the Creative Commons Attribution 4.0 International License. If you
distribute this content or a modified version of it, you must provide
attribution to Red Hat, Inc."
<!-- end anvil-license-body: redhat-csaf -->

Source: `research/01-vuln-data-sources-and-licensing.md` S25.
NOTICE entry: Red Hat CSAF/VEX security data, Red Hat, Inc.

Red Hat's OVAL v2 feed is deprecated and is deliberately not mirrored: since
2024-07-10 Red Hat publishes CSAF for every RHSA and VEX for every CVE
touching the portfolio.

---

## OSV — PyPI ecosystem — `osv-pypi`

OSV licences are **per source database, never unified across the aggregate**.
The PyPI database is CC-BY-4.0 and belongs here; the merged `all.zip` inherits
a stronger duty through its bundled Ubuntu source and is quarantined under
`mirror/tier2/osv/` instead. Tag every ecosystem row separately — that
separation is the entire reason the per-ecosystem rows exist.

<!-- anvil-license-body: osv-pypi -->
SPDX-License-Identifier: CC-BY-4.0

The OSV source table records the PyPI advisory database as Creative Commons
Attribution 4.0. Redistribution requires credit to the database's publisher, a
link to the licence, and an indication of any changes made.
<!-- end anvil-license-body: osv-pypi -->

Source: `research/06-ingestion-and-scraping.md` S14;
`research/01-vuln-data-sources-and-licensing.md` S7/S8.
NOTICE entry: OSV PyPI advisory database, Open Source Vulnerabilities project.
