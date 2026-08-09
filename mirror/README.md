# `mirror/` — the licence-segregated feed mirror, and the evidence the gate reads

This directory is two things at once, and keeping them apart is the whole point:

| | what it is | who wrote it | in git? | can it admit a feed? |
|---|---|---|---|---|
| `LICENSE-MANIFEST.toml` | the **pin** — per feed: canonical licence URL, expected sha256, claimed SPDX id | Anvil | yes | no, but nothing is admitted without it |
| `tier<N>/<dir>/LICENSE.full.txt` | the **evidence** — the publisher's own verbatim licence text | the publisher | **no** | yes |
| `tier<N>/LICENSE-NOTES.md`, `tier2/<dir>/LICENSE` | Anvil's **record** — provenance, the S8 manual override, the quoted operative sentence | Anvil | yes | **no** |

## A fresh clone admits no feed at all. That is deliberate.

Clone Anvil, run `internal/ingest/license`, and every feed is refused with
`ErrUnpinnedLicenseBody`. Nothing is broken.

`plan/00-SPINE.md` S8 requires a gate that reads "LICENSE file bodies, never API
metadata", and the reason for that rule is that **the body is the publisher's
evidence**. The first cut of this gate read only the files in the third row of
that table — Anvil prose, committed alongside the very feed rows it was
validating. A document Anvil wrote in the same commit as the claim is not
evidence of the claim. It is worse than reading API metadata, because it looks
rigorous: a reviewer sees a gate reading a file and stops asking who wrote it.

So the publisher's text is **not in this repository**. Only a pin of it is. Until
an operator deliberately acquires that text and records its digest there is no
evidence, and with no evidence there is no licence tier, and a feed with no
licence tier is refused. A gate that refuses every feed until real evidence
arrives is correct and shippable; a gate that admits feeds on evidence Anvil
wrote is not.

Every `sha256` in `LICENSE-MANIFEST.toml` is currently empty, because pinning a
digest requires downloading the text and no download has been performed.
Recording one from memory would be a fabrication.

## The acquisition step

Run it deliberately. It is not part of any build, test or CI job.

```sh
sh mirror/acquire-license-bodies.sh          # POSIX
pwsh -File mirror/acquire-license-bodies.ps1 # Windows
```

The script:

1. reads `LICENSE-MANIFEST.toml` and nothing else — no "latest", no version
   resolution, no URL derived from anything but the pin;
2. fetches each `text_url` to `tier<N>/<dir>/LICENSE.full.txt`;
3. computes the sha256 of what arrived;
4. if the entry is **pinned**, compares: a mismatch deletes the download, exits
   non-zero, and is never retried;
5. if the entry is **unpinned**, prints the digest and tells you to review the
   text before recording it.

Then, for each feed:

- **read the text you just fetched.** This is the step the whole design exists
  to force. You are certifying that this document is the operative licence for
  this feed, and no automation can do that for you;
- paste the printed digest into that entry's `sha256`;
- re-run the script — it now verifies instead of reporting — and re-run
  `go test ./internal/ingest/license/`.

`go test` reports what is missing before it fails. The mirror-integration tests
**skip with an explicit reason naming the artefact and the command that fixes
it**; they never pass quietly on absent evidence.

## Unknown is not publishable

Tiers 0 and 1 are the **publishable** tiers: what lands there may be merged into
an artifact Anvil ships. A feed reaches one **only** if the publisher's licence
text **is** one of a small, enumerated set of permissive licences — CC0,
CC-BY-4.0, MIT, Apache-2.0, BSD, ISC, and the specific public-domain and
terms-of-use cases this feed table needs. The list is
`internal/ingest/license/publishable.go`, and adding to it is a licence decision
taken deliberately on the evidence of a text.

**Is**, not *contains*. Two things have to hold:

1. the text is positively identified as **exactly one** enumerated licence, by a
   signature that is a contiguous phrase (or a small set of phrases inside a
   bounded window) and that is not sitting inside a sentence denying it; and
2. **nothing else licence-like appears anywhere in the text** — no other
   licence name, no reciprocity wording, no restriction wording, and no terms
   scoped to part of the material.

Everything else is refused: share-alike, restricted, **unrecognised**,
ambiguous, empty.

That default is inverted from the first two revisions of this gate, and the
inversion is the correction. Those revisions asked *"is this share-alike?"* and
published when the answer was no, which made a table of copyleft substrings the
only thing between a reciprocal licence and publication. Two rounds of review
defeated that table — the first with wording it did not list, the second with
OSL-3.0's real operative sentence and then with plain **formatting**: a hard line
wrap, a non-breaking space, a doubled space, a full-width character. All four are
what real licence files and real HTML pages look like.

Rule 2 is the **third** correction, and it is the one an operator is most likely
to meet. The revision that only asked rule 1 published a LICENSE file reading
*"this tree is MIT; the vendored subtree under `third_party/` is CDDL-1.0"* —
it contains exactly one licence Anvil may publish, because the CDDL is invisible
to a list of licences Anvil may publish, so it was identified as MIT and shipped
with the reciprocal terms attached. Rule 2's detector is
`internal/ingest/license/identity.go`; what it still cannot see is written down
there, under *KNOWN LIMITS OF THE VETO*, and at package scope — with a body that
publishes today for every vector — in `known_limits_test.go`.

**Rule 2 does not establish that nothing else licence-like is in the text.** An
earlier version of this document and four revisions of the tier-2 `LICENSE`
files said it did. It is a veto built from three tables of strings, it catches
what those tables list, and an abbreviated or British-spelled licence name is not
in them.

Three consequences an operator will actually meet:

- **A permissive feed can be refused.** If the acquired text does not match a
  signature, the gate says so and names the file. The fix is to read the text and
  record its operative wording in `publishable.go` — never to loosen a signature
  until something passes. Three of the pinned `text_url`s are HTML pages nobody
  has fetched, so this is the likeliest first failure after acquisition.
- **A permissive feed can be refused for naming a second licence.** Rule 2 is a
  veto, and a web page carries navigation and boilerplate a plain licence file
  does not. The same three HTML pins are where this will show up. The fix is to
  re-pin a plain operative text — never to delete a veto marker until a page
  passes, because a veto weakened to admit one page is weakened for every feed.
- **A refusal is never tier 0.** `Gate` and `Resolve` both return `NoTier` (-1),
  which is not a valid tier, so a caller who ignores the error cannot read the
  most permissive tier in the system out of a refusal.

Matching itself happens once, against normalised text: whitespace runs (newlines
and NBSP included) collapsed to one space, compatibility forms folded, case
folded, and every member of a shared **invisible class** dropped. That class has
one owner, `internal/ingest/invisible`, shared with the ingest sanitizer, which
was solving the same problem from its own side with its own list until both were
defeated by characters outside whichever list they held.

This paragraph used to say *"every code point that renders as nothing"* dropped.
**That was false and it is deleted rather than softened.** Nobody can enumerate
that set offline: the class is `Cf`, the TAG block, the zero-width and bidi
block, `Variation_Selector`, the whole of `Other_Default_Ignorable_Code_Point`
and a declared eight-member supplement of blank glyphs that carry no property
saying so — and a combining mark, an unassigned or private-use code point, and an
HTML tag all still split a licence marker. What the normalisation does **not** do
is recorded in `internal/ingest/license/normalise.go`; what the gate as a whole
cannot see is recorded, with a body that publishes today for each vector, in the
*KNOWN LIMITS* section at the top of
`internal/ingest/license/known_limits_test.go`.

**Read that section before you acquire anything.** The short form: the refusal
path is trustworthy and the admission path is not. Eight working ways past the
identity check are recorded there — an abbreviated licence name (*"the GPL"*), a
British spelling (*"Licence"*), the family exemption over-firing, dual-licence
wording, a commentary that merely carries a licence title, a licence quoted in
prose, a denial more than 96 bytes from the grant, and character splitting — and
that list is explicitly **not a census**. The real fix is a licence identifier
over a real corpus, not more substrings. Until then the operator reads every
acquired licence text.

## What Anvil's own prose is allowed to do

Exactly one thing: make the gate **stricter**.

The obligation a decision rests on is the maximum of what the publisher's
verbatim text establishes and what Anvil's record establishes. So a record that
says "this inherits CC-BY-SA-4.0 through the bundled Ubuntu database" can raise
the OSV aggregate from notice to share-alike and force it into quarantine — but
no record can lower an obligation, and no record can supply one on its own. A
body Anvil wrote is never evidence that a feed may be mirrored; it is only ever
evidence that Anvil already knew of a duty.

## The tier layout

```
mirror/
  LICENSE-MANIFEST.toml      the pin
  tier0/LICENSE-NOTES.md     always mirrored, licence-clean, no copyleft
  tier1/LICENSE-NOTES.md     mirrored, attribution required, keep a NOTICE file
  tier2/<source>/LICENSE     SHARE-ALIKE QUARANTINE — own directory, own LICENSE
  tier3/LICENSE-NOTES.md     optional, opt-in at install — ABSENT until opted in
```

Tier 2 is a quarantine, and `internal/ingest/license` enforces the routing half
of it in code: `license.Gate` is the only code path that chooses an output
directory, and `license.CheckWritePath` refuses a write that would move tier 2
content under `mirror/tier0/` or `mirror/tier1/`. The other half of the
quarantine is the inversion above — tier 0/1 admits only what it positively
recognises, so a reciprocal licence nobody enumerated stays out of the published
set whether or not the share-alike markers happen to catch it.

Each tier-2 `LICENSE` file separates what the code enforces from what it does
not, and names the test for each enforced claim. That separation is on its
**fifth** revision, and the first four were all overstatements — each time the
file claimed a control the code did not have, and each time the correction was
more careful wording rather than fewer claims. The fifth revision follows a
different rule: **a claim that cannot be demonstrated is deleted, not
qualified.** Its "not enforced" section is now longer than its "enforced" one. A
compliance document that overstates is a liability, because it tells the next
reader to stop checking. The obligation not to publish a merged corpus is
real, and it is an obligation **on the operator**, because no code in this
repository can observe a publication.

Tier 3 ships with no notes file. An operator who opts a tier-3 source in writes
its record at that point; until then the gate fails closed, which is why the
example feed table ships every tier-3 row disabled.

## EPSS is deliberately unpinnable

`epss` has no entry in the manifest and must not be given one. `research/01`
S18/S19 record no licence document and no SPDX identifier for it; "attribution is
requested" is a request, not a grant of rights. There is no publisher licence
text to pin, so the gate refuses the feed permanently. That refusal is the
correct answer for a source that has never licensed its data, and inventing an
entry to silence it would reintroduce exactly the defect this directory was
rebuilt to remove.
