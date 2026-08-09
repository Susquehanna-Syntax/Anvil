package license

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
)

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

// feedFixture describes one feed's presence in a synthetic mirror: its pin, the
// publisher text that was "acquired" for it, and Anvil's own record.
//
// The three are separate fields because the whole point of the A.6 rework is
// that they are separate artefacts with different authors. A test that could
// not express "the record is perfect and the publisher text is absent" could
// not express the defect.
type feedFixture struct {
	feedID   string
	tier     config.LicenseTier
	dir      string // defaults to feedID
	pinSPDX  string // defaults to "NOASSERTION"
	verbatim string // the publisher's licence text
	notes    string // Anvil's record

	noPin      bool // omit the manifest entry entirely
	unpinned   bool // manifest entry with sha256 = ""
	corruptPin bool // manifest entry pinning the wrong digest
	noVerbatim bool // pin present, publisher text never acquired
	noNotes    bool // no Anvil record

	pinTier *config.LicenseTier // pin a different tier from the row's
	pinDir  string              // pin a different directory from the row's
}

func (f feedFixture) dirName() string {
	if f.dir != "" {
		return f.dir
	}
	return f.feedID
}

// buildMirror renders fixtures into an fstest.MapFS shaped exactly like the
// real mirror/ tree: one pinned manifest, one acquired publisher text per feed,
// and Anvil's per-tier or per-source record.
func buildMirror(t *testing.T, fx ...feedFixture) fs.FS {
	t.Helper()

	fsys := fstest.MapFS{}
	var man strings.Builder
	man.WriteString("# synthetic manifest, gate_test\n")
	man.WriteString("schema_version = 1\n")
	man.WriteString("generated_utc = \"2026-08-09\"\n")
	man.WriteString("generated_by = \"gate_test\"\n")

	notes := map[config.LicenseTier]*strings.Builder{}

	for _, f := range fx {
		dir := f.dirName()
		pinDir := dir
		if f.pinDir != "" {
			pinDir = f.pinDir
		}
		pinTier := f.tier
		if f.pinTier != nil {
			pinTier = *f.pinTier
		}
		spdx := f.pinSPDX
		if spdx == "" {
			spdx = config.LicenseNoAssertion
		}

		if !f.noPin {
			sha := ""
			switch {
			case f.unpinned:
				sha = ""
			case f.corruptPin:
				sha = strings.Repeat("a", 64)
			default:
				sha = digestOf(f.verbatim)
			}
			fmt.Fprintf(&man, "\n[[body]]\nfeed_id = %q\ntier = %d\ndir = %q\n"+
				"spdx_id = %q\ntext_url = \"https://example.invalid/LICENSE\"\n"+
				"sha256 = %q\nclaim_source = \"gate_test fixture\"\n",
				f.feedID, pinTier.Int(), pinDir, spdx, sha)
		}

		if !f.noVerbatim {
			p := path.Join(TierDir(pinTier), pinDir, VerbatimFileName)
			fsys[p] = &fstest.MapFile{Data: []byte(f.verbatim)}
		}

		if f.noNotes {
			continue
		}
		if f.tier == config.LicenseTier2 {
			p := path.Join(TierDir(f.tier), dir, LicenseFileName)
			fsys[p] = &fstest.MapFile{Data: []byte(f.notes)}
			continue
		}
		b, ok := notes[f.tier]
		if !ok {
			b = &strings.Builder{}
			b.WriteString("# fixture notes\n\nProse outside a block is never classified.\n")
			notes[f.tier] = b
		}
		fmt.Fprintf(b, "\n%s\n%s\n%s\n", BodyBeginMarker(f.feedID), f.notes, BodyEndMarker(f.feedID))
	}

	for tier, b := range notes {
		fsys[path.Join(TierDir(tier), NotesFileName)] = &fstest.MapFile{Data: []byte(b.String())}
	}
	fsys[ManifestFileName] = &fstest.MapFile{Data: []byte(man.String())}
	return fsys
}

// The CISA KEV evidence. The publisher text is the CC0 legalcode the README
// names; Anvil's record quotes the README sentence, which is the CLAIM.
const (
	kevVerbatim = `Creative Commons Legal Code

CC0 1.0 Universal

The person who associated a work with this deed has dedicated the work to the
public domain by waiving all rights to the work worldwide under copyright law.`

	kevNotes = `SPDX-License-Identifier: CC0-1.0

Quoted from the cisagov/kev-data README: "This data repository is licensed
under the CC0 license, which allows for universal public domain use of the
information here."`

	kevNote = `GitHub API metadata reports NOASSERTION; the repository README states: ` +
		`"This data repository is licensed under the CC0 license, which allows for ` +
		`universal public domain use of the information here."`
)

// shareAlikeVerbatim is a synthetic Tier 2 publisher text: share-alike, and it
// names itself.
const shareAlikeVerbatim = `Creative Commons Attribution-ShareAlike 4.0 International

Section 3 -- License Conditions.

b. ShareAlike. The Adapter's License You apply must be a Creative Commons
license with the same License Elements, this version or later.`

const shareAlikeNotes = `SPDX-License-Identifier: CC-BY-SA-4.0

Anvil's record: this source is share-alike and lives in the tier 2 quarantine.`

// requireRefused asserts that err is a refusal of the expected kind AND that it
// satisfies the umbrella sentinel. The umbrella check is not decoration: a
// caller that switches on ErrLicenseRefused must never see a refusal leak past
// it as an unrecognised error, because in a licence gate the fail-open bug is
// the silent one.
func requireRefused(t *testing.T, err error, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected refusal %v, got nil error (the gate admitted the feed)", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("expected refusal %v, got %v", want, err)
	}
	if !errors.Is(err, ErrLicenseRefused) {
		t.Fatalf("refusal %v does not satisfy ErrLicenseRefused: %v", want, err)
	}
}

// ---------------------------------------------------------------------------
// A.6's CENTRAL FINDING: Anvil's own prose is not evidence
// ---------------------------------------------------------------------------

// TestAnvilProseAloneCannotAdmitAnyFeed is the regression test for the finding
// that failed A.4: every body the gate read was Anvil prose, committed
// alongside the claim it was supposed to validate.
//
// Each case below carries a PERFECT Anvil record — the right identifier, the
// right operative sentence, at the right tier — and no publisher evidence. All
// three must be refused. Before the rework the first two were ADMITTED, which
// is exactly what "validating a claim against a document authored by the same
// commit" means in practice.
func TestAnvilProseAloneCannotAdmitAnyFeed(t *testing.T) {
	base := feedFixture{
		feedID:   "cisa-kev",
		tier:     config.LicenseTier0,
		pinSPDX:  "CC0-1.0",
		verbatim: kevVerbatim,
		notes:    kevNotes,
	}
	info := func(m fs.FS) LicenseInfo {
		return LicenseInfo{
			FeedID:       "cisa-kev",
			DeclaredTier: config.LicenseTier0,
			DeclaredSPDX: "CC0-1.0",
			Mirror:       m,
		}
	}

	t.Run("no pin at all", func(t *testing.T) {
		f := base
		f.noPin = true
		_, _, err := Gate(info(buildMirror(t, f)))
		requireRefused(t, err, ErrUnpinnedLicenseBody)
	})

	t.Run("pinned but no digest established", func(t *testing.T) {
		f := base
		f.unpinned = true
		_, _, err := Gate(info(buildMirror(t, f)))
		requireRefused(t, err, ErrUnpinnedLicenseBody)
		if !strings.Contains(err.Error(), "acquire-license-bodies") {
			t.Errorf("a fail-closed refusal must name the command that fixes it: %v", err)
		}
	})

	t.Run("pinned but never acquired", func(t *testing.T) {
		f := base
		f.noVerbatim = true
		_, _, err := Gate(info(buildMirror(t, f)))
		requireRefused(t, err, ErrNoLicenseBody)
		if !strings.Contains(err.Error(), "acquire-license-bodies") {
			t.Errorf("a fail-closed refusal must name the command that fixes it: %v", err)
		}
	})

	t.Run("acquired text does not match its pin", func(t *testing.T) {
		f := base
		f.corruptPin = true
		_, _, err := Gate(info(buildMirror(t, f)))
		requireRefused(t, err, ErrBodyDigestMismatch)
	})

	t.Run("and with the publisher text present it is admitted", func(t *testing.T) {
		d, err := Resolve(info(buildMirror(t, base)))
		if err != nil {
			t.Fatalf("a fully evidenced feed must still be admittable; a gate that refuses "+
				"everything is not fail-closed, it is broken: %v", err)
		}
		if d.LicenseFile != "mirror/tier0/cisa-kev/LICENSE.full.txt" {
			t.Errorf("LicenseFile = %q; the decision must rest on the PUBLISHER's text", d.LicenseFile)
		}
		if d.NotesFile != "mirror/tier0/LICENSE-NOTES.md" {
			t.Errorf("NotesFile = %q; Anvil's record must be named separately", d.NotesFile)
		}
		if d.BodySHA256 != d.PinnedSHA256 || len(d.BodySHA256) != 64 {
			t.Errorf("BodySHA256 %q must equal PinnedSHA256 %q and be a 64-hex digest",
				d.BodySHA256, d.PinnedSHA256)
		}
	})
}

// TestAnvilsRecordMayOnlyRaiseTheObligation pins the one influence Anvil's own
// prose is allowed to have. It can ratchet a feed towards refusal; it can never
// soften what the publisher's text says, and it can never establish an
// obligation on its own.
func TestAnvilsRecordMayOnlyRaiseTheObligation(t *testing.T) {
	// Record stricter than the publisher text: the OSV-aggregate shape, where
	// the inherited duty is knowledge Anvil has and the text does not state.
	raise := feedFixture{
		feedID:  "aggregate",
		tier:    config.LicenseTier1,
		pinSPDX: "CC-BY-4.0",
		verbatim: "Creative Commons Attribution 4.0 International. You must give " +
			"appropriate credit and indicate if changes were made.",
		notes: "Anvil's record: merged with a database whose terms are copyleft, so the " +
			"aggregate inherits that duty.",
	}
	_, _, err := Gate(LicenseInfo{
		FeedID:       "aggregate",
		DeclaredTier: config.LicenseTier1,
		DeclaredSPDX: "CC-BY-4.0",
		Mirror:       buildMirror(t, raise),
	})
	requireRefused(t, err, ErrShareAlikeQuarantine)

	// Record more permissive than the publisher text: it must change nothing.
	lower := feedFixture{
		feedID:   "mislabelled",
		tier:     config.LicenseTier1,
		pinSPDX:  config.LicenseNoAssertion,
		verbatim: shareAlikeVerbatim,
		notes:    "Anvil's record: this one is fine, it is just attribution.",
	}
	_, _, err = Gate(LicenseInfo{
		FeedID:       "mislabelled",
		DeclaredTier: config.LicenseTier1,
		DeclaredSPDX: config.LicenseNoAssertion,
		ManualNote:   "recorded",
		Mirror:       buildMirror(t, lower),
	})
	requireRefused(t, err, ErrShareAlikeQuarantine)
}

// TestPinIsBoundToTheFeedRow is the other half of A.6's B2: the evidence a
// decision rests on must be chosen by the feed row, never by the caller. A pin
// that disagrees with the row about tier or directory is a refusal, so a caller
// who supplies the wrong directory cannot inherit another source's licence
// conclusion.
func TestPinIsBoundToTheFeedRow(t *testing.T) {
	tier2 := config.LicenseTier2
	cases := map[string]feedFixture{
		"pin names another directory": {
			feedID: "ubuntu-osv", tier: config.LicenseTier2, dir: "ubuntu",
			pinDir: "alpine", pinSPDX: "CC-BY-SA-4.0",
			verbatim: shareAlikeVerbatim, notes: shareAlikeNotes,
		},
		"pin names another tier": {
			feedID: "ghsa", tier: config.LicenseTier1, pinTier: &tier2,
			pinSPDX: "CC-BY-4.0",
			verbatim: "Creative Commons Attribution 4.0 International; attribution " +
				"required.", notes: "Anvil record.",
		},
		"pin names another licence": {
			feedID: "ghsa", tier: config.LicenseTier1, pinSPDX: "CC0-1.0",
			verbatim: "Creative Commons Attribution 4.0 International.",
			notes:    "Anvil record.",
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := Gate(LicenseInfo{
				FeedID:       f.feedID,
				Dir:          f.dir,
				DeclaredTier: f.tier,
				DeclaredSPDX: "CC-BY-4.0",
				Mirror:       buildMirror(t, f),
			})
			requireRefused(t, err, ErrPinDisagreesWithRow)
		})
	}
}

// TestTier2IsReachableFromTheFeedTableAlone is A.6's blocker B2: "TIER 2 — THE
// QUARANTINE — CANNOT BE ENTERED BY ANY PRODUCTION CALLER".
//
// The three share-alike rows have ids ubuntu-osv, alpine-secdb and osv-merged
// while their quarantine directories are ubuntu, alpine and osv. There was no
// configured mapping between the two, so FromFeed took the directory as a
// parameter and the ONLY place the mapping existed was a var in this test file.
// A quarantine reachable from a test and from nowhere else is not a quarantine.
//
// The mapping is now config.FeedConfig.MirrorDir, and this test asserts the
// route end to end with NO test-side table at all.
func TestTier2IsReachableFromTheFeedTableAlone(t *testing.T) {
	set, err := config.Load(path.Join("..", "config", config.ExampleFileName))
	if err != nil {
		t.Fatalf("loading the example feed table: %v", err)
	}

	var tier2 int
	for _, f := range set.Feeds {
		if f.LicenseTier != config.LicenseTier2 {
			if f.MirrorDir != f.ID {
				t.Errorf("feed %q: mirror_dir %q should default to the id", f.ID, f.MirrorDir)
			}
			continue
		}
		tier2++

		// The whole route, built from the row alone.
		info := FromFeed(f, "", buildMirror(t, feedFixture{
			feedID: f.ID, tier: f.LicenseTier, dir: f.MirrorDir,
			pinSPDX:  "CC-BY-SA-4.0",
			verbatim: shareAlikeVerbatim, notes: shareAlikeNotes,
		}))
		if info.Dir != f.MirrorDir {
			t.Fatalf("feed %q: FromFeed chose dir %q, want the configured %q", f.ID, info.Dir, f.MirrorDir)
		}
		d, err := Resolve(info)
		if err != nil {
			t.Fatalf("feed %q cannot enter the tier 2 quarantine from its own row: %v", f.ID, err)
		}
		want := path.Join(TierDir(config.LicenseTier2), f.MirrorDir)
		if d.Dir != want {
			t.Errorf("feed %q resolved to %q, want %q", f.ID, d.Dir, want)
		}
		if f.MirrorDir == f.ID {
			t.Errorf("feed %q: this test proves nothing unless the directory differs from the id", f.ID)
		}
		for _, publishable := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
			if err := CheckWritePath(publishable, path.Join(d.Dir, "all.json")); err == nil {
				t.Errorf("share-alike data at %s was accepted as tier %d content", d.Dir, publishable.Int())
			}
		}
	}
	if tier2 == 0 {
		t.Fatal("the example feed table has no tier 2 row, so the quarantine route is untested")
	}
}

// ---------------------------------------------------------------------------
// THE INVERTED DEFAULT: unknown is not publishable
// ---------------------------------------------------------------------------

// The corpus below is the point of this section, so it is declared apart from
// the test that drives it and it is worth saying where every string came from.
//
// NONE OF THESE WORDINGS APPEARS IN classifierRules, AND NONE WAS WRITTEN BY
// READING IT. They are the operative clauses of four real licences that the
// marker table has never listed — the Open Software License 3.0, the Eclipse
// Public License 2.0 (its section 3.2, which never names the licence), the CDDL
// 1.0, and the Microsoft Public License — plus one CC-BY-SA deed in the shape a
// fetch of an html page actually produces.
//
// The previous B1 regression test validated the marker table against nine bodies
// QUOTED OUT OF THAT SAME TABLE. It therefore could not fail for any wording
// nobody had listed, which is the only wording that matters. A test whose corpus
// comes from the implementation is not a test; it is the implementation asserting
// itself.
var unenumeratedLicenceBodies = map[string]struct {
	body string
	want error
}{
	// OSL-3.0 §1(c) and §6. The reciprocity is real and the marker table cannot
	// see it; §6's "Attribution Rights" heading is what USED TO CLASSIFY THE
	// WHOLE TEXT AS NOTICE AND PUBLISH IT.
	"osl-3.0 operative wording": {
		body: "1) Grant of Copyright License. c) to distribute or communicate copies of the " +
			"Original Work and Derivative Works to the public, with the proviso that copies " +
			"of Original Work or Derivative Works that You distribute or communicate shall " +
			"be licensed under this Open Software License;\n\n" +
			"6) Attribution Rights. You must retain, in the Source Code of any Derivative " +
			"Works that You create, all copyright, patent or trademark notices from the " +
			"Source Code of the Original Work.",
		want: ErrNotProvablyPublishable,
	},

	// EPL-2.0 §3.2, which states the reciprocal duty without naming the licence.
	"epl-2.0 section 3.2": {
		body: "3.2 When the Program is Distributed in Source Code form: a) it must be made " +
			"available under this Agreement, in Source Code form; and b) a copy of this " +
			"Agreement must be included with each copy of the Program. Recipients must " +
			"preserve all copyright, patent and attribution notices contained within the " +
			"Program.",
		want: ErrNotProvablyPublishable,
	},

	// CDDL-1.0 §3.1.
	"cddl-1.0 availability of source code": {
		body: "3.1. Availability of Source Code. Any Covered Software that You distribute or " +
			"otherwise make available in Executable form must also be made available in " +
			"Source Code form and that Source Code form must be distributed only under the " +
			"terms of this License. You must preserve the copyright and attribution notices " +
			"contained in the Original Software.",
		want: ErrNotProvablyPublishable,
	},

	// MS-PL §3(D). Included precisely because it is nearly permissive: it is the
	// case where "not obviously copyleft" and "safe to publish" come apart, and
	// the answer is still quarantine because nobody has enumerated it.
	"ms-pl conditions and limitations": {
		body: "3. Conditions and Limitations. (D) If you distribute any portion of the " +
			"software in source code form, you may do so only under this license by " +
			"including a complete copy of this license with your distribution. You must " +
			"retain the above copyright notice and any attribution notices.",
		want: ErrNotProvablyPublishable,
	},

	// The formatting defeat, in the shape a fetch of a deed page produces: html
	// tags, hard wrapping mid-sentence, U+00A0, the &nbsp; character reference,
	// and a doubled space. Every one of those defeated the previous revision's
	// substring table. This one IS recognised — as share-alike — so it is
	// refused for the reason that matters rather than for being unrecognised.
	"html-sourced hard-wrapped cc-by-sa deed": {
		body: "<html><head><title>Deed</title></head><body>\n" +
			"<p>This work is licensed under a\n" +
			"Creative\u00a0Commons\n" +
			"Attribution-ShareAlike\u00a04.0\n" +
			"International License.</p>\n" +
			"<p>If you remix, transform, or build upon the material, you must\n" +
			"distribute your contributions under&nbsp;the&nbsp;same\n" +
			"license  as the original.</p>\n" +
			"<p>Attribution is required.</p>\n" +
			"</body></html>",
		want: ErrShareAlikeQuarantine,
	},
}

// TestOnlyPositivelyIdentifiedPermissiveTextsReachThePublishableTiers replaces
// the B1 regression test, and it asserts a PROPERTY rather than a table:
//
//	a body that is not positively identified as one of the enumerated
//	permissive licences never reaches tier 0 or tier 1.
//
// It is driven by bodies the marker table does not contain, so it cannot be
// satisfied by adding a marker, and it fails the day someone re-inverts the
// default. It is the test the tier-2 LICENSE files cite for their first
// ENFORCED IN CODE claim.
func TestOnlyPositivelyIdentifiedPermissiveTextsReachThePublishableTiers(t *testing.T) {
	for name, tc := range unenumeratedLicenceBodies {
		t.Run(name, func(t *testing.T) {
			if spdx, licName, _, ok := IdentifyPermissive(tc.body); ok {
				t.Fatalf("IdentifyPermissive identified this text as %q (%s); the corpus is "+
					"supposed to consist of licences this gate does NOT enumerate, so either "+
					"the fixture or the enumeration is wrong", spdx, licName)
			}

			for _, tier := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
				info := LicenseInfo{
					FeedID:       "unenumerated",
					DeclaredTier: tier,
					DeclaredSPDX: config.LicenseNoAssertion,
					ManualNote:   "no SPDX identifier is stated by the publisher",
					Mirror: buildMirror(t, feedFixture{
						feedID: "unenumerated", tier: tier,
						pinSPDX:  config.LicenseNoAssertion,
						verbatim: tc.body,
						notes:    "Anvil record: publisher terms, transcribed.",
					}),
				}

				d, err := Resolve(info)
				requireRefused(t, err, tc.want)
				if !d.Refused() {
					t.Errorf("tier %d: Resolve returned a decision that does not report itself "+
						"refused: %+v", tier.Int(), d)
				}
				if d.Tier.Valid() {
					t.Errorf("tier %d: Resolve refused but returned Tier %d, which is a VALID "+
						"tier; a refusal must never carry one", tier.Int(), d.Tier.Int())
				}
				if d.Tier.Int() == config.LicenseTier0.Int() {
					t.Errorf("tier %d: Resolve refused and returned tier 0, the most permissive "+
						"tier there is", tier.Int())
				}

				gotTier, dir, err := Gate(info)
				requireRefused(t, err, tc.want)
				if gotTier != NoTier || dir != "" {
					t.Errorf("tier %d: Gate refused but returned (%d, %q)", tier.Int(), gotTier, dir)
				}
			}
		})
	}

	// THE CORPUS IS NOT A RE-RUN OF THE MARKER TABLE. Four of the five bodies
	// are invisible to it — it establishes at most a NOTICE duty for them, which
	// is exactly what the old gate published on. If a later change makes the
	// table recognise them, this assertion fails and the property test must be
	// re-driven with wording the table still cannot see, because a property test
	// fed by the implementation proves nothing.
	for _, name := range []string{
		"osl-3.0 operative wording",
		"epl-2.0 section 3.2",
		"cddl-1.0 availability of source code",
		"ms-pl conditions and limitations",
	} {
		ob, _ := classifyMarkers(NormaliseForMatching(unenumeratedLicenceBodies[name].body))
		if ob == ObligationShareAlike || ob == ObligationRestricted {
			t.Errorf("%s: the marker table now classifies this corpus body as %v, so the test "+
				"no longer exercises the inverted default. Re-drive it with a licence the "+
				"table cannot see — that case is the whole point.", name, ob)
		}
	}
}

// TestNormalisationDefeatsTheFormattingEvasions is the first half of the rework:
// matching happens once, against normalised text.
//
// Each raw string below is a real licence marker made unmatchable by ordinary
// formatting — the shape of a wrapped file, an html page, a typo, a typesetter.
// The test asserts BOTH directions: the old lower-case-only substring match
// misses the marker, and the normalised match finds it. Without the first
// assertion the test would pass on a build that had never normalised anything.
func TestNormalisationDefeatsTheFormattingEvasions(t *testing.T) {
	cases := map[string]struct {
		raw    string
		marker string
	}{
		"hard line wrapping": {
			raw: "If you remix the material you must distribute your contributions under the same\n" +
				"license as the original.",
			marker: "under the same license",
		},
		"non-breaking spaces": {
			raw:    "distribute your contributions under\u00a0the\u00a0same\u00a0license as the original.",
			marker: "under the same license",
		},
		"html character references": {
			raw:    "distribute your contributions under&nbsp;the&nbsp;same&nbsp;license as before.",
			marker: "under the same license",
		},
		"a doubled space": {
			raw:    "you must distribute your contributions under the  same  license as the original.",
			marker: "under the same license",
		},
		"full-width forms": {
			raw:    "This dataset is offered under a \uff33\uff48\uff41\uff52\uff45\uff21\uff4c\uff49\uff4b\uff45 licence.",
			marker: "sharealike",
		},
		"zero-width space": {
			raw:    "This dataset is offered under a Share\u200bAlike licence.",
			marker: "sharealike",
		},
		"typographic hyphens": {
			raw:    "SPDX-License-Identifier: CC\u2011BY\u2011SA\u20114.0",
			marker: "cc-by-sa",
		},
		"ideographic space": {
			raw:    "Released under the GNU\u3000General\u3000Public\u3000License.",
			marker: "gnu general public license",
		},
		"tab-separated columns": {
			raw:    "licence:\tGNU\tGeneral\tPublic\tLicense",
			marker: "gnu general public license",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(strings.ToLower(tc.raw), tc.marker) {
				t.Fatalf("fixture error: %q is already found by a plain lower-case substring "+
					"match, so this case does not exercise normalisation at all", tc.marker)
			}
			if got := NormaliseForMatching(tc.raw); !strings.Contains(got, tc.marker) {
				t.Fatalf("normalised text does not contain %q:\n%q", tc.marker, got)
			}
			if _, ob := Classify(tc.raw); ob != ObligationShareAlike {
				t.Fatalf("Classify obligation = %v, want share-alike; formatting must not "+
					"decide a licence conclusion", ob)
			}
		})
	}
}

// TestNormaliseForMatchingCollapsesWhatItClaimsTo pins the function itself, so
// that a change to it is visible here rather than only as a distant refusal.
func TestNormaliseForMatchingCollapsesWhatItClaimsTo(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"  \n\t  ", ""},
		{"  Leading and trailing  \n", "leading and trailing"},
		{"CC-BY-SA-4.0", "cc-by-sa-4.0"},
		{"one\r\ntwo\u00a0three\u2003four", "one two three four"},
		{"\uff23\uff23\uff10", "cc0"},      // full-width CC0
		{"soft\u00adhyphen", "softhyphen"}, // U+00AD is dropped, not spaced
		{"\ufeffbom", "bom"},               // byte-order mark dropped
		{"quo\u2019te \u201cx\u201d", "quo'te \"x\""},
		{"en\u2013dash", "en-dash"},
		{"\ufb01le", "file"}, // the fi ligature
	}
	for _, tc := range cases {
		if got := NormaliseForMatching(tc.in); got != tc.want {
			t.Errorf("NormaliseForMatching(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEveryMarkerIsAlreadyNormalised closes the failure mode normalisation
// introduces: a marker written with a capital, a double space or a newline can
// never match normalised text, and it fails SILENTLY — the gate simply becomes
// blinder with no test going red.
func TestEveryMarkerIsAlreadyNormalised(t *testing.T) {
	check := func(where, phrase string) {
		t.Helper()
		if phrase == "" {
			t.Errorf("%s: empty marker; it would match every text", where)
			return
		}
		if got := NormaliseForMatching(phrase); got != phrase {
			t.Errorf("%s: marker %q is not in normalised form (%q), so it can never match",
				where, phrase, got)
		}
	}
	for _, r := range classifierRules {
		check("classifierRules", r.marker)
	}
	for _, e := range excludedMarkers {
		check("excludedMarkers", e.marker)
	}
	for _, m := range noGrantMarkers {
		check("noGrantMarkers", m)
	}
	for _, l := range permissiveLicences {
		if len(l.signatures) == 0 {
			t.Errorf("permissive licence %q has no signature, so it can never be identified", l.name)
		}
		for _, sig := range l.signatures {
			if len(sig.phrases) == 0 {
				t.Errorf("permissive licence %q has an empty signature, which matches everything", l.name)
			}
			for _, p := range sig.phrases {
				check("permissiveLicences/"+l.name, p)
			}
		}
	}
	for _, m := range licenceNameMarkers {
		check("licenceNameMarkers", m.marker)
	}
	for _, m := range secondTermsMarkers {
		check("secondTermsMarkers", m.marker)
	}
	for _, cue := range negationCues {
		check("negationCues", cue)
	}
}

// TestEverySignatureIsAPhraseOrABoundedWindow is blocker B2's structural guard.
//
// The defect it exists for was a signature of the form {"apache license",
// "version 2.0"}: two terms required to appear ANYWHERE in the document, which
// a 12 KB file titled "ACME DATA LICENCE, Version 2.0" satisfied while saying
// it was NOT under the Apache License. Whether that signature matches is a
// property of the document's SIZE, not of anything it says.
//
// So the shape is asserted rather than trusted: one phrase means contiguous and
// carries no window; several phrases mean a window, and the window is bounded
// by something smaller than a licence file. A multi-phrase signature with a
// zero window would silently match nothing; a single-phrase signature with one
// would claim a looseness it does not have.
func TestEverySignatureIsAPhraseOrABoundedWindow(t *testing.T) {
	// A window wider than this is a document-wide conjunction wearing a number.
	// 2500 normalised bytes is longer than the whole of BSD-3-Clause, which is
	// the widest legitimate case in the table.
	const maxWindow = 2500
	for _, l := range permissiveLicences {
		for i, sig := range l.signatures {
			switch {
			case len(sig.phrases) == 0:
				t.Errorf("%s signature %d has no phrases", l.name, i)
			case len(sig.phrases) == 1 && sig.window != 0:
				t.Errorf("%s signature %d is a single phrase but carries a window of %d; a "+
					"contiguous match has no window and the number is misleading",
					l.name, i, sig.window)
			case len(sig.phrases) > 1 && sig.window <= 0:
				t.Errorf("%s signature %d has %d phrases and no window, so it can never match",
					l.name, i, len(sig.phrases))
			case sig.window > maxWindow:
				t.Errorf("%s signature %d has a window of %d, which is wider than a licence file; "+
					"that is the document-wide conjunction B2 was about, with a number attached",
					l.name, i, sig.window)
			}
		}
	}
}

// TestEveryEnumeratedPermissiveLicenceIsActuallyPermissive keeps the enumerated
// set honest about itself. An entry carrying a share-alike or restricted
// obligation would be a share-alike licence sitting in the list of things that
// may be published, which is the defect this whole rework exists to remove.
func TestEveryEnumeratedPermissiveLicenceIsActuallyPermissive(t *testing.T) {
	for _, l := range permissiveLicences {
		if !publishableObligations[l.ob] {
			t.Errorf("enumerated permissive licence %q carries obligation %v, which tier 0/1 "+
				"may not carry", l.name, l.ob)
		}
	}
	if publishableObligations[ObligationShareAlike] || publishableObligations[ObligationRestricted] ||
		publishableObligations[ObligationUnknown] {
		t.Error("publishableObligations admits a class the publishable tiers must never carry")
	}
	if len(permissiveNames()) == 0 {
		t.Error("the enumerated permissive set is empty; the gate would quarantine everything, " +
			"which is as useless as publishing everything")
	}
}

// TestPermissiveLicenceTextsAreNotDraggedIntoQuarantine is the other side of the
// inversion, and it is not optional: a gate that quarantines everything is as
// useless as one that publishes everything.
//
// Two things are asserted for every body. First that Classify still reports the
// permissive obligation — the reciprocity markers must not fire on wording
// CC-BY-4.0 and Apache-2.0 also use, which is why "Adapted Material" and
// "Adapter's License" are deliberately NOT markers. Second, and this is new,
// that the body is POSITIVELY IDENTIFIED and reaches its declared tier through
// the real gate. The three CC-BY-4.0 feeds the example table depends on — ghsa,
// redhat-csaf and osv-pypi — are named cases here rather than a footnote.
func TestPermissiveLicenceTextsAreNotDraggedIntoQuarantine(t *testing.T) {
	// Hard-wrapped on purpose: this is the shape a real LICENSE file has, and
	// wrapping is what defeated the previous revision.
	const ccBY40 = `Creative Commons Attribution 4.0 International Public License

By exercising the Licensed Rights, You accept and agree to be bound by the
terms and conditions of this Creative Commons Attribution 4.0 International
Public License.

Section 2 -- Scope.

  5. Downstream recipients.

     b. Additional offer from the Licensor -- Adapted Material. Every
        recipient of Adapted Material from You automatically receives an offer
        from the Licensor to exercise the Licensed Rights in the Adapted
        Material under the conditions of the Adapter's License You apply.

Section 3 -- License Conditions.

  a. Attribution. If You Share the Licensed Material, You must retain
     identification of the creator, a copyright notice, a notice that refers
     to this Public License, and indicate if You modified the Licensed
     Material.`

	cases := map[string]struct {
		body     string
		tier     config.LicenseTier
		declared string
		wantOb   Obligation
		wantSPDX string
		feedID   string
		dir      string
	}{
		"ghsa cc-by-4.0": {
			body: ccBY40, tier: config.LicenseTier1, declared: "CC-BY-4.0",
			wantOb: ObligationNotice, wantSPDX: "CC-BY-4.0", feedID: "ghsa",
		},
		"redhat-csaf cc-by-4.0": {
			body: ccBY40, tier: config.LicenseTier1, declared: "CC-BY-4.0",
			wantOb: ObligationNotice, wantSPDX: "CC-BY-4.0", feedID: "redhat-csaf",
		},
		"osv-pypi cc-by-4.0": {
			body: ccBY40, tier: config.LicenseTier1, declared: "CC-BY-4.0",
			wantOb: ObligationNotice, wantSPDX: "CC-BY-4.0", feedID: "osv-pypi",
		},
		"cisa-kev cc0": {
			body: kevVerbatim, tier: config.LicenseTier0, declared: "CC0-1.0",
			wantOb: ObligationPublicDomain, wantSPDX: "CC0-1.0", feedID: "cisa-kev",
		},
		"cvelistv5 cve programme terms of use": {
			body: "CVE Program Terms of Use\n\nCVE Records may be reproduced, published and " +
				"used to prepare derivative works, provided that the CVE Program is credited " +
				"as the source. Attribution is required.",
			tier: config.LicenseTier0, declared: "CVE-TOU",
			wantOb: ObligationNotice, wantSPDX: "CVE-TOU", feedID: "cvelistv5",
		},
		"nvd united states government work": {
			body: "NVD General FAQs\n\nAll NIST publications are available in the public " +
				"domain according to Title 17 of the United States Code. Acknowledgement of " +
				"the NVD as the source is requested.",
			tier: config.LicenseTier0, declared: "LicenseRef-US-Gov-Public-Domain",
			wantOb: ObligationPublicDomain, wantSPDX: "LicenseRef-US-Gov-Public-Domain",
			feedID: "nvd",
		},
		"apache-2.0 redistribution clause": {
			body: "Apache License, Version 2.0. You may reproduce and distribute copies of the " +
				"Work or Derivative Works thereof in any medium, with or without " +
				"modifications, provided that You retain the above copyright notice.",
			tier: config.LicenseTier1, declared: "Apache-2.0",
			wantOb: ObligationNotice, wantSPDX: "Apache-2.0", feedID: "apache-source",
		},
		"mit": {
			body: "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
				"obtaining a copy of this software, to deal in the Software without " +
				"restriction.",
			tier: config.LicenseTier1, declared: "MIT",
			wantOb: ObligationNotice, wantSPDX: "MIT", feedID: "mit-source",
		},
		"bsd 3-clause": {
			body: "Redistribution and use in source and binary forms, with or without " +
				"modification, are permitted provided that the following conditions are met. " +
				"Neither the name of the copyright holder nor the names of its contributors " +
				"may be used to endorse or promote products derived from this software.",
			tier: config.LicenseTier1, declared: "BSD-3-Clause",
			wantOb: ObligationNotice, wantSPDX: "BSD-3-Clause", feedID: "bsd-source",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ob := Classify(tc.body); ob != tc.wantOb {
				t.Fatalf("Classify obligation = %v, want %v; a reciprocity marker that fires "+
					"on this text refuses feeds the example table depends on", ob, tc.wantOb)
			}
			spdx, licName, _, ok := IdentifyPermissive(tc.body)
			if !ok {
				t.Fatalf("IdentifyPermissive did not recognise this text, so the gate would " +
					"quarantine it. A gate that quarantines everything is as useless as one " +
					"that publishes everything")
			}
			if spdx != tc.wantSPDX {
				t.Errorf("IdentifyPermissive = %q (%s), want %q", spdx, licName, tc.wantSPDX)
			}

			dir := tc.dir
			if dir == "" {
				dir = tc.feedID
			}
			info := LicenseInfo{
				FeedID:       tc.feedID,
				Dir:          tc.dir,
				DeclaredTier: tc.tier,
				DeclaredSPDX: tc.declared,
				ManualNote: "Operative sentence transcribed from the publisher's licence " +
					"text; recorded for the LicenseRef- and NOASSERTION rows.",
				Mirror: buildMirror(t, feedFixture{
					feedID: tc.feedID, tier: tc.tier, dir: tc.dir,
					pinSPDX: tc.wantSPDX, verbatim: tc.body,
					notes: "Anvil record: " + tc.wantSPDX + ".",
				}),
			}
			d, err := Resolve(info)
			if err != nil {
				t.Fatalf("the gate refused a positively identified permissive feed: %v", err)
			}
			if d.Refused() {
				t.Fatalf("Resolve returned no error but a decision reporting itself refused: %+v", d)
			}
			if d.Tier != tc.tier {
				t.Errorf("tier = %d, want %d", d.Tier.Int(), tc.tier.Int())
			}
			if want := path.Join(TierDir(tc.tier), dir); d.Dir != want {
				t.Errorf("dir = %q, want %q", d.Dir, want)
			}
			if d.EffectiveSPDX != tc.wantSPDX || !d.SPDXFromBody {
				t.Errorf("EffectiveSPDX = %q (from body: %v), want %q read from the publisher's text",
					d.EffectiveSPDX, d.SPDXFromBody, tc.wantSPDX)
			}
		})
	}
}

// TestADocumentNamingSeveralLicencesIsAmbiguousAndQuarantined covers the third
// state positive identification can be in.
//
// A LICENSE file that says "this tree is MIT, the vendored subtree is under
// something else" is the realistic shape, and admitting it on whichever
// signature happens to be listed first is how a bundled reciprocal licence
// ships unnoticed. Ambiguous is quarantined, exactly as unrecognised is.
func TestADocumentNamingSeveralLicencesIsAmbiguousAndQuarantined(t *testing.T) {
	const dual = `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software, to deal in the Software without restriction.

The vendored components under third_party/ are distributed under the
Apache License, Version 2.0 and retain their own NOTICE file.`

	if got := len(permissiveMatches(NormaliseForMatching(dual))); got != 2 {
		t.Fatalf("permissiveMatches found %d licences, want 2; the fixture must name two "+
			"ENUMERATED licences or it does not exercise ambiguity", got)
	}
	if _, _, _, ok := IdentifyPermissive(dual); ok {
		t.Error("IdentifyPermissive accepted a document that names two licences")
	}

	for _, tier := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
		// Declared and pinned NOASSERTION, so that the identity checks have
		// nothing to fire on and the refusal under test is the ambiguity, not a
		// disagreement between the row and the body.
		_, _, err := Gate(LicenseInfo{
			FeedID:       "dual-licensed",
			DeclaredTier: tier,
			DeclaredSPDX: config.LicenseNoAssertion,
			ManualNote:   "vendor ships one LICENSE file covering two licences",
			Mirror: buildMirror(t, feedFixture{
				feedID: "dual-licensed", tier: tier, pinSPDX: config.LicenseNoAssertion,
				verbatim: dual, notes: "Anvil record: vendor claims MIT.",
			}),
		})
		requireRefused(t, err, ErrNotProvablyPublishable)
		if !strings.Contains(err.Error(), "ambiguous") {
			t.Errorf("tier %d: the refusal must say the identification was ambiguous: %v",
				tier.Int(), err)
		}
	}

	// The family grouping must not turn a plain BSD-3-Clause text — whose
	// wording necessarily satisfies the BSD-2-Clause signature too — into a
	// false ambiguity. That would refuse a licence the enumeration lists.
	const bsd3 = "Redistribution and use in source and binary forms, with or without " +
		"modification, are permitted provided that the following conditions are met. " +
		"Neither the name of the copyright holder nor the names of its contributors may " +
		"be used to endorse or promote products derived from this software."
	if got := len(permissiveMatches(NormaliseForMatching(bsd3))); got != 1 {
		t.Errorf("permissiveMatches found %d licences for a BSD-3-Clause text, want 1; the "+
			"BSD entries must share a family", got)
	}
}

// TestNoAdmissionToAPublishableTierWithoutPositiveIdentification is the
// structural half of the inversion: not "these bodies are refused" but "no body
// is admitted to tier 0 or tier 1 unless IdentifyPermissive says so".
//
// It sweeps every body this file has, at every tier, with declarations that
// disagree with them, and asserts the implication. A future code path that
// returns a decision early — the NONE branch was exactly that once — trips it
// wherever it is added, which is the property a list of named cases cannot give.
func TestNoAdmissionToAPublishableTierWithoutPositiveIdentification(t *testing.T) {
	bodies := map[string]string{
		"cc0 legalcode":     kevVerbatim,
		"share-alike named": shareAlikeVerbatim,
		"empty":             "",
		"whitespace only":   "   \n\t   \n",
		"opaque":            "The maintainers are friendly and the data is free of charge.",
		"states no grant":   "All rights reserved. No licence is granted to redistribute this data.",
		"restricted":        "This dataset is provided for non-commercial research use.",
		"generic attribution": "Redistribution is permitted provided that attribution is " +
			"required and preserved.",
	}
	for name, tc := range unenumeratedLicenceBodies {
		bodies[name] = tc.body
	}

	declarations := []string{"CC0-1.0", "CC-BY-4.0", config.LicenseNoAssertion, config.LicenseNone}
	tiers := []config.LicenseTier{
		config.LicenseTier0, config.LicenseTier1, config.LicenseTier2, config.LicenseTier3,
	}

	var admitted, admittedPublishable int
	for name, body := range bodies {
		_, _, _, identified := IdentifyPermissive(body)
		for _, tier := range tiers {
			for _, declared := range declarations {
				d, err := Resolve(LicenseInfo{
					FeedID:       "sweep",
					DeclaredTier: tier,
					DeclaredSPDX: declared,
					ManualNote:   "recorded so a missing note is not what refuses the row",
					Mirror: buildMirror(t, feedFixture{
						feedID: "sweep", tier: tier, pinSPDX: declared,
						verbatim: body, notes: "Anvil record.",
					}),
				})
				if err != nil {
					if !d.Refused() {
						t.Errorf("%s/tier %d/%s: refused decision does not report itself refused",
							name, tier.Int(), declared)
					}
					continue
				}
				admitted++
				if d.Refused() {
					t.Errorf("%s/tier %d/%s: admitted decision reports itself refused: %+v",
						name, tier.Int(), declared, d)
				}
				if tier != config.LicenseTier0 && tier != config.LicenseTier1 {
					continue
				}
				admittedPublishable++
				if !identified {
					t.Errorf("%s: ADMITTED to the publishable tier %d under declaration %q "+
						"without being positively identified as a permissive licence. That is "+
						"the inverted default failing, and it is unrecoverable once published.",
						name, tier.Int(), declared)
				}
			}
		}
	}
	if admitted == 0 {
		t.Fatal("the sweep admitted nothing at any tier, so it proved nothing about admission; " +
			"a gate that refuses everything is broken, not safe")
	}
	if admittedPublishable == 0 {
		t.Fatal("the sweep admitted nothing to tier 0 or tier 1, so the implication it asserts " +
			"is vacuously true and it proves nothing at all")
	}
}

// TestResolveRefusalNeverCarriesAPublishableTier is the regression test for the
// defect the re-verifier found in the documented entry point: Gate had been
// fixed to return NoTier, Resolve had not, and `Decision{}.Tier` is tier 0 —
// always mirrored, publishable, no copyleft. A caller reading the decision
// without checking the error got permission.
//
// It sweeps refusals from every stage of Resolve, so a future path that forgets
// the discipline is caught wherever it is added.
func TestResolveRefusalNeverCarriesAPublishableTier(t *testing.T) {
	good := buildMirror(t, feedFixture{
		feedID: "cisa-kev", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
		verbatim: kevVerbatim, notes: kevNotes,
	})
	base := func() LicenseInfo {
		return LicenseInfo{
			FeedID:       "cisa-kev",
			DeclaredTier: config.LicenseTier0,
			DeclaredSPDX: "CC0-1.0",
			Mirror:       good,
		}
	}

	cases := map[string]func(*LicenseInfo){
		"structurally invalid row": func(i *LicenseInfo) { i.FeedID = "" },
		"excluded source":          func(i *LicenseInfo) { i.ManualNote = "Derived from a CIS Benchmark." },
		"no manifest":              func(i *LicenseInfo) { i.Mirror = fstest.MapFS{} },
		"unpinned feed":            func(i *LicenseInfo) { i.FeedID = "not-in-the-manifest" },
		"pin disagrees with the row": func(i *LicenseInfo) {
			i.DeclaredTier = config.LicenseTier1
		},
		"missing manual note": func(i *LicenseInfo) { i.MetadataSPDX = config.LicenseNoAssertion },
		"unrecognised body": func(i *LicenseInfo) {
			i.Mirror = buildMirror(t, feedFixture{
				feedID: "cisa-kev", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
				verbatim: "The maintainers are friendly and the data is free of charge.",
				notes:    "Anvil record.",
			})
		},
		"share-alike outside quarantine": func(i *LicenseInfo) {
			i.DeclaredSPDX = "CC-BY-SA-4.0"
			i.Mirror = buildMirror(t, feedFixture{
				feedID: "cisa-kev", tier: config.LicenseTier0, pinSPDX: "CC-BY-SA-4.0",
				verbatim: shareAlikeVerbatim, notes: shareAlikeNotes,
			})
		},
		"not positively permissive": func(i *LicenseInfo) {
			i.DeclaredSPDX = config.LicenseNoAssertion
			i.ManualNote = "publisher names no identifier"
			i.Mirror = buildMirror(t, feedFixture{
				feedID: "cisa-kev", tier: config.LicenseTier0, pinSPDX: config.LicenseNoAssertion,
				verbatim: unenumeratedLicenceBodies["osl-3.0 operative wording"].body,
				notes:    "Anvil record.",
			})
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			info := base()
			mutate(&info)

			d, err := Resolve(info)
			if err == nil {
				t.Fatalf("expected a refusal, got a decision: %+v", d)
			}
			if !errors.Is(err, ErrLicenseRefused) {
				t.Fatalf("%v does not satisfy ErrLicenseRefused", err)
			}
			if d.Tier.Int() != NoTier {
				t.Errorf("Resolve refused but returned Tier %d, want NoTier (%d)", d.Tier.Int(), NoTier)
			}
			if d.Tier.Valid() {
				t.Errorf("Resolve refused but returned the valid tier %d", d.Tier.Int())
			}
			if !d.Refused() {
				t.Error("the refused decision does not report itself refused")
			}
			if d.Dir != "" {
				t.Errorf("Dir = %q on a refusal, want empty", d.Dir)
			}
			row, rowErr := d.ManifestRow()
			if rowErr == nil {
				t.Error("the refused decision projected onto a license_dir_manifest row without " +
					"complaint; a refusal has no row")
			}
			if config.LicenseTier(row.Tier).Valid() {
				t.Errorf("the refused decision projects onto a license_dir_manifest row at the "+
					"valid tier %d; a refusal must not be writable", row.Tier)
			}
		})
	}

	// And the shape that started it: a Decision nobody filled in. Tier 0 is its
	// zero value, so Valid() alone is not enough to tell permission from
	// forgetfulness.
	if !(Decision{}).Refused() {
		t.Error("the zero Decision does not report itself refused, so a code path that " +
			"forgets to fill one in hands out tier 0")
	}
}

// ---------------------------------------------------------------------------
// A.4's first required test: the CISA KEV case
// ---------------------------------------------------------------------------

// TestGateAdmitsKEVShapeOverNOASSERTIONMetadata is A.4's named validation:
// "the CISA KEV case (API NOASSERTION, README CC0-1.0) is correctly admitted
// via license_manual_note".
func TestGateAdmitsKEVShapeOverNOASSERTIONMetadata(t *testing.T) {
	mirror := buildMirror(t, feedFixture{
		feedID: "cisa-kev", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
		verbatim: kevVerbatim, notes: kevNotes,
	})
	info := LicenseInfo{
		FeedID:       "cisa-kev",
		DeclaredTier: config.LicenseTier0,
		DeclaredSPDX: "CC0-1.0",
		MetadataSPDX: config.LicenseNoAssertion, // what the forge says. Never trusted.
		ManualNote:   kevNote,
		Mirror:       mirror,
	}

	tier, dir, err := Gate(info)
	if err != nil {
		t.Fatalf("Gate refused the CISA KEV shape: %v", err)
	}
	if tier != 0 {
		t.Errorf("tier = %d, want 0", tier)
	}
	if want := "mirror/tier0/cisa-kev"; dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}

	d, err := Resolve(info)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Obligation != ObligationPublicDomain {
		t.Errorf("obligation = %v, want public-domain", d.Obligation)
	}
	if d.EffectiveSPDX != "CC0-1.0" || !d.SPDXFromBody {
		t.Errorf("effective SPDX = %q (from body: %v), want CC0-1.0 read from the publisher's text",
			d.EffectiveSPDX, d.SPDXFromBody)
	}
	if !d.MetadataOverridden {
		t.Error("MetadataOverridden = false; the registry reported NOASSERTION over a declared CC0-1.0 and that disagreement must be recorded")
	}
	if !d.NoteRequired || d.ManualNote == "" {
		t.Error("the S8 manual note must be mandatory and carried when metadata contradicts the declaration")
	}
}

// TestGateRequiresTheManualNoteThatAdmitsKEV is the other half of the same
// requirement: the row is admitted VIA license_manual_note, so removing the
// note must refuse it.
func TestGateRequiresTheManualNoteThatAdmitsKEV(t *testing.T) {
	_, _, err := Gate(LicenseInfo{
		FeedID:       "cisa-kev",
		DeclaredTier: config.LicenseTier0,
		DeclaredSPDX: "CC0-1.0",
		MetadataSPDX: config.LicenseNoAssertion,
		ManualNote:   "", // the override S8 requires is missing
		Mirror: buildMirror(t, feedFixture{
			feedID: "cisa-kev", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
			verbatim: kevVerbatim, notes: kevNotes,
		}),
	})
	requireRefused(t, err, ErrMissingManualNote)
}

// TestGateAdmitsNOASSERTIONOverGenuinelyPermissiveBody is the second direction
// of the trap S8 names, and the one this project caught on PurpleLlama:
// NOASSERTION metadata sitting over a genuinely MIT subtree. The permissive
// answer is the correct one here, and the gate has to be able to reach it — a
// gate that refuses everything is not fail-closed, it is broken.
func TestGateAdmitsNOASSERTIONOverGenuinelyPermissiveBody(t *testing.T) {
	body := `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction, subject to the following conditions: the above copyright
notice shall be included in all copies.`

	d, err := Resolve(LicenseInfo{
		FeedID:       "permissive-subtree",
		DeclaredTier: config.LicenseTier1,
		DeclaredSPDX: config.LicenseNoAssertion,
		MetadataSPDX: config.LicenseNoAssertion,
		ManualNote:   "Registry reports NOASSERTION; the subtree carries a verbatim MIT text.",
		Mirror: buildMirror(t, feedFixture{
			feedID: "permissive-subtree", tier: config.LicenseTier1, pinSPDX: "MIT",
			verbatim: body, notes: "Anvil record: verbatim MIT text in the subtree.",
		}),
	})
	if err != nil {
		t.Fatalf("Gate refused a genuinely permissive body behind NOASSERTION metadata: %v", err)
	}
	if d.Obligation != ObligationNotice {
		t.Errorf("obligation = %v, want notice", d.Obligation)
	}
	if d.EffectiveSPDX != "MIT" {
		t.Errorf("effective SPDX = %q, want MIT read from the body", d.EffectiveSPDX)
	}
}

// ---------------------------------------------------------------------------
// A.6 M2: the published identifier is never the unverified declaration
// ---------------------------------------------------------------------------

// TestEffectiveSPDXNeverFallsBackToTheDeclaration is M2's regression test.
//
// The body below establishes an obligation and names no identifier. The old
// code filled EffectiveSPDX from the feed table's YAML assertion, and that
// value flowed straight into the A.2 cache's license_dir_manifest.spdx_id — so
// the manifest reported a licence nobody had verified, in a column whose only
// writer is a gate whose whole purpose is verification.
//
// THE ROW IS AT TIER 3, and that is a consequence of the inversion rather than
// an evasion of it. A body that establishes an obligation while naming no
// licence is precisely a body that is NOT positively identified, so it can no
// longer reach tier 0 or tier 1 at all — TestOnlyPositivelyIdentifiedPermissive-
// TextsReachThePublishableTiers is the test for that half. Tier 3 is opt-in and
// risk-accepted, it still writes a license_dir_manifest row, and it is where the
// shape M2 is about survives.
func TestEffectiveSPDXNeverFallsBackToTheDeclaration(t *testing.T) {
	d, err := Resolve(LicenseInfo{
		FeedID:       "unnamed-terms",
		DeclaredTier: config.LicenseTier3,
		DeclaredSPDX: "CC-BY-4.0", // the claim. Unverified.
		Mirror: buildMirror(t, feedFixture{
			feedID: "unnamed-terms", tier: config.LicenseTier3, pinSPDX: config.LicenseNoAssertion,
			verbatim: "Redistribution is permitted provided that attribution is required " +
				"and preserved. No identifier is stated anywhere in this document.",
			notes: "Anvil record: the publisher names no SPDX identifier.",
		}),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.SPDXFromBody {
		t.Error("SPDXFromBody = true; the body named no identifier")
	}
	if d.EffectiveSPDX != config.LicenseNoAssertion {
		t.Errorf("EffectiveSPDX = %q, want %s; the gate did not verify %q so it must not report it",
			d.EffectiveSPDX, config.LicenseNoAssertion, d.DeclaredSPDX)
	}
	row, err := d.ManifestRow()
	if err != nil {
		t.Fatalf("ManifestRow on an admitted decision: %v", err)
	}
	if row.SPDXID != config.LicenseNoAssertion {
		t.Errorf("license_dir_manifest.spdx_id = %q, want %s; the cache column must not carry "+
			"an unverified assertion", row.SPDXID, config.LicenseNoAssertion)
	}
	if d.DeclaredSPDX != "CC-BY-4.0" {
		t.Errorf("DeclaredSPDX = %q; the claim must still be visible beside the conclusion", d.DeclaredSPDX)
	}
}

// ---------------------------------------------------------------------------
// A.4's second required test: Tier 2 cannot be written under Tier 0 or Tier 1
// ---------------------------------------------------------------------------

func TestSyntheticTier2RowCannotBeRoutedToTier0Or1(t *testing.T) {
	for _, tier := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
		_, _, err := Gate(LicenseInfo{
			FeedID:       "synthetic-sharealike",
			DeclaredTier: tier,
			DeclaredSPDX: "CC-BY-SA-4.0",
			Mirror: buildMirror(t, feedFixture{
				feedID: "synthetic-sharealike", tier: tier, pinSPDX: "CC-BY-SA-4.0",
				verbatim: shareAlikeVerbatim, notes: shareAlikeNotes,
			}),
		})
		requireRefused(t, err, ErrShareAlikeQuarantine)
		if !strings.Contains(err.Error(), "share-alike") {
			t.Errorf("tier %d: refusal must say why: %v", tier.Int(), err)
		}
	}

	// The same source at Tier 2 is admitted, into its own segregated directory.
	d, err := Resolve(LicenseInfo{
		FeedID:       "ubuntu-osv",
		Dir:          "ubuntu",
		DeclaredTier: config.LicenseTier2,
		DeclaredSPDX: "CC-BY-SA-4.0",
		Mirror: buildMirror(t, feedFixture{
			feedID: "ubuntu-osv", tier: config.LicenseTier2, dir: "ubuntu",
			pinSPDX: "CC-BY-SA-4.0", verbatim: shareAlikeVerbatim, notes: shareAlikeNotes,
		}),
	})
	if err != nil {
		t.Fatalf("Gate refused a share-alike source at its own tier 2: %v", err)
	}
	if d.Dir != "mirror/tier2/ubuntu" {
		t.Fatalf("dir = %q, want mirror/tier2/ubuntu", d.Dir)
	}
	if d.NotesFile != "mirror/tier2/ubuntu/LICENSE" {
		t.Errorf("NotesFile = %q; tier 2 keeps its record in the source's OWN LICENSE", d.NotesFile)
	}
	if !d.Obligation.ShareAlike() {
		t.Errorf("obligation = %v, want share-alike", d.Obligation)
	}

	for _, bad := range []string{
		"mirror/tier0/ubuntu/all.json",
		"mirror/tier1/ubuntu/all.json",
		"mirror/tier0",
		"mirror/tier1",
		`mirror\tier0\ubuntu\all.json`, // Windows separators must not walk out
		"mirror/tier2/alpine/all.json", // another source's quarantine is not this one's
	} {
		if err := d.CheckWritePath(bad); !errors.Is(err, ErrTierRouting) {
			t.Errorf("Decision.CheckWritePath(%q) = %v, want ErrTierRouting", bad, err)
		}
	}
	for _, bad := range []string{
		"mirror/tier0/ubuntu/all.json",
		"mirror/tier1/ubuntu/all.json",
		`mirror\tier1\ubuntu\all.json`,
		"../mirror/tier2/ubuntu/all.json",
		"/etc/passwd",
	} {
		if err := CheckWritePath(config.LicenseTier2, bad); !errors.Is(err, ErrTierRouting) {
			t.Errorf("CheckWritePath(tier2, %q) = %v, want ErrTierRouting", bad, err)
		}
	}
	for _, ok := range []string{
		"mirror/tier2/ubuntu/all.json",
		"mirror/tier2/ubuntu",
		`mirror\tier2\ubuntu\all.json`,
	} {
		if err := d.CheckWritePath(ok); err != nil {
			t.Errorf("Decision.CheckWritePath(%q) = %v, want nil", ok, err)
		}
	}
}

// TestTier2AdmitsNothingButShareAlike keeps the quarantine meaningful in the
// other direction. A permissive source parked in mirror/tier2 would teach a
// reader that tier 2 means "miscellaneous".
func TestTier2AdmitsNothingButShareAlike(t *testing.T) {
	_, _, err := Gate(LicenseInfo{
		FeedID:       "not-sharealike",
		DeclaredTier: config.LicenseTier2,
		DeclaredSPDX: "CC0-1.0",
		Mirror: buildMirror(t, feedFixture{
			feedID: "not-sharealike", tier: config.LicenseTier2, pinSPDX: "CC0-1.0",
			verbatim: kevVerbatim, notes: "Anvil record: public domain.",
		}),
	})
	requireRefused(t, err, ErrShareAlikeQuarantine)
}

// TestPermissiveTagOverShareAlikeBodyIsRefused is the autogrep shape: an
// Apache-2.0 identifier at the root of an artifact whose content is
// GPL/AGPL-derived.
func TestPermissiveTagOverShareAlikeBodyIsRefused(t *testing.T) {
	body := `SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0.

Portions of the rules in this distribution are derived from work published
under the GNU General Public License and retain those terms.`

	if _, ob := Classify(body); ob != ObligationShareAlike {
		t.Fatalf("Classify obligation = %v, want share-alike; a permissive tag must not outrank a copyleft sentence", ob)
	}

	_, _, err := Gate(LicenseInfo{
		FeedID:       "mislabelled-rules",
		DeclaredTier: config.LicenseTier0,
		DeclaredSPDX: "Apache-2.0",
		MetadataSPDX: "Apache-2.0",
		Mirror: buildMirror(t, feedFixture{
			feedID: "mislabelled-rules", tier: config.LicenseTier0, pinSPDX: "Apache-2.0",
			verbatim: body, notes: "Anvil record: vendor claims Apache-2.0.",
		}),
	})
	requireRefused(t, err, ErrShareAlikeQuarantine)
}

// TestBodyContradictingTheDeclaredIdentifierIsRefused covers the narrower
// identity check: both sides name something and they disagree. The body wins.
func TestBodyContradictingTheDeclaredIdentifierIsRefused(t *testing.T) {
	_, _, err := Gate(LicenseInfo{
		FeedID:       "mislabelled-cc",
		DeclaredTier: config.LicenseTier1,
		DeclaredSPDX: "CC0-1.0",
		Mirror: buildMirror(t, feedFixture{
			feedID: "mislabelled-cc", tier: config.LicenseTier1, pinSPDX: "CC0-1.0",
			verbatim: "Creative Commons Attribution 4.0 International. Attribution required.",
			notes:    "Anvil record.",
		}),
	})
	// The pin claims CC0-1.0 and the publisher's text says CC-BY-4.0. Either
	// refusal is correct; what must never happen is admission.
	requireRefused(t, err, ErrBodyContradictsDeclaration)
}

// ---------------------------------------------------------------------------
// Fail-closed
// ---------------------------------------------------------------------------

func TestGateFailsClosed(t *testing.T) {
	const feedID = "unknown-feed"
	pin := "\n[[body]]\nfeed_id = \"" + feedID + "\"\ntier = 0\ndir = \"" + feedID + "\"\n" +
		"spdx_id = \"CC0-1.0\"\ntext_url = \"https://example.invalid/L\"\n" +
		"sha256 = \"" + digestOf(kevVerbatim) + "\"\nclaim_source = \"fixture\"\n"
	manifest := "schema_version = 1\n" + pin
	verbatimPath := path.Join(TierDir(config.LicenseTier0), feedID, VerbatimFileName)

	withMirror := func(extra fstest.MapFS) fs.FS {
		m := fstest.MapFS{
			ManifestFileName: &fstest.MapFile{Data: []byte(manifest)},
			verbatimPath:     &fstest.MapFile{Data: []byte(kevVerbatim)},
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	notesAt := func(body string) fstest.MapFS {
		doc := BodyBeginMarker(feedID) + "\n" + body + "\n" + BodyEndMarker(feedID) + "\n"
		return fstest.MapFS{
			path.Join(TierDir(config.LicenseTier0), NotesFileName): &fstest.MapFile{Data: []byte(doc)},
		}
	}

	tests := []struct {
		name   string
		mirror fs.FS
		want   error
	}{
		{"no mirror tree at all", fstest.MapFS{}, ErrNoLicenseManifest},
		{"no Anvil record for this feed", withMirror(nil), ErrNoLicenseBody},
		{
			"record file exists but carries no block for this feed",
			withMirror(fstest.MapFS{
				path.Join(TierDir(config.LicenseTier0), NotesFileName): &fstest.MapFile{
					Data: []byte("# tier 0\n\nNothing here yet.\n"),
				},
			}),
			ErrNoLicenseBody,
		},
		{"record block exists but is empty", withMirror(notesAt("   \n\t\n")), ErrNoLicenseBody},
		{
			"two record blocks for one feed",
			withMirror(fstest.MapFS{
				path.Join(TierDir(config.LicenseTier0), NotesFileName): &fstest.MapFile{
					Data: []byte(BodyBeginMarker(feedID) + "\nCC0-1.0\n" + BodyEndMarker(feedID) + "\n" +
						BodyBeginMarker(feedID) + "\nApache License, Version 2.0\n" + BodyEndMarker(feedID) + "\n"),
				},
			}),
			ErrAmbiguousLicenseBody,
		},
		{
			"unterminated block swallowing the next one",
			withMirror(fstest.MapFS{
				path.Join(TierDir(config.LicenseTier0), NotesFileName): &fstest.MapFile{
					Data: []byte(BodyBeginMarker(feedID) + "\nCC0-1.0\n" +
						BodyBeginMarker("other-feed") + "\nGNU General Public License\n" +
						BodyEndMarker("other-feed") + "\n" + BodyEndMarker(feedID) + "\n"),
				},
			}),
			ErrAmbiguousLicenseBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Gate(LicenseInfo{
				FeedID:       feedID,
				DeclaredTier: config.LicenseTier0,
				DeclaredSPDX: "CC0-1.0",
				Mirror:       tc.mirror,
			})
			requireRefused(t, err, tc.want)
		})
	}

	// The publisher's text matching no marker at all: no obligation, no tier.
	t.Run("publisher text matches no licence marker", func(t *testing.T) {
		_, _, err := Gate(LicenseInfo{
			FeedID:       "opaque",
			DeclaredTier: config.LicenseTier0,
			DeclaredSPDX: "CC0-1.0",
			Mirror: buildMirror(t, feedFixture{
				feedID: "opaque", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
				verbatim: "The maintainers are friendly and the data is free of charge.",
				notes:    "Anvil record: nothing operative was found.",
			}),
		})
		requireRefused(t, err, ErrUnestablishedLicense)
	})
}

// TestGateReturnsNoTierOnEveryRefusal is A.6's minor finding. Tier 0 is the
// MOST permissive tier this system has — always mirrored, publishable, no
// copyleft — so returning it alongside an error handed the single most
// dangerous default to a caller who checked the error carelessly.
func TestGateReturnsNoTierOnEveryRefusal(t *testing.T) {
	tier, dir, err := Gate(LicenseInfo{
		FeedID:       "cisa-kev",
		DeclaredTier: config.LicenseTier0,
		DeclaredSPDX: "CC0-1.0",
		Mirror:       fstest.MapFS{},
	})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if tier != NoTier {
		t.Errorf("tier = %d on refusal, want NoTier (%d)", tier, NoTier)
	}
	if tier == config.LicenseTier0.Int() {
		t.Error("a refusal must never return tier 0; it is the most permissive tier there is")
	}
	if config.LicenseTier(tier).Valid() {
		t.Errorf("config.LicenseTier(%d).Valid() = true; the refusal value must not be a legal tier", tier)
	}
	if dir != "" {
		t.Errorf("dir = %q on refusal, want empty", dir)
	}
}

func TestRestrictiveTermsAreRefusedAtEveryTier(t *testing.T) {
	bodies := map[string]string{
		"commons clause rider":  "Licensed under LGPL-2.1 with the Commons Clause restriction applied.",
		"non-commercial only":   "This dataset is provided for non-commercial research use.",
		"internal use only":     "These rules are provided for internal business use only.",
		"unredistributable key": "You are not permitted to redistribute the feed access key.",
		"no-derivatives url":    "Published under https://creativecommons.org/licenses/by-nd/4.0/",
	}
	for name, body := range bodies {
		for _, tier := range []config.LicenseTier{
			config.LicenseTier0, config.LicenseTier1, config.LicenseTier2, config.LicenseTier3,
		} {
			_, _, err := Gate(LicenseInfo{
				FeedID:       "restricted-feed",
				DeclaredTier: tier,
				DeclaredSPDX: config.LicenseNoAssertion,
				ManualNote:   "Recorded so the refusal is diagnosable.",
				Mirror: buildMirror(t, feedFixture{
					feedID: "restricted-feed", tier: tier, pinSPDX: config.LicenseNoAssertion,
					verbatim: body, notes: "Anvil record.",
				}),
			})
			if err == nil {
				t.Fatalf("%s at tier %d was admitted", name, tier.Int())
			}
			if !errors.Is(err, ErrLicenseRefused) {
				t.Fatalf("%s at tier %d: %v does not satisfy ErrLicenseRefused", name, tier.Int(), err)
			}
		}
	}
}

func TestCISBenchmarkContentIsRefusedUnconditionally(t *testing.T) {
	// In the publisher's text.
	_, _, err := Gate(LicenseInfo{
		FeedID:       "hardening-feed",
		DeclaredTier: config.LicenseTier0,
		DeclaredSPDX: "CC0-1.0",
		Mirror: buildMirror(t, feedFixture{
			feedID: "hardening-feed", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
			verbatim: "CC0-1.0. Checks derived from the CIS Benchmark for Ubuntu.",
			notes:    "Anvil record.",
		}),
	})
	requireRefused(t, err, ErrExcludedSource)

	// In Anvil's record.
	_, _, err = Gate(LicenseInfo{
		FeedID:       "hardening-feed",
		DeclaredTier: config.LicenseTier0,
		DeclaredSPDX: "CC0-1.0",
		Mirror: buildMirror(t, feedFixture{
			feedID: "hardening-feed", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
			verbatim: kevVerbatim,
			notes:    "Anvil record: content reproduced from a CIS Benchmark document.",
		}),
	})
	requireRefused(t, err, ErrExcludedSource)

	// And in the row itself, before anything is read: the mirror below is
	// empty, so a gate that read first would have returned a different error.
	_, _, err = Gate(LicenseInfo{
		FeedID:       "hardening-feed",
		DeclaredTier: config.LicenseTier0,
		DeclaredSPDX: "CC0-1.0",
		ManualNote:   "Content reproduced from a CIS Benchmark document.",
		Mirror:       fstest.MapFS{},
	})
	requireRefused(t, err, ErrExcludedSource)
}

// ---------------------------------------------------------------------------
// A.6 M1: NONE at tier 3 was admitted on a body matching nothing
// ---------------------------------------------------------------------------

// TestNONEIsNotAdmittedOnSilence is M1's regression test.
//
// The NONE branch used to return BEFORE the ObligationUnknown refusal, so a
// document matching no marker at all — which is exactly what an unfetched page,
// a wrong URL or an HTML error page produces — was ADMITTED whenever the row
// declared NONE at tier 3. Silence is not evidence of absence.
func TestNONEIsNotAdmittedOnSilence(t *testing.T) {
	const note = "No licence document and no SPDX identifier exist; use is at the operator's risk."

	silent := feedFixture{
		feedID: "epss", tier: config.LicenseTier3, pinSPDX: config.LicenseNone,
		verbatim: "The scores are published daily and updated every morning.",
		notes:    "Anvil record: the publisher has never stated terms.",
	}
	_, err := Resolve(LicenseInfo{
		FeedID:       "epss",
		DeclaredTier: config.LicenseTier3,
		DeclaredSPDX: config.LicenseNone,
		ManualNote:   note,
		Mirror:       buildMirror(t, silent),
	})
	requireRefused(t, err, ErrUnestablishedLicense)

	// A document that POSITIVELY states no grant is the admissible shape.
	stated := silent
	stated.verbatim = "All rights reserved. No licence is granted to redistribute this data."
	d, err := Resolve(LicenseInfo{
		FeedID:       "epss",
		DeclaredTier: config.LicenseTier3,
		DeclaredSPDX: config.LicenseNone,
		ManualNote:   note,
		Mirror:       buildMirror(t, stated),
	})
	if err != nil {
		t.Fatalf("a tier 3 NONE row whose evidence states that nothing is granted was refused: %v", err)
	}
	if d.Obligation != ObligationUnknown {
		t.Errorf("obligation = %v; NONE means no grant was made, not that terms were found", d.Obligation)
	}
	if d.EffectiveSPDX != config.LicenseNone {
		t.Errorf("EffectiveSPDX = %q, want %s", d.EffectiveSPDX, config.LicenseNone)
	}
	if d.Dir != "mirror/tier3/epss" {
		t.Errorf("dir = %q, want mirror/tier3/epss", d.Dir)
	}

	// Same row without the note.
	_, err = Resolve(LicenseInfo{
		FeedID:       "epss",
		DeclaredTier: config.LicenseTier3,
		DeclaredSPDX: config.LicenseNone,
		Mirror:       buildMirror(t, stated),
	})
	requireRefused(t, err, ErrMissingManualNote)

	// Same row at a mirrored tier.
	for _, tier := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
		f := stated
		f.tier = tier
		_, err = Resolve(LicenseInfo{
			FeedID:       "epss",
			DeclaredTier: tier,
			DeclaredSPDX: config.LicenseNone,
			ManualNote:   note,
			Mirror:       buildMirror(t, f),
		})
		requireRefused(t, err, ErrUndeclaredLicenseTier)
	}

	// A NONE declaration over evidence that plainly states terms is a
	// contradiction, not a permission.
	terms := stated
	terms.verbatim = kevVerbatim
	_, err = Resolve(LicenseInfo{
		FeedID:       "epss",
		DeclaredTier: config.LicenseTier3,
		DeclaredSPDX: config.LicenseNone,
		ManualNote:   note,
		Mirror:       buildMirror(t, terms),
	})
	requireRefused(t, err, ErrBodyContradictsDeclaration)
}

// TestNONEDeclarationCannotHideAShareAlikeSource guards the reordering that M1
// forced. The restricted and share-alike checks now run BEFORE the NONE branch,
// so a row that declares no licence and whose evidence carries a reciprocity
// duty is quarantined rather than parked at tier 3 outside it.
func TestNONEDeclarationCannotHideAShareAlikeSource(t *testing.T) {
	_, err := Resolve(LicenseInfo{
		FeedID:       "sneaky",
		DeclaredTier: config.LicenseTier3,
		DeclaredSPDX: config.LicenseNone,
		ManualNote:   "operator claims no licence exists",
		Mirror: buildMirror(t, feedFixture{
			feedID: "sneaky", tier: config.LicenseTier3, pinSPDX: config.LicenseNone,
			verbatim: "All rights reserved except that derivatives must be released " +
				"under the same license as the original.",
			notes: "Anvil record.",
		}),
	})
	requireRefused(t, err, ErrShareAlikeQuarantine)
}

// ---------------------------------------------------------------------------
// A.6 M4: one definition of the shared vocabulary, not two
// ---------------------------------------------------------------------------

// TestFeedIDRulesComeFromConfigAlone is half of M4's regression test.
//
// This package used to keep its own, stricter feed-id rule: it allowed '_',
// forbade '.', and therefore structurally REFUSED a feed id the loader
// accepts. Two definitions that agree today are the produce/consume break
// IMPLEMENTATION-PLAN section 6 closed ten instances of.
func TestFeedIDRulesComeFromConfigAlone(t *testing.T) {
	accepted := []string{"osv.dev", "cvelistv5", "cisa-kev", "a1"}
	for _, id := range accepted {
		if !config.ValidFeedID(id) {
			t.Fatalf("fixture error: config.ValidFeedID(%q) is false", id)
		}
		_, _, err := Gate(LicenseInfo{
			FeedID:       id,
			DeclaredTier: config.LicenseTier0,
			DeclaredSPDX: "CC0-1.0",
			Mirror: buildMirror(t, feedFixture{
				feedID: id, tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
				verbatim: kevVerbatim, notes: kevNotes,
			}),
		})
		if err != nil {
			t.Errorf("feed id %q is accepted by internal/ingest/config but the gate refused it: %v", id, err)
		}
	}

	rejected := []string{"", "..", ".", "a/b", `a\b`, "Alpha", "-lead", "trail-", "a--b", ".hidden"}
	for _, id := range rejected {
		if config.ValidFeedID(id) {
			t.Errorf("config.ValidFeedID(%q) = true; the gate and the loader must both refuse it", id)
		}
	}
}

// TestNONETokenIsRecognisedCaseInsensitively is the other half of M4. The
// loader compared the token with == while this package compared with EqualFold,
// so `license_spdx: none` loaded clean at tier 0 there and was refused here.
// Both now call config.SPDXIsNone.
func TestNONETokenIsRecognisedCaseInsensitively(t *testing.T) {
	for _, tok := range []string{"NONE", "none", "None", " none "} {
		if !config.SPDXIsNone(tok) {
			t.Fatalf("config.SPDXIsNone(%q) = false", tok)
		}
		_, err := Resolve(LicenseInfo{
			FeedID:       "epss",
			DeclaredTier: config.LicenseTier0, // a mirrored tier: illegal for NONE
			DeclaredSPDX: tok,
			ManualNote:   "no grant of rights exists",
			Mirror: buildMirror(t, feedFixture{
				feedID: "epss", tier: config.LicenseTier0, pinSPDX: config.LicenseNone,
				verbatim: "All rights reserved. No licence is granted.",
				notes:    "Anvil record.",
			}),
		})
		requireRefused(t, err, ErrUndeclaredLicenseTier)
	}
	if config.SPDXResolvable("noassertion") || config.SPDXResolvable("licenseref-x") {
		t.Error("SPDXResolvable must fold case for NOASSERTION and LicenseRef- too")
	}
}

// ---------------------------------------------------------------------------
// Structural refusals
// ---------------------------------------------------------------------------

func TestStructuralRefusals(t *testing.T) {
	mirror := buildMirror(t, feedFixture{
		feedID: "feed", tier: config.LicenseTier0, pinSPDX: "CC0-1.0",
		verbatim: kevVerbatim, notes: kevNotes,
	})
	base := func() LicenseInfo {
		return LicenseInfo{
			FeedID:       "feed",
			DeclaredTier: config.LicenseTier0,
			DeclaredSPDX: "CC0-1.0",
			Mirror:       mirror,
		}
	}

	tests := []struct {
		name  string
		mutte func(*LicenseInfo)
	}{
		{"no feed id", func(i *LicenseInfo) { i.FeedID = "" }},
		{"feed id with a separator", func(i *LicenseInfo) { i.FeedID = "a/b" }},
		{"feed id escaping the tree", func(i *LicenseInfo) { i.FeedID = ".." }},
		{"directory escaping the tree", func(i *LicenseInfo) { i.Dir = "../../etc" }},
		{"directory with a backslash", func(i *LicenseInfo) { i.Dir = `a\b` }},
		{"upper-case directory", func(i *LicenseInfo) { i.Dir = "Ubuntu" }},
		{"tier below range", func(i *LicenseInfo) { i.DeclaredTier = config.LicenseTier(-1) }},
		{"tier above range", func(i *LicenseInfo) { i.DeclaredTier = config.LicenseTier(4) }},
		{"no declared licence", func(i *LicenseInfo) { i.DeclaredSPDX = "  " }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := base()
			tc.mutte(&info)
			_, _, err := Gate(info)
			requireRefused(t, err, ErrInvalidLicenseInfo)
		})
	}
}

func TestCheckWritePathRejectsAnInvalidTier(t *testing.T) {
	if err := CheckWritePath(config.LicenseTier(9), "mirror/tier9/x"); !errors.Is(err, ErrInvalidLicenseInfo) {
		t.Fatalf("CheckWritePath with tier 9 = %v, want ErrInvalidLicenseInfo", err)
	}
	if err := CheckWritePath(config.LicenseTier0, "  "); !errors.Is(err, ErrTierRouting) {
		t.Fatalf("CheckWritePath with an empty path = %v, want ErrTierRouting", err)
	}
	if got := TierDir(config.LicenseTier(9)); got != "" {
		t.Errorf("TierDir(9) = %q; an invalid tier has no directory and must not invent one", got)
	}
}

// ---------------------------------------------------------------------------
// The classifier
// ---------------------------------------------------------------------------

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		body string
		spdx string
		ob   Obligation
	}{
		{"cc0 legalcode", kevVerbatim, "CC0-1.0", ObligationPublicDomain},
		{"cc-by 4.0 prose", "licensed under the terms of the CC-BY 4.0 open source license", "CC-BY-4.0", ObligationNotice},
		{"cc-by-sa identifier", "SPDX-License-Identifier: CC-BY-SA-4.0", "CC-BY-SA-4.0", ObligationShareAlike},
		{"odbl database licence", "is a database licensed under the Open Database License version 1.0", "ODbL-1.0", ObligationShareAlike},
		{"gpl without an identifier", "distributed under the GNU General Public License", "", ObligationShareAlike},
		{"us government work", "This is a United States Government work in the public domain.",
			"LicenseRef-US-Gov-Public-Domain", ObligationPublicDomain},
		{"mitre terms of use", "Use of the CWE List is permitted with attribution required.", "", ObligationNotice},
		{"cve programme terms", "CVE Program Terms of Use; attribution required.", "CVE-TOU", ObligationNotice},
		{"nothing at all", "The maintainers are friendly.", "", ObligationUnknown},
		{"strongest wins over first", "Apache License, Version 2.0 ... and the GNU Affero General Public License", "", ObligationShareAlike},
		{"restricted beats share-alike", "LGPL-2.1 with the Commons Clause applied", "", ObligationRestricted},
		{"reciprocity without a name", "derivatives must be distributed under the same terms", "", ObligationShareAlike},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spdx, ob := Classify(tc.body)
			if ob != tc.ob {
				t.Errorf("obligation = %v, want %v", ob, tc.ob)
			}
			if spdx != tc.spdx {
				t.Errorf("spdx = %q, want %q", spdx, tc.spdx)
			}
		})
	}
}

func TestStatesNoGrant(t *testing.T) {
	yes := []string{
		"All rights reserved.",
		"No licence is granted for redistribution.",
		"no license is granted",
		"The publisher reserves all rights.",
	}
	no := []string{
		"The scores are published daily, free of charge, with no registration required.",
		"Attribution is requested.",
		"",
		"The maintainers are friendly.",
	}
	for _, s := range yes {
		if !StatesNoGrant(s) {
			t.Errorf("StatesNoGrant(%q) = false", s)
		}
	}
	for _, s := range no {
		if StatesNoGrant(s) {
			t.Errorf("StatesNoGrant(%q) = true; silence and courtesy wording are not a statement "+
				"that nothing was granted — that is the hole M1 closed", s)
		}
	}
}

func TestObligationOrderingIsRestrictivenessOrdering(t *testing.T) {
	ordered := []Obligation{
		ObligationUnknown, ObligationPublicDomain, ObligationNotice,
		ObligationShareAlike, ObligationRestricted,
	}
	for i := 1; i < len(ordered); i++ {
		if !(ordered[i-1] < ordered[i]) {
			t.Fatalf("%v must rank below %v; Classify takes the maximum and the whole "+
				"mislabelled-artifact defence depends on this order", ordered[i-1], ordered[i])
		}
	}
	if ObligationUnknown != 0 {
		t.Error("ObligationUnknown must be the zero value so an unset obligation is a refusal, never a permissive default")
	}
}

// ---------------------------------------------------------------------------
// The checked-in mirror tree
// ---------------------------------------------------------------------------

// repoFS is the repository root, which is where mirror/ sits.
func repoFS(t *testing.T) fs.FS {
	t.Helper()
	root := path.Join("..", "..", "..")
	if _, err := os.Stat(path.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot locate the repository root from the package directory: %v", err)
	}
	return os.DirFS(root)
}

// TestCheckedInManifestParsesAndPinsEveryMirroredFeed asserts that the real
// mirror/LICENSE-MANIFEST.toml is well formed and that every feed in the real
// example table which is expected to be mirrorable has a pin.
func TestCheckedInManifestParsesAndPinsEveryMirroredFeed(t *testing.T) {
	m, err := LoadManifest(repoFS(t))
	if err != nil {
		t.Fatalf("the checked-in licence manifest does not parse: %v", err)
	}
	if len(m.FeedIDs()) == 0 {
		t.Fatal("the checked-in manifest pins nothing")
	}

	set, err := config.Load(path.Join("..", "config", config.ExampleFileName))
	if err != nil {
		t.Fatalf("loading the example feed table: %v", err)
	}
	for _, f := range set.Feeds {
		pin, ok := m.Body(f.ID)
		if !ok {
			// EPSS is deliberately unpinnable: research/01 S18/S19 record no
			// licence document at all, so there is no publisher text to pin
			// and the gate refuses the feed permanently.
			if f.ID == "epss" {
				continue
			}
			t.Errorf("feed %q has no entry in %s", f.ID, ManifestFileName)
			continue
		}
		if pin.Tier != f.LicenseTier {
			t.Errorf("feed %q: manifest pins tier %d, the feed table says %d",
				f.ID, pin.Tier.Int(), f.LicenseTier.Int())
		}
		if pin.Dir != f.MirrorDir {
			t.Errorf("feed %q: manifest pins dir %q, the feed table says mirror_dir %q",
				f.ID, pin.Dir, f.MirrorDir)
		}
	}
}

// TestFreshCloneAdmitsNoFeed is the headline regression test for A.6's central
// finding, run against the REAL repository tree.
//
// Before the rework, every enabled feed in the example table was admitted by a
// fresh clone, on evidence Anvil had written in the same commit. Now every one
// of them is refused for want of the publisher's own text. The refusal is the
// deliverable: this test fails the day someone reintroduces admission-on-prose.
func TestFreshCloneAdmitsNoFeed(t *testing.T) {
	fsys := repoFS(t)
	set, err := config.Load(path.Join("..", "config", config.ExampleFileName))
	if err != nil {
		t.Fatalf("loading the example feed table: %v", err)
	}
	if len(set.Feeds) == 0 {
		t.Fatal("the example feed table is empty")
	}

	status, err := MirrorStatus(fsys)
	if err != nil {
		t.Fatalf("MirrorStatus: %v", err)
	}
	acquired := map[string]bool{}
	for _, s := range status {
		acquired[s.Pin.FeedID] = s.State == BodyVerified
	}

	var refused int
	for _, f := range set.Feeds {
		t.Run(f.ID, func(t *testing.T) {
			info := FromFeed(f, "", fsys)
			_, _, err := Gate(info)

			if acquired[f.ID] {
				// The operator has done the work. This is no longer a
				// fresh-clone assertion; skip loudly rather than pretend.
				t.Skipf("feed %q has an acquired and pinned licence body, so the fresh-clone "+
					"assertion does not apply here", f.ID)
			}
			if err == nil {
				t.Fatalf("feed %q was ADMITTED by a clone that contains no publisher licence "+
					"text. That is the exact defect A.6 failed A.4 for: the gate validated the "+
					"feed row against a document Anvil wrote in the same commit.", f.ID)
			}
			if !errors.Is(err, ErrLicenseRefused) {
				t.Fatalf("feed %q: %v does not satisfy ErrLicenseRefused", f.ID, err)
			}
			if !errors.Is(err, ErrUnpinnedLicenseBody) && !errors.Is(err, ErrNoLicenseBody) {
				t.Errorf("feed %q refused for an unexpected reason: %v", f.ID, err)
			}
			refused++
		})
	}
	if refused == 0 {
		t.Fatal("no feed was gated against the checked-in tree; the test proved nothing")
	}
}

// TestPinnedLicenceBodiesMatchTheirPins is the mirror-integration test. On a
// fresh clone it SKIPS, with a reason naming the exact artefact that is missing
// and the command that produces it. It never passes quietly on absent evidence.
func TestPinnedLicenceBodiesMatchTheirPins(t *testing.T) {
	status, err := MirrorStatus(repoFS(t))
	if err != nil {
		t.Fatalf("MirrorStatus: %v", err)
	}
	if len(status) == 0 {
		t.Fatal("the checked-in manifest pins nothing")
	}

	var verified int
	for _, s := range status {
		t.Run(s.Pin.FeedID, func(t *testing.T) {
			switch s.State {
			case BodyVerified:
				verified++
				if s.Obligation == ObligationUnknown {
					t.Errorf("%s: the acquired text matched no licence marker; the pinned url "+
						"may not be the publisher's operative text (%s)", s.Pin.Path(), s.Pin.TextURL)
				}
				if s.Pin.Tier == config.LicenseTier2 && !s.Obligation.ShareAlike() {
					t.Errorf("%s classifies as %v; tier 2 is exactly the share-alike quarantine",
						s.Pin.Path(), s.Obligation)
				}
				if s.Pin.Tier == config.LicenseTier0 || s.Pin.Tier == config.LicenseTier1 {
					// The inverted default, checked against the bytes the
					// operator actually acquired rather than against a fixture.
					// Three of these text_urls are html pages, so this is also
					// where "the signature was provisional and the real page
					// does not match it" surfaces — as a failure naming the
					// file, before the gate refuses the feed in production.
					raw, readErr := fs.ReadFile(repoFS(t), s.Pin.Path())
					if readErr != nil {
						t.Fatalf("%s: %v", s.Pin.Path(), readErr)
					}
					if _, _, _, ok := IdentifyPermissive(string(raw)); !ok {
						t.Errorf("%s is pinned at the publishable tier %d but is not positively "+
							"identified as any enumerated permissive licence, so the gate will "+
							"refuse the feed. Read the acquired text and record its operative "+
							"wording in publishable.go — do not widen a signature until "+
							"something passes", s.Pin.Path(), s.Pin.Tier.Int())
					}
				}
			case BodyMismatch:
				t.Fatalf("%s", s)
			default:
				t.Skipf("%s", s)
			}
		})
	}
	if verified == 0 {
		t.Log("no publisher licence text is acquired in this tree, so nothing was verified. " +
			"That is the expected state of a fresh clone: run " + AcquireCommand)
	}
}

// TestTier2DirectoriesCarryTheirOwnNonEmptyLicense is A.4's stop condition:
// "mirror/tier2/{ubuntu,alpine,osv}/LICENSE exist and are non-empty".
func TestTier2DirectoriesCarryTheirOwnNonEmptyLicense(t *testing.T) {
	fsys := repoFS(t)
	for _, dir := range []string{"ubuntu", "alpine", "osv"} {
		p := path.Join(TierDir(config.LicenseTier2), dir, LicenseFileName)
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if strings.TrimSpace(string(data)) == "" {
			t.Errorf("%s is empty", p)
			continue
		}
		if _, ob := Classify(string(data)); !ob.ShareAlike() {
			t.Errorf("%s classifies as %v; every tier 2 directory is share-alike by definition", p, ob)
		}
		// A.6: the file must not claim a control the code does not implement.
		text := string(data)
		if !strings.Contains(text, "NOT ENFORCED IN CODE") {
			t.Errorf("%s does not separate what the code enforces from what it does not; a "+
				"licence file that overstates its controls is a compliance liability", p)
		}
		if strings.Contains(text, "RULES, enforced by internal/ingest/license") {
			t.Errorf("%s still asserts that every rule below it is enforced in code. The "+
				"no-merged-corpus rule is not, and cannot be: nothing here observes a publication.", p)
		}
	}

	for _, tier := range []config.LicenseTier{config.LicenseTier0, config.LicenseTier1} {
		p := path.Join(TierDir(tier), NotesFileName)
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if strings.TrimSpace(string(data)) == "" {
			t.Errorf("%s is empty", p)
		}
	}
}

// TestNVDRecordCitesTheLicenceSource is A.6's M3. The NVD block cited
// research/01 S6, which is NIST's enrichment-volume announcement and says
// nothing about licensing. A wrong citation is worse than none, because the
// next reviewer follows it and cannot tell whether the claim or the pointer is
// the error.
func TestNVDRecordCitesTheLicenceSource(t *testing.T) {
	data, err := fs.ReadFile(repoFS(t), path.Join(TierDir(config.LicenseTier0), NotesFileName))
	if err != nil {
		t.Fatalf("%v", err)
	}
	block, err := extractBlock(string(data), "nvd", "tier0 notes")
	if err != nil {
		t.Fatalf("extracting the nvd record: %v", err)
	}
	// The citation is the `Source:` paragraph that follows the block. It is
	// read on its own: prose elsewhere in the section explains the correction
	// and necessarily names S6, and a test that searched the whole section
	// would pass on a document that still mis-cited the licence.
	idx := strings.Index(string(data), BodyEndMarker("nvd"))
	if idx < 0 {
		t.Fatal("no nvd record block in the tier 0 notes")
	}
	tail := string(data)[idx:]
	src := strings.Index(tail, "Source:")
	if src < 0 {
		t.Fatal("the nvd record carries no Source: citation")
	}
	cite := tail[src:]
	if end := strings.Index(cite, "\n\n"); end > 0 {
		cite = cite[:end]
	}
	if !strings.Contains(cite, "S5") {
		t.Errorf("the nvd licence citation does not name research/01 S5, the NVD General FAQs "+
			"and the only source in the corpus that states the licence:\n%s", cite)
	}
	if strings.Contains(cite, "S6") {
		t.Errorf("the nvd licence citation still points at research/01 S6, which is NIST's "+
			"enrichment-volume announcement and says nothing about licensing:\n%s", cite)
	}
	if strings.Contains(block, "S6") {
		t.Error("the nvd record block still cites S6 for its licence conclusion")
	}
	if _, ob := Classify(block); ob != ObligationPublicDomain {
		t.Errorf("the nvd record classifies as %v, want public-domain", ob)
	}
}

// TestDecisionManifestRow checks the projection onto the A.2 cache's
// license_dir_manifest table, whose columns are (directory, tier, license_file,
// spdx_id) and whose only writer is this gate.
func TestDecisionManifestRow(t *testing.T) {
	d, err := Resolve(LicenseInfo{
		FeedID:       "ubuntu-osv",
		Dir:          "ubuntu",
		DeclaredTier: config.LicenseTier2,
		DeclaredSPDX: "CC-BY-SA-4.0",
		Mirror: buildMirror(t, feedFixture{
			feedID: "ubuntu-osv", tier: config.LicenseTier2, dir: "ubuntu",
			pinSPDX: "CC-BY-SA-4.0", verbatim: shareAlikeVerbatim, notes: shareAlikeNotes,
		}),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	row, err := d.ManifestRow()
	if err != nil {
		t.Fatalf("ManifestRow on an admitted decision: %v", err)
	}
	if row.Directory != "mirror/tier2/ubuntu" || row.Tier != 2 ||
		row.LicenseFile != "mirror/tier2/ubuntu/LICENSE.full.txt" || row.SPDXID != "CC-BY-SA-4.0" {
		t.Fatalf("manifest row = %+v", row)
	}
	if strings.HasSuffix(row.LicenseFile, LicenseFileName) {
		t.Error("license_file names Anvil's own record; it must name the publisher's text")
	}
}

// TestARefusalHasNoManifestRow is the regression test for the projection that
// bypassed Refused.
//
// `Decision{}.ManifestRow()` used to return Directory "" with Tier 0 and no
// error at all. Tier 0 is a VALID tier and the most permissive one this system
// has, so a caller that projected before checking — or instead of checking —
// wrote "tier 0" into `license_dir_manifest`, which is the A.2 cache's record
// of which directories may be merged into a published artifact. The zero
// Decision is the shape that matters: it is what a future code path produces by
// forgetting to fill a field, and nothing at the call site looks wrong.
//
// MEASURED against the pre-fix method: every case below returns a row with
// Tier 0 and a nil error.
func TestARefusalHasNoManifestRow(t *testing.T) {
	cases := map[string]Decision{
		"the zero Decision":     {},
		"a Resolve refusal":     {FeedID: "x", Tier: NoTier},
		"tier set but no dir":   {FeedID: "x", Tier: config.LicenseTier1},
		"dir set but no tier":   {FeedID: "x", Tier: NoTier, Dir: "mirror/tier1/x"},
		"tier 0 with empty dir": {FeedID: "x", Tier: config.LicenseTier0},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if !d.Refused() {
				t.Fatalf("fixture error: %+v does not report itself refused, so this case is "+
					"not about a refusal", d)
			}
			row, err := d.ManifestRow()
			if err == nil {
				t.Fatalf("projected a refusal onto the cache manifest without complaint: %+v", row)
			}
			if !errors.Is(err, ErrLicenseRefused) {
				t.Errorf("the error does not satisfy ErrLicenseRefused, so a caller switching on "+
					"that sentinel drops it: %v", err)
			}
			if config.LicenseTier(row.Tier).Valid() {
				t.Errorf("the row carries the valid tier %d; tier 0 in license_dir_manifest is "+
					"permission to merge", row.Tier)
			}
			if row.Directory != "" {
				t.Errorf("the row names the directory %q", row.Directory)
			}
		})
	}
}
