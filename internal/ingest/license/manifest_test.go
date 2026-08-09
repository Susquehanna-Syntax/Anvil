package license

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
)

const goodManifest = `# a manifest
schema_version = 1
generated_utc = "2026-08-09"
generated_by = "manifest_test"

[[body]]
feed_id = "cisa-kev"
tier = 0
dir = "cisa-kev"
spdx_id = "CC0-1.0"
text_url = "https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt"
sha256 = ""
claim_url = "https://example.invalid/README.md"
claim_source = "research/01 S16"
note = "a note with an escaped \" quote in it"

[[body]]
feed_id = "ubuntu-osv"
tier = 2
dir = "ubuntu"
spdx_id = "CC-BY-SA-4.0"
text_url = "https://creativecommons.org/licenses/by-sa/4.0/legalcode.txt"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
claim_source = "research/01 S7"
`

func TestParseManifest(t *testing.T) {
	m, err := parseManifest(goodManifest)
	if err != nil {
		t.Fatalf("parseManifest: %v", err)
	}
	if m.SchemaVersion != ManifestSchemaVersion || m.GeneratedBy != "manifest_test" {
		t.Errorf("top level = %+v", m)
	}
	if got := m.FeedIDs(); len(got) != 2 || got[0] != "cisa-kev" || got[1] != "ubuntu-osv" {
		t.Errorf("FeedIDs = %v, want document order", got)
	}

	kev, ok := m.Body("cisa-kev")
	if !ok {
		t.Fatal("cisa-kev missing")
	}
	if kev.Pinned() {
		t.Error("an empty sha256 must not count as pinned; that is the whole fail-closed rule")
	}
	if kev.Path() != "mirror/tier0/cisa-kev/LICENSE.full.txt" {
		t.Errorf("Path = %q", kev.Path())
	}
	if !strings.Contains(kev.Note, `escaped " quote`) {
		t.Errorf("escape handling: note = %q", kev.Note)
	}

	ubuntu, _ := m.Body("ubuntu-osv")
	if !ubuntu.Pinned() {
		t.Error("a 64-hex sha256 must count as pinned")
	}
	if ubuntu.Tier != config.LicenseTier2 || ubuntu.Dir != "ubuntu" {
		t.Errorf("ubuntu pin = %+v", ubuntu)
	}
	if ubuntu.Path() != "mirror/tier2/ubuntu/LICENSE.full.txt" {
		t.Errorf("Path = %q", ubuntu.Path())
	}

	if un := m.Unpinned(); len(un) != 1 || un[0].FeedID != "cisa-kev" {
		t.Errorf("Unpinned = %v, want exactly cisa-kev", un)
	}
}

// TestParseManifestRefusesEverythingItDoesNotUnderstand is the parser's whole
// contract. A permissive parser in front of a fail-closed gate does not remove
// the failure, it moves it somewhere quieter — so an unknown key, a duplicate,
// a missing required field or a value shape it cannot represent is an error and
// never a default.
func TestParseManifestRefusesEverythingItDoesNotUnderstand(t *testing.T) {
	cases := map[string]string{
		"no schema version": strings.Replace(goodManifest, "schema_version = 1\n", "", 1),
		"future schema version": strings.Replace(goodManifest,
			"schema_version = 1", "schema_version = 2", 1),
		"unknown top-level key": strings.Replace(goodManifest,
			"generated_by =", "generated_by_someone =", 1),
		"unknown body key": strings.Replace(goodManifest,
			"claim_source = \"research/01 S16\"", "claim_srouce = \"typo\"", 1),
		"missing required key": strings.Replace(goodManifest,
			"text_url = \"https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt\"\n", "", 1),
		"duplicate key in one body": strings.Replace(goodManifest,
			"claim_source = \"research/01 S16\"",
			"claim_source = \"research/01 S16\"\nclaim_source = \"and again\"", 1),
		"two pins for one feed": goodManifest + "\n[[body]]\nfeed_id = \"cisa-kev\"\ntier = 0\n" +
			"dir = \"cisa-kev\"\nspdx_id = \"CC0-1.0\"\ntext_url = \"https://x.invalid/L\"\n" +
			"sha256 = \"\"\nclaim_source = \"twice\"\n",
		"tier outside the four": strings.Replace(goodManifest, "tier = 2", "tier = 9", 1),
		"non-integer tier":      strings.Replace(goodManifest, "tier = 0", "tier = \"zero\"", 1),
		"illegal feed id": strings.Replace(goodManifest,
			"feed_id = \"cisa-kev\"", "feed_id = \"../etc\"", 1),
		"illegal directory": strings.Replace(goodManifest,
			"dir = \"ubuntu\"", "dir = \"../../etc\"", 1),
		"http text url": strings.Replace(goodManifest,
			"https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt",
			"http://creativecommons.org/publicdomain/zero/1.0/legalcode.txt", 1),
		"empty spdx id": strings.Replace(goodManifest,
			"spdx_id = \"CC0-1.0\"", "spdx_id = \"\"", 1),
		"empty claim source": strings.Replace(goodManifest,
			"claim_source = \"research/01 S16\"", "claim_source = \"  \"", 1),
		"half-length digest": strings.Replace(goodManifest,
			"sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"",
			"sha256 = \"0000\"", 1),
		"upper-case digest": strings.Replace(goodManifest,
			"sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"",
			"sha256 = \"AAAA000000000000000000000000000000000000000000000000000000000000\"", 1),
		"non-hex digest": strings.Replace(goodManifest,
			"sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"",
			"sha256 = \"zzzz000000000000000000000000000000000000000000000000000000000000\"", 1),
		"unknown table":           goodManifest + "\n[[excluded]]\nfeed_id = \"x\"\n",
		"line that is not a pair": goodManifest + "\njust some prose\n",
		"unterminated string": strings.Replace(goodManifest,
			"generated_by = \"manifest_test\"", "generated_by = \"manifest_test", 1),
		"trailing content after a value": strings.Replace(goodManifest,
			"generated_by = \"manifest_test\"", "generated_by = \"manifest_test\" oops", 1),
		"unsupported escape": strings.Replace(goodManifest,
			"generated_by = \"manifest_test\"", `generated_by = "manifest\ntest"`, 1),
		"negative integer": strings.Replace(goodManifest, "tier = 0", "tier = -1", 1),
		"bare word value":  strings.Replace(goodManifest, "sha256 = \"\"", "sha256 = unpinned", 1),
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if doc == goodManifest {
				t.Fatal("fixture error: the mutation did not change the document")
			}
			_, err := parseManifest(doc)
			if err == nil {
				t.Fatalf("parseManifest accepted a manifest it should refuse")
			}
			if !errors.Is(err, ErrLicenseRefused) {
				t.Errorf("%v does not satisfy ErrLicenseRefused", err)
			}
		})
	}
}

func TestLoadManifestMissingFileIsARefusal(t *testing.T) {
	_, err := LoadManifest(fstest.MapFS{})
	requireRefused(t, err, ErrNoLicenseManifest)
}

// TestMirrorStatusExplainsEveryState is what the skipping tests and the
// operator both read. A status line has to name the artefact and the command,
// or a fail-closed gate is just an outage with no exit.
func TestMirrorStatusExplainsEveryState(t *testing.T) {
	body := "Creative Commons Attribution 4.0 International. Attribution required."
	manifest := "schema_version = 1\n" +
		"\n[[body]]\nfeed_id = \"pinned-ok\"\ntier = 1\ndir = \"pinned-ok\"\n" +
		"spdx_id = \"CC-BY-4.0\"\ntext_url = \"https://x.invalid/a\"\nsha256 = \"" + digestOf(body) + "\"\n" +
		"claim_source = \"fixture\"\n" +
		"\n[[body]]\nfeed_id = \"mismatched\"\ntier = 1\ndir = \"mismatched\"\n" +
		"spdx_id = \"CC-BY-4.0\"\ntext_url = \"https://x.invalid/b\"\nsha256 = \"" +
		strings.Repeat("b", 64) + "\"\nclaim_source = \"fixture\"\n" +
		"\n[[body]]\nfeed_id = \"unpinned\"\ntier = 1\ndir = \"unpinned\"\n" +
		"spdx_id = \"CC-BY-4.0\"\ntext_url = \"https://x.invalid/c\"\nsha256 = \"\"\n" +
		"claim_source = \"fixture\"\n" +
		"\n[[body]]\nfeed_id = \"never-fetched\"\ntier = 1\ndir = \"never-fetched\"\n" +
		"spdx_id = \"CC-BY-4.0\"\ntext_url = \"https://x.invalid/d\"\nsha256 = \"" +
		strings.Repeat("c", 64) + "\"\nclaim_source = \"fixture\"\n"

	fsys := fstest.MapFS{
		ManifestFileName: &fstest.MapFile{Data: []byte(manifest)},
		"mirror/tier1/pinned-ok/LICENSE.full.txt":  &fstest.MapFile{Data: []byte(body)},
		"mirror/tier1/mismatched/LICENSE.full.txt": &fstest.MapFile{Data: []byte(body)},
		"mirror/tier1/unpinned/LICENSE.full.txt":   &fstest.MapFile{Data: []byte(body)},
	}

	got := map[string]BodyStatus{}
	status, err := MirrorStatus(fsys)
	if err != nil {
		t.Fatalf("MirrorStatus: %v", err)
	}
	for _, s := range status {
		got[s.Pin.FeedID] = s
	}

	want := map[string]BodyState{
		"pinned-ok":     BodyVerified,
		"mismatched":    BodyMismatch,
		"unpinned":      BodyUnpinned,
		"never-fetched": BodyMissing,
	}
	for feed, state := range want {
		s, ok := got[feed]
		if !ok {
			t.Fatalf("%s missing from the status report", feed)
		}
		if s.State != state {
			t.Errorf("%s: state = %v, want %v", feed, s.State, state)
		}
		line := s.String()
		if !strings.Contains(line, feed) {
			t.Errorf("%s: status line does not name the feed: %s", feed, line)
		}
		if state != BodyVerified && !strings.Contains(line, "acquire-license-bodies") &&
			!strings.Contains(line, s.Pin.Path()) {
			t.Errorf("%s: status line names neither the artefact nor the command: %s", feed, line)
		}
	}
	if got["pinned-ok"].Obligation != ObligationNotice {
		t.Errorf("a verified body must report the obligation an operator is about to pin, got %v",
			got["pinned-ok"].Obligation)
	}
}
