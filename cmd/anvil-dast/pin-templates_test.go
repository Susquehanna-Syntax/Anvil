// Tests for plan step D.17.
//
// The packet's stated validation is one sentence: "Test with a synthetic
// upstream diff containing a new `code:` template asserting it is flagged and
// blocked from auto-promotion." That is
// TestDiff_NewCodeProtocolTemplateBlocksPromotion and
// TestCLI_CodeTemplateBlocksPromotionEndToEnd, and everything else here exists
// because the surrounding machinery has to be un-bypassable for that one
// assertion to mean anything:
//
//   - a pin that accepts a branch name is not a pin       -> TestPinValid_*
//   - a diff keyed on path reports a move as a rewrite    -> TestDiff_KeysOnIdentityNotPath
//   - a copy that shares its slice leaks the original     -> TestSnapshotCopies*
//   - a report nobody computed must not be promotable     -> TestPromote_Refusals
//   - "git is missing" must never render as "no changes"  -> TestCLI_ToolAbsent*
//
// No test here reaches the network. The CorpusSource seam is driven by
// fixtureSource, which is the same interface gitSource implements, so the
// command paths under test are the command paths production runs.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/engines"
)

// ---------------------------------------------------------------------------
// The other half of the artifact split
// ---------------------------------------------------------------------------

// TestSplit_DASTBinaryActuallyLinksTheDASTTier is the POSITIVE half of the
// S9-AMENDED two-artifact split, and it exists because until this file landed
// the split was satisfied by emptiness in both directions.
//
// TestSplit_CoreBinaryHasNoDASTCapability (../anvil/split_test.go) asserts
// that `go list -deps ./cmd/anvil` names no internal/dast package. That was
// true, and it was also true of `go list -deps ./cmd/anvil-dast`, because
// cmd/anvil-dast was a 32-line placeholder that imported nothing. A guard
// whose subject does not exist passes for free: the whole DAST kernel could
// have been deleted and both halves would have stayed green.
//
// So this asserts the relation rather than one side of it. cmd/anvil-dast must
// REACH the tier; cmd/anvil must NOT; and the two dependency sets must be
// disjoint over internal/dast. Deleting the kernel, or moving this file's
// engines import out, fails here instead of quietly making the other test
// vacuous again.
//
// It shells out to `go list`, whose output Go's test cache does not track, so
// it needs -count=1 for the same reason ../anvil/split_test.go spells out at
// length. CI's `go test -race -count=1 ./...` lane supplies it.
func TestSplit_DASTBinaryActuallyLinksTheDASTTier(t *testing.T) {
	const tier = "/internal/dast"

	deps := func(pkg string) []string {
		t.Helper()
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			var stderr string
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				stderr = string(ee.Stderr)
			}
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, stderr)
		}
		var hits []string
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, tier) {
				hits = append(hits, line)
			}
		}
		return hits
	}

	dastSide := deps(".")
	coreSide := deps(filepath.Join("..", "anvil"))

	if len(dastSide) == 0 {
		t.Fatalf("cmd/anvil-dast reaches ZERO %s packages. The two-artifact split is then "+
			"satisfied by emptiness: the negative half in ../anvil/split_test.go would "+
			"keep passing if the entire DAST tier were deleted, because there would be "+
			"nothing for either binary to link. This file's import of "+
			"internal/dast/engines is what makes the positive half mean something.", tier)
	}
	// Name the packages the DAST binary is expected to carry, by identity.
	// A bare count would keep passing if engines were swapped for something
	// unrelated under the same prefix.
	for _, want := range []string{
		"github.com/Susquehanna-Syntax/Anvil/internal/dast/engines",
		"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz",
	} {
		var found bool
		for _, got := range dastSide {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("cmd/anvil-dast does not reach %s; it reaches:\n  %s",
				want, strings.Join(dastSide, "\n  "))
		}
	}

	if len(coreSide) != 0 {
		t.Fatalf("cmd/anvil reaches %d %s package(s):\n  %s\nThe core binary must ship with "+
			"no network-probing capability compiled in (plan/00-SPINE.md S9-AMENDED).",
			len(coreSide), tier, strings.Join(coreSide, "\n  "))
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// okTemplate is the shape engines.LoadTemplates admits: id, info and http at
// column 0 and nothing else.
func okTemplate(id, body string) string {
	return fmt.Sprintf(`id: %s
info:
  name: fixture %s
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/%s"
`, id, id, body)
}

// codeTemplate is the poisoning shape: a `code:` block, which
// plan/00-SPINE.md S5 excludes outright.
func codeTemplate(id string) string {
	return fmt.Sprintf(`id: %s
info:
  name: exfiltrate
  severity: critical
code:
  - engine:
      - sh
    source: |
      cat /etc/shadow
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`, id)
}

// headlessTemplate is refused by the loader but is NOT a spine S5 hard
// exclusion, so it must be reported without blocking.
func headlessTemplate(id string) string {
	return fmt.Sprintf(`id: %s
info:
  name: browser
  severity: info
headless:
  - steps:
      - action: navigate
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`, id)
}

// writeTree materialises a map of relative paths to contents under a fresh
// temp directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeInto(t, root, files)
	return root
}

func writeInto(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}

// baseCorpus is the "pinned" tree: two admitted templates and one pre-existing
// refusal, so that a NEW refusal in a candidate tree is distinguishable from a
// refusal that was always there.
func baseCorpus() map[string]string {
	return map[string]string{
		"http/alpha.yaml":          okTemplate("anvil-alpha", "a"),
		"http/beta.yaml":           okTemplate("anvil-beta", "b"),
		"headless/existing.yaml":   headlessTemplate("anvil-existing-headless"),
		"LICENSE.md":               "placeholder, overwritten by tests that care",
		".github/workflows/ci.yml": "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n",
	}
}

// snapshotOf loads a corpus map at sha.
func snapshotOf(t *testing.T, sha string, files map[string]string) Snapshot {
	t.Helper()
	s, err := SnapshotDir(sha, writeTree(t, files))
	if err != nil {
		t.Fatalf("SnapshotDir(%s): %v", sha, err)
	}
	return s
}

const (
	// pinnedSHA is the real in-tree pin. The FROM side of every diff must be
	// this, because Diff refuses any other -- which is itself under test.
	pinnedSHA = pinnedCommitSHA
	// candidateSHA is a syntactically valid commit SHA that is not the pin.
	candidateSHA = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"
)

// archivedLicence reads the licence body this repository actually ships.
func archivedLicence(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(archivedLicencePath)))
	if err != nil {
		t.Fatalf("reading the archived licence at %s: %v", archivedLicencePath, err)
	}
	return b
}

func goodProbe(t *testing.T) LicenceProbe {
	t.Helper()
	return LicenceProbe{Path: upstreamLicencePath, Body: archivedLicence(t)}
}

// fixtureSource is a CorpusSource backed by in-memory trees. It implements the
// same interface gitSource does, so the command paths it drives are the ones
// production runs.
type fixtureSource struct {
	head           string
	trees          map[string]map[string]string
	resolveErr     error
	materialiseErr error
	resolved       []string
	materialised   []string
}

func (f *fixtureSource) Resolve(_ context.Context, ref string) (string, error) {
	f.resolved = append(f.resolved, ref)
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	return f.head, nil
}

func (f *fixtureSource) Materialise(_ context.Context, sha, dest string) error {
	f.materialised = append(f.materialised, sha)
	if f.materialiseErr != nil {
		return f.materialiseErr
	}
	tree, ok := f.trees[sha]
	if !ok {
		return fmt.Errorf("fixtureSource has no tree for %s", sha)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	for rel, content := range tree {
		p := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

var _ CorpusSource = (*fixtureSource)(nil)

// ---------------------------------------------------------------------------
// Identity predicates
// ---------------------------------------------------------------------------

func TestIsCommitSHA_RefusesEverythingThatIsNotOne(t *testing.T) {
	good := []string{
		pinnedCommitSHA,
		"0000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffffffffffff",
	}
	for _, s := range good {
		if !isCommitSHA(s) {
			t.Errorf("isCommitSHA(%q) = false, want true", s)
		}
	}
	// Every one of these has been proposed as a pin somewhere, by someone.
	bad := map[string]string{
		"":        "the empty string, which a fetch tool resolves to whatever is newest",
		"main":    "a branch, which moves by definition",
		"HEAD":    "a symbolic ref",
		"latest":  "not a git concept at all",
		"v10.4.7": "a tag, which can be moved onto other bytes",
		"83234ce": "an abbreviation, which git resolves by prefix match",
		"83234CE456DA3E90DDA86DFBC5E605E64A846DF3":  "uppercase, which breaks == against a fetched SHA",
		"83234ce456da3e90dda86dfbc5e605e64a846df":   "39 characters",
		"83234ce456da3e90dda86dfbc5e605e64a846df33": "41 characters",
		"83234ce456da3e90dda86dfbc5e605e64a846dg3":  "a non-hex byte",
		" 3234ce456da3e90dda86dfbc5e605e64a846df3":  "a leading space",
	}
	for s, why := range bad {
		if isCommitSHA(s) {
			t.Errorf("isCommitSHA(%q) = true, want false (%s)", s, why)
		}
	}
}

func TestIsSHA256(t *testing.T) {
	if !isSHA256(archivedLicenceSHA256) {
		t.Errorf("isSHA256(%q) = false", archivedLicenceSHA256)
	}
	for _, s := range []string{"", archivedLicenceSHA256[:63], archivedLicenceSHA256 + "a",
		strings.ToUpper(archivedLicenceSHA256), pinnedCommitSHA} {
		if isSHA256(s) {
			t.Errorf("isSHA256(%q) = true, want false", s)
		}
	}
}

// ---------------------------------------------------------------------------
// The pin
// ---------------------------------------------------------------------------

func TestCurrentPin_IsValid(t *testing.T) {
	if err := CurrentPin().Valid(); err != nil {
		t.Fatalf("the in-tree pin is invalid: %v", err)
	}
}

// TestPinValid_RejectsEveryWayAPinGoesWrong mutates ONE FIELD AT A TIME from a
// pin that is otherwise known good, so a case that passes for the wrong reason
// is visible.
func TestPinValid_RejectsEveryWayAPinGoesWrong(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Pin)
	}{
		{"zero value", func(p *Pin) { *p = Pin{} }},
		{"http repository", func(p *Pin) { p.Repository = "http://github.com/x/y" }},
		{"empty repository", func(p *Pin) { p.Repository = "" }},
		{"ssh repository", func(p *Pin) { p.Repository = "git@github.com:x/y.git" }},
		{"no tracking ref", func(p *Pin) { p.TrackingRef = "" }},
		{"commit is a branch", func(p *Pin) { p.CommitSHA = "main" }},
		{"commit is a tag", func(p *Pin) { p.CommitSHA = "v10.4.7" }},
		{"commit is abbreviated", func(p *Pin) { p.CommitSHA = pinnedCommitSHA[:12] }},
		{"commit is empty", func(p *Pin) { p.CommitSHA = "" }},
		{"commit is uppercase", func(p *Pin) { p.CommitSHA = strings.ToUpper(pinnedCommitSHA) }},
		{"no licence path", func(p *Pin) { p.LicencePath = "" }},
		{"no spdx", func(p *Pin) { p.LicenceSPDX = "" }},
		{"licence digest empty", func(p *Pin) { p.LicenceSHA256 = "" }},
		{"licence digest is a commit sha", func(p *Pin) { p.LicenceSHA256 = pinnedCommitSHA }},
		{"licence digest uppercase", func(p *Pin) {
			p.LicenceSHA256 = strings.ToUpper(archivedLicenceSHA256)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := CurrentPin()
			if err := p.Valid(); err != nil {
				t.Fatalf("baseline pin is already invalid: %v", err)
			}
			tc.mutate(&p)
			err := p.Valid()
			if err == nil {
				t.Fatalf("Pin.Valid() accepted a pin mutated by %q", tc.name)
			}
			if !errors.Is(err, ErrPinInvalid) {
				t.Errorf("error does not wrap ErrPinInvalid: %v", err)
			}
		})
	}
}

// TestPinValid_DoesNotDependOnProvenanceFields records that CommitTag and
// CommitDate are provenance, not identity: clearing them leaves the pin valid,
// which is what lets Promote clear them rather than carrying a stale tag
// forward.
func TestPinValid_DoesNotDependOnProvenanceFields(t *testing.T) {
	p := CurrentPin()
	p.CommitTag = ""
	p.CommitDate = ""
	if err := p.Valid(); err != nil {
		t.Fatalf("clearing provenance invalidated the pin: %v", err)
	}
}

func TestPinSourceForm_RoundTripsTheValues(t *testing.T) {
	p := CurrentPin()
	src := p.SourceForm()
	for _, want := range []string{
		fmt.Sprintf("%q", p.Repository),
		fmt.Sprintf("%q", p.CommitSHA),
		fmt.Sprintf("%q", p.TrackingRef),
		fmt.Sprintf("%q", p.LicenceSHA256),
		fmt.Sprintf("%q", p.LicenceSPDX),
	} {
		if !strings.Contains(src, want) {
			t.Errorf("SourceForm() omits %s:\n%s", want, src)
		}
	}
}

// ---------------------------------------------------------------------------
// The archived licence: this is the CI-lane control
// ---------------------------------------------------------------------------

// TestArchivedLicenceBodyMatchesThePin runs in the ordinary `go test ./...`
// lane, which is the lane CI runs. plan/00-SPINE.md S8 says licence decisions
// are made from FILE BODIES; this asserts the body is present, is the body the
// pin's digest names, and is actually the licence the pin claims -- not a
// stub, not a placeholder, and not a guessed SPDX identifier over an absent
// file. An unverified licence file is worse than an absent one, because the
// compliance gate then passes on it.
func TestArchivedLicenceBodyMatchesThePin(t *testing.T) {
	body := archivedLicence(t)

	if got := digestOf(body); got != archivedLicenceSHA256 {
		t.Fatalf("%s is sha256 %s, the pin says %s", archivedLicencePath, got, archivedLicenceSHA256)
	}
	if archivedLicenceSPDX != "MIT" {
		t.Fatalf("the pin claims SPDX %q; this test only knows how to verify MIT",
			archivedLicenceSPDX)
	}
	text := string(body)
	// Three load-bearing clauses of the MIT text. A stub, a truncation or a
	// different licence fails at least one.
	for _, clause := range []string{
		"MIT License",
		"Permission is hereby granted, free of charge",
		"without restriction, including without limitation the rights",
		"The above copyright notice and this permission notice shall be included",
		`THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND`,
	} {
		if !strings.Contains(text, clause) {
			t.Errorf("the archived body does not contain the MIT clause %q, so the SPDX "+
				"identifier %q in the pin is not supported by the file", clause,
				archivedLicenceSPDX)
		}
	}
	if !strings.Contains(text, "Copyright (c)") {
		t.Error("the archived body carries no copyright line")
	}
	if strings.ContainsRune(text, '\r') {
		t.Error("the archived body contains a carriage return; .gitattributes pins LF and " +
			"a CR would change the digest between a Windows and a Linux checkout")
	}
	if len(body) == 0 {
		t.Fatal("the archived licence body is empty")
	}
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

func TestSnapshotDir_RefusesASHAThatIsNotOne(t *testing.T) {
	dir := writeTree(t, baseCorpus())
	for _, sha := range []string{"", "main", "HEAD", pinnedCommitSHA[:8]} {
		if _, err := SnapshotDir(sha, dir); err == nil {
			t.Errorf("SnapshotDir(%q, ...) succeeded; a snapshot must be attributable to "+
				"a commit", sha)
		}
	}
}

// TestSnapshotDir_RefusesACorpusThatLoadsEmpty is the anti-vacuity floor. A
// corpus with no admitted templates would diff against the pinned corpus as
// "every template removed", and promoting it would ship a scanner that finds
// nothing over any target.
func TestSnapshotDir_RefusesACorpusThatLoadsEmpty(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"README.md":         "not a template",
		"code/only.yaml":    codeTemplate("only-code"),
		"headless/one.yaml": headlessTemplate("only-headless"),
	})
	_, err := SnapshotDir(candidateSHA, dir)
	if err == nil {
		t.Fatal("SnapshotDir accepted a corpus with zero admitted templates")
	}
	if !errors.Is(err, engines.ErrNoTemplates) {
		t.Errorf("error does not wrap engines.ErrNoTemplates: %v", err)
	}
}

func TestSnapshot_ZeroValueIsNotConstructed(t *testing.T) {
	if (Snapshot{}).Constructed() {
		t.Fatal("Snapshot{}.Constructed() is true; a zero snapshot diffs as \"upstream " +
			"removed every template\"")
	}
	// Sealed but empty is also not constructed.
	if (Snapshot{sha: pinnedSHA, sealed: true}).Constructed() {
		t.Fatal("a sealed but empty Snapshot reports Constructed()")
	}
	// Sealed and populated but with a ref instead of a SHA is not constructed.
	s := Snapshot{sha: "main", sealed: true, admitted: map[string]TemplateEntry{"x": {}}}
	if s.Constructed() {
		t.Fatal("a Snapshot whose sha is a branch name reports Constructed()")
	}
}

// TestSnapshotCopies_AreDeepInEveryContainer mutates EVERY container the
// accessors hand out -- both maps and the one slice inside them -- and asserts
// the snapshot is unchanged.
//
// The specific defect this exists to prevent has been found twice in this
// codebase already (Scope.Ports, then Target.Containers): a copy method that
// deep-copies the field the test happens to mutate and shares every other one.
// So this test mutates all of them.
func TestSnapshotCopies_AreDeepInEveryContainer(t *testing.T) {
	s := snapshotOf(t, pinnedSHA, baseCorpus())

	if len(s.admitted) < 2 {
		t.Fatalf("fixture is too small to test: %d admitted", len(s.admitted))
	}
	if len(s.rejected) == 0 {
		t.Fatal("fixture produced no rejections, so Rejected() cannot be tested")
	}

	// --- Admitted(): the map itself ---
	{
		got := s.Admitted()
		var anyID string
		for id := range got {
			anyID = id
			break
		}
		delete(got, anyID)
		got["injected-by-the-test"] = TemplateEntry{ID: "injected-by-the-test"}
		if _, ok := s.admitted[anyID]; !ok {
			t.Errorf("deleting from Admitted()'s result removed %q from the snapshot", anyID)
		}
		if _, ok := s.admitted["injected-by-the-test"]; ok {
			t.Error("inserting into Admitted()'s result inserted into the snapshot")
		}
	}

	// --- Admitted(): the TemplateEntry.protocols slice inside it ---
	{
		got := s.Admitted()
		for id, e := range got {
			if len(e.protocols) == 0 {
				t.Fatalf("entry %q carries no protocols; the slice cannot be tested", id)
			}
			before := s.admitted[id].protocols[0]
			e.protocols[0] = "TAMPERED"
			if after := s.admitted[id].protocols[0]; after != before {
				t.Errorf("mutating Admitted()[%q].protocols[0] changed the snapshot: "+
					"%q -> %q", id, before, after)
			}
		}
	}

	// --- TemplateEntry.Protocols(): a fresh slice per call ---
	//
	// Against a FRESH snapshot on purpose: if the block above found a shared
	// slice it has already corrupted s, and this assertion would then be red
	// for that reason rather than its own.
	{
		fresh := snapshotOf(t, pinnedSHA, baseCorpus())
		var e TemplateEntry
		for _, v := range fresh.admitted {
			e = v
			break
		}
		a, b := e.Protocols(), e.Protocols()
		if len(a) == 0 {
			t.Fatal("Protocols() returned nothing")
		}
		a[0] = "TAMPERED"
		if b[0] == "TAMPERED" {
			t.Error("two Protocols() calls share a backing array")
		}
		if e.protocols[0] == "TAMPERED" {
			t.Error("Protocols() aliases the entry's own slice")
		}
	}

	// --- Rejected(): the map itself ---
	{
		got := s.Rejected()
		var anyPath string
		for p := range got {
			anyPath = p
			break
		}
		before := s.rejected[anyPath]
		delete(got, anyPath)
		got["injected/by/the/test.yaml"] = engines.RejectedTemplate{Path: "injected"}
		if _, ok := s.rejected[anyPath]; !ok {
			t.Errorf("deleting from Rejected()'s result removed %q from the snapshot", anyPath)
		}
		if _, ok := s.rejected["injected/by/the/test.yaml"]; ok {
			t.Error("inserting into Rejected()'s result inserted into the snapshot")
		}
		if s.rejected[anyPath] != before {
			t.Error("the snapshot's rejection changed")
		}
	}

	// --- the scalar fields survive all of the above ---
	if s.SHA() != pinnedSHA {
		t.Errorf("SHA() = %q after mutation, want %q", s.SHA(), pinnedSHA)
	}
	if s.Examined() != len(s.admitted) {
		t.Errorf("Examined() = %d, admitted = %d", s.Examined(), len(s.admitted))
	}
	if !s.Constructed() {
		t.Error("the snapshot stopped being Constructed()")
	}
}

func TestSnapshotAccessors_NilMapsStayNil(t *testing.T) {
	var s Snapshot
	if s.Admitted() != nil {
		t.Error("Admitted() on a zero Snapshot returned a non-nil map")
	}
	if s.Rejected() != nil {
		t.Error("Rejected() on a zero Snapshot returned a non-nil map")
	}
	if (TemplateEntry{}).Protocols() != nil {
		t.Error("Protocols() on a zero TemplateEntry returned a non-nil slice")
	}
}

// ---------------------------------------------------------------------------
// The diff
// ---------------------------------------------------------------------------

func TestDiff_RefusesUnconstructedSnapshots(t *testing.T) {
	good := snapshotOf(t, pinnedSHA, baseCorpus())
	cand := snapshotOf(t, candidateSHA, baseCorpus())

	if _, err := Diff(CurrentPin(), Snapshot{}, cand, goodProbe(t)); !errors.Is(err, ErrUnconstructed) {
		t.Errorf("Diff accepted a zero FROM snapshot: %v", err)
	}
	if _, err := Diff(CurrentPin(), good, Snapshot{}, goodProbe(t)); !errors.Is(err, ErrUnconstructed) {
		t.Errorf("Diff accepted a zero TO snapshot: %v", err)
	}
}

func TestDiff_RefusesAnInvalidPin(t *testing.T) {
	good := snapshotOf(t, pinnedSHA, baseCorpus())
	cand := snapshotOf(t, candidateSHA, baseCorpus())
	if _, err := Diff(Pin{}, good, cand, goodProbe(t)); !errors.Is(err, ErrPinInvalid) {
		t.Errorf("Diff accepted a zero Pin: %v", err)
	}
}

// TestDiff_RefusesAFromSnapshotThatIsNotThePin pins the RELATION. A diff whose
// FROM side is some other commit is a comparison nobody asked for, and its
// ToSHA would then be promoted on the strength of it.
func TestDiff_RefusesAFromSnapshotThatIsNotThePin(t *testing.T) {
	other := snapshotOf(t, candidateSHA, baseCorpus())
	cand := snapshotOf(t, "1111111111111111111111111111111111111111", baseCorpus())
	_, err := Diff(CurrentPin(), other, cand, goodProbe(t))
	if err == nil {
		t.Fatal("Diff accepted a FROM snapshot that is not the pinned commit")
	}
	if !errors.Is(err, ErrPinInvalid) {
		t.Errorf("error does not wrap ErrPinInvalid: %v", err)
	}
}

func TestDiff_AddedRemovedModified(t *testing.T) {
	from := snapshotOf(t, pinnedSHA, baseCorpus())

	to := baseCorpus()
	delete(to, "http/beta.yaml")                                 // removed
	to["http/alpha.yaml"] = okTemplate("anvil-alpha", "CHANGED") // modified
	to["http/gamma.yaml"] = okTemplate("anvil-gamma", "g")       // added
	toSnap := snapshotOf(t, candidateSHA, to)

	rep, err := Diff(CurrentPin(), from, toSnap, goodProbe(t))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if rep.PromotionBlocked() {
		t.Fatalf("an ordinary diff was blocked: %v", rep.Blocks)
	}
	byID := map[string]TemplateChange{}
	for _, c := range rep.Templates {
		byID[c.ID] = c
	}
	if len(byID) != 3 {
		t.Fatalf("expected 3 changes, got %d: %v", len(byID), rep.Templates)
	}
	if got := byID["anvil-beta"].Kind; got != ChangeRemoved {
		t.Errorf("anvil-beta kind = %q, want %q", got, ChangeRemoved)
	}
	if got := byID["anvil-gamma"].Kind; got != ChangeAdded {
		t.Errorf("anvil-gamma kind = %q, want %q", got, ChangeAdded)
	}
	m := byID["anvil-alpha"]
	if m.Kind != ChangeModified {
		t.Errorf("anvil-alpha kind = %q, want %q", m.Kind, ChangeModified)
	}
	if m.FromDigest == "" || m.ToDigest == "" || m.FromDigest == m.ToDigest {
		t.Errorf("anvil-alpha digests are not a real before/after: %q -> %q",
			m.FromDigest, m.ToDigest)
	}
	if !rep.Changed() {
		t.Error("Changed() is false for a diff with three changes")
	}
}

// TestDiff_KeysOnIdentityNotPath: a template that moves directory without
// changing a byte must be ONE modification, not a removal plus an addition.
//
// A path-keyed or index-keyed diff reports an upstream reorganisation as ten
// thousand additions, and a reviewer scrolling that has no chance of spotting
// the one real change inside it. That is the "allowlist matched by position
// rather than identity" failure applied to a diff.
func TestDiff_KeysOnIdentityNotPath(t *testing.T) {
	from := snapshotOf(t, pinnedSHA, baseCorpus())

	to := baseCorpus()
	body := to["http/alpha.yaml"]
	delete(to, "http/alpha.yaml")
	to["http/misconfiguration/alpha.yaml"] = body // same bytes, new path
	toSnap := snapshotOf(t, candidateSHA, to)

	rep, err := Diff(CurrentPin(), from, toSnap, goodProbe(t))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(rep.Templates) != 1 {
		t.Fatalf("a pure move produced %d changes, want 1: %v", len(rep.Templates), rep.Templates)
	}
	c := rep.Templates[0]
	if c.Kind != ChangeModified || c.ID != "anvil-alpha" {
		t.Fatalf("got %+v, want a modification of anvil-alpha", c)
	}
	if c.FromPath != "alpha.yaml" && c.FromPath != "http/alpha.yaml" {
		t.Errorf("FromPath = %q, expected the old location", c.FromPath)
	}
	if !strings.Contains(c.ToPath, "misconfiguration") {
		t.Errorf("ToPath = %q, expected the new location", c.ToPath)
	}
	if c.FromDigest != c.ToDigest {
		t.Errorf("a pure move changed the digest: %q -> %q", c.FromDigest, c.ToDigest)
	}
}

// TestDiff_NewCodeProtocolTemplateBlocksPromotion is plan/50-dast.md D.17's
// stated validation, verbatim: a synthetic upstream diff containing a new
// `code:` template, asserted to be flagged and blocked from auto-promotion.
func TestDiff_NewCodeProtocolTemplateBlocksPromotion(t *testing.T) {
	from := snapshotOf(t, pinnedSHA, baseCorpus())

	to := baseCorpus()
	to["http/cves/2026/CVE-2026-99999.yaml"] = codeTemplate("CVE-2026-99999")
	toSnap := snapshotOf(t, candidateSHA, to)

	rep, err := Diff(CurrentPin(), from, toSnap, goodProbe(t))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// 1. It is FLAGGED: it appears in the report, by path and by the loader's
	//    own reason constant.
	var found *RejectionChange
	for i := range rep.NewRejections {
		if strings.Contains(rep.NewRejections[i].Path, "CVE-2026-99999") {
			found = &rep.NewRejections[i]
		}
	}
	if found == nil {
		t.Fatalf("the new `code:` template is absent from NewRejections: %v", rep.NewRejections)
	}
	if found.Reason != engines.RejectCodeProtocol {
		t.Errorf("reason = %q, want %q", found.Reason, engines.RejectCodeProtocol)
	}
	if found.Protocol != engines.ProtocolCode {
		t.Errorf("protocol = %q, want %q", found.Protocol, engines.ProtocolCode)
	}

	// 2. It is BLOCKED.
	if !rep.PromotionBlocked() {
		t.Fatal("a new `code:` template did not block promotion")
	}
	var blocked bool
	for _, b := range rep.Blocks {
		if b.Reason == BlockNewCodeProtocolTemplate && strings.Contains(b.Subject, "CVE-2026-99999") {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("no %s block names the offending path: %v", BlockNewCodeProtocolTemplate, rep.Blocks)
	}

	// 3. No approval overrides it. This is the "blocked from auto-promotion"
	//    half, and it is asserted against a MAXIMALLY VALID approval -- right
	//    approver, right timestamp, both ends of the transition named
	//    correctly -- so it cannot pass for some unrelated reason.
	_, err = Promote(rep, Approval{
		FromSHA:    rep.FromSHA,
		ToSHA:      rep.ToSHA,
		Approver:   "a human who typed yes",
		ApprovedAt: time.Now(),
	}, goodProbe(t))
	if !errors.Is(err, ErrPromotionBlocked) {
		t.Fatalf("Promote error = %v, want ErrPromotionBlocked", err)
	}

	// 4. The report a human reads says so.
	var buf bytes.Buffer
	if err := WriteReport(&buf, rep); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"PROMOTION BLOCKED", string(BlockNewCodeProtocolTemplate),
		"CVE-2026-99999", string(engines.RejectCodeProtocol)} {
		if !strings.Contains(out, want) {
			t.Errorf("the report omits %q:\n%s", want, out)
		}
	}
}

// TestDiff_PreExistingCodeTemplateDoesNotBlock is the other half of the
// measurement, and without it the test above proves nothing: the gate must
// fire on a NEW `code:` template, not on the 251 that were already there. A
// gate that fires on every diff is a gate someone turns off.
func TestDiff_PreExistingCodeTemplateDoesNotBlock(t *testing.T) {
	base := baseCorpus()
	base["code/exec.yaml"] = codeTemplate("upstream-code-1")

	from := snapshotOf(t, pinnedSHA, base)

	to := map[string]string{}
	for k, v := range base {
		to[k] = v
	}
	to["http/gamma.yaml"] = okTemplate("anvil-gamma", "g")
	toSnap := snapshotOf(t, candidateSHA, to)

	rep, err := Diff(CurrentPin(), from, toSnap, goodProbe(t))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if rep.PromotionBlocked() {
		t.Fatalf("a pre-existing `code:` template blocked promotion: %v", rep.Blocks)
	}
	for _, r := range rep.NewRejections {
		if strings.Contains(r.Path, "exec.yaml") {
			t.Errorf("a pre-existing rejection was reported as new: %v", r)
		}
	}
}

// TestDiff_NewNonBlockingRejectionIsReportedButNotBlocked pins the boundary of
// blockingRejections. A new `headless:` template is refused by the loader and
// must appear in the report -- but it must not block, or no promotion ever
// completes.
func TestDiff_NewNonBlockingRejectionIsReportedButNotBlocked(t *testing.T) {
	from := snapshotOf(t, pinnedSHA, baseCorpus())

	to := baseCorpus()
	to["headless/new.yaml"] = headlessTemplate("anvil-new-headless")
	toSnap := snapshotOf(t, candidateSHA, to)

	rep, err := Diff(CurrentPin(), from, toSnap, goodProbe(t))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	var reported bool
	for _, r := range rep.NewRejections {
		if strings.Contains(r.Path, "new.yaml") {
			reported = true
			if r.Reason != engines.RejectDrivesBrowser {
				t.Errorf("reason = %q, want %q", r.Reason, engines.RejectDrivesBrowser)
			}
		}
	}
	if !reported {
		t.Fatalf("a new refused template was not reported: %v", rep.NewRejections)
	}
	if rep.PromotionBlocked() {
		t.Fatalf("a new `headless:` template blocked promotion: %v", rep.Blocks)
	}
}

func TestBlockingRejections_IsFreshAndIsExactlyTheSpineExclusion(t *testing.T) {
	m := blockingRejections()
	if len(m) != 1 || !m[engines.RejectCodeProtocol] {
		t.Fatalf("blockingRejections() = %v, want exactly {%s}", m, engines.RejectCodeProtocol)
	}
	m[engines.RejectDrivesBrowser] = true
	delete(m, engines.RejectCodeProtocol)
	again := blockingRejections()
	if again[engines.RejectDrivesBrowser] || !again[engines.RejectCodeProtocol] {
		t.Fatal("blockingRejections() returns a shared map; mutating one caller's copy " +
			"changed what blocks a promotion everywhere else")
	}
}

// ---------------------------------------------------------------------------
// The licence half of the diff
// ---------------------------------------------------------------------------

func TestDiff_LicenceBlocks(t *testing.T) {
	body := archivedLicence(t)

	cases := []struct {
		name  string
		probe LicenceProbe
		want  BlockReason // "" means no block
	}{
		{"unchanged body", LicenceProbe{Path: upstreamLicencePath, Body: body}, ""},
		{
			"relicensed",
			LicenceProbe{Path: upstreamLicencePath, Body: []byte("GNU AFFERO GENERAL PUBLIC LICENSE\n")},
			BlockLicenceBodyChanged,
		},
		{
			"one byte changed",
			LicenceProbe{Path: upstreamLicencePath, Body: append(append([]byte{}, body...), ' ')},
			BlockLicenceBodyChanged,
		},
		{
			"unreadable",
			LicenceProbe{Path: upstreamLicencePath, Err: errors.New("no such file")},
			BlockLicenceUnreadable,
		},
		{"empty body", LicenceProbe{Path: upstreamLicencePath}, BlockLicenceUnreadable},
		// THE ZERO VALUE. A caller who forgot to run the probe must not
		// promote past the licence check.
		{"zero value probe", LicenceProbe{}, BlockLicenceUnreadable},
	}

	from := snapshotOf(t, pinnedSHA, baseCorpus())
	toSnap := snapshotOf(t, candidateSHA, baseCorpus())

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Diff(CurrentPin(), from, toSnap, tc.probe)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			var got BlockReason
			for _, b := range rep.Blocks {
				if b.Reason != BlockNewCodeProtocolTemplate {
					got = b.Reason
				}
			}
			if got != tc.want {
				t.Fatalf("block = %q, want %q (blocks: %v)", got, tc.want, rep.Blocks)
			}
			if tc.want != "" {
				if _, err := Promote(rep, Approval{
					FromSHA: rep.FromSHA, ToSHA: rep.ToSHA,
					Approver: "human", ApprovedAt: time.Now(),
				}, tc.probe); !errors.Is(err, ErrPromotionBlocked) {
					t.Errorf("Promote error = %v, want ErrPromotionBlocked", err)
				}
			}
		})
	}
}

func TestReadLicence(t *testing.T) {
	dir := writeTree(t, map[string]string{"LICENSE.md": "MIT-ish\n"})
	p := ReadLicence(dir, "LICENSE.md")
	if p.Err != nil {
		t.Fatalf("ReadLicence: %v", p.Err)
	}
	if string(p.Body) != "MIT-ish\n" {
		t.Errorf("body = %q", p.Body)
	}
	if p.Path != "LICENSE.md" {
		t.Errorf("path = %q", p.Path)
	}
	if p := ReadLicence(dir, "NOPE.md"); p.Err == nil {
		t.Error("ReadLicence of a missing file reported no error")
	}
	if p := ReadLicence(dir, ""); p.Err == nil {
		t.Error("ReadLicence with no path reported no error")
	}
}

// ---------------------------------------------------------------------------
// Promotion
// ---------------------------------------------------------------------------

func cleanReport(t *testing.T) DiffReport {
	t.Helper()
	from := snapshotOf(t, pinnedSHA, baseCorpus())
	to := baseCorpus()
	to["http/gamma.yaml"] = okTemplate("anvil-gamma", "g")
	rep, err := Diff(CurrentPin(), from, snapshotOf(t, candidateSHA, to), goodProbe(t))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if rep.PromotionBlocked() {
		t.Fatalf("the baseline report is blocked: %v", rep.Blocks)
	}
	return rep
}

func TestPromote_Refusals(t *testing.T) {
	rep := cleanReport(t)
	good := Approval{
		FromSHA: rep.FromSHA, ToSHA: rep.ToSHA,
		Approver: "t.snyder", ApprovedAt: time.Now().UTC(),
	}

	cases := []struct {
		name    string
		report  DiffReport
		mutate  func(*Approval)
		wantErr error
	}{
		{"unconstructed report", DiffReport{}, nil, ErrUnconstructed},
		{"hand-built report", DiffReport{FromSHA: pinnedSHA, ToSHA: candidateSHA}, nil, ErrUnconstructed},
		{"zero approval", rep, func(a *Approval) { *a = Approval{} }, ErrNotApproved},
		{"no approver", rep, func(a *Approval) { a.Approver = "" }, ErrNotApproved},
		{"blank approver", rep, func(a *Approval) { a.Approver = "   " }, ErrNotApproved},
		{"no timestamp", rep, func(a *Approval) { a.ApprovedAt = time.Time{} }, ErrNotApproved},
		{"wrong destination", rep, func(a *Approval) {
			a.ToSHA = "2222222222222222222222222222222222222222"
		}, ErrNotApproved},
		// PIN THE RELATION: the right destination approved from the wrong
		// origin is not this transition.
		{"right destination, wrong origin", rep, func(a *Approval) {
			a.FromSHA = "3333333333333333333333333333333333333333"
		}, ErrNotApproved},
		{"empty origin", rep, func(a *Approval) { a.FromSHA = "" }, ErrNotApproved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ap := good
			if tc.mutate != nil {
				tc.mutate(&ap)
			}
			_, err := Promote(tc.report, ap, goodProbe(t))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Promote error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestPromote_RefusesANoOp: approving the commit that is already pinned
// approves nothing, and a job that accepted it would rewrite the pin to the
// value it already had while reporting a successful promotion.
func TestPromote_RefusesANoOp(t *testing.T) {
	from := snapshotOf(t, pinnedSHA, baseCorpus())
	same := snapshotOf(t, pinnedSHA, baseCorpus())
	rep, err := Diff(CurrentPin(), from, same, goodProbe(t))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if rep.Changed() {
		t.Fatal("Changed() is true for a diff of a commit against itself")
	}
	_, err = Promote(rep, Approval{
		FromSHA: pinnedSHA, ToSHA: pinnedSHA,
		Approver: "human", ApprovedAt: time.Now(),
	}, goodProbe(t))
	if !errors.Is(err, ErrNotApproved) {
		t.Fatalf("Promote error = %v, want ErrNotApproved", err)
	}
}

func TestPromote_RefusesToArchiveAnUnreadLicence(t *testing.T) {
	rep := cleanReport(t)
	ap := Approval{FromSHA: rep.FromSHA, ToSHA: rep.ToSHA, Approver: "h", ApprovedAt: time.Now()}
	for _, probe := range []LicenceProbe{
		{},
		{Path: upstreamLicencePath, Err: errors.New("gone")},
		{Path: upstreamLicencePath, Body: []byte{}},
	} {
		if _, err := Promote(rep, ap, probe); !errors.Is(err, ErrPromotionBlocked) {
			t.Errorf("Promote with probe %+v: error = %v, want ErrPromotionBlocked", probe, err)
		}
	}
}

func TestPromote_Success(t *testing.T) {
	rep := cleanReport(t)
	body := []byte("MIT License\n\nCopyright (c) 2027 Someone Else\n")
	probe := LicenceProbe{Path: "LICENCE.txt", Body: body}

	p, err := Promote(rep, Approval{
		FromSHA: rep.FromSHA, ToSHA: rep.ToSHA,
		Approver: "t.snyder", ApprovedAt: time.Now().UTC(),
	}, probe)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if p.CommitSHA != rep.ToSHA {
		t.Errorf("CommitSHA = %q, want %q", p.CommitSHA, rep.ToSHA)
	}
	if p.CommitTag != "" || p.CommitDate != "" {
		t.Errorf("promotion carried the OLD commit's provenance forward: tag=%q date=%q. "+
			"A tag and a date that belong to a different commit are a version invented "+
			"from memory with extra steps", p.CommitTag, p.CommitDate)
	}
	if p.LicencePath != "LICENCE.txt" {
		t.Errorf("LicencePath = %q, want the path the body was read from", p.LicencePath)
	}
	if p.LicenceSHA256 != digestOf(body) {
		t.Errorf("LicenceSHA256 = %q, want the digest of the archived body %q",
			p.LicenceSHA256, digestOf(body))
	}
	if err := p.Valid(); err != nil {
		t.Errorf("the promoted pin is invalid: %v", err)
	}
	// Promotion does not mutate the in-tree pin. A job that could would be a
	// job that promotes itself.
	if CurrentPin().CommitSHA != pinnedCommitSHA {
		t.Fatal("Promote changed CurrentPin()")
	}
}

func TestArchiveLicence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "LICENSE")

	if err := ArchiveLicence(path, LicenceProbe{}); err == nil {
		t.Error("ArchiveLicence wrote an empty body; an unverified licence file is worse " +
			"than an absent one, because the compliance gate then passes on it")
	}
	if err := ArchiveLicence(path, LicenceProbe{Err: errors.New("gone")}); err == nil {
		t.Error("ArchiveLicence wrote an unread body")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a refused ArchiveLicence still created the file")
	}

	body := archivedLicence(t)
	if err := ArchiveLicence(path, LicenceProbe{Path: "LICENSE.md", Body: body}); err != nil {
		t.Fatalf("ArchiveLicence: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("ArchiveLicence did not write the body verbatim; a licence archived after " +
			"normalisation has a digest that no longer matches the body it came from")
	}
	if digestOf(got) != archivedLicenceSHA256 {
		t.Errorf("round-tripped digest = %s, want %s", digestOf(got), archivedLicenceSHA256)
	}
}

// ---------------------------------------------------------------------------
// The report artifact
// ---------------------------------------------------------------------------

func TestWriteReport_RefusesAnUnconstructedReport(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteReport(&buf, DiffReport{}); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("error = %v, want ErrUnconstructed", err)
	}
	if buf.Len() != 0 {
		t.Errorf("a refused WriteReport still wrote %d bytes", buf.Len())
	}
}

func TestWriteReport_IsDeterministic(t *testing.T) {
	rep := cleanReport(t)
	var a, b bytes.Buffer
	if err := WriteReport(&a, rep); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(&b, rep); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("two renderings of one report differ; a report whose bytes wander cannot " +
			"be diffed against last week's")
	}
	if !strings.Contains(a.String(), "AWAITING EXPLICIT PROMOTION") {
		t.Errorf("a clean diff's report does not say an approval is still required:\n%s", a.String())
	}
	if !strings.Contains(a.String(), "A clean diff is not an approval") {
		t.Errorf("the report does not state the promotion rule:\n%s", a.String())
	}
	if !strings.Contains(a.String(), pinnedCommitSHA) || !strings.Contains(a.String(), candidateSHA) {
		t.Errorf("the report does not name both ends of the transition:\n%s", a.String())
	}
}

func TestWriteReport_NoOpSaysSo(t *testing.T) {
	from := snapshotOf(t, pinnedSHA, baseCorpus())
	same := snapshotOf(t, pinnedSHA, baseCorpus())
	rep, err := Diff(CurrentPin(), from, same, goodProbe(t))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteReport(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Nothing to promote") {
		t.Errorf("report:\n%s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// The git seam
// ---------------------------------------------------------------------------

func TestNewGitSource_RefusesANonHTTPSRepository(t *testing.T) {
	for _, r := range []string{"", "http://github.com/x/y", "git@github.com:x/y", "file:///tmp/x"} {
		if _, err := newGitSource(r); !errors.Is(err, ErrPinInvalid) {
			t.Errorf("newGitSource(%q) error = %v, want ErrPinInvalid", r, err)
		}
	}
}

// TestGitSource_MaterialiseRefusesAnythingButAFullSHA never runs git: the
// refusal happens before any subprocess, which is the point. `git checkout
// main` in a job whose whole purpose is to pin by SHA is the exact failure
// plan/50-dast.md D.17's Forbidden actions name.
func TestGitSource_MaterialiseRefusesAnythingButAFullSHA(t *testing.T) {
	g := &gitSource{repository: pinnedRepository, git: "definitely-not-a-real-binary"}
	dest := filepath.Join(t.TempDir(), "out")
	for _, sha := range []string{"", "main", "HEAD", "v10.4.7", pinnedCommitSHA[:8],
		strings.ToUpper(pinnedCommitSHA)} {
		err := g.Materialise(context.Background(), sha, dest)
		if !errors.Is(err, ErrFetch) {
			t.Errorf("Materialise(%q) error = %v, want ErrFetch", sha, err)
		}
		if _, statErr := os.Stat(dest); statErr == nil {
			t.Errorf("Materialise(%q) created %s before refusing", sha, dest)
		}
	}
}

func TestGitSource_ResolveRefusesAnEmptyRef(t *testing.T) {
	g := &gitSource{repository: pinnedRepository, git: "definitely-not-a-real-binary"}
	if _, err := g.Resolve(context.Background(), "   "); !errors.Is(err, ErrFetch) {
		t.Errorf("error = %v, want ErrFetch", err)
	}
}

func TestToolUnavailableError_IsLoudAndCarriesTheExitCode(t *testing.T) {
	e := &ToolUnavailableError{Name: "git", Detail: "not on PATH"}
	if e.ExitCode() != engines.ExitCodeArtefactAbsent {
		t.Errorf("ExitCode() = %d, want %d", e.ExitCode(), engines.ExitCodeArtefactAbsent)
	}
	if !errors.Is(e, ErrToolUnavailable) {
		t.Error("does not unwrap to ErrToolUnavailable")
	}
	if !strings.Contains(e.Error(), "NOT an empty diff") {
		t.Errorf("the message does not distinguish absence from a clean result: %s", e.Error())
	}
}

func TestExitCodeFor(t *testing.T) {
	if got := exitCodeFor(&ToolUnavailableError{Name: "git"}); got != engines.ExitCodeArtefactAbsent {
		t.Errorf("exitCodeFor(tool absent) = %d, want %d", got, engines.ExitCodeArtefactAbsent)
	}
	if got := exitCodeFor(fmt.Errorf("wrapped: %w", &ToolUnavailableError{Name: "git"})); got != engines.ExitCodeArtefactAbsent {
		t.Errorf("exitCodeFor(wrapped tool absent) = %d, want %d", got, engines.ExitCodeArtefactAbsent)
	}
	if got := exitCodeFor(errors.New("something else")); got != 1 {
		t.Errorf("exitCodeFor(other) = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

func run(t *testing.T, src CorpusSource, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runPinTemplates(context.Background(), src, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLI_UsageAndUnknownSubcommand(t *testing.T) {
	if code, _, errOut := run(t, nil); code != 2 || !strings.Contains(errOut, "usage:") {
		t.Errorf("bare invocation: code=%d stderr=%q", code, errOut)
	}
	code, _, errOut := run(t, nil, "promote-everything")
	if code != 2 {
		t.Errorf("unknown subcommand code = %d, want 2", code)
	}
	if !strings.Contains(errOut, "promote-everything") {
		t.Errorf("stderr does not name the unknown subcommand: %q", errOut)
	}
}

func TestCLI_VerifyPassesAgainstThisRepository(t *testing.T) {
	code, out, errOut := run(t, nil, "verify", "--repo-root", filepath.Join("..", ".."))
	if code != 0 {
		t.Fatalf("verify exited %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	for _, want := range []string{pinnedCommitSHA, archivedLicenceSHA256, archivedLicenceSPDX,
		pinnedRepository, archivedLicencePath} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output omits %q:\n%s", want, out)
		}
	}
}

func TestCLI_VerifyFailsWhenTheArchivedLicenceIsMissingOrAltered(t *testing.T) {
	// Missing.
	empty := t.TempDir()
	code, _, errOut := run(t, nil, "verify", "--repo-root", empty)
	if code == 0 {
		t.Fatal("verify passed with no archived licence body at all")
	}
	if !strings.Contains(errOut, archivedLicenceSPDX) {
		t.Errorf("the refusal does not say which claim became unverifiable: %q", errOut)
	}

	// Present but altered by one byte.
	altered := t.TempDir()
	writeInto(t, altered, map[string]string{
		archivedLicencePath: string(archivedLicence(t)) + "\n",
	})
	code, _, errOut = run(t, nil, "verify", "--repo-root", altered)
	if code == 0 {
		t.Fatal("verify passed over a licence body that is not the one the pin names")
	}
	if !strings.Contains(errOut, archivedLicenceSHA256) {
		t.Errorf("the refusal does not name the expected digest: %q", errOut)
	}
}

// TestCLI_ToolAbsentRefusesRatherThanReportingNoChanges is the tool-absent
// path required by the standing orders: it must REFUSE LOUDLY, not pass.
func TestCLI_ToolAbsentRefusesRatherThanReportingNoChanges(t *testing.T) {
	for _, sub := range []string{"diff", "promote"} {
		code, out, errOut := run(t, nil, sub, "--work", t.TempDir())
		if code != engines.ExitCodeArtefactAbsent {
			t.Errorf("%s with no corpus source exited %d, want %d",
				sub, code, engines.ExitCodeArtefactAbsent)
		}
		if strings.Contains(out, "no change") || strings.Contains(out, "template changes: 0") {
			t.Errorf("%s rendered a report despite never reading upstream:\n%s", sub, out)
		}
		if !strings.Contains(errOut, "NOT an empty diff") {
			t.Errorf("%s did not distinguish absence from a clean result: %q", sub, errOut)
		}
	}
}

// TestDispatch_RefusesWhenGitIsGenuinelyAbsentFromPATH exercises the
// PRODUCTION absence path, not the nil-source stand-in above: real
// exec.LookPath, over a PATH that contains nothing.
//
// git IS installed on the development host (that is how the pin's SHA and
// licence body were read), so the only honest way to reach this branch is to
// take PATH away. Without this test the tool-absent refusal is a branch
// nothing has ever entered.
func TestDispatch_RefusesWhenGitIsGenuinelyAbsentFromPATH(t *testing.T) {
	t.Setenv("PATH", filepath.Join(t.TempDir(), "deliberately-empty"))

	if _, err := defaultCorpusSource(); !errors.Is(err, ErrToolUnavailable) {
		t.Fatalf("defaultCorpusSource() with an empty PATH returned %v; a source that "+
			"exists but cannot run git would produce an empty diff", err)
	}

	var out, errb bytes.Buffer
	code := dispatchPinTemplates([]string{"diff", "--work", t.TempDir()}, &out, &errb)
	if code != engines.ExitCodeArtefactAbsent {
		t.Errorf("diff exited %d, want %d", code, engines.ExitCodeArtefactAbsent)
	}
	if out.Len() != 0 {
		t.Errorf("diff produced a report with no git: %q", out.String())
	}
	if !strings.Contains(errb.String(), "NOT an empty diff") {
		t.Errorf("the refusal does not distinguish absence from a clean result: %q", errb.String())
	}

	// `verify` is offline and must keep working on a host with no git at all,
	// which is what makes it usable as a licence-hygiene check in CI.
	out.Reset()
	errb.Reset()
	if code := dispatchPinTemplates(
		[]string{"verify", "--repo-root", filepath.Join("..", "..")}, &out, &errb); code != 0 {
		t.Errorf("verify exited %d with no git on PATH: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("verify complained about the missing git it does not need: %q", errb.String())
	}
}

func TestCLI_RequiresWorkDirectory(t *testing.T) {
	for _, sub := range []string{"diff", "promote"} {
		if code, _, _ := run(t, &fixtureSource{}, sub); code != 2 {
			t.Errorf("%s without --work exited %d, want 2", sub, code)
		}
	}
}

func TestCLI_FetchFailureIsNotACleanDiff(t *testing.T) {
	src := &fixtureSource{resolveErr: errors.New("dns went away")}
	code, out, errOut := run(t, src, "diff", "--work", t.TempDir())
	if code == 0 {
		t.Fatal("a failed resolve exited 0")
	}
	if out != "" {
		t.Errorf("a failed resolve still produced a report: %q", out)
	}
	if !strings.Contains(errOut, "dns went away") {
		t.Errorf("the failure is not reported: %q", errOut)
	}
}

// candidateCorpus builds the two trees a fixtureSource serves, with the real
// archived licence body on the candidate side so the licence check passes for
// the right reason.
func candidateCorpus(t *testing.T, extra map[string]string) *fixtureSource {
	t.Helper()
	lic := string(archivedLicence(t))

	pinned := baseCorpus()
	pinned["LICENSE.md"] = lic

	cand := baseCorpus()
	cand["LICENSE.md"] = lic
	cand["http/gamma.yaml"] = okTemplate("anvil-gamma", "g")
	for k, v := range extra {
		cand[k] = v
	}
	return &fixtureSource{
		head: candidateSHA,
		trees: map[string]map[string]string{
			pinnedCommitSHA: pinned,
			candidateSHA:    cand,
		},
	}
}

// TestCLI_CodeTemplateBlocksPromotionEndToEnd drives the whole command, not
// the functions underneath it: fetch, materialise both trees, load both, diff,
// report, refuse.
func TestCLI_CodeTemplateBlocksPromotionEndToEnd(t *testing.T) {
	src := candidateCorpus(t, map[string]string{
		"http/cves/2026/CVE-2026-31337.yaml": codeTemplate("CVE-2026-31337"),
	})

	code, out, errOut := run(t, src, "diff", "--work", t.TempDir())
	if code == 0 {
		t.Fatalf("a blocked diff exited 0; a supply-chain finding that exits 0 ends up in "+
			"a log nobody reads\nstdout:%s\nstderr:%s", out, errOut)
	}
	for _, want := range []string{"PROMOTION BLOCKED", "CVE-2026-31337",
		string(BlockNewCodeProtocolTemplate)} {
		if !strings.Contains(out, want) {
			t.Errorf("the report omits %q:\n%s", want, out)
		}
	}

	// It fetched the tracking ref and materialised BOTH ends.
	if len(src.resolved) != 1 || src.resolved[0] != pinnedTrackingRef {
		t.Errorf("resolved = %v, want [%s]", src.resolved, pinnedTrackingRef)
	}
	if len(src.materialised) != 2 || src.materialised[0] != pinnedCommitSHA ||
		src.materialised[1] != candidateSHA {
		t.Errorf("materialised = %v, want [%s %s]", src.materialised,
			pinnedCommitSHA, candidateSHA)
	}

	// And promote refuses, with a correct approval and a writable repo root.
	root := t.TempDir()
	code, _, errOut = run(t, candidateCorpus(t, map[string]string{
		"http/cves/2026/CVE-2026-31337.yaml": codeTemplate("CVE-2026-31337"),
	}), "promote", "--work", t.TempDir(), "--repo-root", root,
		"--from", pinnedCommitSHA, "--to", candidateSHA, "--approver", "a.human")
	if code == 0 {
		t.Fatal("promote succeeded over a blocked diff")
	}
	if !strings.Contains(errOut, string(BlockNewCodeProtocolTemplate)) {
		t.Errorf("the refusal does not name the block: %q", errOut)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(archivedLicencePath))); err == nil {
		t.Error("a blocked promotion still archived a licence")
	}
}

// TestCLI_CleanDiffStillRequiresAnExplicitApproval is D.17's Forbidden action:
// no automatic promotion on a clean diff.
func TestCLI_CleanDiffStillRequiresAnExplicitApproval(t *testing.T) {
	work := t.TempDir()
	code, out, errOut := run(t, candidateCorpus(t, nil), "diff", "--work", work)
	if code != 0 {
		t.Fatalf("a clean diff exited %d\nstdout:%s\nstderr:%s", code, out, errOut)
	}
	if !strings.Contains(out, "AWAITING EXPLICIT PROMOTION") {
		t.Fatalf("a clean diff did not ask for an approval:\n%s", out)
	}
	if strings.Contains(out, "PROMOTION BLOCKED") {
		t.Fatalf("a clean diff reported a block:\n%s", out)
	}

	// --out writes the artifact.
	reportPath := filepath.Join(t.TempDir(), "report.txt")
	if code, _, errOut = run(t, candidateCorpus(t, nil), "diff",
		"--work", t.TempDir(), "--out", reportPath); code != 0 {
		t.Fatalf("diff --out exited %d: %s", code, errOut)
	}
	b, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("reading the report artifact: %v", err)
	}
	if string(b) != out {
		t.Error("the report written to --out differs from the one written to stdout")
	}

	// promote with NO approver refuses.
	root := t.TempDir()
	code, _, errOut = run(t, candidateCorpus(t, nil), "promote", "--work", t.TempDir(),
		"--repo-root", root, "--from", pinnedCommitSHA, "--to", candidateSHA)
	if code == 0 {
		t.Fatal("promote succeeded with no approver; that is automatic promotion on a clean diff")
	}
	if !strings.Contains(errOut, "no approver") {
		t.Errorf("stderr: %q", errOut)
	}

	// promote naming the WRONG origin refuses, even with an approver.
	code, _, errOut = run(t, candidateCorpus(t, nil), "promote", "--work", t.TempDir(),
		"--repo-root", root, "--from", "4444444444444444444444444444444444444444",
		"--to", candidateSHA, "--approver", "a.human")
	if code == 0 {
		t.Fatal("promote accepted an approval for a different transition")
	}
	if !strings.Contains(errOut, "one transition, not for one") {
		t.Errorf("stderr: %q", errOut)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(archivedLicencePath))); err == nil {
		t.Error("a refused promotion still archived a licence")
	}
}

func TestCLI_PromoteWithAFullApprovalPrintsConstantsAndArchivesTheLicence(t *testing.T) {
	root := t.TempDir()
	code, out, errOut := run(t, candidateCorpus(t, nil), "promote", "--work", t.TempDir(),
		"--repo-root", root, "--from", pinnedCommitSHA, "--to", candidateSHA,
		"--approver", "t.snyder")
	if code != 0 {
		t.Fatalf("promote exited %d\nstdout:%s\nstderr:%s", code, out, errOut)
	}
	// It prints source a human must commit; it does not edit this file.
	for _, want := range []string{"pinnedCommitSHA", candidateSHA, "t.snyder",
		"Paste over the", "were cleared"} {
		if !strings.Contains(out+errOut, want) {
			t.Errorf("promote output omits %q:\nstdout:%s\nstderr:%s", want, out, errOut)
		}
	}
	if strings.Contains(out, pinnedCommitTag) {
		t.Errorf("the promoted constants carry the OLD tag %q forward:\n%s", pinnedCommitTag, out)
	}
	// The licence body was archived, verbatim.
	got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(archivedLicencePath)))
	if err != nil {
		t.Fatalf("the promotion did not archive a licence body: %v", err)
	}
	if !bytes.Equal(got, archivedLicence(t)) {
		t.Error("the archived body is not the upstream body verbatim")
	}
	// And the in-tree pin is untouched: a human still has to commit it.
	if CurrentPin().CommitSHA != pinnedCommitSHA {
		t.Fatal("promote rewrote the in-tree pin; a job that can promote itself is not a gate")
	}
}
