// D.14's evidence.
//
// ===========================================================================
// WHAT THIS SUITE CAN PROVE ON THIS HOST, AND WHAT IT CANNOT
// ===========================================================================
//
// Nuclei is NOT INSTALLED here (`Get-Command nuclei` finds nothing; `go list
// -m all` contains no projectdiscovery module — both measured on the
// development host, Windows 11, go1.26.5 windows/amd64). So no test here runs
// the engine, and none pretends to: the engine is behind an interface, driven
// by recorded shapes, and SystemEngine refuses on every host rather than
// returning a no-op that would let a scan come back clean.
//
// There is a SECOND, larger gap and it is not about this host at all.
// authz.Adjudicate is the only mint for an authz.Authorization, and
// authz.admissionChain contains Gate11RobotsDeny, which HAS NO IMPLEMENTATION
// REGISTERED (kernel.go's admissionChain comment says so explicitly and calls
// it a refusal rather than a skipped step). So from outside package authz
// there is at present NO WAY TO OBTAIN AN Authorization AT ALL, and therefore
// no way to build a TargetSpec, a Driver, or a RequestProposal that carries a
// real destination.
//
// That is measured here, not assumed:
// TestNoAuthorizationCanBeMintedUntilGate11IsRegistered runs the real Phase 1
// gates and the real admission chain and pins WHERE the chain stops. When the
// orchestrator rules on gate 11 and an implementation is registered, that
// test fails — loudly, with the list of the tests that must then be written.
// It is the only guard that can see this particular damage, because
// everything downstream of it currently refuses for the right reason and a
// suite that only checked refusals would look complete.
//
// internal/SKIPPED-CONTROLS.md entry U4 is the standing record.
//
// ===========================================================================
// THERE IS NO t.Skip IN THIS FILE
// ===========================================================================
//
// TestThisFileSkipsNothing reads this file's own syntax tree and fails if one
// appears. internal/SKIPPED-CONTROLS.md's opening section records two
// separate occasions on which a skip retired a live security control behind a
// green tick.
package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
)

// ---------------------------------------------------------------------------
// Template fixtures
// ---------------------------------------------------------------------------

// goodTemplate is the shape everything else is a variation of: the minimum
// this loader admits.
const goodTemplate = `id: anvil-fixture-ok
info:
  name: fixture
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`

// codeTemplate is the spine S5 hard exclusion, written out.
const codeTemplate = `id: anvil-fixture-code
info:
  name: code protocol fixture
  severity: high
code:
  - engine:
      - sh
    source: |
      echo pwned
`

func writeTemplates(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", p, err)
		}
	}
	return dir
}

func loadOK(t *testing.T, files map[string]string) ([]Template, []RejectedTemplate) {
	t.Helper()
	tpls, rej, err := LoadTemplates(writeTemplates(t, files))
	if err != nil {
		t.Fatalf("LoadTemplates: %v (rejected: %v)", err, rej)
	}
	return tpls, rej
}

func rejectionFor(rej []RejectedTemplate, path string) (RejectedTemplate, bool) {
	for _, r := range rej {
		if r.Path == path {
			return r, true
		}
	}
	return RejectedTemplate{}, false
}

// ---------------------------------------------------------------------------
// THE `code:` PROTOCOL — rejected at load, and provably absent afterwards
// ---------------------------------------------------------------------------

// TestCodeProtocolIsRejectedAtLoadAndCannotBeFired is D.14's named validation:
// "Test with a synthetic `code:` protocol template asserting it is rejected at
// LoadTemplates time and never reaches Fire".
//
// The second half is the one that needs a mechanism rather than a hope. "Never
// reaches Fire" is true here because Fire looks a template up BY IDENTITY in
// the admitted set, and a rejected template has no entry — so the assertion
// below is against TemplateSet.Lookup, which is the function Fire actually
// calls, rather than against a comment saying it would not.
func TestCodeProtocolIsRejectedAtLoadAndCannotBeFired(t *testing.T) {
	raw := map[string]string{
		"ok.yaml":   goodTemplate,
		"code.yaml": codeTemplate,
	}
	tpls, rej := loadOK(t, raw)

	if len(tpls) != 1 || tpls[0].ID() != "anvil-fixture-ok" {
		t.Fatalf("admitted %d template(s) %v; want exactly the non-code one", len(tpls), tpls)
	}
	r, ok := rejectionFor(rej, "code.yaml")
	if !ok {
		t.Fatalf("the `code:` template was not reported as rejected at all. Rejections: %v. "+
			"A rejection nobody can see is indistinguishable from a file that was never "+
			"there, and plan/50-dast.md D.14 requires rejection AT LOAD TIME", rej)
	}
	if r.Reason != RejectCodeProtocol {
		t.Fatalf("the `code:` template was rejected as %q; want %q so the message names "+
			"the spine S5 hard exclusion rather than a generic allowlist miss",
			r.Reason, RejectCodeProtocol)
	}
	if r.Protocol != ProtocolCode {
		t.Fatalf("the rejection names protocol %q; want %q", r.Protocol, ProtocolCode)
	}

	// The identity the rejected file WOULD have had.
	sum := sha256.Sum256([]byte(codeTemplate))
	codeDigest := hex.EncodeToString(sum[:])

	set, err := NewTemplateSet(tpls)
	if err != nil {
		t.Fatalf("NewTemplateSet: %v", err)
	}
	if _, found := set.Lookup("anvil-fixture-code", codeDigest); found {
		t.Fatal("the admitted template set resolves the `code:` template's identity. " +
			"Fire looks its template up in exactly this set, so a hit here is a `code:` " +
			"template reaching the kernel")
	}
	// Positive control: the lookup Fire performs DOES resolve an admitted
	// template. Without this, a Lookup that always returned false would pass
	// the assertion above while breaking every real probe.
	if _, found := set.Lookup(tpls[0].ID(), tpls[0].Digest()); !found {
		t.Fatal("the admitted template set does not resolve a template it admitted, so " +
			"the negative assertion above proves nothing")
	}
}

// TestTheProtocolListIsAnAllowlistAndNotADenylistOfCode is the control that
// separates this loader from the obvious wrong implementation.
//
// A check for the string "code" passes the first row and fails every other
// one. None of `javascript`, `flow`, `headless`, `self-contained`, `dns`,
// `network`, `tcp`, `file`, `ssl`, `websocket`, `whois` or an invented future
// protocol contains it.
func TestTheProtocolListIsAnAllowlistAndNotADenylistOfCode(t *testing.T) {
	cases := []struct {
		key  string
		want RejectionReason
	}{
		{"code", RejectCodeProtocol},
		{"javascript", RejectExecutesCode},
		{"flow", RejectExecutesCode},
		{"headless", RejectDrivesBrowser},
		{"self-contained", RejectSelfContained},
		{"dns", RejectProtocolNotAllowlisted},
		{"network", RejectProtocolNotAllowlisted},
		{"tcp", RejectProtocolNotAllowlisted},
		{"file", RejectProtocolNotAllowlisted},
		{"ssl", RejectProtocolNotAllowlisted},
		{"websocket", RejectProtocolNotAllowlisted},
		{"whois", RejectProtocolNotAllowlisted},
		{"requests", RejectProtocolNotAllowlisted},
		// A protocol that does not exist. This is the row that says the
		// mechanism is an allowlist: nobody had to have heard of it.
		{"quantumteleport", RejectProtocolNotAllowlisted},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			body := "id: anvil-fixture-x\ninfo:\n  name: x\nhttp:\n  - method: GET\n" +
				tc.key + ":\n  - anything: 1\n"
			_, rej, err := LoadTemplates(writeTemplates(t, map[string]string{
				"ok.yaml": goodTemplate,
				"x.yaml":  body,
			}))
			if err != nil {
				t.Fatalf("LoadTemplates: %v", err)
			}
			r, ok := rejectionFor(rej, "x.yaml")
			if !ok {
				t.Fatalf("a template declaring `%s:` was ADMITTED. The list is meant to be "+
					"an allowlist; a protocol nobody enumerated must be refused by "+
					"default. Rejections: %v", tc.key, rej)
			}
			if r.Reason != tc.want {
				t.Fatalf("`%s:` rejected as %q; want %q", tc.key, r.Reason, tc.want)
			}
		})
	}

	// Positive control. Every row above rejects; without this the whole table
	// would pass against a loader that rejected everything.
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": goodTemplate})
	if len(tpls) != 1 {
		t.Fatalf("the plain http template was not admitted (%d admitted), so the table "+
			"above proves only that this loader refuses things", len(tpls))
	}
}

// TestTheStructuralAnalysisIsNotDefeatedBySyntax is the evasion suite.
//
// Every row is a way somebody could hide a top-level `code:` from a scanner
// that read source text naively, or a way an ordinary template could be
// mis-read. The rule the loader follows is stated in analyse's doc comment:
// refuse anything whose structure is not obvious. So most rows here assert a
// REFUSAL, and the ones that assert an admission are the controls that stop
// the loader from being one that simply refuses everything.
func TestTheStructuralAnalysisIsNotDefeatedBySyntax(t *testing.T) {
	type want int
	const (
		admitted want = iota
		rejectedAsCode
		rejectedUnanalysable
		rejectedOther
	)

	cases := []struct {
		name string
		body string
		want want
	}{
		{
			name: "a double-quoted key is still the key",
			body: "id: anvil-q\ninfo:\n  name: q\nhttp:\n  - method: GET\n\"code\":\n  - engine: [sh]\n",
			want: rejectedAsCode,
		},
		{
			name: "a single-quoted key is still the key",
			body: "id: anvil-q\ninfo:\n  name: q\nhttp:\n  - method: GET\n'code':\n  - engine: [sh]\n",
			want: rejectedAsCode,
		},
		{
			name: "the whole document indented hides every key from a column-0 scanner",
			body: "  id: anvil-i\n  info:\n    name: i\n  code:\n    - engine: [sh]\n",
			want: rejectedUnanalysable,
		},
		{
			name: "a tab anywhere refuses",
			body: "id: anvil-t\ninfo:\n\tname: t\nhttp:\n  - method: GET\n",
			want: rejectedUnanalysable,
		},
		{
			name: "a top-level flow mapping refuses",
			body: "{id: anvil-f, info: {name: f}, code: [{engine: [sh]}]}\n",
			want: rejectedUnanalysable,
		},
		{
			name: "a second document refuses",
			body: "id: anvil-d\ninfo:\n  name: d\nhttp:\n  - method: GET\n---\nid: anvil-d2\ncode:\n  - engine: [sh]\n",
			want: rejectedUnanalysable,
		},
		{
			name: "a leading document marker is fine",
			body: "---\n" + strings.Replace(goodTemplate, "anvil-fixture-ok", "anvil-doc", 1),
			want: admitted,
		},
		{
			name: "a duplicate top-level key refuses",
			body: "id: anvil-dup\ninfo:\n  name: d\nhttp:\n  - method: GET\nhttp:\n  - method: POST\n",
			want: rejectedOther,
		},
		{
			name: "`code:` inside an indented block scalar is not a top-level key",
			body: "id: anvil-bs\ninfo:\n  name: bs\n  description: |\n    code:\n      - engine: [sh]\nhttp:\n  - method: GET\n",
			want: admitted,
		},
		{
			name: "a comment mentioning code: is not a key",
			body: "# code: this template used to have one\n" + strings.Replace(goodTemplate, "anvil-fixture-ok", "anvil-comment", 1),
			want: admitted,
		},
		{
			name: "CRLF line endings are normalised, not refused",
			body: strings.ReplaceAll(
				strings.Replace(goodTemplate, "anvil-fixture-ok", "anvil-crlf", 1),
				"\n", "\r\n"),
			want: admitted,
		},
		{
			name: "a byte-order mark is stripped, not treated as part of the first key",
			body: "\uFEFF" + strings.Replace(goodTemplate, "anvil-fixture-ok", "anvil-bom", 1),
			want: admitted,
		},
		{
			name: "a plain scalar at column 0 with no space after the colon refuses",
			body: "id:anvil-ns\ninfo:\n  name: n\nhttp:\n  - method: GET\n",
			want: rejectedUnanalysable,
		},
		{
			name: "a top-level sequence refuses",
			body: "- id: anvil-seq\n- code: x\n",
			want: rejectedUnanalysable,
		},
		{
			name: "no http block at all is refused rather than admitted as inert",
			body: "id: anvil-noexec\ninfo:\n  name: n\nvariables:\n  a: 1\n",
			want: rejectedOther,
		},
		{
			name: "an id carrying a zero-width character is refused",
			body: "id: anvil​fixture\ninfo:\n  name: z\nhttp:\n  - method: GET\n",
			want: rejectedOther,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tpls, rej, err := LoadTemplates(writeTemplates(t, map[string]string{
				"ok.yaml": goodTemplate,
				"x.yaml":  tc.body,
			}))
			if err != nil {
				t.Fatalf("LoadTemplates: %v", err)
			}
			r, wasRejected := rejectionFor(rej, "x.yaml")
			admittedX := false
			for _, tpl := range tpls {
				if tpl.Path() == "x.yaml" {
					admittedX = true
				}
			}
			switch tc.want {
			case admitted:
				if !admittedX {
					t.Fatalf("the fixture was REJECTED (%v) but this row is a control that "+
						"the loader still admits an ordinary template. A loader that "+
						"refuses everything satisfies every negative assertion in this "+
						"file and is useless", r)
				}
			case rejectedAsCode:
				if !wasRejected || r.Reason != RejectCodeProtocol {
					t.Fatalf("rejected=%v reason=%q; want a %q rejection. A `code:` block "+
						"written in a legal alternative spelling is still a `code:` block",
						wasRejected, r.Reason, RejectCodeProtocol)
				}
			case rejectedUnanalysable:
				if !wasRejected || r.Reason != RejectUnanalysable {
					t.Fatalf("rejected=%v reason=%q; want %q. The loader must refuse what "+
						"it cannot read rather than reading it loosely",
						wasRejected, r.Reason, RejectUnanalysable)
				}
			case rejectedOther:
				if !wasRejected {
					t.Fatalf("the fixture was admitted; want a rejection")
				}
				if r.Reason == RejectUnspecified || !r.Reason.Recognised() {
					t.Fatalf("the fixture was rejected with an unusable reason %q", r.Reason)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The loader's other refusals
// ---------------------------------------------------------------------------

// TestAnEmptyTemplateDirectoryIsNotACleanScan is the anti-vacuity floor.
func TestAnEmptyTemplateDirectoryIsNotACleanScan(t *testing.T) {
	t.Run("no files at all", func(t *testing.T) {
		_, _, err := LoadTemplates(t.TempDir())
		if !errors.Is(err, ErrNoTemplates) {
			t.Fatalf("LoadTemplates over an empty directory returned %v; want ErrNoTemplates. "+
				"An engine with no template completes successfully having tested nothing, "+
				"which is byte-identical to a target with no findings", err)
		}
	})
	t.Run("files that all reject", func(t *testing.T) {
		_, rej, err := LoadTemplates(writeTemplates(t, map[string]string{"code.yaml": codeTemplate}))
		if !errors.Is(err, ErrNoTemplates) {
			t.Fatalf("a directory whose every template was rejected returned %v; want "+
				"ErrNoTemplates", err)
		}
		if len(rej) != 1 {
			t.Fatalf("the rejections were lost on the error path: %v. The reason a load "+
				"produced nothing is the whole diagnostic", rej)
		}
	})
	t.Run("a root that does not exist", func(t *testing.T) {
		_, _, err := LoadTemplates(filepath.Join(t.TempDir(), "nope"))
		if !errors.Is(err, ErrNoTemplates) {
			t.Fatalf("a missing template root returned %v; want ErrNoTemplates", err)
		}
	})
	t.Run("no root named", func(t *testing.T) {
		if _, _, err := LoadTemplates("   "); !errors.Is(err, ErrRefused) {
			t.Fatalf("an empty template root returned %v; want ErrRefused", err)
		}
	})
}

// TestTemplateDigestIsOverTheExactBytes anchors the value D.17 pins against.
//
// It is computed here from the fixture's own bytes rather than copied from the
// loader, so a loader that hashed something else — the normalised text, the
// path, the parsed keys — fails.
func TestTemplateDigestIsOverTheExactBytes(t *testing.T) {
	body := "\uFEFF" + strings.ReplaceAll(goodTemplate, "\n", "\r\n")
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": body})
	if len(tpls) != 1 {
		t.Fatalf("admitted %d templates; want 1", len(tpls))
	}
	sum := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(sum[:])
	if tpls[0].Digest() != want {
		t.Fatalf("Digest() = %q; want the SHA-256 of the file's EXACT bytes, %q. The "+
			"loader normalises CRLF and strips a BOM before analysing; if it also hashed "+
			"the normalised text, a D.17 pin computed from the file on disk would never "+
			"match", tpls[0].Digest(), want)
	}
}

// TestALinkInTheTemplateTreeIsRejected. internal/SKIPPED-CONTROLS.md H1
// records this repository shipping a guard that a Windows DIRECTORY JUNCTION
// walked straight through, because the test only ever created the privileged
// kind of link. This one creates the strongest link the host permits and
// NEVER SKIPS: a host that can create neither kind fails, because "the bypass
// is impossible here" is a claim that has to be proven.
func TestALinkInTheTemplateTreeIsRejected(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "smuggled.yaml"), []byte(codeTemplate), 0o600); err != nil {
		t.Fatalf("writing the outside template: %v", err)
	}
	root := writeTemplates(t, map[string]string{"ok.yaml": goodTemplate})
	link := filepath.Join(root, "linked")

	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatalf("os.Symlink: %v", err)
		}
		// Windows: mklink /D needs SeCreateSymbolicLinkPrivilege, mklink /J
		// needs nothing at all. The unprivileged one is the one an ordinary
		// user or a careless build script can actually make, so it is the
		// one that has to be tested.
		out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput()
		if jerr != nil {
			t.Fatalf("this host could create neither a symlink (%v) nor a junction (%v: %s). "+
				"The test refuses to report a pass for a bypass it could not construct",
				err, jerr, strings.TrimSpace(string(out)))
		}
	}

	tpls, rej, err := LoadTemplates(root)
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	for _, tpl := range tpls {
		if strings.HasPrefix(tpl.Path(), "linked/") {
			t.Fatalf("the loader walked through the link and admitted %q. A template root "+
				"that can reach outside itself is not a root, and the file on the far "+
				"side was a `code:` template", tpl.Path())
		}
	}
	r, ok := rejectionFor(rej, "linked")
	if !ok {
		t.Fatalf("the link was neither followed nor reported. Rejections: %v. Silently "+
			"ignoring it is the third option and it is the one that leaves nobody able "+
			"to see what happened", rej)
	}
	if r.Reason != RejectSymlink {
		t.Fatalf("the link was rejected as %q; want %q", r.Reason, RejectSymlink)
	}
}

// TestTwoFilesCannotClaimOneTemplateID. Findings are attributed by id.
func TestTwoFilesCannotClaimOneTemplateID(t *testing.T) {
	_, rej, err := LoadTemplates(writeTemplates(t, map[string]string{
		"a.yaml": goodTemplate,
		// Same id, different bytes, so the digests differ and only the id
		// collides.
		"b.yaml": goodTemplate + "# a trailing comment\n",
	}))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	if len(rej) != 1 || !rej[0].Reason.Recognised() || rej[0].Reason != RejectDuplicateID {
		t.Fatalf("rejections %v; want exactly one %q", rej, RejectDuplicateID)
	}
}

// TestOversizeAndNonUTF8TemplatesAreReportedNotSkipped.
func TestOversizeAndNonUTF8TemplatesAreReportedNotSkipped(t *testing.T) {
	big := goodTemplate + "# " + strings.Repeat("x", MaxTemplateBytes) + "\n"
	_, rej, err := LoadTemplates(writeTemplates(t, map[string]string{
		"ok.yaml":  goodTemplate,
		"big.yaml": big,
		"bad.yaml": "id: anvil-bad\ninfo:\n  name: \xff\xfe\nhttp:\n  - method: GET\n",
	}))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	for path, want := range map[string]RejectionReason{
		"big.yaml": RejectTooLarge,
		"bad.yaml": RejectNotUTF8,
	} {
		r, ok := rejectionFor(rej, path)
		if !ok {
			t.Fatalf("%s produced no rejection at all; rejections: %v", path, rej)
		}
		if r.Reason != want {
			t.Fatalf("%s rejected as %q; want %q", path, r.Reason, want)
		}
	}
}

// TestNonTemplateFilesAreNotRejections. A README is not a refused template,
// and reporting it as one would bury the real refusals.
func TestNonTemplateFilesAreNotRejections(t *testing.T) {
	_, rej := loadOK(t, map[string]string{
		"ok.yaml":       goodTemplate,
		"README.md":     "# templates",
		"nested/ok.yml": strings.Replace(goodTemplate, "anvil-fixture-ok", "anvil-nested", 1),
	})
	if len(rej) != 0 {
		t.Fatalf("rejections %v; a non-template file must not appear", rej)
	}
}

// ---------------------------------------------------------------------------
// Identity, not position
// ---------------------------------------------------------------------------

// TestTemplateLookupIsByIdentityAndNotByPosition.
//
// The engine reports results asynchronously and can reorder, deduplicate, or
// report on a template it loaded elsewhere. An id-only match, or a match by
// index into a slice, files the finding under a template that did not produce
// it — silently.
func TestTemplateLookupIsByIdentityAndNotByPosition(t *testing.T) {
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": goodTemplate})
	set, err := NewTemplateSet(tpls)
	if err != nil {
		t.Fatalf("NewTemplateSet: %v", err)
	}
	id, digest := tpls[0].ID(), tpls[0].Digest()

	if _, ok := set.Lookup(id, digest); !ok {
		t.Fatal("the exact identity did not resolve")
	}
	if _, ok := set.Lookup(id, strings.Repeat("0", 64)); ok {
		t.Fatal("an admitted ID with a DIFFERENT digest resolved. That is a different " +
			"file wearing an admitted template's name, which is exactly what a pinned " +
			"template corpus exists to prevent")
	}
	if _, ok := set.Lookup("anvil-fixture-code", digest); ok {
		t.Fatal("an unadmitted ID resolved against an admitted digest")
	}
	if _, ok := (TemplateSet{}).Lookup(id, digest); ok {
		t.Fatal("the ZERO TemplateSet resolved an identity. A zero value must never mean " +
			"permitted")
	}
	if _, err := NewTemplateSet(nil); !errors.Is(err, ErrNoTemplates) {
		t.Fatalf("NewTemplateSet(nil) = %v; want ErrNoTemplates", err)
	}
}

// ---------------------------------------------------------------------------
// Defensive copies — EVERY slice and map, not just the convenient one
// ---------------------------------------------------------------------------

// TestEveryDefensiveCopyIsReal.
//
// This exact defect has been found twice in this codebase (authz Scope.Ports,
// then containment Target.Containers): a copy constructor that copies the
// struct and shares its slices, with a test that only mutated the field where
// the copy was real. So this test mutates EVERY slice a caller can reach,
// including the ones NESTED inside an element of a copied slice — which is
// where cloneTemplates would fail if it were a plain `copy`.
func TestEveryDefensiveCopyIsReal(t *testing.T) {
	tpls, _ := loadOK(t, map[string]string{
		"a.yaml": goodTemplate,
		"b.yaml": strings.Replace(goodTemplate, "anvil-fixture-ok", "anvil-fixture-b", 1),
	})

	t.Run("Template.Protocols", func(t *testing.T) {
		got := tpls[0].Protocols()
		if len(got) == 0 {
			t.Fatal("Protocols() returned nothing, so mutating it proves nothing")
		}
		got[0] = ProtocolCode
		again := tpls[0].Protocols()
		if again[0] == ProtocolCode {
			t.Fatal("writing through the slice Protocols() returned changed the template. " +
				"A caller can therefore make an admitted template claim it declares `code:`")
		}
		if !tpls[0].Declares(ProtocolHTTP) {
			t.Fatal("the mutation reached the template's own view of its protocols")
		}
	})

	t.Run("TemplateSet.Templates, including the NESTED protocols slice", func(t *testing.T) {
		set, err := NewTemplateSet(tpls)
		if err != nil {
			t.Fatalf("NewTemplateSet: %v", err)
		}
		got := set.Templates()
		got[0].id = "rewritten"
		got[0].digest = strings.Repeat("f", 64)
		// The nested slice. A cloneTemplates that copied the outer slice and
		// left `protocols` aliased passes every assertion above and fails
		// here — this is the trap the two prior defects fell into.
		got[0].protocols[0] = ProtocolCode

		again := set.Templates()
		if again[0].id == "rewritten" || again[0].digest == strings.Repeat("f", 64) {
			t.Fatal("the set's own templates were rewritten through the slice it handed out")
		}
		if again[0].protocols[0] == ProtocolCode {
			t.Fatal("the NESTED protocols slice is shared between the set and the copy it " +
				"hands out. The struct copy is real and the slice copy is not, which is " +
				"the precise shape of the two copy defects already found in this repository")
		}
	})

	t.Run("RunPlan.Targets and RunPlan.Templates", func(t *testing.T) {
		// A RunPlan needs a constructed TargetSpec, which needs an
		// Authorization. See the file header: none can be minted today. The
		// slice-copy property is still testable on the templates half, and
		// NewRunPlan's refusal of an unconstructed spec is asserted in
		// TestNewRunPlanRefusesWhatWasNeverAuthorized.
		p := RunPlan{targets: []TargetSpec{{}}, templates: cloneTemplates(tpls), sealed: true}
		got := p.Templates()
		got[0].protocols[0] = ProtocolCode
		got[0].id = "rewritten"
		if p.Templates()[0].protocols[0] == ProtocolCode || p.Templates()[0].id == "rewritten" {
			t.Fatal("RunPlan.Templates hands out an alias of the sealed plan's own templates")
		}
		tg := p.Targets()
		tg[0].url = "http://evil.example"
		tg[0].pinned = "203.0.113.9:80"
		if p.Targets()[0].url == "http://evil.example" || p.Targets()[0].pinned == "203.0.113.9:80" {
			t.Fatal("RunPlan.Targets hands out an alias, so a caller can retarget a sealed plan")
		}
	})

	t.Run("ScanResult.Findings and ScanResult.Rejected", func(t *testing.T) {
		d := &Driver{
			sealed:   true,
			findings: []Finding{{TemplateID: "a"}},
			rejected: []RejectedTemplate{{Path: "p.yaml", Reason: RejectCodeProtocol}},
		}
		got := d.Result()
		got.Findings[0].TemplateID = "rewritten"
		got.Rejected[0].Reason = RejectUnspecified
		again := d.Result()
		if again.Findings[0].TemplateID == "rewritten" {
			t.Fatal("ScanResult.Findings aliases the driver's own findings")
		}
		if again.Rejected[0].Reason == RejectUnspecified {
			t.Fatal("ScanResult.Rejected aliases the driver's own rejections")
		}
	})

	t.Run("the compiled-in lists", func(t *testing.T) {
		got := protocolAllowlist()
		got[0] = ProtocolCode
		for _, p := range protocolAllowlist() {
			if p == ProtocolCode {
				t.Fatal("mutating the slice protocolAllowlist() returned added `code:` to " +
					"the allowlist. The list must be rebuilt from constants on every call")
			}
		}
		if ProtocolCode.Admitted() {
			t.Fatal("`code:` is on the allowlist after the mutation")
		}
		rs := rejectionReasons()
		rs[0] = RejectUnspecified
		if !RejectCodeProtocol.Recognised() {
			t.Fatal("mutating rejectionReasons() unrecognised the code-protocol reason")
		}
		os := proposalOrigins()
		os[0] = authz.OriginOutOfBandCallback
		for _, o := range proposalOrigins() {
			if o == authz.OriginOutOfBandCallback {
				t.Fatal("mutating proposalOrigins() added the out-of-band callback origin")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// PDCPUpload — forbidden outright
// ---------------------------------------------------------------------------

// spyEngine records what was asked of it. It is the mock D.14's validation
// asks for: "test asserting PDCPUpload is never invoked (mock SDK client,
// assert method not called)".
type spyEngine struct {
	pdcp      int
	executed  int
	closed    int
	lastPlan  RunPlan
	results   []EngineResult
	returnErr error
}

func (s *spyEngine) ExecuteCallbackWithCtx(_ context.Context, plan RunPlan, cb func(EngineResult) error) error {
	s.executed++
	s.lastPlan = plan
	for _, r := range s.results {
		if err := cb(r); err != nil {
			return err
		}
	}
	return s.returnErr
}

func (s *spyEngine) WithPDCPUpload(string, string) error { s.pdcp++; return nil }
func (s *spyEngine) Close() error                        { s.closed++; return nil }

var _ Engine = (*spyEngine)(nil)

// TestPDCPUploadAppearsInNoCallExpressionInThisPackage is the structural half.
//
// The runtime half (a spy asserting a call count of zero) only proves what a
// test happened to exercise. This one reads the package's own syntax tree and
// fails if the identifier is ever SELECTED in a call, whatever code path
// would have reached it — which is the guard that survives a refactor nobody
// wrote a test for.
func TestPDCPUploadAppearsInNoCallExpressionInThisPackage(t *testing.T) {
	fset := token.NewFileSet()
	files := goFilesInThisPackage(t)
	declarations := 0
	inspected := 0

	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		inspected++
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Field:
				for _, name := range v.Names {
					if name.Name == "WithPDCPUpload" {
						declarations++
					}
				}
			case *ast.FuncDecl:
				if v.Name.Name == "WithPDCPUpload" {
					declarations++
				}
			case *ast.CallExpr:
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "WithPDCPUpload" {
					t.Errorf("%s:%d calls WithPDCPUpload. plan/50-dast.md D.14 forbidden "+
						"actions: \"Never call WithPDCPUpload(scanID, teamID)\". The method "+
						"exists on the Engine interface so that its absence from the call "+
						"graph is provable, not so that it can be used",
						filepath.Base(path), fset.Position(v.Pos()).Line)
				}
			}
			return true
		})
	}

	if inspected == 0 {
		t.Fatal("no Go file in this package was parsed, so this guard reported a pass it " +
			"did not measure")
	}
	// Anti-vacuity. If the interface method is renamed or removed, the scan
	// above finds nothing and passes forever while the forbidden call becomes
	// unnameable — and therefore uncheckable.
	if declarations == 0 {
		t.Fatalf("the identifier WithPDCPUpload is DECLARED nowhere in the %d file(s) "+
			"scanned. This guard then has nothing to look for and would pass over a "+
			"package that called the SDK option under any other spelling", inspected)
	}
}

// TestTheEngineSpyNeverSeesPDCPUploadOrInteractsh is the runtime half.
func TestTheEngineSpyNeverSeesPDCPUploadOrInteractsh(t *testing.T) {
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": goodTemplate})
	spy := &spyEngine{}

	// Driver.Run needs an Authorization for its TargetSpec, which cannot be
	// minted (see the file header). The plan the engine is handed is
	// therefore exercised directly, through the same constructor Run uses.
	plan := RunPlan{targets: []TargetSpec{{sealed: true, pinned: "203.0.113.7:443",
		url: "https://target.example.com:443"}}, templates: cloneTemplates(tpls), sealed: true}

	if err := spy.ExecuteCallbackWithCtx(context.Background(), plan, func(EngineResult) error {
		return nil
	}); err != nil {
		t.Fatalf("spy execute: %v", err)
	}
	if spy.pdcp != 0 {
		t.Fatalf("WithPDCPUpload was called %d time(s)", spy.pdcp)
	}
	if spy.executed != 1 {
		t.Fatalf("the engine was executed %d time(s); want 1, otherwise the assertion "+
			"above is a claim about an engine nobody drove", spy.executed)
	}
	if spy.lastPlan.InteractshEnabled() {
		t.Fatal("the plan handed to the engine has interactsh enabled")
	}
	if spy.lastPlan.PDCPUploadEnabled() {
		t.Fatal("the plan handed to the engine has cloud upload enabled")
	}
}

// TestInteractshAndCloudUploadAreOffOnEveryConstructedPlan sweeps the
// constructor rather than one instance. There is no argument to NewRunPlan
// that turns either on, and that is the property being pinned.
func TestInteractshAndCloudUploadAreOffOnEveryConstructedPlan(t *testing.T) {
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": goodTemplate})
	spec := TargetSpec{sealed: true, pinned: "203.0.113.7:443", url: "https://t.example:443"}
	// NewTargetSpec cannot be reached without an Authorization, so this
	// literal stands in for the shape. It is legal only because this test is
	// IN the package; no other package can write it, which is the point of
	// the unexported fields.
	spec.target = authz.Target{}

	if _, err := NewRunPlan([]TargetSpec{spec}, tpls); err == nil {
		t.Fatal("NewRunPlan accepted a TargetSpec whose authz.Target is the zero value. " +
			"Constructed() must require the kernel's target, or a half-built spec reaches " +
			"the engine")
	} else if !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("NewRunPlan refused with %v; want ErrUnconstructed", err)
	}

	// The positive control, and the property this test is named for: a plan
	// the constructor DID build reports both capabilities off. Without this
	// row the assertions are satisfied by a constructor that never returns
	// a plan at all.
	spec.target = mustBareTarget(t)
	plan, err := NewRunPlan([]TargetSpec{spec}, tpls)
	if err != nil {
		t.Fatalf("NewRunPlan refused a well-formed plan: %v", err)
	}
	if plan.InteractshEnabled() {
		t.Fatal("a constructed RunPlan has interactsh enabled. plan/50-dast.md D.14: " +
			"interactsh/OAST must be off by default, and there is meant to be no argument " +
			"to this constructor that turns it on")
	}
	if plan.PDCPUploadEnabled() {
		t.Fatal("a constructed RunPlan has cloud upload enabled")
	}

	// And the zero plan, which is what a caller who skipped the constructor
	// holds: both flags off, and Constructed false.
	var zero RunPlan
	if zero.InteractshEnabled() || zero.PDCPUploadEnabled() || zero.Constructed() {
		t.Fatal("the zero RunPlan reports itself constructed or reports a capability on. " +
			"A Go zero value must never mean permitted")
	}
}

// TestNoOutOfBandOriginCanBeProposed is interactsh's default made structural.
//
// D.14's validation asks for a test "asserting interactsh callback URLs are
// absent from generated requests by default". A test that grepped generated
// requests for known OAST hostnames would be a denylist of somebody else's
// domain names. This asserts the mechanism instead: there is no ORIGIN under
// which this driver will propose an out-of-band request, so there is no
// request for a callback URL to appear in.
func TestNoOutOfBandOriginCanBeProposed(t *testing.T) {
	refused := []authz.RequestOrigin{
		authz.OriginOutOfBandCallback,
		authz.OriginBrowserFetch,
		authz.OriginWebSocketUpgrade,
	}
	for _, o := range refused {
		t.Run(string(o), func(t *testing.T) {
			_, err := NewRequestProposal(ProposalFacts{
				Origin:         o,
				Method:         authz.MethodGet,
				Path:           "/",
				Technique:      authz.TechniquePassiveObservation,
				TemplateID:     "anvil-fixture-ok",
				TemplateDigest: strings.Repeat("a", 64),
			})
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("NewRequestProposal accepted origin %q with error %v. Every one of "+
					"these needs a protocol the template allowlist refuses, so admitting "+
					"one would put the two halves out of step", o, err)
			}
			if !strings.Contains(err.Error(), string(o)) {
				t.Fatalf("the refusal does not name the origin: %v", err)
			}
		})
	}

	// The control: an origin this driver DOES propose gets past the origin
	// check and fails later, on the destination — which is the only thing
	// still missing.
	for _, o := range proposalOrigins() {
		_, err := NewRequestProposal(ProposalFacts{
			Origin:         o,
			Method:         authz.MethodGet,
			Path:           "/",
			Technique:      authz.TechniquePassiveObservation,
			TemplateID:     "anvil-fixture-ok",
			TemplateDigest: strings.Repeat("a", 64),
		})
		if !errors.Is(err, ErrUnconstructed) {
			t.Fatalf("origin %q was refused as %v; a permitted origin must reach the "+
				"destination check, otherwise the table above only proves that this "+
				"constructor refuses everything", o, err)
		}
	}
}

// TestARequestProposalCannotBeMadeFromUnvalidatedFacts.
func TestARequestProposalCannotBeMadeFromUnvalidatedFacts(t *testing.T) {
	base := ProposalFacts{
		Origin:         authz.OriginInitial,
		Method:         authz.MethodGet,
		Path:           "/",
		Technique:      authz.TechniquePassiveObservation,
		TemplateID:     "anvil-fixture-ok",
		TemplateDigest: strings.Repeat("a", 64),
	}
	cases := []struct {
		name  string
		mutid func(*ProposalFacts)
		want  error
	}{
		{"unrecognised method", func(f *ProposalFacts) { f.Method = authz.Method("FETCH") }, ErrRefused},
		{"zero method", func(f *ProposalFacts) { f.Method = authz.MethodUnset }, ErrRefused},
		{"unclassified technique", func(f *ProposalFacts) {
			f.Technique = authz.Technique("mostly_harmless")
		}, ErrRefused},
		{"zero technique", func(f *ProposalFacts) { f.Technique = authz.TechniqueUnspecified }, ErrRefused},
		{"no template id", func(f *ProposalFacts) { f.TemplateID = "" }, ErrRefused},
		{"no template digest", func(f *ProposalFacts) { f.TemplateDigest = "" }, ErrRefused},
		{"zero origin", func(f *ProposalFacts) { f.Origin = authz.OriginUnset }, ErrRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			tc.mutid(&f)
			_, err := NewRequestProposal(f)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewRequestProposal = %v; want %v", err, tc.want)
			}
		})
	}
	// A DESTRUCTIVE technique is classified, so it passes the classification
	// check here and is refused by gate 15 inside the kernel. That is the
	// division of labour, and it is asserted rather than assumed: this
	// package must not quietly become a second, divergent copy of gate 15's
	// denylist.
	f := base
	f.Technique = authz.TechniqueDenialOfService
	if _, err := NewRequestProposal(f); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("a destructive-but-classified technique was refused HERE (%v) rather than "+
			"reaching gate 15. Two copies of that denylist can disagree; there is one, "+
			"and it is in the kernel", err)
	}
}

// TestRequestProposalHoldsNothingThatCouldOpenASocket is plan/50-dast.md exit
// criterion 19, proven by reflection: "The RequestProposal type has zero
// methods or fields capable of performing network I/O".
func TestRequestProposalHoldsNothingThatCouldOpenASocket(t *testing.T) {
	forbidden := map[reflect.Kind]string{
		reflect.Interface:     "an interface field can hold anything, including a net.Conn",
		reflect.Func:          "a func field is a capability handed in from elsewhere",
		reflect.Chan:          "a channel is a handle to something running",
		reflect.Ptr:           "a pointer field reaches mutable state this type does not own",
		reflect.UnsafePointer: "unsafe.Pointer is every capability at once",
		reflect.Map:           "a map field is shared mutable state",
	}
	var walk func(t *testing.T, typ reflect.Type, path string, depth int)
	walk = func(t *testing.T, typ reflect.Type, path string, depth int) {
		if depth > 6 {
			t.Fatalf("%s: the type graph is deeper than this walk goes, so the guard did "+
				"not finish looking", path)
		}
		// net/netip is a VALUE package: netip.Addr holds an unexported
		// pointer into the interned-address table and has no dialer, no
		// listener and no resolver. authz's own gate-3 scanner lists it as
		// inert for exactly that reason ("an address VALUE type; no dialer,
		// listener or resolver"), and it is the type the kernel uses to hold
		// a PINNED address — the opposite of a capability. It is the ONE
		// place this walk stops before reaching a pointer, and it stops by
		// package path rather than by field name so that a different
		// pointer-bearing type cannot arrive under the same exemption.
		if typ.PkgPath() == "net/netip" {
			return
		}
		if why, bad := forbidden[typ.Kind()]; bad {
			t.Fatalf("%s is a %s: %s", path, typ.Kind(), why)
		}
		if typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
			walk(t, typ.Elem(), path+"[]", depth+1)
			return
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			walk(t, f.Type, path+"."+f.Name, depth+1)
		}
	}

	rp := reflect.TypeOf(RequestProposal{})
	if rp.NumField() == 0 {
		t.Fatal("RequestProposal has no fields, so this walk inspects nothing")
	}
	walk(t, rp, "RequestProposal", 0)

	// The methods, too. A method returning something dialable is the same
	// capability by a different route.
	v := reflect.TypeOf(RequestProposal{})
	if v.NumMethod() == 0 {
		t.Fatal("RequestProposal has no methods, so the method sweep inspects nothing")
	}
	for i := 0; i < v.NumMethod(); i++ {
		m := v.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			out := m.Type.Out(j)
			if why, bad := forbidden[out.Kind()]; bad {
				t.Fatalf("RequestProposal.%s returns a %s: %s", m.Name, out.Kind(), why)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// The absence contract
// ---------------------------------------------------------------------------

// TestSystemEngineRefusesRatherThanReturningANoOp.
func TestSystemEngineRefusesRatherThanReturningANoOp(t *testing.T) {
	eng, err := SystemEngine()
	if err == nil {
		t.Fatal("SystemEngine returned no error. nuclei is not installed on any host this " +
			"module ships an adapter for, and an Engine that reported zero findings would " +
			"be indistinguishable from a clean target")
	}
	if eng != nil {
		t.Fatal("SystemEngine returned an Engine alongside its error")
	}
	if !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("the error does not unwrap to ErrEngineUnavailable: %v", err)
	}
	var missing *EngineUnavailableError
	if !errors.As(err, &missing) {
		t.Fatalf("the error is not an *EngineUnavailableError: %v", err)
	}
	if missing.ExitCode() != ExitCodeArtefactAbsent {
		t.Fatalf("ExitCode() = %d; want %d", missing.ExitCode(), ExitCodeArtefactAbsent)
	}
	for _, want := range []string{EngineName, InstallHint, "NOT a clean target"} {
		if !strings.Contains(missing.Error(), want) {
			t.Fatalf("the error message does not contain %q: %s", want, missing.Error())
		}
	}
}

// TestTheArtefactAbsentExitCodeAgreesWithTheSCACollector.
//
// One code across Anvil for "the engine or the ruleset is not present", so an
// operator's wrapper needs no per-tool table. It is asserted by READING the
// other package's source rather than by importing it: D.9's tier-wide gate 2
// check permits a DAST package to link only the stdlib, the DAST tree and
// internal/record, and linking the SCA collector to reach one integer would
// widen that surface for nothing.
func TestTheArtefactAbsentExitCodeAgreesWithTheSCACollector(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "collector", "repo", "trivy_cli.go")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v. This guard refuses to report a pass it did not measure", path, err)
	}
	want := fmt.Sprintf("const ExitCodeArtefactAbsent = %d", ExitCodeArtefactAbsent)
	if !strings.Contains(string(body), want) {
		t.Fatalf("internal/collector/repo does not declare %q. The two artefact-absent exit "+
			"codes have diverged, and an operator wrapping both tiers now needs a per-tool "+
			"table to tell 'not installed' from 'failed'", want)
	}
}

// TestAssertNotSilentlyEmptyRefusesEveryWayNothingRan.
//
// This is the Trivy precedent applied to a probe engine:
// internal/collector/repo.ScanResult.AssertNotSilentlyEmpty exists because an
// SCA collector whose tool was missing returned a finding list byte-identical
// to a clean repository's.
func TestAssertNotSilentlyEmptyRefusesEveryWayNothingRan(t *testing.T) {
	clean := ScanResult{
		Target: "https://target.example.com:443 (93.184.216.34)",
		Coverage: Coverage{
			TemplatesAdmitted: 12,
			RequestsAdmitted:  40,
			RequestsIssued:    40,
			EngineWired:       true,
			IssuerWired:       true,
		},
	}
	// The positive control FIRST. Without it every row below is satisfied by
	// a function that returns an error unconditionally.
	if err := clean.AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("a scan that admitted 12 templates and issued 40 requests was refused: %v. "+
			"An assertion that refuses everything cannot distinguish anything", err)
	}

	cases := []struct {
		name string
		mut  func(*ScanResult)
	}{
		{"the zero result", func(r *ScanResult) { *r = ScanResult{} }},
		{"no engine was ever wired", func(r *ScanResult) {
			r.Coverage.EngineWired = false
			r.Coverage.RequestsIssued = 0
		}},
		{"zero templates admitted", func(r *ScanResult) { r.Coverage.TemplatesAdmitted = 0 }},
		{"templates admitted but nothing reached the wire", func(r *ScanResult) {
			r.Coverage.RequestsIssued = 0
			r.Coverage.RequestsRefused = 40
			r.Coverage.RequestsAdmitted = 0
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := clean
			tc.mut(&r)
			err := r.AssertNotSilentlyEmpty()
			if err == nil {
				t.Fatalf("AssertNotSilentlyEmpty() = nil for %q. An empty finding list "+
					"here records the absence of a scan, not the absence of findings", tc.name)
			}
			if !errors.Is(err, ErrNothingProbed) {
				t.Fatalf("the refusal does not unwrap to ErrNothingProbed: %v", err)
			}
		})
	}

	// Coverage.ProbedNothing is the predicate the refusal rests on, and its
	// zero value must fail closed.
	if !(Coverage{}).ProbedNothing() {
		t.Fatal("the zero Coverage reports that something was probed. A Coverage nobody " +
			"filled in describes a scan nobody ran")
	}
	if clean.Coverage.ProbedNothing() {
		t.Fatal("a fully populated Coverage reports that nothing was probed")
	}
}

// TestRunWithoutAnEngineIsAnAbsenceAndNotAnEmptyResult.
func TestRunWithoutAnEngineIsAnAbsenceAndNotAnEmptyResult(t *testing.T) {
	d := &Driver{sealed: true}
	err := d.Run(context.Background(), nil)
	if err == nil {
		t.Fatal("Run with no Engine returned nil. A driver that reports success having " +
			"executed nothing is the silent-clean failure this package exists to prevent")
	}
	var missing *EngineUnavailableError
	if !errors.As(err, &missing) {
		t.Fatalf("Run with no Engine returned %v; want an *EngineUnavailableError", err)
	}

	// And on an unconstructed driver.
	var zero *Driver
	if err := zero.Run(context.Background(), nil); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("Run on a nil Driver = %v; want ErrUnconstructed", err)
	}
	if _, err := zero.Fire(context.Background(), RequestProposal{}, authz.Clock{}); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("Fire on a nil Driver = %v; want ErrUnconstructed", err)
	}
}

// TestFireRefusesAProposalItCannotAttributeAndNeverAudits.
//
// The check that a proposal names an ADMITTED template runs before anything
// touches the kernel. This asserts both halves: the refusal, and that the
// audit sink saw nothing — because a refusal that had already written gate
// rows would mean the kernel had been consulted about a template that must
// never reach it.
func TestFireRefusesAProposalItCannotAttributeAndNeverAudits(t *testing.T) {
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": goodTemplate})
	set, err := NewTemplateSet(tpls)
	if err != nil {
		t.Fatalf("NewTemplateSet: %v", err)
	}
	sink := &countingSink{}
	d := &Driver{sealed: true, cfg: Config{Templates: set}}

	sum := sha256.Sum256([]byte(codeTemplate))
	p := RequestProposal{
		sealed:    true,
		spec:      TargetSpec{sealed: true, pinned: "203.0.113.7:443"},
		origin:    authz.OriginInitial,
		method:    authz.MethodGet,
		path:      "/",
		technique: authz.TechniquePassiveObservation,
		tplID:     "anvil-fixture-code",
		tplDigest: hex.EncodeToString(sum[:]),
	}
	// The spec has no authz.Target, so Constructed() is false and Fire stops
	// at the proposal check. Give it one that IS constructed but unauthorized
	// so the template check is the one that fires.
	p.spec.target = mustBareTarget(t)

	_, err = d.Fire(context.Background(), p, mustClock(t))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Fire accepted a proposal naming a template the driver did not admit: %v", err)
	}
	if !strings.Contains(err.Error(), "anvil-fixture-code") {
		t.Fatalf(`Fire refused, but NOT at the template-identity check — the refusal does not
name the template at all. MEASURED: with the identity lookup removed, this is
what the failure looks like, because Fire falls through to
authz.RequireAuthorization and reports a missing authorization instead.

That is still a refusal, and it is not the control being tested here. The
control is that a template the loader REJECTED cannot reach the kernel through
Fire, and it holds because the lookup is by identity and a rejected template
has no entry. Restore it.

Refusal was: %v`, err)
	}
	if sink.n != 0 {
		t.Fatalf("%d audit row(s) were written for a proposal the driver refused before "+
			"consulting the kernel", sink.n)
	}
	if got := d.Result().Coverage.RequestsRefused; got != 1 {
		t.Fatalf("Coverage.RequestsRefused = %d after one refusal; want 1. A refusal that "+
			"does not move the counter is invisible to AssertNotSilentlyEmpty", got)
	}
	if d.Result().Coverage.RequestsIssued != 0 {
		t.Fatal("a refused proposal was counted as issued")
	}
}

type countingSink struct{ n int }

func (s *countingSink) WriteGateDecision(authz.GateRecord) (authz.AuditSeq, error) {
	s.n++
	return authz.AuditSeq(s.n), nil
}

// ---------------------------------------------------------------------------
// The kernel, driven for real
// ---------------------------------------------------------------------------

const (
	fixtureHost     = "target.example.com"
	fixtureRepo     = "Susquehanna-Syntax/Anvil"
	fixtureNowRFC   = "2026-08-10T12:00:00Z"
	fixtureIssuedS  = "2026-08-01T12:00:00Z"
	fixtureExpiresS = "2026-08-20T12:00:00Z"
)

func mustClock(t *testing.T) authz.Clock {
	t.Helper()
	at, err := time.Parse(time.RFC3339, fixtureNowRFC)
	if err != nil {
		t.Fatalf("parsing the fixture instant: %v", err)
	}
	c, err := authz.NewClock(at)
	if err != nil {
		t.Fatalf("authz.NewClock: %v", err)
	}
	return c
}

// mustBareTarget builds a kernel Target directly. NewTarget is exported and
// does not require an Authorization — it is gate 8/9's OUTPUT type, not a
// permission — so a Target can be constructed for a test that needs one to
// exist. It authorizes nothing on its own; RequireAuthorization is what
// decides, and it refuses this one.
func mustBareTarget(t *testing.T) authz.Target {
	t.Helper()
	tgt, err := authz.NewTarget(authz.SchemeHTTPS, fixtureHost, fixtureHost, 443,
		mustAddr(t, "93.184.216.34"))
	if err != nil {
		t.Fatalf("authz.NewTarget: %v", err)
	}
	return tgt
}

func scopeFileJSON() []byte {
	return []byte(fmt.Sprintf(
		`{"schema_version":1,"mode":"external","allow":[{"host":%q,"ports":[443]}],"deny":[]}`,
		fixtureHost))
}

func attestationFileJSON(hash authz.ScopeHash) []byte {
	return []byte(fmt.Sprintf(
		`{"schema_version":1,"id":"attest-2026-08-01-001","identity":"Susquehanna Syntax, `+
			`operator of %s","authority":"operator","scope_hash":%q,"issued_at":%q,"expires_at":%q}`,
		fixtureHost, string(hash), fixtureIssuedS, fixtureExpiresS))
}

// initiateRun drives the real Phase 1 gates. Nothing here is a fixture double:
// gates 6, 4, 5 and 7 all run, and EnableDAST mints the gate-1 enablement.
func initiateRun(t *testing.T) authz.RunInitiation {
	t.Helper()
	raw := scopeFileJSON()
	trigger, err := authz.NewTriggerContext(authz.TriggerFacts{
		Event:            authz.TriggerEventManualOperator,
		Repository:       fixtureRepo,
		Actor:            "operator",
		ActorPermission:  authz.ActorPermissionAdmin,
		PermissionSource: authz.PermissionSourceOperatorLocal,
	})
	if err != nil {
		t.Fatalf("authz.NewTriggerContext: %v", err)
	}
	policy, err := authz.NewTriggerPolicy(authz.TriggerEventManualOperator)
	if err != nil {
		t.Fatalf("authz.NewTriggerPolicy: %v", err)
	}
	init, res := authz.InitiateRun(authz.RunRequest{
		Artifact:                   authz.ArtifactDAST,
		Mode:                       string(authz.ModeExternal),
		ScopeFile:                  raw,
		AttestationFile:            attestationFileJSON(authz.ScopeHashOf(raw)),
		AttestationLifetimeCeiling: authz.MaxAttestationLifetime,
		Trigger:                    trigger,
		TriggerPolicy:              policy,
		ScopeRepository:            fixtureRepo,
		Clock:                      mustClock(t),
	})
	if !res.Passed() {
		t.Fatalf("authz.InitiateRun refused at %s: %v. This harness drives the real Phase 1 "+
			"gates, so a refusal here means the fixture no longer satisfies them",
			res.Gate(), res.Err())
	}
	if !init.Initiated() {
		t.Fatal("authz.InitiateRun passed but the initiation reports itself uninitiated")
	}
	return init
}

// TestNoAuthorizationCanBeMintedUntilGate11IsRegistered is the single most
// important test in this file, and it is a test about what is NOT possible.
//
// authz.Adjudicate is the only mint for an authz.Authorization. The admission
// chain contains Gate11RobotsDeny and nothing is registered for it, so the
// chain refuses every target there — kernel.go's own comment says "A missing
// gate is a REFUSAL, never a skipped step" and leaves the decision on where
// the robots policy enters the kernel to the orchestrator.
//
// The consequence for D.14 is exact and it is recorded here rather than in a
// comment nobody runs: THE DRIVER'S ADMIT-AND-ISSUE PATH CANNOT BE EXERCISED
// FROM OUTSIDE PACKAGE authz TODAY. Every test in this file that would need a
// TargetSpec built by NewTargetSpec instead asserts a refusal.
//
// When gate 11 is registered this test FAILS, and its message lists what must
// then be written. That is deliberate: everything downstream currently refuses
// for the right reason, so a suite without this test would look complete on
// the day the gap closed.
func TestNoAuthorizationCanBeMintedUntilGate11IsRegistered(t *testing.T) {
	init := initiateRun(t)
	scope, err := init.Scope()
	if err != nil {
		t.Fatalf("init.Scope: %v", err)
	}
	att, err := init.Attestation()
	if err != nil {
		t.Fatalf("init.Attestation: %v", err)
	}
	en, err := init.Enablement()
	if err != nil {
		t.Fatalf("init.Enablement: %v", err)
	}

	sink := &countingSink{}
	dec := authz.Adjudicate(sink, en, mustBareTarget(t), scope, att, mustClock(t))

	if dec.Allowed() {
		t.Fatalf(`the kernel ADMITTED a target, so an authz.Authorization can now be minted
from outside package authz. This test is the tripwire for exactly that, and it
is now the thing standing between this packet and its stop condition. Write:

  1. NewTargetSpec against the real Authorization, asserting URL() carries the
     CANONICAL host and PinnedAddr() carries gate 9's pinned address.
  2. Fire's happy path end to end: proposal -> NewRequestIntent ->
     GateAudit.AuditedAdmit -> Issuer, asserting one audit row per gate in
     authz.GovernorGateOrder() and that Coverage.RequestsIssued moved.
  3. Fire's refusal path with a REAL kernel refusal (an out-of-scope
     redirect target), asserting nothing reached the Issuer.
  4. Driver.Run's unattributable-result refusal, which needs a Driver, which
     needs an Authorization.
  5. NewTargetSpec refusing an Authorization minted for a DIFFERENT target,
     which is the cross-target token reuse RequireAuthorization exists for.

Then delete this test and update internal/SKIPPED-CONTROLS.md U4.`)
	}
	if dec.Gate() != authz.Gate11RobotsDeny {
		t.Fatalf(`the admission chain stopped at %s (%s), not at gate 11.

This test pins WHERE the chain stops so that the reason D.14's driver cannot be
exercised end to end stays measured rather than assumed. A stop at a different
gate means the fixture harness above no longer satisfies gates 4-10, and the
gate-11 conclusion recorded in internal/SKIPPED-CONTROLS.md U4 would be wrong.
Refusal detail: %v`, dec.Gate(), dec.Reason(), dec.Err())
	}
	if _, err := dec.Authorization(); err == nil {
		t.Fatal("a refused Decision handed out an Authorization")
	}
	if sink.n == 0 {
		t.Fatal("the refused adjudication wrote zero audit rows. Gate 21 logs every " +
			"allow AND every deny; a denial whose rows all vanish is the same control " +
			"failing in the direction nobody looks at")
	}
}

// TestTargetSpecRefusesEveryUnauthorizedRoute. This is the fail-closed half of
// the boundary, and it is fully testable today.
func TestTargetSpecRefusesEveryUnauthorizedRoute(t *testing.T) {
	tgt := mustBareTarget(t)

	cases := []struct {
		name   string
		auth   authz.Authorization
		target authz.Target
	}{
		{"a zero Authorization against a real target", authz.Authorization{}, tgt},
		{"a zero Authorization against a zero target", authz.Authorization{}, authz.Target{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := NewTargetSpec(tc.auth, tc.target)
			if err == nil {
				t.Fatal("NewTargetSpec built a spec with no authorization. A target that " +
					"reaches the engine without passing gates 8-10 is a scope bypass with " +
					"extra steps")
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not unwrap to ErrRefused: %v", err)
			}
			if spec.Constructed() {
				t.Fatal("a refused NewTargetSpec still returned a constructed spec")
			}
		})
	}

	// The zero value, which is what any composite literal in another package
	// can produce.
	var zero TargetSpec
	if zero.Constructed() {
		t.Fatal("the zero TargetSpec reports itself constructed")
	}
	if zero.URL() != "" || zero.PinnedAddr() != "" {
		t.Fatal("the zero TargetSpec names a destination")
	}
}

// TestNewDriverRefusesEveryHalfBuiltKernel.
func TestNewDriverRefusesEveryHalfBuiltKernel(t *testing.T) {
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": goodTemplate})
	set, err := NewTemplateSet(tpls)
	if err != nil {
		t.Fatalf("NewTemplateSet: %v", err)
	}
	init := initiateRun(t)
	scope, _ := init.Scope()
	att, _ := init.Attestation()
	key, res := authz.NewAuditKey(att, scope)
	if !res.Passed() {
		t.Fatalf("authz.NewAuditKey: %v", res.Err())
	}
	run, err := init.RunClock()
	if err != nil {
		t.Fatalf("init.RunClock: %v", err)
	}
	audit, res := authz.NewGateAudit(&countingSink{}, key, run)
	if !res.Passed() {
		t.Fatalf("authz.NewGateAudit: %v", res.Err())
	}
	gov, res := authz.NewGovernor(authz.GovernorConfig{
		Target:      mustBareTarget(t),
		Scope:       scope,
		Attestation: att,
		Caps:        authz.CodedCaps(),
		Thresholds:  authz.CodedHealthThresholds(),
		Robots:      authz.RobotsNotFound(fixtureHost, 443),
		Start:       mustClock(t),
	})
	if !res.Passed() {
		t.Fatalf("authz.NewGovernor: %v", res.Err())
	}

	full := Config{
		Governor:  gov,
		Audit:     audit,
		Templates: set,
		Target:    mustBareTarget(t),
	}
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"no governor", func(c *Config) { c.Governor = nil }},
		{"no audit writer", func(c *Config) { c.Audit = nil }},
		{"no template set", func(c *Config) { c.Templates = TemplateSet{} }},
		{"no target", func(c *Config) { c.Target = authz.Target{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full
			tc.mut(&cfg)
			if _, err := NewDriver(cfg); err == nil {
				t.Fatalf("NewDriver accepted a config with %q", tc.name)
			}
		})
	}
	// And the row that matters most: a config that is complete in every
	// respect EXCEPT the authorization is still refused, because
	// NewTargetSpec is on the constructor's critical path.
	if _, err := NewDriver(full); err == nil {
		t.Fatal("NewDriver built a driver from a fully-wired kernel and a ZERO " +
			"Authorization. Every gate can be in place and the token still has to name " +
			"this target")
	} else if !errors.Is(err, ErrRefused) {
		t.Fatalf("the refusal does not unwrap to ErrRefused: %v", err)
	}
}

// TestNewRunPlanRefusesWhatWasNeverAuthorized.
func TestNewRunPlanRefusesWhatWasNeverAuthorized(t *testing.T) {
	tpls, _ := loadOK(t, map[string]string{"ok.yaml": goodTemplate})
	if _, err := NewRunPlan(nil, tpls); !errors.Is(err, ErrRefused) {
		t.Fatalf("NewRunPlan with no targets = %v; want ErrRefused. A run plan with no "+
			"target probes nothing and reports clean", err)
	}
	if _, err := NewRunPlan([]TargetSpec{{}}, tpls); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("NewRunPlan accepted a zero TargetSpec: %v", err)
	}
	spec := TargetSpec{sealed: true, pinned: "203.0.113.7:443", target: mustBareTarget(t)}
	if _, err := NewRunPlan([]TargetSpec{spec}, nil); !errors.Is(err, ErrNoTemplates) {
		t.Fatalf("NewRunPlan with no templates = %v; want ErrNoTemplates", err)
	}
	if _, err := NewRunPlan([]TargetSpec{spec}, []Template{{}}); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("NewRunPlan accepted a zero Template: %v", err)
	}
	plan, err := NewRunPlan([]TargetSpec{spec}, tpls)
	if err != nil {
		t.Fatalf("NewRunPlan refused a well-formed plan: %v. Every assertion above would "+
			"then be satisfied by a constructor that refuses everything", err)
	}
	if !plan.Constructed() {
		t.Fatal("a plan NewRunPlan built reports itself unconstructed")
	}
}

// ---------------------------------------------------------------------------
// Scrubbing
// ---------------------------------------------------------------------------

func TestScrubRemovesEveryHiddenClassAndCountsIt(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		check func(EvidenceStats) bool
	}{
		{"bidi override", "a‮b", "ab", func(s EvidenceStats) bool { return s.Bidi == 1 }},
		{"bidi isolate", "a⁦b⁩", "ab", func(s EvidenceStats) bool { return s.Bidi == 2 }},
		{"zero width space", "a​b", "ab", func(s EvidenceStats) bool { return s.ZeroWidth == 1 }},
		{"word joiner", "a⁠b", "ab", func(s EvidenceStats) bool { return s.ZeroWidth == 1 }},
		{"soft hyphen", "a­b", "ab", func(s EvidenceStats) bool { return s.ZeroWidth == 1 }},
		{"tag character", "a\U000E0041b", "ab", func(s EvidenceStats) bool { return s.Tag == 1 }},
		{"C0 control", "a\x07b", "ab", func(s EvidenceStats) bool { return s.Controls == 1 }},
		{"C1 control", "ab", "ab", func(s EvidenceStats) bool { return s.Controls == 1 }},
		{"DEL", "a\x7Fb", "ab", func(s EvidenceStats) bool { return s.Controls == 1 }},
		{"invalid utf8", "a\xffb", "ab", func(s EvidenceStats) bool { return s.InvalidUTF8 == 1 }},
		{"tab and newline survive", "a\tb\nc", "a\tb\nc", func(s EvidenceStats) bool { return !s.Modified() }},
		{"ordinary text is untouched", "GET / -> 200", "GET / -> 200",
			func(s EvidenceStats) bool { return !s.Modified() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, st := scrub(tc.in)
			if got != tc.want {
				t.Fatalf("scrub(%q) = %q; want %q", tc.in, got, tc.want)
			}
			if !tc.check(st) {
				t.Fatalf("scrub(%q) stats = %s, which does not account for what it removed",
					tc.in, st)
			}
		})
	}

	t.Run("length is bounded and the truncation is recorded", func(t *testing.T) {
		in := strings.Repeat("x", MaxEvidenceBytes+1000)
		got, st := scrub(in)
		if len(got) > MaxEvidenceBytes {
			t.Fatalf("scrub returned %d bytes; the cap is %d", len(got), MaxEvidenceBytes)
		}
		if st.TruncatedFrom != len(in) {
			t.Fatalf("TruncatedFrom = %d; want %d, otherwise a reader cannot tell the "+
				"evidence was cut", st.TruncatedFrom, len(in))
		}
		if !st.Modified() {
			t.Fatal("a truncated string does not report itself modified")
		}
	})

	t.Run("truncation does not split a rune", func(t *testing.T) {
		in := strings.Repeat("é", MaxEvidenceBytes)
		got, _ := scrub(in)
		if strings.ContainsRune(got, 0xFFFD) {
			t.Fatal("truncation produced a replacement character, so it cut a rune in half")
		}
	})

	t.Run("Merge accumulates", func(t *testing.T) {
		var acc EvidenceStats
		_, a := scrub("x‮y")
		_, b := scrub("x​y")
		acc.Merge(a)
		acc.Merge(b)
		if acc.Bidi != 1 || acc.ZeroWidth != 1 || acc.Removed() != 2 {
			t.Fatalf("Merge lost a count: %s", acc)
		}
	})
}

// ---------------------------------------------------------------------------
// Structural guards over this package's own source
// ---------------------------------------------------------------------------

// TestThisFileSkipsNothing. internal/SKIPPED-CONTROLS.md's opening section
// records two occasions on which a skip retired a live security control
// behind a green tick.
func TestThisFileSkipsNothing(t *testing.T) {
	fset := token.NewFileSet()
	inspected := 0
	for _, path := range goFilesInThisPackage(t) {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		inspected++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow" {
				t.Errorf("%s:%d calls t.%s. nuclei is absent from this host and the driver "+
					"says so by REFUSING; a test that says so by skipping lets the package "+
					"print ok", filepath.Base(path), fset.Position(call.Pos()).Line, sel.Sel.Name)
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no test file was parsed, so this guard reported a pass it did not measure")
	}
}

// TestThisPackageConstructsNoSocket is a local restatement of gate 3 tier 1.
//
// D.9's scanner already covers this package (its walk includes _test.go files
// inside internal/dast), and that is the authority. This is a fast local
// echo so that the failure lands in the package being edited rather than
// three directories away, and it is deliberately narrower: it asserts the
// import list, which is where a capability would have to arrive.
func TestThisPackageConstructsNoSocket(t *testing.T) {
	inert := map[string]bool{
		"context": true, "crypto/sha256": true, "encoding/hex": true, "errors": true,
		"fmt": true, "go/ast": true, "go/parser": true, "go/token": true, "io/fs": true, "net/netip": true,
		"os": true, "os/exec": true, "path/filepath": true, "reflect": true,
		"runtime": true, "sort": true, "strings": true, "sync": true, "testing": true,
		"time": true, "unicode/utf8": true,
	}
	const module = "github.com/Susquehanna-Syntax/Anvil"

	fset := token.NewFileSet()
	inspected := 0
	for _, path := range goFilesInThisPackage(t) {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		inspected++
		for _, spec := range f.Imports {
			p := strings.Trim(spec.Path.Value, `"`)
			if p == module || strings.HasPrefix(p, module+"/") {
				continue
			}
			if !inert[p] {
				t.Errorf("%s imports %q, which is not on this package's inert list. Gate 3 "+
					"tier 1 refuses ANY socket constructed inside internal/dast outside "+
					"internal/dast/authz, with no allowlist and no code path that can add "+
					"one. If the import genuinely cannot open a socket, add it here AND to "+
					"inertImports in internal/dast/authz/egress_chokepoint_test.go",
					filepath.Base(path), p)
			}
		}
	}
	if inspected < 2 {
		t.Fatalf("only %d file(s) were parsed; this package has an implementation file and "+
			"a test file, so a smaller number means the walk did not find them", inspected)
	}
}

// TestNoStringLiteralTargetReachesTheEngine.
//
// The claim this package makes is that a destination reaches the engine only
// through an authz.Authorization. This reads the implementation's syntax tree
// and asserts that TargetSpec's `url` and `pinned` fields are written in
// exactly one place — NewTargetSpec — so a second, ungated constructor cannot
// appear without failing here.
func TestNoStringLiteralTargetReachesTheEngine(t *testing.T) {
	fset := token.NewFileSet()
	path := filepath.Join(thisPackageDir(t), "nuclei.go")
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var writers []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		ident, ok := lit.Type.(*ast.Ident)
		if !ok || ident.Name != "TargetSpec" {
			return true
		}
		named := false
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && (k.Name == "url" || k.Name == "pinned") {
				named = true
			}
		}
		if named {
			writers = append(writers, fmt.Sprintf("line %d", fset.Position(lit.Pos()).Line))
		}
		return true
	})

	if len(writers) != 1 {
		t.Fatalf("%d composite literal(s) in nuclei.go write TargetSpec.url or "+
			"TargetSpec.pinned (%s). There must be exactly one, inside NewTargetSpec, "+
			"which begins with authz.PinnedDialAddress. A second writer is a second door "+
			"into the engine's target list, and a choke point with two doors is not a "+
			"choke point", len(writers), strings.Join(writers, ", "))
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return a
}

func thisPackageDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return dir
}

func goFilesInThisPackage(t *testing.T) []string {
	t.Helper()
	dir := thisPackageDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	if len(out) == 0 {
		t.Fatalf("no Go file found in %s. A guard that reads the package's own source and "+
			"finds none has not passed, it has not run", dir)
	}
	return out
}

// repoRoot finds the module root, and FAILS rather than skipping when it
// cannot — the same rule authz's repoRootForGuards applies.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir := thisPackageDir(t)
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if strings.Contains(string(b), "module github.com/Susquehanna-Syntax/Anvil") {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s. This guard refuses to report a pass it did not "+
				"measure", thisPackageDir(t))
		}
		dir = parent
	}
}
