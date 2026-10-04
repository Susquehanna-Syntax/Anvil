package recall_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/recall"
	"github.com/Susquehanna-Syntax/Anvil/internal/recall/recalltest"
)

func pack(t *testing.T) *recall.Pack {
	t.Helper()
	p, err := recall.LoadPack(recalltest.RulePack())
	if err != nil {
		t.Fatalf("the vendored rule pack does not verify: %v", err)
	}
	return p
}

// TestTheVendoredPackVerifies is the pack as committed: every rule and licence
// body hashes to the manifest, the manifest names this selection, and every
// rule's provenance is complete.
func TestTheVendoredPackVerifies(t *testing.T) {
	p := pack(t)
	if n := len(p.Rules()); n != 176 {
		t.Errorf("the pack holds %d rule files; the owner's selection of 2026-10-03 vendors 176", n)
	}
	if n := len(p.Manifest.ExcludedByLicence); n != 131 {
		t.Errorf("the manifest lists %d rules excluded for an LGPL-3.0 upstream; the generator left out 131", n)
	}
	for _, r := range p.Rules() {
		if !slices.Contains(recall.AdmittedLicences, r.Licence) || r.LicenceEvidence == "" || r.Commit == "" || r.Repository == "" {
			t.Errorf("%s: incomplete provenance %+v", r.Path, r)
		}
		if strings.HasPrefix(r.Path, "gitlab-sast-rules/c/") {
			t.Errorf("%s: GitLab's c/ rules are GPL-2.0 and excluded", r.Path)
		}
	}
	for _, tool := range []string{recall.ToolOpengrep, recall.ToolGosec, recall.ToolBandit} {
		if pin, ok := p.Tool(tool); !ok || pin.Version == "" || pin.Licence == "" {
			t.Errorf("no pin for %s: %+v", tool, pin)
		}
	}
}

// copyPack copies data/rules to a temporary directory a test may mutate.
func copyPack(t *testing.T) string {
	t.Helper()
	src, dst := recalltest.RulePack(), t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func editJSON(t *testing.T, path string, edit func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// resign makes the manifest name the selection on disk again, so a mutation
// to the selection reaches the check it is aimed at instead of tripping the
// digest check first.
func resign(t *testing.T, dir string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "selection.json"))
	if err != nil {
		t.Fatal(err)
	}
	editJSON(t, filepath.Join(dir, "MANIFEST.json"), func(m map[string]any) {
		m["selection_sha256"] = sha256Hex(raw)
	})
}

// TestThePackGuardsFire is the negative control for every pack check: each
// mutation is a way a rule could reach Lane B without review, and each must
// be refused. The GitLab directory allowlist is the first two.
func TestThePackGuardsFire(t *testing.T) {
	firstRule := func(m map[string]any) map[string]any {
		return m["rules"].([]any)[0].(map[string]any)
	}
	cases := map[string]func(t *testing.T, dir string){
		"a GitLab directory off the allowlist (c/, GPL-2.0)": func(t *testing.T, dir string) {
			editJSON(t, filepath.Join(dir, "selection.json"), func(m map[string]any) {
				c := m["corpora"].([]any)[0].(map[string]any)
				c["directories"] = append(c["directories"].([]any), "c")
				m["excluded_directories"] = m["excluded_directories"].([]any)[1:]
			})
			resign(t, dir)
		},
		"a GitLab directory that is a licence trap (doc/, CC BY-SA 4.0)": func(t *testing.T, dir string) {
			editJSON(t, filepath.Join(dir, "selection.json"), func(m map[string]any) {
				c := m["corpora"].([]any)[0].(map[string]any)
				c["directories"] = append(c["directories"].([]any), "doc")
			})
			resign(t, dir)
		},
		"a corpus from a repository that is not admitted": func(t *testing.T, dir string) {
			editJSON(t, filepath.Join(dir, "selection.json"), func(m map[string]any) {
				m["corpora"].([]any)[1].(map[string]any)["repository"] = "https://github.com/semgrep/semgrep-rules"
			})
			resign(t, dir)
		},
		"a rule whose licence is not admitted": func(t *testing.T, dir string) {
			editJSON(t, filepath.Join(dir, "MANIFEST.json"), func(m map[string]any) {
				firstRule(m)["licence"] = "GPL-2.0"
			})
		},
		"a rule with no licence evidence": func(t *testing.T, dir string) {
			editJSON(t, filepath.Join(dir, "MANIFEST.json"), func(m map[string]any) {
				firstRule(m)["licence_evidence"] = " "
			})
		},
		"a rule file edited after vendoring": func(t *testing.T, dir string) {
			var first string
			editJSON(t, filepath.Join(dir, "MANIFEST.json"), func(m map[string]any) { first = firstRule(m)["path"].(string) })
			f := filepath.Join(dir, filepath.FromSlash(first))
			b, _ := os.ReadFile(f)
			if err := os.WriteFile(f, append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"an unlisted rule file beside the vendored ones": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "gitlab-sast-rules", "python", "extra.yml"), []byte("rules: []\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a selection the manifest was not generated from": func(t *testing.T, dir string) {
			editJSON(t, filepath.Join(dir, "selection.json"), func(m map[string]any) { m["decided_by"] = "someone else" })
		},
		"a licence body edited after archiving": func(t *testing.T, dir string) {
			f := filepath.Join(dir, "0xdea-semgrep-rules", "LICENSE")
			b, _ := os.ReadFile(f)
			if err := os.WriteFile(f, append(b, ' '), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a corpus pinned to a branch, not a commit": func(t *testing.T, dir string) {
			editJSON(t, filepath.Join(dir, "selection.json"), func(m map[string]any) {
				m["corpora"].([]any)[0].(map[string]any)["commit"] = "main"
			})
			resign(t, dir)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyPack(t)
			if _, err := recall.LoadPack(dir); err != nil {
				t.Fatalf("the unmutated copy does not load: %v", err)
			}
			mutate(t, dir)
			if _, err := recall.LoadPack(dir); !errors.Is(err, recall.ErrRulePack) {
				t.Fatalf("the mutated pack loaded (err %v)", err)
			}
		})
	}
}

func TestExcludedPaths(t *testing.T) {
	p := pack(t)
	for path, want := range map[string]bool{
		"tests/test_x.py": true, "src/tests/x.c": true, "docs/examples/a.c": true, "pkg/x_test.go": true,
		"pkg/testdata/a.go": true, "conftest.py": true, "lib/test_util.py": true,
		"src/app.py": false, "lib/testing.c": false, "src/latest/x.go": false, "contest.py": false,
	} {
		if got := p.Excluded(path); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestTheArgumentVectorsSwitchOffTargetSuppression holds the flags that keep
// the scanned repository from silencing Lane B, and the absence of the flag
// that would make gosec's silence look like a clean scan.
func TestTheArgumentVectorsSwitchOffTargetSuppression(t *testing.T) {
	og := recall.OpengrepArgs([]string{"/r/a.yml"}, []string{"/repo/a.py"})
	for _, want := range []string{"--disable-nosem", "--disable-version-check", "--timeout-threshold=0", "--config=/r/a.yml"} {
		if !slices.Contains(og, want) {
			t.Errorf("opengrep args %v lack %s", og, want)
		}
	}
	if og[len(og)-1] != "/repo/a.py" {
		t.Errorf("opengrep's targets must be the files handed to it: %v", og)
	}
	gs := recall.GosecArgs("/tmp/out.json")
	if !slices.Contains(gs, "-nosec") || slices.Contains(gs, "-quiet") || !slices.Contains(gs, "-no-fail") {
		t.Errorf("gosec args %v", gs)
	}
	bd := recall.BanditArgs([]string{"/repo/a.py"}, "/tmp/out.json")
	if !slices.Contains(bd, "--ignore-nosec") || slices.Contains(bd, "-r") {
		t.Errorf("bandit args %v", bd)
	}
	env := strings.Join(recall.GosecEnv(""), "\n")
	for _, want := range []string{"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly"} {
		if !strings.Contains(env, want) {
			t.Errorf("gosec's environment lacks %s", want)
		}
	}
}

// fakeExec answers version checks with the pins and every scan with fixed
// output, exit code and report bytes.
type fakeExec struct {
	stdout   string
	code     int
	report   string // written to the report file gosec and bandit are given
	version  map[string]string
	runError error
}

func (f fakeExec) Run(_ context.Context, bin string, args []string, _ string, _ []string) ([]byte, []byte, int, error) {
	tool := filepath.Base(bin)
	if len(args) == 1 && strings.Contains(args[0], "version") {
		v := map[string]string{"opengrep": "1.26.0", "gosec": "Version: 2.29.0", "bandit": "bandit 1.9.4"}[tool]
		if f.version != nil {
			v = f.version[tool]
		}
		return []byte(v + "\n"), nil, 0, nil
	}
	if f.runError != nil {
		return nil, nil, 0, f.runError
	}
	for i, a := range args {
		if out, ok := strings.CutPrefix(a, "-out="); ok && f.report != "" {
			_ = os.WriteFile(out, []byte(f.report), 0o600)
		}
		if a == "-o" && i+1 < len(args) && f.report != "" {
			_ = os.WriteFile(args[i+1], []byte(f.report), 0o600)
		}
	}
	return []byte(f.stdout), []byte("stderr text"), f.code, nil
}

// oneFile is a tree with a single Python file, which needs opengrep and bandit.
func oneFile(t *testing.T, name, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestAbsentFailedAndNoMatchesAreThreeAnswers is the three-way distinction
// every runner owes: an absent tool, a failed tool and a clean run never look
// alike.
func TestAbsentFailedAndNoMatchesAreThreeAnswers(t *testing.T) {
	ctx := context.Background()
	p := pack(t)
	root := oneFile(t, "a.go", "package a\n")
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tools := recalltest.Tools()

	t.Run("absent", func(t *testing.T) {
		s := recall.Scanner{Pack: p, Tools: recall.Tools{Opengrep: filepath.Join(t.TempDir(), "opengrep"), Gosec: tools.Gosec}, Exec: fakeExec{}}
		_, err := s.Prepare(ctx, root)
		var absent *recall.ToolAbsentError
		if !errors.As(err, &absent) || absent.ExitCode() != recall.ExitCodeArtefactAbsent {
			t.Fatalf("an absent opengrep gave %v", err)
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		s := recall.Scanner{Pack: p, Tools: tools, Exec: fakeExec{version: map[string]string{"opengrep": "1.25.0", "gosec": "Version: 2.29.0"}}}
		if _, err := s.Prepare(ctx, root); !errors.Is(err, recall.ErrToolFailed) {
			t.Fatalf("an unpinned opengrep release gave %v", err)
		}
	})
	scan := func(t *testing.T, x recall.Exec) (recall.Result, error) {
		t.Helper()
		s := recall.Scanner{Pack: p, Tools: tools, Exec: x}
		plan, err := s.Prepare(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		return s.Scan(ctx, plan)
	}
	cleanOpengrep := `{"results":[],"errors":[],"paths":{"scanned":["` + filepath.Join(root, "a.go") + `"]}}`
	cleanGosec := `{"Golang errors":{},"Issues":[],"Stats":{"files":1}}`
	for name, x := range map[string]fakeExec{
		"opengrep exits 2":                     {stdout: cleanOpengrep, code: 2},
		"opengrep prints nothing":              {stdout: ""},
		"opengrep prints half a report":        {stdout: `{"results":[`},
		"opengrep's report has no paths":       {stdout: `{"results":[],"errors":[]}`},
		"opengrep could not be run":            {runError: errors.New("exec format error")},
		"gosec writes nothing (as -quiet did)": {stdout: cleanOpengrep},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scan(t, x); !errors.Is(err, recall.ErrToolFailed) {
				t.Fatalf("got %v, want a failed tool", err)
			}
		})
	}
	t.Run("no matches", func(t *testing.T) {
		res, err := scan(t, fakeExec{stdout: cleanOpengrep, report: cleanGosec})
		if err != nil || res.Count != 0 || len(res.Problems) != 0 {
			t.Fatalf("a clean run: %+v, %v", res, err)
		}
	})
	t.Run("a file handed over and not scanned is a coverage problem", func(t *testing.T) {
		res, err := scan(t, fakeExec{stdout: `{"results":[],"errors":[],"paths":{"scanned":[]}}`, report: cleanGosec})
		if err != nil || len(res.Problems) != 1 {
			t.Fatalf("got %+v, %v; want one problem", res.Problems, err)
		}
	})
	t.Run("a package gosec cannot load is a coverage problem", func(t *testing.T) {
		res, err := scan(t, fakeExec{stdout: cleanOpengrep, report: `{"Golang errors":{"` + filepath.Join(root, "a.go") + `":[{"line":1,"error":"no module"}]},"Issues":[],"Stats":{"files":1}}`})
		if err != nil || len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "gosec could not load") {
			t.Fatalf("got %+v, %v", res.Problems, err)
		}
	})
}

// expectedFixture is every candidate testdata/laneb-fixture must yield: the
// planted matches, the suppressed one still reported, nothing from tests/.
var expectedFixture = []string{
	"gitlab-sast-rules/java_crypto_rule-CipherDESInsecure src/Digest.java:6 Digest.cipher",
	"gitlab-sast-rules/java_crypto_rule-CipherIntegrity src/Digest.java:6 Digest.cipher",
	"bandit/B404 src/app.py:2 ",
	"bandit/B307 src/app.py:7 run_expression",
	"gitlab-sast-rules/python_eval_rule-eval src/app.py:7 run_expression",
	"bandit/B602 src/app.py:11 run_command",
	"0xdea-semgrep-rules/raptor-write-into-stack-buffer src/copy.c:6 copy",
	"0xdea-semgrep-rules/raptor-insecure-api-strcpy-strcat src/copy.c:6 copy",
	"gosec/G204 src/main.go:12 runner.run",
	"bandit/B307 src/suppressed.py:6 run_expression",
	"gitlab-sast-rules/python_eval_rule-eval src/suppressed.py:6 run_expression",
	"gitlab-sast-rules/javascript_require_rule-non-literal-require web/app.js:3 load",
}

func describe(res recall.Result) []string {
	var out []string
	for _, c := range res.Candidates {
		id := c.RuleIDVersioned[:strings.LastIndex(c.RuleIDVersioned, "@")]
		out = append(out, id+" "+c.Path+":"+itoa(c.StartLine)+" "+c.Symbol)
	}
	return out
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func checkFixture(t *testing.T, res recall.Result, plan recall.Plan) {
	t.Helper()
	if got := describe(res); !slices.Equal(got, expectedFixture) {
		t.Fatalf("fixture candidates:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(expectedFixture, "\n"))
	}
	if res.Count != len(expectedFixture) || len(res.Problems) != 0 {
		t.Fatalf("count %d, problems %v", res.Count, res.Problems)
	}
	if plan.Excluded != 1 {
		t.Errorf("the selection's paths excluded %d files, want 1 (tests/test_planted.py)", plan.Excluded)
	}
	for _, c := range res.Candidates {
		p := c.Provenance
		if p.Source == "" || p.Repository == "" || p.Version == "" || p.RulePath == "" || p.Licence == "" || p.LicenceEvidence == "" {
			t.Errorf("%s at %s:%d has incomplete provenance %+v", c.RuleIDVersioned, c.Path, c.StartLine, p)
		}
		if c.CWE == "" || strings.TrimSpace(c.Snippet) == "" || c.Context == "" {
			t.Errorf("%s at %s:%d lacks a CWE, snippet or context", c.RuleIDVersioned, c.Path, c.StartLine)
		}
	}
}

// TestTheFixtureFromRecordedReports runs the whole recall tier over the
// fixture with the tools' real reports replayed, so it runs where the tools
// are not installed. TestTheFixtureWithTheRealTools proves the recording.
func TestTheFixtureFromRecordedReports(t *testing.T) {
	root, err := filepath.Abs(recalltest.FixtureRoot())
	if err != nil {
		t.Fatal(err)
	}
	replay := &recalltest.Replay{Root: root}
	s := recall.Scanner{Pack: pack(t), Tools: recalltest.Tools(), Exec: replay}
	plan, err := s.Prepare(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	checkFixture(t, res, plan)
	// Every target handed to opengrep and bandit is a file, never the root.
	for _, call := range replay.Calls {
		if slices.Contains(call, root) {
			t.Errorf("a tool was handed the tree's root as a target: %v", call)
		}
	}
}

// realTools is the tools from ANVIL_OPENGREP, ANVIL_GOSEC, ANVIL_BANDIT and
// ANVIL_GOBIN, or their names on PATH.
func realTools() recall.Tools {
	return recall.Tools{Opengrep: os.Getenv("ANVIL_OPENGREP"), Gosec: os.Getenv("ANVIL_GOSEC"),
		Bandit: os.Getenv("ANVIL_BANDIT"), GoBin: os.Getenv("ANVIL_GOBIN")}
}

// TestTheFixtureWithTheRealTools runs the real, pinned tools over the
// fixture. Where they are absent the scan must refuse as a missing tool, never
// come back empty; with ANVIL_LANEB_E2E=1 (CI's Lane B end-to-end job) an
// absent tool fails the test. To re-record the replayed reports after a
// fixture or rule change, run it with ANVIL_LANEB_RECORD=1.
func TestTheFixtureWithTheRealTools(t *testing.T) {
	root, err := filepath.Abs(recalltest.FixtureRoot())
	if err != nil {
		t.Fatal(err)
	}
	var x recall.Exec = recall.ProcessExec{}
	if os.Getenv("ANVIL_LANEB_RECORD") == "1" {
		x = recalltest.Recorder{Root: root, Real: x}
	}
	tools := realTools()
	if tools.GoBin == "" {
		if goBin, err := exec.LookPath("go"); err == nil {
			tools.GoBin = filepath.Dir(goBin)
		}
	}
	s := recall.Scanner{Pack: pack(t), Tools: tools, Exec: x}
	plan, err := s.Prepare(context.Background(), root)
	if errors.Is(err, recall.ErrToolAbsent) {
		if os.Getenv("ANVIL_LANEB_E2E") == "1" {
			t.Fatalf("ANVIL_LANEB_E2E=1 and a recall tool is absent: %v", err)
		}
		t.Logf("a recall tool is not installed, and the scan refused as a missing tool, as it must: %v", err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	checkFixture(t, res, plan)
	t.Logf("the real tools found the %d planted candidates", res.Count)
}

func TestDedupeIsDeterministic(t *testing.T) {
	a := recall.Candidate{Tool: recall.ToolOpengrep, RuleIDVersioned: "gitlab-sast-rules/x@1", CWE: "CWE-22", Path: "a.go", StartLine: 3}
	b := recall.Candidate{Tool: recall.ToolGosec, RuleIDVersioned: "gosec/G304@2.29.0", CWE: "CWE-22", Path: "a.go", StartLine: 3}
	c := recall.Candidate{Tool: recall.ToolOpengrep, RuleIDVersioned: "gitlab-sast-rules/y@1", CWE: "CWE-78", Path: "a.go", StartLine: 3}
	for _, in := range [][]recall.Candidate{{a, b, c}, {c, b, a}, {b, c, a}} {
		got := recall.Dedupe(in)
		if len(got) != 2 || got[0].Tool != recall.ToolGosec || got[1].CWE != "CWE-78" {
			t.Fatalf("Dedupe(%v) = %v", in, got)
		}
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestTheReviewersEvasionsAreRecorded holds the fixes for the same-family
// review of 2026-10-03 (docs/reviews/lane-b-gate.md): each way a scanned tree
// kept code from a tool, or broke the scan, is now either scanned or recorded
// as incomplete coverage, never silent. It needs the real tools, like
// TestTheFixtureWithTheRealTools.
func TestTheReviewersEvasionsAreRecorded(t *testing.T) {
	tools := realTools()
	if goBin, err := exec.LookPath("go"); err == nil && tools.GoBin == "" {
		tools.GoBin = filepath.Dir(goBin)
	}
	root := t.TempDir()
	outside := t.TempDir()
	write := func(base, rel, body string) {
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := "package main\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc main() { _ = exec.Command(\"sh\", \"-c\", os.Args[1]).Run() }\n"
	write(root, "mod/go.mod", "module example.invalid/m\n\ngo 1.22\n")
	write(root, "mod/a.go", cmd)
	write(root, "mod/w.go", "//go:build windows\n\n"+cmd)                                                   // another platform
	write(root, "mod/c.go", "package main\n\n// #include \"/etc/hostname\"\nimport \"C\"\n\nfunc c() {}\n") // cgo
	write(root, "mod/vendor/v/v.go", "package v\n")
	write(root, "loose/l.go", cmd) // in no module
	write(outside, "linked.go", cmd)
	if err := os.Symlink(filepath.Join(outside, "linked.go"), filepath.Join(root, "mod", "linked.go")); err != nil {
		t.Fatal(err)
	}
	write(root, ".github/scripts/rel.py", "import os\nos.system(input())\n") // bandit's default excludes
	write(root, "CVSS-tool/app.py", "import os\nos.system(input())\n")

	s := recall.Scanner{Pack: pack(t), Tools: tools}
	plan, err := s.Prepare(context.Background(), root)
	if errors.Is(err, recall.ErrToolAbsent) {
		if os.Getenv("ANVIL_LANEB_E2E") == "1" {
			t.Fatalf("ANVIL_LANEB_E2E=1 and a recall tool is absent: %v", err)
		}
		t.Logf("a recall tool is not installed, and the scan refused as a missing tool: %v", err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), plan)
	if err != nil {
		t.Fatalf("a symbolic link in a module broke the scan: %v", err)
	}
	problems := strings.Join(res.Problems, "\n")
	for _, want := range []string{
		"gosec analysed",              // w.go and c.go were not analysed
		"belong to no Go module",      // loose/l.go
		"which is not a regular file", // the link gosec followed
	} {
		if !strings.Contains(problems, want) {
			t.Errorf("no problem mentions %q; problems:\n%s", want, problems)
		}
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "under vendor/") {
		t.Errorf("the vendored Go file is not noted: %v", res.Notes)
	}
	host, _ := os.ReadFile("/etc/hostname")
	if h := strings.TrimSpace(string(host)); h != "" && strings.Contains(problems, h) {
		t.Errorf("a cgo #include put a host file's contents into the scan's output")
	}
	byPath := map[string]bool{}
	for _, c := range res.Candidates {
		byPath[c.Tool+" "+c.Path] = true
	}
	for _, want := range []string{"bandit .github/scripts/rel.py", "bandit CVSS-tool/app.py"} {
		if !byPath[want] {
			t.Errorf("no candidate %q: bandit's default excludes are still in force (%v)", want, byPath)
		}
	}
}
