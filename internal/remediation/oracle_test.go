package remediation

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// targetSim simulates the scanned and the patched targets: each reports
// whether a payload triggers the vulnerability.
type targetSim struct{ base, patched func(payload string) bool }

func (s targetSim) Replay(_ context.Context, t ReplayTarget, _ record.Repro, payload string) (bool, string, error) {
	if t.Tree == "base" {
		return s.base(payload), "", nil
	}
	return s.patched(payload), "", nil
}

const sqli = "' OR 1=1 --"

var baseT, patchT = ReplayTarget{Tree: "base"}, ReplayTarget{Tree: "patched"}

// TestANarrowFixIsCaughtByMutation is the remediation exit gate's row "a
// narrow fix is caught by mutation": a patch that special-cases the recorded
// payload passes the exact replay, and a mutated payload that is a live
// exploit on the scanned code still triggers, so the oracle refuses it. A real
// fix passes every live mutant and earns the label. A mutant that never
// triggered on the scanned code proves nothing and never counts: a patch
// whose mutants are all dead stays unverified.
func TestANarrowFixIsCaughtByMutation(t *testing.T) {
	repro := &record.Repro{Payload: sqli, InjectionPoint: record.ReproInjection{Kind: record.InjectionPointQuery, Name: "q"}}
	ctx := context.Background()
	vulnerable := func(p string) bool { return strings.Contains(strings.ToUpper(p), "OR") }

	unpatched := targetSim{vulnerable, vulnerable}
	if o := RunOracle(ctx, unpatched, baseT, patchT, repro); o.Verdict != OracleStillTriggers || !o.Blocking() || LabelFor(o) != LabelUnverifiedSecurity {
		t.Fatalf("unpatched: %+v", o)
	}

	narrow := targetSim{vulnerable, func(p string) bool { return p != sqli && vulnerable(p) }}
	o := RunOracle(ctx, narrow, baseT, patchT, repro)
	if o.Verdict != OracleMutantTriggers || !o.Blocking() || len(o.Survived) == 0 || LabelFor(o) != LabelUnverifiedSecurity {
		t.Fatalf("a narrow fix was not caught: %+v", o)
	}

	fixed := targetSim{vulnerable, func(string) bool { return false }}
	o = RunOracle(ctx, fixed, baseT, patchT, repro)
	if o.Verdict != OracleFixedIncludingMutants || o.Blocking() || o.Mutants < 5 || LabelFor(o) != LabelVerifiedFixed {
		t.Fatalf("a real fix: %+v", o)
	}

	// The reviewer's case: the scanned code triggers only on the exact
	// payload, so every mutant is dead there, and a patch that blocks only the
	// exact payload must not be called verified.
	exactOnly := func(p string) bool { return p == sqli }
	o = RunOracle(ctx, targetSim{exactOnly, func(string) bool { return false }}, baseT, patchT, repro)
	if o.Mutants != 0 || o.Dead == 0 || LabelFor(o) != LabelUnverifiedSecurity || o.Blocking() {
		t.Fatalf("dead mutants earned something: %+v", o)
	}
	// A reproduction that does not trigger on the scanned code proves nothing.
	o = RunOracle(ctx, targetSim{func(string) bool { return false }, func(string) bool { return false }}, baseT, patchT, repro)
	if o.Verdict != OracleBaseDoesNotTrigger || LabelFor(o) != LabelUnverifiedSecurity || o.Blocking() {
		t.Fatalf("a dead reproduction: %+v", o)
	}

	if o := RunOracle(ctx, nil, baseT, patchT, repro); o.Verdict != OracleNoReplayer || LabelFor(o) != LabelUnverifiedSecurity {
		t.Fatalf("no replayer: %+v", o)
	}
	if o := RunOracle(ctx, fixed, baseT, patchT, nil); o.Verdict != OracleNoReproduction || LabelFor(o) != LabelUnverifiedSecurity {
		t.Fatalf("no reproduction: %+v", o)
	}
	// A hand-built result claiming the verdict without mutants earns nothing.
	if LabelFor(OracleResult{Verdict: OracleFixedIncludingMutants}) != LabelUnverifiedSecurity {
		t.Fatal("a verdict with no mutant replayed earned verified_fixed")
	}
	for _, m := range Mutate(sqli) {
		if m == sqli {
			t.Fatal("the original payload is among its mutants")
		}
	}
}

// TestVerifiedFixedHasOneRoad is the remediation exit gate's row "verified
// fixed has one road": in every non-test Go file of the module, the label's
// constant and its literal appear only where they are declared and in
// LabelFor, so nothing else can mint the label.
func TestVerifiedFixedHasOneRoad(t *testing.T) {
	root := moduleRoot(t)
	type site struct{ file, fn string }
	var sites []site
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "plan", "research", "eval", "testdata", "node_modules", "tools":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		for _, decl := range f.Decls {
			name := "(package level)"
			if fd, ok := decl.(*ast.FuncDecl); ok {
				name = fd.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name == "LabelVerifiedFixed" {
						sites = append(sites, site{rel, name})
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING && strings.Contains(x.Value, "verified_fixed") {
						sites = append(sites, site{rel, name})
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[site]bool{
		{"internal/remediation/oracle.go", "(package level)"}: true, // the declaration
		{"internal/remediation/oracle.go", "LabelFor"}:        true, // the one road
		{"internal/remediation/prs.go", "Body"}:               true, // reads the label to word the body; mints nothing
	}
	seen := map[site]bool{}
	for _, s := range sites {
		seen[s] = true
		if !allowed[s] {
			t.Errorf("%s:%s names the verified-fixed label; only LabelFor may produce it", s.file, s.fn)
		}
	}
	if !seen[site{"internal/remediation/oracle.go", "LabelFor"}] {
		t.Fatal("the scan did not find LabelFor's use of the label, so it proves nothing")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}
