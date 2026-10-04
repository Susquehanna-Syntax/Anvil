package remediation

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type gateFile struct {
	Rows []struct {
		Criterion string `json:"criterion"`
		Status    string `json:"status"`
		Evidence  []struct {
			Test string `json:"test"`
			Path string `json:"path"`
		} `json:"evidence"`
	} `json:"rows"`
}

func readGate(t *testing.T) (string, gateFile) {
	t.Helper()
	root := moduleRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "gates", "remediation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g gateFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return root, g
}

// TestTheGateFileCitesWhatExists holds docs/gates/remediation.json to its own
// rule: every row names a status and evidence, every cited path exists, and
// every cited test is defined in the file the row names.
func TestTheGateFileCitesWhatExists(t *testing.T) {
	root, g := readGate(t)
	if len(g.Rows) < 14 {
		t.Fatalf("the gate file has %d rows; the remediation exit gate has fourteen", len(g.Rows))
	}
	for _, row := range g.Rows {
		if row.Criterion == "" || row.Status == "" || len(row.Evidence) == 0 {
			t.Errorf("row %q names no evidence or no status", row.Criterion)
		}
		for _, ev := range row.Evidence {
			src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ev.Path)))
			if err != nil {
				t.Errorf("row %q cites %s: %v", row.Criterion, ev.Path, err)
				continue
			}
			if ev.Test == "" {
				continue
			}
			def := regexp.MustCompile(`(?m)^(func|def) ` + regexp.QuoteMeta(ev.Test) + `\(`)
			if !def.Match(src) {
				t.Errorf("row %q cites %s in %s, which does not define it", row.Criterion, ev.Test, ev.Path)
			}
		}
	}
}

// skipCalls lists the Skip, Skipf and SkipNow calls inside node, or inside the
// whole file when node is nil.
func skipCalls(fset *token.FileSet, node ast.Node) []string {
	var out []string
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "Skip", "Skipf", "SkipNow":
				out = append(out, fset.Position(call.Pos()).String())
			}
		}
		return true
	})
	return out
}

// TestNoGateTestCanSkip is the remediation exit gate's row "no skipped
// security test": no Go test the gate cites, and no test in this package,
// contains a call that could skip it. A guard that can skip can pass without
// running.
func TestNoGateTestCanSkip(t *testing.T) {
	root, g := readGate(t)
	checked := 0
	for _, row := range g.Rows {
		for _, ev := range row.Evidence {
			if ev.Test == "" || !strings.HasSuffix(ev.Path, ".go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(ev.Path)), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name.Name != ev.Test {
					continue
				}
				checked++
				for _, at := range skipCalls(fset, fd) {
					t.Errorf("%s (cited by %q) can skip at %s", ev.Test, row.Criterion, at)
				}
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d cited tests were checked", checked)
	}
	files, _ := filepath.Glob(filepath.Join(root, "internal", "remediation", "*_test.go"))
	for _, p := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, at := range skipCalls(fset, f) {
			t.Errorf("a remediation test can skip at %s", at)
		}
	}
	// The negative control: the scan sees a skip.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x_test.go", "package x\nfunc TestX(t *T) { if c { t.Skipf(\"%s\", \"no\") } }\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipCalls(fset, f)) != 1 {
		t.Fatal("the scan missed a planted skip")
	}
}
