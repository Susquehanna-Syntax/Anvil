package hygiene_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// go doc concatenates every comment attached to a package clause, in file
// order, and shows the first sentence as the package summary. Before plan node
// packagedocs, several packages attached file comments to their package
// clause, so go doc introduced the authorization kernel with one of its phases,
// the attack-surface inventory with its authentication helper and the
// comparator with Alpine's version ordering. The rule this guard keeps:
//
//   - every package with non-test Go source has a doc.go;
//   - doc.go holds the package summary and nothing else (no imports, no
//     declarations), starting "Package <name> " or, for a command,
//     "Command <directory> ";
//   - no other non-test file attaches a comment to its package clause. File
//     comments stay, separated from the package line by a blank line.

// docProblems checks one set of Go source files, keyed by slash-separated
// path relative to the module root. It is a pure function so the negative
// control can run the shipping check on a synthetic tree.
func docProblems(files map[string][]byte) []string {
	byDir := map[string][]string{}
	for p := range files {
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			byDir[path.Dir(p)] = append(byDir[path.Dir(p)], p)
		}
	}
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	var problems []string
	for _, dir := range dirs {
		paths := byDir[dir]
		sort.Strings(paths)
		hasDocGo := false
		for _, p := range paths {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, files[p], parser.ParseComments)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: does not parse: %v", p, err))
				continue
			}
			if path.Base(p) != "doc.go" {
				if f.Doc != nil {
					problems = append(problems, fmt.Sprintf("%s: a comment is attached to the package "+
						"clause, so go doc shows it as part of the package summary. Put a blank line "+
						"between it and the package line; the summary belongs in %s/doc.go", p, dir))
				}
				continue
			}
			hasDocGo = true
			want := "Package " + f.Name.Name + " "
			if f.Name.Name == "main" {
				want = "Command " + path.Base(dir) + " "
			}
			if f.Doc == nil || !strings.HasPrefix(f.Doc.Text(), want) {
				problems = append(problems, fmt.Sprintf("%s: the package summary must start %q", p, want))
			}
			if len(f.Imports) > 0 || len(f.Decls) > 0 {
				problems = append(problems, fmt.Sprintf("%s: holds code; doc.go holds the package "+
					"summary and nothing else", p))
			}
			for _, cg := range f.Comments {
				if cg != f.Doc && !isBuildConstraint(cg) {
					problems = append(problems, fmt.Sprintf("%s: carries a comment other than the "+
						"package summary", p))
					break
				}
			}
		}
		if !hasDocGo {
			problems = append(problems, fmt.Sprintf("%s: no doc.go; every package states what it is "+
				"in one place", dir))
		}
	}
	return problems
}

func isBuildConstraint(cg *ast.CommentGroup) bool {
	return len(cg.List) == 1 && strings.HasPrefix(cg.List[0].Text, "//go:build ")
}

func TestEveryPackageSummaryIsItsOwn(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	listed, how := listTree(t, root)
	files := map[string][]byte{}
	for _, rel := range listed {
		top := strings.SplitN(rel, "/", 2)[0]
		if !strings.HasSuffix(rel, ".go") || strings.Contains("/"+rel, "/testdata/") || top == "eval" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue // listed by git but deleted in the working tree
		}
		files[rel] = data
	}
	// The module has dozens of packages; a handful of files means the listing
	// broke, and an empty set passes every rule.
	if len(files) < 100 {
		t.Fatalf("only %d Go files listed (%s); that is a broken listing, not a small module", len(files), how)
	}
	for _, p := range docProblems(files) {
		t.Error(p)
	}
}

// TestThePackageDocGuardFails is the negative control: each synthetic package
// breaks one rule, and the shipping check must name every one of them.
func TestThePackageDocGuardFails(t *testing.T) {
	good := []byte("// Package good is fine.\npackage good\n")
	cases := map[string]struct {
		files map[string][]byte
		want  string
	}{
		"attached file comment": {map[string][]byte{
			"a/doc.go": []byte("// Package a is fine.\npackage a\n"),
			"a/b.go":   []byte("// Phase 1 of something.\npackage a\n"),
		}, "attached to the package clause"},
		"no doc.go": {map[string][]byte{
			"b/b.go": []byte("// File comment.\n\npackage b\n"),
		}, "no doc.go"},
		"wrong summary": {map[string][]byte{
			"c/doc.go": []byte("// This package does things.\npackage c\n"),
		}, `must start "Package c "`},
		"command summary": {map[string][]byte{
			"cmd/tool/doc.go": []byte("// Package main is a tool.\npackage main\n"),
		}, `must start "Command tool "`},
		"code in doc.go": {map[string][]byte{
			"d/doc.go": []byte("// Package d is fine.\npackage d\n\nconst X = 1\n"),
		}, "holds code"},
		"second comment in doc.go": {map[string][]byte{
			"e/doc.go": []byte("// Package e is fine.\npackage e\n\n// stray\n"),
		}, "other than the package summary"},
	}
	for name, c := range cases {
		c.files["good/doc.go"] = good
		got := strings.Join(docProblems(c.files), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: the guard did not report %q; it said:\n%s", name, c.want, got)
		}
		if strings.Contains(got, "good/") {
			t.Errorf("%s: the guard refused the well-formed package: %s", name, got)
		}
	}
	// Test files are not part of go doc and may carry their own package comment.
	tests := map[string][]byte{"f/doc.go": []byte("// Package f is fine.\npackage f\n"),
		"f/f_test.go": []byte("// Package f_test is external.\npackage f_test\n")}
	if p := docProblems(tests); len(p) > 0 {
		t.Errorf("a test file's package comment was refused: %v", p)
	}
}
