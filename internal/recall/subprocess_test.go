package recall_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTheRecallTierLinksNoTool holds "subprocess only" (plan node opengrep):
// the recall tier and the Lane B pipeline import the standard library and
// Anvil's own packages and nothing else, so no recall tool, binding or rule
// engine can be linked into the anvil binary. Every tool is an exec.
func TestTheRecallTierLinksNoTool(t *testing.T) {
	const module = "github.com/Susquehanna-Syntax/Anvil/"
	checked := 0
	for _, dir := range []string{".", "../laneb"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range parsed.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				first, _, _ := strings.Cut(p, "/")
				if strings.Contains(first, ".") && !strings.HasPrefix(p, module) {
					t.Errorf("%s imports %q: the recall tier runs its tools as processes and links none", f, p)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no imports were checked; the guard read nothing")
	}
}
