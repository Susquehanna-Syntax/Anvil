// This file names the enclosing symbol for the two native analysers, which do
// not report one. opengrep's matches carry the name its own parser found.

package recall

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// goSymbol is the function or method declaration around line, as go/parser
// reads it: "Func", or "Recv.Method" with the receiver's type name. A match
// inside a function literal belongs to the declaration that contains it. A
// file that does not parse, or a line outside every declaration, gives "".
func goSymbol(src []byte, line int) string {
	if len(src) == 0 {
		return ""
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.SkipObjectResolution)
	if err != nil {
		return ""
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fset.Position(fd.Pos()).Line > line || fset.Position(fd.End()).Line < line {
			continue
		}
		if fd.Recv == nil || len(fd.Recv.List) == 0 {
			return fd.Name.Name
		}
		return receiverName(fd.Recv.List[0].Type) + "." + fd.Name.Name
	}
	return ""
}

func receiverName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return receiverName(t.X)
	case *ast.IndexExpr:
		return receiverName(t.X)
	case *ast.IndexListExpr:
		return receiverName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// pythonSymbol is the chain of class and def blocks around line, read from
// indentation: "Class.method", "function", or "" at module level. A block
// encloses the line only if it starts strictly less indented, and only
// logical-line starts count: a forward pass tracks brackets, strings and
// comments, so the closing line of a def signature split over several lines,
// or a line inside a triple-quoted string, is never read as a block. It is a
// reading of the layout rather than a parse, and it is deterministic, which
// is what identity needs: the same file gives the same answer on every scan.
func pythonSymbol(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	starts := pythonLogicalStarts(lines)
	target := line - 1
	for target > 0 && !starts[target] {
		target-- // a match inside a continued line belongs to its logical line
	}
	limit := indentOf(lines[target])
	if strings.TrimSpace(lines[target]) == "" {
		limit = 1 << 30
	}
	var chain []string
	// A match on a def or class line, signature included, belongs to it.
	if name, ok := pythonBlockName(lines[target]); ok {
		chain = append(chain, name)
	}
	for i := target - 1; i >= 0 && limit > 0; i-- {
		s := strings.TrimSpace(lines[i])
		if !starts[i] || s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		ind := indentOf(lines[i])
		if ind >= limit {
			continue
		}
		limit = ind
		if name, ok := pythonBlockName(lines[i]); ok {
			chain = append([]string{name}, chain...)
		}
	}
	return strings.Join(chain, ".")
}

// pythonBlockName reads the name a def or class line opens.
func pythonBlockName(line string) (string, bool) {
	s := strings.TrimSpace(line)
	for _, kw := range []string{"def ", "async def ", "class "} {
		if rest, ok := strings.CutPrefix(s, kw); ok {
			if j := strings.IndexAny(rest, "(:["); j >= 0 {
				rest = rest[:j]
			}
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// pythonLogicalStarts marks the lines that begin a logical line: not inside
// an open bracket, an open triple-quoted string or a backslash continuation.
func pythonLogicalStarts(lines []string) []bool {
	starts := make([]bool, len(lines))
	depth := 0
	quote := ""   // the open string's delimiter, one quote character or three
	cont := false // the previous line ended in a backslash
	for i, l := range lines {
		starts[i] = depth == 0 && quote == "" && !cont
		cont = false
		for j := 0; j < len(l); j++ {
			c := l[j]
			if quote != "" {
				if c == '\\' {
					j++
					continue
				}
				if strings.HasPrefix(l[j:], quote) {
					j += len(quote) - 1
					quote = ""
				}
				continue
			}
			switch c {
			case '#':
				j = len(l)
			case '\'', '"':
				q := string(c)
				if strings.HasPrefix(l[j:], q+q+q) {
					q += q + q
				}
				quote = q
				j += len(q) - 1
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				if depth > 0 {
					depth--
				}
			case '\\':
				cont = j == len(l)-1
			}
		}
		if len(quote) == 1 {
			quote = "" // a one-quote string does not span lines
		}
	}
	return starts
}

func indentOf(s string) int {
	n := 0
	for _, r := range s {
		switch r {
		case ' ':
			n++
		case '\t':
			n += 8 - n%8
		default:
			return n
		}
	}
	return n
}
