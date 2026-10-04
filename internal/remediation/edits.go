package remediation

// Anchored edits (plan node apply). The model's reply is parsed into edits;
// each SEARCH text must occur exactly once in the file as it is at the scanned
// commit; the harness writes nothing until every edit anchors. The result is a
// new file content per path, which the git side turns into a diff carrying the
// scanned blob's identity and applies with git apply --3way.

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// WholeFileLimit is the line count under which a file may be replaced whole.
const WholeFileLimit = 300

// Edit is one parsed edit.
type Edit struct {
	Path    string
	Search  string // empty for a whole-file replacement
	Replace string
	Whole   bool
}

var (
	editRE  = regexp.MustCompile(`(?ms)^FILE:[ \t]*([^\r\n]+?)[ \t]*\r?\n<<<<<<< SEARCH\r?\n(.*?)\r?\n=======\r?\n(.*?)\r?\n?>>>>>>> REPLACE`)
	wholeRE = regexp.MustCompile(`(?ms)^FILE:[ \t]*([^\r\n]+?)[ \t]*\r?\n<<<<<<< WHOLE\r?\n(.*?)\r?\n?>>>>>>> WHOLE`)
)

// ParseEdits reads every edit block from a reply, in reply order.
func ParseEdits(reply string) []Edit {
	type at struct {
		pos int
		e   Edit
	}
	var all []at
	for _, m := range editRE.FindAllStringSubmatchIndex(reply, -1) {
		all = append(all, at{m[0], Edit{Path: reply[m[2]:m[3]], Search: reply[m[4]:m[5]], Replace: reply[m[6]:m[7]]}})
	}
	for _, m := range wholeRE.FindAllStringSubmatchIndex(reply, -1) {
		all = append(all, at{m[0], Edit{Path: reply[m[2]:m[3]], Replace: reply[m[4]:m[5]], Whole: true}})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].pos < all[j].pos })
	out := make([]Edit, len(all))
	for i, a := range all {
		out[i] = a.e
	}
	return out
}

// ErrAnchor means at least one edit could not be placed. Its text lists every
// problem, which is what the anchor-repair turn shows the model.
type ErrAnchor struct{ Problems []string }

func (e *ErrAnchor) Error() string {
	return "remediation: edits do not anchor: " + strings.Join(e.Problems, "; ")
}

// errNoEdits is the anchor problem of a reply with no edit block.
var errNoEdits = errors.New("the reply contains no edit block")

// Anchor applies edits to the base contents of the files the group may edit.
// It returns the new content of every file an edit touched, or *ErrAnchor
// naming every edit that could not be placed. A file's line endings are kept:
// a CRLF file's SEARCH and REPLACE texts are matched and written with CRLF,
// because the model is shown, and answers in, LF.
func Anchor(base map[string]string, edits []Edit) (map[string]string, error) {
	if len(edits) == 0 {
		return nil, &ErrAnchor{Problems: []string{errNoEdits.Error()}}
	}
	out := map[string]string{}
	var problems []string
	for i, e := range edits {
		orig, ok := base[e.Path]
		if !ok {
			problems = append(problems, fmt.Sprintf("edit %d names %q, which is not a file you may edit", i+1, e.Path))
			continue
		}
		cur, seen := out[e.Path]
		if !seen {
			cur = orig
		}
		crlf := strings.Contains(orig, "\r\n")
		search, replace := e.Search, e.Replace
		if crlf {
			search, replace = toCRLF(search), toCRLF(replace)
		}
		if e.Whole {
			if n := lineCount(orig); n >= WholeFileLimit {
				problems = append(problems, fmt.Sprintf("edit %d replaces %q whole, but it has %d lines (limit %d)", i+1, e.Path, n, WholeFileLimit))
				continue
			}
			if !strings.HasSuffix(replace, "\n") && strings.HasSuffix(orig, "\n") {
				replace += map[bool]string{true: "\r\n", false: "\n"}[crlf]
			}
			out[e.Path] = replace
			continue
		}
		if search == "" {
			problems = append(problems, fmt.Sprintf("edit %d to %q has an empty SEARCH", i+1, e.Path))
			continue
		}
		switch n := strings.Count(cur, search); n {
		case 1:
			out[e.Path] = strings.Replace(cur, search, replace, 1)
		case 0:
			problems = append(problems, fmt.Sprintf("edit %d: its SEARCH text does not occur in %q", i+1, e.Path))
		default:
			problems = append(problems, fmt.Sprintf("edit %d: its SEARCH text occurs %d times in %q; include more lines so it is unique", i+1, n, e.Path))
		}
	}
	if len(problems) > 0 {
		return nil, &ErrAnchor{Problems: problems}
	}
	for p, s := range out {
		if s == base[p] {
			delete(out, p)
		}
	}
	if len(out) == 0 {
		return nil, &ErrAnchor{Problems: []string{"the edits change nothing"}}
	}
	return out, nil
}

func toCRLF(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

func lineCount(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}
