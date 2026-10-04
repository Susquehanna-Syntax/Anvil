// This file is the candidate contract (plan node candidatelist) and the scan
// that produces candidates.
//
// A CANDIDATE IS A RULE MATCH NOBODY HAS JUDGED. It carries:
//
//   - a function-authoritative identity: the enclosing symbol, named by a
//     parser (go/parser for any Go match, opengrep's own for its other
//     matches, an indentation reading for bandit's), or empty when the match
//     is top-level and the file alone identifies it;
//   - an advisory-only line hint: lines move with every edit above them, so
//     they locate a match for a reader and never identify it;
//   - the rule id, versioned, and one CWE;
//   - the snippet, verbatim target-repository source and therefore untrusted
//     whatever Anvil did to extract it;
//   - the rule's provenance: repository, commit or release, licence.
//
// THE COUNT IS PART OF THE CONTRACT. Candidates per scan, not model size,
// decides whether Lane B is affordable (the candidates-per-scan register row),
// so every Scan returns it and the scan controller records it on every scan.

package recall

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Provenance is where a candidate's rule came from. Every field is non-empty
// on every candidate; Scan refuses to return one that is not.
type Provenance struct {
	// Source is the corpus name ("gitlab-sast-rules") or the native tool
	// ("gosec").
	Source string `json:"source"`
	// Repository is the upstream repository URL.
	Repository string `json:"repository"`
	// Version is the corpus commit or the tool release.
	Version string `json:"version"`
	// RulePath is the vendored rule file, relative to the pack root, or the
	// tool's own rule id for a native analyser.
	RulePath string `json:"rulePath"`
	// Licence is the rule's SPDX licence, and LicenceEvidence what it was read
	// from.
	Licence         string `json:"licence"`
	LicenceEvidence string `json:"licenceEvidence"`
}

// Candidate is one recall candidate.
type Candidate struct {
	Tool            string `json:"tool"`
	RuleID          string `json:"ruleId"`
	RuleIDVersioned string `json:"ruleIdVersioned"`
	CWE             string `json:"cwe"`
	Path            string `json:"path"` // repository-relative, slash-separated
	StartLine       int    `json:"startLine"`
	EndLine         int    `json:"endLine"`
	Symbol          string `json:"symbol"` // the enclosing symbol, e.g. "Server.handle"; empty at top level
	Snippet         string `json:"snippet"`
	// Context is the match with ContextLines of source either side, for a
	// reader and for the coding agent; untrusted, like Snippet.
	ContextStartLine int        `json:"contextStartLine"`
	ContextEndLine   int        `json:"contextEndLine"`
	Context          string     `json:"context"`
	Provenance       Provenance `json:"provenance"`
}

// ContextLines is how many lines of source surround a match in its context.
const ContextLines = 3

// EnclosingSymbolPath is the anvil-fp/v1 SAST tier's enclosing_symbol_path:
// "path::Symbol", or empty when the match has no enclosing symbol.
func (c Candidate) EnclosingSymbolPath() string {
	if c.Symbol == "" {
		return ""
	}
	return c.Path + "::" + c.Symbol
}

// Result is one scan's output.
type Result struct {
	Candidates []Candidate
	// Count is len(Candidates): the candidates-per-scan metric.
	Count int
	// ByTool counts candidates per tool.
	ByTool map[string]int
	// Files is how many files Lane B handed a tool; ToolsRun the tools it ran.
	Files    int
	ToolsRun []string
	// Problems are coverage failures. Any problem makes the scan incomplete,
	// which the store records as a partial scan that resolves nothing.
	Problems []string
	// Notes are informational and do not make the scan incomplete.
	Notes []string
	// PartialParses counts files opengrep parsed only in part. This is the
	// engine's ordinary behaviour on macro-heavy C (144 of curl's 495 files on
	// 2026-10-03), so it is reported rather than treated as incomplete.
	PartialParses int
}

// Scanner runs the recall tier.
type Scanner struct {
	Pack  *Pack
	Tools Tools
	Exec  Exec // nil means ProcessExec
}

// Plan is what a scan of one tree will run, decided before anything runs.
type Plan struct {
	Root string
	// Targets are the absolute paths of the files handed to each tool.
	Opengrep []string
	Bandit   []string
	// Modules are the Go module roots gosec runs in.
	Modules []string
	// GoFiles counts, per module root, the non-test Go files the Go tool
	// would load there: gosec is expected to analyse each one. Orphans are Go
	// files in no module, and Vendored those under a vendor/ directory.
	GoFiles  map[string]int
	Orphans  int
	Vendored int
	// Excluded is how many source files the selection's excluded paths kept
	// out.
	Excluded int

	bins map[string]string
}

// Needs lists the tools the plan runs.
func (p Plan) Needs() []string {
	var out []string
	if len(p.Opengrep) > 0 {
		out = append(out, ToolOpengrep)
	}
	if len(p.Modules) > 0 {
		out = append(out, ToolGosec)
	}
	if len(p.Bandit) > 0 {
		out = append(out, ToolBandit)
	}
	return out
}

// Only narrows a plan to the named repository-relative files, for a scan of
// what one push changed. Gosec still loads whole packages (it cannot do
// less), so its matches outside the named files are dropped afterwards by
// whoever asked for the narrowing.
func (p Plan) Only(rel []string) Plan {
	want := map[string]bool{}
	for _, r := range rel {
		want[filepath.Join(p.Root, filepath.FromSlash(r))] = true
	}
	keep := func(in []string) []string {
		var out []string
		for _, f := range in {
			if want[f] {
				out = append(out, f)
			}
		}
		return out
	}
	q := p
	q.Opengrep, q.Bandit = keep(p.Opengrep), keep(p.Bandit)
	goChanged := false
	for r := range want {
		goChanged = goChanged || strings.HasSuffix(r, ".go")
	}
	if !goChanged {
		q.Modules = nil
	}
	return q
}

// Empty reports whether the tree holds no file any recall tool reads.
func (p Plan) Empty() bool { return len(p.Needs()) == 0 }

// extensions maps a file extension to the rule languages that read it.
var extensions = map[string][]string{
	".c": {"c", "cpp"}, ".h": {"c", "cpp"},
	".cc": {"cpp"}, ".cpp": {"cpp"}, ".cxx": {"cpp"}, ".hpp": {"cpp"}, ".hh": {"cpp"}, ".hxx": {"cpp"},
	".py": {"python"}, ".pyi": {"python"},
	".go":   {"go"},
	".java": {"java"},
	".js":   {"javascript"}, ".jsx": {"javascript"}, ".mjs": {"javascript"}, ".cjs": {"javascript"},
	".ts": {"typescript"}, ".tsx": {"typescript"},
	".cs":    {"csharp"},
	".scala": {"scala"},
}

// Prepare enumerates root and decides which tools the scan needs, then
// resolves each one and checks its version against the pin. It runs nothing
// over the repository, so a missing tool stops a scan before it starts.
//
// Enumeration never follows a symbolic link and never enters .git: a link is
// a path out of the tree under scan.
func (s Scanner) Prepare(ctx context.Context, root string) (Plan, error) {
	if s.Pack == nil {
		return Plan{}, fmt.Errorf("%w: no rule pack", ErrRulePack)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Root: abs, bins: map[string]string{}, GoFiles: map[string]int{}}
	langs := map[string]bool{}
	for _, l := range s.Pack.Languages() {
		langs[l] = true
	}
	var goFiles []string // non-test Go files the Go tool would load, absolute
	var modules []string
	err = filepath.WalkDir(abs, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(abs, full)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" && full != abs {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && strings.HasSuffix(d.Name(), ".go") && !strings.HasSuffix(d.Name(), "_test.go") {
			if goToolSees(rel) {
				goFiles = append(goFiles, full)
			} else if inVendor(rel) {
				plan.Vendored++
			}
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if d.Name() == "go.mod" {
			modules = append(modules, filepath.Dir(full))
			return nil
		}
		ls, ok := extensions[strings.ToLower(filepath.Ext(d.Name()))]
		if !ok {
			return nil
		}
		if s.Pack.Excluded(rel) {
			plan.Excluded++
			return nil
		}
		ruled := false
		for _, l := range ls {
			ruled = ruled || langs[l]
		}
		if ruled {
			plan.Opengrep = append(plan.Opengrep, full)
		}
		if filepath.Ext(d.Name()) == ".py" {
			plan.Bandit = append(plan.Bandit, full)
		}
		return nil
	})
	if err != nil {
		return Plan{}, fmt.Errorf("recall: enumerating %s: %w", abs, err)
	}
	if len(goFiles) > 0 {
		plan.Modules = modules
		for _, f := range goFiles {
			if m := owningModule(f, modules); m != "" {
				plan.GoFiles[m]++
			} else {
				plan.Orphans++
			}
		}
	}
	x := s.exec()
	for _, tool := range plan.Needs() {
		bin, err := resolve(tool, s.Tools.binary(tool))
		if err != nil {
			return plan, err
		}
		pin, ok := s.Pack.Tool(tool)
		if !ok {
			return plan, fmt.Errorf("%w: the selection pins no %s release", ErrRulePack, tool)
		}
		if err := checkVersion(ctx, x, tool, bin, pin.Version); err != nil {
			return plan, err
		}
		plan.bins[tool] = bin
	}
	return plan, nil
}

func (s Scanner) exec() Exec {
	if s.Exec == nil {
		return ProcessExec{}
	}
	return s.Exec
}

// Scan runs a prepared plan. A tool that fails fails the scan: a candidate
// list missing one tool's matches would read as that tool finding nothing.
func (s Scanner) Scan(ctx context.Context, plan Plan) (Result, error) {
	res := Result{ByTool: map[string]int{}, ToolsRun: plan.Needs(), Files: len(plan.Opengrep)}
	if plan.Empty() {
		return res, nil
	}
	x := s.exec()
	var runs []toolRun
	if len(plan.Opengrep) > 0 {
		rules := make([]string, 0, len(s.Pack.Rules()))
		for _, r := range s.Pack.Rules() {
			p, err := filepath.Abs(filepath.Join(s.Pack.Root, filepath.FromSlash(r.Path)))
			if err != nil {
				return res, err
			}
			rules = append(rules, p)
		}
		run, err := runOpengrep(ctx, x, plan.bins[ToolOpengrep], rules, plan.Opengrep)
		if err != nil {
			return res, err
		}
		// Every file handed to opengrep must be one it says it scanned. A file
		// it skipped (over its size limit, unreadable) is a hole in coverage.
		missed := 0
		for _, t := range plan.Opengrep {
			if !run.scanned[t] {
				missed++
			}
		}
		if missed > 0 {
			run.problems = append(run.problems, fmt.Sprintf("opengrep did not scan %d of the %d files it was given", missed, len(plan.Opengrep)))
		}
		runs = append(runs, run)
	}
	if len(plan.Modules) > 0 {
		run, err := runGosec(ctx, x, plan.bins[ToolGosec], s.Tools.GoBin, plan.Modules)
		if err != nil {
			return res, err
		}
		// gosec analyses only the files the Go tool loads for this platform
		// with cgo off; one it left out (build-constrained for another OS,
		// cgo, unloadable) was read by opengrep alone, and the scan says so.
		for _, m := range plan.Modules {
			if want, got := plan.GoFiles[m], run.analysed[m]; got < want {
				run.problems = append(run.problems, fmt.Sprintf(
					"gosec analysed %d of the %d Go files in module %s; the rest (another platform's build constraints, cgo, or a package it could not load) were read by opengrep only",
					got, want, relOrSelf(plan.Root, m)))
			}
		}
		runs = append(runs, run)
	}
	if plan.Orphans > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf(
			"%d Go file(s) belong to no Go module, so gosec did not analyse them (opengrep did)", plan.Orphans))
	}
	if plan.Vendored > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%d Go file(s) under vendor/ were read by opengrep only; gosec does not analyse vendored packages", plan.Vendored))
	}
	if len(plan.Bandit) > 0 {
		run, err := runBandit(ctx, x, plan.bins[ToolBandit], plan.Bandit)
		if err != nil {
			return res, err
		}
		missed := 0
		for _, t := range plan.Bandit {
			if !run.scanned[t] {
				missed++
			}
		}
		if missed > 0 {
			run.problems = append(run.problems, fmt.Sprintf("bandit did not scan %d of the %d files it was given", missed, len(plan.Bandit)))
		}
		runs = append(runs, run)
	}

	files := newSourceCache(plan.Root)
	var cands []Candidate
	for _, run := range runs {
		res.Problems = append(res.Problems, run.problems...)
		res.PartialParses += run.partialParses
		for _, f := range run.findings {
			c, keep, err := s.candidate(plan.Root, f, files)
			var notRegular *notRegularError
			if errors.As(err, &notRegular) {
				// A tool followed a symbolic link Lane B does not follow
				// (gosec loads a linked .go file as part of its package).
				// The match is not reported, and the scan says so.
				res.Problems = append(res.Problems, fmt.Sprintf(
					"%s reported a match in %s, which is not a regular file in the tree; Lane B does not follow links", f.tool, notRegular.rel))
				continue
			}
			if err != nil {
				return res, err
			}
			if keep {
				cands = append(cands, c)
			}
		}
	}
	res.Candidates = Dedupe(cands)
	res.Count = len(res.Candidates)
	for _, c := range res.Candidates {
		res.ByTool[c.Tool]++
	}
	return res, nil
}

// candidate turns one tool finding into a candidate, or drops it (keep false)
// when it lies outside the tree, in an excluded path, or under an excluded
// tool rule.
func (s Scanner) candidate(root string, f rawFinding, files *sourceCache) (Candidate, bool, error) {
	abs := f.absPath
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, abs)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return Candidate{}, false, nil
	}
	rel = filepath.ToSlash(rel)
	if s.Pack.Excluded(rel) {
		return Candidate{}, false, nil
	}
	c := Candidate{Tool: f.tool, Path: rel, StartLine: f.startLine, EndLine: f.endLine}
	if c.EndLine < c.StartLine {
		c.EndLine = c.StartLine
	}
	switch f.tool {
	case ToolOpengrep:
		r, id, ok := s.Pack.RuleByID(f.rule)
		if !ok {
			return c, false, &ToolFailedError{Tool: ToolOpengrep, Reason: fmt.Sprintf("reported rule %q, which resolves to no single rule in the pack", f.rule)}
		}
		c.RuleID = id
		c.RuleIDVersioned = r.Corpus + "/" + c.RuleID + "@" + r.BlobSHA1[:12]
		c.CWE = r.CWEs[0]
		c.Provenance = Provenance{
			Source: r.Corpus, Repository: r.Repository, Version: r.Commit, RulePath: r.Path,
			Licence: r.Licence, LicenceEvidence: r.LicenceEvidence,
		}
		c.Symbol = strings.Join(f.enclosing, ".")
	default:
		if s.Pack.ToolRuleExcluded(f.tool, f.rule) {
			return Candidate{}, false, nil
		}
		pin, _ := s.Pack.Tool(f.tool)
		c.RuleID = f.rule
		c.RuleIDVersioned = f.tool + "/" + f.rule + "@" + pin.Version
		c.CWE = f.cwe
		if c.CWE == "" {
			return c, false, &ToolFailedError{Tool: f.tool, Reason: fmt.Sprintf("rule %s reported no CWE; every candidate needs one", f.rule)}
		}
		c.Provenance = Provenance{
			Source: f.tool, Repository: pin.Repository, Version: pin.Version, RulePath: f.tool + ":" + f.rule,
			Licence: pin.Licence, LicenceEvidence: pin.LicenceEvidence,
		}
	}
	lines, err := files.lines(rel)
	if errors.Is(err, errNotRegular) {
		return c, false, &notRegularError{rel: rel}
	}
	if err != nil {
		return c, false, fmt.Errorf("recall: reading %s for a %s match: %w", rel, f.tool, err)
	}
	c.Snippet = snippet(lines, c.StartLine, c.EndLine, maxSnippetLines)
	c.ContextStartLine = max(1, c.StartLine-ContextLines)
	c.ContextEndLine = min(len(lines), c.EndLine+ContextLines)
	c.Context = snippet(lines, c.ContextStartLine, c.ContextEndLine, maxSnippetLines+2*ContextLines)
	// One naming per language, whichever tool matched: a Go method is
	// "Recv.Method" from go/parser for gosec and opengrep alike (opengrep's
	// own context drops the receiver), and bandit's matches are read from
	// Python's indentation.
	switch {
	case strings.HasSuffix(rel, ".go"):
		c.Symbol = goSymbol(files.source(rel), c.StartLine)
	case f.tool == ToolBandit:
		c.Symbol = pythonSymbol(lines, c.StartLine)
	}
	if err := c.check(); err != nil {
		return c, false, err
	}
	return c, true, nil
}

// check is the contract: 100% non-empty provenance, and the fields the
// fingerprint and the record need.
func (c Candidate) check() error {
	p := c.Provenance
	for name, v := range map[string]string{
		"rule id": c.RuleIDVersioned, "CWE": c.CWE, "path": c.Path, "snippet": strings.TrimSpace(c.Snippet),
		"provenance source": p.Source, "provenance repository": p.Repository, "provenance version": p.Version,
		"provenance rule path": p.RulePath, "provenance licence": p.Licence, "provenance licence evidence": p.LicenceEvidence,
	} {
		if v == "" {
			return fmt.Errorf("recall: a %s candidate at %s:%d has no %s", c.Tool, c.Path, c.StartLine, name)
		}
	}
	if c.StartLine < 1 {
		return fmt.Errorf("recall: a %s candidate at %s has no line", c.Tool, c.Path)
	}
	return nil
}

// toolOrder is the precedence Dedupe applies when two tools match the same
// line with the same CWE: a native analyser, which has type or AST
// information, over a pattern rule.
var toolOrder = map[string]int{ToolGosec: 0, ToolBandit: 1, ToolOpengrep: 2}

// Dedupe keeps one candidate per (path, line, CWE), the unit the
// candidates-per-scan instrument counts, choosing deterministically: tool
// precedence, then the rule id. It returns them sorted by path, line, CWE.
func Dedupe(cands []Candidate) []Candidate {
	sorted := append([]Candidate(nil), cands...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.CWE != b.CWE {
			return a.CWE < b.CWE
		}
		if toolOrder[a.Tool] != toolOrder[b.Tool] {
			return toolOrder[a.Tool] < toolOrder[b.Tool]
		}
		return a.RuleIDVersioned < b.RuleIDVersioned
	})
	out := sorted[:0]
	for i, c := range sorted {
		if i > 0 {
			p := out[len(out)-1]
			if p.Path == c.Path && p.StartLine == c.StartLine && p.CWE == c.CWE {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// maxSnippetLines bounds a snippet. A match spanning more lines than this is
// cut, and says so in its last line.
const maxSnippetLines = 40

func snippet(lines []string, start, end, maxLines int) string {
	if start < 1 || start > len(lines) {
		return ""
	}
	if end > len(lines) {
		end = len(lines)
	}
	cut := false
	if end-start+1 > maxLines {
		end, cut = start+maxLines-1, true
	}
	s := strings.Join(lines[start-1:end], "\n")
	if cut {
		s += "\n…"
	}
	return s
}

var errNotRegular = errors.New("not a regular file")

// notRegularError is a tool match in a path that is not a regular file in
// the tree: a symbolic link, most often.
type notRegularError struct{ rel string }

func (e *notRegularError) Error() string { return "recall: " + e.rel + " is not a regular file" }

// goToolSees reports whether the Go tool loads a file at this relative path:
// not under testdata/ or vendor/, nor under a directory whose name starts
// with "." or "_".
func goToolSees(rel string) bool {
	segs := strings.Split(rel, "/")
	for _, s := range segs[:len(segs)-1] {
		if s == "testdata" || s == "vendor" || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "_") {
			return false
		}
	}
	return !strings.HasPrefix(segs[len(segs)-1], ".") && !strings.HasPrefix(segs[len(segs)-1], "_")
}

func inVendor(rel string) bool {
	return rel == "vendor" || strings.HasPrefix(rel, "vendor/") || strings.Contains(rel, "/vendor/")
}

// owningModule is the deepest module root containing file, or "".
func owningModule(file string, modules []string) string {
	best := ""
	for _, m := range modules {
		if strings.HasPrefix(file, m+string(filepath.Separator)) && len(m) > len(best) {
			best = m
		}
	}
	return best
}

// sourceCache reads each file once.
type sourceCache struct {
	root  string
	files map[string][]string
	raw   map[string][]byte
}

func newSourceCache(root string) *sourceCache {
	return &sourceCache{root: root, files: map[string][]string{}, raw: map[string][]byte{}}
}

func (c *sourceCache) lines(rel string) ([]string, error) {
	if l, ok := c.files[rel]; ok {
		return l, nil
	}
	full := filepath.Join(c.root, filepath.FromSlash(rel))
	st, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		out = append(out, strings.TrimRight(sc.Text(), "\r"))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	c.files[rel], c.raw[rel] = out, b
	return out, nil
}

func (c *sourceCache) source(rel string) []byte { return c.raw[rel] }
