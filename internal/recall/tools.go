// This file builds each tool's argument vector and parses its JSON report.
// The argument builders are pure functions so a test can assert the safety
// flags without running anything.

package recall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rawFinding is one tool-reported match before it becomes a candidate.
type rawFinding struct {
	tool      string
	rule      string // the tool's rule id (opengrep's dotted id, gosec's G304, bandit's B602)
	absPath   string
	startLine int
	endLine   int
	cwe       string   // the tool's own CWE, if it reports one
	enclosing []string // opengrep's enclosing context, outermost first (reversed from its report)
}

// toolRun is one tool's contribution to a scan.
type toolRun struct {
	findings []rawFinding
	// scanned holds the absolute paths the tool says it read.
	scanned map[string]bool
	// problems are coverage failures: something was asked of the tool and not
	// done. Each one makes the scan incomplete.
	problems []string
	// partialParses counts files opengrep parsed only in part (C macros, for
	// one). Recorded, not treated as incomplete: see Result.PartialParses.
	partialParses int
}

// maxArgBytes bounds one invocation's argument vector. Linux allows about
// 2 MiB of arguments and environment together; batches stay well under it.
const maxArgBytes = 512 << 10

// batches splits targets so no invocation's arguments exceed maxArgBytes.
func batches(fixed int, targets []string) [][]string {
	var out [][]string
	var cur []string
	size := fixed
	for _, t := range targets {
		if len(cur) > 0 && size+len(t)+1 > maxArgBytes {
			out = append(out, cur)
			cur, size = nil, fixed
		}
		cur = append(cur, t)
		size += len(t) + 1
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// RuleTimeoutSeconds is how long one rule may run on one file: opengrep's own
// default, stated so it cannot drift. On curl on 2026-10-03 a few rules timed
// out on two files at 5 s, and still did at 30 s (different rules each run,
// so the cause is load as much as cost), while 30 s took the scan from 56 s
// to 217 s. A timeout is reported as incomplete coverage either way, so it
// can never mark a finding fixed.
const RuleTimeoutSeconds = 5

// OpengrepArgs is opengrep's argument vector for rule files and absolute
// target files. The report is read from stdout: under --experimental,
// opengrep 1.26.0 ignores --output and prints the report (seen 2026-10-03).
//
//   - --disable-nosem: a nosemgrep comment in the scanned code is ignored.
//   - --disable-version-check: no request to opengrep's servers.
//   - --experimental --output-enclosing-context: opengrep's own parser names
//     the function and class around each match, which is the candidate's
//     function-authoritative identity.
//   - --timeout and --timeout-threshold=0: a rule gets RuleTimeoutSeconds on
//     a file, and a file is never skipped for its timeouts. A timeout still
//     happens, and is reported as incomplete coverage, never silently.
//   - targets are files, never a directory: a directory target is what
//     consults .semgrepignore and opengrep's default ignore list.
func OpengrepArgs(rules, targets []string) []string {
	args := []string{"scan", "--json", "--quiet", "--disable-version-check",
		"--disable-nosem", "--experimental", "--output-enclosing-context", "--no-autofix",
		"--timeout=" + strconv.Itoa(RuleTimeoutSeconds), "--timeout-threshold=0"}
	for _, r := range rules {
		args = append(args, "--config="+r)
	}
	return append(args, targets...)
}

// GosecArgs is gosec's argument vector over every package under the working
// directory. -nosec ignores #nosec and gosec:disable annotations; -no-fail
// makes the exit code mean "ran" rather than "found"; -quiet is never passed.
func GosecArgs(out string) []string {
	return []string{"-fmt=json", "-out=" + out, "-no-fail", "-nosec", "./..."}
}

// GosecEnv is the environment gosec runs in: the operator's, with the Go
// command pinned to the local toolchain and kept off the network. Package
// loading that would need a download fails instead, and gosec reports it as a
// load error, which Lane B records as incomplete coverage.
func GosecEnv(goBin string) []string {
	env := []string{}
	for _, kv := range os.Environ() {
		k := kv[:max(strings.IndexByte(kv, '='), 0)]
		switch k {
		case "GOFLAGS", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOINSECURE":
			continue
		case "PATH":
			if goBin != "" {
				kv = "PATH=" + goBin + string(os.PathListSeparator) + kv[len("PATH="):]
			}
		}
		env = append(env, kv)
	}
	return append(env, "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
}

// BanditArgs is bandit's argument vector over absolute target files.
// --ignore-nosec ignores `# nosec`; explicit files stop bandit discovering a
// .bandit file in a scanned directory.
func BanditArgs(targets []string, out string) []string {
	return append([]string{"-f", "json", "-o", out, "-q", "--ignore-nosec"}, targets...)
}

func runOpengrep(ctx context.Context, x Exec, bin string, rules, targets []string) (toolRun, error) {
	run := toolRun{scanned: map[string]bool{}}
	tmp, err := os.MkdirTemp("", "anvil-opengrep-")
	if err != nil {
		return run, err
	}
	defer os.RemoveAll(tmp)
	fixed := len(strings.Join(OpengrepArgs(rules, nil), " "))
	for _, b := range batches(fixed, targets) {
		out, errb, code, err := x.Run(ctx, bin, OpengrepArgs(rules, b), tmp, nil)
		if err != nil {
			return run, &ToolFailedError{Tool: ToolOpengrep, Reason: err.Error()}
		}
		if code != 0 && code != 1 {
			return run, &ToolFailedError{Tool: ToolOpengrep, ExitCode: code, Stderr: string(errb)}
		}
		if err := parseOpengrep(out, &run); err != nil {
			return run, &ToolFailedError{Tool: ToolOpengrep, ExitCode: code, Stderr: string(errb), Reason: err.Error()}
		}
	}
	return run, nil
}

type opengrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			EnclosingContext []struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"enclosing_context"`
			Metadata struct {
				CWE json.RawMessage `json:"cwe"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Level   string          `json:"level"`
		Type    json.RawMessage `json:"type"`
		Path    string          `json:"path"`
		Message string          `json:"message"`
	} `json:"errors"`
	Paths *struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
}

func parseOpengrep(raw []byte, run *toolRun) error {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fmt.Errorf("the report is empty; an empty report is never read as a clean scan")
	}
	var rep opengrepReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return fmt.Errorf("unparseable report: %w", err)
	}
	if rep.Paths == nil || rep.Results == nil {
		return fmt.Errorf("the report has no results or paths section, so it cannot say what was scanned")
	}
	for _, p := range rep.Paths.Scanned {
		run.scanned[p] = true
	}
	for _, r := range rep.Results {
		// opengrep lists the context innermost first ("from_pyfile", then
		// "Config", seen 2026-10-03 on flask); the symbol reads outermost first.
		var enc []string
		for i := len(r.Extra.EnclosingContext) - 1; i >= 0; i-- {
			if n := r.Extra.EnclosingContext[i].Name; n != "" {
				enc = append(enc, n)
			}
		}
		run.findings = append(run.findings, rawFinding{
			tool: ToolOpengrep, rule: r.CheckID, absPath: r.Path,
			startLine: r.Start.Line, endLine: r.End.Line, enclosing: enc,
		})
	}
	for _, e := range rep.Errors {
		kind := strings.Trim(string(e.Type), `"`)
		if strings.HasPrefix(kind, `["PartialParsing"`) || kind == "PartialParsing" {
			run.partialParses++
			continue
		}
		where := e.Path
		if where == "" {
			where = "the scan"
		}
		run.problems = append(run.problems, fmt.Sprintf("opengrep %s in %s: %s", e.Level, where, tail(firstLine(e.Message), 200)))
	}
	return nil
}

func runGosec(ctx context.Context, x Exec, bin, goBin string, modules []string) (toolRun, error) {
	run := toolRun{scanned: map[string]bool{}}
	tmp, err := os.MkdirTemp("", "anvil-gosec-")
	if err != nil {
		return run, err
	}
	defer os.RemoveAll(tmp)
	env := GosecEnv(goBin)
	for i, mod := range modules {
		out := filepath.Join(tmp, fmt.Sprintf("out-%04d.json", i))
		_, errb, code, err := x.Run(ctx, bin, GosecArgs(out), mod, env)
		if err != nil {
			return run, &ToolFailedError{Tool: ToolGosec, Reason: err.Error()}
		}
		if code != 0 {
			return run, &ToolFailedError{Tool: ToolGosec, ExitCode: code, Stderr: string(errb)}
		}
		if err := parseGosec(out, mod, &run); err != nil {
			return run, &ToolFailedError{Tool: ToolGosec, Stderr: string(errb), Reason: err.Error()}
		}
	}
	return run, nil
}

type gosecReport struct {
	GolangErrors map[string][]struct {
		Line  int    `json:"line"`
		Error string `json:"error"`
	} `json:"Golang errors"`
	Issues []struct {
		RuleID string `json:"rule_id"`
		File   string `json:"file"`
		Line   string `json:"line"`
		CWE    struct {
			ID string `json:"id"`
		} `json:"cwe"`
	} `json:"Issues"`
	Stats *struct {
		Files int `json:"files"`
	} `json:"Stats"`
}

func parseGosec(file, module string, run *toolRun) error {
	raw, err := readReport(file)
	if err != nil {
		return err
	}
	var rep gosecReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return fmt.Errorf("unparseable report: %w", err)
	}
	if rep.Stats == nil {
		return fmt.Errorf("the report has no Stats section, so it cannot say what was scanned")
	}
	files := make([]string, 0, len(rep.GolangErrors))
	for f := range rep.GolangErrors {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		errs := rep.GolangErrors[f]
		msg := ""
		if len(errs) > 0 {
			msg = errs[0].Error
		}
		run.problems = append(run.problems, fmt.Sprintf("gosec could not load %s (%d error(s), first: %s); its packages were analysed without full type information",
			relOrSelf(module, f), len(errs), tail(msg, 160)))
	}
	for _, is := range rep.Issues {
		start, end := lineRange(is.Line)
		run.findings = append(run.findings, rawFinding{
			tool: ToolGosec, rule: is.RuleID, absPath: is.File, startLine: start, endLine: end,
			cwe: cweOf(is.CWE.ID),
		})
	}
	return nil
}

func runBandit(ctx context.Context, x Exec, bin string, targets []string) (toolRun, error) {
	run := toolRun{scanned: map[string]bool{}}
	tmp, err := os.MkdirTemp("", "anvil-bandit-")
	if err != nil {
		return run, err
	}
	defer os.RemoveAll(tmp)
	fixed := len(strings.Join(BanditArgs(nil, filepath.Join(tmp, "out-0000.json")), " "))
	for i, b := range batches(fixed, targets) {
		out := filepath.Join(tmp, fmt.Sprintf("out-%04d.json", i))
		_, errb, code, err := x.Run(ctx, bin, BanditArgs(b, out), tmp, nil)
		if err != nil {
			return run, &ToolFailedError{Tool: ToolBandit, Reason: err.Error()}
		}
		if code != 0 && code != 1 {
			return run, &ToolFailedError{Tool: ToolBandit, ExitCode: code, Stderr: string(errb)}
		}
		if err := parseBandit(out, &run); err != nil {
			return run, &ToolFailedError{Tool: ToolBandit, ExitCode: code, Stderr: string(errb), Reason: err.Error()}
		}
	}
	return run, nil
}

type banditReport struct {
	Errors []struct {
		Filename string `json:"filename"`
		Reason   string `json:"reason"`
	} `json:"errors"`
	Results []struct {
		TestID     string `json:"test_id"`
		Filename   string `json:"filename"`
		LineNumber int    `json:"line_number"`
		LineRange  []int  `json:"line_range"`
		IssueCWE   struct {
			ID int `json:"id"`
		} `json:"issue_cwe"`
	} `json:"results"`
	Metrics map[string]json.RawMessage `json:"metrics"`
}

func parseBandit(file string, run *toolRun) error {
	raw, err := readReport(file)
	if err != nil {
		return err
	}
	var rep banditReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return fmt.Errorf("unparseable report: %w", err)
	}
	if rep.Results == nil || rep.Metrics == nil {
		return fmt.Errorf("the report has no results or metrics section, so it cannot say what was scanned")
	}
	failed := map[string]bool{}
	for _, e := range rep.Errors {
		failed[e.Filename] = true
		run.problems = append(run.problems, fmt.Sprintf("bandit could not scan %s: %s", e.Filename, tail(e.Reason, 160)))
	}
	// bandit's metrics hold one entry per file it read, keyed by the path it
	// was given, plus "_totals".
	for k := range rep.Metrics {
		if k != "_totals" && !failed[k] {
			run.scanned[k] = true
		}
	}
	for _, r := range rep.Results {
		end := r.LineNumber
		if n := len(r.LineRange); n > 0 && r.LineRange[n-1] > end {
			end = r.LineRange[n-1]
		}
		cwe := ""
		if r.IssueCWE.ID > 0 {
			cwe = "CWE-" + strconv.Itoa(r.IssueCWE.ID)
		}
		run.findings = append(run.findings, rawFinding{
			tool: ToolBandit, rule: r.TestID, absPath: r.Filename, startLine: r.LineNumber, endLine: end, cwe: cwe,
		})
	}
	return nil
}

func readReport(file string) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("no report was written: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, fmt.Errorf("the report is empty; an empty report is never read as a clean scan")
	}
	return raw, nil
}

var cweNumber = regexp.MustCompile(`(?i)^\s*(?:cwe-?)?0*(\d+)`)

// cweOf normalises "CWE-078", "cwe-78" and "78" to "CWE-78"; anything else is
// the empty string.
func cweOf(s string) string {
	m := cweNumber.FindStringSubmatch(s)
	if m == nil || m[1] == "" {
		return ""
	}
	return "CWE-" + m[1]
}

// lineRange reads gosec's line field, "12" or "12-14".
func lineRange(s string) (int, int) {
	a, b, ok := strings.Cut(s, "-")
	start, _ := strconv.Atoi(strings.TrimSpace(a))
	end := start
	if ok {
		if e, err := strconv.Atoi(strings.TrimSpace(b)); err == nil && e >= start {
			end = e
		}
	}
	return start, end
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func relOrSelf(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return p
}
