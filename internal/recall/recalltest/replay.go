package recalltest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/Susquehanna-Syntax/Anvil/internal/recall"
)

// RootToken stands for the fixture's absolute path in a recorded report.
const RootToken = "@LANEB_FIXTURE_ROOT@"

// Dir is the directory holding the recorded reports.
func Dir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "recorded")
}

// FixtureRoot is testdata/laneb-fixture in this checkout.
func FixtureRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata", "laneb-fixture")
}

// RulePack is data/rules in this checkout.
func RulePack() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "data", "rules")
}

// Replay is an Exec that answers each tool with its recorded report, with the
// fixture root put back in. Version commands answer with the pinned versions.
// Tools names the binaries it answers to, so a test points recall.Tools at
// them; they need not exist on disk.
type Replay struct {
	Root string
	// Calls records every invocation, for tests that assert on arguments.
	mu    sync.Mutex
	Calls [][]string
}

// Tools are the binary paths Replay answers to. They are absolute paths into
// the recorded directory, which hold small executable stand-ins so that
// recall's resolve step, which stats the file, accepts them.
func Tools() recall.Tools {
	d := Dir()
	return recall.Tools{
		Opengrep: filepath.Join(d, "bin", recall.ToolOpengrep),
		Gosec:    filepath.Join(d, "bin", recall.ToolGosec),
		Bandit:   filepath.Join(d, "bin", recall.ToolBandit),
	}
}

// Run implements recall.Exec.
func (r *Replay) Run(_ context.Context, bin string, args []string, _ string, _ []string) ([]byte, []byte, int, error) {
	r.mu.Lock()
	r.Calls = append(r.Calls, append([]string{bin}, args...))
	r.mu.Unlock()
	tool := filepath.Base(bin)
	if len(args) == 1 && strings.Contains(args[0], "version") {
		switch tool {
		case recall.ToolOpengrep:
			return []byte("1.26.0\n"), nil, 0, nil
		case recall.ToolGosec:
			return []byte("Version: 2.29.0\nGit tag: v2.29.0\n"), nil, 0, nil
		case recall.ToolBandit:
			return []byte("bandit 1.9.4\n"), nil, 0, nil
		}
	}
	raw, err := os.ReadFile(filepath.Join(Dir(), tool+".json"))
	if err != nil {
		return nil, nil, 0, err
	}
	raw = bytes.ReplaceAll(raw, []byte(RootToken), []byte(r.Root))
	switch tool {
	case recall.ToolOpengrep:
		return raw, nil, 0, nil
	case recall.ToolGosec:
		for _, a := range args {
			if out, ok := strings.CutPrefix(a, "-out="); ok {
				return nil, nil, 0, os.WriteFile(out, raw, 0o600)
			}
		}
	case recall.ToolBandit:
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				return nil, nil, 1, os.WriteFile(args[i+1], raw, 0o600)
			}
		}
	}
	return nil, nil, 0, errors.New("recalltest: no report destination in " + fmt.Sprint(args))
}

// Recorder wraps a real Exec and saves each tool's report with the fixture
// root replaced by RootToken. It is how the recorded reports were made.
type Recorder struct {
	Root string
	Real recall.Exec
}

// Run implements recall.Exec.
func (r Recorder) Run(ctx context.Context, bin string, args []string, dir string, env []string) ([]byte, []byte, int, error) {
	out, errb, code, err := r.Real.Run(ctx, bin, args, dir, env)
	if err != nil || (len(args) == 1 && strings.Contains(args[0], "version")) {
		return out, errb, code, err
	}
	tool := filepath.Base(bin)
	for _, t := range []string{recall.ToolOpengrep, recall.ToolGosec, recall.ToolBandit} {
		if strings.Contains(tool, t) {
			tool = t
		}
	}
	report := out
	for i, a := range args {
		if p, ok := strings.CutPrefix(a, "-out="); ok {
			report, _ = os.ReadFile(p)
		}
		if a == "-o" && i+1 < len(args) {
			report, _ = os.ReadFile(args[i+1])
		}
	}
	report = bytes.ReplaceAll(report, []byte(r.Root), []byte(RootToken))
	if werr := os.WriteFile(filepath.Join(Dir(), tool+".json"), report, 0o644); werr != nil {
		return out, errb, code, werr
	}
	return out, errb, code, err
}
