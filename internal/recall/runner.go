// This file is the subprocess boundary every recall tool crosses.
//
// SUBPROCESS ONLY. opengrep is an OCaml CLI with no bindings in any language,
// so a process is the only way to run it, and it keeps the LGPL-2.1 engine at
// arm's length: Anvil links none of it. gosec and bandit run the same way, so
// all three share one boundary and one error vocabulary.
//
// A MISSING TOOL IS NEVER A CLEAN SCAN. Every run ends in exactly one of:
//
//	the tool is absent              *ToolAbsentError (ExitCodeArtefactAbsent)
//	the tool ran and failed         *ToolFailedError, with its exit code and stderr
//	the tool ran and matched nothing  a nil error and no findings, plus the
//	                                  files it says it scanned
//
// and the last is only ever reached when the tool wrote a report this package
// could parse. Silence is not a report: gosec with -quiet writes nothing at all
// for a package without findings (seen 2026-10-03), so this package never
// passes -quiet to gosec, and an absent or empty report is a failure.
//
// THE SCANNED REPOSITORY DOES NOT GET A VOTE. Each tool can be told by the code
// it scans to look away: `nosemgrep` comments for opengrep, `#nosec` for gosec,
// `# nosec` for bandit, a committed .semgrepignore, a .bandit file in a scanned
// directory, and opengrep's built-in default ignores, which skip tests/ and
// more without saying so. A repository under scan is untrusted, so every one is
// switched off: --disable-nosem, -nosec, --ignore-nosec, and explicit file
// targets (a directory target is what consults ignore files and defaults).
// What Lane B does not report is decided by data/rules/selection.json, in
// review, and nowhere else.

package recall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExitCodeArtefactAbsent is the exit status a command wrapping this package
// uses when a recall tool is absent: the same reserved value the Trivy
// collector uses, distinct from success and from a failed scan.
const ExitCodeArtefactAbsent = 2

// ErrToolAbsent and ErrToolFailed are the two failures every runner reports.
var (
	ErrToolAbsent = errors.New("recall: a recall tool is not installed")
	ErrToolFailed = errors.New("recall: a recall tool failed")
)

// ToolAbsentError names the tool and where it was looked for.
type ToolAbsentError struct {
	Tool string
	Path string
	Err  error
}

func (e *ToolAbsentError) Error() string {
	return fmt.Sprintf("recall: %s is not available (looked for %q: %v); install the pinned release named in data/rules/selection.json or set its path under recall: in the operator configuration (exit %d)",
		e.Tool, e.Path, e.Err, ExitCodeArtefactAbsent)
}

// Unwrap lets errors.Is match ErrToolAbsent.
func (e *ToolAbsentError) Unwrap() error { return ErrToolAbsent }

// ExitCode is the exit status a wrapping command uses.
func (e *ToolAbsentError) ExitCode() int { return ExitCodeArtefactAbsent }

// ToolFailedError is a tool that ran and did not produce a usable report.
type ToolFailedError struct {
	Tool     string
	ExitCode int
	Stderr   string
	Reason   string
}

func (e *ToolFailedError) Error() string {
	msg := fmt.Sprintf("recall: %s failed", e.Tool)
	if e.ExitCode != 0 {
		msg += fmt.Sprintf(" with exit code %d", e.ExitCode)
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if s := tail(e.Stderr, 600); s != "" {
		msg += " (stderr: " + s + ")"
	}
	return msg
}

// Unwrap lets errors.Is match ErrToolFailed.
func (e *ToolFailedError) Unwrap() error { return ErrToolFailed }

func tail(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// Exec runs one process. Tests replace it; production uses ProcessExec.
type Exec interface {
	// Run executes bin with args in dir. env, when non-nil, replaces the
	// environment. It returns the exit code (0 on success) and an error only
	// when the process could not be run at all.
	Run(ctx context.Context, bin string, args []string, dir string, env []string) (stdout, stderr []byte, exitCode int, err error)
}

// ProcessExec is the os/exec implementation of Exec.
type ProcessExec struct{}

// Run implements Exec.
func (ProcessExec) Run(ctx context.Context, bin string, args []string, dir string, env []string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.Stdin = &out, &errb, nil
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), errb.Bytes(), -1, ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.Bytes(), errb.Bytes(), ee.ExitCode(), nil
	}
	return out.Bytes(), errb.Bytes(), 0, err
}

// Tools names the binaries. An empty field means the tool's own name, looked
// up on PATH; a value with a path separator is used as given.
type Tools struct {
	Opengrep string
	Gosec    string
	Bandit   string
	// GoBin is the directory holding the `go` command gosec loads packages
	// with. Empty means the `go` on PATH.
	GoBin string
}

func (t Tools) binary(tool string) string {
	switch tool {
	case ToolOpengrep:
		return t.Opengrep
	case ToolGosec:
		return t.Gosec
	case ToolBandit:
		return t.Bandit
	}
	return ""
}

// The three tool names, as data/rules/selection.json pins them.
const (
	ToolOpengrep = "opengrep"
	ToolGosec    = "gosec"
	ToolBandit   = "bandit"
)

// resolve finds a tool's executable or returns a *ToolAbsentError.
func resolve(tool, configured string) (string, error) {
	name := configured
	if name == "" {
		name = tool
	}
	if strings.ContainsRune(name, filepath.Separator) {
		st, err := os.Stat(name)
		if err != nil {
			return "", &ToolAbsentError{Tool: tool, Path: name, Err: err}
		}
		if st.IsDir() || st.Mode().Perm()&0o111 == 0 {
			return "", &ToolAbsentError{Tool: tool, Path: name, Err: errors.New("not an executable file")}
		}
		return name, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", &ToolAbsentError{Tool: tool, Path: name, Err: err}
	}
	return p, nil
}

// checkVersion runs the tool's version command and refuses a release other
// than the pinned one: provenance names a version, and a candidate attributed
// to a version that did not produce it is a false provenance.
func checkVersion(ctx context.Context, x Exec, tool, bin, want string) error {
	var args []string
	switch tool {
	case ToolOpengrep:
		args = []string{"--version"}
	case ToolGosec:
		args = []string{"-version"}
	case ToolBandit:
		args = []string{"--version"}
	}
	out, errb, code, err := x.Run(ctx, bin, args, "", nil)
	if err != nil {
		return &ToolAbsentError{Tool: tool, Path: bin, Err: err}
	}
	if code != 0 {
		return &ToolFailedError{Tool: tool, ExitCode: code, Stderr: string(errb), Reason: "its version command failed"}
	}
	got := versionOf(tool, string(out)+string(errb))
	if got != want {
		return &ToolFailedError{Tool: tool, Reason: fmt.Sprintf("version %q is not the pinned %q", got, want)}
	}
	return nil
}

// versionOf reads the version each tool prints: opengrep "1.26.0", gosec
// "Version: 2.29.0" (among other lines), bandit "bandit 1.9.4" (among others).
func versionOf(tool, out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case tool == ToolOpengrep && len(f) == 1:
			return strings.TrimPrefix(f[0], "v")
		case tool == ToolGosec && len(f) == 2 && f[0] == "Version:":
			return strings.TrimPrefix(f[1], "v")
		case tool == ToolBandit && len(f) >= 2 && f[0] == "bandit":
			return f[1]
		}
	}
	return ""
}
