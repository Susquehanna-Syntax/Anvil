package remediation

// Running the target's own build and tests (plan node ladder). The commands
// are the operator's, from configuration, never read from the repository; but
// what they run is the repository's code, so they run in bubblewrap with an
// ALLOWLISTED file system and no network:
//
//   - read-only: /usr (and /bin, /lib, /lib64, /sbin as the host lays them
//     out), /etc, and any directory the operator lists (a toolchain under a
//     home directory, say), minus the directories Hide names;
//   - read-write: one directory, an export of the patched tree with no .git;
//   - fresh: /tmp, /proc, /dev; new user, pid, ipc, uts, cgroup and network
//     namespaces, so only a loopback interface exists.
//
// Nothing else is visible: not the operator's home, not the store, not the
// controller's clone and its .git, not the scanned checkout. The environment
// is cleared and rebuilt from a fixed list plus the operator's additions, with
// credential-shaped names refused. Where the kernel refuses unprivileged
// namespaces, or bubblewrap is absent, the build is refused, never run
// unconfined: Sandbox.Run reports ErrNoSandbox and the rung fails closed.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoSandbox means this host cannot run a command confined.
var ErrNoSandbox = errors.New("remediation: no build sandbox on this host (bubblewrap is absent, or unprivileged user namespaces are refused); the build is not run")

// Sandbox runs commands confined to one directory, with no network.
type Sandbox struct {
	// Bwrap is the bubblewrap executable; empty means "bwrap" on PATH.
	Bwrap   string
	Timeout time.Duration
	// Env is added to the command's minimal environment; credential-shaped
	// names are refused (CheckEnv).
	Env []string
	// ReadOnly are extra directories visible read-only (a toolchain).
	ReadOnly []string
	// Hide are directories inside the visible tree replaced by an empty tmpfs
	// (where an operator keeps a secret under /etc, say).
	Hide []string
}

// SandboxResult is one command's outcome.
type SandboxResult struct {
	Exit    int
	Tail    string // the last 2 KiB of combined output
	Elapsed time.Duration
}

func (s Sandbox) bwrap() string {
	if s.Bwrap != "" {
		return s.Bwrap
	}
	return "bwrap"
}

// args is the bubblewrap command line for argv confined to dir.
func (s Sandbox) args(dir string, env, argv []string) []string {
	a := []string{"--unshare-all", "--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr"}
	for _, d := range []string{"/bin", "/lib", "/lib64", "/sbin", "/lib32", "/libx32"} {
		if target, err := os.Readlink(d); err == nil {
			a = append(a, "--symlink", target, d)
		} else if st, err := os.Stat(d); err == nil && st.IsDir() {
			a = append(a, "--ro-bind", d, d)
		}
	}
	// Order matters: a later mount covers an earlier one. The fresh /tmp comes
	// before the extra read-only directories (a toolchain may live under it),
	// the hidden directories after them, and the writable directory last.
	a = append(a, "--ro-bind", "/etc", "/etc", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp")
	for _, d := range s.ReadOnly {
		a = append(a, "--ro-bind", d, d)
	}
	for _, d := range s.Hide {
		a = append(a, "--tmpfs", d)
	}
	a = append(a, "--bind", dir, dir, "--chdir", dir, "--clearenv")
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		a = append(a, "--setenv", k, v)
	}
	return append(append(a, "--"), argv...)
}

// Available reports whether this host can run a command confined.
func (s Sandbox) Available(ctx context.Context) bool {
	dir, err := os.MkdirTemp("", "anvil-sandbox-probe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	return exec.CommandContext(ctx, s.bwrap(), s.args(dir, nil, []string{"true"})...).Run() == nil
}

// credentialShaped matches environment names that commonly carry a secret.
var credentialShaped = []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY",
	"ACCESS_KEY", "PRIVATE_KEY", "AUTH", "SESSION", "COOKIE", "GITHUB_", "GH_", "AWS_", "AZURE_", "GOOGLE_",
	"SSH_AUTH_SOCK", "NETRC", "DOCKER_CONFIG", "KUBECONFIG", "ASKPASS"}

// CheckEnv refuses a credential-shaped name in an environment list.
func CheckEnv(env []string) error {
	for _, kv := range env {
		name := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		for _, c := range credentialShaped {
			if strings.Contains(name, c) {
				return fmt.Errorf("remediation: %s is credential-shaped and may not reach a sandboxed command", name)
			}
		}
	}
	return nil
}

// Run runs argv confined to dir, which must be an absolute directory.
func (s Sandbox) Run(ctx context.Context, dir string, argv []string) (SandboxResult, error) {
	if len(argv) == 0 {
		return SandboxResult{}, errors.New("remediation: empty command")
	}
	if !filepath.IsAbs(dir) {
		return SandboxResult{}, fmt.Errorf("remediation: the sandbox directory %q is not absolute", dir)
	}
	if err := CheckEnv(s.Env); err != nil {
		return SandboxResult{}, err
	}
	if !s.Available(ctx) {
		return SandboxResult{}, ErrNoSandbox
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	env := append([]string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "TMPDIR=/tmp", "LANG=C",
		"GOTOOLCHAIN=local", "GOPROXY=off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"PIP_NO_INDEX=1", "npm_config_offline=true"}, s.Env...)
	cmd := exec.CommandContext(ctx, s.bwrap(), s.args(dir, env, argv)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	res := SandboxResult{Elapsed: time.Since(start), Tail: tail(out.String(), 2048)}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.Exit = exitErr.ExitCode()
		if ctx.Err() != nil {
			res.Exit = 124
			res.Tail = fmt.Sprintf("timed out after %s\n%s", timeout, res.Tail)
		}
	default:
		return res, err
	}
	return res, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
