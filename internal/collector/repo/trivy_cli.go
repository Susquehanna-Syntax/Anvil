// This file is the PROCESS BOUNDARY of the repo SCA collector: everything
// that decides which binary runs, with which argument vector, under which
// environment, and how its absence or failure is reported. The parsing side
// lives in trivy.go and never touches os/exec.
//
// The split is not cosmetic. plan/00-SPINE.md S12 records that Trivy "exposes
// no REST/RPC API and its maintainers direct users to 'use Trivy's code
// directly', with no `pkg/` API stability contract", and rules that native
// linking is vendor-pin-and-monitor with a CLI fallback that must keep
// existing. The Runner interface below is that boundary drawn in Go: a future
// native path implements Runner and the CLI implementation stays compiled in
// as the fallback. plan/20-lane-a-ingestion-sca.md exit criterion 15 — "no
// direct dependency on Trivy `pkg/` internals without a CLI fallback
// annotated in code" — is the criterion this file exists to satisfy, and
// trivy_test.go's TestNoTrivyLibraryImport enforces it by reading this
// package's own source.

package repo

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

// ---------------------------------------------------------------------------
// The binary, and what its absence means
// ---------------------------------------------------------------------------

// BinaryName is the executable this collector shells out to. It is not a
// config key: a collector that would run "whatever binary the operator
// named" is a collector whose read-only and no-network guarantees mean
// nothing. Config.Binary may only point at a DIFFERENT PATH to this same
// program (a pinned release under /opt, a test double), never at a different
// program by name.
const BinaryName = "trivy"

// ExitCodeArtefactAbsent is the process exit code a command wrapping this
// package MUST use when the Trivy binary (or its vulnerability database) is
// not present, distinct from both success and "the scan failed".
//
// Reserved to match M0.7's opengrep acquisition path, which fixed the same
// hazard for the recall tier: eval/tools/opengrep/smoke.py documents
// "2  the engine or the ruleset is not present  <-- loud, not a 'clean scan'".
// The reason is narrow and specific and it is the whole design constraint of
// this package: an SCA collector that returns zero findings because its tool
// is missing is byte-for-byte indistinguishable from a clean repository, and
// for a security scanner that is the worst failure available. Nothing here
// degrades to an empty result. See also ScanResult.AssertNotSilentlyEmpty,
// which enforces the same rule one layer up, on the data.
const ExitCodeArtefactAbsent = 2

// InstallHint is printed inside every binary-absent error. It names the
// artefact and how to obtain it, because "trivy: executable file not found in
// $PATH" tells an operator nothing they can act on at 3am.
//
// It carries no version literal on purpose; see Config.RequiredVersion for
// where the pinned release tag belongs and why this file does not hard-code
// one.
const InstallHint = "install the pinned Trivy release from " +
	"https://github.com/aquasecurity/trivy/releases (Apache-2.0), put it on PATH, " +
	"or set Config.Binary to its absolute path"

// Sentinel errors. Every failure in this package is one of these, wrapped
// with the detail that makes it actionable. There is no path that returns a
// nil error and an empty ScanResult because something was missing.
var (
	// ErrBinaryMissing: the Trivy executable could not be resolved or is not
	// executable. Always carries *BinaryMissingError.
	ErrBinaryMissing = errors.New("repo: trivy binary is not available")

	// ErrTrivyFailed: Trivy ran and exited non-zero, or could not be run to
	// completion (timeout, killed). Trivy's own stderr is attached.
	ErrTrivyFailed = errors.New("repo: trivy invocation failed")

	// ErrBadConfig: the collector configuration is not admissible. Rejected
	// before any process is started, so a bad config can never become a
	// half-run scan.
	ErrBadConfig = errors.New("repo: invalid collector configuration")

	// ErrDBUpdateUnrouted: a vulnerability-database update was requested
	// without naming the repository to pull it from. plan/20's A.10
	// Forbidden actions: "Do not invoke Trivy in any mode that fetches its DB
	// from a redistributable-unclear mirror without going through A.11's
	// consume-only accelerator."
	ErrDBUpdateUnrouted = errors.New("repo: trivy DB update requested without a configured DB repository")

	// ErrVersionMismatch: the resolved binary is not the pinned release.
	ErrVersionMismatch = errors.New("repo: trivy version does not match the configured pin")
)

// BinaryMissingError is the typed absence. It names the binary, the path that
// was searched, and how to fix it, and it reports ExitCodeArtefactAbsent so a
// command wrapper does not have to re-derive the exit code from the error
// string.
type BinaryMissingError struct {
	// Name is the program that is missing, always BinaryName.
	Name string
	// Path is what the caller asked for: an absolute path when Config.Binary
	// named one, otherwise the bare program name that was searched on PATH.
	Path string
	// Err is the underlying exec.LookPath / os.Stat failure.
	Err error
}

func (e *BinaryMissingError) Error() string {
	where := "on PATH"
	if filepath.IsAbs(e.Path) || strings.ContainsAny(e.Path, `/\`) {
		where = "at " + e.Path
	}
	return fmt.Sprintf(
		"repo: the %s binary was not found %s (%v). This is NOT a clean repository: "+
			"no scan ran, so no result — empty or otherwise — was produced. To fix: %s. "+
			"A wrapping command must exit %d for this condition.",
		e.Name, where, e.Err, InstallHint, ExitCodeArtefactAbsent)
}

func (e *BinaryMissingError) Unwrap() error { return ErrBinaryMissing }

// ExitCode reports the process exit code a wrapping command must use for this
// condition.
func (e *BinaryMissingError) ExitCode() int { return ExitCodeArtefactAbsent }

// RunError is a Trivy invocation that started but did not produce a usable
// report. Trivy's stderr is carried all the way out, flattened to one line so
// it stays greppable in a journal — the same rule internal/policy applies to
// git's stderr.
type RunError struct {
	Args     []string
	ExitCode int
	Stderr   string
	Err      error
}

func (e *RunError) Error() string {
	msg := fmt.Sprintf("repo: `%s %s` failed", BinaryName, strings.Join(e.Args, " "))
	if e.ExitCode != 0 {
		msg += fmt.Sprintf(" with exit code %d", e.ExitCode)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if e.Stderr != "" {
		msg += ": " + oneLine(e.Stderr)
	}
	return msg
}

func (e *RunError) Unwrap() error { return ErrTrivyFailed }

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// ---------------------------------------------------------------------------
// Subcommand and flag allowlists
//
// These are CONSTANT LISTS, not runtime checks, so that trivy_test.go can
// assert against the compiled-in vocabulary the way A.9's packet requires for
// the host collector ("grep the constant list, not a runtime check"). A
// runtime check only proves what the test happened to exercise; a list the
// test reads directly proves what the binary can ever emit.
// ---------------------------------------------------------------------------

// SubcommandFilesystem is the only Trivy subcommand this collector invokes:
// `trivy fs <path>` scans a directory tree that is already on disk.
const SubcommandFilesystem = "fs"

// AllowedSubcommands is the complete set of Trivy subcommands reachable from
// this package. One entry, and it stays one entry.
func AllowedSubcommands() []string { return []string{SubcommandFilesystem} }

// MutatingSubcommands are Trivy subcommands that change state outside the
// scan: they delete caches, install plugins or modules, or write registry
// credentials. plan/00-SPINE.md S7's "the host agent is read-only — no
// package manager in a mutating mode, not behind a flag" is stated about the
// host collector; the same rule is applied here because `trivy clean` and
// `trivy plugin install` are exactly the shape it forbids.
func MutatingSubcommands() []string {
	return []string{
		"clean",    // deletes cached DBs and scan caches
		"plugin",   // install/uninstall/update executable plugins
		"module",   // install/uninstall WASM modules
		"registry", // login/logout: writes credential material to disk
	}
}

// NetworkSubcommands are Trivy subcommands that reach the network for the
// SUBJECT of the scan rather than for its database — they clone a remote git
// repository, pull an image, or query a live cluster. `repo` is in this list
// and that is deliberate: A.10's objective is "fs/repo mode" over a
// repository ALREADY ON DISK, and `trivy repo <url>` would fetch attacker-
// influenced content over the network from inside a collector that has no
// egress policy of its own.
func NetworkSubcommands() []string {
	return []string{"repo", "image", "vm", "kubernetes", "aws", "server"}
}

// ForbiddenFlags are Trivy flags this package must never emit.
//
//   - --exit-code makes Trivy exit non-zero when it FINDS something, which
//     would make "vulnerabilities exist" indistinguishable from "the tool
//     broke" at the process level. Never passed; findings are read from the
//     report, not from the exit status.
//   - --reset and --clear-cache delete cached data (mutating).
//   - --download-db-only and --download-java-db-only turn a scan into a
//     fetch, bypassing the A.11 routing rule below.
//   - --server points the scan at a remote Trivy daemon, moving the trust
//     boundary somewhere this package cannot reason about.
func ForbiddenFlags() []string {
	return []string{
		"--exit-code", "--reset", "--clear-cache",
		"--download-db-only", "--download-java-db-only", "--server",
	}
}

// ScannersVuln is the only scanner this collector enables, and it is not a
// config key.
//
//   - `secret` would write credential material discovered in the repository
//     into this package's output, which internal/record/SECRETS.md exists to
//     prevent.
//   - `misconfig` and `license` are other steps' territory, not Lane A SCA.
//
// A safety boundary is not a tuning knob, so this one is compiled in.
// --detection-priority, which IS a tuning knob, is a config passthrough — see
// Config.DetectionPriority.
const ScannersVuln = "vuln"

// ---------------------------------------------------------------------------
// The Runner seam — where a native path would attach
// ---------------------------------------------------------------------------

// Runner executes one Trivy invocation and returns its stdout.
//
// THIS IS THE FALLBACK SEAM plan/00-SPINE.md S12 requires. If Trivy's `pkg/`
// packages are ever linked natively, that path implements Runner and this
// file's CLIRunner remains compiled in and reachable by configuration — it is
// never deleted, because S12's finding is that Trivy publishes no `pkg/` API
// stability contract, so the native path can break on any upstream release
// and the CLI path is what the collector falls back to. A native
// implementation must live behind this interface and must not be the sole
// path (plan/20 A.10 Forbidden actions; exit criterion 15).
//
// Implementations must not retry, must not swallow a non-zero exit, and must
// not return a nil error alongside empty stdout.
type Runner interface {
	// Run executes the given argument vector and returns stdout. dir, when
	// non-empty, is the working directory. Implementations return a
	// *RunError for any non-zero exit and a *BinaryMissingError when the
	// artefact is absent.
	Run(ctx context.Context, args []string) (stdout []byte, err error)
}

// CLIRunner is the subprocess implementation of Runner: the path plan/20 A.10
// takes and the path that must keep working forever.
type CLIRunner struct {
	// Binary is the executable to run. Empty means BinaryName, resolved on
	// PATH.
	Binary string

	// Env, when non-nil, REPLACES the inherited environment. Leave it nil in
	// production: Trivy needs HOME/XDG_CACHE_HOME (or --cache-dir) to find
	// its database, and a hand-built environment that omits them turns a
	// working install into a confusing failure.
	//
	// No credential is read, written or logged by this package. The GitHub
	// token Lane A's poller uses is ops-provisioned and named by
	// internal/ingest/config; nothing here reads it, and neither the argument
	// vector nor the environment is ever echoed into an error or a log line.
	Env []string

	// MaxOutputBytes caps captured stdout. Zero means DefaultMaxOutputBytes.
	// A report larger than the cap is a hard failure, never a truncated parse
	// — half a JSON document parses to zero findings, which is the exact
	// silent-empty outcome this package refuses.
	MaxOutputBytes int
}

// DefaultMaxOutputBytes caps a Trivy JSON report at 256 MiB. A monorepo with
// thousands of manifests produces tens of megabytes; a quarter of a gigabyte
// means something else went wrong.
const DefaultMaxOutputBytes = 256 << 20

// ResolveBinary returns the absolute path of the Trivy executable, or a
// *BinaryMissingError. An empty name means BinaryName on PATH; a name
// containing a path separator is used verbatim and stat'd.
func ResolveBinary(name string) (string, error) {
	if name == "" {
		name = BinaryName
	}
	if strings.ContainsAny(name, `/\`) {
		info, err := os.Stat(name)
		if err != nil {
			return "", &BinaryMissingError{Name: BinaryName, Path: name, Err: err}
		}
		if info.IsDir() {
			return "", &BinaryMissingError{
				Name: BinaryName, Path: name, Err: errors.New("is a directory, not an executable"),
			}
		}
		return name, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", &BinaryMissingError{Name: BinaryName, Path: name, Err: err}
	}
	return path, nil
}

// Run implements Runner over os/exec.
func (r CLIRunner) Run(ctx context.Context, args []string) ([]byte, error) {
	bin, err := ResolveBinary(r.Binary)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	if r.Env != nil {
		cmd.Env = r.Env
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	cmd.Stdin = nil

	runErr := cmd.Run()

	limit := r.MaxOutputBytes
	if limit <= 0 {
		limit = DefaultMaxOutputBytes
	}
	if out.Len() > limit {
		return nil, &RunError{
			Args:   args,
			Stderr: errBuf.String(),
			Err: fmt.Errorf("report is %d bytes, over the %d-byte cap; refusing to parse a truncated report",
				out.Len(), limit),
		}
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, &RunError{Args: args, Stderr: errBuf.String(), Err: ctxErr}
	}
	if runErr != nil {
		re := &RunError{Args: args, Stderr: errBuf.String(), Err: runErr}
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			re.ExitCode = ee.ExitCode()
			re.Err = nil // the exit code IS the diagnosis; stderr carries the rest
		}
		return nil, re
	}
	if out.Len() == 0 {
		return nil, &RunError{
			Args:   args,
			Stderr: errBuf.String(),
			Err:    errors.New("exited 0 but wrote no report; an empty report is never read as a clean repository"),
		}
	}
	return out.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Argument construction
// ---------------------------------------------------------------------------

// BuildArgs returns the exact argument vector this collector would pass to
// Trivy for the given configuration and path, or ErrBadConfig.
//
// Exported because it is the thing worth testing: the safety properties of
// this collector are properties of this slice, and a test that has to run a
// process to see them is a test that cannot run where Trivy is absent.
func BuildArgs(c Config, path string) ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: scan path must not be empty", ErrBadConfig)
	}
	if strings.HasPrefix(path, "-") {
		// A path that begins with '-' would be parsed as a flag. Refuse
		// rather than paper over it with "--", because a repository path
		// starting with a dash is a sign the caller is passing something
		// that is not a path.
		return nil, fmt.Errorf("%w: scan path %q begins with '-' and would be read as a flag", ErrBadConfig, path)
	}

	args := []string{
		SubcommandFilesystem,
		"--format", "json",
		"--quiet",
		// --scanners vuln: see ScannersVuln for why this is not a config key.
		"--scanners", ScannersVuln,
		// --list-all-pkgs is what makes "clean" provable. Without it Trivy
		// omits a target entirely when it has no vulnerabilities, so an empty
		// Results array means either "every manifest is clean" or "no
		// manifest was found" and nothing distinguishes them. With it, every
		// detected target appears with its package list, and Coverage can
		// report how much was actually scanned. See Coverage.ScannedNothing.
		"--list-all-pkgs",
	}

	if c.SkipDBUpdate {
		args = append(args, "--skip-db-update", "--skip-java-db-update")
	}
	if c.OfflineScan {
		args = append(args, "--offline-scan")
	}
	if c.CacheDir != "" {
		args = append(args, "--cache-dir", c.CacheDir)
	}
	if c.DBRepository != "" {
		args = append(args, "--db-repository", c.DBRepository)
	}
	if c.DetectionPriority != DetectionPriorityUnset {
		args = append(args, "--detection-priority", string(c.DetectionPriority))
	}

	return append(args, path), nil
}

// versionArgs is the argument vector for the pin check.
func versionArgs() []string { return []string{"--version", "--format", "json"} }

// ---------------------------------------------------------------------------
// Version pin
// ---------------------------------------------------------------------------

// DefaultVersionTimeout bounds `trivy --version`. It does no I/O beyond
// reading its own build info.
const DefaultVersionTimeout = 30 * time.Second

// Version returns the version string the resolved binary reports.
//
// Trivy prints JSON when asked to (`--version --format json`), and a plain
// "Version: x.y.z" block otherwise; both are handled, because the flag
// combination is not guaranteed across the release range a pin might name.
func Version(ctx context.Context, runner Runner) (string, error) {
	out, err := runner.Run(ctx, versionArgs())
	if err != nil {
		return "", err
	}
	return parseVersion(out)
}

// parseVersion extracts the version from either output shape without pulling
// in a JSON model for two fields.
func parseVersion(out []byte) (string, error) {
	s := string(out)
	if i := strings.Index(s, `"Version"`); i >= 0 {
		rest := s[i+len(`"Version"`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			rest = rest[j+1:]
			if k := strings.Index(rest, `"`); k >= 0 {
				if v := strings.TrimSpace(rest[:k]); v != "" {
					return v, nil
				}
			}
		}
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "Version:"); ok {
			if v = strings.TrimSpace(v); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("%w: could not read a version from %q", ErrTrivyFailed, oneLine(s))
}

// checkVersionPin compares the resolved binary against Config.RequiredVersion
// and returns ErrVersionMismatch when they differ. A leading "v" on either
// side is ignored; nothing else is.
func checkVersionPin(ctx context.Context, runner Runner, required string) (string, error) {
	got, err := Version(ctx, runner)
	if err != nil {
		return "", err
	}
	if normalizeVersion(got) != normalizeVersion(required) {
		return got, fmt.Errorf(
			"%w: binary reports %q, configuration pins %q. plan/20-lane-a-ingestion-sca.md pins the "+
				"exact Trivy release tag used by internal/collector/repo; an unpinned scanner makes a "+
				"regression diff between two runs unattributable",
			ErrVersionMismatch, got, required)
	}
	return got, nil
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}
