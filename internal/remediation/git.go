package remediation

// Git, run against a checkout of an untrusted repository. Every invocation
// goes through Git.run: hooks off, fsmonitor off, no system or global
// configuration, no terminal prompt, no credential helper, and an environment
// that names nothing of the operator's. The model never touches the
// repository; this file is the only thing that does.
//
// The clone's .git is never shown to the target's code. The build, the tests,
// the rescan and the oracle each get a fresh export of a tree (Export: files
// only, written through a temporary index), so nothing the repository runs
// can plant a filter, a worktree or a push URL in the configuration the
// controller's own git calls read.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Trailer keys every Anvil commit carries (plan node commit).
const (
	TrailerFinding = "Anvil-Finding"
	TrailerAudit   = "Anvil-Audit"
	TrailerKey     = "Anvil-Idempotency-Key"
)

// Git runs git in one working directory.
type Git struct {
	Dir string
	// Bin is the git executable; empty means "git" on PATH.
	Bin string
	// index, when set, is a temporary GIT_INDEX_FILE (Export).
	index string
}

// gitSafety are the -c settings on every call. A repository's own files can
// name hooks, filters and helpers only through configuration, and none of
// that configuration is read: these override the clone's local config, and
// the system and global files are switched off by the environment.
var gitSafety = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.fsmonitor=false",
	"-c", "core.sshCommand=false",
	"-c", "credential.helper=",
	"-c", "protocol.allow=never",
	"-c", "protocol.file.allow=always",
	"-c", "diff.external=",
	"-c", "core.worktree=",
	"-c", "core.quotePath=true",
	"-c", "user.name=Anvil",
	"-c", "user.email=anvil@anvil.invalid",
	"-c", "commit.gpgSign=false",
	"-c", "advice.detachedHead=false",
}

func gitEnv() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/nonexistent",
		"LANG=C", "LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
		"GIT_AUTHOR_DATE=", "GIT_COMMITTER_DATE=",
	}
}

func (g Git) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "git"
}

func (g Git) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	full := append(append([]string{}, gitSafety...), args...)
	cmd := exec.CommandContext(ctx, g.bin(), full...)
	cmd.Dir = g.Dir
	cmd.Env = gitEnv()
	if g.index != "" {
		cmd.Env = append(cmd.Env, "GIT_INDEX_FILE="+g.index)
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// Prepare makes dir a clone of src checked out, detached, at base. An existing
// clone is reused: it is reset and cleaned, never trusted as it stands.
func Prepare(ctx context.Context, bin, src, dir, base string) (Git, error) {
	if !shaRE.MatchString(base) {
		return Git{}, fmt.Errorf("remediation: base commit %q is not a full object id", base)
	}
	g := Git{Dir: dir, Bin: bin}
	if _, err := os.Stat(filepath.Join(dir, ".git")); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return Git{}, err
		}
		parent := Git{Dir: filepath.Dir(dir), Bin: bin}
		if _, err := parent.run(ctx, nil, "clone", "-q", "--no-checkout", "--no-hardlinks", "--", src, dir); err != nil {
			return Git{}, err
		}
	}
	if _, err := g.run(ctx, nil, "cat-file", "-e", base+"^{commit}"); err != nil {
		if _, ferr := g.run(ctx, nil, "fetch", "-q", "--", src, base); ferr != nil {
			return Git{}, fmt.Errorf("remediation: the base commit %s is not in %s: %w", base, src, ferr)
		}
	}
	for _, args := range [][]string{
		{"reset", "-q", "--hard"},
		{"checkout", "-q", "--detach", "--force", base},
		{"clean", "-qfdx"},
	} {
		if _, err := g.run(ctx, nil, args...); err != nil && args[0] != "reset" {
			return Git{}, err
		}
	}
	return g, nil
}

// Head is the checked-out commit.
func (g Git) Head(ctx context.Context) (string, error) {
	out, err := g.run(ctx, nil, "rev-parse", "--verify", "HEAD^{commit}")
	return strings.TrimSpace(string(out)), err
}

// SafePath refuses a repository path git would quote or a diff header could
// misread: anything but printable ASCII, a quote, a backslash, a leading dash,
// or a dot segment. Such a path is never patched.
func SafePath(p string) error {
	if p == "" || strings.HasPrefix(p, "-") || strings.HasPrefix(p, "/") {
		return fmt.Errorf("remediation: path %q is not a plain repository path", p)
	}
	for _, r := range p {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return fmt.Errorf("remediation: path %q holds a character git would quote; it is not patched", p)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("remediation: path %q has an empty or dot segment", p)
		}
	}
	return nil
}

// Blob reads path at commit and returns its content, blob id and mode.
func (g Git) Blob(ctx context.Context, commit, path string) (content, blob, mode string, err error) {
	if err := SafePath(path); err != nil {
		return "", "", "", err
	}
	out, err := g.run(ctx, nil, "ls-tree", "--full-tree", "-z", commit, "--", path)
	if err != nil {
		return "", "", "", err
	}
	entry := strings.TrimSuffix(string(out), "\x00")
	meta, name, ok := strings.Cut(entry, "\t")
	f := strings.Fields(meta)
	if !ok || name != path || len(f) != 3 || f[1] != "blob" {
		return "", "", "", fmt.Errorf("remediation: %q is not a file at %s", path, commit)
	}
	if f[0] != "100644" && f[0] != "100755" {
		return "", "", "", fmt.Errorf("remediation: %q has mode %s; only regular files are edited", path, f[0])
	}
	raw, err := g.run(ctx, nil, "cat-file", "blob", f[2])
	return string(raw), f[2], f[0], err
}

// Diff synthesises a unified diff from path's blob at the scanned commit to
// next, carrying both blob ids, so git apply --3way can place it against the
// exact scanned blob or fail.
func (g Git) Diff(ctx context.Context, path, oldBlob, mode, next string) (string, error) {
	if err := SafePath(path); err != nil {
		return "", err
	}
	newOut, err := g.run(ctx, []byte(next), "hash-object", "-w", "--stdin")
	if err != nil {
		return "", err
	}
	newBlob := strings.TrimSpace(string(newOut))
	raw, err := g.run(ctx, nil, "diff", "--full-index", "--no-color", "--no-ext-diff", "--no-textconv", oldBlob, newBlob)
	if err != nil {
		return "", err
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[1], "index ") {
		return "", fmt.Errorf("remediation: unexpected diff header for %s", path)
	}
	lines[0] = fmt.Sprintf("diff --git a/%s b/%s\n", path, path)
	lines[1] = fmt.Sprintf("index %s..%s %s\n", oldBlob, newBlob, mode)
	lines[2] = "--- a/" + path + "\n"
	lines[3] = "+++ b/" + path + "\n"
	return strings.Join(lines, ""), nil
}

// Apply checks then applies a patch with a three-way merge into the index.
// Partial application is never asked for: either every hunk lands or the
// tree is left as it was.
func (g Git) Apply(ctx context.Context, patch string) error {
	if _, err := g.run(ctx, []byte(patch), "apply", "--check", "--3way", "--index", "-"); err != nil {
		return err
	}
	if _, err := g.run(ctx, []byte(patch), "apply", "--3way", "--index", "-"); err != nil {
		_ = g.Rollback(ctx)
		return err
	}
	return nil
}

// StagedPaths lists the paths whose staged content differs from rev.
func (g Git) StagedPaths(ctx context.Context, rev string) ([]string, error) {
	out, err := g.run(ctx, nil, "diff", "--cached", "--name-only", "--no-renames", "-z", rev)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// WriteTree records the index as a tree and returns its id.
func (g Git) WriteTree(ctx context.Context) (string, error) {
	out, err := g.run(ctx, nil, "write-tree")
	return strings.TrimSpace(string(out)), err
}

// Export writes treeish's files into dir, which must not exist yet: no .git,
// nothing but the tree. It goes through a temporary index so the clone's own
// index and working tree are untouched, and checkout-index refuses to write
// through a symbolic link the tree itself contains.
func (g Git) Export(ctx context.Context, treeish, dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("remediation: export directory %s already exists", dir)
	}
	idx, err := os.CreateTemp("", "anvil-export-index-")
	if err != nil {
		return err
	}
	_ = idx.Close()
	_ = os.Remove(idx.Name())
	defer os.Remove(idx.Name())
	tg := g
	tg.index = idx.Name()
	if _, err := tg.run(ctx, nil, "read-tree", treeish); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_, err = tg.run(ctx, nil, "checkout-index", "-a", "-f", "--prefix="+strings.TrimSuffix(dir, "/")+"/")
	return err
}

// BranchesContaining lists the Anvil fix branches that contain sha.
func (g Git) BranchesContaining(ctx context.Context, sha string) ([]string, error) {
	out, err := g.run(ctx, nil, "branch", "--list", "anvil/fix/*", "--contains", sha, "--format=%(refname:short)")
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// Rollback discards every change in the working tree and index.
func (g Git) Rollback(ctx context.Context) error {
	if _, err := g.run(ctx, nil, "reset", "-q", "--hard"); err != nil {
		return err
	}
	_, err := g.run(ctx, nil, "clean", "-qfdx")
	return err
}

// Trailers is the trailer block of one Anvil commit.
type Trailers struct {
	Audit    string
	Findings []string // fingerprints, in group order
	Keys     []string // the handoff idempotency key of each finding, same order
}

// Commit records the staged change on branch, created at base if absent, with
// the trailers, and returns the commit id.
func (g Git) Commit(ctx context.Context, branch, base, subject string, tr Trailers) (string, error) {
	tree, err := g.WriteTree(ctx)
	if err != nil {
		return "", err
	}
	return g.CommitTree(ctx, tree, branch, base, subject, tr)
}

// CommitTree records exactly tree on branch, created at base if absent, with
// the trailers, and returns the commit id. The controller commits the tree id
// its ladder judged, never whatever the index holds by then.
func (g Git) CommitTree(ctx context.Context, tree, branch, base, subject string, tr Trailers) (string, error) {
	if len(tr.Findings) == 0 || len(tr.Findings) != len(tr.Keys) || tr.Audit == "" {
		return "", errors.New("remediation: a commit needs an audit and one key per finding")
	}
	var msg strings.Builder
	msg.WriteString(subject + "\n\nProposed by Anvil. Not verified unless the pull request says so.\n\n")
	fmt.Fprintf(&msg, "%s: %s\n", TrailerAudit, tr.Audit)
	for i := range tr.Findings {
		fmt.Fprintf(&msg, "%s: %s\n%s: %s\n", TrailerFinding, tr.Findings[i], TrailerKey, tr.Keys[i])
	}
	if !shaRE.MatchString(tree) {
		return "", fmt.Errorf("remediation: %q is not a tree id", tree)
	}
	parent := base
	if out, err := g.run(ctx, nil, "rev-parse", "--verify", "-q", "refs/heads/"+branch); err == nil {
		parent = strings.TrimSpace(string(out))
	}
	out, err := g.run(ctx, []byte(msg.String()), "commit-tree", tree, "-p", parent)
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(string(out))
	if _, err := g.run(ctx, nil, "update-ref", "refs/heads/"+branch, sha); err != nil {
		return "", err
	}
	return sha, nil
}

// CommitWithKey finds an Anvil commit on any anvil/fix/ branch whose trailers
// carry key. It is how a crash between commit and disposition is recovered.
func (g Git) CommitWithKey(ctx context.Context, key string) (string, bool, error) {
	out, err := g.run(ctx, nil, "log", "--branches=anvil/fix/*", "--format=%H%x00%(trailers:key="+TrailerKey+",valueonly,separator=%x01)%x02")
	if err != nil {
		return "", false, err
	}
	for _, rec := range strings.Split(string(out), "\x02") {
		sha, vals, ok := strings.Cut(strings.TrimSpace(rec), "\x00")
		if !ok {
			continue
		}
		for _, v := range strings.Split(vals, "\x01") {
			if strings.TrimSpace(v) == key {
				return sha, true, nil
			}
		}
	}
	return "", false, nil
}

// TrailersOf reads an Anvil commit's trailers.
func (g Git) TrailersOf(ctx context.Context, sha string) (Trailers, error) {
	out, err := g.run(ctx, nil, "log", "-1", "--format=%(trailers:only,unfold)", sha)
	if err != nil {
		return Trailers{}, err
	}
	var tr Trailers
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch k {
		case TrailerAudit:
			tr.Audit = v
		case TrailerFinding:
			tr.Findings = append(tr.Findings, v)
		case TrailerKey:
			tr.Keys = append(tr.Keys, v)
		}
	}
	return tr, nil
}

// ChangedPaths lists the paths a commit changed against its first parent.
func (g Git) ChangedPaths(ctx context.Context, sha string) ([]string, error) {
	out, err := g.run(ctx, nil, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", sha+"^", sha)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// Checkout moves the working tree to rev, discarding anything uncommitted.
func (g Git) Checkout(ctx context.Context, rev string) error {
	_, err := g.run(ctx, nil, "checkout", "-q", "--detach", "--force", rev)
	if err == nil {
		_, err = g.run(ctx, nil, "clean", "-qfdx")
	}
	return err
}
