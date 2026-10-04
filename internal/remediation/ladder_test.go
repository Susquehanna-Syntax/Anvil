package remediation

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo makes a repository with the given files committed and returns its
// directory and the commit.
func gitRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g := Git{Dir: dir}
	ctx := context.Background()
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "-A"}, {"commit", "-q", "-m", "base"}} {
		if _, err := g.run(ctx, nil, args...); err != nil {
			t.Fatal(err)
		}
	}
	head, err := g.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return dir, head
}

// TestTheDiffCarriesTheScannedBlob: the synthesised diff names the scanned
// blob and applies with --3way into the index; the same diff refuses a tree
// whose blob changed underneath it, and leaves that tree as it was.
func TestTheDiffCarriesTheScannedBlob(t *testing.T) {
	ctx := context.Background()
	src, base := gitRepo(t, map[string]string{"src/a.c": "int x;\nstrcpy(b, s);\nint y;\n", "run.sh": "#!/bin/sh\n"})
	g, err := Prepare(ctx, "", src, filepath.Join(t.TempDir(), "work"), base)
	if err != nil {
		t.Fatal(err)
	}
	content, blob, mode, err := g.Blob(ctx, base, "src/a.c")
	if err != nil || mode != "100644" {
		t.Fatalf("%v %s", err, mode)
	}
	next := strings.Replace(content, "strcpy(b, s);", "strlcpy(b, s, sizeof b);", 1)
	d, err := g.Diff(ctx, "src/a.c", blob, mode, next)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, "index "+blob+"..") || !strings.HasPrefix(d, "diff --git a/src/a.c b/src/a.c\n") {
		t.Fatalf("the diff does not carry the scanned blob:\n%s", d)
	}
	if err := g.Apply(ctx, d); err != nil {
		t.Fatal(err)
	}
	staged, err := g.run(ctx, nil, "diff", "--cached", "--name-only")
	if err != nil || strings.TrimSpace(string(staged)) != "src/a.c" {
		t.Fatalf("staged %q %v", staged, err)
	}
	if err := g.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// The tree moves on: the scanned blob is no longer what is checked out.
	if err := os.WriteFile(filepath.Join(g.Dir, "src/a.c"), []byte("int x;\nchanged(b, s);\nint y;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := g.run(ctx, nil, "commit", "-qam", "moved"); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(ctx, d); err == nil {
		t.Fatal("a diff against an old blob applied to a changed one")
	}
	raw, _ := os.ReadFile(filepath.Join(g.Dir, "src/a.c"))
	if string(raw) != "int x;\nchanged(b, s);\nint y;\n" {
		t.Fatalf("a refused apply changed the tree: %q", raw)
	}
}

// TestTrailersFindAnEarlierCommit: a commit records its three trailers, and
// CommitWithKey finds it by any of its keys, which is how a crash between
// commit and disposition is recovered.
func TestTrailersFindAnEarlierCommit(t *testing.T) {
	ctx := context.Background()
	src, base := gitRepo(t, map[string]string{"a.py": "eval(x)\n"})
	g, err := Prepare(ctx, "", src, filepath.Join(t.TempDir(), "work"), base)
	if err != nil {
		t.Fatal(err)
	}
	content, blob, mode, _ := g.Blob(ctx, base, "a.py")
	d, _ := g.Diff(ctx, "a.py", blob, mode, strings.Replace(content, "eval", "ast.literal_eval", 1))
	if err := g.Apply(ctx, d); err != nil {
		t.Fatal(err)
	}
	tr := Trailers{Audit: "audit-1", Findings: []string{fp(1), fp(2)}, Keys: []string{"k1", "k2"}}
	sha, err := g.Commit(ctx, "anvil/fix/audit-1/g", base, "Anvil: fix", tr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.TrailersOf(ctx, sha)
	if err != nil || got.Audit != "audit-1" || len(got.Findings) != 2 || len(got.Keys) != 2 || got.Keys[1] != "k2" {
		t.Fatalf("%+v %v", got, err)
	}
	if s, ok, err := g.CommitWithKey(ctx, "k2"); err != nil || !ok || s != sha {
		t.Fatalf("CommitWithKey: %s %v %v", s, ok, err)
	}
	if _, ok, _ := g.CommitWithKey(ctx, "k3"); ok {
		t.Fatal("an unknown key found a commit")
	}
	if _, err := g.Commit(ctx, "anvil/fix/audit-1/g", base, "x", Trailers{Audit: "a"}); err == nil {
		t.Fatal("a commit with no finding was made")
	}
	// The scanned checkout itself was never written.
	if out, _ := (Git{Dir: src}).run(ctx, nil, "branch", "--list", "anvil/*"); strings.TrimSpace(string(out)) != "" {
		t.Fatalf("the source checkout gained a branch: %s", out)
	}
}

// TestGitIgnoresTheRepositorysHooks: a hook planted in the clone does not run.
func TestGitIgnoresTheRepositorysHooks(t *testing.T) {
	ctx := context.Background()
	src, base := gitRepo(t, map[string]string{"a.py": "x = 1\n"})
	g, err := Prepare(ctx, "", src, filepath.Join(t.TempDir(), "work"), base)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	for _, h := range []string{"pre-commit", "post-checkout", "reference-transaction", "post-index-change"} {
		_ = os.WriteFile(filepath.Join(g.Dir, ".git", "hooks", h), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)
	}
	content, blob, mode, _ := g.Blob(ctx, base, "a.py")
	d, _ := g.Diff(ctx, "a.py", blob, mode, content+"y = 2\n")
	if err := g.Apply(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Commit(ctx, "anvil/fix/a/b", base, "s", Trailers{Audit: "a", Findings: []string{fp(1)}, Keys: []string{"k"}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Checkout(ctx, base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a hook in the clone ran")
	}
}

// TestTheBuildHasNoNetwork: the sandbox runs this test binary, which tries to
// connect to a listener on the host, then to read a secret and write a file
// outside its directory. Where the host allows the sandbox, the connection,
// the read and the write all fail (and the same binary outside the sandbox
// connects, the control); where it does not, the sandbox refuses to run the
// command at all, and the ladder's build rung fails closed.
func TestTheBuildHasNoNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	exe, _ := os.Executable()
	ctrl := exec.Command(exe)
	ctrl.Env = []string{"ANVIL_TEST_DIAL=" + ln.Addr().String()}
	if err := ctrl.Run(); err != nil {
		t.Fatalf("the control could not reach the listener outside the sandbox: %v", err)
	}
	// The secret lives beside this test, under the checkout (a home directory
	// on a developer's machine and on a CI runner), not under /tmp, which the
	// sandbox replaces with its own tmpfs whatever else it shows.
	outside, err := os.MkdirTemp(".", ".sandbox-probe-")
	if err != nil {
		t.Fatal(err)
	}
	if outside, err = filepath.Abs(outside); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	if strings.HasPrefix(outside, "/tmp/") {
		t.Fatalf("the probe directory %s is under /tmp, so the test would show nothing", outside)
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsEnv := []string{"ANVIL_TEST_READ=" + secret, "ANVIL_TEST_WRITE=" + filepath.Join(outside, "planted")}
	ctrl = exec.Command(exe)
	ctrl.Env = append([]string{"ANVIL_TEST_DIAL="}, fsEnv...)
	if err := ctrl.Run(); err == nil {
		t.Fatal("the control was refused the file system outside the sandbox, so the test shows nothing")
	}
	_ = os.Remove(filepath.Join(outside, "planted"))

	sb := Sandbox{Env: []string{"ANVIL_TEST_DIAL=" + ln.Addr().String()}, ReadOnly: []string{filepath.Dir(exe)}}
	ctx := context.Background()
	dir := t.TempDir()
	res, err := sb.Run(ctx, dir, []string{exe})
	if !sb.Available(ctx) {
		// CI's Go job installs bubblewrap and allows unprivileged namespaces,
		// and says so: there, a missing sandbox is a failure, not a refusal.
		if os.Getenv("ANVIL_SANDBOX_REQUIRED") == "1" {
			t.Fatalf("ANVIL_SANDBOX_REQUIRED is set and the sandbox is unavailable: %v", err)
		}
		if !errors.Is(err, ErrNoSandbox) {
			t.Fatalf("no sandbox on this host, and the command was not refused: %v", err)
		}
		export := func(context.Context) (string, func(), error) { return t.TempDir(), func() {}, nil }
		out := Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}}.Run(ctx,
			Patch{Export: export, Files: map[string]string{"a.c": "x"}, Allowed: map[string]bool{"a.c": true}})
		if !strings.Contains(out.Blocked(), RungBuild) {
			t.Fatalf("the build rung did not fail closed: %+v", out.Rungs)
		}
		t.Log("this host refuses the sandbox: it fails closed (docs/controls.md, U12)")
		return
	}
	if err != nil || res.Exit != 3 {
		t.Fatalf("inside the sandbox the dial exited %d (%v): %s; 3 means it could not connect", res.Exit, err, res.Tail)
	}
	fs := Sandbox{Env: fsEnv, ReadOnly: []string{filepath.Dir(exe)}}
	if res, err := fs.Run(ctx, dir, []string{exe}); err != nil || res.Exit != 0 {
		t.Fatalf("inside the sandbox the file-system probe exited %d (%v): %s; 0 means it could neither read the secret nor write outside", res.Exit, err, res.Tail)
	}
	if _, err := os.Stat(filepath.Join(outside, "planted")); err == nil {
		t.Fatal("the sandboxed command wrote outside its directory")
	}
	if res, err := sb.Run(ctx, dir, []string{"sh", "-c", "echo ok > built && cat built"}); err != nil || res.Exit != 0 {
		t.Fatalf("the sandbox could not write its own directory: %d %v %s", res.Exit, err, res.Tail)
	}
	if _, err := (Sandbox{Env: []string{"GITHUB_TOKEN=x"}}).Run(ctx, dir, []string{"true"}); err == nil {
		t.Fatal("a credential-shaped variable reached the sandbox")
	}
}

// passSandbox stands in for bubblewrap where a test is about the controller,
// not the sandbox: it runs the command after "--" as it is.
func passSandbox(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bwrap")
	script := "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do\n  [ \"$#\" -eq 0 ] && exit 0\n  shift\ndone\nshift\nexec \"$@\"\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheLadderStopsAtTheFirstBlockingRung(t *testing.T) {
	ctx := context.Background()
	sb := Sandbox{Bwrap: passSandbox(t)}
	export := func(context.Context) (string, func(), error) { return t.TempDir(), func() {}, nil }
	ok := func(context.Context, string, []string) (map[string]bool, error) { return map[string]bool{}, nil }
	base := Patch{Export: export, Files: map[string]string{"src/a.c": "y"}, Allowed: map[string]bool{"src/a.c": true}, Diff: "+y\n-x\n",
		Fingerprints: map[string]bool{fp(1): true}, BaseFingerprints: map[string]bool{fp(1): true, fp(2): true}}

	cases := []struct {
		name  string
		l     Ladder
		p     func(Patch) Patch
		rung  string
		regr  bool
		clean bool
	}{
		{"passes", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, nil, "", false, true},
		{"workflow file", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, func(p Patch) Patch {
			p.Files = map[string]string{".github/workflows/ci.yml": "x"}
			p.Allowed = map[string]bool{".github/workflows/ci.yml": true}
			return p
		}, RungPaths, false, false},
		{"another file", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, func(p Patch) Patch {
			p.Files = map[string]string{"src/b.c": "x"}
			return p
		}, RungPaths, false, false},
		{"lower-case makefile", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, func(p Patch) Patch {
			p.Files = map[string]string{"makefile": "x"}
			p.Allowed = map[string]bool{"makefile": true}
			return p
		}, RungPaths, false, false},
		{"conftest", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, func(p Patch) Patch {
			p.Files = map[string]string{"tests/conftest.py": "x"}
			p.Allowed = map[string]bool{"tests/conftest.py": true}
			return p
		}, RungPaths, false, false},
		{"devcontainer", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, func(p Patch) Patch {
			p.Files = map[string]string{".devcontainer/setup.js": "x"}
			p.Allowed = map[string]bool{".devcontainer/setup.js": true}
			return p
		}, RungPaths, false, false},
		{"go.mod", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, func(p Patch) Patch {
			p.Files = map[string]string{"go.mod": "x"}
			p.Allowed = map[string]bool{"go.mod": true}
			return p
		}, RungPaths, false, false},
		{"too big", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: ok}, func(p Patch) Patch {
			p.Diff = strings.Repeat("+x\n", DefaultMaxChangedLines+1)
			return p
		}, RungSize, false, false},
		{"no build command", Ladder{Sandbox: sb, Test: []string{"true"}, Rescan: ok}, nil, RungBuild, false, false},
		{"build fails", Ladder{Sandbox: sb, Build: []string{"false"}, Test: []string{"true"}, Rescan: ok}, nil, RungBuild, false, false},
		{"tests fail", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"false"}, Rescan: ok}, nil, RungTests, false, false},
		{"rule still matches", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: func(context.Context, string, []string) (map[string]bool, error) {
			return map[string]bool{fp(1): true}, nil
		}}, nil, RungRescan, false, false},
		{"new finding", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: func(context.Context, string, []string) (map[string]bool, error) {
			return map[string]bool{fp(9): true}, nil
		}}, nil, RungRescan, true, false},
		{"rescan incomplete", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}, Rescan: func(context.Context, string, []string) (map[string]bool, error) {
			return nil, errors.New("coverage incomplete")
		}}, nil, RungRescan, false, false},
		{"no rescan", Ladder{Sandbox: sb, Build: []string{"true"}, Test: []string{"true"}}, nil, RungRescan, false, false},
	}
	for _, c := range cases {
		p := base
		if c.p != nil {
			p = c.p(base)
		}
		out := c.l.Run(ctx, p)
		blocked := out.Blocked()
		if c.clean {
			if blocked != "" {
				t.Errorf("%s: blocked at %s", c.name, blocked)
			}
			last := out.Rungs[len(out.Rungs)-1]
			if last.Name != RungHumanReview || last.Result != RungRequired {
				t.Errorf("%s: human review is not the last, required rung: %+v", c.name, last)
			}
			continue
		}
		if !strings.HasPrefix(blocked, c.rung+":") || out.Regression != c.regr {
			t.Errorf("%s: blocked at %q (regression %v), want %s", c.name, blocked, out.Regression, c.rung)
		}
		if out.Rungs[len(out.Rungs)-1].Name != c.rung {
			t.Errorf("%s: the ladder climbed past its blocking rung", c.name)
		}
	}
	for name, text := range rungText {
		if text[0] == "" || text[1] == "" {
			t.Errorf("rung %s does not say what it proves and what it does not", name)
		}
	}
}
