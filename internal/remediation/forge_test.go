package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// TestTheForgeCannotReachAMergeEndpoint is half of the remediation exit gate's
// row "no path reaches a merge API": the client's allowlist holds no merge
// route, a merge request is refused before any socket opens, and the one
// PATCH it may send can only close a pull request.
func TestTheForgeCannotReachAMergeEndpoint(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	g := GitHubREST{API: srv.URL, Token: "t", HTTP: srv.Client()}
	ctx := context.Background()

	merges := []struct{ method, path string }{
		{http.MethodPut, "/repos/o/r/pulls/1/merge"},
		{http.MethodPost, "/repos/o/r/merges"},
		{http.MethodPut, "/repos/o/r/pulls/1/update-branch"},
		{http.MethodPost, "/graphql"},
		{http.MethodPatch, "/repos/o/r"},
		{http.MethodDelete, "/repos/o/r/git/refs/heads/main"},
		{http.MethodPost, "/repos/o/r/git/refs"},
		{http.MethodPut, "/repos/o/r/contents/README.md"},
	}
	for _, m := range merges {
		if err := g.do(ctx, m.method, m.path, map[string]any{"merge_method": "squash"}, nil); !errors.Is(err, ErrForgeRoute) {
			t.Errorf("%s %s was not refused: %v", m.method, m.path, err)
		}
	}
	if err := g.do(ctx, http.MethodPatch, "/repos/o/r/pulls/1", map[string]any{"draft": false}, nil); !errors.Is(err, ErrForgeRoute) {
		t.Errorf("a PATCH that marks a draft ready was not refused: %v", err)
	}
	if err := g.do(ctx, http.MethodPatch, "/repos/o/r/pulls/1", map[string]any{"state": "closed", "base": "x"}, nil); !errors.Is(err, ErrForgeRoute) {
		t.Errorf("a PATCH that does more than close was not refused: %v", err)
	}
	if hits != 0 {
		t.Fatalf("%d refused request(s) reached the server", hits)
	}
	// The negative control: allowed requests do reach it.
	if err := g.Close(ctx, "o/r", 1); err != nil || hits != 1 {
		t.Fatalf("the allowed close did not reach the server: %v (%d hits)", err, hits)
	}
	for _, r := range forgeAllowlist {
		if strings.Contains(r.path.String(), "merge") {
			t.Fatalf("the allowlist holds a merge route: %s", r.path)
		}
	}
}

// mergeShapes are what a merge looks like in Go source: a REST merge route, a
// GraphQL merge mutation, an auto-merge setting, or git's own merge command.
var mergeShapes = regexp.MustCompile(`(?i)(/merges?\b|merge_method|automerge|auto_merge|enablePullRequestAutoMerge|mergePullRequest|^"merge"$|\bgh\b.*\bmerge\b)`)

// TestNoCodePathNamesAMergeAPI is the other half: no string literal in any
// non-test Go file of the module has the shape of a merge call. Prose in
// comments does not count; only what code could send does.
func TestNoCodePathNamesAMergeAPI(t *testing.T) {
	root := moduleRoot(t)
	var found []string
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "plan", "research", "eval", "testdata", "node_modules", "tools":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		scanned++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && mergeShapes.MatchString(lit.Value) {
				found = append(found, fmt.Sprintf("%s: %s", fset.Position(lit.Pos()), lit.Value))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files; the walk is not seeing the module", scanned)
	}
	for _, f := range found {
		t.Errorf("a merge-shaped literal: %s", f)
	}
	// The negative control: the pattern does match a merge call.
	for _, bad := range []string{`"/repos/o/r/pulls/1/merge"`, `"merge_method"`, `"merge"`, `"gh pr merge 1"`} {
		if !mergeShapes.MatchString(bad) {
			t.Errorf("the pattern misses %s", bad)
		}
	}
}

// TestNoCodePathAsksGitApplyToReject is the remediation exit gate's row
// "--reject never appears": partial application would leave a half-patched
// tree, so no non-test Go file of the module may hold the flag.
func TestNoCodePathAsksGitApplyToReject(t *testing.T) {
	root := moduleRoot(t)
	var hits []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "plan", "research", "eval", "testdata", "node_modules", "tools":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), "--reject") || strings.Contains(string(raw), `"--rej"`) {
			hits = append(hits, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("--reject appears in %v", hits)
	}
}

// fakeForge is an in-process forge. It records every call; nothing leaves
// the process.
type fakeForge struct {
	mu       sync.Mutex
	perm     Permissions
	next     int
	prs      map[int]*PullRequest
	bodies   map[int]string
	comments map[int][]string
	heads    map[int]string
	calls    []string
}

func newFakeForge() *fakeForge {
	return &fakeForge{perm: Permissions{Reported: true}, prs: map[int]*PullRequest{}, bodies: map[int]string{},
		comments: map[int][]string{}, heads: map[int]string{}}
}

func (f *fakeForge) Permissions(_ context.Context, repo string) (Permissions, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "permissions "+repo)
	return f.perm, nil
}

func (f *fakeForge) OpenDraft(_ context.Context, repo, head, base, title, body string) (PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	pr := &PullRequest{Number: f.next, URL: fmt.Sprintf("https://forge.invalid/%s/pull/%d", repo, f.next), State: "open", Draft: true}
	f.prs[f.next] = pr
	f.bodies[f.next] = body
	f.heads[f.next] = repo + " " + head
	f.calls = append(f.calls, fmt.Sprintf("open %s %s->%s", repo, head, base))
	return *pr, nil
}

func (f *fakeForge) FindOpen(_ context.Context, repo, head string) (PullRequest, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for n := 1; n <= f.next; n++ {
		if pr := f.prs[n]; pr != nil && pr.State == "open" && f.heads[n] == repo+" "+head {
			return *pr, true, nil
		}
	}
	return PullRequest{}, false, nil
}

func (f *fakeForge) Get(_ context.Context, _ string, n int) (PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.prs[n], nil
}

func (f *fakeForge) Comment(_ context.Context, _ string, n int, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.comments[n] = append(f.comments[n], body)
	return nil
}

func (f *fakeForge) Close(_ context.Context, _ string, n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prs[n].State = "closed"
	f.calls = append(f.calls, fmt.Sprintf("close %d", n))
	return nil
}

// TestThePushTokensScopeExcludesMerge is the remediation exit gate's row "the
// push token's scope excludes merge": a token with any write access to the
// upstream is refused before anything is pushed, and the GitHub client reads
// the permissions GitHub reports for the token.
func TestThePushTokensScopeExcludesMerge(t *testing.T) {
	ctx := context.Background()
	for _, p := range []Permissions{{Push: true, Reported: true}, {Maintain: true, Reported: true}, {Admin: true, Reported: true}} {
		f := newFakeForge()
		f.perm = p
		if err := CheckPushScope(ctx, f, "upstream/repo"); !errors.Is(err, ErrMergeCapable) {
			t.Errorf("%+v was not refused: %v", p, err)
		}
	}
	if err := CheckPushScope(ctx, newFakeForge(), "upstream/repo"); err != nil {
		t.Fatalf("a read-only token was refused: %v", err)
	}
	silent := newFakeForge()
	silent.perm = Permissions{}
	if err := CheckPushScope(ctx, silent, "upstream/repo"); !errors.Is(err, ErrNoPermissions) {
		t.Fatalf("a token whose permissions the forge did not report was accepted: %v", err)
	}
	quiet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"full_name": "upstream/repo"}`))
	}))
	defer quiet.Close()
	if err := CheckPushScope(ctx, GitHubREST{API: quiet.URL, Token: "tok", HTTP: quiet.Client()}, "upstream/repo"); !errors.Is(err, ErrNoPermissions) {
		t.Fatalf("an answer with no permissions object was accepted: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/upstream/repo" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"permissions": map[string]bool{"admin": false, "maintain": false, "push": true, "pull": true}})
	}))
	defer srv.Close()
	err := CheckPushScope(ctx, GitHubREST{API: srv.URL, Token: "tok", HTTP: srv.Client()}, "upstream/repo")
	if !errors.Is(err, ErrMergeCapable) {
		t.Fatalf("GitHub's push permission was not read as merge-capable: %v", err)
	}
}

// TestADraftIsAlwaysADraft: the GitHub client always asks for a draft.
func TestADraftIsAlwaysADraft(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"number": 7, "html_url": "u", "state": "open", "draft": true}`))
	}))
	defer srv.Close()
	pr, err := GitHubREST{API: srv.URL, Token: "t", HTTP: srv.Client()}.OpenDraft(context.Background(), "o/r", "f:b", "main", "t", "b")
	if err != nil || pr.Number != 7 || got["draft"] != true {
		t.Fatalf("%+v %v %v", pr, got, err)
	}
}

// TestThePushCredentialAnswersOnlyTheForksHost: the credential helper the push
// process uses gives the token to the fork's host and to nothing else, so a
// rewritten or redirected URL cannot collect it.
func TestThePushCredentialAnswersOnlyTheForksHost(t *testing.T) {
	ask := func(host string) string {
		cmd := exec.Command("git", "-c", "credential.helper=", "-c", pushCredentialHelper, "credential", "fill")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0", "ANVIL_PUSH_TOKEN=s3cret", "ANVIL_PUSH_HOST=github.com"}
		cmd.Stdin = strings.NewReader("protocol=https\nhost=" + host + "\n\n")
		out, _ := cmd.Output()
		return string(out)
	}
	if got := ask("github.com"); !strings.Contains(got, "password=s3cret") {
		t.Fatalf("the fork's host did not get the token: %q", got)
	}
	for _, h := range []string{"evil.example", "github.com.evil.example", "api.github.com"} {
		if got := ask(h); strings.Contains(got, "s3cret") {
			t.Fatalf("%s got the token", h)
		}
	}
}
