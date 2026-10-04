package remediation

// The pull-request lifecycle (plan node prs). Each validated group becomes a
// DRAFT pull request whose body is the evidence. Nothing here merges: the
// forge client can reach only the endpoints on forgeAllowlist, and no merge
// endpoint is on it (TestTheForgeCannotReachAMergeEndpoint). The push token
// must not be able to write to the upstream repository at all, so it cannot
// merge there either: Anvil pushes to a fork and opens the pull request from
// it (CheckPushScope).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// PullRequest is the forge's view of one pull request.
type PullRequest struct {
	Number int    `json:"number"`
	URL    string `json:"html_url"`
	State  string `json:"state"` // open or closed
	Draft  bool   `json:"draft"`
	Merged bool   `json:"merged"`
}

// Permissions is what the push token may do on a repository.
type Permissions struct {
	Admin    bool `json:"admin"`
	Maintain bool `json:"maintain"`
	Push     bool `json:"push"`
	// Reported is false when the forge's answer carried no permissions.
	Reported bool `json:"-"`
}

// Forge is the pull-request host. GitHub implements it over its REST API;
// tests use a fake.
type Forge interface {
	Permissions(ctx context.Context, repo string) (Permissions, error)
	OpenDraft(ctx context.Context, repo, head, base, title, body string) (PullRequest, error)
	Get(ctx context.Context, repo string, number int) (PullRequest, error)
	// FindOpen reports the open pull request from head ("owner:branch"), if any.
	FindOpen(ctx context.Context, repo, head string) (PullRequest, bool, error)
	Comment(ctx context.Context, repo string, number int, body string) error
	Close(ctx context.Context, repo string, number int) error
}

// ErrMergeCapable means the push token could merge into the upstream.
var ErrMergeCapable = errors.New("remediation: the push token can write to the upstream repository, so it could merge there; give Anvil a token scoped to a fork")

// ErrNoPermissions means the forge did not say what the token may do.
var ErrNoPermissions = errors.New("remediation: the forge reported no permissions for the push token, so Anvil cannot show it cannot merge; refused")

// CheckPushScope refuses a token with any write access to the upstream, and a
// token whose permissions the forge does not report: an unknown scope is not
// a narrow one. GitHub's permissions object is the token holder's role on the
// repository, which is what decides whether it could merge there.
func CheckPushScope(ctx context.Context, f Forge, upstream string) error {
	p, err := f.Permissions(ctx, upstream)
	if err != nil {
		return err
	}
	if !p.Reported {
		return fmt.Errorf("%w (%s)", ErrNoPermissions, upstream)
	}
	if p.Admin || p.Maintain || p.Push {
		return fmt.Errorf("%w (%s: admin %v, maintain %v, push %v)", ErrMergeCapable, upstream, p.Admin, p.Maintain, p.Push)
	}
	return nil
}

// forgeRoute is one endpoint the GitHub client may call.
type forgeRoute struct {
	method string
	path   *regexp.Regexp
}

const repoPart = `[A-Za-z0-9._-]+/[A-Za-z0-9._-]+`

// forgeAllowlist is every request the GitHub client can make. Anything else is
// refused before a socket opens.
var forgeAllowlist = []forgeRoute{
	{http.MethodGet, regexp.MustCompile(`^/repos/` + repoPart + `$`)},
	{http.MethodPost, regexp.MustCompile(`^/repos/` + repoPart + `/pulls$`)},
	{http.MethodGet, regexp.MustCompile(`^/repos/` + repoPart + `/pulls/[0-9]+$`)},
	{http.MethodGet, regexp.MustCompile(`^/repos/` + repoPart + `/pulls$`)},
	{http.MethodPatch, regexp.MustCompile(`^/repos/` + repoPart + `/pulls/[0-9]+$`)},
	{http.MethodPost, regexp.MustCompile(`^/repos/` + repoPart + `/issues/[0-9]+/comments$`)},
}

// ErrForgeRoute means a request outside the allowlist was attempted.
var ErrForgeRoute = errors.New("remediation: the forge client refuses a request outside its allowlist")

func allowedRoute(method, path string) bool {
	for _, r := range forgeAllowlist {
		if r.method == method && r.path.MatchString(path) {
			return true
		}
	}
	return false
}

// GitHubREST is the GitHub REST client.
type GitHubREST struct {
	API   string // https://api.github.com, or a test server
	Token string
	HTTP  *http.Client
}

func (g GitHubREST) do(ctx context.Context, method, path string, body any, out any) error {
	return g.doQuery(ctx, method, path, nil, body, out)
}

// doQuery is do with a query string; the route is checked on the path alone,
// and only a GET may carry a query.
func (g GitHubREST) doQuery(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	if len(query) > 0 && method != http.MethodGet {
		return fmt.Errorf("%w: a query on %s", ErrForgeRoute, method)
	}
	if !allowedRoute(method, path) {
		return fmt.Errorf("%w: %s %s", ErrForgeRoute, method, path)
	}
	if method == http.MethodPatch {
		// The one PATCH is closing a superseded draft; it may change nothing else.
		m, ok := body.(map[string]any)
		if !ok || len(m) != 1 || m["state"] != "closed" {
			return fmt.Errorf("%w: a PATCH may only close a pull request", ErrForgeRoute)
		}
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	target := strings.TrimRight(g.API, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+g.Token)
	c := g.HTTP
	if c == nil {
		c = &http.Client{Timeout: time.Minute}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("remediation: forge %s %s answered %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Permissions reads the token's permissions on repo.
func (g GitHubREST) Permissions(ctx context.Context, repo string) (Permissions, error) {
	var out struct {
		Permissions *Permissions `json:"permissions"`
	}
	if err := g.do(ctx, http.MethodGet, "/repos/"+repo, nil, &out); err != nil {
		return Permissions{}, err
	}
	if out.Permissions == nil {
		return Permissions{}, nil
	}
	p := *out.Permissions
	p.Reported = true
	return p, nil
}

// FindOpen lists the open pull requests from head.
func (g GitHubREST) FindOpen(ctx context.Context, repo, head string) (PullRequest, bool, error) {
	var prs []PullRequest
	err := g.doQuery(ctx, http.MethodGet, "/repos/"+repo+"/pulls", url.Values{"head": {head}, "state": {"open"}}, nil, &prs)
	if err != nil || len(prs) == 0 {
		return PullRequest{}, false, err
	}
	return prs[0], true, nil
}

// OpenDraft opens a draft pull request. Draft is not a parameter: it is
// always true.
func (g GitHubREST) OpenDraft(ctx context.Context, repo, head, base, title, body string) (PullRequest, error) {
	var pr PullRequest
	err := g.do(ctx, http.MethodPost, "/repos/"+repo+"/pulls",
		map[string]any{"title": title, "head": head, "base": base, "body": body, "draft": true, "maintainer_can_modify": true}, &pr)
	return pr, err
}

// Get reads a pull request.
func (g GitHubREST) Get(ctx context.Context, repo string, number int) (PullRequest, error) {
	var pr PullRequest
	err := g.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%d", repo, number), nil, &pr)
	return pr, err
}

// Comment adds a comment.
func (g GitHubREST) Comment(ctx context.Context, repo string, number int, body string) error {
	return g.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", repo, number), map[string]any{"body": body}, nil)
}

// Close closes a pull request without merging it.
func (g GitHubREST) Close(ctx context.Context, repo string, number int) error {
	return g.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/pulls/%d", repo, number), map[string]any{"state": "closed"}, nil)
}

// Pusher sends a fix branch to the fork. Pushing happens in its own process:
// the token reaches only that git process's environment, never the controller's
// generation process.
type Pusher interface {
	Push(ctx context.Context, dir, branch string) error
}

// pushCredentialHelper gives the token only to the host named by
// ANVIL_PUSH_HOST, the fork remote's own; any other host asking gets nothing.
const pushCredentialHelper = `credential.helper=!f() { h=; while read l; do case "$l" in host=*) h="${l#host=}";; esac; done; ` +
	`[ "$h" = "$ANVIL_PUSH_HOST" ] || exit 0; echo username=x-access-token; echo "password=$ANVIL_PUSH_TOKEN"; }; f`

// GitPusher pushes with git over HTTPS, the token supplied by a credential
// helper that reads it from the push process's environment.
type GitPusher struct {
	Bin     string
	Remote  string // the fork's https URL
	Token   string
	Timeout time.Duration
}

// Push pushes branch to the fork, never with --force.
func (p GitPusher) Push(ctx context.Context, dir, branch string) error {
	if !strings.HasPrefix(p.Remote, "https://") {
		return errors.New("remediation: the fork remote must be an https URL")
	}
	bin := p.Bin
	if bin == "" {
		bin = "git"
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u, err := url.Parse(p.Remote)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("remediation: the fork remote must be a plain https URL")
	}
	// The helper answers only for the fork's own host, so a redirect or a
	// rewritten URL cannot collect the token.
	args := append(append([]string{}, gitSafety...),
		"-c", "protocol.https.allow=always",
		"-c", "http.followRedirects=false",
		"-c", pushCredentialHelper,
		"push", "--porcelain", "--", p.Remote, "refs/heads/"+branch+":refs/heads/"+branch)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(gitEnv(), "ANVIL_PUSH_TOKEN="+p.Token, "ANVIL_PUSH_HOST="+u.Host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("remediation: push: %v: %s", err, strings.TrimSpace(strings.ReplaceAll(string(out), p.Token, "***")))
	}
	return nil
}
