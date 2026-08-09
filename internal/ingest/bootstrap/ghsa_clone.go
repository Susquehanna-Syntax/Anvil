package bootstrap

// The blobless partial clone. GHSA and only GHSA.
//
// ===========================================================================
// research/06 RISK #7, WHICH THIS FILE EXISTS TO MAKE UNREACHABLE
// ===========================================================================
//
// The intuitive design for a syncing daemon is "clone --depth=1 once, then git
// fetch on a timer". research/06 Risk #7 records GitHub's own warning against
// it, in GitHub's words: a `git fetch` operation in a shallow clone "might end
// up downloading an almost-full commit history", and "shallow fetches can cause
// more harm than good" (research/06 S20). A shallow clone is the right tool for
// a CI job that clones, builds and deletes. It is the wrong tool for a process
// that fetches every hour for a year, because the cheap clone buys an expensive
// fetch forever, and the cost does not show up until the daemon has been in
// production long enough for the shallow boundary to matter.
//
// So the refusal is structural rather than documentary, in three places:
//
//	cloneArgs        builds the command and has no parameter that could carry
//	                 a depth. There is no code path that produces `--depth`.
//	assertNoShallowFlags  refuses any argument vector containing a shallowing
//	                 flag, including one an injected GitRunner supplied, so a
//	                 future caller cannot smuggle one in through the seam.
//	assertNotShallow refuses to IMPORT from a repository that is shallow,
//	                 however it got that way — a clone somebody made by hand,
//	                 a directory restored from a CI cache. `git rev-parse
//	                 --is-shallow-repository` is asked, and .git/shallow is
//	                 checked, because the answer must not depend on one of them
//	                 being available.
//
// ===========================================================================
// WHY A CLONE AT ALL, WHEN THE WHOLE PACKET IS "BULK ARCHIVES, NOT GIT"
// ===========================================================================
//
// Because the argument against git history is an argument about cvelistV5, not
// about git. cvelistV5 commits every ~7 minutes — ~205/day, ~75,000/year — over
// 300,000+ small files, and a blobless clone still downloads every commit AND
// every tree, which on that repository dominates everything else (research/06
// S7, S20). Its 570 MB baseline zip transfers the same content once.
//
// github/advisory-database is the case where the tool fits: one file per
// advisory, so git hands back exact change sets for free, and research/06 names
// it "the right tool for GHSA specifically, the wrong tool for cvelistV5".
// --filter=blob:none fetches commits and trees and defers blobs until a
// checkout needs them, which is exactly the shape of "give me the current
// advisories and then tell me precisely which ones changed".
//
// internal/ingest/config already refuses to let this drift: SyncGitBloblessFetch
// and BootstrapBloblessClone are only legal together, so no feed can configure a
// fetch with nothing to fetch into, or a clone nothing fetches from.
//
// ===========================================================================
// THE CREDENTIAL NEVER TOUCHES THIS PROCESS
// ===========================================================================
//
// A token on a command line is readable by every process on the host. A token
// in a Go variable is one careless %v away from a log file. The git path needs
// neither: the credential helper installed below names the ENVIRONMENT VARIABLE
// the feed row declared, and the child git process reads it from the
// environment it inherits. Anvil never reads the value, so there is no value to
// leak, and the argument vector carries a variable name that is public by
// design.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
)

// ---------------------------------------------------------------------------
// The git seam
// ---------------------------------------------------------------------------

// GitCommand is one git invocation.
//
// Env carries EXTRA environment entries and is expected to be empty: the
// credential path works by naming a variable the parent already has, not by
// passing a value down. It exists so that a caller who genuinely needs to set
// GIT_TERMINAL_PROMPT or similar has a place to do it, and so that a test can
// assert nothing secret travels here.
type GitCommand struct {
	Dir  string
	Args []string
	Env  []string
}

// GitRunner runs git. It is an interface so that every test in this package
// runs against a fake and NOTHING in the suite reaches the network.
type GitRunner interface {
	Run(ctx context.Context, c GitCommand) ([]byte, error)
}

// execGit runs the git on PATH.
type execGit struct{}

func (execGit) Run(ctx context.Context, c GitCommand) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", c.Args...)
	cmd.Dir = c.Dir
	if len(c.Env) > 0 {
		cmd.Env = append(os.Environ(), c.Env...)
	}
	// A daemon must never block on a credential prompt.
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("git %s: %w: %s",
			strings.Join(c.Args, " "), err, strings.TrimSpace(errOut.String()))
	}
	return out.Bytes(), nil
}

func (b *Bootstrapper) git() GitRunner {
	if b.Git != nil {
		return b.Git
	}
	return execGit{}
}

// ---------------------------------------------------------------------------
// The shallow-clone refusals
// ---------------------------------------------------------------------------

// ErrShallowClone reports an attempt to build, or to import from, a shallow
// repository. See this file's header for research/06 Risk #7.
var ErrShallowClone = errors.New("bootstrap: shallow clones are refused as a sync primitive")

// shallowFlags are every spelling git accepts for "truncate the history". They
// are refused as a SET rather than as `--depth`, because --shallow-since and
// --shallow-exclude produce exactly the same broken fetch and are exactly what
// somebody reaches for after being told not to use --depth.
var shallowFlags = []string{
	"--depth",
	"--shallow-since",
	"--shallow-exclude",
	"--unshallow", // only meaningful on a repo that is already shallow
	"--deepen",
}

// assertNoShallowFlags refuses an argument vector that would shallow a clone or
// a fetch.
//
// It is applied to EVERY command this package runs, not only to the clone,
// because the GitRunner is an injected seam and the guarantee has to hold for
// arguments this file did not write.
func assertNoShallowFlags(args []string) error {
	for _, a := range args {
		for _, bad := range shallowFlags {
			if a == bad || strings.HasPrefix(a, bad+"=") {
				return refuse(ErrShallowClone,
					"the argument %q would produce or extend a shallow repository; GitHub's own "+
						"guidance is that \"a git fetch operation in a shallow clone might end up "+
						"downloading an almost-full commit history\" (research/06 Risk #7, S20), so "+
						"Anvil clones with --filter=blob:none and never with a depth", a)
			}
		}
	}
	return nil
}

// cloneArgs is the ONLY clone this package can construct.
//
// There is no depth parameter, and adding one would have to be a deliberate
// edit to this function rather than a call-site option — which is the point.
// --no-tags is not an optimisation for its own sake: advisory-database's tags
// are not part of the advisory content and every one of them is a ref the
// steady-state fetch would have to negotiate.
func cloneArgs(remote, dir string) []string {
	return []string{
		"clone",
		"--filter=blob:none",
		"--no-tags",
		"--single-branch",
		"--",
		remote,
		dir,
	}
}

// credentialArgs installs a credential helper that reads the token from the
// CHILD's environment, by the variable name the feed row declared.
//
// The token value never enters this process. What appears on the command line
// is the NAME of an environment variable, which is public information — it is
// written in the operator's feeds.yaml and printed in this repository's example
// file. `git config` interpolation is not used; the helper is a shell function,
// which is git's documented mechanism for exactly this.
func credentialArgs(envName string) []string {
	if envName == "" {
		return nil
	}
	helper := fmt.Sprintf(
		`!f() { test "$1" = get && echo username=x-access-token && echo "password=${%s}"; }; f`, envName)
	return []string{"-c", "credential.helper=", "-c", "credential.helper=" + helper}
}

// ---------------------------------------------------------------------------
// The blobless-clone bootstrap
// ---------------------------------------------------------------------------

func (b *Bootstrapper) bloblessClone(
	ctx context.Context,
	feed config.FeedConfig,
	decision license.Decision,
	prior Progress,
	res BootstrapResult,
) (BootstrapResult, error) {
	state, err := readFeedState(ctx, b.DB, feed.ID)
	if err != nil {
		return res, err
	}

	remote := feed.BootstrapURL
	if remote == "" {
		remote = feed.URL
	}
	if remote == "" {
		return res, refuse(ErrFetch, "feed %q has no bootstrap_url and no url to clone", feed.ID)
	}

	if err := os.MkdirAll(b.WorkDir, 0o755); err != nil {
		return res, fmt.Errorf("bootstrap: creating work dir: %w", err)
	}
	dir := filepath.Join(b.WorkDir, feed.ID+".git")

	head, err := b.ensureClone(ctx, feed, remote, dir, prior)
	if err != nil {
		return res, err
	}
	res.ArchiveSHA256 = head
	res.ArchiveReused = prior.Phase == PhaseInProgress && prior.ArchiveSHA256 == head

	// The commit is the resume key AND the handoff: it is what A.14's
	// `git fetch` starts from, and it is what makes a cursor meaningful. A
	// clone that advanced to a new commit restarts the import from file zero,
	// because a cursor counted over one tree says nothing about another.
	resume := prior
	if resume.Phase != PhaseInProgress || resume.ArchiveSHA256 != head {
		resume = Progress{Phase: PhaseNotStarted}
	}
	res.Resumed = resume.Phase == PhaseInProgress
	res.ResumedFromEntry = resume.Entries

	files, err := advisoryFiles(dir)
	if err != nil {
		return res, err
	}
	if len(files) > MaxEntries {
		return res, refuse(ErrArchiveTooLarge, "the clone holds %d advisory files, over the %d limit",
			len(files), MaxEntries)
	}

	w := &writer{
		b:        b,
		feed:     feed,
		decision: decision,
		state:    state,
		res:      &res,
		progress: Progress{
			Phase:         PhaseInProgress,
			Mechanism:     string(feed.BootstrapMechanism),
			ArchiveSHA256: head,
			Entries:       resume.Entries,
			Cursor:        resume.Cursor,
			Records:       resume.Records,
			Handoff:       head,
			CloneDir:      filepath.Base(dir),
		},
		asOf:      b.now().UTC(),
		lastEntry: resume.Entries - 1,
		lastName:  resume.Cursor,
	}

	start := resume.Entries
	if start > len(files) || (resume.Cursor != "" && start > 0 && files[start-1] != resume.Cursor) {
		// The working tree changed under a cursor that claimed otherwise.
		// Restarting is the only option that cannot skip a file that was never
		// imported; every write is idempotent, so it costs time and nothing else.
		start = 0
	}

	dc := &decodeCtx{feedID: feed.ID}
	meter := &readMeter{}
	for i := start; i < len(files); i++ {
		rel := files[i]
		n, err := b.decodeCloneFile(dc, dir, rel, meter, func(rec advisoryRecord) error {
			return w.add(ctx, rec)
		})
		if err != nil {
			res.Sanitizer, res.PeakReadBytes, res.BytesRead = dc.stats, meter.MaxRead, meter.Total
			return res, err
		}
		res.EntriesRead++
		if n == 0 {
			res.EntriesSkipped++
		}
		if err := w.entryDone(ctx, i, rel); err != nil {
			res.Sanitizer, res.PeakReadBytes, res.BytesRead = dc.stats, meter.MaxRead, meter.Total
			return res, err
		}
	}
	res.Sanitizer, res.PeakReadBytes, res.BytesRead = dc.stats, meter.MaxRead, meter.Total

	if err := w.finish(ctx); err != nil {
		return res, err
	}
	res.Complete = true
	return res, nil
}

// ensureClone makes the clone exist, proves it is not shallow, and returns the
// commit HEAD points at.
//
// It is idempotent: an existing, non-shallow clone at the recorded commit is
// reused rather than re-cloned, which is what makes a resume cheap. A directory
// that exists but is not a usable repository is removed and re-cloned, because
// "a directory is there" is not evidence of anything.
func (b *Bootstrapper) ensureClone(ctx context.Context, feed config.FeedConfig, remote, dir string, prior Progress) (string, error) {
	// The .git directory is checked before git is asked anything. "git said
	// yes" is not evidence that this directory is a clone: a rev-parse run
	// against a path that does not exist can still answer from an enclosing
	// repository, and importing from the wrong tree is worse than re-cloning.
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		if head, err := b.headCommit(ctx, dir); err == nil {
			if err := b.assertNotShallow(ctx, dir); err != nil {
				return "", err
			}
			return head, nil
		}
	}
	if _, err := os.Stat(dir); err == nil {
		if err := os.RemoveAll(dir); err != nil {
			return "", fmt.Errorf("bootstrap: clearing unusable clone %q: %w", dir, err)
		}
	}

	args := append(credentialArgs(credentialEnvFor(feed)), cloneArgs(remote, dir)...)
	if err := assertNoShallowFlags(args); err != nil {
		return "", err
	}
	if _, err := b.git().Run(ctx, GitCommand{Dir: b.WorkDir, Args: args}); err != nil {
		return "", refuse(ErrFetch, "feed %q: cloning %s: %v", feed.ID, redactURL(remote), err)
	}
	if err := b.assertNotShallow(ctx, dir); err != nil {
		return "", err
	}
	return b.headCommit(ctx, dir)
}

// credentialEnvFor returns the environment variable name the feed row declared
// for its credential, and "" when the feed authenticates with nothing. It never
// returns a value.
func credentialEnvFor(feed config.FeedConfig) string {
	if feed.AuthMode == config.AuthNone {
		return ""
	}
	return feed.CredentialEnv
}

// assertNotShallow refuses to import from a shallow repository.
//
// Both checks are made because either can be unavailable: `git rev-parse
// --is-shallow-repository` needs git 2.15+, and .git/shallow can sit somewhere
// else in a worktree or a separate git dir. A shallow repo detected by either
// is refused; a repo neither can prove shallow is accepted.
func (b *Bootstrapper) assertNotShallow(ctx context.Context, dir string) error {
	if _, err := os.Stat(filepath.Join(dir, ".git", "shallow")); err == nil {
		return refuse(ErrShallowClone, "%s carries a .git/shallow file", dir)
	}
	args := []string{"rev-parse", "--is-shallow-repository"}
	if err := assertNoShallowFlags(args); err != nil {
		return err
	}
	out, err := b.git().Run(ctx, GitCommand{Dir: dir, Args: args})
	if err != nil {
		// Not a fatal refusal: an older git does not know the flag. The
		// .git/shallow check above already ran and is the one that does not
		// depend on a git version.
		return nil
	}
	if strings.TrimSpace(string(out)) == "true" {
		return refuse(ErrShallowClone,
			"%s is a shallow repository; a git fetch against it may download an almost-full "+
				"commit history (research/06 Risk #7)", dir)
	}
	return nil
}

func (b *Bootstrapper) headCommit(ctx context.Context, dir string) (string, error) {
	args := []string{"rev-parse", "HEAD"}
	if err := assertNoShallowFlags(args); err != nil {
		return "", err
	}
	out, err := b.git().Run(ctx, GitCommand{Dir: dir, Args: args})
	if err != nil {
		return "", err
	}
	head := strings.TrimSpace(string(out))
	if !isHexSHA(head) {
		return "", refuse(ErrFetch, "git rev-parse HEAD in %s returned something that is not a commit", dir)
	}
	return head, nil
}

func isHexSHA(s string) bool {
	if len(s) < 7 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// advisoryFiles lists the JSON files in a clone, in a DETERMINISTIC order.
//
// The order is load-bearing, not cosmetic: it is what the resume cursor counts
// against, and a filesystem walk whose order varies between runs is a cursor
// that means a different thing every time it is read. .git is skipped entirely.
func advisoryFiles(dir string) ([]string, error) {
	var out []string
	root := os.DirFS(dir)
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(p), ".json") {
			out = append(out, path.Clean(p))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: walking clone %q: %w", dir, err)
	}
	sort.Strings(out)
	return out, nil
}

// decodeCloneFile streams one advisory file out of the clone.
//
// github/advisory-database publishes OSV-format documents, so the same decoder
// the OSV bulk archives use reads them. That is not a coincidence to be tidied
// away later: OSV re-exports GHSA (research/06 S14/S15), and one decoder for one
// format is what keeps the two ingestion routes from disagreeing about the same
// advisory.
func (b *Bootstrapper) decodeCloneFile(dc *decodeCtx, dir, rel string, meter *readMeter, emit func(advisoryRecord) error) (int, error) {
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return 0, fmt.Errorf("bootstrap: opening %q: %w", rel, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err == nil && info.Size() > MaxRecordBytes {
		return 0, refuse(ErrRecordTooLarge, "%q is %d bytes, over the %d-byte limit", rel, info.Size(), MaxRecordBytes)
	}
	return dc.decodeEntry(rel, &meteredReader{r: f, m: meter}, emit)
}

// ---------------------------------------------------------------------------
// Fetch handoff — read by A.14, never re-derived by it
// ---------------------------------------------------------------------------

// FetchArgs is the steady-state `git fetch` A.14 should run against a clone
// this package produced, given the feed's stored watermark.
//
// It lives here rather than in A.14 for one reason: the fetch and the clone
// must be constrained by the same rule, and a rule that lives in two packages
// is a rule that will hold in one of them. assertNoShallowFlags runs on the
// result, so the fetch cannot be shallowed either.
//
// It returns false when the watermark does not record a completed clone, which
// is the honest answer to "what should I fetch into" when nothing has been
// cloned yet.
func FetchArgs(watermark string) ([]string, bool) {
	p, err := ParseWatermark(watermark)
	if err != nil || p.Phase != PhaseComplete || p.CloneDir == "" {
		return nil, false
	}
	args := []string{"fetch", "--filter=blob:none", "--no-tags", "origin"}
	if assertNoShallowFlags(args) != nil {
		return nil, false
	}
	return args, true
}

// CloneDir returns the working tree a completed blobless clone landed in,
// relative to the Bootstrapper's WorkDir.
func CloneDir(watermark string) (string, bool) {
	p, err := ParseWatermark(watermark)
	if err != nil || p.Phase != PhaseComplete || p.CloneDir == "" {
		return "", false
	}
	return p.CloneDir, true
}
