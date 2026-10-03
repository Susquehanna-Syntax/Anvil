// This file is template pinning: supply-chain pinning for the nuclei-templates
// corpus.
//
// # The failure this prevents
//
// research/23-dast-signal-sources.md Risk #3 is supply-chain poisoning of the
// template corpus, and the spine's safety section answers it with one sentence: "Pin
// nuclei-templates by commit SHA and diff before promotion." The corpus is
// roughly ten thousand YAML files maintained by people Anvil has no
// relationship with, and `nuclei -update-templates` against a moving `main` is
// a standing invitation for whatever landed upstream in the last hour to run
// against a customer's estate on the next scheduled scan.
//
// So this job does three separable things, and keeps them separable:
//
//	fetch       resolve the tracking ref to a commit SHA, materialise it
//	diff        compare it, by template identity, against the PINNED SHA
//	promote     refuse unless a human named this exact transition
//
// Nothing here promotes on a clean diff. A clean diff is a precondition for a
// human being asked; it is not an approval, and there is no flag that makes it
// one. Template pinning's design says so in as many words.
//
// # Why the pin is a SHA and never a ref
//
// The lesson is already recorded in .github/workflows/ci.yml, which pins the
// Anvil LICENSE by sha256 rather than by name: a tag can be moved, a branch
// moves by definition, and a version written from memory 404s. `main` is what
// this job FETCHES; a 40-character commit SHA is what it PINS. isCommitSHA is
// the whole enforcement, and it refuses "main", "HEAD", "latest", "v10.4.7"
// and any abbreviation, because none of those is forty hex characters.
//
// # How this file reaches the outside world
//
// Through CorpusSource, and only through CorpusSource. The production
// implementation shells out to `git`; the tests drive fixture trees. When git
// is not on the host, gitSource REFUSES with a typed absence carrying
// engines.ExitCodeArtefactAbsent -- it does not degrade into "no diff found",
// because "nothing changed upstream" and "I could not look" are the same
// supply-chain outcome only if you are not paying attention.
//
// # What decides whether a template is dangerous
//
// Not this file. internal/dast/engines.LoadTemplates already owns that
// judgement, by an allowlist matched on identity, and the nuclei driver built it so that a
// `code:` template is refused at load time. This job calls it on BOTH trees
// and diffs the results, which means the definition of "dangerous" lives in
// exactly one place and this file cannot drift from it.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/engines"
)

// ---------------------------------------------------------------------------
// The pin itself
// ---------------------------------------------------------------------------

// The pinned corpus.
//
// EVERY VALUE BELOW WAS READ FROM A PRIMARY SOURCE ON 2026-08-22 FROM THE
// DEVELOPMENT HOST. None of it is remembered, and none of it is a placeholder.
// The exact commands, so a reviewer can re-run them rather than trust this
// comment:
//
//	git ls-remote --tags https://github.com/projectdiscovery/nuclei-templates
//	  -> refs/tags/v10.4.7 = 83234ce456da3e90dda86dfbc5e605e64a846df3
//	  -> ZERO refs ending in ^{}: every tag in that repository is lightweight,
//	     so a tag SHA is a commit SHA and no peeling step is being skipped.
//
//	git fetch --depth=1 --filter=blob:none origin 83234ce4...
//	git cat-file -t 83234ce456da3e90dda86dfbc5e605e64a846df3   -> commit
//	git log -1 --format=%cI                                    -> 2026-08-03T13:55:24+07:00
//	git ls-tree 83234ce4... | grep -i licen
//	  -> 100644 blob 93c6a78f51fce232923d923e5e1fa1080eeb99df  LICENSE.md
//	git cat-file -p 93c6a78f...  -> the MIT licence BODY, archived verbatim at
//	                                data/LICENSES/nuclei-templates/LICENSE
//
// The licence was read as a FILE BODY out of the repository at the pinned
// commit, per the spine's licence section -- not from a repository-metadata field,
// which is the route that returns NOASSERTION over a real licence and, in one
// audited case, a permissive tag over a restrictive body.
//
// The archived body is 1079 bytes, LF-only (0x0D count: zero), sha256 below.
const (
	// pinnedRepository is the corpus. HTTPS, canonical host, no mirror.
	pinnedRepository = "https://github.com/projectdiscovery/nuclei-templates"

	// pinnedTrackingRef is what a scheduled run FETCHES. It is deliberately
	// a moving ref and it is deliberately NOT the pin: research 23's
	// recommendation item 1 is "track main for the fetch, pin by SHA for
	// what actually ships".
	pinnedTrackingRef = "refs/heads/main"

	// pinnedCommitSHA is what ships. Forty lowercase hex characters.
	pinnedCommitSHA = "83234ce456da3e90dda86dfbc5e605e64a846df3"

	// pinnedCommitTag and pinnedCommitDate are PROVENANCE, not identity.
	// A tag can be moved onto a different commit tomorrow; the SHA cannot.
	// They are recorded so a human reading a diff report knows roughly what
	// era of the corpus is pinned, and they are never used to resolve
	// anything.
	pinnedCommitTag  = "v10.4.7"
	pinnedCommitDate = "2026-08-03T13:55:24+07:00"

	// upstreamLicencePath is where the licence body lives IN THE CORPUS.
	// Note the extension: it is LICENSE.md upstream, LICENSE in the archive.
	upstreamLicencePath = "LICENSE.md"

	// archivedLicencePath is where Anvil keeps the body, relative to the
	// repository root.
	archivedLicencePath = "data/LICENSES/nuclei-templates/LICENSE"

	// archivedLicenceSPDX is the identifier for the body that was actually
	// read. It agrees with plan/design/dynamic-tier.md's Pinned Versions And Licences
	// table ("MIT"), and it was derived from the text, not from the table.
	archivedLicenceSPDX = "MIT"

	// archivedLicenceSHA256 is the sha256 of that body's exact bytes.
	//
	// This is the value that makes an upstream relicence STOP a promotion
	// rather than ride along inside it. MIT is irrevocable for code already
	// released, so a relicence upstream does not retroactively poison the
	// pinned snapshot -- but it absolutely changes what the NEXT snapshot
	// costs, and a promotion that absorbed it silently would put Anvil in
	// breach without anyone having decided to.
	archivedLicenceSHA256 = "5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c"
)

// Pin is the pinned state of an upstream corpus.
//
// The zero value is NOT a pin, and Valid says so. This matters more than it
// looks: a Pin{} has CommitSHA == "", and a fetch tool that treats an empty
// SHA as "no constraint" resolves it to whatever is newest. FAIL CLOSED means
// the empty string is a refusal, never a wildcard.
type Pin struct {
	Repository    string
	TrackingRef   string
	CommitSHA     string
	CommitTag     string
	CommitDate    string
	LicencePath   string
	LicenceSPDX   string
	LicenceSHA256 string
}

// CurrentPin returns the in-tree pin.
//
// The pin is a set of Go constants in this file rather than a JSON file the
// job rewrites, and that is the promotion gate's teeth: changing what ships
// requires a source edit, a commit and a review. A job that can rewrite its
// own pin can promote itself.
func CurrentPin() Pin {
	return Pin{
		Repository:    pinnedRepository,
		TrackingRef:   pinnedTrackingRef,
		CommitSHA:     pinnedCommitSHA,
		CommitTag:     pinnedCommitTag,
		CommitDate:    pinnedCommitDate,
		LicencePath:   upstreamLicencePath,
		LicenceSPDX:   archivedLicenceSPDX,
		LicenceSHA256: archivedLicenceSHA256,
	}
}

// Valid reports whether p is a usable pin. Every clause is a way a pin has
// gone wrong somewhere before.
func (p Pin) Valid() error {
	if !strings.HasPrefix(p.Repository, "https://") {
		return fmt.Errorf("%w: repository %q is not an https URL", ErrPinInvalid, p.Repository)
	}
	if p.TrackingRef == "" {
		return fmt.Errorf("%w: no tracking ref", ErrPinInvalid)
	}
	if !isCommitSHA(p.CommitSHA) {
		return fmt.Errorf("%w: pinned commit %q is not a 40-character lowercase hex commit "+
			"SHA. A branch name, a tag, an abbreviation or an empty string is not a pin: "+
			"the first three can be moved onto different bytes without the pin changing, "+
			"and the fourth resolves to whatever is newest",
			ErrPinInvalid, p.CommitSHA)
	}
	if p.LicencePath == "" {
		return fmt.Errorf("%w: no upstream licence path", ErrPinInvalid)
	}
	if p.LicenceSPDX == "" {
		return fmt.Errorf("%w: no licence identifier", ErrPinInvalid)
	}
	if !isSHA256(p.LicenceSHA256) {
		return fmt.Errorf("%w: archived licence digest %q is not a 64-character lowercase "+
			"hex sha256. Without it an upstream relicence cannot be detected, and the "+
			"licence half of this job becomes decoration",
			ErrPinInvalid, p.LicenceSHA256)
	}
	return nil
}

// SourceForm renders the constant block a promotion requires a human to paste
// into this file.
//
// This is the "explicit promotion step" of template pinning's design expected
// output schema, made as awkward as it deserves to be. The job computes the
// new pin; a person commits it.
func (p Pin) SourceForm() string {
	var b strings.Builder
	b.WriteString("// Regenerated by `anvil-dast pin-templates promote`. Paste over the\n")
	b.WriteString("// corresponding constants in cmd/anvil-dast/pin-templates.go and commit.\n")
	b.WriteString("const (\n")
	fmt.Fprintf(&b, "\tpinnedRepository      = %q\n", p.Repository)
	fmt.Fprintf(&b, "\tpinnedTrackingRef     = %q\n", p.TrackingRef)
	fmt.Fprintf(&b, "\tpinnedCommitSHA       = %q\n", p.CommitSHA)
	fmt.Fprintf(&b, "\tpinnedCommitTag       = %q\n", p.CommitTag)
	fmt.Fprintf(&b, "\tpinnedCommitDate      = %q\n", p.CommitDate)
	fmt.Fprintf(&b, "\tupstreamLicencePath   = %q\n", p.LicencePath)
	fmt.Fprintf(&b, "\tarchivedLicenceSPDX   = %q\n", p.LicenceSPDX)
	fmt.Fprintf(&b, "\tarchivedLicenceSHA256 = %q\n", p.LicenceSHA256)
	b.WriteString(")\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

var (
	// ErrPinInvalid: a Pin that cannot be used as one.
	ErrPinInvalid = errors.New("pin-templates: pin is not usable")

	// ErrUnconstructed: a Snapshot or DiffReport arrived as a zero value or
	// a composite literal instead of coming from its constructor. Same
	// discipline as engines.ErrUnconstructed, for the same reason: a report
	// nobody computed must not be promotable.
	ErrUnconstructed = errors.New("pin-templates: value was not built by its constructor")

	// ErrPromotionBlocked: the diff contains something no approval may
	// override.
	ErrPromotionBlocked = errors.New("pin-templates: promotion is blocked")

	// ErrNotApproved: promotion was attempted without an approval that names
	// this exact transition.
	ErrNotApproved = errors.New("pin-templates: promotion was not approved")

	// ErrToolUnavailable: git is not on this host. Always carries
	// *ToolUnavailableError.
	ErrToolUnavailable = errors.New("pin-templates: the git command is not available")

	// ErrFetch: the corpus could not be resolved or materialised.
	ErrFetch = errors.New("pin-templates: upstream corpus could not be read")
)

// ToolUnavailableError is the typed absence of the external tool, mirroring
// engines.EngineUnavailableError. It reports the same exit code so a wrapper
// does not need a per-tool table.
//
// It exists so the tool-absent path REFUSES rather than reporting an empty
// diff. An empty diff and an unattempted diff are byte-identical in every
// field a caller reads, and for a supply-chain gate that is the worst
// available failure.
type ToolUnavailableError struct {
	Name   string
	Detail string
}

func (e *ToolUnavailableError) Error() string {
	return fmt.Sprintf(
		"pin-templates: %s is not available (%s). This is NOT an empty diff: the upstream "+
			"corpus was never read, so nothing was compared against the pinned commit. "+
			"A wrapping command must exit %d for this condition.",
		e.Name, e.Detail, engines.ExitCodeArtefactAbsent)
}

func (e *ToolUnavailableError) Unwrap() error { return ErrToolUnavailable }

// ExitCode reports the process exit code a wrapping command must use.
func (e *ToolUnavailableError) ExitCode() int { return engines.ExitCodeArtefactAbsent }

// ---------------------------------------------------------------------------
// Identity predicates
// ---------------------------------------------------------------------------

// isCommitSHA reports whether s is a full lowercase hex git commit SHA.
//
// Full, and lowercase, both on purpose. An abbreviation is ambiguous by
// construction and git will happily resolve a 7-character prefix to whatever
// it matches today; uppercase is refused so that a pin and a fetched SHA
// compare with ==, and two spellings of one commit never read as two commits.
func isCommitSHA(s string) bool { return isLowerHex(s, 40) }

// isSHA256 reports whether s is a full lowercase hex sha256 digest.
func isSHA256(s string) bool { return isLowerHex(s, 64) }

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// The seam to the outside world
// ---------------------------------------------------------------------------

// CorpusSource is every way this job touches anything it did not compute.
//
// Two methods, because the third one people reach for -- "read me file X at
// SHA Y" -- would be a second route to the licence body, and a control with
// two routes is a control with one route plus an untested one. The licence is
// read out of the materialised tree with os.ReadFile, so the bytes the licence
// check sees are the bytes the diff was computed over.
type CorpusSource interface {
	// Resolve maps a ref to the commit SHA it currently names. It must
	// return a full 40-character SHA or an error; it must never return a
	// ref, an abbreviation, or an empty string with a nil error.
	Resolve(ctx context.Context, ref string) (string, error)

	// Materialise places the corpus at exactly sha into dest, which the
	// caller has created and owns. Implementations must refuse a sha that
	// is not a full commit SHA rather than letting git interpret it.
	Materialise(ctx context.Context, sha string, dest string) error
}

// gitSource is the production CorpusSource. It shells out.
//
// A subprocess rather than a Go git library on purpose: the module has one
// direct requirement (modernc.org/sqlite) and plan/design/spine.md's dependency
// posture is that anything entering the graph is reviewed. `git` is already a
// build-host requirement, so this adds no dependency at all -- and if it is
// absent, that fact is reported rather than absorbed.
type gitSource struct {
	// repository is the URL. Fixed at construction; there is no method that
	// changes it, so a compromised ref string cannot redirect the fetch.
	repository string
	// git is the resolved absolute path to the binary.
	git string
}

// newGitSource resolves git or refuses. There is no code path in which this
// returns a usable source with a missing tool.
func newGitSource(repository string) (*gitSource, error) {
	if !strings.HasPrefix(repository, "https://") {
		return nil, fmt.Errorf("%w: repository %q is not an https URL", ErrPinInvalid, repository)
	}
	p, err := exec.LookPath("git")
	if err != nil {
		return nil, &ToolUnavailableError{
			Name:   "git",
			Detail: fmt.Sprintf("exec.LookPath(%q) over PATH returned: %v", "git", err),
		}
	}
	return &gitSource{repository: repository, git: p}, nil
}

func (g *gitSource) Resolve(ctx context.Context, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", fmt.Errorf("%w: no ref was named", ErrFetch)
	}
	out, err := g.run(ctx, "", "ls-remote", g.repository, ref)
	if err != nil {
		return "", fmt.Errorf("%w: ls-remote %s %s: %w", ErrFetch, g.repository, ref, err)
	}
	var shas []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		shas = append(shas, fields[0])
	}
	// Exactly one. Zero means the ref is gone -- which is a supply-chain
	// event, not a no-op -- and more than one means the ref is ambiguous,
	// and picking the first would be an allowlist matched by position.
	if len(shas) != 1 {
		return "", fmt.Errorf("%w: ref %q resolved to %d commits at %s, expected exactly 1",
			ErrFetch, ref, len(shas), g.repository)
	}
	if !isCommitSHA(shas[0]) {
		return "", fmt.Errorf("%w: ref %q resolved to %q, which is not a full commit SHA",
			ErrFetch, ref, shas[0])
	}
	return shas[0], nil
}

func (g *gitSource) Materialise(ctx context.Context, sha, dest string) error {
	if !isCommitSHA(sha) {
		return fmt.Errorf("%w: refusing to materialise %q: only a full 40-character "+
			"lowercase commit SHA may be checked out, so that git is never handed "+
			"something it could interpret as a moving ref", ErrFetch, sha)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("%w: creating %q: %w", ErrFetch, dest, err)
	}
	steps := [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", g.repository},
		// --depth=1 against an explicit SHA: no history, no other refs, and
		// nothing reachable from any branch tip is pulled in. If the server
		// refuses to serve the SHA, that is an error here rather than a
		// silent fallback to a branch.
		{"fetch", "--quiet", "--depth=1", "origin", sha},
		{"checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, args := range steps {
		if _, err := g.run(ctx, dest, args...); err != nil {
			return fmt.Errorf("%w: git %s in %q: %w", ErrFetch, args[0], dest, err)
		}
	}
	// Confirm what actually landed. `git fetch <sha>` succeeding is not the
	// same claim as "HEAD is that sha", and this job's entire value is that
	// the bytes it diffed are the bytes the SHA names.
	head, err := g.run(ctx, dest, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("%w: rev-parse HEAD in %q: %w", ErrFetch, dest, err)
	}
	if got := strings.TrimSpace(head); got != sha {
		return fmt.Errorf("%w: materialised %q but HEAD is %q", ErrFetch, sha, got)
	}
	return nil
}

func (g *gitSource) run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, g.git, args...)
	cmd.Dir = dir
	// A hermetic environment: no ~/.gitconfig aliases, no credential helper
	// prompt, no interactive terminal to block a scheduled run forever.
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ASKPASS=",
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

// TemplateEntry is one admitted template, reduced to what a diff compares.
type TemplateEntry struct {
	// ID is the template's declared identifier. This is the IDENTITY the
	// diff keys on -- not the path, and never the index. A corpus that
	// reorganises its directories moves ten thousand paths without changing
	// a single template, and a positional or path-keyed diff would report
	// that as ten thousand additions and hide the one real change inside it.
	ID string
	// Path is where it lived, relative to the corpus root.
	Path string
	// Digest is engines.Template.Digest: sha256 of the exact bytes on disk.
	Digest string

	protocols []engines.Protocol
}

// Protocols returns the template's top-level keys as a FRESH SLICE.
func (e TemplateEntry) Protocols() []engines.Protocol {
	if e.protocols == nil {
		return nil
	}
	out := make([]engines.Protocol, len(e.protocols))
	copy(out, e.protocols)
	return out
}

// Snapshot is one corpus tree, loaded through the nuclei driver's template loader.
//
// The zero value is not a snapshot. Constructed says so, and Diff refuses one,
// because a Snapshot{} has no admitted templates and no rejections -- which,
// compared against a real one, reads as "upstream deleted everything and
// nothing was refused". That is a diff a reviewer would wave through.
type Snapshot struct {
	sha      string
	admitted map[string]TemplateEntry
	rejected map[string]engines.RejectedTemplate
	examined int
	sealed   bool
}

// Constructed reports whether s came from SnapshotDir.
func (s Snapshot) Constructed() bool {
	return s.sealed && isCommitSHA(s.sha) && len(s.admitted) > 0
}

// SHA is the commit the snapshot was taken at.
func (s Snapshot) SHA() string { return s.sha }

// Examined is how many admitted templates the snapshot holds.
func (s Snapshot) Examined() int { return s.examined }

// Admitted returns the admitted templates as a FRESH MAP whose values carry
// FRESH SLICES.
func (s Snapshot) Admitted() map[string]TemplateEntry {
	if s.admitted == nil {
		return nil
	}
	out := make(map[string]TemplateEntry, len(s.admitted))
	for k, v := range s.admitted {
		v.protocols = v.Protocols()
		out[k] = v
	}
	return out
}

// Rejected returns the refusals as a FRESH MAP, keyed by path.
//
// Keyed by path and not by id because a rejected template's id is frequently
// unreadable -- that is sometimes WHY it was rejected -- and a map keyed on
// the empty string collapses every anonymous refusal into one entry. Path is
// the only identity a refused file reliably has.
func (s Snapshot) Rejected() map[string]engines.RejectedTemplate {
	if s.rejected == nil {
		return nil
	}
	out := make(map[string]engines.RejectedTemplate, len(s.rejected))
	for k, v := range s.rejected {
		out[k] = v
	}
	return out
}

// CorpusScanSubdir is the part of the materialised corpus this job loads.
//
// IT IS THE ROOT, and that is a decision rather than a default.
//
// The obvious alternative is to scan only `http/`, since that is the one
// upstream directory whose templates the nuclei driver's loader can admit at all --
// everything under code/, javascript/, headless/, network/, dns/, file/,
// ssl/, dast/ and cloud/ is refused by the protocol allowlist, and scanning
// the root therefore files thousands of pre-existing refusals plus every
// GitHub Actions workflow in .github/. Measured against the pinned commit,
// the corpus root holds: .github, cloud, code, dast, dns, file, headless,
// helpers, http, javascript, network, profiles, ssl, workflows.
//
// It is still the root, for two reasons.
//
//  1. A CHECK THAT CANNOT SEE THE DAMAGE IS NOT A CHECK. Scoping to `http/`
//     means a `code:` template landing in any other directory is invisible to
//     this gate, and template pinning's design says "rejects any new `code:`
//     protocol template in the diff outright" -- in the diff, not in one
//     directory of it.
//  2. Which subdirectories the scan engine actually points LoadTemplates at
//     is not decided anywhere in this tree today; the dynamic tier's entrypoint owns wiring
//     the scan, and the nuclei driver's LoadTemplates takes a directory from its caller.
//     A gate whose scope is a guess about another packet's future decision is
//     a gate that silently narrows the day that decision is made. The root is
//     the superset, and a superset cannot be narrowed by someone else.
//
// The cost is noise: the report's NewRejections section will list upstream's
// new workflow YAML alongside its new templates. That is a cost paid in a
// report a human is required to read anyway, and it buys the property that a
// refusal cannot hide in a directory nobody scoped in.
const CorpusScanSubdir = "."

// SnapshotDir loads the corpus tree rooted at dir, taken at sha.
//
// It returns an error rather than an empty Snapshot when the tree yields no
// admitted templates. engines.LoadTemplates already refuses that case with
// ErrNoTemplates for its own reason -- an engine with no templates reports
// clean over anything -- and the reason applies here too: a corpus that loads
// as empty would diff against the pinned corpus as "every template removed",
// and a promotion that absorbed it would ship a scanner that finds nothing.
func SnapshotDir(sha, dir string) (Snapshot, error) {
	if !isCommitSHA(sha) {
		return Snapshot{}, fmt.Errorf("%w: %q is not a commit SHA, so a snapshot taken "+
			"here could not be attributed to anything", ErrPinInvalid, sha)
	}
	admitted, rejected, err := engines.LoadTemplates(dir)
	if err != nil {
		return Snapshot{}, fmt.Errorf("pin-templates: loading corpus at %s from %q: %w",
			sha, dir, err)
	}
	s := Snapshot{
		sha:      sha,
		admitted: make(map[string]TemplateEntry, len(admitted)),
		rejected: make(map[string]engines.RejectedTemplate, len(rejected)),
		examined: len(admitted),
		sealed:   true,
	}
	for _, t := range admitted {
		s.admitted[t.ID()] = TemplateEntry{
			ID:        t.ID(),
			Path:      t.Path(),
			Digest:    t.Digest(),
			protocols: t.Protocols(),
		}
	}
	for _, r := range rejected {
		s.rejected[r.Path] = r
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// The licence probe
// ---------------------------------------------------------------------------

// LicenceProbe is an attempt to read the upstream licence body.
//
// The ZERO VALUE IS A FAILURE, not an absence of concern: Body nil, Err nil.
// Diff treats an empty body as unreadable and blocks. This is the fail-closed
// shape -- a struct whose zero value means "no problem found" would let a
// caller who forgot to run the probe promote past the licence check.
type LicenceProbe struct {
	// Path is where the body was looked for, relative to the corpus root.
	Path string
	// Body is the exact bytes read. Never normalised: a licence compared
	// after whitespace folding is a licence whose diff can be hidden in
	// whitespace.
	Body []byte
	// Err is why it could not be read, if it could not.
	Err error
}

// ReadLicence reads the licence body out of a materialised corpus tree.
func ReadLicence(dir, rel string) LicenceProbe {
	p := LicenceProbe{Path: rel}
	if rel == "" {
		p.Err = errors.New("no upstream licence path was named")
		return p
	}
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		p.Err = err
		return p
	}
	p.Body = b
	return p
}

// ---------------------------------------------------------------------------
// The diff
// ---------------------------------------------------------------------------

// ChangeKind is what happened to one template between two commits.
type ChangeKind string

// The change kinds.
const (
	ChangeAdded    ChangeKind = "added"
	ChangeRemoved  ChangeKind = "removed"
	ChangeModified ChangeKind = "modified"
)

// TemplateChange is one entry in the diff.
type TemplateChange struct {
	Kind                 ChangeKind
	ID                   string
	FromPath, ToPath     string
	FromDigest, ToDigest string
}

func (c TemplateChange) String() string {
	switch c.Kind {
	case ChangeAdded:
		return fmt.Sprintf("+ %s  %s  %s", c.ID, c.ToPath, c.ToDigest)
	case ChangeRemoved:
		return fmt.Sprintf("- %s  %s  %s", c.ID, c.FromPath, c.FromDigest)
	default:
		loc := c.ToPath
		if c.FromPath != c.ToPath {
			loc = c.FromPath + " -> " + c.ToPath
		}
		return fmt.Sprintf("~ %s  %s  %s -> %s", c.ID, loc, c.FromDigest, c.ToDigest)
	}
}

// RejectionChange is a file the loader refused at ToSHA that it did not refuse
// at FromSHA -- i.e. upstream ADDED something Anvil will not load.
type RejectionChange struct {
	Path     string
	ID       string
	Reason   engines.RejectionReason
	Protocol engines.Protocol
	Detail   string
}

func (c RejectionChange) String() string {
	s := fmt.Sprintf("! %s  %s", c.Path, c.Reason)
	if c.Protocol != engines.ProtocolUnspecified {
		s += fmt.Sprintf("  (%s:)", c.Protocol)
	}
	if c.ID != "" {
		s += "  id=" + c.ID
	}
	return s
}

// BlockReason names why a promotion may not proceed. Every value is a
// constant; none is assembled from upstream's bytes.
type BlockReason string

// The block reasons.
const (
	// BlockNewCodeProtocolTemplate: upstream added a `code:` template.
	//
	// engines.LoadTemplates already refuses to load it, so this block is not
	// what stops it running. What this block stops is the SNAPSHOT being
	// promoted at all. Those are different remedies: dropping one file and
	// shipping the rest treats a poisoned corpus as a corpus with a typo,
	// whereas research/23-dast-signal-sources.md Risk #3 is that the commit
	// which carried the `code:` template also carried the other four hundred
	// changes in that diff. A human looks at the whole snapshot, or none of
	// it ships.
	BlockNewCodeProtocolTemplate BlockReason = "new_code_protocol_template"

	// BlockLicenceBodyChanged: the licence body at ToSHA is not the body
	// archived at the pinned commit.
	BlockLicenceBodyChanged BlockReason = "upstream_licence_body_changed"

	// BlockLicenceUnreadable: the licence body could not be read at all.
	// Fail closed -- an unread licence is not a permissive one.
	BlockLicenceUnreadable BlockReason = "upstream_licence_body_unreadable"
)

// blockingRejections is the set of loader refusals that stop a promotion
// outright, by identity.
//
// It is EXACTLY the spine's hard exclusion, and the narrowness is deliberate
// rather than an oversight, so it is worth saying what is NOT here and why.
// Upstream ships thousands of `javascript:`, `flow:`, `headless:` and
// `self-contained:` templates and adds more every week; every one is already
// refused at load time by an allowlist matched on identity, and none can
// reach engines.Fire. Blocking a promotion on each would mean no promotion
// ever completes, and a gate that always fires is a gate someone disables.
//
// They are not ignored: every one appears in the report's NewRejections
// section by name and reason, and the promotion still requires a human who
// has that report in front of them. What differs is that a `code:` template
// is the one an approval CANNOT wave through, because the spine's exclusion list excludes the
// protocol outright and no operator has standing to override a spine
// exclusion from a command line.
func blockingRejections() map[engines.RejectionReason]bool {
	return map[engines.RejectionReason]bool{
		engines.RejectCodeProtocol: true,
	}
}

// Block is one reason a promotion is refused.
type Block struct {
	Reason  BlockReason
	Subject string
	Detail  string
}

func (b Block) String() string {
	s := fmt.Sprintf("BLOCKED %s", b.Reason)
	if b.Subject != "" {
		s += ": " + b.Subject
	}
	if b.Detail != "" {
		s += " -- " + b.Detail
	}
	return s
}

// DiffReport is the artifact template pinning's design requires: what changed
// between the pinned commit and the fetched one, and whether anything in it
// forbids promotion.
//
// The zero value is not a report. Promote refuses one.
type DiffReport struct {
	Repository     string
	FromSHA, ToSHA string
	FromCount      int
	ToCount        int
	Templates      []TemplateChange
	NewRejections  []RejectionChange
	Blocks         []Block
	sealed         bool
}

// Constructed reports whether r came from Diff.
func (r DiffReport) Constructed() bool { return r.sealed }

// PromotionBlocked reports whether anything in the diff forbids promotion
// regardless of approval.
func (r DiffReport) PromotionBlocked() bool { return len(r.Blocks) > 0 }

// Changed reports whether the diff contains anything at all.
func (r DiffReport) Changed() bool { return r.FromSHA != r.ToSHA }

// Diff compares two snapshots against a pin and decides what may be promoted.
//
// It is a pure function of its arguments. It reads no file, resolves no ref
// and takes no clock reading, so a report is reproducible from the two trees
// it was computed over -- which is what lets a reviewer re-run it and get the
// same bytes a scheduled job produced at 3am.
func Diff(pin Pin, from, to Snapshot, lic LicenceProbe) (DiffReport, error) {
	if err := pin.Valid(); err != nil {
		return DiffReport{}, err
	}
	if !from.Constructed() {
		return DiffReport{}, fmt.Errorf("%w: the FROM snapshot did not come from "+
			"SnapshotDir; a zero Snapshot diffs as \"upstream removed every template\"",
			ErrUnconstructed)
	}
	if !to.Constructed() {
		return DiffReport{}, fmt.Errorf("%w: the TO snapshot did not come from SnapshotDir",
			ErrUnconstructed)
	}
	// PIN THE RELATION. A diff whose FROM side is not the pinned commit is
	// a diff against something nobody approved, and its ToSHA would then be
	// promoted on the strength of a comparison that never happened.
	if from.SHA() != pin.CommitSHA {
		return DiffReport{}, fmt.Errorf("%w: the FROM snapshot is at %s but the pin is %s; "+
			"a promotion decision may only be made against the commit that is actually "+
			"pinned", ErrPinInvalid, from.SHA(), pin.CommitSHA)
	}

	r := DiffReport{
		Repository: pin.Repository,
		FromSHA:    from.SHA(),
		ToSHA:      to.SHA(),
		FromCount:  from.Examined(),
		ToCount:    to.Examined(),
		sealed:     true,
	}

	fromT, toT := from.Admitted(), to.Admitted()
	for id, f := range fromT {
		t, ok := toT[id]
		if !ok {
			r.Templates = append(r.Templates, TemplateChange{
				Kind: ChangeRemoved, ID: id,
				FromPath: f.Path, FromDigest: f.Digest,
			})
			continue
		}
		if t.Digest != f.Digest || t.Path != f.Path {
			r.Templates = append(r.Templates, TemplateChange{
				Kind: ChangeModified, ID: id,
				FromPath: f.Path, ToPath: t.Path,
				FromDigest: f.Digest, ToDigest: t.Digest,
			})
		}
	}
	for id, t := range toT {
		if _, ok := fromT[id]; !ok {
			r.Templates = append(r.Templates, TemplateChange{
				Kind: ChangeAdded, ID: id,
				ToPath: t.Path, ToDigest: t.Digest,
			})
		}
	}

	fromR, toR := from.Rejected(), to.Rejected()
	blocking := blockingRejections()
	for path, rej := range toR {
		if _, existed := fromR[path]; existed {
			continue
		}
		r.NewRejections = append(r.NewRejections, RejectionChange{
			Path:     path,
			ID:       rej.ID,
			Reason:   rej.Reason,
			Protocol: rej.Protocol,
			Detail:   rej.Detail,
		})
		if blocking[rej.Reason] {
			r.Blocks = append(r.Blocks, Block{
				Reason:  BlockNewCodeProtocolTemplate,
				Subject: path,
				Detail: fmt.Sprintf("the loader refused this file with reason %q; "+
					"The spine's exclusion list excludes the `code:` protocol outright, "+
					"and a snapshot that introduces one is not promotable by any "+
					"approval", rej.Reason),
			})
		}
	}

	// The licence. Checked LAST so that a corpus which is blocked for a
	// `code:` template is still reported as blocked for that, first.
	switch {
	case lic.Err != nil:
		r.Blocks = append(r.Blocks, Block{
			Reason:  BlockLicenceUnreadable,
			Subject: lic.Path,
			Detail: fmt.Sprintf("reading the upstream licence body failed: %v. "+
				"An unread licence is not a permissive one", lic.Err),
		})
	case len(lic.Body) == 0:
		r.Blocks = append(r.Blocks, Block{
			Reason:  BlockLicenceUnreadable,
			Subject: lic.Path,
			Detail: "the upstream licence body was empty or the probe was never run " +
				"(a zero-value LicenceProbe reaches here); either way nothing was " +
				"compared against the archived body",
		})
	default:
		if got := digestOf(lic.Body); got != pin.LicenceSHA256 {
			r.Blocks = append(r.Blocks, Block{
				Reason:  BlockLicenceBodyChanged,
				Subject: lic.Path,
				Detail: fmt.Sprintf("upstream licence body is sha256 %s, archived body "+
					"at %s is sha256 %s. %s was read from the body at the pinned "+
					"commit, not from repository metadata; a change here is a "+
					"relicence and must be reviewed before it is absorbed",
					got, archivedLicencePath, pin.LicenceSHA256, pin.LicenceSPDX),
			})
		}
	}

	sortReport(&r)
	return r, nil
}

func sortReport(r *DiffReport) {
	sort.Slice(r.Templates, func(i, j int) bool {
		if r.Templates[i].Kind != r.Templates[j].Kind {
			return r.Templates[i].Kind < r.Templates[j].Kind
		}
		return r.Templates[i].ID < r.Templates[j].ID
	})
	sort.Slice(r.NewRejections, func(i, j int) bool {
		if r.NewRejections[i].Path != r.NewRejections[j].Path {
			return r.NewRejections[i].Path < r.NewRejections[j].Path
		}
		return r.NewRejections[i].Reason < r.NewRejections[j].Reason
	})
	sort.Slice(r.Blocks, func(i, j int) bool {
		if r.Blocks[i].Reason != r.Blocks[j].Reason {
			return r.Blocks[i].Reason < r.Blocks[j].Reason
		}
		return r.Blocks[i].Subject < r.Blocks[j].Subject
	})
}

// WriteReport renders the diff artifact.
//
// Deterministic: same two trees in, same bytes out, no timestamp and no map
// iteration order. A report whose bytes wander cannot be diffed against last
// week's, which is the only way anyone notices a slow change.
func WriteReport(w io.Writer, r DiffReport) error {
	if !r.Constructed() {
		return fmt.Errorf("%w: refusing to render a DiffReport that did not come from Diff",
			ErrUnconstructed)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "nuclei-templates promotion diff\n")
	fmt.Fprintf(&b, "repository: %s\n", r.Repository)
	fmt.Fprintf(&b, "pinned:     %s  (%d templates admitted)\n", r.FromSHA, r.FromCount)
	fmt.Fprintf(&b, "candidate:  %s  (%d templates admitted)\n", r.ToSHA, r.ToCount)
	fmt.Fprintf(&b, "\ntemplate changes: %d\n", len(r.Templates))
	for _, c := range r.Templates {
		fmt.Fprintf(&b, "  %s\n", c)
	}
	fmt.Fprintf(&b, "\nnewly refused by the loader: %d\n", len(r.NewRejections))
	for _, c := range r.NewRejections {
		fmt.Fprintf(&b, "  %s\n", c)
	}
	fmt.Fprintf(&b, "\nblocks: %d\n", len(r.Blocks))
	for _, bl := range r.Blocks {
		fmt.Fprintf(&b, "  %s\n", bl)
	}
	b.WriteString("\nverdict: ")
	switch {
	case r.PromotionBlocked():
		b.WriteString("PROMOTION BLOCKED. Nothing in this snapshot may be promoted, " +
			"and no approval overrides a block.\n")
	case !r.Changed():
		b.WriteString("no change: the candidate IS the pinned commit. Nothing to promote.\n")
	default:
		fmt.Fprintf(&b, "AWAITING EXPLICIT PROMOTION. A clean diff is not an approval.\n"+
			"  anvil-dast pin-templates promote --from %s --to %s --approver <name>\n",
			r.FromSHA, r.ToSHA)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// ---------------------------------------------------------------------------
// Promotion
// ---------------------------------------------------------------------------

// Approval is a human decision about ONE transition.
//
// It names both ends. That is the point, and it is not redundant: approving
// "move to 83234ce4" says nothing about how far the corpus travelled to get
// there. Approving 83234ce4 FROM the commit released last week is a review of
// a few hundred templates; approving the same destination from a commit a year
// old is a review of tens of thousands, and the two approvals cannot be the
// same decision. Pinning both ends also means an approval cannot be replayed
// after the pin has moved on underneath it.
//
// The zero value approves nothing.
type Approval struct {
	FromSHA    string
	ToSHA      string
	Approver   string
	ApprovedAt time.Time
}

// Promote computes the new pin, or refuses.
//
// It does NOT write this file, and there is no flag that makes it. It returns
// the Pin a human must commit. Template pinning's design forbids automatic
// promotion on a clean diff, and the way to be sure a job never promotes
// itself is for it to have no code that can.
func Promote(r DiffReport, ap Approval, upstreamLicence LicenceProbe) (Pin, error) {
	if !r.Constructed() {
		return Pin{}, fmt.Errorf("%w: refusing to promote against a DiffReport that did "+
			"not come from Diff", ErrUnconstructed)
	}
	if r.PromotionBlocked() {
		var names []string
		for _, b := range r.Blocks {
			names = append(names, string(b.Reason)+" ("+b.Subject+")")
		}
		return Pin{}, fmt.Errorf("%w: %d block(s) stand against %s: %s. No approval "+
			"overrides a block", ErrPromotionBlocked, len(r.Blocks), r.ToSHA,
			strings.Join(names, "; "))
	}
	if !r.Changed() {
		return Pin{}, fmt.Errorf("%w: candidate %s is the pinned commit; there is nothing "+
			"to promote and an approval here approves nothing", ErrNotApproved, r.ToSHA)
	}
	if strings.TrimSpace(ap.Approver) == "" {
		return Pin{}, fmt.Errorf("%w: no approver was named", ErrNotApproved)
	}
	if ap.ApprovedAt.IsZero() {
		return Pin{}, fmt.Errorf("%w: approval carries no timestamp", ErrNotApproved)
	}
	if ap.FromSHA != r.FromSHA || ap.ToSHA != r.ToSHA {
		return Pin{}, fmt.Errorf("%w: the approval names the transition %s -> %s but the "+
			"report is %s -> %s. An approval is for one transition, not for one "+
			"destination",
			ErrNotApproved, shortSHA(ap.FromSHA), shortSHA(ap.ToSHA),
			shortSHA(r.FromSHA), shortSHA(r.ToSHA))
	}
	if upstreamLicence.Err != nil || len(upstreamLicence.Body) == 0 {
		return Pin{}, fmt.Errorf("%w: the licence body to archive could not be read (%v); "+
			"a promotion that archives nothing leaves data/LICENSES with a stale body "+
			"and the compliance gate passing on it",
			ErrPromotionBlocked, upstreamLicence.Err)
	}

	p := CurrentPin()
	p.CommitSHA = r.ToSHA
	// Provenance that a promotion cannot honestly carry forward is CLEARED,
	// not guessed. The tag and date belonged to the old commit; whoever
	// lands the new pin fills these from `git ls-remote --tags` and
	// `git log -1 --format=%cI` at the new SHA, the same way the current
	// values were obtained. Writing the old ones through would be a version
	// invented from memory with extra steps.
	p.CommitTag = ""
	p.CommitDate = ""
	p.LicencePath = upstreamLicence.Path
	p.LicenceSHA256 = digestOf(upstreamLicence.Body)
	if err := p.Valid(); err != nil {
		return Pin{}, err
	}
	return p, nil
}

func shortSHA(s string) string {
	if s == "" {
		return "(none)"
	}
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ArchiveLicence writes the licence body to path, creating parents.
//
// The bytes go through unmodified. A licence archived after normalisation is
// a licence whose archived digest no longer matches the body it came from,
// which defeats the only check that can see a relicence.
func ArchiveLicence(path string, lic LicenceProbe) error {
	if lic.Err != nil {
		return fmt.Errorf("pin-templates: refusing to archive an unread licence: %w", lic.Err)
	}
	if len(lic.Body) == 0 {
		return errors.New("pin-templates: refusing to archive an empty licence body; " +
			"an unverified licence file is worse than an absent one, because the " +
			"compliance gate then passes on it")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("pin-templates: creating %q: %w", filepath.Dir(path), err)
	}
	return os.WriteFile(path, lic.Body, 0o644)
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

// pinTemplatesUsage is printed for a bare or unknown subcommand.
const pinTemplatesUsage = `usage: anvil-dast pin-templates <subcommand> [flags]

  verify    check the in-tree pin and the archived licence body. Offline.
  diff      fetch the tracking ref, diff it against the pinned commit, write
            the promotion report. Requires git and network.
  promote   the same diff, plus an explicit approval naming both ends of the
            transition. Prints the pin constants a human must commit and
            archives the licence body. Never runs itself.
`

// runPinTemplates is the subcommand entry point.
//
// It takes its CorpusSource as an argument rather than constructing one, so
// the tests drive fixture trees through the same code path production uses.
// A nil source is legal only for `verify`, which touches nothing outside the
// repository.
func runPinTemplates(ctx context.Context, src CorpusSource, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, pinTemplatesUsage)
		return 2
	}
	switch args[0] {
	case "verify":
		return pinVerify(args[1:], stdout, stderr)
	case "diff":
		return pinDiff(ctx, src, args[1:], stdout, stderr)
	case "promote":
		return pinPromote(ctx, src, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "anvil-dast pin-templates: unknown subcommand %q\n\n", args[0])
		fmt.Fprint(stderr, pinTemplatesUsage)
		return 2
	}
}

func pinVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin-templates verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("repo-root", ".", "path to the Anvil repository root")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pin := CurrentPin()
	if err := pin.Valid(); err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates verify: %v\n", err)
		return 1
	}
	path := filepath.Join(*root, filepath.FromSlash(archivedLicencePath))
	body, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates verify: the archived licence body at "+
			"%s could not be read: %v. The pin claims %s; without the body that claim "+
			"is unverifiable and must not be relied on\n", path, err, pin.LicenceSPDX)
		return 1
	}
	if got := digestOf(body); got != pin.LicenceSHA256 {
		fmt.Fprintf(stderr, "anvil-dast pin-templates verify: archived licence at %s is "+
			"sha256 %s, pin says %s\n", path, got, pin.LicenceSHA256)
		return 1
	}
	fmt.Fprintf(stdout, "pin ok\n  repository: %s\n  commit:     %s (%s, %s)\n"+
		"  tracking:   %s\n  licence:    %s from %s, sha256 %s, archived at %s\n",
		pin.Repository, pin.CommitSHA, pin.CommitTag, pin.CommitDate, pin.TrackingRef,
		pin.LicenceSPDX, pin.LicencePath, pin.LicenceSHA256, archivedLicencePath)
	return 0
}

// prepare does the shared work of `diff` and `promote`: resolve the tracking
// ref, materialise both commits, load both, compare.
func prepare(ctx context.Context, src CorpusSource, work string, stderr io.Writer) (DiffReport, LicenceProbe, int) {
	pin := CurrentPin()
	if err := pin.Valid(); err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: %v\n", err)
		return DiffReport{}, LicenceProbe{}, 1
	}
	if src == nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: %v\n", &ToolUnavailableError{
			Name:   "git",
			Detail: "no corpus source was wired",
		})
		return DiffReport{}, LicenceProbe{}, engines.ExitCodeArtefactAbsent
	}

	head, err := src.Resolve(ctx, pin.TrackingRef)
	if err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: resolving %s: %v\n", pin.TrackingRef, err)
		return DiffReport{}, LicenceProbe{}, exitCodeFor(err)
	}

	fromDir := filepath.Join(work, "pinned")
	toDir := filepath.Join(work, "candidate")
	if err := src.Materialise(ctx, pin.CommitSHA, fromDir); err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: materialising pinned %s: %v\n",
			pin.CommitSHA, err)
		return DiffReport{}, LicenceProbe{}, exitCodeFor(err)
	}
	if err := src.Materialise(ctx, head, toDir); err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: materialising candidate %s: %v\n",
			head, err)
		return DiffReport{}, LicenceProbe{}, exitCodeFor(err)
	}

	from, err := SnapshotDir(pin.CommitSHA, filepath.Join(fromDir, CorpusScanSubdir))
	if err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: %v\n", err)
		return DiffReport{}, LicenceProbe{}, 1
	}
	to, err := SnapshotDir(head, filepath.Join(toDir, CorpusScanSubdir))
	if err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: %v\n", err)
		return DiffReport{}, LicenceProbe{}, 1
	}

	lic := ReadLicence(toDir, pin.LicencePath)
	rep, err := Diff(pin, from, to, lic)
	if err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates: %v\n", err)
		return DiffReport{}, LicenceProbe{}, 1
	}
	return rep, lic, 0
}

func pinDiff(ctx context.Context, src CorpusSource, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin-templates diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	work := fs.String("work", "", "working directory for materialised corpora (required)")
	out := fs.String("out", "", "write the report here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *work == "" {
		fmt.Fprintln(stderr, "anvil-dast pin-templates diff: --work is required")
		return 2
	}
	rep, _, code := prepare(ctx, src, *work, stderr)
	if code != 0 {
		return code
	}
	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(stderr, "anvil-dast pin-templates diff: %v\n", err)
			return 1
		}
		defer f.Close()
		w = f
	}
	if err := WriteReport(w, rep); err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates diff: %v\n", err)
		return 1
	}
	// A blocked diff exits non-zero so a scheduled run is LOUD. Exit 0 on a
	// report saying "BLOCKED" is how a supply-chain finding ends up in a log
	// nobody reads.
	if rep.PromotionBlocked() {
		return 1
	}
	return 0
}

func pinPromote(ctx context.Context, src CorpusSource, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pin-templates promote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	work := fs.String("work", "", "working directory for materialised corpora (required)")
	root := fs.String("repo-root", ".", "path to the Anvil repository root")
	from := fs.String("from", "", "the commit being promoted FROM (must equal the current pin)")
	to := fs.String("to", "", "the commit being promoted TO")
	approver := fs.String("approver", "", "who approved this transition")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *work == "" {
		fmt.Fprintln(stderr, "anvil-dast pin-templates promote: --work is required")
		return 2
	}
	rep, lic, code := prepare(ctx, src, *work, stderr)
	if code != 0 {
		return code
	}
	if err := WriteReport(stderr, rep); err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates promote: %v\n", err)
		return 1
	}
	pin, err := Promote(rep, Approval{
		FromSHA:    *from,
		ToSHA:      *to,
		Approver:   *approver,
		ApprovedAt: time.Now().UTC(),
	}, lic)
	if err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates promote: %v\n", err)
		return 1
	}
	path := filepath.Join(*root, filepath.FromSlash(archivedLicencePath))
	if err := ArchiveLicence(path, lic); err != nil {
		fmt.Fprintf(stderr, "anvil-dast pin-templates promote: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n// archived licence body -> %s\n// approved by %s\n"+
		"// pinnedCommitTag and pinnedCommitDate were cleared: fill them from\n"+
		"//   git ls-remote --tags %s\n//   git log -1 --format=%%cI %s\n",
		pin.SourceForm(), path, *approver, pin.Repository, pin.CommitSHA)
	return 0
}

// exitCodeFor maps a failure to a process exit code, preserving the artefact-
// absent code so a wrapper can tell "the tool was missing" from "the diff
// failed".
func exitCodeFor(err error) int {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return 1
}

// defaultCorpusSource builds the production source, or returns the typed
// absence. It never returns a source that will silently do nothing.
func defaultCorpusSource() (CorpusSource, error) {
	return newGitSource(pinnedRepository)
}

// dispatchPinTemplates is what main() calls. It wires the production source
// for the subcommands that reach the network, and deliberately does not for
// `verify`, which is offline and must keep working on a host with no git --
// including the CI licence lane.
//
// When git is absent and the subcommand needs it, this returns
// engines.ExitCodeArtefactAbsent and says so. It does not fall through to an
// empty diff.
func dispatchPinTemplates(args []string, stdout, stderr io.Writer) int {
	var src CorpusSource
	if len(args) > 0 && args[0] != "verify" {
		s, err := defaultCorpusSource()
		if err != nil {
			fmt.Fprintf(stderr, "anvil-dast pin-templates %s: %v\n", args[0], err)
			return exitCodeFor(err)
		}
		src = s
	}
	return runPinTemplates(context.Background(), src, args, stdout, stderr)
}
