# Remediation exit gate: adversarial review of the security and correctness conclusions

**A same-family review.** The critic was a Claude model reviewing work a Claude model wrote, on 2026-10-04,
read-only, with no network. It shares the author's blind spots and it is not an independent check: the owner
withdrew cross-family critics so that no plan or code goes to a third-party model provider. Where the critic relied
on its own memory rather than on code it read or a command it ran, that is said below.

It was asked to break ten conclusions about `internal/remediation`: prompt-injection containment, the generation
process's isolation, git and the build inside an untrusted checkout, the merge path and the push token, the one road
to "verified fixed", idempotency and leases, the triage gate's statement, anchored edits and the path rung, the
honesty of the ladder and the pull-request body, and whether the gate file's PROVEN rows are proven by the tests they
cite. It read the whole package and most of its tests, ran one probe (the old sandbox could read the operator's home
and write outside its directory), and stopped before building end-to-end reproductions of its git findings, which
it reasoned from the code.

## Findings, and what was done

Every fix below was seen failing under a deliberate mutation before it was trusted (2026-10-04), except where the
row says otherwise.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | blocking | The build sandbox removed only the network. The target's build and tests ran as the operator, could read the home directory, and could write the store, other clones and the scanned checkout. | **Fixed.** The sandbox is bubblewrap with an allowlisted file system: `/usr` and `/etc` read-only, a fresh `/tmp`, `/proc` and `/dev`, operator-listed read-only directories (a toolchain), the directories holding the forge token and endpoint key hidden, and one writable directory; new user, pid, ipc, uts, cgroup and network namespaces. `TestTheBuildHasNoNetwork` now also runs a probe that must fail to read a secret kept outside `/tmp` and fail to write beside it; mutating the sandbox to show the whole file system fails it. The critic's own observation (the old sandbox's reach) was the first version of the test's secret, under `/tmp`, which the sandbox's tmpfs hid anyway; the mutation stayed silent until the secret moved beside the test. |
| 2 | blocking | The controller's git calls trusted a `.git/` the build could rewrite: filters, `core.worktree`, `include.path` and `pushInsteadOf` in the clone's config, and a credential helper that gave the token to any host. | **Fixed at the cause.** Nothing the target runs sees the clone: the build and tests run in a fresh export of the patched tree (files only, written through a temporary index), the rescan in another, the oracle's two targets in two more. The clone's configuration is written only by `git clone`. `core.worktree` is also pinned empty on every call; the push sets `http.followRedirects=false`, and its credential helper answers only the fork remote's host. Held by the test installation's build, which fails unless it sees the sources and no `.git` (mutating the ladder to build in the clone fails `TestTheControllerConsumesAnAuditToItsDispositions`), and by `TestThePushCredentialAnswersOnlyTheForksHost`. |
| 3 | blocking | The commit was made from the index after the build and tests had run, so a test step could stage an extra file into a proposal whose body said it touched only its findings' files. | **Fixed.** The build never sees the clone (row 2), so it cannot stage anything. After the apply, the index must differ from the base in exactly the patched files, or the group fails validation. The tree is recorded once (`write-tree`), every rung judges an export of that tree id, and the commit is made from that tree id itself (`CommitTree`; the re-check found the first fix committed a second `write-tree` that only happened to match). The staged-path check is a second belt that no test can trigger now that nothing else writes the index; it is stated, not claimed as seen failing. |
| 4 | blocking (a PROVEN row not proven) | The oracle counted a mutant as caught when it failed against the patch, without checking it was a live exploit against the scanned code. A patch blocking only the exact payload could earn `verified_fixed` from dead mutants. | **Fixed.** The reproduction must trigger on the scanned code (otherwise `base_does_not_trigger`, unverified); each mutant is replayed on the scanned code first and only live ones count; `verified_fixed` needs at least one live mutant and none surviving. `TestANarrowFixIsCaughtByMutation` now includes the critic's case (every mutant dead: unverified) and a dead reproduction; both mutations fail it. `ReplayTarget` now carries a tree id and a fresh export, never the clone (row 11). |
| 5 | should-fix | The disallowed-path list was a case-sensitive denylist missing many build, CI and tool files. | **Fixed with an allowlist.** Only source files in the languages Lane B covers may be patched, compared case-insensitively; anything under a hidden directory or dot-file, and source files that builds or test runners execute (`setup.py`, `conftest.py`, `*.config.*`, …), are refused. |
| 6 | should-fix | Diff headers wrote paths unquoted; a tab or newline in a path could mislead `git apply`. | **Fixed.** A path with anything but printable ASCII (no space, quote or backslash), a leading dash or slash, or a dot or empty segment is never patched (`SafePath`, `TestAPathGitWouldQuoteIsNeverPatched`). |
| 7 | should-fix | Crash recovery checked only the first member's key, never opened a missing pull request, and could leave an orphan draft. | **Fixed.** Every member's key is looked up; the attempt is recorded (keyed by its tree) before the commit, so a crash after it keeps the evidence; recovery moves it to applied and opens the pull request from the stored rungs; before any draft is opened the forge is asked for an open one from the same branch, which is adopted. `TestACrashBeforeThePullRequestIsRecovered`. |
| 8 | should-fix | Two workers could share one clone. | **Fixed.** An exclusive `flock` on the clone for each group's work (`TestTwoWorkersNeverShareAClone`). |
| 9 | should-fix | The push-scope check passed when the forge reported no permissions (from memory: some token kinds omit them). | **Fixed.** An answer without a permissions object is refused. The check reads the token holder's role on the upstream, which is what decides whether it could merge there; that is now said in the code and the gate file. Token scopes themselves are not read. |
| 10 | should-fix | The production rescan (`LaneBRescan`) was untested, and an empty narrowed plan would read as "the rule no longer matches". | **Fixed.** A rescan that reads none of the touched files is an error; `TestTheProductionRescanIsLaneB` runs it over the fixture and finds the scan's own fingerprints. |
| 11 | should-fix | `ReplayTarget.Commit` was the unpatched base. | **Fixed** with row 4: a tree id and a fresh export. |
| 12 | note | `BaseCommit` ran `git status` in the operator's checkout with only hooks and fsmonitor off. | **Fixed:** `--no-optional-locks`, no untracked cache, no external diff, credential helper or protocol. Filters named by the scanned checkout's own configuration still apply there; that configuration is the operator's, not the repository's content. |
| 13 | note | Re-anchoring compared a working-tree snippet with blob content; CRLF conversion could make unchanged code look changed. | **Fixed:** both sides are compared with line endings normalised. |
| 14 | note | "No inherited file descriptor" overstated the generation process's isolation (from memory). | **Reworded:** only the three standard streams are passed; a descriptor the parent itself inherited without close-on-exec could still reach it. |
| 15 | note | Pull-request titles and commit subjects carried raw paths; bidirectional and zero-width characters passed; short fingerprints could panic. | **Fixed:** target strings are stripped of control and format characters and bounded before they reach a title, a subject or the body; the body shows whole fingerprints. |
| 16 | note | Supersession matched a fingerprint across every repository. | **Fixed:** it is limited to the new draft's repository. |

## Conclusions that survived

The fences in both prompts (the closing tag depends on a hash of the fenced bytes); the generation process's
environment of one marker, its key on stdin, no proxy and no redirects; the forge client's five-route allowlist
(now six, adding the list of open pull requests from one head, read-only) with no merge route and a PATCH that can
only close; the idempotency key; renewal before the commit; Lane B's evidence never overwritten, triage off by
default and unreadable answers made report-only; exactly-once anchoring, edits only to the group's own files,
regular files only, `--3way` against the blob id and no `--reject`; `LabelFor` as the only road to the label;
migration 0003 as purely additive.

## What this review does not cover

It is one critic of the same model family. Its git findings (rows 2, 3 and 6) were reasoned from code and from its
memory of git's behaviour, not reproduced; the fixes remove the conditions rather than depend on that behaviour.
Nothing live was examined: GitHub's real permissions semantics, a model's behaviour against injection, Phase 8's
replayer. It did not read the eval changes (the triage-precision harness and the register), the handoff state
machine beyond the functions it names, or four test files (`triage_test.go`, `oracle_test.go`, `edits_test.go`,
`prs_test.go`).

## The re-check

The same critic re-read the fixes to the four blocking findings on 2026-10-04 (read-only; it ran a bubblewrap probe
with the new arguments and five of the cited tests in a scratch copy) and found all four **closed**, with no new
blocking finding. It could not run `TestTheBuildHasNoNetwork` itself: its copy sat under `/tmp`, and the test refuses
to run there by design, because the sandbox's own tmpfs would hide the probe's secret whatever else it showed. Its
notes, and what was done:

- Row 3: the commit re-ran `write-tree` instead of committing the recorded tree id. **Fixed** (`CommitTree`).
- Row 1: everything under `/etc` and under the operator's read-only directories stays readable to the target's
  code; with no network, the only way out is the build's pass or fail. **Stated** in the settings and the README:
  a read-only directory must hold no secret.
- Row 4: the mutation set is fixed and public, so a patch that normalises case, encoding and whitespace before
  matching the payload's distinctive substring survives every live mutant while a different exploit still works.
  That is the limit of mutation testing; the gate's row says what the oracle shows, not more.
