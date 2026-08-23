# `go-apispec` — pin, licence determination, and maintenance assessment

This directory is packet **D.20**'s licence half. It holds the two files Apache-2.0 attribution is
made of — the licence body and the NOTICE body — read from the upstream repository at a pinned
commit, archived verbatim, and hashed so the determination is reproducible rather than asserted.

`internal/dast/inventory/tier2_go_extract_test.go` re-reads both files on every `go test ./...` and
fails if either drifts from the hashes below. That is what makes this directory a control rather
than a comment.

**No Go source from `go-apispec` is vendored here today.** Why not is [§5](#5-what-is-not-vendored-and-why).

---

## 1. The pin

Every value in this section was read from a primary source on **2026-08-23** from the development
host. None of it is remembered and none of it is a placeholder. The exact commands, so a reviewer
re-runs them rather than trusting this file:

```bash
git ls-remote --heads --tags https://github.com/antst/go-apispec
git clone --filter=blob:none --no-checkout https://github.com/antst/go-apispec
git -C go-apispec cat-file -t 53a81eb07666e55adbd6a5732b1f5ee9a2af5f82   # -> commit
git -C go-apispec log -1 --format=%cI 53a81eb07666e55adbd6a5732b1f5ee9a2af5f82
git -C go-apispec ls-tree 53a81eb07666e55adbd6a5732b1f5ee9a2af5f82 | grep -Ei 'licen|notice'
git -C go-apispec cat-file -p 53a81eb07666e55adbd6a5732b1f5ee9a2af5f82:LICENSE | sha256sum
git -C go-apispec cat-file -p 53a81eb07666e55adbd6a5732b1f5ee9a2af5f82:NOTICE  | sha256sum
```

| Field | Value |
|---|---|
| Repository | `https://github.com/antst/go-apispec` |
| Go module path | `github.com/antst/go-apispec` |
| Pinned commit SHA | `53a81eb07666e55adbd6a5732b1f5ee9a2af5f82` |
| Commit date | `2026-06-17T20:25:22+02:00` |
| Tag at that commit (provenance, **not** identity) | `v0.4.25` |
| `main` at time of reading (**not** the pin) | `63f249957ee855c0516dd6c1438c72922ead378c`, `2026-06-24T13:00:37+02:00` |

### 1.1 The peel check, which here does NOT come out the way D.17's did

`cmd/anvil-dast/pin-templates.go` records that `projectdiscovery/nuclei-templates` returns **zero**
peeled refs, so a tag SHA is a commit SHA there and no peeling step is being skipped.

**`antst/go-apispec` is not like that.** `git ls-remote --tags` returns `^{}` peeled refs for most of
its tags — `v0.4.24`'s tag ref is `f8c809d6…`, and `git cat-file -t f8c809d6…` answers `tag`, not
`commit`. A worker who copied D.17's reasoning across without re-running the check would have pinned
a tag object and believed it was a commit.

`v0.4.25` happens to be lightweight — it has no `^{}` companion — and `git cat-file -t` on it answers
`commit`. That was **verified, not assumed**, and it is the only reason the SHA in the table above is
usable as a commit pin.

---

## 2. Licence determination — read from the file BODY

`plan/00-SPINE.md` S8: read LICENSE file bodies, never API metadata. Seven artifacts in
`research/13-license-compatibility-audit.md` return `NOASSERTION` over a real licence and one is
tagged permissively while its own NOTICE places it under a restrictive licence.

| File | Bytes (LF) | CR bytes | git blob SHA at the pin | sha256 of the body |
|---|---|---|---|---|
| `LICENSE` | 11357 | 0 | `261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64` | `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` |
| `NOTICE` | 434 | 0 | `33a1a872a807dea39ebac1226fb624fd38b2902f` | `5b62d0b6db9f254da3fef7305ac2909fe3107b19c458c58ecd4ab49c3a55c74d` |

**Finding: Apache-2.0, unmodified, with a NOTICE file present.**

The "unmodified" half is measured, not eyeballed. The archived body was diffed against the canonical
text served by the Apache Software Foundation itself:

```bash
curl -sSL https://www.apache.org/licenses/LICENSE-2.0.txt -o canonical.txt
diff canonical.txt third_party/go-apispec/LICENSE
# 1d0
# <              <- one leading blank line, present upstream at apache.org, absent here
```

One blank line. **Nothing else differs** — no rider, no added clause, no "Commons Clause", no field-of-use
restriction. As corroboration from a second independent direction, `sha256sum canonical.txt` is
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`, which is byte-for-byte the value
`.github/workflows/ci.yml:452` already pins for **Anvil's own** `LICENSE`.

### 2.1 Share-alike posture: NOT share-alike, so no quarantine

Checked explicitly, because `plan/00-SPINE.md` S8 quarantines share-alike sources under
`data/share-alike/` and `mirror/tier2/`, and putting one in `third_party/` instead is a compliance
defect rather than a filing preference.

Apache-2.0 has no share-alike term: §4 requires attribution, licence-text carriage, NOTICE
reproduction and change notices, and nowhere requires derivative works to be licensed under the same
terms. The body was also grepped for copyleft vocabulary (`share-alike`, `copyleft`, `reciprocal`,
`same terms`, `GPL`, `AGPL`, `MPL`, `SSPL`, `non-commercial`) and the NOTICE body likewise. The only
hits were the substring `mpl` inside the ordinary Apache words *complies*, *implied*, *compliance* and
*example* — i.e. **zero** real matches.

`THIRD-PARTY-LICENSES.md` states the house rule directly: "Apache-2.0 artifacts and their §4(d)
duties live in `NOTICE`; share-alike sources are quarantined under `data/share-alike/` and appear in
neither file's body."

**Posture: `third_party/`, no quarantine. Correct for Apache-2.0.**

### 2.2 The §4(d) NOTICE duty, and exactly how far it is discharged here

Apache-2.0 §4(d) attaches to **distributing** the Work or a Derivative Work. This packet distributes
no `go-apispec` code (§5), so the duty that is live today is discharged by this directory: the
licence body and the NOTICE body travel with the pin, verbatim, hash-checked in CI.

The moment anybody vendors `go-apispec` **source** under this directory, the duty widens to the
aggregated root `NOTICE`, and D.20's stop condition ("NOTICE aggregation verified") becomes
reachable and required. `TestVendoringGoSourceWouldWidenTheNoticeDuty` in
`internal/dast/inventory/tier2_go_extract_test.go` is that trigger: it fails the build if a `.go`
file appears under `third_party/go-apispec/` while the root `NOTICE` does not carry the body above.
The control is armed now and passes now for a stated, true reason.

**Outstanding, and outside D.20's write scope:** appending this NOTICE body to the root `NOTICE`, and
adding a `go-apispec` row to `THIRD-PARTY-LICENSES.md`. Neither is required until source is vendored;
both are pre-requisites for vendoring it.

---

## 3. Maintenance spike — VENDOR vs FORK

`plan/50-dast.md:1269-1271` left this open: "Whether go-apispec's maintenance state and test coverage
justify VENDORING vs FORKING was not independently assessed here."

Measured on **2026-08-23** from this host. Commit and tag figures come from a full clone of the
repository; issue and PR counts come from the GitHub search API — metadata, which is fine for counting
issues and is **not** what any licence claim above rests on.

| Signal | Measurement | Command |
|---|---|---|
| Last commit on `main` | `2026-06-24T13:00:37+02:00` — **60 days stale** | `git log -1 --format=%cI origin/main` |
| Repo `pushed_at` | `2026-08-21T04:45:10Z` — but this is Dependabot branches, **not `main`** | GitHub API |
| Commits on `main`, total | 289, first `2025-06-25` | `git rev-list --count origin/main` |
| Commits by month | 2025-09: 84 · 2025-11: 40 · 2025-08: 39 · 2025-10: 33 · 2026-04: 32 · 2026-06: 26 · 2026-05: 11 · **2026-07, 2026-08: 0** | `git log --date=format:%Y-%m` |
| Releases | 26 tags, `v0.4.0`…`v0.4.25`; latest `2026-06-17` | `git ls-remote --tags` |
| Release cadence at its peak | 4 tags in one day (`v0.4.18`–`v0.4.21`, 2026-06-13) | tag commit dates |
| Open issues / closed issues / open PRs | 10 / 19 / 3 (2 of the 3 are Dependabot) | GitHub search API |
| Stars / forks | 34 / **0** | GitHub API |
| Authorship | Ehab Terra 173 (the upstream original), Anton Starikov 49, GitHub Action 55, Dependabot 9, two drive-by contributors | `git shortlog -sne origin/main` |
| Test files | 98 `_test.go` of 221 `.go` (44%), across ~92,700 lines of Go | `find`/`wc` at the pin |
| Coverage gate | **`≥95%` per package, enforced in CI**, with `-race`: `go test -race -coverprofile=…` then `scripts/check-coverage.sh` (`DEFAULT_MIN=95.0`) | `.github/workflows/ci.yml:65-73` at the pin |
| Self-reported coverage | 96.2% (README badge — a repo-authored claim, recorded as such) | `README.md:5` at the pin |
| Upstream `ehabterra/apispec` | 84 stars, 48 open issues, `pushed_at 2026-08-21` — **more active than the rewrite** | GitHub API |

### 3.1 Verdict: **VENDOR**, at a pinned commit — do not fork

Three reasons, in order of weight:

1. **Test discipline is genuinely above this project's own bar for a dependency.** A `≥95%`-per-package
   coverage floor enforced in CI under `-race` is not a badge; it is a gate that fails builds. A fork
   inherits the code and *loses the gate*, because the gate lives in the upstream's CI and runs on
   upstream's pushes. Forking to escape a maintenance risk that is mostly *staleness* would trade a
   measured control for an unmeasured one.

2. **The bus factor is 1 and the effective author is not the current maintainer.** 173 of 289 commits
   are Ehab Terra's, from the project this one was rewritten out of; the rewriter has 49; there are
   zero forks. That is a real long-term risk — but it is a risk that a **pin** answers and a **fork**
   does not. A pin means upstream going quiet changes nothing about what Anvil ships. A fork means
   Anvil owns 92,700 lines of type-resolution and control-flow analysis on day one.

3. **Sixty days of silence on `main` is not abandonment, and the shape of the silence matters.** The
   history is bursty by design — 84 commits in 2025-09, 4 releases in one day in 2026-06, then
   nothing for two months. Dependabot PRs are open and unmerged, which is the signal to watch: it is
   the difference between "between bursts" and "gone". **Re-assess if `main` has no commit by
   2026-12-17** (six months past `v0.4.25`), or if the open Dependabot PRs are still unmerged then.

Fork *later*, from the pin, only if that re-assessment comes back dead — and by then Anvil will have
run the vendored pipeline against real repositories and will know which 5% of those 92,700 lines it
actually depends on.

### 3.2 What this assessment does NOT cover

Its test suite was **not executed here**. Running it needs `golang.org/x/tools`, `testify`,
`yaml.v3` and a deprecated `packagestest` module in Anvil's graph (§5), and `-race` on this host
works only from PowerShell. The 96.2% figure is the upstream's own claim, read from its README, and
is recorded as a claim. The `≥95%` gate is not a claim — the enforcing script and its threshold were
read from the workflow file at the pinned commit.

---

## 4. What `go-apispec` would be used for

`plan/50-dast.md` D.20 specifies its pipeline for Tier 2 static route extraction: package load +
type check → AST traversal → call graph from router registration to handler → OpenAPI emission, over
`chi`, `gin`, `net/http`, `echo`, `fiber` and `gorilla/mux`.

`research/22-attack-surface-discovery.md` lines 330–341 are the reason it is a library rather than an
LLM: *"Do not use the SAST LLM to enumerate routes — use deterministic AST tooling."*

`internal/dast/inventory/tier2_go_extract.go` is wired for it: `TypeCheckedExtractor` is the seam,
and `ExtractionModeTypeChecked` selects it. With no extractor wired, that mode **refuses loudly** and
never degrades into an empty route list.

---

## 5. What is NOT vendored, and why

The 221 Go files and ~92,700 lines of `go-apispec` are **not** in this directory. Two measured
blockers, neither of them a matter of taste:

**(a) Gate 3's repository scan reaches this directory — measured, not read off the source.**
`internal/dast/authz/egress_chokepoint_test.go` walks the whole module and treats any import outside
its inert allowlist as egress capability. Its walk skips `.git`, `testdata`, `vendor` and
dot/underscore directories; `third_party` is on none of those lists. Measured on 2026-08-23 by
dropping one throwaway `.go` file into `third_party/go-apispec/probe/` and re-running the gate: the
scanned-file count went **98 → 99**, and removing the file put it back. The walk sees this directory.

The consequence follows from `CheckGate3EgressChokePoint` in
`internal/dast/authz/phase0_build.go:638-660`: a package outside the DAST tree whose imports confer
egress must be covered by `nonKernelEgressAllowlist` or it is a finding. `go-apispec` imports
`golang.org/x/tools`, `gopkg.in/yaml.v3` and `github.com/stretchr/testify`, and none of the three is
on `inertImports`. Vendoring its source therefore requires editing `nonKernelEgressAllowlist` —
outside D.20's write scope, and a widening that deserves its own reviewed diff rather than riding
along inside a vendoring commit. (Limit 5 in that file's header anticipates exactly this for
`vendor/`; `third_party/` reopens it.)

The measurement above could not be observed end-to-end today because gate 3 already fails on an
unrelated pre-existing finding — `internal/dast/inventory/tier1_repospec.go:152 import "encoding/xml"`,
D.19's, with `encoding/xml` absent from `inertImports` — and tier-1 findings are reported first and
short-circuit the tier-2 report. The file-count delta is the part that was measured; the tier-2
verdict is read from the code above and is stated as such.

**(b) `go.mod` and `go.sum` are outside D.20's write scope.** A vendored tree that does not compile is
worse than an absent one: it sits unbuilt, unexercised, and still creates the §4(d) duty in §2.2
against a root `NOTICE` this packet may not write.

Worth flagging beyond scope, because it is a security property and not a packaging one: `go-apispec`'s
pipeline begins with `golang.org/x/tools/go/packages` in a type-checking mode, which **runs `go list`
over the target repository** — module downloads, and with cgo the C toolchain. Against an untrusted
target repository that is a code-execution surface, and it belongs behind D.11's containment rather
than in-process. `TypeCheckedExtractor` being an interface is what leaves room for that.

The extraction that ships **today** is `ExtractionModeSyntactic`, built on `go/ast`, `go/parser` and
`go/token` — all three already on gate 3's inert allowlist, described there as "Go syntax trees" and
"Go source parsing". It parses source as inert bytes, executes nothing, and adds no module to the
graph. It resolves less than the type-checked pipeline would, and every gap is reported as a
`CoverageCaveat` rather than dropped.
