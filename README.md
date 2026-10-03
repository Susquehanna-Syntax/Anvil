# Anvil

An open-source, **profit-free**, self-hostable system that finds vulnerabilities in Linux servers and
code repositories and proposes fixes — using locally-served open-weight models, and never browsing the
live web at inference time.

**Status (2026-10-03): Phases 0–4 of 10 are built; Phase 5, the evaluation that gates the model tier, is
next.** `anvil scan` runs Lane A end to end: it matches a repository (through Trivy) or a host inventory
(through Anvil's own comparator) against the advisory cache, seals the SAST half, writes the record and its
findings to the store, marks each finding new, persisting, regressed or fixed against earlier scans, and writes
the record as SARIF 2.1.0. What is not built yet: Lane B's model tier (it waits on the evaluation), remediation,
the dynamic tier running live (it is built but has never touched a kernel or a target), and the release packages.
A fresh clone admits no real advisory feed until an operator acquires and certifies the publishers' licence
texts (`mirror/README.md`); `testdata/lanea-fixture` is an offline snapshot that proves the chain without one.

## Try it on the fixture

```bash
go build -o anvil ./cmd/anvil
printf 'version: 1\nstateDir: state\n' > anvil.yml
export ANVIL_CONFIG=$PWD/anvil.yml
./anvil feeds import testdata/lanea-fixture
./anvil scan --host --inventory testdata/lanea-fixture/host/inventory-1.json --out host.sarif
./anvil scan --host --inventory testdata/lanea-fixture/host/inventory-2.json
./anvil findings
```

`sh test/e2e/fixture.sh` runs the same sequence, plus a repository scan, and asserts every exit status. Exit
statuses: 0 clean, 1 findings, 2 usage, 3 refused, 4 missing tool, 5 error; a refusal or a missing tool is never 0.

## What it does

Two detection lanes, one audit record, and a remediation tier that proposes and never merges.

- **Lane A — deterministic, zero inference.** SBOM and host-package matching by version comparator.
  Owns dependency and host findings. CVE/OSV/GHSA describe vulnerable *package versions*, and a version
  comparator answers that exactly, for free.
- **Lane B — first-party source.** A deterministic recall tier produces candidates and a small model
  adjudicates a short candidate list. It never forms the N×M cross product of advisories against code.
- **Dynamic tier.** Ships as a **separate artifact** (`anvil-dast`), separately installed, requiring
  explicit attestation before it probes anything.
- **Remediation.** Proposes patches. It does not merge them.

## Three rules that are enforced in code, not documentation

1. **Never auto-merge a patch.** The best measured security-patch rate on real CVEs is 34.0%.
2. **Only a DAST reproduction that now fails earns "verified fixed."** A clean SAST rescan does not:
   detectors reach 10.16–13.82% true-positive on vulnerabilities that survive an incomplete patch.
3. **The host agent is read-only.** No package manager in a mutating mode — not behind a flag.

## Two artifacts, and why

| Artifact | Contains |
|---|---|
| `anvil` | Lane A, Lane B, record, store, remediation. **No network-probing capability compiled in.** |
| `anvil-dast` | The dynamic tier. Separate release, separate install, explicit attestation. |

This is a split in the build, not a configuration flag, because a boolean inside a single shipped
binary still supplies the probing capability to everyone who installs it. `TestSplit` in
[`cmd/anvil/split_test.go`](cmd/anvil/split_test.go) fails the build if any DAST package becomes
reachable from the core binary's import graph, and CI additionally injects a violation on every run to
prove the guard can still fail. A guard that has never failed has not been tested.

## Hardware tiers

| Tier | Machine | What runs |
|---|---|---|
| **S** | 8 GB / 4 core, no GPU | SAST only; coding agent remote; DAST not installed |
| **M** | 32 GB / 8 core | SAST + DAST against declared ephemeral targets; coding agent remote |
| **L** | 64 GB+ / GPU | everything local |

## Build

Go 1.26+, no cgo, no C toolchain — [`modernc.org/sqlite`](https://modernc.org/sqlite) translates SQLite
to Go, so the static binary and the cross-compilation matrix both hold.

```bash
go build ./...
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/anvil
```

## Data sources

Advisory data reaches the cache only through the licence gate: a feed is admitted when the publisher's own licence
text has been acquired, read, and pinned by digest in `mirror/LICENSE-MANIFEST.toml`, and share-alike sources are
quarantined in tier 2.

**The Trivy database is off by default** (the owner's decision of 2026-10-03). Trivy decides repository
dependencies against its own database, which aggregates share-alike sources (Ubuntu, Alpine) that tier 2
quarantines, and whose publishers state no redistribution terms. Repository SCA therefore runs only when the
operator's configuration says `trivyDB: {enabled: true}`, and every finding it produces carries tier-2 attribution
(`LicenseRef-Anvil-TrivyDB-Tier2`, source `trivy-db/<upstream>`). With it off, `anvil scan --repo` exits 3, never 0.

## Licence

Apache-2.0 — see [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), and
[`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).

Apache was chosen for the one-way valve (Apache can flow into GPL/AGPL later, never the reverse) and for
the §4 NOTICE mechanism, which matches Anvil's long attribution list. **It was not chosen for the patent
grant**, which runs from contributors over their own contributions and is not a freedom-to-operate
instrument; `NOTICE` §6 records the third-party patent exposure that remains open.

Every licence in this repository was determined by **reading the LICENSE file body, never registry
metadata** — seven artifacts in the audit return `NOASSERTION` over a real licence, and one hides a
restrictive licence behind a permissive tag.

## A note on what is not in this repository

The design corpus (`research/`) and the implementation plan and its verification tooling (`plan/`,
`tools/`) are **deliberately not distributed**. They are how Anvil was designed and verified, not
something a user of Anvil needs. Source comments and commit messages cite them by path; those paths
resolve in the maintainer's working tree, not in a clone. That is intentional, and the citations are
kept because a reader is better served by knowing a decision has a recorded justification than by
seeing an unexplained assertion.
