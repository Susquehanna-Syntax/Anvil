# M0.7 — licence findings for the deterministic recall tier

Every claim below was fetched in-session on **2026-08-06** from a primary source and is quoted from
the LICENSE file body, not from an API `license` metadata field. Where an API field is cited it is
cited as corroboration only, never as the finding. This follows `plan/00-SPINE.md` S8's compliance
mechanic ("reads LICENSE file bodies, never API metadata") and the verification discipline in
`research/13-license-compatibility-audit.md` / `research/14-critique-and-gaps.md`.

---

## 1. Engine — `opengrep/opengrep` @ `v1.26.0` — **LGPL-2.1**

**Fetched:** `https://raw.githubusercontent.com/opengrep/opengrep/v1.26.0/LICENSE`
(504 lines; the pin is the tag, so the fetch is reproducible.)

Opening lines of the LICENSE body, verbatim:

```
                  GNU LESSER GENERAL PUBLIC LICENSE
                       Version 2.1, February 1999

 Copyright (C) 1991, 1999 Free Software Foundation, Inc.
```

**Finding: LGPL-2.1.** Consistent with `plan/00-SPINE.md` S4 and with
`research/10-prior-art-and-landscape.md` [S11] ("`opengrep/opengrep` is **LGPL-2.1**, ~9,931 commits,
forked from Semgrep at version 1.100.0").

**Release pin (GitHub Releases API, `/repos/opengrep/opengrep/releases/latest`):**

| Field | Value |
|---|---|
| Tag | `v1.26.0` |
| Tagged commit | `1bef4ea4ff3264754132eec823b5b1d8cde3e4ee` |
| Published | 2026-07-24T20:00:53Z |
| Prerelease | false |

### Linkage posture — this is the whole compliance argument, and it is short

opengrep is an **OCaml CLI with zero bindings in any language** (`plan/00-SPINE.md` S12). There is no
FFI surface to link against even if someone wanted to. Anvil therefore `exec`s the binary and reads
its stdout. No cgo, no shared object, no static link, no in-process plugin. LGPL-2.1's combined-work
obligations (§6) are about works that *link* the library; a program that shells out to a separate
executable and talks to it over a pipe is not one. `plan/30-lane-b-detection.md` B.1 makes the
subprocess-only rule a build-enforced invariant on the Go side; this evaluation harness holds the
same line by construction — `anvil_opengrep/runner.py` only ever calls `subprocess.run`.

### The obligation that *does* attach, and is deferred, not dismissed

If Anvil ever **distributes** the compiled opengrep binary — e.g. bakes it into a published container
image — that is conveyance of an LGPL-2.1 work and triggers notice + offer-of-source duties for the
opengrep binary itself. That is out of scope for M0.7 (the harness fetches the binary at setup time on
the operator's own machine and ships nothing), and it is already assigned: `plan/30-lane-b-detection.md`
B.2 owns `data/LICENSES/opengrep-binary-distribution.md`. Recorded here so the deferral is a decision
and not an oversight.

---

## 2. Ruleset — `AikidoSec/opengrep-rules` @ `7ac79af` — **MIT**

**Fetched:**
`https://raw.githubusercontent.com/AikidoSec/opengrep-rules/7ac79affecf709eb7263a243b518a417cd7e0ab2/LICENSE`
(1075 bytes, sha256 `3053445ee21294dbf1c714f45c0808aa3bb29ee60e0737efde63bcbb523ac8c8`, git blob
`b48a9af2d18b4847a0cfa4882d4aafa180052543`). The URL pins the **commit**, so this is the licence text
of the exact tree Anvil uses, not of whatever `main` becomes later.

Verbatim from the LICENSE body:

```
MIT License

Copyright (c) 2025 Aikido Security BV

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
```

**Finding: MIT.** No field-of-use restriction, no Commons Clause rider, no non-commercial clause. The
grant explicitly includes `distribute` and `sublicense`, so vendoring the rules into an Apache-2.0
project is clean, subject only to MIT's attribution condition (retain the copyright notice and the
permission notice — `acquire.py` copies `LICENSE` into every checkout for exactly that reason).

Corroborating metadata (`/repos/AikidoSec/opengrep-rules`, fetched in-session, **not** the finding):
`license.spdx_id = "MIT"`, `archived = false`, `default_branch = "main"`,
`pushed_at = 2026-06-04T16:08:29Z`, 37 stars. This matches `research/10` [S13] and `research/14` M6.

**Pinned commit:** `7ac79affecf709eb7263a243b518a417cd7e0ab2` (2026-06-04T16:06:22Z, "Merge pull
request #2 from AikidoSec/kapyteinaikido-patch-1"). This is the current `main` head; the repo has 7
commits total, one branch, and zero tags, so there is no release to pin to and the commit SHA is the
only stable handle.

Each rule file also carries its own in-band licence declaration, which is unusual and worth recording
— `rules/github_workflow_prompt_injection/github_workflow_prompt_injection.yaml` contains:

```yaml
    license: MIT License (https://github.com/AikidoSec/opengrep-rules/blob/main/LICENSE)
```

---

## 3. Excluded — recorded so nobody re-adds them

### `opengrep/opengrep-rules` — **HARD EXCLUDED**, `plan/00-SPINE.md` S5

Re-verified in-session 2026-08-06 via `/repos/opengrep/opengrep-rules`, independently reproducing all
four values from `research/10` [S12] and `research/14` (V6):

| Field | Observed 2026-08-06 |
|---|---|
| `archived` | `true` |
| `license.spdx_id` | `NOASSERTION` |
| `stargazers_count` | 6 |
| `pushed_at` | 2025-11-28T13:17:29Z |

Its LICENSE is LGPL-2.1 **plus a Commons Clause rider** removing the right to Sell the Software.
Commons Clause is not OSI-approved; redistributing these rules inside an OSI-licensed project is a
licence conflict. It is not used, not fetched, and not referenced by any code path here. The only
reason it appears in this repository at all is as a named exclusion in `MANIFEST.toml [[excluded.repos]]`,
so that a future contributor reaching for "the obvious substitute" hits a wall with a reason on it.

### Semgrep-maintained rules — **HARD EXCLUDED**, `plan/00-SPINE.md` S5

Semgrep Rules License v.1.0 permits use "only for your own internal business purposes" and forbids
distribution. Out in every form, including rules derived by reading them.

---

## 4. Coverage finding — measured, and it is the thing to actually worry about

The licence question on `AikidoSec/opengrep-rules` is settled and clean. The **coverage** question is
not, and M0.7 measured it rather than assuming it. At the pinned commit the entire repository is:

```
LICENSE
README.md
rules/github_workflow_prompt_injection/github_workflow_prompt_injection.yaml
rules/npm_staged_publishing_missing/npm_staged_publishing_missing.yaml
```

Two rules. Both `languages: [yaml]`. Both `paths.include`-filtered to `.github/workflows/**` and
`.github/actions/**`. Neither performs taint analysis. Neither looks at application source code in any
language Anvil targets.

`research/10` already hedged this — "Small and low-visibility, but legally unambiguous... rule coverage
unassessed" [S13] — and `plan/30-lane-b-detection.md` open issue 6 states outright that first-party
coverage "is unverified anywhere in" the corpus. This is the verification. The result is that the
recall tier's *rule corpus*, as picked, is a two-rule GitHub-Actions linter.

This does **not** contradict `plan/00-SPINE.md` S4 or S5 on licence grounds — the picks are correct and
the exclusions hold. It bears on what INSTR-01 (candidates-per-scan, `plan/10-milestone0-evaluation.md`
M0.11) will actually measure: against this corpus, a repo with no GitHub Actions workflows yields
exactly zero candidates, and the adjudicator-precision case that `research/14` M6 says rests on this
tier existing has almost nothing to adjudicate. The engine is not the problem — opengrep's taint
support is real. The MIT rule corpus is the problem.

Escalated to the orchestrator, not resolved here: M0.7's scope is acquisition, and choosing a different
or additional rule source is an S4/S5 component decision that this packet may not make.
