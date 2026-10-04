# `eval/tools/opengrep` — the deterministic recall tier, pinned

> **Since Phase 6 (2026-10-03)** the engine pinned here (v1.26.0, by SHA-256) is the one Lane B runs, but the
> rule corpus is not: Lane B runs the owner's selection in `data/rules` (GitLab's sast-rules and 0xdea's C rules),
> through `internal/recall`. The Aikido corpus below, two GitHub-workflow rules, is kept only as the acquisition's
> record.

Anvil's **opengrep acquisition** (`plan/design/evaluation.md`). Acquires and invokes the recall-tier
stand-in that the candidates-per-scan instrument (the spine's affordability rule) measures against:

| | Pick | Licence | Pin |
|---|---|---|---|
| Engine | `opengrep/opengrep` | LGPL-2.1 | release tag `v1.26.0`, per-asset sha256 |
| Rules | `AikidoSec/opengrep-rules` | MIT | commit `7ac79affecf709eb7263a243b518a417cd7e0ab2` |

Licence findings, quoted from the LICENSE file bodies, are in [`LICENSES.md`](LICENSES.md). The pins
themselves are in [`MANIFEST.toml`](MANIFEST.toml). **Read `LICENSES.md` section 4 before reading any
the candidates-per-scan instrument number** — the MIT rule corpus is two rules, and that changes what a candidate count means.

## Use

```bash
cd eval/tools/opengrep

python -m anvil_opengrep.acquire --rules      # clone + verify the pinned ruleset (a few KB)
python -m anvil_opengrep.acquire --engine     # download + sha256-verify the engine (~42 MB)
python -m anvil_opengrep.acquire --verify-only  # check what is on disk, download nothing

python smoke.py                               # end-to-end run against the sample repo
python -m pytest tests -q                     # unit tests; smoke tests skip if artefacts absent
```

```python
from anvil_opengrep import OpengrepRunner

result = OpengrepRunner().scan("/path/to/repo")
print(result.candidate_count)                 # the candidates-per-scan instrument quantity
for finding in result.findings:
    print(finding.rule_id, finding.candidate_key)
```

`smoke.py` exit codes: `0` expected candidates, `1` pin drift, `2` engine/ruleset absent, `3` scan failed.

## Subprocess only, never linked

opengrep is an OCaml CLI with **zero bindings in any language** (the spine's Go control-plane decision), so
`subprocess.run` is not a stylistic choice — it is the only mechanism that exists. `runner.py` contains
no FFI, no `ctypes`, no dynamic load. `manifest.py` refuses to load a manifest whose
`engine.linkage` is anything other than `"subprocess"`, so the invariant fails at load time rather
than in review. This is the same line the opengrep runner's design holds on the Go side.

The LGPL obligation that *does* attach — shipping the compiled binary inside a distributed container
image is conveyance — is out of scope here and assigned to the rule vendoring. See `LICENSES.md` section 1.

## Failing loudly

Every failure in this package raises. There is no path that returns an empty finding list because
something was missing:

| Condition | Behaviour |
|---|---|
| engine binary absent / not executable | `EngineNotAvailable` |
| ruleset checkout absent | `RulesetNotAvailable` |
| asset sha256 or rule blob SHA mismatch | `ChecksumMismatch`, never retried |
| exit code outside `{0, 1}` | `OpengrepRunError` with stderr attached |
| no SARIF written, or unparseable | `OpengrepOutputError` |
| `--config` naming an S5-excluded repo | `ForbiddenRuleSource` |

The reason is narrow and specific. The candidates-per-scan instrument reads candidate counts as a measurement. If a missing
binary could produce "0 candidates", a broken install and a genuinely clean repo would be recorded
identically, and the experiment would be quietly worthless. So `ScanResult.findings == ()` means
exactly one thing: the pinned engine ran the pinned rules over the target and matched nothing.

## The spine's hard exclusions, enforced in code

The spine's exclusion list excludes `opengrep/opengrep-rules` (archived, `NOASSERTION`, LGPL-2.1 +
Commons Clause) and every Semgrep-maintained ruleset (internal business use only).
`manifest.assert_rule_source_permitted()` runs against the manifest at load time **and** against
whatever `ruleset_path` a caller actually hands `OpengrepRunner`, because an exclusion enforced only
on the happy path is not enforced. `tests/test_manifest.py` covers both repos and both path
separators.

One consequence worth knowing: the vendored ruleset directory is deliberately named
`vendor/aikido-opengrep-rules/`, not `vendor/opengrep/opengrep-rules/`, since the latter contains the
excluded slug as a substring and the guard would refuse it.

## The fixture is materialized, not committed

Both pinned rules carry `paths.include` filters on `.github/workflows/**`, so a fixture that exercises
them must live at that path. Rather than create a real `.github/workflows/` directory inside the Anvil
repository — where actionlint, Dependabot, and anything globbing `**/.github/workflows` would find
inert fixture files — the fixtures are stored flat in `fixtures/` and assembled into the required
layout in a temp directory at scan time by `anvil_opengrep.fixtures.materialize_sample_repo()`.

That also avoids a subtler trap: opengrep scans **only git-tracked files** when the target is a git
repository. A fixture sitting untracked inside this repo would be silently skipped. A freshly
materialized plain directory is not a git repo, so everything in it is scanned.

The sample repo carries two positive cases (one per rule), one clean workflow, and `src/decoy_app.py`
— an unguarded command injection that the pinned ruleset is *expected not to find*. That non-result
is the coverage finding from `LICENSES.md` section 4 in executable form.

## Layout

```
MANIFEST.toml            pins: release tag, per-asset sha256, ruleset commit + blob SHAs, the spine's hard exclusions
LICENSES.md              licence findings quoted from LICENSE bodies; the coverage finding
smoke.py                 end-to-end driver
anvil_opengrep/
  manifest.py            parse + validate the pins; the hard-exclusion guard
  acquire.py             pinned fetch + checksum verification (nothing runs on import)
  runner.py              subprocess wrapper; SARIF 2.1.0 parsing
  fixtures.py            materializes the sample repo
  errors.py              every failure mode
fixtures/                flat fixture sources
tests/                   unit tests + the smoke test (skips loudly without artefacts)
vendor/                  acquired artefacts — gitignored, never committed
```
