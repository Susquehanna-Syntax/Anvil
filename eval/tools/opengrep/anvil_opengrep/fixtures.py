"""Materialize the smoke-test sample repo into a throwaway directory.

Why materialize instead of committing the tree as-is: both pinned AikidoSec
rules carry `paths.include` filters on `.github/workflows/**`, so a fixture that
exercises them has to live at that path. Creating a real `.github/workflows/`
directory anywhere inside the Anvil repository would put inert fixture files in
front of every tool that globs `**/.github/workflows` — actionlint, Dependabot,
workflow scanners. So the fixture files are stored flat under `fixtures/` and
assembled into the required layout in a temp directory at scan time.

Second benefit: the materialized tree is not a git repository, and opengrep
defaults to scanning only git-tracked files when the target is one. A plain
directory sidesteps that entirely.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

FIXTURE_SOURCE_DIR = Path(__file__).resolve().parent.parent / "fixtures"

# source filename in fixtures/  ->  path inside the materialized sample repo
SAMPLE_REPO_LAYOUT: dict[str, str] = {
    "workflow_prompt_injection.yml": ".github/workflows/workflow_prompt_injection.yml",
    "workflow_npm_publish.yml": ".github/workflows/workflow_npm_publish.yml",
    "clean_workflow.yml": ".github/workflows/clean_workflow.yml",
    "decoy_app.py": "src/decoy_app.py",
}

# What the pinned ruleset (AikidoSec/opengrep-rules @ 7ac79af) is expected to
# find. Asserted by the smoke test so that a silently-changed pin is caught.
EXPECTED_RULE_IDS: frozenset[str] = frozenset(
    {"github_workflow_prompt_injection", "npm_staged_publishing_missing"}
)

# Files the ruleset must NOT flag. A hit here means misattribution or pin drift.
EXPECTED_CLEAN_PATHS: frozenset[str] = frozenset(
    {".github/workflows/clean_workflow.yml", "src/decoy_app.py"}
)


def materialize_sample_repo(dest: str | Path | None = None) -> Path:
    """Write the sample repo into `dest` (or a fresh temp dir) and return its root.

    The caller owns cleanup when it passes `dest`; when it does not, the
    directory is a `tempfile.mkdtemp` the caller should remove.
    """
    root = (
        Path(dest) if dest is not None else Path(tempfile.mkdtemp(prefix="anvil-opengrep-fixture-"))
    )
    root.mkdir(parents=True, exist_ok=True)
    for source_name, relative in SAMPLE_REPO_LAYOUT.items():
        source = FIXTURE_SOURCE_DIR / source_name
        if not source.is_file():
            raise FileNotFoundError(f"fixture source missing: {source}")
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root
