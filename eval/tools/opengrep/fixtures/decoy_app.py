"""FIXTURE — the coverage control. Materialized at src/decoy_app.py.

This file contains a textbook command-injection sink. The pinned AikidoSec
ruleset is expected to produce ZERO findings on it, because at commit
7ac79af that ruleset is two YAML-only rules filtered to .github/workflows and
.github/actions and covers no general-purpose source language.

That non-result is the point. It is the executable form of the coverage finding
in LICENSES.md section 4: the recall tier's engine can analyse Python, but its
MIT rule corpus does not.
"""

import os
import subprocess


def run_report(user_supplied: str) -> None:
    # Command injection. Deliberately unguarded. Nothing here is imported or run.
    os.system("generate-report " + user_supplied)  # noqa: S605
    subprocess.run(f"archive {user_supplied}", shell=True, check=False)  # noqa: S602
