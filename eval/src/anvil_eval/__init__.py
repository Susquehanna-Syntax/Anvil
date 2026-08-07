"""Anvil Milestone 0 evaluation harness.

This package is a **pure-Python** tree. It exists under the third of the three
carve-outs in ``plan/00-SPINE.md`` S12 ("Where Python survives — exactly three
places, none of them control-plane runtime"): *the evaluation harness and
KL-divergence quantisation checks*. No Go code belongs here, and nothing in this
tree is part of the Anvil control plane.

The package provides the shared skeleton that every later Milestone 0 step
builds on:

* ``anvil_eval.data``     — corpus loaders (M0.3 PrimeVul, M0.4 ARVO, M0.5 CWE-Bench-Java)
* ``anvil_eval.harness``  — experiment runners (M0.9…M0.16)

Those submodules are written by later packets; this module only fixes the
version, the on-disk layout, and the small helpers that keep every step
pointing at the same directories.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "__version__",
    "EVAL_ROOT",
    "REPO_ROOT",
    "DATA_DIR",
    "MODELS_DIR",
    "TOOLS_DIR",
    "RESULTS_DIR",
    "NOTES_DIR",
    "HARNESS_DIR",
    "SCHEMA_DIR",
    "REGISTER_PATH",
    "REGISTER_SCHEMA_PATH",
    "result_path",
]

__version__ = "0.1.0"

#: Root of the ``eval/`` tree. Resolved from this file's location so it is
#: correct for an editable install (``pip install -e eval/``) regardless of the
#: process working directory.
EVAL_ROOT: Path = Path(__file__).resolve().parents[2]

#: Repository root (the parent of ``eval/``).
REPO_ROOT: Path = EVAL_ROOT.parent

# Canonical sub-trees. These paths are the contract between M0 steps; a step
# that writes somewhere else breaks the register's ``artifact_path`` fields.
DATA_DIR: Path = EVAL_ROOT / "data"          # M0.3, M0.4, M0.5 — gitignored payloads
MODELS_DIR: Path = EVAL_ROOT / "models"      # M0.6 — pinned-download manifests, not weights
TOOLS_DIR: Path = EVAL_ROOT / "tools"        # M0.7 — opengrep engine + pinned ruleset
RESULTS_DIR: Path = EVAL_ROOT / "results"    # eval/results/<ID>.json, committed
NOTES_DIR: Path = EVAL_ROOT / "notes"        # licence findings and critic verdicts
HARNESS_DIR: Path = EVAL_ROOT / "harness"    # experiment runner scripts
SCHEMA_DIR: Path = EVAL_ROOT / "schema"      # M0.1 — register JSON Schema

#: The experiment register (authored by M0.1, updated by M0.17/M0.18).
REGISTER_PATH: Path = EVAL_ROOT / "register.yaml"

#: JSON Schema the register validates against (authored by M0.1).
REGISTER_SCHEMA_PATH: Path = SCHEMA_DIR / "register.schema.json"


def result_path(experiment_id: str) -> Path:
    """Return the canonical result artifact path for an experiment ID.

    The register's ``result.artifact_path`` field is specified as
    ``eval/results/<id>.json`` in ``plan/10-milestone0-evaluation.md``; every
    experiment step must write there and nowhere else.

    >>> result_path("EXP-01").name
    'EXP-01.json'
    """
    experiment_id = experiment_id.strip()
    if not experiment_id:
        raise ValueError("experiment_id must be a non-empty string")
    return RESULTS_DIR / f"{experiment_id}.json"
