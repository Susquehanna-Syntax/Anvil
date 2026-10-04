"""Anvil Milestone 0 evaluation harness.

This package is a **pure-Python** tree. It exists under the third of the three
carve-outs in the spine's Go control-plane decision (``plan/design/spine.md``, "Where
Python survives — exactly three places, none of them control-plane runtime"): *the
evaluation harness and KL-divergence quantisation checks*. No Go code belongs here, and
nothing in this tree is part of the Anvil control plane.

The package provides the shared skeleton that every later Milestone 0 step
builds on:

* ``anvil_eval.data``     — corpus loaders (PrimeVul, CWE-Bench-Java)
* ``anvil_eval.harness``  — experiment runners (the evaluation experiments)

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

# Canonical sub-trees. These paths are the contract between evaluation steps; a step
# that writes somewhere else breaks the register's ``artifact_path`` fields.
DATA_DIR: Path = EVAL_ROOT / "data"          # corpora, e.g. PrimeVul — gitignored payloads
MODELS_DIR: Path = EVAL_ROOT / "models"      # candidate models: pinned manifests, not weights
TOOLS_DIR: Path = EVAL_ROOT / "tools"        # opengrep engine + pinned ruleset
RESULTS_DIR: Path = EVAL_ROOT / "results"    # eval/results/<ID>.json, committed
NOTES_DIR: Path = EVAL_ROOT / "notes"        # licence findings and critic verdicts
HARNESS_DIR: Path = EVAL_ROOT / "harness"    # experiment runner scripts
SCHEMA_DIR: Path = EVAL_ROOT / "schema"      # register JSON Schema

#: The experiment register (updated by the register roll-up and by the gate decision).
REGISTER_PATH: Path = EVAL_ROOT / "register.yaml"

#: JSON Schema the register validates against.
REGISTER_SCHEMA_PATH: Path = SCHEMA_DIR / "register.schema.json"


def result_path(experiment_id: str) -> Path:
    """Return the canonical result artifact path for an experiment ID.

    The register's ``result.artifact_path`` field is specified as
    ``eval/results/<id>.json`` in ``plan/design/evaluation.md``; every
    experiment step must write there and nowhere else.

    >>> result_path("advisory-permutation").name
    'advisory-permutation.json'
    """
    experiment_id = experiment_id.strip()
    if not experiment_id:
        raise ValueError("experiment_id must be a non-empty string")
    return RESULTS_DIR / f"{experiment_id}.json"
