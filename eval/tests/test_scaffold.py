"""Scaffold tests for the Anvil evaluation harness (M0.2).

These are deliberately offline and dependency-light: they assert that the
package imports, that its declared on-disk layout is self-consistent, and that
the S12 carve-out is honoured (``eval/`` is a pure-Python tree — no Go sources).
Later M0 packets add their own test modules alongside this one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import anvil_eval

#: Paths this packet (M0.2) owns. Scans below are scoped to these so that they
#: stay fast and do not fail on artifacts legitimately produced by later steps
#: (e.g. M0.6's model downloads under ``eval/models/``).
SCAFFOLD_PATHS = ("pyproject.toml", "requirements.txt", ".gitignore", "src", "tests")


def test_package_imports_and_declares_a_version() -> None:
    assert isinstance(anvil_eval.__version__, str)
    assert anvil_eval.__version__.count(".") == 2, "expected a MAJOR.MINOR.PATCH version"


def test_eval_root_resolves_to_this_checkout() -> None:
    """EVAL_ROOT must point at the ``eval/`` tree containing this test file."""
    expected = Path(__file__).resolve().parents[1]
    assert anvil_eval.EVAL_ROOT == expected
    assert (anvil_eval.EVAL_ROOT / "pyproject.toml").is_file()


def test_declared_subtrees_live_under_eval_root() -> None:
    """Every canonical directory constant must be inside ``eval/``.

    Later steps write results and manifests through these constants; if one of
    them ever escaped the eval tree it would write into the Go control plane.
    """
    subtrees = [
        anvil_eval.DATA_DIR,
        anvil_eval.MODELS_DIR,
        anvil_eval.TOOLS_DIR,
        anvil_eval.RESULTS_DIR,
        anvil_eval.NOTES_DIR,
        anvil_eval.HARNESS_DIR,
        anvil_eval.SCHEMA_DIR,
        anvil_eval.REGISTER_PATH,
        anvil_eval.REGISTER_SCHEMA_PATH,
    ]
    for path in subtrees:
        assert path.is_relative_to(anvil_eval.EVAL_ROOT), f"{path} escapes EVAL_ROOT"


def test_result_path_matches_the_registers_artifact_path_convention() -> None:
    """`plan/10-milestone0-evaluation.md` specifies ``eval/results/<id>.json``."""
    for experiment_id in ("EXP-01", "EXP-12", "INSTR-01", "S12-RTT"):
        path = anvil_eval.result_path(experiment_id)
        assert path.parent == anvil_eval.RESULTS_DIR
        assert path.name == f"{experiment_id}.json"


def test_result_path_rejects_an_empty_id() -> None:
    with pytest.raises(ValueError):
        anvil_eval.result_path("   ")


def _scaffold_files() -> list[Path]:
    files: list[Path] = []
    for name in SCAFFOLD_PATHS:
        target = anvil_eval.EVAL_ROOT / name
        if target.is_file():
            files.append(target)
        elif target.is_dir():
            files.extend(p for p in target.rglob("*") if p.is_file())
    return files


def test_scaffold_contains_no_go_sources() -> None:
    """S12 carve-out #3: the evaluation harness is a pure-Python tree.

    The M0.2 packet is explicit that "no Go code belongs in ``eval/`` at all".
    """
    offenders = [
        p
        for p in _scaffold_files()
        if p.suffix == ".go" or p.name in {"go.mod", "go.sum"}
    ]
    assert offenders == [], f"Go artifacts found under eval/: {offenders}"
