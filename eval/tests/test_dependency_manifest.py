"""Tests over the M0.2 dependency manifest itself.

These guard the two constraints the M0.2 packet names explicitly:
no cgo/Go SQLite dependency has any business in this tree, and no dataset or
model weight is vendored by the scaffold.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

EVAL_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = EVAL_ROOT / "pyproject.toml"


@pytest.fixture(scope="module")
def pyproject() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def test_pyproject_is_valid_toml_and_names_the_package(pyproject: dict) -> None:
    assert pyproject["project"]["name"] == "anvil-eval"
    assert pyproject["project"]["requires-python"].startswith(">=3.")


def test_src_layout_is_declared(pyproject: dict) -> None:
    assert pyproject["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]
    assert (EVAL_ROOT / "src" / "anvil_eval" / "__init__.py").is_file()


def test_no_go_or_cgo_flavoured_dependency_is_declared(pyproject: dict) -> None:
    """Forbidden action (M0.2): no ``mattn/go-sqlite3``, no cgo dependency."""
    declared = list(pyproject["project"]["dependencies"])
    for group in pyproject["project"].get("optional-dependencies", {}).values():
        declared.extend(group)
    lowered = " ".join(declared).lower()
    for banned in ("go-sqlite3", "mattn", "cgo"):
        assert banned not in lowered, f"forbidden dependency token {banned!r} in manifest"


def test_requirements_file_exists_and_is_pinned() -> None:
    """`requirements.txt` is the reproducible pin set for the core+dev install."""
    requirements = EVAL_ROOT / "requirements.txt"
    assert requirements.is_file()
    pins = [
        line.strip()
        for line in requirements.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert pins, "requirements.txt declares no pins"
    for pin in pins:
        assert "==" in pin, f"unpinned requirement: {pin!r}"


def test_scaffold_vendors_no_dataset_or_model_weight() -> None:
    """Forbidden action (M0.2): do not vendor any dataset or model weight.

    Scoped to the paths M0.2 owns — ``eval/data/`` and ``eval/models/`` are
    later steps' write scope and are gitignored payload directories.
    """
    weight_suffixes = {".gguf", ".safetensors", ".onnx", ".bin", ".pt", ".pth", ".h5", ".ckpt"}
    scanned = [EVAL_ROOT / "src", EVAL_ROOT / "tests"]
    offenders = [
        p
        for root in scanned
        for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in weight_suffixes
    ]
    assert offenders == [], f"model/dataset payloads vendored under eval/: {offenders}"
