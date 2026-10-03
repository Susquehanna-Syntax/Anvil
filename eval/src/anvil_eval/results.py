"""Result artifacts and the register rows that quote them.

``write_artifact`` validates against ``eval/schema/result.schema.json`` before anything reaches
disk, so an artifact whose negative control failed is never written. ``record`` copies an
artifact's number into its register row's ``result`` block and marks the row complete. It edits
the YAML text in place, so the register's comments survive, and it never touches ``decision``:
only the owner writes that field.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import yaml

from anvil_eval import REGISTER_PATH, REGISTER_SCHEMA_PATH, REPO_ROOT, SCHEMA_DIR, result_path

RESULT_SCHEMA_PATH = SCHEMA_DIR / "result.schema.json"


class RecordError(RuntimeError):
    """The artifact or the register edit would break a rule the register depends on."""


def git_state(root: Path = REPO_ROOT) -> dict:
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return {"commit": commit, "dirty": bool(dirty)}


def today() -> str:
    return datetime.now(UTC).date().isoformat()


def validate_artifact(doc: dict) -> None:
    schema = json.loads(RESULT_SCHEMA_PATH.read_text("utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(doc), key=str)
    if errors:
        raise RecordError("; ".join(f"{list(e.absolute_path)}: {e.message}" for e in errors[:5]))


def write_artifact(doc: dict, path: Path | None = None) -> Path:
    validate_artifact(doc)
    out = path or result_path(doc["id"])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", "utf-8")
    return out


def _row_span(text: str, rid: str) -> tuple[int, int]:
    start = text.find(f"\n  - id: {rid}\n")
    if start < 0:
        raise RecordError(f"no register row {rid!r}")
    end = text.find("\n  - id: ", start + 1)
    return start, len(text) if end < 0 else end


def record(rid: str, register: Path = REGISTER_PATH, artifact: Path | None = None) -> None:
    """Copy ``eval/results/<rid>.json``'s value into the row's ``result`` and set it complete."""
    art = artifact or result_path(rid)
    doc = json.loads(art.read_text("utf-8"))
    validate_artifact(doc)
    if doc["id"] != rid:
        raise RecordError(f"{art} is the artifact for {doc['id']!r}, not {rid!r}")
    rel = f"eval/results/{rid}.json"  # by convention; ``artifact`` only changes the read
    text = register.read_text("utf-8")
    before = yaml.safe_load(text)
    start, end = _row_span(text, rid)
    row = text[start:end]
    block = (
        "    result:\n"
        f"      value: {json.dumps(doc['value'])}\n"
        f"      unit: {json.dumps(doc['unit'])}\n"
        f"      measured_at: {json.dumps(doc['measured_at'])}\n"
        f"      artifact_path: {json.dumps(rel)}\n"
    )
    row, n = re.subn(r"    result:\n(?:      .*\n){4}", block, row, count=1)
    if n != 1:
        raise RecordError(f"{rid}: the result block is not in the expected four-line shape")
    row, n = re.subn(r"\n    status: \w+\n", "\n    status: complete\n", row, count=1)
    if n != 1:
        raise RecordError(f"{rid}: no status line")
    new = text[:start] + row + text[end:]
    after = yaml.safe_load(new)
    schema = json.loads(REGISTER_SCHEMA_PATH.read_text("utf-8"))
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(after))
    if errors:
        raise RecordError(f"{rid}: the edited register does not validate: {errors[0].message}")
    for b, a in zip(before["experiments"], after["experiments"], strict=True):
        if b["decision"] != a["decision"]:
            raise RecordError(f"{b['id']}: recording a result must never change decision")
        if b["id"] != rid and b != a:
            raise RecordError(f"recording {rid} changed row {b['id']}")
    register.write_text(new, "utf-8")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3 or sys.argv[1] != "record":
        sys.exit("usage: python -m anvil_eval.results record <register-row-id>")
    record(sys.argv[2])
    print(f"{sys.argv[2]}: result recorded; decision left to the owner")
