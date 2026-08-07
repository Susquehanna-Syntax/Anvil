"""The experiment register must validate, and an unrun row must never read as a pass.

plan step M0.18 reads eval/register.yaml and decides whether Anvil's detection-model
tier exists at all. Two rows -- EXP-01 (advisory-permutation ablation) and EXP-02
(code-metrics baseline) -- can delete that tier entirely.

That makes exactly one property load-bearing: **a row whose experiment has not been
run must be impossible to confuse with a row that passed.** Everything else in the
register is bookkeeping; this is the safety property.

These tests exist because the register and its schema shipped with nothing anywhere
in the repository actually checking one against the other -- the validation was run
once, by hand, at authoring time. A schema nobody runs is a comment.

The negative cases are mutation tests. Each one takes the real register, introduces
one specific way an undecided row could be made to read as decided, and asserts the
schema rejects it. The `deferred` case is here because it was a real bug: the guard
originally covered not_started/in_progress/blocked and omitted deferred, so EXP-05
could be set to PASS and validation accepted it.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

EVAL_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = EVAL_ROOT / "schema" / "register.schema.json"
REGISTER_PATH = EVAL_ROOT / "register.yaml"

# The fourteen rows the plan requires. Named explicitly rather than counted, so a
# row being renamed fails loudly instead of silently keeping the count right.
REQUIRED_IDS = [
    *(f"EXP-{n:02d}" for n in range(1, 13)),
    "INSTR-01",
    "S12-RTT",
]

# Any status meaning "this experiment has not produced an adjudicated outcome".
UNRUN_STATUSES = ["not_started", "in_progress", "blocked", "deferred"]


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def register() -> dict:
    return yaml.safe_load(REGISTER_PATH.read_text(encoding="utf-8"))


def _rows(register: dict) -> list[dict]:
    """The register may carry its rows under a key or as a bare list."""
    if isinstance(register, dict):
        for key in ("experiments", "rows", "register"):
            if isinstance(register.get(key), list):
                return register[key]
        raise AssertionError(f"no row list found in register keys: {sorted(register)}")
    return register


def _errors(schema: dict, doc: dict) -> list:
    return list(jsonschema.Draft202012Validator(schema).iter_errors(doc))


def test_schema_is_itself_valid(schema: dict) -> None:
    jsonschema.Draft202012Validator.check_schema(schema)


def test_register_validates(schema: dict, register: dict) -> None:
    errors = _errors(schema, register)
    assert not errors, "register.yaml does not validate:\n" + "\n".join(
        f"  {list(e.absolute_path)}: {e.message}" for e in errors
    )


def test_all_fourteen_rows_present_exactly_once(register: dict) -> None:
    ids = [r["id"] for r in _rows(register)]
    assert sorted(ids) == sorted(REQUIRED_IDS), (
        f"missing={sorted(set(REQUIRED_IDS) - set(ids))} "
        f"unexpected={sorted(set(ids) - set(REQUIRED_IDS))}"
    )
    assert len(ids) == len(set(ids)), "duplicate row ids"


def test_no_row_has_a_null_absent_or_empty_decision(register: dict) -> None:
    """The sentinel must be explicit. Absence is the failure mode being prevented."""
    for row in _rows(register):
        assert "decision" in row, f"{row['id']}: decision key absent"
        assert row["decision"] not in (None, ""), f"{row['id']}: decision is null/empty"


def test_every_unrun_row_is_unresolved(register: dict) -> None:
    for row in _rows(register):
        if row["status"] in UNRUN_STATUSES:
            assert row["decision"] == "UNRESOLVED", (
                f"{row['id']} has status={row['status']} but decision={row['decision']!r}. "
                "An experiment that has not run cannot carry an adjudicated outcome."
            )


@pytest.mark.parametrize("status", UNRUN_STATUSES)
def test_schema_rejects_a_pass_on_an_unrun_row(schema: dict, register: dict, status: str) -> None:
    """Mutation test, one per unrun status.

    This is the test that would have caught the `deferred` hole: the guard covered
    three of the four unrun statuses, so a deferred row could be marked PASS.
    """
    mutated = copy.deepcopy(register)
    rows = _rows(mutated)
    rows[0]["status"] = status
    rows[0]["decision"] = "PASS"
    # A deferred row carries its own extra obligations; satisfy them so the only
    # reason validation can fail is the decision itself.
    if status == "deferred":
        rows[0]["deferred_reason"] = "mutation test"
        rows[0]["owner_step"] = "deferred"

    assert _errors(schema, mutated), (
        f"schema ACCEPTED decision=PASS on a status={status} row. "
        "An unadjudicated row can be made to read as a pass."
    )


@pytest.mark.parametrize(
    "field,value",
    [("decision", None), ("decision", ""), ("decision", "OK")],
)
def test_schema_rejects_malformed_decisions(
    schema: dict, register: dict, field: str, value
) -> None:
    mutated = copy.deepcopy(register)
    _rows(mutated)[0][field] = value
    assert _errors(schema, mutated), f"schema accepted {field}={value!r}"


def test_schema_rejects_a_deleted_row(schema: dict, register: dict) -> None:
    mutated = copy.deepcopy(register)
    del _rows(mutated)[0]
    assert _errors(schema, mutated), "schema accepted a register with a row removed"
