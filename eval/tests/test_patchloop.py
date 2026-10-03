"""The patch-quality loop on a synthetic C case with a real build, real tests and a real oracle.

Each fake coder is built to land on one outcome, so every branch is seen, including the ones
that must not count as fixed: a patch that builds and passes the tests but still overflows is
``exploit_still_triggers``, never ``verified_fixed``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from anvil_eval import patchloop

FIXTURE = Path(__file__).parent / "fixtures" / "patch" / "overflow"
VULN = "    strcpy(buf, name);"


@pytest.fixture
def case(tmp_path):
    root = tmp_path / "overflow"
    shutil.copytree(FIXTURE, root)
    for cmd in (["init", "-q"], ["add", "."], ["-c", "user.email=t@example.invalid", "-c",
                                               "user.name=t", "commit", "-qm", "case"]):
        subprocess.run(["git", "-C", str(root), *cmd], check=True)
    return patchloop.Case(
        id="synthetic-overflow", root=root, file="greet.c",
        finding="CWE-121: stack-based buffer overflow in greet(): strcpy into a 16-byte buffer",
        build=["cc", "-fsanitize=address", "-g", "-o", "greet", "greet.c"],
        test=["sh", "test.sh"], oracle=["sh", "oracle.sh"], timeout=120,
    )


def edit(search: str, replace: str) -> str:
    return f"<<<<<<< SEARCH\n{search}\n=======\n{replace}\n>>>>>>> REPLACE\n"


REPLIES = {
    "verified_fixed": edit(VULN, '    snprintf(buf, sizeof buf, "%s", name);'),
    # Builds and passes the tests, and leaves the overflow in place.
    "exploit_still_triggers": edit('    printf("hello %s\\n", buf);',
                                   '    printf("hello %s\\n", buf);\n    fflush(stdout);'),
    "build_fail": edit(VULN, "    strcpy(buf, name"),
    "test_fail": edit(VULN, '    snprintf(buf, 3, "%s", name);'),
    "apply_fail": edit("    strcpy(buf, nme);", "    /* nothing */"),
    "no_patch": "The code looks fine to me.",
}


@pytest.mark.parametrize("expected", list(REPLIES))
def test_each_outcome_is_reachable(case, expected):
    out = patchloop.attempt(case, lambda msgs: REPLIES[expected])
    assert out.outcome == expected, (out.detail, out.steps)
    # The checkout is restored whatever happened.
    status = subprocess.run(["git", "-C", str(case.root), "status", "--porcelain"],
                            capture_output=True, text=True, check=True).stdout
    assert status == ""


def test_without_an_oracle_a_good_patch_is_unverified_not_fixed(case):
    case.oracle = None
    out = patchloop.attempt(case, lambda msgs: REPLIES["verified_fixed"])
    assert out.outcome == "unverified"


def test_a_search_that_matches_twice_is_refused():
    with pytest.raises(patchloop.ApplyError, match="2 times"):
        patchloop.apply_edits("a\nb\na\n", [("a", "c")])


def test_the_prompt_carries_the_file_and_marks_it_untrusted(case):
    msgs = patchloop.prompt(case)
    assert "untrusted data" in msgs[0]["content"] and VULN in msgs[1]["content"]


def test_summary_rates_and_the_oracle_denominator():
    outs = [patchloop.Outcome(str(i), o) for i, o in enumerate(
        ["verified_fixed", "exploit_still_triggers", "build_fail", "no_patch"])]
    s = patchloop.summarise(outs, oracle_cases=4)
    assert s["verified_fix_rate"] == 0.25 and s["build_pass_rate"] == 0.5
    assert patchloop.summarise(outs, 0)["verified_fix_rate"].startswith("not measurable")
