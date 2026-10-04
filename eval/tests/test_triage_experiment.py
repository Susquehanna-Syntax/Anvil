"""The triage-precision harness's bookkeeping: selection, Juliet's labels, scoring.

The model run is deferred (every GPU run waits until after Phase 9, the owner's decision of
2026-10-04); the stub-endpoint control that drives ``anvil triage`` needs the recall tools and
runs inside every real report.
"""

from __future__ import annotations

from anvil_eval.experiments import triage as tp

C_CASE = """#include "std_testcase.h"

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_01_bad()
{
    char * data;
    strcpy(data, source);
}

#endif /* OMITBAD */

static void goodG2B()
{
    strcpy(data, source);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_01_good()
{
    goodG2B();
}

int main(int argc, char * argv[])
{
    printLine("x");
}
"""

JAVA_CASE = """package testcases.CWE327_Use_Broken_Crypto;

public class CWE327_Use_Broken_Crypto__basic_01 extends AbstractTestCase
{
    public void bad() throws Throwable
    {
        Cipher des = Cipher.getInstance("DES");
    }

    public void good() throws Throwable
    {
        good1();
    }

    private void good1() throws Throwable
    {
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
"""


def test_selection_is_deterministic_and_skips_support_files():
    names = [f"C/testcases/CWE121_X/s01/CWE121_X__a_{i:02d}.c" for i in range(1, 20)]
    names += ["C/testcases/CWE121_X/s01/io.c", "C/testcases/CWE121_X/main_linux.cpp",
              "C/testcasesupport/std_testcase.h", "C/testcases/CWE89_Y/CWE89_Y__b_01.c"]
    a = tp.select(names, "C/testcases/", (".c", ".cpp"), 3)
    assert a == tp.select(list(reversed(names)), "C/testcases/", (".c", ".cpp"), 3)
    assert len(a) == 4 and all("io.c" not in n and "main_linux" not in n for n in a)


def test_labels_follow_juliet_function_names(tmp_path):
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "x.c").write_text(C_CASE)
    (tmp_path / "x.java").write_text(JAVA_CASE)
    cands = [{"path": "c/x.c", "startLine": 8, "ruleIdVersioned": "r@1", "cwe": "CWE-121"},
             {"path": "c/x.c", "startLine": 15, "ruleIdVersioned": "r@1", "cwe": "CWE-121"},
             {"path": "c/x.c", "startLine": 25, "ruleIdVersioned": "r@1", "cwe": "CWE-121"},
             {"path": "x.java", "startLine": 7, "ruleIdVersioned": "j@1", "cwe": "CWE-327"},
             {"path": "x.java", "startLine": 17, "ruleIdVersioned": "j@1", "cwe": "CWE-327"}]
    rows = tp.labelled(tmp_path, cands)
    got = [(r["path"], r["startLine"], r["function"], r["label"]) for r in rows]
    bad_c = "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_01_bad"
    assert got == [("c/x.c", 8, bad_c, "bad"),
                   ("c/x.c", 15, "goodG2B", "good"),
                   ("x.java", 7, "bad", "bad"),
                   ("x.java", 17, "good1", "good")]
    assert tp.label_of("badSink") == "bad" and tp.label_of("goodB2GSink") == "good"
    assert tp.label_of("main") is None and tp.label_of("printLine") is None


def test_scoring_and_its_label_blind_control():
    rows = [{"path": "a", "startLine": i, "ruleId": "r", "label": lab, "cwe": "CWE-1",
             "case_cwe": "CWE-1"} for i, lab in enumerate(["bad", "bad", "bad", "good", "good"])]
    v = {("a", 0, "r"): {"verdict": "true_positive", "seconds": 1.0, "promptTokens": 300},
         ("a", 1, "r"): {"verdict": "true_positive"},
         ("a", 2, "r"): {"verdict": "insufficient_context"},
         ("a", 3, "r"): {"verdict": "false_positive"},
         ("a", 4, "r"): {"verdict": "true_positive"}}
    s = tp.score(rows, v)
    assert s["base_rate"] == 0.6 and s["plausible_precision"] == round(2 / 3, 4)
    assert s["confusion"] == {"tp": 2, "fp": 1, "fn": 0, "tn": 1, "insufficient_context_on_true": 1,
                              "insufficient_context_on_false": 0}
    assert s["false_positive_drop_rate"] == 0.5 and s["plausible_recall"] == round(2 / 3, 4)
    lo, hi = s["plausible_precision_ci95"]
    assert lo < 2 / 3 < hi
    blind = tp.score(rows, {k: {"verdict": "true_positive"} for k in v})
    assert blind["plausible_precision"] == blind["base_rate"]
