"""The corpus loaders, on synthetic files shaped like the real ones (CI has neither corpus)."""

from __future__ import annotations

import json
import zipfile

import pytest

from anvil_eval.data import CorpusError, cwe, primevul

VUL = "static int parse(char *s) {\n  char b[8];\n  strcpy(b, s);\n  return 0;\n}"
FIX = "static int parse(char *s) {\n  char b[8];\n  strncpy(b, s, 7);\n  return 0;\n}"


def _row(target, func, commit="c1", project="p", cwe_=("CWE-121",), desc="overflow in parse"):
    return {"idx": 1, "project": project, "commit_id": commit, "target": target, "func": func,
            "cwe": list(cwe_), "cve": "CVE-2020-1", "cve_desc": desc}


def _write(tmp_path, rows):
    p = tmp_path / "primevul_test_paired.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return p


def _idx(row, i):
    return dict(row, idx=i)


def test_pairs_are_adjacent_rows_vulnerable_first(tmp_path):
    # The second pair joins two differently named functions, as one real PrimeVul pair does.
    rows = [_idx(_row(1, VUL), 1), _idx(_row(0, FIX), 2),
            _idx(_row(1, VUL.replace("parse", "save"), commit="c2"), 3),
            _idx(_row(0, FIX.replace("parse", "saveAs"), commit="c3"), 4)]
    ps = primevul.pairs(_write(tmp_path, rows))
    assert [p.key for p in ps] == ["p:1", "p:3"]
    assert all(p.vulnerable.target == 1 and p.patched.target == 0 for p in ps)
    assert ps[0].cwe == "CWE-121" and ps[0].cve_desc == "overflow in parse"
    assert primevul.cross_commit(ps) == 1


@pytest.mark.parametrize(
    "rows,match",
    [
        ([_row(1, VUL)], "cannot form pairs"),
        ([_row(0, FIX), _row(1, VUL)], "not vulnerable then patched"),
        ([_row(1, VUL), _row(0, VUL)], "identical"),
        ([_row(1, VUL), _row(0, FIX, project="q")], "two projects"),
        ([{"project": "p", "target": 1, "func": VUL}], "missing"),
        ([_row(2, VUL)], "target"),
    ],
)
def test_malformed_pairing_is_refused(tmp_path, rows, match):
    with pytest.raises(CorpusError, match=match):
        primevul.pairs(_write(tmp_path, rows))


def test_the_length_rule_drops_a_pair_if_either_side_is_long(tmp_path):
    long_fix = FIX + "\n" + "/* pad */\n" * 2000
    ps = primevul.pairs(_write(tmp_path, [_row(1, VUL), _row(0, long_fix)]))
    kept, dropped = primevul.within_length(ps)
    assert kept == [] and dropped == 1


def test_function_name_skips_keywords_and_return_types():
    assert primevul.function_name("static inline int *Foo::bar(int a) { }") == "Foo::bar"
    assert primevul.function_name("int\nmain (void)\n{") == "main"


def test_the_manifest_pins_what_was_fetched(tmp_path):
    _write(tmp_path, [_row(1, VUL), _row(0, FIX)])
    primevul.write_manifest(tmp_path)
    assert primevul.verified("primevul_test_paired.jsonl", tmp_path).is_file()
    (tmp_path / "primevul_test_paired.jsonl").write_text("{}\n")
    with pytest.raises(CorpusError, match="differs"):
        primevul.verified("primevul_test_paired.jsonl", tmp_path)


def _catalogue(tmp_path):
    xml = """<?xml version="1.0"?><Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"
      xmlns:xhtml="http://www.w3.org/1999/xhtml">
      <Weaknesses><Weakness ID="121" Name="Stack-based Buffer Overflow">
        <Description>A stack buffer is   overwritten.</Description></Weakness></Weaknesses>
      <Categories><Category ID="264" Name="Permissions, Privileges, and Access Controls">
        <Summary>Weaknesses in this category relate to permissions.</Summary></Category>
      </Categories></Weakness_Catalog>"""
    path = tmp_path / "cwec.xml.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("cwec_v4.20.xml", xml)
    return path


def test_cwe_catalogue_reads_weaknesses_and_categories(tmp_path):
    entries = cwe.load(_catalogue(tmp_path), sha256=None)
    assert entries["CWE-121"].advisory_text() == (
        "CWE-121: Stack-based Buffer Overflow. A stack buffer is overwritten."
    )
    assert entries["CWE-264"].name.startswith("Permissions")


def test_cwe_catalogue_refuses_an_unpinned_archive(tmp_path):
    with pytest.raises(CorpusError, match="not the pinned"):
        cwe.load(_catalogue(tmp_path))


@pytest.mark.parametrize("raw,norm", [("CWE-079", "CWE-79"), ("cwe-79", "CWE-79"), ("79", "CWE-79"),
                                      ("NVD-CWE-Other", "NVD-CWE-Other")])
def test_cwe_labels_normalise(raw, norm):
    assert cwe.normalise(raw) == norm


def test_a_non_cwe_label_is_refused():
    with pytest.raises(CorpusError):
        cwe.normalise("CVE-2020-1")
