"""The rule vendoring: licences read from rule headers, refusals before anything is written."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from anvil_eval import vendor_rules as vr

PIN = "a" * 40
MIT = "MIT License\n\nCopyright (c) 2022 raptor\n\nPermission is hereby granted...\n"


GITLAB_MIT = "# License: MIT (c) GitLab Inc.\n"


APACHE = b"Apache License\nVersion 2.0, January 2004\n"


@pytest.fixture(autouse=True)
def licence_bodies(tmp_path, monkeypatch):
    """The gosec release archive and bandit's licence are local acquisitions, absent in CI; each
    test gets stand-ins holding an Apache-2.0 opening, which is all plan() checks."""
    tarball = tmp_path / "gosec.tar.gz"
    with tarfile.open(tarball, "w:gz") as t:
        info = tarfile.TarInfo("LICENSE.txt")
        info.size = len(APACHE)
        t.addfile(info, io.BytesIO(APACHE))
    bandit = tmp_path / "bandit-LICENSE"
    bandit.write_bytes(APACHE)
    monkeypatch.setattr(vr, "GOSEC_TARBALL", tarball)
    monkeypatch.setattr(vr, "BANDIT_LICENCE", bandit)


def rule(header: str, rid: str = "r-1", cwe: str = "CWE-78") -> str:
    return (f"{header}rules:\n  - id: {rid}\n    languages: [python]\n    metadata:\n"
            f"      cwe: \"{cwe}\"\n")


def corpus(tmp_path, name, files):
    root = tmp_path / "corpora" / name
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text(PIN + "\n")
    (root / "LICENSE").write_text(MIT)
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)
    return tmp_path / "corpora"


def selection(name="gitlab-sast-rules", dirs=("python",), suffix=".yml", excluded_files=()):
    return {
        "version": 1, "decided_by": "t", "decided_on": "2026-10-03", "tools": [],
        "corpora": [{"name": name, "repository": "https://example.invalid", "commit": PIN,
                     "licence_file": "LICENSE", "rule_suffix": suffix, "directories": list(dirs)}],
        "excluded_directories": [], "excluded_rule_files": list(excluded_files),
        "excluded_tool_rules": [], "excluded_paths": {"directories": [], "file_globs": []},
    }


def test_a_gitlab_header_decides_the_licence(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {
        "python/a.yml": rule("# License: MIT (c) GitLab Inc.\n"),
        "python/b.yml": rule("# License: Apache 2.0 (c) gosec\n", "r-2"),
    })
    rules, _, _ = vr.plan(selection(), root)
    assert {r.licence for r in rules} == {"MIT", "Apache-2.0"}


def test_a_gpl_rule_refuses_the_whole_run(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {
        "python/a.yml": rule("# License: MIT (c) GitLab Inc.\n"),
        "python/b.yml": rule("# License: GPL 2.0 (c) 1989, 1991 Free Software Foundation, Inc.\n",
                             "r-2"),
    })
    with pytest.raises(vr.VendorError, match="GPL-2.0"):
        vr.plan(selection(), root)


@pytest.mark.parametrize("header", ["", "# License: BSD-ish\n", "# License: MIT (c) GitLab Inc.\n"
                                    "# License: Apache 2.0 (c) gosec\n"])
def test_an_unread_or_conflicting_header_refuses(tmp_path, header):
    root = corpus(tmp_path, "gitlab-sast-rules", {"python/a.yml": rule(header)})
    with pytest.raises(vr.VendorError):
        vr.plan(selection(), root)


def test_a_corpus_without_headers_takes_its_licence_body(tmp_path):
    root = corpus(tmp_path, "0xdea-semgrep-rules", {"rules/c/a.yaml": rule("")})
    rules, _, _ = vr.plan(selection("0xdea-semgrep-rules", ("rules/c",), ".yaml"), root)
    assert rules[0].licence == "MIT" and "Copyright (c) 2022 raptor" in rules[0].licence_evidence


def test_a_checkout_off_its_pin_refuses(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {"python/a.yml": rule(GITLAB_MIT)})
    (root / "gitlab-sast-rules" / ".git" / "HEAD").write_text("b" * 40 + "\n")
    with pytest.raises(vr.VendorError, match="pinned"):
        vr.plan(selection(), root)


def test_an_exclusion_must_name_a_real_file(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {"python/a.yml": rule(GITLAB_MIT)})
    sel = selection(excluded_files=[{"corpus": "gitlab-sast-rules", "path": "python/gone.yml",
                                     "reason": "x"}])
    with pytest.raises(vr.VendorError, match="does not exist"):
        vr.plan(sel, root)


def test_a_refused_run_writes_nothing(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {
        "python/a.yml": rule("# License: GPL 2.0 (c) 1989, 1991 Free Software Foundation, Inc.\n")})
    out = tmp_path / "rules"
    out.mkdir()
    (out / "selection.json").write_text(json.dumps(selection()))
    with pytest.raises(vr.VendorError):
        vr.vendor(out, root)
    assert sorted(p.name for p in out.iterdir()) == ["selection.json"]


def test_the_committed_manifest_matches_the_committed_selection():
    sel = vr.SELECTION.read_bytes()
    man = json.loads(vr.MANIFEST.read_text())
    assert man["selection_sha256"] == vr.sha256(sel)
    assert all(r["licence"] in vr.ALLOWED for r in man["rules"])
    assert len(man["excluded_by_licence"]) == 131
    assert all(e["licence"] == "LGPL-3.0" for e in man["excluded_by_licence"])
    assert not any(r["path"].startswith("gitlab-sast-rules/c/") for r in man["rules"])


def test_a_companion_decides_when_it_names_an_upstream(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {
        "python/a.yml": rule(GITLAB_MIT),
        "python/a.py": "# License: Apache 2.0 (c) PyCQA\nimport os\n",
        "python/b.yml": rule(GITLAB_MIT, "r-2"),
        "python/b.py": "# License: MIT (c) GitLab Inc.\n",
        "python/c.yml": rule(GITLAB_MIT, "r-3"),
        "python/c.py": "import os  # no header\n",
    })
    rules, _, left_out = vr.plan(selection(), root)
    by = {r.source_path: r for r in rules}
    assert by["python/a.yml"].licence == "Apache-2.0"
    assert by["python/a.yml"].licence_evidence.startswith("derived from bandit")
    assert by["python/b.yml"].licence == "MIT"
    assert "states no licence" in by["python/c.yml"].licence_evidence
    assert left_out == []


def test_an_lgpl_companion_is_left_out_when_the_selection_excludes_it(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {
        "python/a.yml": rule(GITLAB_MIT),
        "python/a.py": "// License: LGPL-3.0 License (c) find-sec-bugs\n",
        "python/b.yml": rule(GITLAB_MIT, "r-2"),
    })
    sel = selection()
    sel["exclude_by_derived_licence"] = {"licences": ["LGPL-3.0"]}
    rules, _, left_out = vr.plan(sel, root)
    assert [r.source_path for r in rules] == ["python/b.yml"]
    assert left_out[0]["licence"] == "LGPL-3.0" and "find-sec-bugs" in left_out[0]["evidence"]


def test_an_lgpl_companion_refuses_the_run_when_nothing_excludes_it(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {
        "python/a.yml": rule(GITLAB_MIT),
        "python/a.py": "// License: LGPL-3.0 License (c) find-sec-bugs\n",
    })
    with pytest.raises(vr.VendorError, match="LGPL-3.0"):
        vr.plan(selection(), root)


def test_an_unread_companion_header_refuses(tmp_path):
    root = corpus(tmp_path, "gitlab-sast-rules", {
        "python/a.yml": rule(GITLAB_MIT),
        "python/a.py": "# License: WTFPL\n",
    })
    with pytest.raises(vr.VendorError, match="unread licence header"):
        vr.plan(selection(), root)
