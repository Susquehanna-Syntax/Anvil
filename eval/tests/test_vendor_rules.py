"""The rule vendoring: licences read from rule headers, refusals before anything is written."""

from __future__ import annotations

import json

import pytest

from anvil_eval import vendor_rules as vr

PIN = "a" * 40
MIT = "MIT License\n\nCopyright (c) 2022 raptor\n\nPermission is hereby granted...\n"


GITLAB_MIT = "# License: MIT (c) GitLab Inc.\n"


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
    rules, _ = vr.plan(selection(), root)
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
    rules, _ = vr.plan(selection("0xdea-semgrep-rules", ("rules/c",), ".yaml"), root)
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
    assert not any(r["path"].startswith("gitlab-sast-rules/c/") for r in man["rules"])
