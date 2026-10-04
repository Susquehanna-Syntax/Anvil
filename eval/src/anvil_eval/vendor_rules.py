"""Vendor Lane B's selected rules into data/rules (plan node recall).

Reads ``data/rules/selection.json`` (the owner's selection of 2026-10-03), takes each corpus from
its pinned checkout under ``~/.cache/anvil-eval/recall/rules`` (``python -m anvil_eval.recall
acquire`` fetches them), and writes:

* every selected rule file, byte for byte, under ``data/rules/<corpus>/<path in the corpus>``;
* each corpus's LICENSE body, byte for byte, beside its rules;
* the Apache-2.0 body the gosec-derived Go rules are licensed under, from the pinned gosec release
  tarball (its ``LICENSE.txt``);
* ``data/rules/MANIFEST.json``: per rule file, the corpus, repository, commit, path, git blob SHA-1,
  SHA-256, rule ids, CWEs, languages and licence, with the evidence the licence was read from.

Licences are read from the bodies, never from metadata. A GitLab rule file states its own licence in
a ``# License:`` header, and that header decides, not the repository LICENSE: the C rules say
GPL 2.0 under a repository LICENSE that says MIT. A rule file with no header takes its corpus's
LICENSE body only when ``NO_PER_FILE_HEADERS`` names its corpus. Any licence outside
MIT and Apache-2.0, or a header this module cannot read, refuses the whole run: nothing is written.

Only rule YAML is copied. The corpora's rule tests are third-party Go, Java and C sources, which
gate 3 (internal/dast/authz/egress_chokepoint_test.go) and the licence boundary both keep out of
this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from anvil_eval import REPO_ROOT, recall

RULES_DIR = REPO_ROOT / "data" / "rules"
SELECTION = RULES_DIR / "selection.json"
MANIFEST = RULES_DIR / "MANIFEST.json"
GOSEC_TARBALL = recall.RECALL_BIN.parent / "gosec_2.29.0_linux_amd64.tar.gz"
GOSEC_LICENCE_NAME = "LICENSE.gosec-Apache-2.0.txt"

#: The licences a vendored rule may carry. Both are permissive and Apache-2.0 compatible.
ALLOWED = ("MIT", "Apache-2.0")

#: A GitLab ``# License:`` header, as written in the pinned corpus, mapped to its SPDX id. Every
#: header seen at commit 53bf5cf6 is here; anything else is refused rather than guessed.
HEADERS = {
    "MIT (c) GitLab Inc.": "MIT",
    "License: MIT (c) GitLab Inc.": "MIT",  # go/crypto/rule-tlsversion.yml repeats the word
    "Apache 2.0 (c) gosec": "Apache-2.0",
    "GPL 2.0 (c) 1989, 1991 Free Software Foundation, Inc.": "GPL-2.0",
}

#: Corpora whose rule files carry no per-file licence header, so the corpus LICENSE body governs.
#: 0xdea's LICENSE is MIT, (c) 2022 raptor, and none of its rule files has a header.
NO_PER_FILE_HEADERS = {"0xdea-semgrep-rules"}

HEADER_RE = re.compile(r"^#\s*License:\s*(.+?)\s*$", re.M)


class VendorError(RuntimeError):
    """The selection cannot be vendored as stated; nothing was written."""


@dataclass(frozen=True)
class Rule:
    corpus: str
    source_path: str
    data: bytes
    ids: list[str]
    cwes: list[str]
    languages: list[str]
    licence: str
    licence_evidence: str


def blob_sha1(data: bytes) -> str:
    """Git's blob id: sha1 of ``blob <len>\\0`` and the content."""
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cwe(raw: str) -> str:
    m = re.search(r"(?i)cwe-?(\d+)", raw)
    if not m:
        raise VendorError(f"unreadable CWE {raw!r}")
    return f"CWE-{int(m.group(1))}"


def licence_of(corpus: str, path: str, text: str) -> tuple[str, str]:
    headers = HEADER_RE.findall(text.split("\nrules:", 1)[0])
    if not headers:
        if corpus in NO_PER_FILE_HEADERS:
            return "", ""  # plan() reads the corpus LICENSE body and states it
        raise VendorError(f"{corpus}/{path} has no licence header")
    spdx = {HEADERS.get(h) for h in headers}
    if None in spdx or len(spdx) != 1:
        raise VendorError(f"{corpus}/{path}: unreadable or conflicting licence headers {headers}")
    return spdx.pop(), "# License: " + headers[0]


def read_rule(corpus: str, root: Path, rel: str) -> Rule:
    data = (root / rel).read_bytes()
    text = data.decode("utf-8")
    licence, evidence = licence_of(corpus, rel, text)
    doc = yaml.safe_load(text)
    rules = (doc or {}).get("rules") or []
    if not rules:
        raise VendorError(f"{corpus}/{rel} defines no rule")
    ids, cwes, langs = [], [], []
    for r in rules:
        ids.append(str(r["id"]))
        raw = (r.get("metadata") or {}).get("cwe")
        for c in raw if isinstance(raw, list) else [raw] if raw else []:
            if _cwe(str(c)) not in cwes:
                cwes.append(_cwe(str(c)))
        for lang in r.get("languages") or []:
            if lang not in langs:
                langs.append(str(lang))
    if not cwes:
        raise VendorError(f"{corpus}/{rel} names no CWE; every candidate needs one")
    return Rule(corpus, rel, data, ids, cwes, langs, licence, evidence)


def plan(selection: dict, corpus_root: Path) -> tuple[list[Rule], dict[str, bytes]]:
    """Every rule the selection admits, and every licence body to archive. Writes nothing."""
    excluded_dirs = {(d["corpus"], d["directory"]) for d in selection["excluded_directories"]}
    excluded_files = {(f["corpus"], f["path"]) for f in selection["excluded_rule_files"]}
    rules: list[Rule] = []
    licences: dict[str, bytes] = {}
    for c in selection["corpora"]:
        root = corpus_root / c["name"]
        head = (root / ".git" / "HEAD").read_text().strip() if (root / ".git").exists() else ""
        if head != c["commit"]:
            raise VendorError(f"{c['name']}: checkout HEAD is {head or 'absent'}, pinned "
                              f"{c['commit']}; run python -m anvil_eval.recall acquire")
        for d in c["directories"]:
            if (c["name"], d) in excluded_dirs:
                raise VendorError(f"{c['name']}/{d} is both selected and excluded")
        corpus_licence = (root / c["licence_file"]).read_bytes()
        licences[f"{c['name']}/LICENSE"] = corpus_licence
        for d in c["directories"]:
            for f in sorted((root / d).rglob("*" + c["rule_suffix"])):
                rel = f.relative_to(root).as_posix()
                if (c["name"], rel) in excluded_files:
                    continue
                rule = read_rule(c["name"], root, rel)
                if not rule.licence:
                    body = corpus_licence.decode("utf-8").splitlines()
                    if not body or body[0].strip() != "MIT License":
                        raise VendorError(f"{c['name']}: cannot read its LICENSE body as MIT")
                    holder = next((ln.strip() for ln in body if ln.startswith("Copyright")), "")
                    rule = Rule(**{**rule.__dict__, "licence": "MIT", "licence_evidence":
                                   f"the corpus LICENSE body: MIT License, {holder}; the rule "
                                   f"file has no licence header of its own"})
                if rule.licence not in ALLOWED:
                    raise VendorError(f"{c['name']}/{rel} is {rule.licence}, which Lane B may not "
                                      f"vendor ({rule.licence_evidence})")
                rules.append(rule)
    for f in selection["excluded_rule_files"]:
        # An exclusion that names nothing would read as a decision that changed nothing.
        if not (corpus_root / f["corpus"] / f["path"]).is_file():
            raise VendorError(f"excluded rule file {f['corpus']}/{f['path']} does not exist")
    if any(r.licence == "Apache-2.0" for r in rules):
        with tarfile.open(GOSEC_TARBALL) as t:
            body = t.extractfile("LICENSE.txt").read()
        if b"Apache License" not in body or b"Version 2.0" not in body:
            raise VendorError("gosec's LICENSE.txt is not the Apache-2.0 body")
        licences[f"gitlab-sast-rules/{GOSEC_LICENCE_NAME}"] = body
    return rules, licences


def manifest(selection_bytes: bytes, selection: dict, rules: list[Rule],
             licences: dict[str, bytes]) -> dict:
    by_corpus = {c["name"]: c for c in selection["corpora"]}
    return {
        "version": 1,
        "generated_by": "python -m anvil_eval.vendor_rules",
        "selection_sha256": sha256(selection_bytes),
        "licences": [{"path": p, "sha256": sha256(b)} for p, b in sorted(licences.items())],
        "rules": [{
            "corpus": r.corpus,
            "repository": by_corpus[r.corpus]["repository"],
            "commit": by_corpus[r.corpus]["commit"],
            "path": f"{r.corpus}/{r.source_path}",
            "blob_sha1": blob_sha1(r.data),
            "sha256": sha256(r.data),
            "ids": r.ids,
            "cwes": r.cwes,
            "languages": r.languages,
            "licence": r.licence,
            "licence_evidence": r.licence_evidence,
            "licence_file": (f"gitlab-sast-rules/{GOSEC_LICENCE_NAME}"
                             if r.licence == "Apache-2.0" else f"{r.corpus}/LICENSE"),
        } for r in rules],
    }


def vendor(rules_dir: Path = RULES_DIR, corpus_root: Path | None = None) -> dict:
    corpus_root = corpus_root or recall.RECALL_DATA / "rules"
    selection_bytes = (rules_dir / "selection.json").read_bytes()
    selection = json.loads(selection_bytes)
    rules, licences = plan(selection, corpus_root)
    doc = manifest(selection_bytes, selection, rules, licences)
    for c in selection["corpora"]:
        shutil.rmtree(rules_dir / c["name"], ignore_errors=True)
    for r in rules:
        out = rules_dir / r.corpus / r.source_path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(r.data)
    for p, b in licences.items():
        (rules_dir / p).parent.mkdir(parents=True, exist_ok=True)
        (rules_dir / p).write_bytes(b)
    (rules_dir / "MANIFEST.json").write_text(json.dumps(doc, indent=1) + "\n")
    return {"rules": len(rules), "licences": sorted(licences)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.vendor_rules")
    ap.parse_args(argv)
    try:
        print(json.dumps(vendor(), indent=1))
    except VendorError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
