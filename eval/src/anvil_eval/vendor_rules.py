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

Licences are read from the bodies, never from metadata. A GitLab rule file states a licence in a
``# License:`` header, and that header outranks the repository LICENSE: the C rules say GPL 2.0
under a repository LICENSE that says MIT. But GitLab ported most of its rules from other
analysers, and the header of the rule's own companion test file (same name, the language's
extension) names where it came from: "LGPL-3.0 License (c) find-sec-bugs" beside a rule headed
"MIT (c) GitLab Inc." (the same-family review of 2026-10-03 found this; GitLab's mappings/ files
agree). So a GitLab rule's licence is the stricter of the two headers: a third-party companion
wins. The selection's ``exclude_by_derived_licence`` names the licences whose rules are left out
(LGPL-3.0, the owner's decision of 2026-10-03), and the manifest lists every rule it left out. A
rule file with no header takes its corpus's LICENSE body only when ``NO_PER_FILE_HEADERS`` names
its corpus. Any other licence outside MIT and Apache-2.0, or a header this module cannot read,
refuses the whole run: nothing is written.

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
BANDIT_LICENCE = (recall.RECALL_VENV / "lib" / "python3.13" / "site-packages"
                  / "bandit-1.9.4.dist-info" / "licenses" / "LICENSE")
BANDIT_LICENCE_NAME = "LICENSE.bandit-Apache-2.0.txt"

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

#: A GitLab companion test file's ``License:`` header, mapped to (SPDX id, upstream). Every header
#: seen beside a vendored rule at commit 53bf5cf6 is here; anything else is refused.
COMPANION_HEADERS = {
    "LGPL-3.0 License (c) find-sec-bugs": ("LGPL-3.0", "find-sec-bugs"),
    "LGPL-3.0 License (c) security-code-scan": ("LGPL-3.0", "security-code-scan"),
    "Apache 2.0 (c) PyCQA": ("Apache-2.0", "bandit"),
    "Apache 2.0 (c) gosec": ("Apache-2.0", "gosec"),
    "Apache 2.0": ("Apache-2.0", ""),
    "MIT (c) JS Foundation and other contributors, https://js.foundation": ("MIT", "JS Foundation"),
    "MIT (c) GitLab Inc.": ("MIT", "GitLab"),
    "MIT Copyright (c) 2022-Present GitLab B.V.": ("MIT", "GitLab"),
}
COMPANION_RE = re.compile(r"License:\s*(.+?)\s*$", re.M)


def companion_licence(root: Path, rel: str) -> tuple[str, str, str] | None:
    """(SPDX, upstream, evidence) from the rule's companion test files, or None if it has none."""
    base = rel.rsplit(".", 1)[0]
    found = []
    silent = []
    for f in sorted(root.glob(base + ".*")):
        if f.suffix in (".yml", ".yaml"):
            continue
        m = COMPANION_RE.search("\n".join(f.read_text("utf-8", "replace").splitlines()[:15]))
        if not m:
            # No header gives no evidence either way; the rule's own header governs, and the
            # evidence says the companion was silent.
            silent.append(f.name)
            continue
        if m.group(1) not in COMPANION_HEADERS:
            raise VendorError(f"{rel}: companion {f.name} has an unread licence header "
                              f"{m.group(1)!r}")
        spdx, upstream = COMPANION_HEADERS[m.group(1)]
        found.append((spdx, upstream, f"its GitLab companion {f.name}: License: {m.group(1)}"))
    if not found:
        if silent:
            return ("", "", "its GitLab companion " + ", ".join(silent) + " states no licence")
        return None
    if len({f[0] for f in found}) != 1:
        raise VendorError(f"{rel}: companions disagree on the licence: {found}")
    return found[0]


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


def derive(rule: Rule, root: Path) -> Rule:
    """A GitLab rule's licence: the stricter of its own header and its companion's."""
    comp = companion_licence(root, rule.source_path)
    if comp is None:
        return Rule(**{**rule.__dict__, "licence_evidence":
                       rule.licence_evidence + "; it has no companion test file"})
    spdx, upstream, evidence = comp
    if upstream in ("", "GitLab") or not spdx:
        return Rule(**{**rule.__dict__,
                       "licence_evidence": rule.licence_evidence + "; " + evidence})
    return Rule(**{**rule.__dict__, "licence": spdx, "licence_evidence":
                   f"derived from {upstream}: {evidence}; the rule's own header says "
                   f"{rule.licence_evidence.removeprefix('# License: ')}"})


def plan(selection: dict, corpus_root: Path) -> tuple[list[Rule], dict[str, bytes], list[dict]]:
    """Every rule the selection admits, every licence body to archive, and every rule left out for
    its derived licence. Writes nothing."""
    by_licence = selection.get("exclude_by_derived_licence") or {"licences": []}
    left_out: list[dict] = []
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
                if c["name"] == "gitlab-sast-rules":
                    rule = derive(rule, root)
                    if rule.licence in by_licence["licences"]:
                        left_out.append({"path": f"{rule.corpus}/{rel}", "licence": rule.licence,
                                         "evidence": rule.licence_evidence})
                        continue
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
    if any(r.licence_evidence.startswith("derived from bandit") for r in rules):
        body = BANDIT_LICENCE.read_bytes()
        if b"Apache License" not in body or b"Version 2.0" not in body:
            raise VendorError("bandit's LICENSE is not the Apache-2.0 body")
        licences[f"gitlab-sast-rules/{BANDIT_LICENCE_NAME}"] = body
    if any(r.licence == "Apache-2.0" and not r.licence_evidence.startswith("derived from bandit")
           for r in rules):
        with tarfile.open(GOSEC_TARBALL) as t:
            body = t.extractfile("LICENSE.txt").read()
        if b"Apache License" not in body or b"Version 2.0" not in body:
            raise VendorError("gosec's LICENSE.txt is not the Apache-2.0 body")
        licences[f"gitlab-sast-rules/{GOSEC_LICENCE_NAME}"] = body
    return rules, licences, left_out


def licence_file(r: Rule) -> str:
    if r.licence == "Apache-2.0":
        name = BANDIT_LICENCE_NAME if r.licence_evidence.startswith("derived from bandit") \
            else GOSEC_LICENCE_NAME
        return f"gitlab-sast-rules/{name}"
    return f"{r.corpus}/LICENSE"


def manifest(selection_bytes: bytes, selection: dict, rules: list[Rule],
             licences: dict[str, bytes], left_out: list[dict] | None = None) -> dict:
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
            "licence_file": licence_file(r),
        } for r in rules],
        "excluded_by_licence": left_out or [],
    }


def vendor(rules_dir: Path = RULES_DIR, corpus_root: Path | None = None) -> dict:
    corpus_root = corpus_root or recall.RECALL_DATA / "rules"
    selection_bytes = (rules_dir / "selection.json").read_bytes()
    selection = json.loads(selection_bytes)
    rules, licences, left_out = plan(selection, corpus_root)
    doc = manifest(selection_bytes, selection, rules, licences, left_out)
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
    return {"rules": len(rules), "licences": sorted(licences), "excluded_by_licence": len(left_out)}


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
