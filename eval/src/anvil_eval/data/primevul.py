"""PrimeVul v0.1 (MIT): paired vulnerable and patched C/C++ functions with CVE and CWE metadata.

PrimeVul is distributed through Google Drive (github.com/DLVulDet/PrimeVul, the v0.1 folder), so the
owner fetches it by hand into ``eval/data/primevul/``. ``write_manifest`` then records each file's
size and SHA-256, and every experiment refuses to read a file whose hash differs from the
manifest's.

A paired file holds each pair as two adjacent rows: the vulnerable function, then its patched
version. That is the dataset's own structure, measured on 2026-10-03 on every v0.1 paired split
(test 435 of 435, valid 480 of 480, train 3,789 of 3,789). The loader pairs by adjacency, requires
the vulnerable row first, the patched row second and one project for both, and raises on anything
else. Pairing by function name was tried first and is wrong: one test pair joins drogon's
``HttpFileImpl::save`` with its patched ``saveAs``. A few pairs take the patched row from a later
commit (2 of 435 in test); they are kept and counted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from anvil_eval import DATA_DIR, acquire
from anvil_eval.data import CorpusError

PRIMEVUL_DIR = DATA_DIR / "primevul"
FILES = (
    "primevul_train.jsonl",
    "primevul_valid.jsonl",
    "primevul_test.jsonl",
    "primevul_train_paired.jsonl",
    "primevul_valid_paired.jsonl",
    "primevul_test_paired.jsonl",
)
REQUIRED = ("project", "commit_id", "target", "func")

#: The pre-registered length rule (register row advisory-permutation): both functions of a pair
#: at most this many characters. Model-independent, so every arm and framing sees one set.
MAX_FUNC_CHARS = 12_000

_NAME = re.compile(r"([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(")
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "defined"}


@dataclass(frozen=True)
class Function:
    idx: str
    project: str
    commit: str
    target: int
    func: str
    cwe: tuple[str, ...]
    cve: str
    cve_desc: str


@dataclass(frozen=True)
class Pair:
    key: str
    vulnerable: Function
    patched: Function

    @property
    def cwe(self) -> str:
        return self.vulnerable.cwe[0] if self.vulnerable.cwe else ""

    @property
    def cve_desc(self) -> str:
        return self.vulnerable.cve_desc


def function_name(func: str) -> str:
    """The defined function's name: the first identifier followed by ``(`` that is not a keyword."""
    head = func.split("{", 1)[0]
    for m in _NAME.finditer(head):
        if m.group(1) not in _KEYWORDS:
            return m.group(1)
    raise CorpusError(f"no function name in {head[:80]!r}")


def _cwes(raw) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [raw]
    return tuple(str(c).strip() for c in raw if str(c).strip())


def read_rows(path: Path) -> list[Function]:
    if not path.is_file():
        raise CorpusError(f"{path} is missing; PrimeVul v0.1 is fetched by hand (see the README)")
    rows = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            missing = [k for k in REQUIRED if k not in rec]
            if missing:
                raise CorpusError(f"{path.name}:{lineno}: missing {missing}")
            if rec["target"] not in (0, 1):
                raise CorpusError(f"{path.name}:{lineno}: target {rec['target']!r}")
            rows.append(
                Function(
                    idx=str(rec.get("idx", lineno)),
                    project=str(rec["project"]),
                    commit=str(rec["commit_id"]),
                    target=int(rec["target"]),
                    func=rec["func"],
                    cwe=_cwes(rec.get("cwe")),
                    cve=str(rec.get("cve") or ""),
                    cve_desc=str(rec.get("cve_desc") or ""),
                )
            )
    if not rows:
        raise CorpusError(f"{path} holds no rows")
    return rows


def pairs(path: Path) -> list[Pair]:
    """Pair a ``*_paired.jsonl`` file: rows 2k and 2k+1, vulnerable first, one project."""
    rows = read_rows(path)
    if len(rows) % 2:
        raise CorpusError(f"{path.name}: {len(rows)} rows cannot form pairs")
    out = []
    for i in range(0, len(rows), 2):
        vul, fix = rows[i], rows[i + 1]
        if (vul.target, fix.target) != (1, 0):
            raise CorpusError(f"{path.name}: rows {i + 1}-{i + 2} are not vulnerable then patched")
        if vul.project != fix.project:
            raise CorpusError(f"{path.name}: rows {i + 1}-{i + 2} join two projects")
        if vul.func == fix.func:
            raise CorpusError(f"{path.name}: rows {i + 1}-{i + 2} pair two identical functions")
        out.append(Pair(f"{vul.project}:{vul.idx}", vul, fix))
    if len({p.key for p in out}) != len(out):
        raise CorpusError(f"{path.name}: two pairs share a vulnerable row's idx")
    return out


def cross_commit(ps: list[Pair]) -> int:
    """Pairs whose patched row comes from a different commit than the vulnerable one."""
    return sum(p.vulnerable.commit != p.patched.commit for p in ps)


def within_length(ps: list[Pair], limit: int = MAX_FUNC_CHARS) -> tuple[list[Pair], int]:
    kept = [p for p in ps if len(p.vulnerable.func) <= limit and len(p.patched.func) <= limit]
    return kept, len(ps) - len(kept)


def write_manifest(directory: Path | None = None) -> dict:
    """Record the size and SHA-256 of every PrimeVul file present; run once, after the fetch."""
    directory = directory or PRIMEVUL_DIR
    files = {}
    for name in FILES:
        p = directory / name
        if p.is_file():
            files[name] = {"size": p.stat().st_size, "sha256": acquire.sha256_file(p)}
    if "primevul_test_paired.jsonl" not in files:
        raise CorpusError(f"{directory}: primevul_test_paired.jsonl is required")
    manifest = {
        "corpus": "PrimeVul v0.1",
        "source": "https://github.com/DLVulDet/PrimeVul (README: the v0.1 Google Drive folder)",
        "licence": "MIT (the repository's LICENSE body, Copyright (c) 2024 DLVulDet)",
        "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "files": files,
    }
    (directory / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", "utf-8")
    return manifest


def verified(name: str, directory: Path | None = None) -> Path:
    """The path of ``name``, after checking it against the manifest written at acquisition."""
    directory = directory or PRIMEVUL_DIR
    mpath = directory / "MANIFEST.json"
    if not mpath.is_file():
        raise CorpusError(f"{mpath} is missing; run `python -m anvil_eval.data.primevul manifest`")
    pinned = json.loads(mpath.read_text("utf-8"))["files"].get(name)
    if pinned is None:
        raise CorpusError(f"{name} is not in {mpath}")
    p = directory / name
    if not p.is_file() or acquire.sha256_file(p) != pinned["sha256"]:
        raise CorpusError(f"{p} differs from the manifest written at acquisition")
    return p


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["manifest"]:
        sys.exit("usage: python -m anvil_eval.data.primevul manifest")
    m = write_manifest()
    for name, f in m["files"].items():
        print(f"{name}: {f['size']} bytes, sha256 {f['sha256']}")
    for split in ("test", "valid"):
        ps = pairs(PRIMEVUL_DIR / f"primevul_{split}_paired.jsonl")
        kept, _ = within_length(ps)
        print(f"{split} pairs: {len(ps)}; within {MAX_FUNC_CHARS} characters: {len(kept)}; "
              f"patched row from a later commit: {cross_commit(ps)}")
