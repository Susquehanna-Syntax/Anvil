"""PrimeVul v0.1 (MIT): paired vulnerable and patched C/C++ functions with CVE and CWE metadata.

PrimeVul is distributed through Google Drive (github.com/DLVulDet/PrimeVul, the v0.1 folder), so the
owner fetches it by hand into ``eval/data/primevul/``. ``write_manifest`` then records each file's
size and SHA-256, and every experiment refuses to read a file whose hash differs from the
manifest's.

A paired file holds each vulnerable function and its patched version as two rows from the same fix
commit. The loader pairs rows by (project, commit, function name), requires exactly one vulnerable
and one patched row per key, and raises on anything else rather than guessing.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
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
    """Pair a ``*_paired.jsonl`` file: each key needs one vulnerable and one patched row."""
    groups: dict[str, list[Function]] = defaultdict(list)
    order: list[str] = []
    for f in read_rows(path):
        key = f"{f.project}@{f.commit}:{function_name(f.func)}"
        if key not in groups:
            order.append(key)
        groups[key].append(f)
    out = []
    for key in order:
        g = groups[key]
        vul = [f for f in g if f.target == 1]
        fix = [f for f in g if f.target == 0]
        if len(vul) != 1 or len(fix) != 1:
            raise CorpusError(
                f"{path.name}: {key} has {len(vul)} vulnerable and {len(fix)} patched rows"
            )
        if vul[0].func == fix[0].func:
            raise CorpusError(f"{path.name}: {key} pairs two identical functions")
        out.append(Pair(key, vul[0], fix[0]))
    return out


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
    test_pairs = pairs(PRIMEVUL_DIR / "primevul_test_paired.jsonl")
    kept, dropped = within_length(test_pairs)
    print(f"test pairs: {len(test_pairs)}; within {MAX_FUNC_CHARS} characters: {len(kept)}")
