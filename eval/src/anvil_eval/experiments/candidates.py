"""Candidates per scan (register row candidates-per-scan, plan node candidatecount).

A permanent instrument: run the recall federation (opengrep over GitLab's sast-rules and 0xdea's
C/C++ rules, gosec on Go, bandit on Python) over a pinned repository and count candidates. One
candidate is one (file, line, CWE) after de-duplication across tools; a finding without a CWE
keeps its rule id in that slot.

* Full scan: the whole checkout at the pinned commit.
* Per push: each of the most recent first-parent commits (up to 20), scanning the files that
  commit touched and keeping only candidates on lines it added or changed.

Each tool is a subprocess. A missing tool is a refusal and a failed tool is an error; neither is
ever a count of zero, because a zero from a broken install and a zero from a clean repository
must not look alike (that is how a two-rule corpus measured nothing).

Negative control: the federation runs over a planted fixture with one known-bad file per
language family and over a clean file. Every planted file must yield a candidate and the clean
file none; otherwise the artifact does not validate. The Go file and its go.mod are stored with a
``.txt`` suffix, because ``eval/`` holds no Go source (``tests/test_scaffold.py``), and are
materialised into a temporary directory for the scan.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from anvil_eval import EVAL_ROOT, REPO_ROOT, RESULTS_DIR, recall, results

ID = "candidates-per-scan"
RUNS_DIR = RESULTS_DIR / "runs" / ID
FULL_BAR, PUSH_BAR = 500, 50
FIXTURES = EVAL_ROOT / "tests" / "fixtures" / "recall"
ANVIL_COMMIT = "1d8657e889cdf292b1ee792ceb36913f6d8539d2"  # main after Phase 4 (#18)
GO = Path.home() / "sdk" / "go1.26.5" / "bin"

C_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
SCANNED_EXT = C_EXT | {".py", ".go", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
                       ".cs", ".scala"}


class ToolMissing(RuntimeError):
    """A recall tool is not installed; the scan is refused rather than counted as zero."""


class ToolFailed(RuntimeError):
    """A recall tool ran and failed."""


@dataclass(frozen=True)
class Candidate:
    tool: str
    rule: str
    path: str  # relative to the scanned root
    line: int
    cwe: str

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.path, self.line, self.cwe or self.rule)


def _cwe(raw) -> str:
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    if isinstance(raw, dict):
        raw = raw.get("id", "")
    m = re.search(r"(?i)cwe-?(\d+)", str(raw)) or re.fullmatch(r"\s*(\d+)\s*", str(raw))
    return f"CWE-{int(m.group(1))}" if m else ""  # 'CWE-078' and '78' are one CWE


def _need(path: Path, name: str) -> Path:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ToolMissing(f"{name} is not installed at {path}; run python -m anvil_eval.recall "
                          "acquire")
    return path


def run_opengrep(root: Path, targets: list[Path], has_c: bool) -> list[Candidate]:
    exe = _need(recall.opengrep_bin(), "opengrep")
    configs = [recall.GITLAB.path / d for d in recall.GITLAB_RULE_DIRS]
    if has_c:
        configs.append(recall.OXDEA.path / "rules")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        cmd = [str(exe), "scan", "--json", "--output", str(out), "--quiet", "--no-git-ignore"]
        for c in configs:
            cmd += ["--config", str(c)]
        proc = subprocess.run(cmd + [str(t) for t in targets], capture_output=True, text=True,
                              cwd=root)
        if proc.returncode not in (0, 1) or not out.is_file():
            raise ToolFailed(f"opengrep exited {proc.returncode}: {proc.stderr[-800:]}")
        doc = json.loads(out.read_text())
    return [Candidate("opengrep", r["check_id"].rsplit(".", 1)[-1],
                      os.path.relpath((root / r["path"]).resolve(), root.resolve()),
                      int(r["start"]["line"]), _cwe(r["extra"].get("metadata", {}).get("cwe")))
            for r in doc["results"]]


def run_gosec(root: Path, packages: list[str]) -> list[Candidate]:
    exe = _need(recall.RECALL_BIN / "gosec", "gosec")
    env = dict(os.environ, PATH=f"{GO}:{os.environ.get('PATH', '')}", GOTOOLCHAIN="local",
               GOFLAGS="-mod=mod")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        # Never -quiet: with it, gosec writes nothing at all for a package with no findings
        # (seen on 2026-10-03), and silence must never be read as a count.
        proc = subprocess.run([str(exe), "-fmt=json", f"-out={out}", "-no-fail",
                               *packages], capture_output=True, text=True, cwd=root, env=env)
        if proc.returncode != 0 or not out.is_file():
            raise ToolFailed(f"gosec exited {proc.returncode}: {proc.stderr[-800:]}")
        doc = json.loads(out.read_text())
    if doc.get("Golang errors"):
        raise ToolFailed(f"gosec could not load packages: {list(doc['Golang errors'])[:3]}")
    return [Candidate("gosec", i["rule_id"], os.path.relpath(i["file"], root.resolve()),
                      int(str(i["line"]).split("-")[0]), _cwe(i.get("cwe")))
            for i in doc.get("Issues") or []]


def run_bandit(root: Path, targets: list[Path]) -> list[Candidate]:
    exe = _need(recall.RECALL_VENV / "bin" / "bandit", "bandit")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        proc = subprocess.run([str(exe), "-r", "-q", "-f", "json", "-o", str(out),
                               *[str(t) for t in targets]], capture_output=True, text=True,
                              cwd=root)
        if proc.returncode not in (0, 1) or not out.is_file():
            raise ToolFailed(f"bandit exited {proc.returncode}: {proc.stderr[-800:]}")
        doc = json.loads(out.read_text())
    if doc.get("errors"):
        raise ToolFailed(f"bandit errors: {doc['errors'][:3]}")
    return [Candidate("bandit", r["test_id"], os.path.relpath((root / r["filename"]).resolve(),
                                                              root.resolve()),
                      int(r["line_number"]), _cwe(r.get("issue_cwe")))
            for r in doc["results"]]


def scan(root: Path, files: Iterable[Path] | None = None) -> list[Candidate]:
    """Every tool the tree calls for, over ``files`` (all tracked files when None)."""
    root = root.resolve()
    if files is None:
        listed = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True,
                                text=True)
        names = listed.stdout.split() if listed.returncode == 0 else [
            str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]
        files = [root / n for n in names]
        whole = True
    else:
        whole = False
    files = [f for f in files if f.suffix in SCANNED_EXT and f.is_file()]
    if not files:
        return []
    out = run_opengrep(root, [root] if whole else files, any(f.suffix in C_EXT for f in files))
    py = [f for f in files if f.suffix == ".py"]
    if py:
        out += run_bandit(root, [root] if whole else py)
    # gosec skips test files by default; leave them out of its package list to match.
    go = [f for f in files if f.suffix == ".go" and not f.name.endswith("_test.go")]
    if go and (root / "go.mod").is_file():
        pkgs = ["./..."] if whole else sorted({"./" + os.path.relpath(f.parent, root) for f in go})
        out += run_gosec(root, pkgs)
    return out


def dedupe(cands: list[Candidate]) -> list[Candidate]:
    seen: dict[tuple, Candidate] = {}
    for c in cands:
        seen.setdefault(c.key, c)
    return list(seen.values())


def changed_lines(root: Path, commit: str) -> dict[str, set[int]]:
    """Lines ``commit`` added or changed, per file, numbered as in ``commit``."""
    diff = subprocess.run(["git", "-C", str(root), "diff", "--unified=0", "--no-renames",
                           f"{commit}~1", commit], capture_output=True, text=True, check=True)
    out: dict[str, set[int]] = {}
    path = None
    for line in diff.stdout.splitlines():
        if line.startswith("+++ "):
            path = None if line[4:] == "/dev/null" else line[6:]
        elif line.startswith("@@") and path:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            start, count = int(m.group(1)), int(m.group(2) or 1)
            out.setdefault(path, set()).update(range(start, start + count))
    return {p: ls for p, ls in out.items() if ls}


def per_push(root: Path, pushes: int) -> list[dict]:
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    commits = subprocess.run(["git", "-C", str(root), "rev-list", "--first-parent",
                              f"--max-count={pushes + 1}", head], capture_output=True,
                             text=True, check=True).stdout.split()[:-1][:pushes]
    rows = []
    try:
        for c in commits:
            subprocess.run(["git", "-C", str(root), "checkout", "-q", "--detach", c], check=True)
            lines = changed_lines(root, c)
            found = dedupe(scan(root, [root / p for p in lines]))
            kept = [f for f in found if f.line in lines.get(f.path, ())]
            rows.append({"commit": c, "files_changed": len(lines), "candidates": len(kept)})
    finally:
        subprocess.run(["git", "-C", str(root), "checkout", "-q", "--detach", head], check=True)
    return rows


def measure_repo(name: str, root: Path, pushes: int) -> dict:
    full = dedupe(scan(root))
    by_tool: dict[str, int] = {}
    for c in full:
        by_tool[c.tool] = by_tool.get(c.tool, 0) + 1
    push = per_push(root, pushes)
    counts = sorted(p["candidates"] for p in push)
    return {
        "repo": name,
        "commit": subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                 capture_output=True, text=True, check=True).stdout.strip(),
        "full_scan": len(full),
        "full_scan_by_tool": by_tool,
        "full_scan_by_cwe_top10": _top(full),
        "pushes": push,
        "per_push_median": counts[len(counts) // 2] if counts else 0,
        "per_push_max": counts[-1] if counts else 0,
    }


def _top(cands: list[Candidate]) -> dict[str, int]:
    tally: dict[str, int] = {}
    for c in cands:
        tally[c.cwe or "none"] = tally.get(c.cwe or "none", 0) + 1
    return dict(sorted(tally.items(), key=lambda kv: -kv[1])[:10])


def materialise(src: Path, dest: Path) -> Path:
    """Copy a fixture directory, dropping the ``.txt`` that keeps Go sources out of eval/."""
    dest.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        name = f.name[: -len(".txt")] if f.name.endswith((".go.txt", ".mod.txt")) else f.name
        (dest / name).write_bytes(f.read_bytes())
    return dest


def control() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        planted = materialise(FIXTURES / "planted", Path(tmp) / "planted")
        found = dedupe(scan(planted, sorted(planted.iterdir())))
        files = sorted(p.name for p in planted.iterdir() if p.suffix in SCANNED_EXT)
        clean_dir = materialise(FIXTURES / "clean", Path(tmp) / "clean")
        clean = dedupe(scan(clean_dir, sorted(clean_dir.iterdir())))
    hit = {c.path for c in found}
    return {"planted_files": files, "planted_flagged": sorted(hit),
            "by_tool": sorted({(c.tool, c.path) for c in found}),
            "clean_candidates": [asdict(c) for c in clean],
            "passed": set(files) <= hit and not clean}


def anvil_checkout() -> Path:
    d = recall.RECALL_DATA / "repos" / "anvil"
    if not d.is_dir():
        subprocess.run(["git", "-C", str(REPO_ROOT), "worktree", "add", "--detach", str(d),
                        ANVIL_COMMIT], check=True)
    return d


def run() -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    targets = [(p.name, p.path, p.commit) for p in recall.REPOS]
    targets.append(("anvil", anvil_checkout(), ANVIL_COMMIT))
    rows = []
    for name, path, commit in targets:
        # An interrupted run can leave a checkout at a push commit: start from the pin.
        subprocess.run(["git", "-C", str(path), "checkout", "-q", "--detach", commit], check=True)
        rows.append(measure_repo(name, path, recall.PUSHES))
    out = RUNS_DIR / "counts.json"
    out.write_text(json.dumps({"repos": rows, "control": control()}, indent=1) + "\n")
    return out


def report() -> Path:
    run_doc = json.loads((RUNS_DIR / "counts.json").read_text())
    rows = run_doc["repos"]
    biggest = max(rows, key=lambda r: r["full_scan"])
    worst_push = max(r["per_push_max"] for r in rows)
    ctl = run_doc["control"]
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": biggest["full_scan"],
        "unit": "candidates per full scan, the largest of the sample repositories (per-push "
                "counts and every repository in the artifact)",
        "command": "python -m anvil_eval.experiments.candidates report",
        "git": results.git_state(),
        "pins": {
            "opengrep": "v1.26.0 (eval/tools/opengrep/MANIFEST.toml)",
            "gitlab_sast_rules": {"commit": recall.GITLAB.commit,
                                  "dirs": list(recall.GITLAB_RULE_DIRS)},
            "0xdea_semgrep_rules": recall.OXDEA.commit,
            "gosec": recall.GOSEC, "bandit": recall.BANDIT,
            "repos": {r["repo"]: r["commit"] for r in rows},
        },
        "result": {
            "repos": rows,
            "largest_full_scan": {"repo": biggest["repo"], "candidates": biggest["full_scan"]},
            "largest_push": worst_push,
            "bars": {"full_scan": FULL_BAR, "per_push": PUSH_BAR},
            "within_bars": biggest["full_scan"] < FULL_BAR and worst_push < PUSH_BAR,
        },
        "negative_control": {
            "description": "a planted file per language family must each yield a candidate, and "
                           "a clean file none",
            "expected": "every planted file flagged; no candidate in the clean file",
            "observed": {k: v for k, v in ctl.items() if k != "passed"},
            "passed": ctl["passed"],
        },
    }
    return results.write_artifact(doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.experiments.candidates")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    sub.add_parser("report")
    s = sub.add_parser("scan")
    s.add_argument("root", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "run":
        print(run())
    elif a.cmd == "report":
        print(report())
    else:
        found = dedupe(scan(a.root))
        print(json.dumps({"candidates": len(found)}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

