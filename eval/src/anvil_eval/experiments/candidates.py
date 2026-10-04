"""Candidates per scan (register row candidates-per-scan, plan node candidatecount).

A permanent instrument. Since Phase 6 it measures through Lane B itself: ``anvil recall``, built
from this checkout, runs the vendored rule pack (``data/rules``, the owner's selection of
2026-10-03) and the native analysers exactly as a repository scan does, and prints the candidates.
There is one implementation of the selection, the exclusions and the de-duplication, and it is the
one that ships; this module only drives it and counts.

* Full scan: the whole checkout at the pinned commit.
* Per push: each of the most recent first-parent commits (up to 20), scanning the files that
  commit touched and keeping only candidates on lines it added or changed.

A missing tool is a refusal and a failed tool is an error; neither is ever a count of zero.
``anvil recall`` exits 4 for the first, and its JSON lists coverage problems (a file a tool was
given and did not scan, a rule that timed out), which the artifact records per repository.

Negative control: Lane B runs over a planted fixture with one known-bad file per language family,
the same files again under a ``tests/`` directory, and a clean file. Every planted file must yield
a candidate, nothing under ``tests/`` may (the selection excludes test trees), and the clean file
must yield none; otherwise the artifact does not validate. The Go file and its go.mod are stored
with a ``.txt`` suffix, because ``eval/`` holds no Go source (``tests/test_scaffold.py``), and are
materialised into a temporary directory for the scan.

The measurement before the narrowing (10,714 candidates on curl, 2026-10-03, commit 66669864) is
carried in the artifact as ``previous``; its raw run is in git history.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from anvil_eval import EVAL_ROOT, REPO_ROOT, RESULTS_DIR, recall, results

ID = "candidates-per-scan"
RUNS_DIR = RESULTS_DIR / "runs" / ID
FULL_BAR, PUSH_BAR = 500, 50
FIXTURES = EVAL_ROOT / "tests" / "fixtures" / "recall"
ANVIL_COMMIT = "1d8657e889cdf292b1ee792ceb36913f6d8539d2"  # main after Phase 4 (#18)
GO = Path.home() / "sdk" / "go1.26.5" / "bin"
RULES = REPO_ROOT / "data" / "rules"

#: The measurement this instrument replaced on 2026-10-03, before the owner's narrowing.
PREVIOUS = {
    "measured_at": "2026-10-03",
    "value": 10714,
    "git_commit": "666698643f22fb1863e7c24cc20c2dbe29610cbc",
    "what": "the whole federation, before the owner's selection: GitLab's seven allowlisted "
            "directories including c/, 0xdea's rules including rules/noisy, bandit B101, no "
            "path exclusions; counted by the Python runners this module then held",
    "full_scan": {"curl": 10714, "flask": 1090, "anvil": 159, "express": 8,
                  "spring-petclinic": 0},
    "largest_push": 88,
}


class ToolMissing(RuntimeError):
    """A recall tool or the rule pack is not installed; the scan is refused, never zero."""


class ToolFailed(RuntimeError):
    """``anvil recall`` ran and failed."""


@dataclass(frozen=True)
class Candidate:
    tool: str
    rule: str  # versioned, as the record carries it
    path: str  # relative to the scanned root
    line: int
    cwe: str


class Anvil:
    """``anvil recall``, built from this checkout and configured with the pinned tools."""

    def __init__(self, workdir: Path):
        self.bin = workdir / "anvil"
        subprocess.run([str(GO / "go"), "build", "-o", str(self.bin), "./cmd/anvil"], check=True,
                       cwd=REPO_ROOT, env=dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="0"))
        self.config = workdir / "anvil.yml"
        self.config.write_text(
            "version: 1\n"
            f"stateDir: {workdir / 'state'}\n"
            "recall:\n"
            f"  rules: {RULES}\n"
            f"  opengrep: {recall.opengrep_bin()}\n"
            f"  gosec: {recall.RECALL_BIN / 'gosec'}\n"
            f"  bandit: {recall.RECALL_VENV / 'bin' / 'bandit'}\n"
            f"  goBin: {GO}\n")

    def recall(self, root: Path, files: list[str] | None = None) -> dict:
        proc = subprocess.run([str(self.bin), "recall", "--config", str(self.config), str(root),
                               *(files or [])], capture_output=True, text=True)
        if proc.returncode == 4:
            raise ToolMissing(proc.stderr.strip())
        if proc.returncode not in (0, 1, 3):
            raise ToolFailed(f"anvil recall exited {proc.returncode}: {proc.stderr[-800:]}")
        return json.loads(proc.stdout)


def candidates_of(doc: dict) -> list[Candidate]:
    return [Candidate(c["tool"], c["ruleIdVersioned"], c["path"], c["startLine"], c["cwe"])
            for c in doc["candidates"]]


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


def per_push(anvil: Anvil, root: Path, pushes: int) -> list[dict]:
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
            found = candidates_of(anvil.recall(root, sorted(lines))) if lines else []
            kept = [f for f in found if f.line in lines.get(f.path, ())]
            rows.append({"commit": c, "files_changed": len(lines), "candidates": len(kept)})
    finally:
        subprocess.run(["git", "-C", str(root), "checkout", "-q", "--detach", head], check=True)
    return rows


def _top(values: list[str], n: int = 10) -> dict[str, int]:
    tally: dict[str, int] = {}
    for v in values:
        tally[v] = tally.get(v, 0) + 1
    return dict(sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[:n])


def measure_repo(anvil: Anvil, name: str, root: Path, pushes: int) -> dict:
    doc = anvil.recall(root)
    full = candidates_of(doc)
    push = per_push(anvil, root, pushes)
    counts = sorted(p["candidates"] for p in push)
    return {
        "repo": name,
        "commit": subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                 capture_output=True, text=True, check=True).stdout.strip(),
        "full_scan": len(full),
        "full_scan_by_tool": doc["byTool"],
        "full_scan_by_rule_top10": _top([c.rule for c in full]),
        "full_scan_by_cwe_top10": _top([c.cwe for c in full]),
        "files_scanned": doc["files"],
        "files_excluded": doc["excluded"],
        "coverage_problems": doc["problems"],
        "partial_parses": doc["partialParses"],
        "pushes": push,
        "per_push_median": counts[len(counts) // 2] if counts else 0,
        "per_push_max": counts[-1] if counts else 0,
    }


def materialise(src: Path, dest: Path) -> Path:
    """Copy a fixture directory, dropping the ``.txt`` that keeps Go sources out of eval/."""
    dest.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        name = f.name[: -len(".txt")] if f.name.endswith((".go.txt", ".mod.txt")) else f.name
        (dest / name).write_bytes(f.read_bytes())
    return dest


def control(anvil: Anvil) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        planted = materialise(FIXTURES / "planted", Path(tmp) / "planted")
        # The same planted files under tests/: the selection excludes test trees, so none of
        # these may be flagged. The Go module stays at the root.
        tests = planted / "tests"
        tests.mkdir()
        for f in planted.iterdir():
            if f.is_file() and f.suffix in (".py", ".js", ".java", ".c"):
                (tests / f.name).write_bytes(f.read_bytes())
        found = candidates_of(anvil.recall(planted))
        files = sorted(p.name for p in planted.iterdir()
                       if p.is_file() and p.suffix in (".py", ".js", ".java", ".c", ".go"))
        clean_dir = materialise(FIXTURES / "clean", Path(tmp) / "clean")
        clean = candidates_of(anvil.recall(clean_dir))
    hit = {c.path for c in found}
    in_tests = sorted(c.path for c in found if c.path.startswith("tests/"))
    return {"planted_files": files, "planted_flagged": sorted(hit - set(in_tests)),
            "flagged_under_tests": in_tests,
            "by_tool": sorted({(c.tool, c.path) for c in found}),
            "clean_candidates": [c.__dict__ for c in clean],
            "passed": set(files) <= hit and not in_tests and not clean}


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
    with tempfile.TemporaryDirectory() as tmp:
        anvil = Anvil(Path(tmp))
        rows = []
        for name, path, commit in targets:
            # An interrupted run can leave a checkout at a push commit: start from the pin.
            subprocess.run(["git", "-C", str(path), "checkout", "-q", "--detach", commit],
                           check=True)
            rows.append(measure_repo(anvil, name, path, recall.PUSHES))
        ctl = control(anvil)
    out = RUNS_DIR / "counts.json"
    out.write_text(json.dumps({"repos": rows, "control": ctl}, indent=1) + "\n")
    return out


def report() -> Path:
    run_doc = json.loads((RUNS_DIR / "counts.json").read_text())
    rows = run_doc["repos"]
    biggest = max(rows, key=lambda r: r["full_scan"])
    worst_push = max(r["per_push_max"] for r in rows)
    ctl = run_doc["control"]
    selection = json.loads((RULES / "selection.json").read_text())
    manifest = json.loads((RULES / "MANIFEST.json").read_text())
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": biggest["full_scan"],
        "unit": "candidates per full scan, the largest of the sample repositories (per-push "
                "counts and every repository in the artifact)",
        "command": "python -m anvil_eval.experiments.candidates report",
        "git": results.git_state(),
        "pins": {
            "measured_through": "anvil recall, built from the commit in git",
            "selection_sha256": manifest["selection_sha256"],
            "selection_decided": f"{selection['decided_by']}, {selection['decided_on']}",
            "rule_files": len(manifest["rules"]),
            "corpora": {c["name"]: {"commit": c["commit"], "directories": c["directories"]}
                        for c in selection["corpora"]},
            "tools": {t["name"]: t["version"] for t in selection["tools"]},
            "gosec": recall.GOSEC, "bandit": recall.BANDIT,
            "repos": {r["repo"]: r["commit"] for r in rows},
        },
        "result": {
            "repos": rows,
            "largest_full_scan": {"repo": biggest["repo"], "candidates": biggest["full_scan"]},
            "largest_push": worst_push,
            "bars": {"full_scan": FULL_BAR, "per_push": PUSH_BAR},
            "within_bars": biggest["full_scan"] < FULL_BAR and worst_push < PUSH_BAR,
            "previous": PREVIOUS,
        },
        "negative_control": {
            "description": "a planted file per language family must each yield a candidate, the "
                           "same files under tests/ none, and a clean file none",
            "expected": "every planted file flagged; nothing under tests/; no candidate in the "
                        "clean file",
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
        with tempfile.TemporaryDirectory() as tmp:
            doc = Anvil(Path(tmp)).recall(a.root)
        print(json.dumps({k: v for k, v in doc.items() if k != "candidates"}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
