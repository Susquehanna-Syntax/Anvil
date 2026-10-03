"""CWE-Bench-Java (MIT): 120 Java CVEs with buggy commits, fixed methods and build settings.

The seed tables are read from a clone of ``iris-sast/cwe-bench-java`` at the pinned commit. Each
case's project is cloned at its ``buggy_commit_id``. A case becomes a patch-quality case pointed at
the first core file ``fix_info.csv`` lists, with a build and a test command for its build tool.
No case has an exploit oracle, so the loop can report build and test results here but never
``verified_fixed``.

Building needs the JDK and Maven or Gradle version ``build_info.csv`` names per case: JDK 8u202
for most and JDK 17 for the rest. JDK 8u202 is an Oracle build under Oracle's own binary licence,
so which JDK 8 to install is the owner's decision; the JDK homes are passed in, never guessed.
"""

from __future__ import annotations

import csv
import subprocess
from dataclasses import dataclass
from pathlib import Path

from anvil_eval import DATA_DIR
from anvil_eval.data import CorpusError

REPO = "https://github.com/iris-sast/cwe-bench-java.git"
COMMIT = "afe0ebd0adc237abb46255f9cd479b1d71819136"
ROOT = DATA_DIR / "cwe-bench-java"


@dataclass(frozen=True)
class Project:
    slug: str
    cve: str
    cwe: str
    cwe_name: str
    url: str
    buggy_commit: str
    jdk: str
    maven: str
    gradle: str
    fixed_file: str
    fixed_class: str
    fixed_method: str


def _rows(path: Path) -> list[dict]:
    if not path.is_file():
        raise CorpusError(f"{path} is missing; clone {REPO} at {COMMIT}")
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def projects(root: Path = ROOT) -> list[Project]:
    """Every case whose build is recorded as working, joined with its first core fix."""
    info = _rows(root / "data" / "project_info.csv")
    build = {r["project_slug"]: r for r in _rows(root / "data" / "build_info.csv")}
    fixes: dict[str, dict] = {}
    for r in _rows(root / "data" / "fix_info.csv"):
        fixes.setdefault(r["project_slug"], r)
    out = []
    for r in info:
        slug = r["project_slug"]
        b, f = build.get(slug), fixes.get(slug)
        if b is None or f is None or b["status"] != "success":
            continue
        out.append(Project(
            slug=slug, cve=r["cve_id"], cwe=r["cwe_id"], cwe_name=r["cwe_name"],
            url=r["github_url"], buggy_commit=r["buggy_commit_id"], jdk=b["jdk_version"],
            maven=b["mvn_version"], gradle=b["gradle_version"], fixed_file=f["file"],
            fixed_class=f["class"], fixed_method=f["method"],
        ))
    if not out:
        raise CorpusError(f"{root}: no buildable case")
    return out


def finding(p: Project) -> str:
    where = f"{p.fixed_class}.{p.fixed_method}" if p.fixed_method else p.fixed_class
    return f"{p.cwe} {p.cwe_name} in {where} ({p.cve})"


def commands(p: Project) -> tuple[list[str], list[str]]:
    """The build and the test command for the case's build tool."""
    test_filter = f"-Dtest={p.fixed_class}*Test*"
    if p.maven != "n/a":
        base = ["mvn", "-B", "-q", "-Dmaven.javadoc.skip=true", "-Drat.skip=true",
                "-Dcheckstyle.skip=true"]
        return (base + ["-DskipTests", "compile"],
                base + ["test", test_filter, "-DfailIfNoTests=false",
                        "-Dsurefire.failIfNoSpecifiedTests=false"])
    return (["./gradlew", "--offline", "compileJava"],
            ["./gradlew", "--offline", "test", "--tests", f"*{p.fixed_class}*"])


def checkout(p: Project, dest: Path) -> Path:
    if not (dest / ".git").is_dir():
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", p.url], check=True)
    subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin",
                    p.buggy_commit], check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", "--detach", p.buggy_commit],
                   check=True)
    return dest
