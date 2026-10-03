"""The recall federation's pins and acquisition (plan node recall; the owner chose it 2026-10-03).

Rule corpora and sample repositories are fetched with git at a pinned commit, so the content is
verified by the commit hash itself. Binaries are fetched from their release pages and checked
against the SHA-256 the release publishes. Payloads land under ``eval/tools/recall/bin`` and
``eval/data/recall``, which git ignores.

GitLab's sast-rules is not uniformly MIT: its LICENSE puts ``doc/`` under CC BY-SA 4.0 and keeps
third-party components under their own licences. Only the seven rule directories in
``GITLAB_RULE_DIRS`` are ever read, which is the directory allowlist the plan asks Phase 6 to
enforce when it vendors them.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tarfile
import venv
from dataclasses import dataclass
from pathlib import Path

from anvil_eval import DATA_DIR, EVAL_ROOT, TOOLS_DIR, acquire

RECALL_DATA = DATA_DIR / "recall"
RECALL_BIN = TOOLS_DIR / "recall" / "bin"
RECALL_VENV = EVAL_ROOT / ".venv-recall"


def opengrep_bin() -> Path:
    """The engine ``eval/tools/opengrep`` pins (release v1.26.0, sha256-verified on fetch)."""
    sys.path.insert(0, str(TOOLS_DIR / "opengrep"))
    from anvil_opengrep.acquire import engine_path

    return engine_path()


@dataclass(frozen=True)
class GitPin:
    name: str
    url: str
    commit: str
    depth: int
    language: str = ""
    licence: str = ""

    @property
    def path(self) -> Path:
        return RECALL_DATA / ("rules" if not self.language else "repos") / self.name


GITLAB = GitPin("gitlab-sast-rules",
                "https://gitlab.com/gitlab-org/security-products/sast-rules.git",
                "53bf5cf6df3c51b6c02110f5a638b5e6213666cd", 1,
                licence="MIT Expat (allowlisted dirs)")
OXDEA = GitPin("0xdea-semgrep-rules", "https://github.com/0xdea/semgrep-rules.git",
               "dae50da6e6e629750f1daec73a01ef9206a372ab", 1, licence="MIT")
GITLAB_RULE_DIRS = ("c", "csharp", "go", "java", "javascript", "python", "scala")

PUSHES = 20
REPOS = (
    GitPin("flask", "https://github.com/pallets/flask.git",
           "d73fa1cdcbd8b1465c151db8924ba58b1dd14e35", PUSHES + 1, "python"),
    GitPin("curl", "https://github.com/curl/curl.git",
           "21983c2fca1e4ecf3393e94455b343d082b6f1c9", PUSHES + 1, "c"),
    GitPin("spring-petclinic", "https://github.com/spring-projects/spring-petclinic.git",
           "500158f732419217507c7656904b8e6aa1bcc0d6", PUSHES + 1, "java"),
    GitPin("express", "https://github.com/expressjs/express.git",
           "7ef98448f8b38099ab1ded55e458538ad47a51e7", PUSHES + 1, "javascript"),
)

GOSEC = {
    "version": "2.29.0",
    "url": "https://github.com/securego/gosec/releases/download/v2.29.0/"
           "gosec_2.29.0_linux_amd64.tar.gz",
    "sha256": "6431b119741c1f4a50fdfcf94e782e16b9e642afc8c7fa9b5d39d48bf3003095",
    "licence": "Apache-2.0",
}
BANDIT = {"version": "1.9.4", "licence": "Apache-2.0"}


def git_fetch(pin: GitPin) -> Path:
    """Fetch ``pin.commit`` (and ``pin.depth`` - 1 ancestors) into its directory; verify HEAD."""
    d = pin.path
    if not (d / ".git").is_dir():
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        subprocess.run(["git", "-C", str(d), "remote", "add", "origin", pin.url], check=True)
    subprocess.run(["git", "-C", str(d), "fetch", "-q", "--depth", str(pin.depth), "origin",
                    pin.commit], check=True)
    subprocess.run(["git", "-C", str(d), "checkout", "-q", "--detach", pin.commit], check=True)
    head = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    if head != pin.commit:
        raise acquire.AcquisitionError(f"{pin.name}: HEAD is {head}, pinned {pin.commit}")
    return d


def fetch_gosec() -> Path:
    tarball = RECALL_BIN.parent / "gosec_2.29.0_linux_amd64.tar.gz"
    acquire.fetch_url(GOSEC["url"], GOSEC["sha256"], tarball)
    with tarfile.open(tarball) as t:
        t.extract("gosec", RECALL_BIN, filter="data")
    return RECALL_BIN / "gosec"


def make_bandit_venv() -> Path:
    if not (RECALL_VENV / "bin" / "bandit").is_file():
        venv.create(RECALL_VENV, with_pip=True)
        subprocess.run([str(RECALL_VENV / "bin" / "python"), "-m", "pip", "install", "-q",
                        f"bandit=={BANDIT['version']}"], check=True)
    return RECALL_VENV / "bin" / "bandit"


def acquire_all() -> dict:
    out = {}
    for pin in (GITLAB, OXDEA, *REPOS):
        git_fetch(pin)
        out[pin.name] = pin.commit
    out["gosec"] = str(fetch_gosec())
    out["bandit"] = str(make_bandit_venv())
    subprocess.run([sys.executable, "-m", "anvil_opengrep.acquire", "--engine"], check=True,
                   cwd=TOOLS_DIR / "opengrep")
    out["opengrep"] = str(opengrep_bin())
    return out


if __name__ == "__main__":
    if sys.argv[1:] != ["acquire"]:
        sys.exit("usage: python -m anvil_eval.recall acquire")
    print(json.dumps(acquire_all(), indent=1))
