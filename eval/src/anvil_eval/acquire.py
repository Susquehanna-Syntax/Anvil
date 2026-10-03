"""Pinned acquisition: every byte the evaluation reads is fetched at a fixed revision and verified.

Two sources exist. A Hugging Face model repository is fetched file by file at a pinned commit, and
each file is checked against the hash the hub reports for that commit: the SHA-256 of an LFS
object, or the git blob SHA-1 of a small file. Any other artefact (the CWE catalogue, a release
tarball) is fetched from a URL and checked against a SHA-256 written down before the fetch.

A mismatch raises and leaves nothing behind under the final name. Nothing is ever re-hosted: the
payloads land under ``eval/models/`` or ``eval/data/``, which git ignores except for the manifests
this module writes.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

HF_BASE = os.environ.get("ANVIL_HF_BASE", "https://huggingface.co")
_CHUNK = 1 << 20


class AcquisitionError(RuntimeError):
    """A fetch failed, or what arrived is not what was pinned."""


@dataclass(frozen=True)
class RemoteFile:
    path: str
    size: int
    sha256: str | None  # LFS objects only
    git_oid: str  # the git blob SHA-1 the hub reports for every file


def _open(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "anvil-eval"})
    try:
        return urllib.request.urlopen(req, timeout=60)
    except OSError as exc:  # URLError and HTTPError are both OSErrors
        raise AcquisitionError(f"GET {url}: {exc}") from exc


def hf_tree(repo: str, revision: str, base: str = HF_BASE) -> list[RemoteFile]:
    """List every file in ``repo`` at ``revision``, with the hashes the hub records."""
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise AcquisitionError(f"{repo}: revision must be a full commit SHA, got {revision!r}")
    with _open(f"{base}/api/models/{repo}/tree/{revision}?recursive=1") as resp:
        entries = json.load(resp)
    files = []
    for e in entries:
        if e.get("type") != "file":
            continue
        lfs = e.get("lfs") or {}
        files.append(
            RemoteFile(
                path=e["path"],
                size=int(e["size"]),
                sha256=lfs.get("oid"),
                git_oid=e["oid"],
            )
        )
    if not files:
        raise AcquisitionError(f"{repo}@{revision}: the hub lists no files")
    return files


def git_blob_sha1(path: Path) -> str:
    size = path.stat().st_size
    h = hashlib.sha1(f"blob {size}\0".encode())
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path) -> None:
    """Stream ``url`` to a temporary file beside ``dest``; the caller verifies, then renames."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _open(url) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out, _CHUNK)


def _verify(rf: RemoteFile, path: Path) -> str:
    if path.stat().st_size != rf.size:
        raise AcquisitionError(f"{rf.path}: {path.stat().st_size} bytes, pinned {rf.size}")
    digest = sha256_file(path)
    if rf.sha256 is not None:
        if digest != rf.sha256:
            raise AcquisitionError(f"{rf.path}: sha256 {digest}, pinned {rf.sha256}")
    elif git_blob_sha1(path) != rf.git_oid:
        raise AcquisitionError(f"{rf.path}: git blob hash differs from the pinned {rf.git_oid}")
    return digest


def fetch_hf_repo(
    repo: str,
    revision: str,
    dest: Path,
    include: Iterable[str] | None = None,
    base: str = HF_BASE,
) -> dict:
    """Fetch ``repo`` at ``revision`` into ``dest`` and return the manifest it wrote.

    ``include`` limits the fetch to the named paths; a name the hub does not list is an error,
    not a silent omission. A file already present with the pinned hash is not fetched again.
    """
    tree = {rf.path: rf for rf in hf_tree(repo, revision, base)}
    wanted = list(tree) if include is None else list(include)
    missing = [p for p in wanted if p not in tree]
    if missing:
        raise AcquisitionError(f"{repo}@{revision}: not in the pinned tree: {missing}")
    dest.mkdir(parents=True, exist_ok=True)
    recorded = []
    for p in sorted(wanted):
        rf = tree[p]
        final = dest / p
        if final.exists():
            try:
                digest = _verify(rf, final)
            except AcquisitionError:
                final.unlink()
            else:
                recorded.append({"path": p, "size": rf.size, "sha256": digest})
                continue
        final.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=final.parent, prefix=".part-")
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            _download(f"{base}/{repo}/resolve/{revision}/{p}", tmp)
            digest = _verify(rf, tmp)
            tmp.replace(final)
        finally:
            tmp.unlink(missing_ok=True)
        recorded.append({"path": p, "size": rf.size, "sha256": digest})
    manifest = {
        "source": f"{base}/{repo}",
        "repo": repo,
        "revision": revision,
        "acquired_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "files": recorded,
    }
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def fetch_url(url: str, sha256: str, dest: Path) -> Path:
    """Fetch ``url`` to ``dest`` and refuse it unless its SHA-256 is ``sha256``."""
    if len(sha256) != 64:
        raise AcquisitionError(f"{url}: a pinned sha256 is required before fetching")
    if dest.exists() and sha256_file(dest) == sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=".part-")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        _download(url, tmp)
        got = sha256_file(tmp)
        if got != sha256:
            raise AcquisitionError(f"{url}: sha256 {got}, pinned {sha256}")
        tmp.replace(dest)
    finally:
        tmp.unlink(missing_ok=True)
    return dest
