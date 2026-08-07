"""Pinned acquisition of the opengrep engine and the AikidoSec ruleset.

Nothing here runs on import, and nothing here is invoked by the runner. The
harness operator runs `python -m anvil_opengrep.acquire` once, deliberately.

Two invariants:

1. **Only what MANIFEST.toml pins.** No "latest", no version resolution, no
   redirect to an unpinned URL. The URL comes out of the manifest verbatim.
2. **Checksum or nothing.** The engine asset must match its pinned sha256 and
   the ruleset checkout must match its pinned commit SHA and per-file git blob
   SHAs. A mismatch raises ChecksumMismatch and deletes the partial download; it
   is never retried, never warned about, never ignored.

The digests in MANIFEST.toml were read from the GitHub Releases API in-session
and have not yet been confirmed by downloading the asset (see the honesty note
in the manifest). This module is where that confirmation happens.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from .errors import ChecksumMismatch, OpengrepError, RulesetNotAvailable
from .manifest import Manifest, assert_rule_source_permitted, load_manifest

# Where acquired artefacts land. Kept out of git (see .gitignore in this dir).
DEFAULT_VENDOR_DIR = Path(__file__).resolve().parent.parent / "vendor"
ENGINE_SUBDIR = "engine"
# NOT "opengrep-rules" and NOT nested under a dir called "opengrep": the S5
# substring guard in manifest.assert_rule_source_permitted would (correctly)
# refuse a path containing "opengrep/opengrep-rules".
RULES_SUBDIR = "aikido-opengrep-rules"

_CHUNK = 1 << 20


def engine_path(vendor_dir: Path | None = None, manifest: Manifest | None = None) -> Path:
    """Filesystem location the pinned engine binary is installed to."""
    manifest = manifest or load_manifest()
    vendor = Path(vendor_dir) if vendor_dir else DEFAULT_VENDOR_DIR
    return vendor / ENGINE_SUBDIR / manifest.engine_version / manifest.asset_for().filename


def ruleset_path(vendor_dir: Path | None = None, manifest: Manifest | None = None) -> Path:
    """Filesystem location the pinned ruleset checkout is installed to."""
    manifest = manifest or load_manifest()
    vendor = Path(vendor_dir) if vendor_dir else DEFAULT_VENDOR_DIR
    return vendor / RULES_SUBDIR / manifest.ruleset_commit_sha


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1(path: Path) -> str:
    """Compute the git blob object id for a file: sha1(b"blob <len>\\0" + content).

    Content-addressed and stable forever, unlike a codeload tarball, so a
    checkout can be verified file-by-file without trusting git or the network.
    """
    data = Path(path).read_bytes()
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324 - git's object id, not a security hash


def fetch_engine(
    vendor_dir: Path | None = None,
    manifest: Manifest | None = None,
    platform_key: str | None = None,
) -> Path:
    """Download the pinned opengrep binary for this host and verify its sha256."""
    manifest = manifest or load_manifest()
    asset = manifest.asset_for(platform_key)
    vendor = Path(vendor_dir) if vendor_dir else DEFAULT_VENDOR_DIR
    dest_dir = vendor / ENGINE_SUBDIR / manifest.engine_version
    dest = dest_dir / asset.filename

    if dest.is_file():
        actual = sha256_file(dest)
        if actual == asset.sha256:
            return dest
        raise ChecksumMismatch(
            f"existing {dest} has sha256 {actual}, manifest pins {asset.sha256}. "
            "Delete it deliberately; this file is not overwritten automatically."
        )

    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(dest_dir), prefix=".partial-")
    os.close(tmp_fd)
    tmp = Path(tmp_name)
    try:
        # The URL is manifest-pinned; it is never derived from user input.
        with urllib.request.urlopen(asset.url) as response, tmp.open("wb") as out:  # noqa: S310
            shutil.copyfileobj(response, out, _CHUNK)
        actual = sha256_file(tmp)
        if actual != asset.sha256:
            raise ChecksumMismatch(
                f"{asset.url}\n  expected sha256 {asset.sha256}\n  actual   sha256 {actual}\n"
                "Supply-chain mismatch. Not retried. Investigate before proceeding."
            )
        size = tmp.stat().st_size
        if size != asset.size_bytes:
            raise ChecksumMismatch(
                f"{asset.url}: size {size} != pinned {asset.size_bytes} "
                "(digest matched, which is odd)"
            )
        tmp.replace(dest)
    finally:
        if tmp.exists():
            tmp.unlink()

    if os.name != "nt":
        dest.chmod(dest.stat().st_mode | 0o111)
    return dest


def fetch_ruleset(vendor_dir: Path | None = None, manifest: Manifest | None = None) -> Path:
    """Clone AikidoSec/opengrep-rules and hard-check out the pinned commit SHA.

    git is used only as a transport. Trust comes from `verify_ruleset`, which
    re-derives every file's git blob id locally.
    """
    manifest = manifest or load_manifest()
    assert_rule_source_permitted(manifest.ruleset_repo)
    dest = ruleset_path(vendor_dir, manifest)
    if dest.is_dir():
        verify_ruleset(dest, manifest)
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=str(dest.parent), prefix=".clone-"))
    try:
        # core.autocrlf=false / core.eol=lf are load-bearing, not cosmetic. With
        # git's Windows defaults the working tree gets CRLF line endings and every
        # file's bytes stop matching its blob id, so verify_ruleset correctly but
        # uselessly rejects an otherwise-pristine checkout. Forcing LF makes the
        # checkout byte-identical to the pinned objects on every platform.
        _git(
            [
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "clone",
                "--quiet",
                "--no-checkout",
                manifest.ruleset_repo,
                str(staging / "repo"),
            ]
        )
        repo = staging / "repo"
        _git(
            [
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "-C",
                str(repo),
                "checkout",
                "--quiet",
                "--detach",
                manifest.ruleset_commit_sha,
            ]
        )
        head = _git(["-C", str(repo), "rev-parse", "HEAD"]).strip()
        if head != manifest.ruleset_commit_sha:
            raise ChecksumMismatch(
                f"checked out HEAD {head} != pinned {manifest.ruleset_commit_sha}"
            )
        _rmtree(repo / ".git")
        repo.replace(dest)
    finally:
        _rmtree(staging)

    verify_ruleset(dest, manifest)
    return dest


def verify_ruleset(path: Path, manifest: Manifest | None = None) -> None:
    """Re-derive each pinned file's git blob id from local bytes.

    Raises RulesetNotAvailable if a pinned file is missing, ChecksumMismatch if
    its content differs from the pin. The MIT LICENSE file is included in the
    pin set on purpose: MIT's only condition is that the notice travels with the
    rules, so an absent LICENSE is a compliance failure, not a cosmetic one.
    """
    manifest = manifest or load_manifest()
    root = Path(path)
    if not root.is_dir():
        raise RulesetNotAvailable(
            f"pinned ruleset checkout missing at {root}. "
            "Run: python -m anvil_opengrep.acquire --rules"
        )
    for entry in manifest.ruleset_files:
        target = root / entry.path
        if not target.is_file():
            raise RulesetNotAvailable(f"pinned ruleset file missing: {target}")
        actual = git_blob_sha1(target)
        if actual != entry.blob_sha1:
            raise ChecksumMismatch(
                f"{target}\n  expected git blob {entry.blob_sha1}\n  actual   git blob {actual}\n"
                f"The pinned ruleset at {manifest.ruleset_commit_sha} has been modified locally."
            )


def _rmtree(path: Path) -> None:
    """rmtree that survives git's read-only pack files on Windows."""

    def _on_error(func, target, _exc):  # pragma: no cover - platform dependent
        try:
            os.chmod(target, 0o700)
            func(target)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, t, e: _on_error(f, t, e))
    else:  # pragma: no cover - Python 3.11 fallback
        shutil.rmtree(path, onerror=lambda f, t, e: _on_error(f, t, e))


def _git(args: list[str]) -> str:
    if shutil.which("git") is None:
        raise OpengrepError("git is not on PATH; it is required to fetch the pinned ruleset")
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise OpengrepError(
            f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m anvil_opengrep.acquire",
        description="Fetch the MANIFEST.toml-pinned opengrep engine and AikidoSec ruleset.",
    )
    parser.add_argument("--engine", action="store_true", help="fetch the pinned engine binary")
    parser.add_argument("--rules", action="store_true", help="fetch the pinned ruleset checkout")
    parser.add_argument("--vendor-dir", default=None, help="override the vendor directory")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify what is already on disk; download nothing",
    )
    args = parser.parse_args(argv)

    if not args.engine and not args.rules:
        args.engine = args.rules = True

    manifest = load_manifest()
    vendor = Path(args.vendor_dir) if args.vendor_dir else None

    print(f"manifest        : {manifest.path}")
    print(
        f"engine          : {manifest.engine_repo} {manifest.engine_version} "
        f"({manifest.engine_license})"
    )
    print(
        f"ruleset         : {manifest.ruleset_name} @ {manifest.ruleset_commit_sha} "
        f"({manifest.ruleset_license})"
    )

    try:
        if args.rules:
            target = ruleset_path(vendor, manifest)
            if args.verify_only:
                verify_ruleset(target, manifest)
                print(f"ruleset verified: {target}")
            else:
                print(f"ruleset at      : {fetch_ruleset(vendor, manifest)}")
        if args.engine:
            target = engine_path(vendor, manifest)
            if args.verify_only:
                if not target.is_file():
                    raise OpengrepError(f"engine binary absent at {target}")
                actual = sha256_file(target)
                expected = manifest.asset_for().sha256
                if actual != expected:
                    raise ChecksumMismatch(f"{target}: {actual} != pinned {expected}")
                print(f"engine verified : {target}")
            else:
                print(f"engine at       : {fetch_engine(vendor, manifest)}")
    except OpengrepError as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
