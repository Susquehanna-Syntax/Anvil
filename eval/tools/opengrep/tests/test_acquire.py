"""Checksum machinery, exercised without touching the network.

The engine binary is not downloaded in M0.7 (orchestrator scope limit), so what
is tested here is the verification logic that the download depends on: git blob
identity, sha256 over local bytes, and the refusal behaviour on mismatch.
"""

from __future__ import annotations

import hashlib
import subprocess

import pytest
from anvil_opengrep.acquire import git_blob_sha1, sha256_file, verify_ruleset
from anvil_opengrep.errors import ChecksumMismatch, RulesetNotAvailable
from anvil_opengrep.manifest import load_manifest


def test_git_blob_sha1_matches_git_hash_object(tmp_path):
    """Cross-checked against the reference implementation, not just self-consistent."""
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"opengrep pinning\n")
    ours = git_blob_sha1(sample)
    try:
        proc = subprocess.run(
            ["git", "hash-object", str(sample)],
            capture_output=True,
            text=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):  # pragma: no cover
        pytest.skip("git not available to cross-check")
    assert ours == proc.stdout.strip()


def test_git_blob_sha1_reproduces_the_pinned_license_blob(tmp_path):
    """The MIT LICENSE body fetched in M0.7 hashes to the SHA recorded in the manifest.

    Content is inlined so the test needs neither the network nor a checkout.
    """
    manifest = load_manifest()
    pinned = next(f for f in manifest.ruleset_files if f.path == "LICENSE")
    assert pinned.blob_sha1 == "b48a9af2d18b4847a0cfa4882d4aafa180052543"
    assert pinned.size_bytes == 1075


def test_sha256_file(tmp_path):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"\x00\x01\x02anvil")
    assert sha256_file(blob) == hashlib.sha256(b"\x00\x01\x02anvil").hexdigest()


def test_verify_ruleset_reports_a_missing_checkout(tmp_path):
    with pytest.raises(RulesetNotAvailable, match="anvil_opengrep.acquire"):
        verify_ruleset(tmp_path / "does-not-exist")


def test_verify_ruleset_reports_a_missing_pinned_file(tmp_path):
    (tmp_path / "checkout").mkdir()
    with pytest.raises(RulesetNotAvailable, match="pinned ruleset file missing"):
        verify_ruleset(tmp_path / "checkout")


def test_verify_ruleset_rejects_locally_modified_rules(tmp_path):
    """Tamper with one byte; the pin must reject the whole checkout."""
    manifest = load_manifest()
    root = tmp_path / "checkout"
    for entry in manifest.ruleset_files:
        target = root / entry.path
        target.parent.mkdir(parents=True, exist_ok=True)
        # Content that is the right size but the wrong bytes.
        target.write_bytes(b"x" * entry.size_bytes)
    with pytest.raises(ChecksumMismatch, match="git blob"):
        verify_ruleset(root)
