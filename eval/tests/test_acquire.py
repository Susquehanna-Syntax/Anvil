"""Pinned acquisition refuses anything that is not byte-for-byte what was pinned."""

from __future__ import annotations

import hashlib
import json

import pytest

from anvil_eval import acquire
from conftest import json_response

REV = "a" * 40
LICENSE = b"Apache License\nVersion 2.0\n"
WEIGHTS = b"\x00\x01weights" * 1000


def _blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def _hub(files: dict[str, bytes], served: dict[str, bytes] | None = None, lfs=("w.gguf",)):
    """A fake hub: ``files`` is what the tree reports, ``served`` what the resolve URL returns."""
    served = files if served is None else served

    def handler(method, path, body):
        if path.startswith(f"/api/models/org/m/tree/{REV}"):
            tree = []
            for name, data in files.items():
                entry = {"type": "file", "path": name, "size": len(data), "oid": _blob_sha1(data)}
                if name in lfs:
                    entry["lfs"] = {"oid": hashlib.sha256(data).hexdigest(), "size": len(data)}
                tree.append(entry)
            return json_response(tree)
        prefix = f"/org/m/resolve/{REV}/"
        if path.startswith(prefix) and path[len(prefix):] in served:
            return 200, served[path[len(prefix):]], "application/octet-stream"
        return 404, b"", "text/plain"

    return handler


def test_fetches_and_writes_a_manifest(http_stub, tmp_path):
    base = http_stub(_hub({"LICENSE": LICENSE, "w.gguf": WEIGHTS}))
    m = acquire.fetch_hf_repo("org/m", REV, tmp_path, base=base)
    assert (tmp_path / "w.gguf").read_bytes() == WEIGHTS
    assert m["revision"] == REV
    on_disk = json.loads((tmp_path / "MANIFEST.json").read_text())
    assert {f["path"] for f in on_disk["files"]} == {"LICENSE", "w.gguf"}


@pytest.mark.parametrize("victim", ["w.gguf", "LICENSE"])
def test_refuses_a_file_whose_bytes_differ_from_the_pin(http_stub, tmp_path, victim):
    files = {"LICENSE": LICENSE, "w.gguf": WEIGHTS}
    tampered = dict(files)
    tampered[victim] = files[victim][:-1] + b"X"  # same size, different bytes
    base = http_stub(_hub(files, tampered))
    with pytest.raises(acquire.AcquisitionError):
        acquire.fetch_hf_repo("org/m", REV, tmp_path, base=base)
    assert not (tmp_path / victim).exists(), "a refused file must not be left under its name"
    assert not list(tmp_path.glob(".part-*"))


def test_refuses_a_truncated_file(http_stub, tmp_path):
    files = {"w.gguf": WEIGHTS}
    base = http_stub(_hub(files, {"w.gguf": WEIGHTS[:-10]}))
    with pytest.raises(acquire.AcquisitionError, match="bytes"):
        acquire.fetch_hf_repo("org/m", REV, tmp_path, base=base)


def test_a_requested_path_missing_from_the_pin_is_an_error(http_stub, tmp_path):
    base = http_stub(_hub({"LICENSE": LICENSE}))
    with pytest.raises(acquire.AcquisitionError, match="not in the pinned tree"):
        acquire.fetch_hf_repo("org/m", REV, tmp_path, include=["model.gguf"], base=base)


def test_a_branch_name_is_not_a_pin(tmp_path):
    with pytest.raises(acquire.AcquisitionError, match="full commit SHA"):
        acquire.fetch_hf_repo("org/m", "main", tmp_path, base="http://127.0.0.1:1")


def test_a_corrupt_local_copy_is_fetched_again(http_stub, tmp_path):
    base = http_stub(_hub({"w.gguf": WEIGHTS}))
    (tmp_path / "w.gguf").write_bytes(b"stale")
    acquire.fetch_hf_repo("org/m", REV, tmp_path, base=base)
    assert (tmp_path / "w.gguf").read_bytes() == WEIGHTS


def test_fetch_url_checks_the_pinned_sha256(http_stub, tmp_path):
    base = http_stub(lambda m, p, b: (200, b"catalogue", "application/zip"))
    good = hashlib.sha256(b"catalogue").hexdigest()
    assert acquire.fetch_url(f"{base}/c.zip", good, tmp_path / "c.zip").read_bytes() == b"catalogue"
    with pytest.raises(acquire.AcquisitionError, match="sha256"):
        acquire.fetch_url(f"{base}/c.zip", "0" * 64, tmp_path / "d.zip")
    assert not (tmp_path / "d.zip").exists()
    with pytest.raises(acquire.AcquisitionError, match="pinned sha256 is required"):
        acquire.fetch_url(f"{base}/c.zip", "", tmp_path / "e.zip")
