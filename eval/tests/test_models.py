"""The candidate catalogue is an allowlist; a candidate's licence evidence is re-read before use."""

from __future__ import annotations

import pytest

from anvil_eval import acquire, models


def test_every_pin_is_a_full_commit_and_every_evidence_a_blob_hash():
    for c in models.CANDIDATES.values():
        assert len(c.revision) == 40 and int(c.revision, 16) >= 0, c.name
        assert len(c.evidence.git_oid) == 40, c.name
        assert c.evidence.kind in ("file", "card") and c.evidence.quote, c.name
        assert c.licence in ("Apache-2.0", "MIT"), c.name


def test_no_excluded_family_is_catalogued():
    for c in models.CANDIDATES.values():
        repo = c.repo.lower()
        assert not any(f in repo for f in models.EXCLUDED_FAMILIES), c.repo
    # Gemma 4 is eligible by name; Gemma 1 to 3 would be refused by the check above.
    assert any("gemma-4" in c.repo.lower() for c in models.CANDIDATES.values())
    assert any(f in "google/gemma-3-1b-it" for f in models.EXCLUDED_FAMILIES)


def _staged(tmp_path, text: str) -> tuple[models.Candidate, object]:
    (tmp_path / "LICENSE").write_text(text)
    oid = acquire.git_blob_sha1(tmp_path / "LICENSE")
    ev = models.Evidence("file", "LICENSE", oid, "Apache License", "2026-10-03", "test")
    c = models.Candidate("x", "test", "org/x", "a" * 40, "Apache-2.0", ev, 0.0, "gguf")
    return c, tmp_path


def test_unchanged_evidence_verifies(tmp_path):
    c, root = _staged(tmp_path, "Apache License\nVersion 2.0\n")
    models.verify_licence(c, root)


def test_changed_evidence_is_refused(tmp_path):
    c, root = _staged(tmp_path, "Apache License\nVersion 2.0\n")
    (root / "LICENSE").write_text("Apache License\nVersion 2.0, plus a field-of-use clause\n")
    with pytest.raises(models.LicenceNotVerified, match="differs"):
        models.verify_licence(c, root)


def test_missing_evidence_is_refused(tmp_path):
    c, root = _staged(tmp_path, "Apache License\n")
    (root / "LICENSE").unlink()
    with pytest.raises(models.LicenceNotVerified, match="missing"):
        models.verify_licence(c, root)


def test_an_unknown_candidate_cannot_be_served():
    with pytest.raises(KeyError, match="not a catalogued candidate"):
        models.get("llama-3-8b")
