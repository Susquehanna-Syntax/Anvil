"""The manifest is the supply-chain boundary. These tests defend its shape."""

from __future__ import annotations

import textwrap

import pytest
from anvil_opengrep.errors import ForbiddenRuleSource, ManifestError
from anvil_opengrep.manifest import (
    DEFAULT_MANIFEST_PATH,
    assert_rule_source_permitted,
    load_manifest,
)


def test_manifest_loads_and_pins_the_spine_picks():
    manifest = load_manifest()
    assert manifest.engine_repo == "https://github.com/opengrep/opengrep"
    assert manifest.engine_version == "v1.26.0"
    assert manifest.engine_license == "LGPL-2.1"
    assert manifest.ruleset_name == "AikidoSec/opengrep-rules"
    assert manifest.ruleset_license == "MIT"
    assert manifest.ruleset_commit_sha == "7ac79affecf709eb7263a243b518a417cd7e0ab2"


def test_every_engine_asset_carries_a_full_sha256():
    manifest = load_manifest()
    assert manifest.engine_assets, "no engine assets pinned"
    for asset in manifest.engine_assets:
        assert len(asset.sha256) == 64
        assert asset.url.startswith(
            "https://github.com/opengrep/opengrep/releases/download/v1.26.0/"
        ), f"{asset.platform} asset URL is not pinned to the release tag"
        assert asset.size_bytes > 0


def test_ruleset_is_pinned_by_full_commit_sha_not_a_branch():
    manifest = load_manifest()
    assert len(manifest.ruleset_commit_sha) == 40
    assert manifest.ruleset_commit_sha not in {"main", "HEAD", "master"}
    assert manifest.ruleset_files, "no per-file blob pins recorded"
    # MIT's single condition is that the notice travels with the rules, so the
    # LICENSE file is part of the pin, not an optional extra.
    assert any(f.path == "LICENSE" for f in manifest.ruleset_files)


def test_measured_coverage_is_recorded_honestly():
    """The two-rule corpus is a finding, not an accident. It must stay visible."""
    manifest = load_manifest()
    assert set(manifest.ruleset_rule_ids) == {
        "github_workflow_prompt_injection",
        "npm_staged_publishing_missing",
    }


@pytest.mark.parametrize(
    "source",
    [
        "opengrep/opengrep-rules",
        "https://github.com/opengrep/opengrep-rules",
        "/vendor/opengrep/opengrep-rules",
        "semgrep/semgrep-rules",
        "C:\\vendor\\semgrep-rules",
    ],
)
def test_s5_hard_exclusions_are_refused(source):
    """plan/00-SPINE.md S5. Enforced in code, not in a comment."""
    with pytest.raises(ForbiddenRuleSource):
        assert_rule_source_permitted(source)


@pytest.mark.parametrize(
    "source",
    [
        "AikidoSec/opengrep-rules",
        "https://github.com/AikidoSec/opengrep-rules",
        "/eval/tools/opengrep/vendor/aikido-opengrep-rules/7ac79af",
    ],
)
def test_permitted_rule_source_passes(source):
    assert_rule_source_permitted(source)


def test_manifest_rejects_a_non_subprocess_linkage_claim(tmp_path):
    body = DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8").replace(
        'linkage = "subprocess"', 'linkage = "static"'
    )
    bad = tmp_path / "MANIFEST.toml"
    bad.write_text(body, encoding="utf-8")
    with pytest.raises(ManifestError, match="subprocess"):
        load_manifest(bad)


def test_manifest_rejects_a_short_ruleset_sha(tmp_path):
    body = DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8").replace(
        'commit_sha = "7ac79affecf709eb7263a243b518a417cd7e0ab2"',
        'commit_sha = "7ac79af"',
    )
    bad = tmp_path / "MANIFEST.toml"
    bad.write_text(body, encoding="utf-8")
    with pytest.raises(ManifestError, match="40-char"):
        load_manifest(bad)


def test_manifest_rejects_a_missing_file(tmp_path):
    with pytest.raises(ManifestError, match="not found"):
        load_manifest(tmp_path / "nope.toml")


def test_manifest_rejects_malformed_toml(tmp_path):
    bad = tmp_path / "MANIFEST.toml"
    bad.write_text(textwrap.dedent("""[engine\nversion = """), encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(bad)
