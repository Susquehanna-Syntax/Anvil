"""Anvil M0.7 — pinned acquisition + subprocess wrapper for the opengrep engine.

The deterministic recall tier (plan/00-SPINE.md S4) is the opengrep engine
(LGPL-2.1) driven by AikidoSec/opengrep-rules (MIT). This package is the
evaluation harness's side of that: it reads MANIFEST.toml, fetches exactly the
pinned artefacts and nothing else, and invokes the engine as a subprocess.

opengrep is invoked as a SUBPROCESS ONLY, never linked. It is an OCaml CLI with
zero bindings in any language (plan/00-SPINE.md S12), so subprocess is not a
preference here, it is the only option that exists.
"""

from __future__ import annotations

from .errors import (
    ChecksumMismatch,
    EngineNotAvailable,
    ForbiddenRuleSource,
    ManifestError,
    OpengrepError,
    OpengrepOutputError,
    OpengrepRunError,
    RulesetNotAvailable,
)
from .manifest import Manifest, load_manifest
from .runner import Finding, OpengrepRunner, ScanResult

__all__ = [
    "ChecksumMismatch",
    "EngineNotAvailable",
    "Finding",
    "ForbiddenRuleSource",
    "Manifest",
    "ManifestError",
    "OpengrepError",
    "OpengrepOutputError",
    "OpengrepRunError",
    "OpengrepRunner",
    "RulesetNotAvailable",
    "ScanResult",
    "load_manifest",
]
