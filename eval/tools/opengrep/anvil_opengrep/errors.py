"""Failure modes for the opengrep acquisition + invocation path.

Every one of these is a hard stop. Nothing in this package degrades gracefully:
a missing binary, a missing ruleset, a checksum mismatch, or an unparseable
result must be loud, because the alternative is INSTR-01 quietly reporting
"0 candidates" for a reason that has nothing to do with the target repo.
"""

from __future__ import annotations


class OpengrepError(Exception):
    """Base class for every failure in this package."""


class ManifestError(OpengrepError):
    """MANIFEST.toml is missing, malformed, or missing a required pin."""


class EngineNotAvailable(OpengrepError):
    """The pinned opengrep binary is not present or not executable.

    Raised instead of returning an empty result set. See README.md ("Failing
    loudly") for why this is never downgraded to a warning.
    """


class RulesetNotAvailable(OpengrepError):
    """The pinned AikidoSec/opengrep-rules checkout is absent or unverified."""


class ChecksumMismatch(OpengrepError):
    """A fetched artefact did not match its pinned digest.

    This is a supply-chain event, not a retry-able network error.
    """


class OpengrepRunError(OpengrepError):
    """opengrep ran but failed: non-recoverable exit code, or timeout."""


class OpengrepOutputError(OpengrepError):
    """opengrep exited plausibly but its stdout was not parseable JSON."""


class ForbiddenRuleSource(OpengrepError):
    """An S5 hard-excluded rule source was passed to the runner.

    plan/00-SPINE.md S5: never opengrep/opengrep-rules (archived, NOASSERTION,
    LGPL-2.1 + Commons Clause), never any Semgrep-maintained ruleset.
    """
