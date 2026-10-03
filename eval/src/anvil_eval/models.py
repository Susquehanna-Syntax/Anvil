"""The candidate models, each pinned to a revision with the licence evidence read at that revision.

A candidate is served only from this catalogue, and only after :func:`verify_licence` has re-read
its licence evidence from the acquired files and found it unchanged. The plan's rule (plan node
models) is that a candidate whose licence cannot be verified from its own text at its pinned
revision is dropped before any run; here that is a refusal, not a convention.

Two kinds of evidence exist. ``file`` is a licence body shipped in the repository (``LICENSE``),
pinned by its git blob hash. ``card`` is the model card's own prose naming the licence, used where
the repository ships no licence file; it is pinned by the card's blob hash and the exact sentence
must still be in it. Registry metadata (the hub's ``license:`` tag) is never evidence.

Usage (owner-run; it downloads gigabytes)::

    python -m anvil_eval.models acquire qwen3.5-2b
    python -m anvil_eval.models convert qwen3.5-2b      # needs eval/.venv-convert and llama.cpp
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from anvil_eval import MODELS_DIR, acquire

LLAMA_CPP_BUILD = "b11146"
LLAMA_CPP_COMMIT = "7fe450e19305b828c199d602c23a8337aaa1f03b"
LLAMA_CPP_DIR = Path(
    os.environ.get("ANVIL_LLAMA_CPP", Path.home() / ".local/opt/llama.cpp-b11146")
)


class LicenceNotVerified(RuntimeError):
    """The candidate's licence evidence is missing or no longer what was read."""


@dataclass(frozen=True)
class Evidence:
    kind: str  # "file" or "card"
    path: str
    git_oid: str
    quote: str  # a sentence that must appear in the file; for "file", its licence title
    read_on: str
    note: str


@dataclass(frozen=True)
class Candidate:
    name: str
    role: str
    repo: str
    revision: str
    licence: str
    evidence: Evidence
    size_gb: float
    convert: str  # "gguf" or "onnx"

    @property
    def dir(self) -> Path:
        return MODELS_DIR / self.name

    @property
    def hf_dir(self) -> Path:
        return self.dir / "hf"

    def gguf(self, quant: str) -> Path:
        return self.dir / "gguf" / f"{self.name}-{quant}.gguf"


_APACHE_NOTE = (
    "Apache-2.0 body; identical to apache.org's LICENSE-2.0.txt except that the appendix's "
    "copyright placeholder is filled in"
)

CANDIDATES: dict[str, Candidate] = {
    c.name: c
    for c in [
        Candidate(
            name="qwen3.5-2b",
            role="adjudicator, primary",
            repo="Qwen/Qwen3.5-2B",
            revision="15852e8c16360a2fea060d615a32b45270f8a8fc",
            licence="Apache-2.0",
            evidence=Evidence(
                "file", "LICENSE", "f938136e3adacfd92be087f6e113b5d6d97f678f",
                "Apache License", "2026-10-03",
                _APACHE_NOTE + " ('Copyright 2026 Alibaba Cloud'). The checkpoint is "
                "vision-language (Qwen3_5ForConditionalGeneration); no text-only repository "
                "exists. llama.cpp converts the language model alone, and Anvil serves it "
                "without a vision projector, which is the text-only configuration.",
            ),
            size_gb=4.57,
            convert="gguf",
        ),
        Candidate(
            name="gemma-4-e2b-it",
            role="adjudicator, second",
            repo="google/gemma-4-E2B-it",
            revision="3e22461f65e89153144f8adb70e3b8c2cc9845a7",
            licence="Apache-2.0",
            evidence=Evidence(
                "card", "README.md", "61e18105d7cb61ce375aa16ed66442b85116bb8a",
                '<b>License</b>: <a href="https://ai.google.dev/gemma/docs/gemma_4_license" '
                'target="_blank">Apache 2.0</a>',
                "2026-10-03",
                "No LICENSE file in the repository. The card's own text names Apache 2.0 and "
                "links ai.google.dev/gemma/docs/gemma_4_license, which on 2026-10-03 held the "
                "Apache 2.0 text. The card does not incorporate the older Gemma terms or "
                "prohibited-use policy; that page's navigation links to them, and nothing in "
                "the card refers to them.",
            ),
            size_gb=10.28,
            convert="gguf",
        ),
        Candidate(
            name="qwen3.5-0.8b",
            role="adjudicator, fallback (not acquired)",
            repo="Qwen/Qwen3.5-0.8B",
            revision="2fc06364715b967f1860aea9cf38778875588b17",
            licence="Apache-2.0",
            evidence=Evidence(
                "file", "LICENSE", "f938136e3adacfd92be087f6e113b5d6d97f678f",
                "Apache License", "2026-10-03", _APACHE_NOTE,
            ),
            size_gb=1.77,
            convert="gguf",
        ),
        Candidate(
            name="smollm3-3b",
            role="adjudicator, auditability runner-up (not acquired)",
            repo="HuggingFaceTB/SmolLM3-3B",
            revision="a07cc9a04f16550a088caea529712d1d335b0ac1",
            licence="Apache-2.0",
            evidence=Evidence(
                "card", "README.md", "4877f429e45d2f112c03ac14c00b19b97cadc914",
                "## License\n[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)",
                "2026-10-03", "No LICENSE file; the card's License section names Apache 2.0.",
            ),
            size_gb=6.17,
            convert="gguf",
        ),
        Candidate(
            name="phi-4-mini-instruct",
            role="adjudicator, most permissive (not acquired)",
            repo="microsoft/Phi-4-mini-instruct",
            revision="cfbefacb99257ffa30c83adab238a50856ac3083",
            licence="MIT",
            evidence=Evidence(
                "file", "LICENSE", "8ab7b4964d147858b89544e8ca33203237161edc",
                "MIT License", "2026-10-03", "MIT body, 'Copyright (c) Microsoft Corporation.'",
            ),
            size_gb=7.69,
            convert="gguf",
        ),
        Candidate(
            name="unixcoder-base",
            role="encoder",
            repo="microsoft/unixcoder-base",
            revision="5604afdc964f6c53782a6813140ade5216b99006",
            licence="Apache-2.0",
            evidence=Evidence(
                "card", "README.md", "06edcdcd5105be959feae49b1318bb2cb3e4685f",
                "- **License:** Apache-2.0", "2026-10-03",
                "No LICENSE file; the card's prose names Apache-2.0. The weights are a pickled "
                "pytorch_model.bin, so the ONNX export loads them with torch.load(weights_only="
                "True) and nothing else ever unpickles them.",
            ),
            size_gb=0.51,
            convert="onnx",
        ),
        Candidate(
            name="qwen3-coder-30b-a3b",
            role="coder, patch quality (not acquired)",
            repo="Qwen/Qwen3-Coder-30B-A3B-Instruct",
            revision="b2cff646eb4bb1d68355c01b18ae02e7cf42d120",
            licence="Apache-2.0",
            evidence=Evidence(
                "file", "LICENSE", "6634c8cc3133b3848ec74b9f275acaaa1ea618ab",
                "Apache License", "2026-10-03", _APACHE_NOTE + " ('Copyright 2024 Alibaba Cloud')",
            ),
            size_gb=61.08,
            convert="gguf",
        ),
    ]
}

#: Families the plan excludes on licence grounds (plan node models). Matched against the repo id
#: of every catalogue entry by a test; the catalogue itself is the allowlist.
EXCLUDED_FAMILIES = ("gemma-1", "gemma-2", "gemma-3", "gemma-7b", "gemma-2b", "llama",
                     "starcoder2", "mistral", "mixtral", "codestral")


def get(name: str) -> Candidate:
    try:
        return CANDIDATES[name]
    except KeyError:
        raise KeyError(f"{name!r} is not a catalogued candidate: {sorted(CANDIDATES)}") from None


def verify_licence(c: Candidate, root: Path | None = None) -> None:
    """Re-read ``c``'s licence evidence from the acquired files; raise unless it is unchanged."""
    path = (root or c.hf_dir) / c.evidence.path
    if not path.is_file():
        raise LicenceNotVerified(f"{c.name}: {path} is missing; acquire the model first")
    if acquire.git_blob_sha1(path) != c.evidence.git_oid:
        raise LicenceNotVerified(f"{c.name}: {c.evidence.path} differs from the text read")
    if c.evidence.quote not in path.read_text(encoding="utf-8"):
        raise LicenceNotVerified(f"{c.name}: {c.evidence.path} no longer says {c.evidence.quote!r}")


def acquire_candidate(c: Candidate) -> dict:
    manifest = acquire.fetch_hf_repo(c.repo, c.revision, c.hf_dir)
    verify_licence(c)
    manifest["licence"] = {"spdx": c.licence, "evidence": c.evidence.__dict__}
    (c.dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _bin(name: str) -> Path:
    return LLAMA_CPP_DIR / f"llama-{LLAMA_CPP_BUILD}" / name


def convert_candidate(c: Candidate, quants: tuple[str, ...] = ("Q4_K_M", "Q8_0")) -> dict:
    """Convert to BF16 GGUF with llama.cpp's own converter, then quantise. Records every hash."""
    verify_licence(c)
    if c.convert != "gguf":
        raise ValueError(f"{c.name} converts to {c.convert}; use anvil_eval.encoder export")
    py = Path(__file__).resolve().parents[2] / ".venv-convert" / "bin" / "python"
    out = c.gguf("BF16")
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(py), str(LLAMA_CPP_DIR / "src" / "convert_hf_to_gguf.py"), str(c.hf_dir),
         "--outtype", "bf16", "--outfile", str(out)],
        check=True,
    )
    env = dict(os.environ, LD_LIBRARY_PATH=str(_bin("")))
    files = {"BF16": out}
    for q in quants:
        subprocess.run([str(_bin("llama-quantize")), str(out), str(c.gguf(q)), q],
                       check=True, env=env)
        files[q] = c.gguf(q)
    record = {
        "llama_cpp": {"build": LLAMA_CPP_BUILD, "commit": LLAMA_CPP_COMMIT},
        "from": {"repo": c.repo, "revision": c.revision},
        "files": {q: {"path": p.name, "sha256": acquire.sha256_file(p)} for q, p in files.items()},
    }
    (c.dir / "gguf" / "MANIFEST.json").write_text(json.dumps(record, indent=2) + "\n",
                                                  encoding="utf-8")
    return record


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.models")
    ap.add_argument("action", choices=["list", "acquire", "verify", "convert"])
    ap.add_argument("names", nargs="*")
    a = ap.parse_args(argv)
    if a.action == "list":
        for c in CANDIDATES.values():
            print(f"{c.name:22} {c.size_gb:6.2f} GB  {c.licence:10} {c.repo}@{c.revision[:12]}"
                  f"  ({c.role})")
        return 0
    for name in a.names:
        c = get(name)
        if a.action == "acquire":
            acquire_candidate(c)
        elif a.action == "verify":
            verify_licence(c)
        else:
            convert_candidate(c)
        print(f"{name}: {a.action} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
