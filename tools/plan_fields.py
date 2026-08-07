#!/usr/bin/env python3
"""Extract cross-area shared vocabulary from plan/ for the semantic-contradiction gate.

plan/IMPLEMENTATION-PLAN.md section 4 records that no cross-family critic ever
reviewed the assembled plan, and that the deterministic check in section 2.6
"cannot catch a semantic contradiction such as two areas meaning different
things by the same field name". This script does the mechanical half of that
gate: it finds every shared name and prints where each one is used, so the
semantic half has a small, exact input instead of 480 KB of plan text.

    python tools/plan_fields.py                 # collisions only
    python tools/plan_fields.py --all           # every extracted name
    python tools/plan_fields.py --deps          # Dependency Summary bundle
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

PLAN_DIR = Path(__file__).resolve().parent.parent / "plan"

AREAS = {
    "10-milestone0-evaluation.md": "M0",
    "20-lane-a-ingestion-sca.md": "A",
    "30-lane-b-detection.md": "B",
    "40-record-and-storage.md": "R",
    "50-dast.md": "D",
    "60-remediation.md": "X",
    "70-orchestration-ci.md": "O",
    "80-compliance.md": "C",
}

# The three shared vocabularies that can silently diverge between areas.
PATTERNS = {
    # SARIF extension keys: anvil/state, anvil/dastCoverage, ...
    "anvil-key": re.compile(r"anvil/[a-zA-Z][a-zA-Z0-9_.]*"),
    # Go identifiers under internal/ that more than one area names.
    "go-path": re.compile(r"internal/[a-z0-9_]+(?:/[a-z0-9_]+)*\.go"),
    # snake_case record/db columns the spine S6 list names.
    "record-field": re.compile(
        r"\b(?:dast_status|dast_coverage|dast_confirmed|target_provenance|remediable_by_agent|"
        r"INSUFFICIENT_CONTEXT|as_of|staleness_seconds|parse_degraded|endpoint_coverage|"
        r"inventory_provenance|sealedAt|anvil_generated|untrusted|verified)\b"
    ),
}


def usage_context(text: str, name: str, radius: int = 90) -> list[str]:
    out = []
    for m in re.finditer(re.escape(name), text):
        lo, hi = max(0, m.start() - radius), min(len(text), m.end() + radius)
        out.append(" ".join(text[lo:hi].split()))
    return out


def dependency_summaries() -> str:
    """Concatenate each area's Dependency Summary plus the global sequence."""
    chunks: list[str] = []
    plan = (PLAN_DIR / "IMPLEMENTATION-PLAN.md").read_text(encoding="utf-8")
    m = re.search(r"^## 1\. Global sequence.*?(?=^## 2\.)", plan, re.S | re.M)
    if m:
        chunks.append("===== IMPLEMENTATION-PLAN.md section 1 (the assembly) =====\n" + m.group(0))

    for name, prefix in AREAS.items():
        text = (PLAN_DIR / name).read_text(encoding="utf-8")
        found = False
        for m in re.finditer(r"^#+ .*Depend\w*.*$", text, re.M):
            start = m.start()
            nxt = re.search(r"^#+ ", text[m.end():], re.M)
            end = m.end() + (nxt.start() if nxt else len(text) - m.end())
            chunks.append(f"===== {name} (area {prefix}) =====\n{text[start:end].strip()}")
            found = True
        if not found:
            # Area 10 states its dependencies in prose before "## Steps".
            m = re.search(r"\*\*Before .*?(?=^## Steps)", text, re.S | re.M)
            if m:
                chunks.append(f"===== {name} (area {prefix}) =====\n{m.group(0).strip()}")

        # Every packet's Depends-on edge, so ordering can be checked exactly.
        edges = re.findall(
            r"\*{0,2}Step ID\*{0,2}:\*{0,2}\s*(\S+).*?\*{0,2}Phase/group\*{0,2}:\*{0,2}\s*([^\n]*).*?"
            r"\*{0,2}Depends on\*{0,2}:\*{0,2}\s*([^\n]*)",
            text,
            re.S,
        )
        if edges:
            lines = [f"  {sid.strip('*` ')} [{grp.strip()}] <- {dep.strip()}" for sid, grp, dep in edges]
            chunks.append(f"----- {name} declared edges -----\n" + "\n".join(lines))
    return "\n\n".join(chunks)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="print every name, not just collisions")
    ap.add_argument("--deps", action="store_true", help="print the Dependency Summary bundle and exit")
    args = ap.parse_args()

    if args.deps:
        print(dependency_summaries())
        return 0

    texts = {name: (PLAN_DIR / name).read_text(encoding="utf-8") for name in AREAS}

    # kind -> name -> area prefix -> [contexts]
    index: dict[str, dict[str, dict[str, list[str]]]] = {
        k: defaultdict(lambda: defaultdict(list)) for k in PATTERNS
    }
    for name, text in texts.items():
        prefix = AREAS[name]
        for kind, pat in PATTERNS.items():
            for hit in set(pat.findall(text)):
                index[kind][hit][prefix] = usage_context(text, hit)

    total_shared = 0
    for kind in PATTERNS:
        entries = index[kind]
        shared = {n: a for n, a in entries.items() if len(a) > 1}
        target = entries if args.all else shared
        total_shared += len(shared)
        print(f"\n########## {kind}: {len(entries)} distinct, {len(shared)} used by >1 area ##########")
        for nm in sorted(target):
            areas = target[nm]
            print(f"\n--- {nm}  [areas: {', '.join(sorted(areas))}] ---")
            for prefix in sorted(areas):
                for ctx in areas[prefix][:3]:
                    print(f"    {prefix}: ...{ctx}...")
    print(f"\ntotal shared names across areas: {total_shared}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
