#!/usr/bin/env python3
"""Deterministic cross-reference check over every worker packet in plan/.

This is the executable form of the check described in plan/IMPLEMENTATION-PLAN.md
section 2.6. It found defects D1-D3 when both cross-family critic routes failed.
Re-run it after any edit to an area file.

    python tools/plan_xref.py            # exit 0 = clean, 1 = defects found
    python tools/plan_xref.py --verbose  # also print the parsed inventory

Checks:
  C1  every declared step ID is unique
  C2  numbering is gapless within each area
  C3  every cited step ID resolves to a declared step
  C4  every "Depends on" ID resolves to a declared step
  C5  no step depends on a later step in its own area
  C6  no two packets in the same area + same parallel group write the same path
  C7  every packet carries the mandatory fields from 00-ROUTING.md
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

PLAN_DIR = Path(__file__).resolve().parent.parent / "plan"

# Area file -> the step-ID prefix that area owns.
AREA_PREFIX = {
    "10-milestone0-evaluation.md": "M0",
    "20-lane-a-ingestion-sca.md": "A",
    "30-lane-b-detection.md": "B",
    "40-record-and-storage.md": "R",
    "50-dast.md": "D",
    "60-remediation.md": "X",
    "70-orchestration-ci.md": "O",
    "80-compliance.md": "C",
}

# A step ID is <prefix>.<n>. M0 must be tried before the single letters so that
# "M0.18" is not read as a bare word followed by "0.18".
STEP_ID_RE = re.compile(r"\b(M0|[ABRDXOC])\.(\d+)\b")

MANDATORY_FIELDS = [
    "Step ID",
    "Phase/group",
    "Depends on",
    "Backend/model",
    "Objective",
    "Scope and files",
    "Forbidden actions",
    "Expected output schema",
    "Validation/evidence required",
    "Stop condition",
    "Why this model",
]

# Field keys as they actually appear across the eight area files. Area planners
# varied the punctuation slightly; accept the variants rather than fail on them.
# Two packet dialects exist across the eight area files: plain "Key:  value"
# inside a fenced block (areas 20-80) and bold "**Key:** value" unfenced
# (area 10). Both are accepted; neither is normalised in the source files.
FIELD_KEY_RE = re.compile(
    r"^\*{0,2}(Step ID|Phase/group|Depends on|Backend/model|Objective|Scope and files|"
    r"Forbidden actions|Inputs/artifact refs|Inputs and artifact refs|"
    r"Expected output schema|Validation/evidence required|Validation or evidence required|"
    r"Stop condition|Why this model)\*{0,2}\s*:\*{0,2}\s*(.*)$"
)

FIELD_ALIASES = {
    "Inputs and artifact refs": "Inputs/artifact refs",
    "Validation or evidence required": "Validation/evidence required",
}

# Paths claimed inside a "Scope and files" value. Deliberately conservative: a
# token that contains a slash or a known source extension and no whitespace.
PATH_RE = re.compile(r"[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-*]+)+/?|[A-Za-z0-9_.\-]+\.(?:go|sql|ya?ml|json|csv|md|py|sh)\b")


@dataclass
class Packet:
    step_id: str
    area_file: str
    line_no: int
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def prefix(self) -> str:
        return self.step_id.rsplit(".", 1)[0]

    @property
    def number(self) -> int:
        return int(self.step_id.rsplit(".", 1)[1])

    @property
    def group(self) -> str:
        """Normalised parallel-group key. Two packets collide only if equal."""
        raw = self.fields.get("Phase/group", "").strip().lower()
        m = re.search(r"parallel group\s*(\d+)", raw)
        if m:
            return f"parallel:{m.group(1)}"
        return f"serial:{self.line_no}"  # serial packets never collide

    def depends_on(self) -> list[str]:
        raw = self.fields.get("Depends on", "")
        if re.search(r"\bnone\b", raw, re.I):
            return []
        return [f"{p}.{n}" for p, n in STEP_ID_RE.findall(raw)]

    def write_paths(self) -> set[str]:
        raw = self.fields.get("Scope and files", "")
        # Take only the WRITE clause. Areas write it as "WRITE: a, b; READ: c"
        # or "WRITE: a, b READ: c" or "WRITE/APPEND: ...".
        writes: set[str] = set()
        for m in re.finditer(r"WRITE(?:/APPEND)?\s*:\s*(.*?)(?=(?:READ(?:/APPEND)?\s*:)|$)", raw, re.S | re.I):
            for path in PATH_RE.findall(m.group(1)):
                path = path.rstrip(".,;")
                if path and not path.startswith(("research/", "plan/")):
                    writes.add(path)
        return writes


def parse_area(path: Path) -> tuple[list[Packet], list[str]]:
    """Return (packets, citations) for one area file."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    packets: list[Packet] = []

    current: Packet | None = None
    current_key: str | None = None

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Packet boundaries: a fence, a heading, or a horizontal rule ends it.
        # A markdown heading needs a space after the hashes; "Risk #8:" inside a
        # wrapped field value must not be mistaken for one.
        if stripped.startswith("```") or re.match(r"#{1,6}\s", stripped) or re.fullmatch(r"-{3,}|\*{3,}", stripped):
            current, current_key = None, None
            continue

        m = FIELD_KEY_RE.match(stripped)
        if m:
            key, value = FIELD_ALIASES.get(m.group(1), m.group(1)), m.group(2).strip()
            if key == "Step ID":
                sid = value.strip().strip("*` ")
                current = Packet(step_id=sid, area_file=path.name, line_no=idx)
                packets.append(current)
                current_key = None
                continue
            if current is not None:
                current.fields[key] = value
                current_key = key
            continue

        # Anything else inside an open packet continues the last field. Area 10
        # wraps values at column 0, so indentation cannot be the signal.
        if current is not None and current_key and stripped:
            current.fields[current_key] += " " + stripped

    citations = [f"{p}.{n}" for p, n in STEP_ID_RE.findall(text)]
    return packets, citations


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    all_packets: list[Packet] = []
    citations_by_file: dict[str, list[str]] = {}
    defects: list[str] = []

    for name in sorted(AREA_PREFIX):
        p = PLAN_DIR / name
        if not p.exists():
            defects.append(f"MISSING AREA FILE: {name}")
            continue
        packets, citations = parse_area(p)
        all_packets.extend(packets)
        citations_by_file[name] = citations

    declared: dict[str, Packet] = {}

    # C1 - uniqueness
    for pkt in all_packets:
        if pkt.step_id in declared:
            prev = declared[pkt.step_id]
            defects.append(
                f"C1 duplicate step ID {pkt.step_id}: {prev.area_file}:{prev.line_no} "
                f"and {pkt.area_file}:{pkt.line_no}"
            )
        declared[pkt.step_id] = pkt

    # C1b - each area declares only its own prefix
    for pkt in all_packets:
        expected = AREA_PREFIX[pkt.area_file]
        if pkt.prefix != expected:
            defects.append(
                f"C1b {pkt.area_file}:{pkt.line_no} declares {pkt.step_id}, "
                f"but this area's prefix is {expected}"
            )

    # C2 - gapless numbering
    by_prefix: dict[str, list[int]] = defaultdict(list)
    for pkt in all_packets:
        by_prefix[pkt.prefix].append(pkt.number)
    for prefix, nums in sorted(by_prefix.items()):
        nums.sort()
        expected = list(range(1, len(nums) + 1))
        if nums != expected:
            missing = sorted(set(expected) - set(nums))
            extra = sorted(set(nums) - set(expected))
            defects.append(
                f"C2 area {prefix} numbering not gapless 1..{len(nums)}: "
                f"missing={missing} unexpected={extra}"
            )

    # C3 - every citation resolves
    dangling: dict[str, set[str]] = defaultdict(set)
    for name, citations in citations_by_file.items():
        for cid in citations:
            if cid not in declared:
                dangling[cid].add(name)
    for cid, files in sorted(dangling.items()):
        defects.append(f"C3 dangling step reference {cid} cited in {sorted(files)}")

    # C4 / C5 - dependency resolution and intra-area ordering
    for pkt in sorted(all_packets, key=lambda p: (p.area_file, p.number)):
        for dep in pkt.depends_on():
            if dep not in declared:
                defects.append(
                    f"C4 {pkt.step_id} ({pkt.area_file}:{pkt.line_no}) depends on "
                    f"undeclared step {dep}"
                )
                continue
            target = declared[dep]
            if target.prefix == pkt.prefix and target.number >= pkt.number:
                defects.append(
                    f"C5 {pkt.step_id} depends on same-area step {dep} which runs "
                    f"at or after it"
                )

    # C6 - write-scope overlap inside one area + parallel group
    groups: dict[tuple[str, str], list[Packet]] = defaultdict(list)
    for pkt in all_packets:
        groups[(pkt.area_file, pkt.group)].append(pkt)
    for (area, group), pkts in sorted(groups.items()):
        if not group.startswith("parallel:") or len(pkts) < 2:
            continue
        seen: dict[str, str] = {}
        for pkt in pkts:
            for path in pkt.write_paths():
                if path in seen and seen[path] != pkt.step_id:
                    defects.append(
                        f"C6 write-scope overlap in {area} {group}: {seen[path]} and "
                        f"{pkt.step_id} both write {path}"
                    )
                seen.setdefault(path, pkt.step_id)

    # C7 - mandatory fields present
    for pkt in all_packets:
        missing = [f for f in MANDATORY_FIELDS if f != "Step ID" and f not in pkt.fields]
        if missing:
            defects.append(
                f"C7 {pkt.step_id} ({pkt.area_file}:{pkt.line_no}) missing fields: "
                f"{', '.join(missing)}"
            )

    print(f"packets parsed: {len(all_packets)}")
    for prefix, nums in sorted(by_prefix.items()):
        print(f"  {prefix:>2}: {len(nums)} steps ({prefix}.1-{prefix}.{max(nums)})")

    if args.verbose:
        print("\n--- write scopes ---")
        for pkt in all_packets:
            paths = sorted(pkt.write_paths())
            if paths:
                print(f"  {pkt.step_id:>6} [{pkt.group}] {', '.join(paths)}")

    if defects:
        print(f"\n{len(defects)} DEFECT(S):")
        for d in defects:
            print(f"  - {d}")
        return 1

    print("\nclean: no cross-reference defects")
    return 0


if __name__ == "__main__":
    sys.exit(main())
