"""The CWE catalogue: the CWE-text framing's advisory, and Lane B's label space.

Read straight from MITRE's ``cwec_v4.20.xml.zip`` (MITRE CWE Terms of Use, attribution required;
``mirror/tier0/LICENSE-NOTES.md``). The archive is pinned by SHA-256: MITRE publishes no digest, so
the pin is the hash of the copy acquired on 2026-10-03, recorded as a first-use hash.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path

from anvil_eval import DATA_DIR, acquire
from anvil_eval.data import CorpusError

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip"
CWE_ZIP = DATA_DIR / "cwe" / "cwec_v4.20.xml.zip"
CWE_SHA256 = "3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50"
_NS = "{http://cwe.mitre.org/cwe-7}"

#: NVD's placeholders: a pair labelled with one of these has no CWE text to frame it with.
NO_CWE = frozenset({"NVD-CWE-Other", "NVD-CWE-noinfo", ""})


@dataclass(frozen=True)
class Entry:
    id: str  # "CWE-79"
    name: str
    description: str

    def advisory_text(self) -> str:
        return f"{self.id}: {self.name}. {self.description}"


def _text(el: ET.Element | None) -> str:
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def load(path: Path = CWE_ZIP, sha256: str | None = CWE_SHA256) -> dict[str, Entry]:
    """Every weakness and category in the catalogue, keyed ``CWE-<id>``."""
    if not path.is_file():
        raise CorpusError(f"{path} is missing; fetch {CWE_URL}")
    if sha256 is not None and acquire.sha256_file(path) != sha256:
        raise CorpusError(f"{path} is not the pinned CWE 4.20 archive")
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if n.endswith(".xml")]
        if len(names) != 1:
            raise CorpusError(f"{path}: expected one XML file, found {names}")
        root = ET.fromstring(z.read(names[0]))
    entries: dict[str, Entry] = {}
    for tag, body in (("Weakness", "Description"), ("Category", "Summary")):
        for el in root.iter(f"{_NS}{tag}"):
            cid = f"CWE-{el.get('ID')}"
            entries[cid] = Entry(cid, el.get("Name", ""), _text(el.find(f"{_NS}{body}")))
    if not entries:
        raise CorpusError(f"{path}: no weaknesses parsed")
    return entries


def normalise(label: str) -> str:
    """``'CWE-079'``, ``'cwe-79'`` and ``'79'`` become ``'CWE-79'``; placeholders pass through."""
    label = label.strip()
    if label in NO_CWE:
        return label
    m = re.fullmatch(r"(?i)(?:cwe-)?0*(\d+)", label)
    if not m:
        raise CorpusError(f"not a CWE label: {label!r}")
    return f"CWE-{m.group(1)}"
