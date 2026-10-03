"""Make `anvil_opengrep` importable without depending on the harness scaffold's package.

This tree is self-contained on purpose: the opengrep acquisition must be verifiable on its own,
before or after the harness scaffold lands.
"""

from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
