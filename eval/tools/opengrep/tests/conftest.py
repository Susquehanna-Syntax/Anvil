"""Make `anvil_opengrep` importable without depending on M0.2's eval package.

This tree is self-contained on purpose: M0.7 must be verifiable on its own,
before or after the harness scaffold lands.
"""

from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
