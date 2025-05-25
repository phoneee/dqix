from __future__ import annotations

"""Helpers for expanding domain target CLI arguments.

Accepts list of strings which can be domain names *or* text files containing
one domain per line (comments with `#` are ignored). Returns a flat list of
explicit domain strings. Directories are skipped with a warning.
"""

from pathlib import Path
from typing import List

__all__ = ["expand_targets"]


def expand_targets(items: List[str]) -> List[str]:
    """Expand *items* containing domains and/or filenames into a domain list."""
    expanded: List[str] = []
    for itm in items:
        p = Path(itm)
        if p.is_file():
            try:
                for line in p.read_text("utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        expanded.append(line)
            except OSError:
                print(f"Warning: Could not read file {itm}")
        elif p.is_dir():
            print(f"Warning: Skipping directory {itm}")
        else:
            expanded.append(itm)
    return expanded 