from __future__ import annotations

"""CLI argument parser for DQIX.
Separated from dqix/cli.py to keep the entry-point lean and easier to test.
"""

import argparse
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Return a fully-configured :class:`argparse.ArgumentParser`."""
    ap = argparse.ArgumentParser(
        description=(
            "Domain Quality Index (DQIX) Scorer. Evaluates domain "
            "configurations based on selected level."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Positional / required --------------------------------------------------
    ap.add_argument(
        "targets",
        nargs="+",
        help="One or more domain names or file paths (one domain per line).",
    )

    # General options --------------------------------------------------------
    ap.add_argument(
        "-l",
        "--level",
        type=int,
        choices=[1, 2, 3],
        default=3,
        help="Assessment level (1=Minimal, 2=Safe, 3=Policy). Default: 3",
    )
    ap.add_argument(
        "-j",
        "--threads",
        type=int,
        default=min(32, (os.cpu_count() or 1) + 4),
        help="Number of concurrent threads. Default: auto (max 32).",
    )
    ap.add_argument(
        "--csv",
        type=Path,
        help="Save results to a CSV file at the specified path.",
    )

    # Verbosity / debug ------------------------------------------------------
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed scores for each probe that isn't perfect.",
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Show all probe details, including raw data and potential errors. Implies -v.",
    )

    # Scan fine-tuning -------------------------------------------------------
    ap.add_argument(
        "--tls-method",
        choices=["ssllabs", "sslyze", "nmap"],
        default="ssllabs",
        help="TLS probing backend: ssllabs (detailed, remote), sslyze (local, fast), nmap (local, fast)",
    )
    ap.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Write full probe results to this JSON file (one object per domain)",
    )
    return ap


def parse_args() -> argparse.Namespace:  # pragma: no cover – tiny wrapper
    """Parse command-line arguments and return a :class:`argparse.Namespace`."""
    return build_parser().parse_args() 