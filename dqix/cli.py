#!/usr/bin/env python3
"""
DQIX CLI
========
Usage examples
--------------
Minimal level-1 (TLS+DNSSEC)         : python -m dqix.cli -l 1 example.com
Full level-3 with verbose warnings   : python -m dqix.cli -l 3 --verbose example.com
Debug (show _raw JSON / errors)      : python -m dqix.cli --debug example.com
"""

from __future__ import annotations
import os
import csv
from pathlib import Path
from typing import Dict, Tuple, Any, List
import json

# Import probes to trigger registration
import dqix.probes

from dqix.core import PROBES
from dqix.core.levels import load_level
from dqix.core.probes import Probe, set_verbosity_level, set_tls_method
from dqix.core.scoring import domain_score as _score
from dqix.utils.targets import expand_targets
from dqix.output import supports_color as _supports_color, c as _c, print_single_domain_table as _print_single_domain_table, get_probe_icon as _get_probe_icon, get_probe_color as _get_probe_color

# Colour constants for summary line
try:
    from colorama import Fore  # type: ignore
except ImportError:  # pragma: no cover
    class _FStub:
        def __getattr__(self, _):
            return ""

    Fore = _FStub()  # type: ignore

# Graceful progress bar import (fallback to no-op if tqdm is unavailable)
try:
    from tqdm.auto import tqdm  # Rich progress bar across terminals/Jupyter
except ImportError:  # pragma: no cover – tqdm is optional at runtime

    class _TqdmFallback:  # Minimal stub with the needed API (context-manager & write)
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

        def update(self, n=1):
            pass

        def write(self, msg):
            print(msg)

    def tqdm(*args, **kwargs):
        # If used as an iterator wrapper `for x in tqdm(list):` simply return the iterable.
        if args:
            return args[0]
        return _TqdmFallback()


def _configure_verbosity_and_tls(args) -> int:
    """Configure verbosity level and TLS method based on arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Verbosity level (0=silent, 1=verbose, 2=debug)
    """
    # 0 = silent, 1 = verbose, 2 = debug
    verbosity = 2 if args.debug else (1 if args.verbose else 0)

    # Debug implies verbose for downstream logic
    if args.debug:
        args.verbose = True

    # Configure verbosity and TLS backend for the probe layer
    set_verbosity_level(verbosity)
    set_tls_method(args.tls_method)
    
    return verbosity


def _load_and_validate_probes(level: int) -> Dict[str, Any]:
    """Load probes for the specified level and validate.
    
    Args:
        level: Probe level to load
        
    Returns:
        Dictionary of loaded probes
        
    Raises:
        SystemExit: If no probes could be loaded
    """
    probes = load_level(level)
    if not probes:
        print(f"Error: No probes loaded for level {level}. Check preset configuration.")
        raise SystemExit(1)
    return probes


def _expand_and_validate_targets(targets: List[str]) -> List[str]:
    """Expand and validate target domains.
    
    Args:
        targets: List of target specifications
        
    Returns:
        List of expanded domain names
        
    Raises:
        SystemExit: If no valid targets found
    """
    domains = list(expand_targets(targets))
    if not domains:
        print("Error: No domain targets specified.")
        raise SystemExit(1)
    return domains


def _save_csv_results(results: List[Dict[str, Any]], csv_path: Path) -> None:
    """Save results to CSV file.
    
    Args:
        results: List of result dictionaries
        csv_path: Path to save CSV file
    """
    if not results:
        print("No results to save to CSV.")
        return
        
    # Dynamically determine fieldnames based on all keys present in rows, ensuring common ones are first
    common_fields = ["domain", "dqi"]
    all_keys = set(k for r in results for k in r.keys())
    # Prioritize common fields, then sort others
    fieldnames = common_fields + sorted(list(all_keys - set(common_fields)))

    try:
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=fieldnames, extrasaction="ignore"
            )  # Ignore extra fields not in header
            writer.writeheader()
            writer.writerows(results)
        print(f"Results saved to → {csv_path}")
    except IOError:
        print(f"Error: Could not write CSV to {csv_path}")


def _save_json_results(results: List[Dict[str, Any]], json_path: str) -> None:
    """Save results to JSON file.
    
    Args:
        results: List of result dictionaries
        json_path: Path to save JSON file
    """
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"JSON results saved to → {json_path}")
    except IOError:
        print(f"Error: Could not write JSON to {json_path}")


def _display_single_domain_table(results: List[Dict[str, Any]], probes: Dict[str, Any], verbosity: int) -> None:
    """Display single domain results in table format.
    
    Args:
        results: List of result dictionaries
        probes: Dictionary of probes used
        verbosity: Verbosity level
    """
    if verbosity == 0 and len(results) == 1:
        _print_single_domain_table(results[0], probes)


def main():
    """Main CLI entry point."""
    # Argument parsing is delegated to a helper module for clarity
    from .cli_args import parse_args  # local import to avoid circular deps in some envs

    args = parse_args()

    # Configure verbosity and TLS settings
    verbosity = _configure_verbosity_and_tls(args)
    
    # Load and validate probes
    probes = _load_and_validate_probes(args.level)
    
    # Expand and validate target domains
    domains = _expand_and_validate_targets(args.targets)

    # Run scan (progress printing handled by runner)
    from dqix.runner import run_domains

    results = run_domains(
        domains,
        probes,
        level=args.level,
        threads=args.threads,
        verbosity=verbosity,
        debug=args.debug,
    )

    # Handle output formats
    if args.csv:
        _save_csv_results(results, args.csv)

    if args.json_out:
        _save_json_results(results, args.json_out)

    # Display results for single domain in non-verbose mode
    _display_single_domain_table(results, probes, verbosity)


# Move the executable entry-point to the very end so helper functions are loaded first
if __name__ == "__main__":
    main()
