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
import argparse
import concurrent.futures
import os
import csv
from pathlib import Path
from typing import Dict, Tuple, Any  # Added Any
import json

from dqix.core import PROBES, load_weights
from dqix.core.probes import Probe, set_verbosity_level, set_tls_method

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


def _expand(items: list[str]) -> list[str]:  # Return type hint
    expanded_items = []
    for itm in items:
        p = Path(itm)
        if p.is_file() and p.exists():  # Check if it's a file before reading
            try:
                for line in p.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        expanded_items.append(line)
            except IOError:  # Handle potential read errors
                print(f"Warning: Could not read file {itm}")
        elif p.is_dir():  # Optionally skip directories or handle them differently
            print(f"Warning: Skipping directory {itm}")
        else:  # Assumed to be a domain name
            expanded_items.append(itm)
    return expanded_items


def _load_level(level: int) -> Dict[str, Probe]:  # More specific type hint for Probe
    weights = load_weights(level)
    selected: Dict[str, Probe] = {}  # Type hint for selected
    for pid, w_value in weights.items():  # Renamed w to w_value for clarity
        if pid in PROBES:
            probe_instance = PROBES[pid]  # Renamed probe to probe_instance
            try:
                probe_instance.weight = float(w_value)  # override weight from YAML
                selected[pid] = probe_instance
            except ValueError:
                print(
                    f"Warning: Invalid weight '{w_value}' for probe '{pid}' in level {level}. Skipping probe."
                )
    return selected


def _score(
    domain: str, probes: Dict[str, Probe]
) -> Tuple[float, Dict[str, Any]]:  # Probe type hint, Any for detail
    total_score_contribution, detail_dict = 0.0, {}  # Renamed variables
    for pid, p_instance in probes.items():
        s, raw = p_instance.run(domain)  # s ∈ [0,1]
        detail_dict[pid] = s
        if isinstance(
            raw, dict
        ):  # raw can sometimes be other types if a probe fails unexpectedly
            detail_dict[pid + "_raw"] = raw
        else:  # Handle cases where raw might not be a dict
            detail_dict[pid + "_raw"] = {
                "error": "Raw data not available or not a dict",
                "value": raw,
            }
        total_score_contribution += p_instance.weight * s
    return round(total_score_contribution * 100, 1), detail_dict


def main():
    ap = argparse.ArgumentParser(
        description="Domain Quality Index (DQIX) Scorer. Evaluates domain configurations based on selected level.",
        formatter_class=argparse.RawTextHelpFormatter,  # For better help text formatting
    )
    ap.add_argument(
        "targets",
        nargs="+",
        help="One or more domain names or file paths (one domain per line).",
    )
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
    )  # Capped default threads
    ap.add_argument(
        "--csv", type=Path, help="Save results to a CSV file at the specified path."
    )
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
    args = ap.parse_args()

    # 0 = silent, 1 = verbose, 2 = debug
    verbosity = 2 if args.debug else (1 if args.verbose else 0)

    # Debug implies verbose for downstream logic
    if args.debug:
        args.verbose = True

    # Configure verbosity and TLS backend for the probe layer
    set_verbosity_level(verbosity)
    set_tls_method(args.tls_method)

    probes = _load_level(args.level)
    if not probes:
        print(
            f"Error: No probes loaded for level {args.level}. Check preset configuration."
        )
        return

    domains = list(_expand(args.targets))
    if not domains:
        print("Error: No domain targets specified.")
        return

    rows = []
    results = []
    # ------- Concurrent execution w/ real-time progress bar ----------------
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        future_to_domain = {ex.submit(_score, dom, probes): dom for dom in domains}

        # Create a single progress bar tracking overall completion. Disable when not verbose.
        with tqdm(
            total=len(domains),
            desc=f"DQI-L{args.level} scan",
            unit="domain",
            disable=(verbosity == 0),
        ) as pbar:
            for future in concurrent.futures.as_completed(future_to_domain):
                dom = future_to_domain[future]
                try:
                    score, det = future.result()

                    # Show summary per domain (always), but use tqdm.write only if bar is enabled.
                    summary_line = f"{dom:<30} DQI-L{args.level}={score}"
                    if verbosity == 0:
                        print(summary_line)
                    else:
                        pbar.write(summary_line)

                    if args.verbose:
                        for pid, p_instance in probes.items():
                            probe_score = det.get(pid, 0.0)
                            points_lost_contribution = round(
                                p_instance.weight * (1.0 - probe_score) * 100, 1
                            )

                            show_details = args.debug or (
                                args.verbose
                                and probe_score < 1.0
                                and points_lost_contribution > 0.05
                            )

                            if show_details:
                                flag = "⚠" if probe_score < 0.95 else "·"
                                if args.debug and not (
                                    probe_score < 1.0
                                    and points_lost_contribution > 0.05
                                ):
                                    flag = "·"

                                raw_output = det.get(pid + "_raw", {})
                                raw_str = str(raw_output)
                                if len(raw_str) > 150:
                                    raw_str = raw_str[:147] + "..."

                                pbar.write(
                                    f"  {flag} {pid:<12} -{points_lost_contribution:04.1f} pts  "
                                    f"(score={probe_score:.2f}, weight={p_instance.weight:.2f}) raw={raw_str}"
                                )

                    rows.append({"domain": dom, "dqi": score, **det})
                    results.append({"domain": dom, "dqi": score, **det})
                except Exception as e:
                    pbar.write(f"Error processing domain {dom}: {e}")
                    if args.debug:
                        import traceback

                        traceback.print_exc()
                    rows.append(
                        {"domain": dom, "dqi": "Error", "error_message": str(e)}
                    )
                    results.append({"domain": dom, "error": str(e)})

                # Update progress after each domain finishes.
                pbar.update(1)

    # ----------------------------------------------------------------------
    if args.csv:
        if rows:  # Only write CSV if there are rows
            # Dynamically determine fieldnames based on all keys present in rows, ensuring common ones are first
            common_fields = ["domain", "dqi"]
            all_keys = set(k for r in rows for k in r.keys())
            # Prioritize common fields, then sort others
            fieldnames = common_fields + sorted(list(all_keys - set(common_fields)))

            try:
                with args.csv.open("w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(
                        fh, fieldnames=fieldnames, extrasaction="ignore"
                    )  # Ignore extra fields not in header
                    writer.writeheader()
                    writer.writerows(rows)
                print(f"Results saved to → {args.csv}")
            except IOError:
                print(f"Error: Could not write CSV to {args.csv}")
        else:
            print("No results to save to CSV.")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()

# Public alias so tests can `from dqix.cli import load_level`
load_level = _load_level
