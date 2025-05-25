from __future__ import annotations

"""Parallel domain scorer with progress bar.

Isolates threading/tqdm concerns away from CLI so logic can be reused by API
or unit-tested more easily.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from dqix.core.scoring import domain_score as _score
from dqix.output import c as _c, supports_color as _supports_color, print_probe_details, get_probe_icon, get_probe_color

try:
    from colorama import Fore  # type: ignore
except ImportError:  # pragma: no cover
    class _FStub:  # type: ignore
        def __getattr__(self, _):
            return ""
    Fore = _FStub()  # type: ignore

# -------------------------------- tqdm helper ---------------------------------

try:
    from tqdm.auto import tqdm  # rich progress bar
except ImportError:  # fallback minimal stub

    class _TqdmFallback:  # noqa: D401 – minimal stub
        def __init__(self, *_, **__):
            pass

        def __enter__(self):  # context-manager noop
            return self

        def __exit__(self, *_):  # noqa: D401 – ignore
            pass

        def update(self, _=1):
            pass

        def write(self, msg):  # noqa: D401 – mimic tqdm.write
            print(msg)

    def tqdm(*args, **kwargs):  # type: ignore
        if args:
            return args[0]
        return _TqdmFallback()


# ---------------------------------------------------------------------------

def run_domains(
    domains: List[str],
    probes: Dict[str, Any],
    *,
    level: int,
    threads: int,
    verbosity: int,
    debug: bool,
) -> List[Dict[str, Any]]:
    """Run *probes* over *domains* concurrently and stream progress output.

    Returns list of result dicts (same structure as domain_score).
    """
    results: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_to_domain = {ex.submit(_score, dom, probes): dom for dom in domains}

        with tqdm(
            total=len(domains),
            desc=f"DQI-L{level} scan",
            unit="domain",
            disable=(verbosity == 0),
        ) as pbar:
            for future in as_completed(future_to_domain):
                dom = future_to_domain[future]
                try:
                    score, det = future.result()

                    # ---------- summary line ---------------------------------
                    colour = (
                        Fore.GREEN if score >= 80 else (Fore.YELLOW if score >= 60 else Fore.RED)
                    )
                    summary = f"{dom:<30} DQI-L{level}={_c(f'{score:0.1f}', colour)}"
                    (pbar.write if verbosity > 0 else print)(summary)

                    # Verbose / debug
                    if verbosity:
                        for pid, probe in probes.items():
                            probe_score = det.get(pid, 0.0)
                            points_lost = probe.weight * (1 - probe_score) * 100
                            show = debug or (verbosity and probe_score < 1.0 and points_lost > 0.05)
                            if not show:
                                continue
                            print_probe_details(pid, probe_score, det, probe, debug=debug)

                    res_entry = {"domain": dom, "dqi": score, **det}
                    results.append(res_entry)
                except Exception as exc:
                    err_line = f"Error processing domain {dom}: {exc}"
                    pbar.write(err_line)
                    results.append({"domain": dom, "error": str(exc)})
                pbar.update(1)
    return results 