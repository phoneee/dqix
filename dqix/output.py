from __future__ import annotations

"""Output formatting helpers (tables, colours, icons)."""

from typing import Any

from prettytable import PrettyTable

try:
    from colorama import Fore, Style  # type: ignore
except ImportError:  # pragma: no cover – fallback if colorama absent
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()  # type: ignore

__all__ = [
    "supports_color",
    "c",
    "get_probe_icon",
    "get_probe_color",
    "print_single_domain_table",
    "print_probe_details",
]


def supports_color() -> bool:
    import sys, os
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def c(text: str, colour: str) -> str:  # noqa: D401 – colour wrapper
    if not supports_color():
        return text
    return f"{colour}{text}{Style.RESET_ALL}"


# ----------------- Probe Icon / Colour maps ---------------------------------

_ICON_MAP = {
    "tls": "🔒",
    "dnssec": "🔐",
    "headers": "🛡️",
    "mail": "📧",
    "whois": "📝",
    "impersonation": "👤",
    "dns_basic": "🌐",
    "dkim": "✉️",
    "caa": "🔑",
    "accessibility": "♿",
    "cookie": "🍪",
    "sri": "🔏",
    "eco_index": "🌱",
}

_COLOR_MAP = {
    "tls": Fore.CYAN,
    "dnssec": Fore.BLUE,
    "headers": Fore.MAGENTA,
    "mail": Fore.YELLOW,
    "whois": Fore.WHITE,
    "impersonation": Fore.RED,
    "dns_basic": Fore.GREEN,
    "dkim": Fore.YELLOW,
    "caa": Fore.CYAN,
    "accessibility": Fore.GREEN,
    "cookie": Fore.YELLOW,
    "sri": Fore.BLUE,
    "eco_index": Fore.GREEN,
}


def get_probe_icon(pid: str) -> str:
    return _ICON_MAP.get(pid, "•")


def get_probe_color(pid: str) -> str:
    return _COLOR_MAP.get(pid, Fore.WHITE)


# ------------------------ Table Printer -------------------------------------

def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "✓" if value else "✗"
    if isinstance(value, (int, float)):
        return f"{value:,.2f}"
    return str(value)


def print_single_domain_table(result: dict[str, Any], probes: dict[str, Any]) -> None:
    """Pretty print a table (non-verbose single domain view)."""
    table = PrettyTable()
    table.field_names = ["Probe", "Points", "Details"]
    table.align.update({"Probe": "l", "Points": "r", "Details": "l"})
    table.hrules = True

    for pid, probe in probes.items():
        score = result.get(pid, 0.0)
        raw = result.get(f"{pid}_raw", {})
        points = score * probe.weight * 100

        details: list[str] = []
        if isinstance(raw, dict):
            if "error" in raw:
                details.append(f"Error: {raw['error']}")
            for k, v in sorted(raw.items()):
                if k in {"error", "attempted_domain", "original_domain"}:
                    continue
                details.append(f"{k.replace('_', ' ').title()}: {_format_value(v)}")
        icon = get_probe_icon(pid)
        col = get_probe_color(pid)
        table.add_row([c(f"{icon} {pid}", col), c(f"{points:,.1f}", col), " | ".join(details)])

    print(table)


# ---------------- Verbose / Debug probe line -------------------------------


def print_probe_details(
    probe_id: str,
    score: float,
    details: dict[str, Any],
    probe_instance: Any,
    *,
    debug: bool = False,
) -> None:
    """Pretty-print a single probe detail line (used in verbose/debug)."""

    points_lost = (1.0 - score) * probe_instance.weight * 100

    # Icon & colour bucket
    if score >= 0.95:
        icon, col = "✓", Fore.GREEN
    elif score >= 0.5:
        icon, col = "⚠", Fore.YELLOW
    else:
        icon, col = "✖", Fore.RED

    line = (
        f"  {c(icon, col)} {probe_id:<15} "
        f"{points_lost:+6.1f} pts  "
        f"(score={score:.2f}, w={probe_instance.weight:.2f})"
    )

    if debug:
        import json as _json

        raw_output = details.get(f"{probe_id}_raw", {})
        raw_str = _json.dumps(raw_output, ensure_ascii=False)
        if len(raw_str) > 200 and not debug:
            raw_str = raw_str[:197] + "..."
        line += f" raw={raw_str}"

    print(line) 