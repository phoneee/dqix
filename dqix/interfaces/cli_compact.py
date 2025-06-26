"""
Compact and cool CLI display functions for DQIX.
Reduces output size while making it more visually appealing.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.progress import Progress, BarColumn, TextColumn
import json

console = Console()

def get_score_emoji(score: float) -> str:
    """Get emoji based on score."""
    if score >= 0.95: return "🏆"
    elif score >= 0.85: return "✅"
    elif score >= 0.7: return "⚡"
    elif score >= 0.5: return "⚠️"
    else: return "❌"

def get_score_color(score: float) -> str:
    """Get color based on score."""
    if score >= 0.85: return "bright_green"
    elif score >= 0.7: return "green"
    elif score >= 0.5: return "yellow"
    elif score >= 0.3: return "orange1"
    else: return "red"

def create_score_bar(score: float, width: int = 10) -> str:
    """Create a compact visual score bar."""
    filled = int(score * width)
    return f"[{get_score_color(score)}]{'█' * filled}[/][dim]{'░' * (width - filled)}[/]"

def display_compact_result(result: dict[str, Any], detailed: bool = False):
    """Display scan results in a compact, cool format."""
    domain = result['domain']
    score = result['overall_score']
    level = result['compliance_level']
    
    # Compact header with inline score
    header_text = Text()
    header_text.append(f"{domain} ", style="bold cyan")
    header_text.append(f"{get_score_emoji(score)} ", style="bold")
    header_text.append(f"{score:.0%} ", style=f"bold {get_score_color(score)}")
    header_text.append(create_score_bar(score, 15))
    
    console.print(Panel(header_text, title="🔍 DQIX Scan", border_style="blue", padding=(0, 1)))
    
    # Compact probe results in a single table
    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column("Probe", style="cyan", width=20)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Visual", width=12)
    table.add_column("Status", width=30)
    
    probe_icons = {
        "tls": "🔐",
        "https": "🌐", 
        "dns": "🌍",
        "security_headers": "🛡️"
    }
    
    for probe in result['probe_results']:
        probe_id = probe['probe_id']
        score = probe['score']
        icon = probe_icons.get(probe_id, "📊")
        
        # Compact status based on score and details
        status_parts = []
        if probe.get('is_successful', True):
            details = probe.get('details', {})
            if probe_id == "tls":
                if details.get('version'): status_parts.append(details['version'])
                if details.get('certificate_valid'): status_parts.append("✓Cert")
            elif probe_id == "https":
                if details.get('redirect'): status_parts.append("✓Redirect")
                if details.get('hsts'): status_parts.append("✓HSTS")
            elif probe_id == "dns":
                if details.get('dnssec'): status_parts.append("✓DNSSEC")
                if details.get('spf'): status_parts.append("✓SPF")
            elif probe_id == "security_headers":
                headers_count = sum(1 for k, v in details.items() if v and k != 'score')
                status_parts.append(f"{headers_count} headers")
        else:
            status_parts.append("Failed")
            
        status = " • ".join(status_parts) if status_parts else "Checked"
        
        table.add_row(
            f"{icon} {probe_id.replace('_', ' ').title()}",
            f"{score:.0%}",
            create_score_bar(score, 8),
            f"[dim]{status}[/]"
        )
    
    console.print(table)
    
    # Quick recommendations if score < 0.85
    if score < 0.85 and result.get('recommendations'):
        console.print("\n[bold yellow]💡 Quick Fixes:[/]")
        for i, rec in enumerate(result['recommendations'][:3], 1):
            console.print(f"  {i}. {rec}")
    
    # Timestamp in footer
    console.print(f"\n[dim]Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")

def display_ultra_compact_result(result: dict[str, Any]):
    """Ultra-compact one-line result display."""
    domain = result['domain']
    score = result['overall_score']
    
    # Build probe scores string
    probe_scores = []
    for probe in result['probe_results']:
        icon = {"tls": "🔐", "https": "🌐", "dns": "🌍", "security_headers": "🛡️"}.get(probe['probe_id'], "📊")
        probe_scores.append(f"{icon}{probe['score']:.0%}")
    
    # One-line output
    console.print(
        f"{get_score_emoji(score)} {domain}: "
        f"[{get_score_color(score)}]{score:.0%}[/] "
        f"{create_score_bar(score, 10)} "
        f"[dim]{' '.join(probe_scores)}[/]"
    )

def display_comparison_compact(results: List[dict[str, Any]]):
    """Display domain comparison in compact format."""
    # Sort by score
    results.sort(key=lambda x: x['overall_score'], reverse=True)
    
    # Create comparison table
    table = Table(title="🏆 Domain Comparison", box="ROUNDED", show_header=True)
    table.add_column("Rank", style="cyan", width=6, justify="center")
    table.add_column("Domain", style="bold", width=25)
    table.add_column("Score", justify="center", width=10)
    table.add_column("Visual", width=15)
    table.add_column("Probes", width=40)
    
    for i, result in enumerate(results, 1):
        domain = result['domain']
        score = result['overall_score']
        
        # Compact probe summary
        probe_summary = []
        for probe in result['probe_results']:
            if probe['score'] < 0.7:  # Only show weak probes
                icon = {"tls": "🔐", "https": "🌐", "dns": "🌍", "security_headers": "🛡️"}.get(probe['probe_id'], "📊")
                probe_summary.append(f"{icon}{probe['score']:.0%}")
        
        table.add_row(
            f"#{i}",
            domain,
            f"{get_score_emoji(score)} {score:.0%}",
            create_score_bar(score, 12),
            " ".join(probe_summary) if probe_summary else "[green]All Strong[/]"
        )
    
    console.print(table)
    
    # Quick winner summary
    if results:
        winner = results[0]
        console.print(f"\n🥇 [bold green]{winner['domain']}[/] leads with {winner['overall_score']:.0%} score!")

def display_monitor_status(domain: str, current_score: float, previous_score: Optional[float] = None):
    """Display monitoring status in compact format."""
    trend = ""
    if previous_score is not None:
        diff = current_score - previous_score
        if diff > 0.01:
            trend = f" [green]↑{diff:.1%}[/]"
        elif diff < -0.01:
            trend = f" [red]↓{abs(diff):.1%}[/]"
        else:
            trend = " [dim]→[/]"
    
    console.print(
        f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
        f"{get_score_emoji(current_score)} {domain}: "
        f"[{get_score_color(current_score)}]{current_score:.0%}[/]"
        f"{trend} "
        f"{create_score_bar(current_score, 8)}"
    )

def display_error_compact(domain: str, error: str):
    """Display error in compact format."""
    console.print(f"❌ {domain}: [red]{error}[/]")

def display_json_compact(data: dict[str, Any]):
    """Display JSON in syntax-highlighted compact format."""
    # Remove verbose fields for compact display
    compact_data = {
        "domain": data.get("domain"),
        "score": round(data.get("overall_score", 0), 3),
        "level": data.get("compliance_level"),
        "probes": {
            p["probe_id"]: {
                "score": round(p["score"], 2),
                "status": "pass" if p.get("is_successful", True) else "fail"
            }
            for p in data.get("probe_results", [])
        }
    }
    console.print_json(json.dumps(compact_data))