"""CLI commands for DQIX.

This module provides commands for the DQIX CLI.
"""

import os
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table

from ..core.probes import PROBES
from ..plugins import get_probe_plugins, get_output_plugins, get_scoring_plugins

console = Console()

def list_probes() -> None:
    """List all available probes."""
    table = Table(title="Available Probes")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Weight", style="yellow")
    
    # Core probes
    for probe_id, probe in PROBES.items():
        table.add_row(
            probe_id,
            probe.__name__,
            str(probe.weight)
        )
        
    # Plugin probes
    for plugin in get_probe_plugins():
        for probe in plugin.get_probes():
            table.add_row(
                probe.id,
                probe.__name__,
                str(probe.weight)
            )
            
    console.print(table)
    
def list_plugins() -> None:
    """List all available plugins."""
    table = Table(title="Available Plugins")
    table.add_column("Type", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Description", style="blue")
    
    # Probe plugins
    for plugin in get_probe_plugins():
        table.add_row(
            "Probe",
            plugin.name,
            plugin.version,
            plugin.description
        )
        
    # Output plugins
    for plugin in get_output_plugins():
        table.add_row(
            "Output",
            plugin.name,
            plugin.version,
            plugin.description
        )
        
    # Scoring plugins
    for plugin in get_scoring_plugins():
        table.add_row(
            "Scoring",
            plugin.name,
            plugin.version,
            plugin.description
        )
        
    console.print(table)
    
def check_domain(domain: str, probes: Optional[List[str]] = None) -> None:
    """Check domain quality.
    
    Args:
        domain: Domain to check
        probes: List of probe IDs to run (optional)
    """
    from ..core.engine import Engine
    
    engine = Engine()
    
    if probes:
        engine.set_probes(probes)
        
    results = engine.run(domain)
    
    table = Table(title=f"Results for {domain}")
    table.add_column("Probe", style="cyan")
    table.add_column("Score", style="green")
    table.add_column("Details", style="blue")
    
    for probe_id, result in results.items():
        score, details = result
        table.add_row(
            probe_id,
            f"{score:.2f}",
            str(details)
        )
        
    console.print(table)
    
def export_results(domain: str, format: str = "json") -> None:
    """Export domain check results.
    
    Args:
        domain: Domain to export results for
        format: Output format (json, yaml, csv)
    """
    from ..core.engine import Engine
    from ..core.output import get_formatter
    
    engine = Engine()
    results = engine.run(domain)
    
    formatter = get_formatter(format)
    output = formatter.format(results)
    
    console.print(output)
    
def configure() -> None:
    """Configure DQIX settings."""
    from ..config import Config
    
    config = Config()
    
    # Get current settings
    current = config.get_all()
    
    # Prompt for new settings
    settings = {}
    
    for key, value in current.items():
        new_value = click.prompt(
            f"Enter value for {key}",
            default=str(value)
        )
        settings[key] = new_value
        
    # Save settings
    config.update(settings)
    console.print("[bold green]Settings updated successfully![/bold green]") 