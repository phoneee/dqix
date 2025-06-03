"""Main CLI module for DQIX.

This module provides the main entry point for the DQIX CLI.
"""

import click
from rich.console import Console

from .base import InteractiveCLI
from .commands import (
    list_probes,
    list_plugins,
    check_domain,
    export_results,
    configure,
)

console = Console()

def create_cli() -> InteractiveCLI:
    """Create CLI application.
    
    Returns:
        InteractiveCLI instance
    """
    cli = InteractiveCLI(
        name="DQIX",
        description="Domain Quality Index - An open-source tool for measuring domain quality"
    )
    
    # Add commands
    cli.add_command("probes", list_probes)
    cli.add_command("plugins", list_plugins)
    cli.add_command("check", check_domain)
    cli.add_command("export", export_results)
    cli.add_command("config", configure)
    
    return cli

@click.group()
def cli():
    """DQIX - Domain Quality Index CLI."""
    pass

@cli.command()
def interactive():
    """Start interactive CLI session."""
    cli = create_cli()
    cli.start()

@cli.command()
def probes():
    """List all available probes."""
    list_probes()

@cli.command()
def plugins():
    """List all available plugins."""
    list_plugins()

@cli.command()
@click.argument("domain")
@click.option("--probes", "-p", help="List of probe IDs to run")
def check(domain: str, probes: str):
    """Check domain quality."""
    probe_list = probes.split(",") if probes else None
    check_domain(domain, probe_list)

@cli.command()
@click.argument("domain")
@click.option("--format", "-f", default="json", help="Output format (json, yaml, csv)")
def export(domain: str, format: str):
    """Export domain check results."""
    export_results(domain, format)

@cli.command()
def config():
    """Configure DQIX settings."""
    configure()

def main():
    """Main entry point."""
    cli() 