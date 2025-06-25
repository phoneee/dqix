"""Clean CLI interface for DQIX."""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from ..application.use_cases import (
    AssessDomainCommand, 
    AssessDomainUseCase,
    AssessDomainsCommand,
    AssessDomainsUseCase
)
from ..domain.entities import ProbeConfig
from ..domain.services import AssessmentService, DomainValidationService, ScoringService
from ..infrastructure.repositories import FileAssessmentRepository, InMemoryCacheRepository
from ..infrastructure.probes import ProbeExecutor


app = typer.Typer(
    name="dqix",
    help="Domain Quality Index - Clean Architecture",
    add_completion=False,
)

console = Console()


def create_use_case() -> AssessDomainUseCase:
    """Factory function to create use case with dependencies."""
    # Infrastructure
    probe_executor = ProbeExecutor()
    assessment_repo = FileAssessmentRepository()
    cache_repo = InMemoryCacheRepository()
    
    # Domain services
    scoring_service = ScoringService()
    validation_service = DomainValidationService()
    assessment_service = AssessmentService(scoring_service, validation_service)
    
    # Use case
    return AssessDomainUseCase(
        probe_executor=probe_executor,
        assessment_service=assessment_service,
        validation_service=validation_service,
        assessment_repo=assessment_repo,
        cache_repo=cache_repo
    )


@app.command()
def assess(
    domain: str = typer.Argument(..., help="Domain to assess"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Timeout in seconds"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable caching"),
    max_concurrent: int = typer.Option(10, "--max-concurrent", "-c", help="Max concurrent probes"),
) -> None:
    """Assess a single domain quality."""
    
    config = ProbeConfig(
        timeout=timeout,
        cache_enabled=not no_cache,
        max_concurrent=max_concurrent
    )
    
    command = AssessDomainCommand(
        domain_name=domain,
        probe_config=config
    )
    
    use_case = create_use_case()
    
    try:
        with console.status(f"[bold green]Assessing {domain}..."):
            result = asyncio.run(use_case.execute(command))
        
        # Display results
        _display_assessment_result(result)
        
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)


@app.command()
def assess_bulk(
    domains_file: Path = typer.Argument(..., help="File containing domains to assess"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Timeout in seconds"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable caching"),
    max_concurrent: int = typer.Option(5, "--max-concurrent", "-c", help="Max concurrent domains"),
) -> None:
    """Assess multiple domains from file."""
    
    if not domains_file.exists():
        console.print(f"[red]File not found: {domains_file}[/red]")
        sys.exit(1)
    
    # Load domains
    domains = []
    with open(domains_file) as f:
        for line in f:
            domain = line.strip()
            if domain and not domain.startswith('#'):
                domains.append(domain)
    
    if not domains:
        console.print("[red]No domains found in file[/red]")
        sys.exit(1)
    
    config = ProbeConfig(
        timeout=timeout,
        cache_enabled=not no_cache,
        max_concurrent=max_concurrent
    )
    
    command = AssessDomainsCommand(
        domain_names=domains,
        probe_config=config
    )
    
    # Create bulk use case
    single_use_case = create_use_case()
    bulk_use_case = AssessDomainsUseCase(single_use_case)
    
    try:
        with Progress() as progress:
            task = progress.add_task("[green]Assessing domains...", total=len(domains))
            
            results = asyncio.run(bulk_use_case.execute(command))
            progress.update(task, completed=len(domains))
        
        # Display summary
        _display_bulk_results(results)
        
    except Exception as e:
        console.print(f"[red]Error during bulk assessment: {e}[/red]")
        sys.exit(1)


@app.command()
def list_probes() -> None:
    """List available probes."""
    from ..infrastructure.probes.implementations import get_all_probes
    
    probes = get_all_probes()
    
    table = Table(title="Available Probes")
    table.add_column("ID", style="cyan")
    table.add_column("Category", style="green")
    
    for probe in probes:
        table.add_row(probe.probe_id, probe.category.value)
    
    console.print(table)


def _display_assessment_result(result) -> None:
    """Display single assessment result."""
    # Overall score
    console.print(f"\n[bold]Domain:[/bold] {result.domain.name}")
    console.print(f"[bold]Overall Score:[/bold] {result.overall_score:.2f}")
    console.print(f"[bold]Compliance Level:[/bold] {result.compliance_level.value}")
    
    # Probe results table
    table = Table(title="Probe Results")
    table.add_column("Probe", style="cyan")
    table.add_column("Score", style="green")
    table.add_column("Status", style="blue")
    
    for probe_result in result.probe_results:
        status = "✓ Success" if probe_result.is_successful else "✗ Failed"
        table.add_row(
            probe_result.probe_id,
            f"{probe_result.score:.2f}",
            status
        )
    
    console.print(table)


def _display_bulk_results(results: List) -> None:
    """Display bulk assessment results."""
    if not results:
        console.print("[yellow]No results to display[/yellow]")
        return
    
    # Summary statistics
    total = len(results)
    avg_score = sum(r.overall_score for r in results) / total
    
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"Total domains assessed: {total}")
    console.print(f"Average score: {avg_score:.2f}")
    
    # Results table
    table = Table(title="Bulk Assessment Results")
    table.add_column("Domain", style="cyan")
    table.add_column("Score", style="green")
    table.add_column("Level", style="blue")
    
    for result in results:
        table.add_row(
            result.domain.name,
            f"{result.overall_score:.2f}",
            result.compliance_level.value
        )
    
    console.print(table)


if __name__ == "__main__":
    app() 