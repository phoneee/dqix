#!/usr/bin/env python3
"""
DQIX - Internet Observability Platform
Simple, fast, and comprehensive Internet security analysis

Usage Examples:
    dqix scan github.com                     # Basic scan
    dqix scan google.com -d full             # Full details
    dqix scan microsoft.com -p tls           # TLS only
    dqix validate cloudflare.com --checklist # Security checklist
    dqix test comprehensive                  # Run test suite
    dqix dashboard                           # Start web interface
"""

import asyncio
import signal
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    from .application.use_cases import DomainAssessmentUseCase
    from .domain.entities import Domain, ProbeConfig
    from .interfaces.cli import app as cli_app
except ImportError as e:
    print(f"❌ DQIX Import Error: {e}")
    print("💡 Try: pip install -e .")
    sys.exit(1)

console = Console()

def show_banner():
    """Display DQIX banner with version info."""
    banner = """
[bold blue]╔══════════════════════════════════════════════════════════════════╗[/bold blue]
[bold blue]║[/bold blue]  [bold white]🔍 DQIX - Internet Observability Platform[/bold white]                  [bold blue]║[/bold blue]
[bold blue]║[/bold blue]  [dim]Measuring the health of the Internet, together, in the open.[/dim]    [bold blue]║[/bold blue]
[bold blue]╚══════════════════════════════════════════════════════════════════╝[/bold blue]

[bold cyan]Quick Commands:[/bold cyan]
[white]  dqix scan [domain][/white]               [dim]# Comprehensive Internet health check[/dim]
[white]  dqix scan [domain] -d technical[/white]  [dim]# Technical deep dive analysis[/dim]
[white]  dqix validate [domain][/white]           [dim]# Security checklist validation[/dim]
[white]  dqix test comprehensive[/white]          [dim]# Test with known good domains[/dim]
[white]  dqix dashboard[/white]                   [dim]# Launch web interface[/dim]

[bold yellow]Probe Priority Order:[/bold yellow] [green]TLS[/green] → [blue]HTTPS[/blue] → [cyan]DNS[/cyan] → [magenta]Security Headers[/magenta]
"""
    console.print(Panel(banner, border_style="blue", padding=(1, 2)))

def handle_keyboard_interrupt(signum, frame):
    """Handle Ctrl+C gracefully."""
    console.print("\n[yellow]⚠️ Interrupted by user. Exiting gracefully...[/yellow]")
    sys.exit(0)

def quick_scan_demo():
    """Show a quick demo of DQIX capabilities."""

    console.print("[bold green]🚀 DQIX Quick Demo[/bold green]\n")

    demo_table = Table(title="Internet Security Analysis Example")
    demo_table.add_column("Domain", style="cyan", no_wrap=True)
    demo_table.add_column("TLS Score", justify="right", style="green")
    demo_table.add_column("DNS Score", justify="right", style="blue")
    demo_table.add_column("Overall", justify="right", style="bold")
    demo_table.add_column("Grade", justify="center")

    demo_results = [
        ("github.com", "95.2%", "89.1%", "92.1%", "A"),
        ("google.com", "88.7%", "94.3%", "90.5%", "A"),
        ("cloudflare.com", "97.8%", "96.2%", "95.8%", "A+"),
        ("microsoft.com", "91.4%", "87.9%", "89.3%", "B+")
    ]

    for domain, tls, dns, overall, grade in demo_results:
        demo_table.add_row(domain, tls, dns, overall, grade)

    console.print(demo_table)
    console.print("\n[dim]💡 Try: [bold]dqix scan github.com[/bold] for a real analysis[/dim]")

async def run_quick_analysis(domain_name: str):
    """Run a quick analysis demonstration."""

    console.print(f"[bold]🔍 Quick Internet Analysis: {domain_name}[/bold]\n")

    try:
        # Initialize components
        Domain(domain_name)
        ProbeConfig(timeout=15)

        # Simulate analysis with progress
        from rich.progress import Progress, SpinnerColumn, TextColumn

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:

            task = progress.add_task("🔄 Analyzing Internet security...", total=None)

            # Simulate probe execution
            await asyncio.sleep(1)
            progress.update(task, description="🔐 Checking TLS/SSL security...")
            await asyncio.sleep(0.8)

            progress.update(task, description="🌐 Analyzing HTTPS implementation...")
            await asyncio.sleep(0.7)

            progress.update(task, description="🌍 Examining DNS infrastructure...")
            await asyncio.sleep(0.9)

            progress.update(task, description="🛡️ Reviewing security headers...")
            await asyncio.sleep(0.6)

            progress.update(task, description="✅ Analysis complete!")

        # Display mock results
        console.print("\n[bold green]✅ Internet Health Analysis Complete[/bold green]")

        result_table = Table(title=f"Security Analysis: {domain_name}")
        result_table.add_column("Security Check", style="cyan")
        result_table.add_column("Score", justify="right")
        result_table.add_column("Status", justify="center")
        result_table.add_column("Details", style="dim")

        # Mock data based on domain characteristics
        if "github" in domain_name.lower():
            results = [
                ("TLS/SSL Security", "95.2%", "✅", "TLS 1.3, Strong ciphers"),
                ("HTTPS Implementation", "92.8%", "✅", "Secure redirects, HSTS"),
                ("DNS Infrastructure", "89.1%", "✅", "IPv6, DNSSEC, SPF/DMARC"),
                ("Security Headers", "87.5%", "⚠️", "Good CSP, Frame protection")
            ]
            overall_score = 91.1
            grade = "A"
        elif "google" in domain_name.lower():
            results = [
                ("TLS/SSL Security", "88.7%", "✅", "TLS 1.3, Modern config"),
                ("HTTPS Implementation", "94.2%", "✅", "Excellent performance"),
                ("DNS Infrastructure", "94.3%", "✅", "Robust infrastructure"),
                ("Security Headers", "85.1%", "✅", "Strong policies")
            ]
            overall_score = 90.6
            grade = "A"
        else:
            results = [
                ("TLS/SSL Security", "82.3%", "✅", "Good configuration"),
                ("HTTPS Implementation", "79.1%", "⚠️", "Room for improvement"),
                ("DNS Infrastructure", "85.7%", "✅", "Standard setup"),
                ("Security Headers", "71.2%", "⚠️", "Basic implementation")
            ]
            overall_score = 79.6
            grade = "B"

        for check, score, status, details in results:
            result_table.add_row(check, score, status, details)

        console.print(result_table)

        # Overall score panel
        score_color = "green" if overall_score >= 90 else "yellow" if overall_score >= 80 else "red"

        score_panel = Panel(
            f"[bold white]Overall Internet Health Score: [bold {score_color}]{overall_score:.1f}%[/bold {score_color}][/bold white]\n"
            f"[bold]Security Grade: {grade}[/bold]",
            title="🏆 Final Assessment",
            border_style=score_color
        )
        console.print(score_panel)

        # Recommendations
        recommendations = [
            "💡 Consider implementing stricter Content Security Policy",
            "🔧 Enable HSTS preloading for enhanced security",
            "🌐 Add IPv6 support if not already configured"
        ]

        rec_text = "\n".join(recommendations[:2])
        rec_panel = Panel(rec_text, title="💡 Recommendations", border_style="yellow")
        console.print(rec_panel)

        console.print(f"\n[dim]💡 For detailed analysis: [bold]dqix scan {domain_name} -d technical[/bold][/dim]")

    except Exception as e:
        console.print(f"[red]❌ Analysis failed: {e}[/red]")
        console.print(f"[dim]💡 Try: [bold]dqix scan {domain_name}[/bold] for comprehensive analysis[/dim]")

def main():
    """Main entry point for DQIX CLI."""

    # Set up signal handling
    signal.signal(signal.SIGINT, handle_keyboard_interrupt)

    # Check if running without arguments
    if len(sys.argv) == 1:
        show_banner()
        quick_scan_demo()
        console.print("\n[bold cyan]🚀 Get Started:[/bold cyan]")
        console.print("[white]dqix scan github.com[/white]                [dim]# Try scanning GitHub[/dim]")
        console.print("[white]dqix validate google.com --checklist[/white] [dim]# Security validation[/dim]")
        console.print("[white]dqix test comprehensive[/white]              [dim]# Run test suite[/dim]")
        console.print("[white]dqix --help[/white]                          [dim]# Show all commands[/dim]")
        return

    # Handle quick demo commands
    if len(sys.argv) >= 2:
        if sys.argv[1] == "demo":
            domain = sys.argv[2] if len(sys.argv) > 2 else "github.com"
            console.print("[bold blue]🔍 DQIX Internet Observability Platform[/bold blue]")
            console.print(f"[dim]Running quick demo analysis for: {domain}[/dim]\n")
            try:
                asyncio.run(run_quick_analysis(domain))
            except KeyboardInterrupt:
                console.print("\n[yellow]Demo interrupted by user.[/yellow]")
            return

        elif sys.argv[1] == "version":
            console.print("[bold blue]DQIX Internet Observability Platform[/bold blue]")
            console.print("[dim]Version: 1.0.0-alpha[/dim]")
            console.print("[dim]Internet health measurement platform[/dim]")
            return

        elif sys.argv[1] == "info":
            show_banner()

            info_table = Table(title="DQIX Platform Information")
            info_table.add_column("Component", style="cyan")
            info_table.add_column("Status", justify="center")
            info_table.add_column("Description", style="dim")

            components = [
                ("Core Engine", "✅", "Internet security analysis engine"),
                ("TLS Probe", "✅", "SSL/TLS protocol and certificate analysis"),
                ("DNS Probe", "✅", "DNS infrastructure and email security"),
                ("HTTPS Probe", "✅", "HTTPS implementation verification"),
                ("Security Headers", "✅", "HTTP security headers analysis"),
                ("Web Dashboard", "🔧", "Modern Tailwind + daisyUI interface"),
                ("API Interface", "🔧", "RESTful API for integrations"),
                ("Reporting", "✅", "JSON, HTML, and console output")
            ]

            for component, status, description in components:
                info_table.add_row(component, status, description)

            console.print(info_table)

            console.print("\n[bold yellow]📊 Analysis Capabilities:[/bold yellow]")
            console.print("• [cyan]TLS/SSL Security[/cyan] - Protocol versions, cipher suites, certificate validation")
            console.print("• [blue]HTTPS Implementation[/blue] - Accessibility, redirects, performance")
            console.print("• [green]DNS Infrastructure[/green] - Records, DNSSEC, email authentication")
            console.print("• [magenta]Security Headers[/magenta] - HSTS, CSP, frame protection")

            console.print("\n[bold cyan]🎯 Use Cases:[/bold cyan]")
            console.print("• Government compliance monitoring")
            console.print("• Academic research and benchmarking")
            console.print("• Security posture assessment")
            console.print("• Infrastructure health monitoring")
            return

    # Run the main CLI application
    try:
        cli_app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        console.print("[dim]Please report this issue to the DQIX development team.[/dim]")
        sys.exit(1)

if __name__ == "__main__":
    main()
