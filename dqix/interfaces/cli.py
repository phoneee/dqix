"""
DQIX CLI - Modern, intuitive command-line interface for domain quality assessment.

Following UX best practices:
- Noun-first command structure (domain assess, domain compare, etc.)
- Progressive disclosure - show relevant info only
- Consistent behavior and naming
- Clear, actionable help text
- Rich output formatting
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns
from rich import box

from ..application.use_cases import DomainAssessmentUseCase
from ..infrastructure.factory import create_infrastructure
from ..domain.entities import ComplianceLevel

# Initialize console and Typer app
console = Console()
app = typer.Typer(
    name="dqix",
    help="🔍 DQIX - Domain Quality Index Assessment Tool",
    no_args_is_help=True,
    rich_markup_mode="rich"
)

# Global settings
DEFAULT_SAVE_DIR = ".dqix_assessments"


# ============================================================================
# Core Commands - Following noun-first structure
# ============================================================================

@app.command("assess")
def assess_domain(
    domain: str = typer.Argument(..., help="Domain to assess (e.g., example.com)"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show detailed analysis"),
    technical: bool = typer.Option(False, "-t", "--technical", help="Include technical details"),
    checklist: bool = typer.Option(False, "--checklist", help="Show detailed measurement checklists"),
    recommendations: bool = typer.Option(False, "-r", "--recommendations", help="Show improvement recommendations"),
    format: str = typer.Option("rich", "-f", "--format", help="Output format: rich, json, table"),
    save: bool = typer.Option(False, "-s", "--save", help="Save results to file"),
    save_dir: str = typer.Option(DEFAULT_SAVE_DIR, "--save-dir", help="Directory to save results"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    comprehensive: bool = typer.Option(False, "-c", "--comprehensive", help="Run comprehensive analysis")
):
    """🔍 Assess a single domain with comprehensive security and compliance analysis."""
    
    # Validate domain
    domain = domain.strip().lower()
    if not domain or '/' in domain or ' ' in domain:
        console.print("❌ Invalid domain format. Use: example.com", style="red")
        raise typer.Exit(1)
    
    # Show assessment start
    console.print(f"\n🔍 Assessing domain: [bold cyan]{domain}[/bold cyan]")
    
    try:
        # Run assessment with progress
        result = asyncio.run(_run_assessment_with_progress(domain, timeout, comprehensive))
        
        # Display results based on format
        if format == "json":
            _display_json_result(result)
        elif format == "table":
            _display_table_result(result, verbose, technical or checklist, recommendations)
        else:  # rich format (default)
            _display_rich_result(result, verbose, technical or checklist, recommendations)
        
        # Save if requested
        if save:
            _save_assessment_result(result, save_dir)
        
    except Exception as e:
        console.print(f"❌ Assessment failed: {str(e)}", style="red")
        raise typer.Exit(1)


@app.command("compare")
def compare_domains(
    domains: List[str] = typer.Argument(..., help="Domains to compare (space-separated)"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show detailed comparison"),
    checklist: bool = typer.Option(False, "--checklist", help="Show detailed measurement checklists"),
    format: str = typer.Option("rich", "-f", "--format", help="Output format: rich, json, table"),
    save: bool = typer.Option(False, "-s", "--save", help="Save comparison results"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds")
):
    """📊 Compare multiple domains side-by-side."""
    
    if len(domains) < 2:
        console.print("❌ Need at least 2 domains to compare", style="red")
        raise typer.Exit(1)
    
    if len(domains) > 5:
        console.print("❌ Maximum 5 domains can be compared at once", style="red")
        raise typer.Exit(1)
    
    console.print(f"\n📊 Comparing {len(domains)} domains...")
    
    try:
        # Assess all domains
        results = []
        for domain in domains:
            console.print(f"  • Assessing {domain}...")
            result = asyncio.run(_run_assessment_with_progress(domain, timeout, False))
            results.append(result)
        
        # Display comparison
        _display_comparison(results, format, verbose)
        
        # Display detailed measurements for each domain if checklist is enabled
        if checklist and format != "json":
            for result in results:
                console.print(f"\n[bold cyan]📋 Detailed Measurements for {result.get('domain', 'Unknown')}[/bold cyan]")
                probe_results = result.get("probe_results", [])
                if probe_results:
                    _display_measurement_checklists(probe_results)
                else:
                    console.print("  No probe results available")
        
        if save:
            _save_comparison_results(results, DEFAULT_SAVE_DIR)
        
    except Exception as e:
        console.print(f"❌ Comparison failed: {str(e)}", style="red")
        raise typer.Exit(1)


@app.command("bulk")
def bulk_assess(
    file_path: str = typer.Argument(..., help="File containing domains (txt, csv, or json)"),
    format: str = typer.Option("rich", "-f", "--format", help="Output format: rich, json, csv"),
    save_dir: str = typer.Option(DEFAULT_SAVE_DIR, "--save-dir", help="Directory to save results"),
    concurrent: int = typer.Option(5, "-c", "--concurrent", help="Number of concurrent assessments"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    summary: bool = typer.Option(True, "--summary/--no-summary", help="Show summary statistics")
):
    """📋 Assess multiple domains from a file with progress tracking."""
    
    # Load domains from file
    try:
        domains = _load_domains_from_file(file_path)
    except Exception as e:
        console.print(f"❌ Failed to load domains: {str(e)}", style="red")
        raise typer.Exit(1)
    
    if not domains:
        console.print("❌ No valid domains found in file", style="red")
        raise typer.Exit(1)
    
    console.print(f"\n📋 Bulk assessment: {len(domains)} domains")
    console.print(f"   Concurrency: {concurrent} | Timeout: {timeout}s")
    
    try:
        # Run bulk assessment
        results = asyncio.run(_run_bulk_assessment(domains, concurrent, timeout))
        
        # Display results
        _display_bulk_results(results, format, summary)
        
        # Save results
        _save_bulk_results(results, save_dir, format)
        
    except Exception as e:
        console.print(f"❌ Bulk assessment failed: {str(e)}", style="red")
        raise typer.Exit(1)


@app.command("probes")
def list_probes(
    detailed: bool = typer.Option(False, "-d", "--detailed", help="Show detailed probe information"),
    category: Optional[str] = typer.Option(None, "-c", "--category", help="Filter by category: security, performance, compliance")
):
    """🔬 List all available assessment probes."""
    
    console.print("\n🔬 Available Assessment Probes\n")
    
    # Get probe information
    infrastructure = create_infrastructure()
    probe_registry = infrastructure.get_probe_registry()
    probes_dict = probe_registry.get_all_probes()
    probes = list(probes_dict.values())
    
    if category:
        probes = [p for p in probes if p.category.value.lower() == category.lower()]
    
    if not probes:
        console.print("❌ No probes found", style="red")
        return
    
    if detailed:
        _display_detailed_probes(probes)
    else:
        _display_simple_probes(probes)


# ============================================================================
# Helper Functions
# ============================================================================

async def _run_assessment_with_progress(domain: str, timeout: int, comprehensive: bool) -> Dict[str, Any]:
    """Run domain assessment with progress indicator."""
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("Analyzing domain...", total=100)
        
        # Initialize use case
        infrastructure = create_infrastructure()
        use_case = DomainAssessmentUseCase(infrastructure)
        
        # Run assessment
        result = await use_case.assess_domain(domain, timeout, comprehensive)
        
        progress.update(task, completed=100)
        
        return result


def _display_rich_result(result: Dict[str, Any], verbose: bool, technical: bool, recommendations: bool):
    """Display assessment result in rich format."""
    
    domain = result.get("domain", "Unknown")
    score = result.get("overall_score", 0.0)
    compliance = result.get("compliance_level", "unknown")
    error = result.get("error")
    
    # Handle error cases
    if error:
        error_panel = Panel(
            f"[bold white]❌ Domain Assessment Failed[/bold white]\n"
            f"[cyan]Domain:[/cyan] {domain}\n"
            f"[cyan]Timestamp:[/cyan] {result.get('timestamp', 'Unknown')}\n"
            f"[red]Error:[/red] {error}",
            title="Assessment Error",
            border_style="red"
        )
        console.print(error_panel)
        return
    
    # Header panel for successful assessments
    header = Panel(
        f"[bold white]🔍 Domain Assessment Report[/bold white]\n"
        f"[cyan]Domain:[/cyan] {domain}\n"
        f"[cyan]Timestamp:[/cyan] {result.get('timestamp', 'Unknown')}\n"
        f"[cyan]Overall Score:[/cyan] {score:.2f}/1.00\n"
        f"[cyan]Compliance Level:[/cyan] {compliance}",
        title="Assessment Summary",
        border_style="blue"
    )
    console.print(header)
    
    # Score bar
    score_bar = _create_score_bar(score)
    console.print(score_bar)
    
    # Probe results table
    _display_probe_results_table(result.get("probe_results", []), technical)
    
    # Category breakdown
    _display_category_breakdown(result.get("category_scores", {}))
    
    # Show recommendations if requested
    if recommendations:
        _display_recommendations(result)
    
    # Show technical details if requested
    if technical and verbose:
        _display_technical_details(result)


def _display_json_result(result: Dict[str, Any]):
    """Display result in JSON format."""
    console.print(json.dumps(result, indent=2, default=str))


def _display_table_result(result: Dict[str, Any], verbose: bool, technical: bool, recommendations: bool):
    """Display result in simple table format."""
    
    # Basic info table
    info_table = Table(title="Domain Assessment", box=box.SIMPLE)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("Domain", result.get("domain", "Unknown"))
    info_table.add_row("Score", f"{result.get('overall_score', 0.0):.2f}/1.00")
    info_table.add_row("Compliance", result.get("compliance_level", "unknown"))
    info_table.add_row("Timestamp", result.get("timestamp", "Unknown"))
    
    console.print(info_table)
    console.print()
    
    # Probe results
    _display_probe_results_table(result.get("probe_results", []), technical)


def _create_score_bar(score: float) -> Panel:
    """Create a visual score bar."""
    bar_length = 40
    filled_length = int(bar_length * score)
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    
    # Color based on score
    if score >= 0.8:
        color = "green"
    elif score >= 0.6:
        color = "yellow"
    else:
        color = "red"
    
    return Panel(
        f"[{color}]{bar}[/{color}] {score:.1f}/1.00",
        title="Overall Score",
        border_style=color
    )


def _display_probe_results_table(probe_results: List[Dict[str, Any]], show_technical: bool):
    """Display probe results in a table."""
    
    table = Table(title="📊 Probe Analysis Results", box=box.ROUNDED)
    table.add_column("Probe", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Score", style="white", justify="center")
    table.add_column("Status", style="white", justify="center")
    table.add_column("Details", style="white")
    
    for probe in probe_results:
        # Status emoji
        score = probe.get("score", 0.0)
        if probe.get("error"):
            status = "❌ Error"
            status_style = "red"
        elif score >= 0.8:
            status = "✅ Excellent"
            status_style = "green"
        elif score >= 0.6:
            status = "⚠️ Good"
            status_style = "yellow"
        else:
            status = "🔴 Needs Improvement"
            status_style = "red"
        
        # Details
        if probe.get("error"):
            details = probe["error"]
        elif show_technical and "technical_details" in probe:
            details = "Technical details available"
        else:
            details = "No issues detected"
        
        table.add_row(
            probe.get("probe_id", "Unknown"),
            probe.get("category", "unknown"),
            f"{score:.1f}",
            f"[{status_style}]{status}[/{status_style}]",
            details
        )
    
    console.print(table)
    
    # Display detailed measurement checklists if technical details are requested
    if show_technical:
        _display_measurement_checklists(probe_results)


def _display_measurement_checklists(probe_results: List[Dict[str, Any]]):
    """Display comprehensive measurement checklists for each probe result."""
    
    console.print("\n📋 Detailed Measurement Checklists\n")
    
    if not probe_results:
        console.print("[dim]No probe results available for detailed analysis[/dim]")
        return
    
    for probe in probe_results:
        probe_id = probe.get("probe_id", "Unknown")
        technical_details = probe.get("technical_details", {})
        probe_error = probe.get("error")
        
        console.print(f"\n[bold cyan]🔬 {probe_id.upper()} Probe Measurements[/bold cyan]")
        
        # Handle probe errors
        if probe_error:
            console.print(f"[red]❌ Probe Error: {probe_error}[/red]")
            continue
        
        # Handle missing technical details
        if not technical_details:
            console.print("[dim]No technical details available for this probe[/dim]")
            continue
            
        # Display probe-specific checklists
        try:
            if probe_id == "tls":
                _display_tls_checklist(technical_details)
            elif probe_id == "dns":
                _display_dns_checklist(technical_details)
            elif probe_id == "security_headers":
                _display_security_headers_checklist(technical_details)
            else:
                console.print(f"[yellow]Checklist not yet implemented for {probe_id} probe[/yellow]")
        except Exception as e:
            console.print(f"[red]Error displaying checklist: {str(e)}[/red]")


def _display_tls_checklist(details: Dict[str, Any]):
    """Display TLS measurement checklist."""
    
    # TLS Protocol Analysis
    console.print("\n[bold]🔐 TLS Protocol Analysis[/bold]")
    connection = details.get("connection_analysis", {})
    
    # Safely extract cipher suite information
    cipher_suite = connection.get("cipher_suite", [])
    protocol_version = connection.get("protocol_version", "Unknown")
    
    if isinstance(cipher_suite, list) and len(cipher_suite) > 0:
        cipher_name = cipher_suite[0] if cipher_suite[0] else "Unknown"
        key_size = f"{cipher_suite[2]} bits" if len(cipher_suite) > 2 and cipher_suite[2] else "Unknown"
    else:
        cipher_name = "Unknown"
        key_size = "Unknown"
    
    checklist_items = [
        ("Protocol Version", protocol_version),
        ("Cipher Suite", cipher_name),
        ("Key Size", key_size),
        ("Compression", "Disabled" if connection.get("compression") is None else "Enabled"),
    ]
    
    _print_checklist_section("Protocol Configuration", checklist_items)
    
    # Certificate Analysis
    console.print("\n[bold]📜 Certificate Analysis[/bold]")
    cert = details.get("certificate_analysis", {})
    validity = cert.get("validity", {})
    
    cert_items = [
        ("Issuer", cert.get("issuer", {}).get("commonName", "Unknown")),
        ("Subject", cert.get("subject", {}).get("commonName", "Unknown")),
        ("Valid From", validity.get("not_before", "Unknown")),
        ("Valid Until", validity.get("not_after", "Unknown")),
        ("Days Until Expiry", f"{validity.get('days_until_expiry', 'Unknown')} days"),
        ("Is Expired", "❌ Yes" if validity.get("is_expired") else "✅ No"),
        ("Expires Soon", "⚠️ Yes" if validity.get("expires_soon") else "✅ No"),
    ]
    
    _print_checklist_section("Certificate Validity", cert_items)
    
    # Public Key Analysis
    pub_key = cert.get("public_key", {})
    key_items = [
        ("Algorithm", pub_key.get("algorithm", "Unknown")),
        ("Key Size", f"{pub_key.get('size_bits', 'Unknown')} bits"),
        ("Is Weak", "❌ Yes" if pub_key.get("is_weak") else "✅ No"),
        ("Key Type", pub_key.get("details", {}).get("type", "Unknown")),
    ]
    
    _print_checklist_section("Public Key", key_items)
    
    # Security Assessment
    security = details.get("security_assessment", {})
    security_items = [
        ("Overall Security Level", security.get("overall_security_level", "Unknown").title()),
        ("Modern TLS", "✅ Yes" if details.get("technical_summary", {}).get("modern_tls") else "❌ No"),
        ("Secure Cipher", "✅ Yes" if details.get("technical_summary", {}).get("secure_cipher") else "❌ No"),
        ("Vulnerabilities Found", security.get("vulnerabilities", []).__len__()),
    ]
    
    _print_checklist_section("Security Assessment", security_items)


def _display_dns_checklist(details: Dict[str, Any]):
    """Display DNS measurement checklist."""
    
    # Basic DNS Records
    console.print("\n[bold]🌐 DNS Records Analysis[/bold]")
    records = details.get("dns_records_analysis", {})
    counts = records.get("record_counts", {})
    
    # Calculate total records
    total_records = sum(counts.values()) if counts else 0
    
    dns_items = [
        ("A Records (IPv4)", counts.get("a_records", 0)),
        ("AAAA Records (IPv6)", counts.get("aaaa_records", 0)),
        ("MX Records (Mail)", counts.get("mx_records", 0)),
        ("NS Records (Nameservers)", counts.get("ns_records", 0)),
        ("TXT Records", counts.get("txt_records", 0)),
        ("CNAME Records", counts.get("cname_records", 0)),
        ("Total DNS Records", total_records),
    ]
    
    _print_checklist_section("DNS Record Inventory", dns_items)
    
    # Mail Security Analysis
    console.print("\n[bold]📧 Mail Security Analysis[/bold]")
    mail = details.get("mail_security_analysis", {})
    
    spf = mail.get("spf_analysis", {})
    dmarc = mail.get("dmarc_analysis", {})
    dkim = mail.get("dkim_analysis", {})
    
    mail_items = [
        ("SPF Record", "✅ Found" if spf.get("record_found") else "❌ Missing"),
        ("SPF Policy", spf.get("security_level", "None").title()),
        ("DMARC Record", "✅ Found" if dmarc.get("record_found") else "❌ Missing"),
        ("DMARC Policy", dmarc.get("policy", "None").title()),
        ("DKIM Selectors", f"{dkim.get('selectors_active', 0)} active"),
        ("Mail Security Score", f"{mail.get('security_score', 0)}/100"),
    ]
    
    _print_checklist_section("Email Authentication", mail_items)
    
    # Security Features
    console.print("\n[bold]🛡️ DNS Security Features[/bold]")
    security = details.get("security_features_analysis", {})
    
    security_items = [
        ("DNSSEC", "✅ Enabled" if security.get("dnssec_enabled") else "❌ Disabled"),
        ("CAA Records", f"{len(security.get('caa_records', []))} found"),
        ("IPv6 Support", "✅ Yes" if details.get("technical_assessment", {}).get("ipv6_support") else "❌ No"),
        ("Security Score", f"{security.get('security_score', 0)}/100"),
    ]
    
    _print_checklist_section("Security Features", security_items)


def _display_security_headers_checklist(details: Dict[str, Any]):
    """Display Security Headers measurement checklist."""
    
    # HTTP Security Analysis
    console.print("\n[bold]🔒 HTTP Security Headers[/bold]")
    headers = details.get("security_headers_analysis", {})
    
    # Safely extract response information
    https_response = details.get("https_response", {})
    http_response = details.get("http_response", {})
    
    https_accessible = https_response.get("accessible", False)
    http_redirects = http_response.get("redirect_info", {}).get("redirected", False)
    response_time = https_response.get("response_time_ms", 0)
    
    # Core Security Headers
    core_items = [
        ("HTTPS Accessible", "✅ Yes" if https_accessible else "❌ No"),
        ("HTTP Redirects to HTTPS", "✅ Yes" if http_redirects else "❌ No"),
        ("Response Time", f"{response_time}ms" if response_time else "Unknown"),
        ("HTTPS Status Code", https_response.get("status_code", "Unknown")),
    ]
    
    _print_checklist_section("Basic HTTPS Configuration", core_items)
    
    # Security Headers Checklist
    hsts = headers.get("hsts", {})
    csp = headers.get("csp", {})
    frame_options = headers.get("x_frame_options", {})
    content_type = headers.get("x_content_type_options", {})
    xss_protection = headers.get("x_xss_protection", {})
    referrer = headers.get("referrer_policy", {})
    
    headers_items = [
        ("HSTS (Strict-Transport-Security)", 
         f"✅ Present ({hsts.get('security_level', 'unknown')})" if hsts.get("present") else "❌ Missing"),
        ("CSP (Content-Security-Policy)", 
         f"✅ Present ({csp.get('security_level', 'unknown')})" if csp.get("present") else "❌ Missing"),
        ("X-Frame-Options", 
         f"✅ Present ({frame_options.get('security_level', 'unknown')})" if frame_options.get("present") else "❌ Missing"),
        ("X-Content-Type-Options", 
         "✅ Present" if content_type.get("present") else "❌ Missing"),
        ("X-XSS-Protection", 
         "✅ Present" if xss_protection.get("present") else "❌ Missing"),
        ("Referrer-Policy", 
         "✅ Present" if referrer.get("present") else "❌ Missing"),
    ]
    
    _print_checklist_section("Security Headers Status", headers_items)
    
    # Header Statistics
    stats = details.get("header_statistics", {})
    assessment = details.get("security_assessment", {})
    
    stats_items = [
        ("Total Headers", stats.get("total_headers", 0)),
        ("Security Headers", stats.get("security_headers_count", 0)),
        ("Missing Critical", len(stats.get("missing_security_headers", []))),
        ("Information Disclosure", len(stats.get("information_disclosure", []))),
        ("Overall Security Score", f"{assessment.get('overall_score', 0)}/100"),
        ("Security Level", assessment.get("security_level", "Unknown").title()),
    ]
    
    _print_checklist_section("Security Assessment Summary", stats_items)


def _print_checklist_section(title: str, items: List[tuple]):
    """Print a checklist section with items."""
    
    table = Table(title=title, box=box.SIMPLE, show_header=False)
    table.add_column("Measurement", style="cyan", width=30)
    table.add_column("Value", style="white")
    
    for item, value in items:
        # Handle None values
        if value is None:
            formatted_value = "[dim]Not Available[/dim]"
        # Format boolean and status values with colors
        elif isinstance(value, bool):
            formatted_value = "✅ Yes" if value else "❌ No"
        elif isinstance(value, str):
            # Handle empty strings
            if not value.strip():
                formatted_value = "[dim]Not Set[/dim]"
            # Handle status indicators
            elif any(indicator in value.lower() for indicator in ["✅", "❌", "⚠️"]):
                formatted_value = value
            # Handle "Unknown" values
            elif value.lower() in ["unknown", "none", "n/a", "not available"]:
                formatted_value = f"[dim]{value}[/dim]"
            else:
                formatted_value = value
        elif isinstance(value, (int, float)):
            # Handle score values
            if item.lower().endswith("score") or "score" in item.lower():
                if value == 0:
                    formatted_value = f"[red]{value}[/red]"
                elif value >= 80:
                    formatted_value = f"[green]{value}[/green]"
                elif value >= 60:
                    formatted_value = f"[yellow]{value}[/yellow]"
                else:
                    formatted_value = f"[red]{value}[/red]"
            # Handle count values
            elif value == 0 and any(word in item.lower() for word in ["records", "found", "active", "missing"]):
                formatted_value = f"[dim]{value}[/dim]"
            else:
                formatted_value = str(value)
        else:
            formatted_value = str(value)
        
        table.add_row(f"• {item}", formatted_value)
    
    console.print(table)


def _display_category_breakdown(category_scores: Dict[str, float]):
    """Display category score breakdown."""
    
    if not category_scores:
        return
    
    console.print("\n📈 Category Breakdown:")
    for category, score in category_scores.items():
        color = "green" if score >= 0.8 else "yellow" if score >= 0.6 else "red"
        console.print(f"  {category}: [{color}]{score:.1f}/1.00[/{color}]")


def _display_recommendations(result: Dict[str, Any]):
    """Display improvement recommendations."""
    
    recommendations = []
    
    # Collect recommendations from probe results
    for probe in result.get("probe_results", []):
        if probe.get("score", 1.0) < 0.8:
            probe_id = probe.get("probe_id", "Unknown")
            recommendations.append(f"Improve {probe_id} security configuration")
    
    if recommendations:
        rec_panel = Panel(
            "\n".join(f"• {rec}" for rec in recommendations),
            title="🔧 Improvement Recommendations",
            border_style="yellow"
        )
        console.print(rec_panel)


def _display_technical_details(result: Dict[str, Any]):
    """Display technical details."""
    
    console.print("\n🔧 Technical Details:")
    for probe in result.get("probe_results", []):
        if "technical_details" in probe:
            console.print(f"\n[bold]{probe.get('probe_id', 'Unknown')}:[/bold]")
            details = probe["technical_details"]
            if isinstance(details, dict):
                for key, value in details.items():
                    console.print(f"  {key}: {value}")
            else:
                console.print(f"  {details}")


def _display_comparison(results: List[Dict[str, Any]], format: str, verbose: bool = False):
    """Display domain comparison."""
    
    if format == "json":
        console.print(json.dumps(results, indent=2, default=str))
        return
    
    # Create comparison table
    table = Table(title="📊 Domain Comparison", box=box.ROUNDED)
    table.add_column("Domain", style="cyan")
    table.add_column("Score", style="white", justify="center")
    table.add_column("Compliance", style="magenta", justify="center")
    table.add_column("Security", style="white", justify="center")
    
    for result in results:
        domain = result.get("domain", "Unknown")
        score = result.get("overall_score", 0.0)
        compliance = result.get("compliance_level", "unknown")
        
        # Calculate security score from probe results
        security_scores = [p.get("score", 0.0) for p in result.get("probe_results", []) 
                          if p.get("category") == "security"]
        security_avg = sum(security_scores) / len(security_scores) if security_scores else 0.0
        
        # Color coding
        score_color = "green" if score >= 0.8 else "yellow" if score >= 0.6 else "red"
        
        table.add_row(
            domain,
            f"[{score_color}]{score:.2f}[/{score_color}]",
            compliance,
            f"{security_avg:.2f}"
        )
    
    console.print(table)


def _display_detailed_probes(probes: List[Any]):
    """Display detailed probe information."""
    
    for probe in probes:
        probe_panel = Panel(
            f"[cyan]Category:[/cyan] {probe.category.value}\n"
            f"[cyan]Description:[/cyan] {probe.__doc__ or 'No description available'}\n"
            f"[cyan]Module:[/cyan] {probe.__module__}",
            title=f"🔬 {probe.probe_id}",
            border_style="blue"
        )
        console.print(probe_panel)


def _display_simple_probes(probes: List[Any]):
    """Display simple probe list."""
    
    table = Table(title="Available Probes", box=box.SIMPLE)
    table.add_column("Probe ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Description", style="white")
    
    for probe in probes:
        description = (probe.__doc__ or "No description").split('\n')[0][:60]
        table.add_row(
            probe.probe_id,
            probe.category.value,
            description
        )
    
    console.print(table)


def _load_domains_from_file(file_path: str) -> List[str]:
    """Load domains from various file formats."""
    
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    domains = []
    
    if path.suffix.lower() == '.json':
        with open(path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                domains = [str(d).strip() for d in data]
            elif isinstance(data, dict) and 'domains' in data:
                domains = [str(d).strip() for d in data['domains']]
    
    elif path.suffix.lower() == '.csv':
        import csv
        with open(path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if row and not row[0].startswith('#'):
                    domains.append(row[0].strip())
    
    else:  # txt or other
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
    
    # Filter valid domains
    valid_domains = []
    for domain in domains:
        if domain and '.' in domain and ' ' not in domain:
            valid_domains.append(domain.lower())
    
    return valid_domains


async def _run_bulk_assessment(domains: List[str], concurrent: int, timeout: int) -> List[Dict[str, Any]]:
    """Run bulk assessment with concurrency control."""
    
    results = []
    semaphore = asyncio.Semaphore(concurrent)
    
    async def assess_single(domain: str) -> Dict[str, Any]:
        async with semaphore:
            try:
                infrastructure = create_infrastructure()
                use_case = DomainAssessmentUseCase(infrastructure)
                return await use_case.assess_domain(domain, timeout, False)
            except Exception as e:
                return {
                    "domain": domain,
                    "error": str(e),
                    "overall_score": 0.0,
                    "compliance_level": "error"
                }
    
    # Run assessments with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("Assessing domains...", total=len(domains))
        
        tasks = [assess_single(domain) for domain in domains]
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            progress.advance(task)
    
    return results


def _display_bulk_results(results: List[Dict[str, Any]], format: str, show_summary: bool):
    """Display bulk assessment results."""
    
    if format == "json":
        console.print(json.dumps(results, indent=2, default=str))
        return
    
    # Handle empty results
    if not results:
        console.print("[red]No results to display[/red]")
        return
    
    # Summary statistics
    if show_summary:
        total = len(results)
        successful = len([r for r in results if not r.get("error")])
        failed = total - successful
        
        # Calculate stats for successful assessments
        if successful > 0:
            successful_results = [r for r in results if not r.get("error")]
            avg_score = sum(r.get("overall_score", 0.0) for r in successful_results) / successful
            high_scores = len([r for r in successful_results if r.get("overall_score", 0.0) >= 0.8])
            medium_scores = len([r for r in successful_results if 0.6 <= r.get("overall_score", 0.0) < 0.8])
            low_scores = len([r for r in successful_results if r.get("overall_score", 0.0) < 0.6])
            
            summary_panel = Panel(
                f"[cyan]Total Domains:[/cyan] {total}\n"
                f"[green]Successful:[/green] {successful}\n"
                f"[red]Failed:[/red] {failed}\n"
                f"[yellow]Average Score:[/yellow] {avg_score:.2f}\n"
                f"[green]High Scores (≥0.8):[/green] {high_scores}\n"
                f"[yellow]Medium Scores (0.6-0.8):[/yellow] {medium_scores}\n"
                f"[red]Low Scores (<0.6):[/red] {low_scores}",
                title="📊 Bulk Assessment Summary",
                border_style="blue"
            )
            console.print(summary_panel)
        else:
            error_panel = Panel(
                f"[cyan]Total Domains:[/cyan] {total}\n"
                f"[red]All assessments failed[/red]\n"
                f"[yellow]Check domains and network connectivity[/yellow]",
                title="📊 Bulk Assessment Summary",
                border_style="red"
            )
            console.print(error_panel)
    
    # Results table
    table = Table(title="Bulk Assessment Results", box=box.ROUNDED)
    table.add_column("Domain", style="cyan")
    table.add_column("Score", style="white", justify="center")
    table.add_column("Compliance", style="magenta")
    table.add_column("Status", style="white")
    
    for result in results:
        domain = result.get("domain", "Unknown")
        score = result.get("overall_score", 0.0)
        compliance = result.get("compliance_level", "unknown")
        
        if result.get("error"):
            status = "❌ Error"
            score_text = "N/A"
        else:
            status = "✅ Success"
            score_color = "green" if score >= 0.8 else "yellow" if score >= 0.6 else "red"
            score_text = f"[{score_color}]{score:.2f}[/{score_color}]"
        
        table.add_row(domain, score_text, compliance, status)
    
    console.print(table)


def _save_assessment_result(result: Dict[str, Any], save_dir: str):
    """Save single assessment result."""
    
    save_path = Path(save_dir)
    save_path.mkdir(exist_ok=True)
    
    domain = result.get("domain", "unknown")
    timestamp = datetime.now().isoformat()
    filename = f"{domain}_{timestamp}.json"
    
    file_path = save_path / filename
    with open(file_path, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    
    console.print(f"💾 Results saved to: {file_path}")


def _save_comparison_results(results: List[Dict[str, Any]], save_dir: str):
    """Save comparison results."""
    
    save_path = Path(save_dir)
    save_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().isoformat()
    filename = f"comparison_{timestamp}.json"
    
    file_path = save_path / filename
    with open(file_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    console.print(f"💾 Comparison saved to: {file_path}")


def _save_bulk_results(results: List[Dict[str, Any]], save_dir: str, format: str):
    """Save bulk assessment results."""
    
    save_path = Path(save_dir)
    save_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().isoformat()
    
    if format == "csv":
        import csv
        filename = f"bulk_assessment_{timestamp}.csv"
        file_path = save_path / filename
        
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "Score", "Compliance", "Status", "Error"])
            
            for result in results:
                writer.writerow([
                    result.get("domain", ""),
                    result.get("overall_score", 0.0),
                    result.get("compliance_level", ""),
                    "Error" if result.get("error") else "Success",
                    result.get("error", "")
                ])
    else:
        filename = f"bulk_assessment_{timestamp}.json"
        file_path = save_path / filename
        
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    
    console.print(f"💾 Bulk results saved to: {file_path}")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main CLI entry point."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n❌ Operation cancelled by user", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n❌ Unexpected error: {str(e)}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    main() 