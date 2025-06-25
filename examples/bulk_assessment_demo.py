#!/usr/bin/env python3
"""
Bulk Domain Assessment Demo - DQIX Clean Architecture Example

This example demonstrates how to assess multiple domains efficiently
using DQIX's bulk assessment capabilities.

Usage:
    python examples/bulk_assessment_demo.py
    
Or with a custom domain list:
    python examples/bulk_assessment_demo.py domains.txt
"""

import asyncio
import sys
from pathlib import Path
from typing import List

from dqix.application.use_cases import (
    AssessDomainsCommand,
    AssessDomainsUseCase,
    AssessDomainUseCase
)
from dqix.domain.entities import ProbeConfig
from dqix.domain.services import AssessmentService, DomainValidationService, ScoringService
from dqix.infrastructure.probes import ProbeExecutor
from dqix.infrastructure.repositories import FileAssessmentRepository, InMemoryCacheRepository


def create_bulk_use_case() -> AssessDomainsUseCase:
    """
    Create bulk assessment use case with all dependencies.
    
    Returns:
        AssessDomainsUseCase: Ready for bulk domain assessment
    """
    # Infrastructure
    probe_executor = ProbeExecutor()
    assessment_repo = FileAssessmentRepository("./examples/bulk_assessments")
    cache_repo = InMemoryCacheRepository()
    
    # Domain services
    scoring_service = ScoringService()
    validation_service = DomainValidationService()
    assessment_service = AssessmentService(scoring_service, validation_service)
    
    # Single domain use case
    single_use_case = AssessDomainUseCase(
        probe_executor=probe_executor,
        assessment_service=assessment_service,
        validation_service=validation_service,
        assessment_repo=assessment_repo,
        cache_repo=cache_repo
    )
    
    # Bulk use case
    return AssessDomainsUseCase(single_use_case)


def get_sample_domains() -> List[str]:
    """
    Get a sample list of domains for demonstration.
    
    These domains represent different categories:
    - Popular websites (high security expected)
    - Government sites (high compliance expected)
    - Educational institutions
    - Commercial sites
    
    Returns:
        List[str]: Sample domain names
    """
    return [
        # Popular tech sites
        "google.com",
        "github.com",
        "stackoverflow.com",
        "cloudflare.com",
        
        # Government sites (should have high security)
        "gov.uk",
        "usa.gov",
        
        # Educational institutions
        "mit.edu",
        "stanford.edu",
        
        # News sites
        "bbc.com",
        "reuters.com",
        
        # E-commerce
        "amazon.com",
        "shopify.com"
    ]


def load_domains_from_file(file_path: Path) -> List[str]:
    """
    Load domains from a text file.
    
    File format:
    - One domain per line
    - Lines starting with # are comments
    - Empty lines are ignored
    
    Args:
        file_path: Path to the domains file
        
    Returns:
        List[str]: Domain names from file
        
    Example file content:
        # Popular domains
        google.com
        github.com
        
        # Government sites
        gov.uk
        usa.gov
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Domains file not found: {file_path}")
    
    domains = []
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
                
            # Basic validation
            if ' ' in line:
                print(f"Warning: Line {line_num} contains spaces, skipping: {line}")
                continue
                
            domains.append(line)
    
    return domains


async def assess_domains_with_progress(domains: List[str]) -> None:
    """
    Assess domains with progress reporting.
    
    Args:
        domains: List of domain names to assess
    """
    print(f"🚀 Starting bulk assessment of {len(domains)} domains")
    
    # Configuration for bulk assessment
    config = ProbeConfig(
        timeout=20,           # Shorter timeout for bulk
        retry_count=1,        # Fewer retries for speed
        cache_enabled=True,   # Use cache to avoid duplicate work
        max_concurrent=3      # Limit concurrency to avoid overwhelming servers
    )
    
    # Create command
    command = AssessDomainsCommand(
        domain_names=domains,
        probe_config=config
    )
    
    # Execute bulk assessment
    use_case = create_bulk_use_case()
    results = await use_case.execute(command)
    
    # Process results
    successful = [r for r in results if r.successful_probes]
    failed = len(domains) - len(successful)
    
    print(f"\n📊 Bulk Assessment Results")
    print(f"Total domains: {len(domains)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {failed}")
    
    if successful:
        # Calculate statistics
        scores = [r.overall_score for r in successful]
        avg_score = sum(scores) / len(scores)
        max_score = max(scores)
        min_score = min(scores)
        
        print(f"\n📈 Score Statistics")
        print(f"Average: {avg_score:.2f}")
        print(f"Highest: {max_score:.2f}")
        print(f"Lowest: {min_score:.2f}")
        
        # Top performers
        top_domains = sorted(successful, key=lambda r: r.overall_score, reverse=True)[:3]
        print(f"\n🏆 Top 3 Domains")
        for i, result in enumerate(top_domains, 1):
            print(f"{i}. {result.domain.name}: {result.overall_score:.2f} ({result.compliance_level.value})")
        
        # Compliance level distribution
        from collections import Counter
        compliance_counts = Counter(r.compliance_level.value for r in successful)
        print(f"\n📋 Compliance Level Distribution")
        for level, count in compliance_counts.items():
            percentage = (count / len(successful)) * 100
            print(f"{level.title()}: {count} domains ({percentage:.1f}%)")


async def generate_report(domains: List[str], output_file: str = "bulk_assessment_report.txt") -> None:
    """
    Generate a detailed report of bulk assessment.
    
    Args:
        domains: List of domains to assess
        output_file: Output file name for the report
    """
    print(f"📝 Generating detailed report...")
    
    config = ProbeConfig(timeout=30, cache_enabled=True, max_concurrent=2)
    command = AssessDomainsCommand(domain_names=domains, probe_config=config)
    
    use_case = create_bulk_use_case()
    results = await use_case.execute(command)
    
    # Generate report
    with open(output_file, 'w') as f:
        f.write("DQIX Bulk Domain Assessment Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Assessment Date: {results[0].timestamp if results else 'N/A'}\n")
        f.write(f"Total Domains: {len(domains)}\n")
        f.write(f"Successful Assessments: {len([r for r in results if r.successful_probes])}\n\n")
        
        f.write("Detailed Results:\n")
        f.write("-" * 30 + "\n")
        
        for result in results:
            f.write(f"\nDomain: {result.domain.name}\n")
            f.write(f"Overall Score: {result.overall_score:.2f}\n")
            f.write(f"Compliance Level: {result.compliance_level.value}\n")
            f.write("Probe Results:\n")
            
            for probe_result in result.probe_results:
                status = "PASS" if probe_result.is_successful else "FAIL"
                f.write(f"  - {probe_result.probe_id}: {probe_result.score:.2f} [{status}]\n")
                if probe_result.error:
                    f.write(f"    Error: {probe_result.error}\n")
            f.write("\n")
    
    print(f"✅ Report saved to: {output_file}")


async def main():
    """
    Main function for bulk assessment demo.
    """
    print("🔍 DQIX Bulk Domain Assessment Demo")
    print("=" * 50)
    
    # Check if domains file provided
    if len(sys.argv) > 1:
        domains_file = Path(sys.argv[1])
        try:
            domains = load_domains_from_file(domains_file)
            print(f"📁 Loaded {len(domains)} domains from {domains_file}")
        except FileNotFoundError as e:
            print(f"❌ Error: {e}")
            return
    else:
        domains = get_sample_domains()
        print(f"📋 Using {len(domains)} sample domains")
    
    # Show domains to be assessed
    print("\n🎯 Domains to assess:")
    for i, domain in enumerate(domains, 1):
        print(f"  {i:2d}. {domain}")
    
    # Perform bulk assessment
    print(f"\n⏳ Starting assessment...")
    await assess_domains_with_progress(domains)
    
    # Generate detailed report
    print(f"\n📄 Generating report...")
    await generate_report(domains)
    
    print(f"\n✨ Bulk assessment completed!")
    print(f"\nTo create your own domains file:")
    print(f"1. Create a text file with one domain per line")
    print(f"2. Use # for comments")
    print(f"3. Run: python {__file__} your_domains.txt")


if __name__ == "__main__":
    asyncio.run(main()) 