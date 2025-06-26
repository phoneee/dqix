#!/usr/bin/env python3
"""
Domain Assessment Demo - DQIX Clean Architecture Example

This example demonstrates how to use DQIX to assess domain quality
using the clean architecture pattern.

Usage:
    python examples/domain_assessment_demo.py
"""

import asyncio

from dqix.application.use_cases import AssessDomainCommand, AssessDomainUseCase
from dqix.domain.entities import ProbeConfig
from dqix.domain.services import AssessmentService, DomainValidationService, ScoringService
from dqix.infrastructure.probes import ProbeExecutor
from dqix.infrastructure.repositories import FileAssessmentRepository, InMemoryCacheRepository


def create_assessment_use_case() -> AssessDomainUseCase:
    """
    Factory function to create a complete assessment use case.

    This demonstrates dependency injection in clean architecture:
    - Infrastructure layer provides concrete implementations
    - Domain layer provides business logic
    - Application layer orchestrates the workflow

    Returns:
        AssessDomainUseCase: Ready-to-use assessment service
    """
    # Infrastructure layer - external services
    probe_executor = ProbeExecutor()
    assessment_repo = FileAssessmentRepository("./examples/assessments")
    cache_repo = InMemoryCacheRepository()

    # Domain layer - business logic
    scoring_service = ScoringService()
    validation_service = DomainValidationService()
    assessment_service = AssessmentService(scoring_service, validation_service)

    # Application layer - use case orchestration
    return AssessDomainUseCase(
        probe_executor=probe_executor,
        assessment_service=assessment_service,
        validation_service=validation_service,
        assessment_repo=assessment_repo,
        cache_repo=cache_repo
    )


async def assess_single_domain(domain: str) -> None:
    """
    Assess a single domain and display results.

    Args:
        domain: Domain name to assess (e.g., 'example.com')
    """
    print(f"🔍 Assessing domain: {domain}")

    # Create configuration
    config = ProbeConfig(
        timeout=30,
        retry_count=2,
        cache_enabled=True,
        max_concurrent=5
    )

    # Create command
    command = AssessDomainCommand(
        domain_name=domain,
        probe_config=config
    )

    # Execute assessment
    use_case = create_assessment_use_case()
    result = await use_case.execute(command)

    # Display results
    print(f"\n📊 Assessment Results for {result.domain.name}")
    print(f"Overall Score: {result.overall_score:.2f}")
    print(f"Compliance Level: {result.compliance_level.value}")
    print(f"Timestamp: {result.timestamp}")

    print("\n🔬 Probe Results:")
    for probe_result in result.probe_results:
        status = "✅" if probe_result.is_successful else "❌"
        print(f"  {status} {probe_result.probe_id}: {probe_result.score:.2f}")
        if probe_result.error:
            print(f"    Error: {probe_result.error}")


async def assess_multiple_domains(domains: list[str]) -> None:
    """
    Assess multiple domains and compare results.

    Args:
        domains: List of domain names to assess
    """
    print(f"🔍 Assessing {len(domains)} domains...")

    config = ProbeConfig(timeout=20, max_concurrent=3)
    use_case = create_assessment_use_case()

    results = []
    for domain in domains:
        try:
            command = AssessDomainCommand(domain_name=domain, probe_config=config)
            result = await use_case.execute(command)
            results.append(result)
            print(f"✅ {domain}: {result.overall_score:.2f}")
        except Exception as e:
            print(f"❌ {domain}: Failed - {e}")

    # Summary
    if results:
        avg_score = sum(r.overall_score for r in results) / len(results)
        print(f"\n📈 Summary: {len(results)} domains assessed")
        print(f"Average score: {avg_score:.2f}")

        # Best and worst
        best = max(results, key=lambda r: r.overall_score)
        worst = min(results, key=lambda r: r.overall_score)
        print(f"Best: {best.domain.name} ({best.overall_score:.2f})")
        print(f"Worst: {worst.domain.name} ({worst.overall_score:.2f})")


def demonstrate_domain_validation():
    """
    Demonstrate domain validation service.

    Shows how the domain validation service works with various inputs.
    """
    print("🔍 Domain Validation Examples")

    validation_service = DomainValidationService()

    test_cases = [
        "example.com",
        "https://www.google.com/path",
        "sub.domain.co.uk",
        "invalid..domain",
        "very-long-domain-name-that-might-be-problematic.com",
        "localhost",
        "192.168.1.1",
        ""
    ]

    for test_domain in test_cases:
        try:
            clean_domain = validation_service.sanitize_domain_name(test_domain)
            print(f"  '{test_domain}' → '{clean_domain}'")
        except Exception as e:
            print(f"  '{test_domain}' → Error: {e}")


async def main():
    """
    Main demonstration function.

    This function shows various ways to use DQIX:
    1. Single domain assessment
    2. Multiple domain assessment
    3. Domain validation examples
    """
    print("🚀 DQIX Domain Assessment Demo")
    print("=" * 50)

    # 1. Single domain assessment
    print("\n1️⃣ Single Domain Assessment")
    await assess_single_domain("example.com")

    # 2. Multiple domain assessment
    print("\n2️⃣ Multiple Domain Assessment")
    test_domains = [
        "google.com",
        "github.com",
        "stackoverflow.com"
    ]
    await assess_multiple_domains(test_domains)

    # 3. Domain validation examples
    print("\n3️⃣ Domain Validation Examples")
    demonstrate_domain_validation()

    print("\n✨ Demo completed!")
    print("\nTo use DQIX in your own code:")
    print("1. Import the required modules")
    print("2. Create a use case with create_assessment_use_case()")
    print("3. Create a command with your domain and config")
    print("4. Execute with await use_case.execute(command)")


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())
