#!/usr/bin/env python3
"""
Probe Demo - DQIX Individual Probe Testing

This example demonstrates how to test individual probes
and understand their scoring mechanisms.

Usage:
    python examples/probe_demo.py
"""

import asyncio

from dqix.domain.entities import Domain, ProbeCategory, ProbeConfig
from dqix.infrastructure.probes.implementations import get_all_probes, get_probes_by_category


async def test_single_probe(probe, domain: Domain, config: ProbeConfig) -> None:
    """
    Test a single probe and display detailed results.

    Args:
        probe: The probe instance to test
        domain: Domain to test against
        config: Probe configuration
    """
    print(f"\n🔬 Testing {probe.probe_id} probe")
    print(f"   Category: {probe.category.value}")
    print(f"   Domain: {domain.name}")

    try:
        result = await probe.check(domain, config)

        print(f"   Score: {result.score:.2f}")
        print(f"   Status: {'✅ Success' if result.is_successful else '❌ Failed'}")

        if result.error:
            print(f"   Error: {result.error}")

        # Show key details (limit to avoid clutter)
        if result.details:
            print("   Key Details:")
            for key, value in list(result.details.items())[:3]:  # Show first 3 items
                if isinstance(value, (str, int, float, bool)):
                    print(f"     {key}: {value}")
                elif isinstance(value, list) and len(value) <= 3:
                    print(f"     {key}: {value}")
                else:
                    print(f"     {key}: [complex data]")

    except Exception as e:
        print(f"   ❌ Exception: {e}")


async def test_all_probes_for_domain(domain_name: str) -> None:
    """
    Test all available probes against a single domain.

    Args:
        domain_name: Domain name to test (e.g., 'example.com')
    """
    print(f"🎯 Testing all probes for: {domain_name}")

    domain = Domain(name=domain_name)
    config = ProbeConfig(timeout=15, max_concurrent=1)  # Sequential for demo

    probes = get_all_probes()

    for probe in probes:
        await test_single_probe(probe, domain, config)

    print(f"\n✅ Completed testing {len(probes)} probes")


async def test_probes_by_category(domain_name: str, category: ProbeCategory) -> None:
    """
    Test probes of a specific category.

    Args:
        domain_name: Domain name to test
        category: Probe category to test
    """
    print(f"🔍 Testing {category.value} probes for: {domain_name}")

    domain = Domain(name=domain_name)
    config = ProbeConfig(timeout=20)

    probes = get_probes_by_category(category)

    if not probes:
        print(f"   No probes found for category: {category.value}")
        return

    for probe in probes:
        await test_single_probe(probe, domain, config)


async def compare_domains(domain_names: list) -> None:
    """
    Compare probe results across multiple domains.

    Args:
        domain_names: List of domain names to compare
    """
    print(f"🔍 Comparing {len(domain_names)} domains across all probes")

    config = ProbeConfig(timeout=10, max_concurrent=2)
    probes = get_all_probes()

    # Store results for comparison
    results = {}

    for domain_name in domain_names:
        print(f"\n📊 Assessing {domain_name}...")
        domain = Domain(name=domain_name)
        domain_results = {}

        for probe in probes:
            try:
                result = await probe.check(domain, config)
                domain_results[probe.probe_id] = result.score
                print(f"   {probe.probe_id}: {result.score:.2f}")
            except Exception as e:
                domain_results[probe.probe_id] = 0.0
                print(f"   {probe.probe_id}: Failed ({e})")

        results[domain_name] = domain_results

    # Display comparison table
    print("\n📈 Comparison Summary")
    print("=" * 60)

    # Header
    header = "Domain".ljust(20)
    for probe in probes:
        header += f"{probe.probe_id}".ljust(12)
    print(header)
    print("-" * 60)

    # Results
    for domain_name, domain_results in results.items():
        row = domain_name.ljust(20)
        for probe in probes:
            score = domain_results.get(probe.probe_id, 0.0)
            row += f"{score:.2f}".ljust(12)
        print(row)


def demonstrate_probe_configuration():
    """
    Demonstrate different probe configurations.
    """
    print("⚙️ Probe Configuration Examples")
    print("=" * 40)

    configs = [
        ("Fast", ProbeConfig(timeout=5, retry_count=1, max_concurrent=10)),
        ("Standard", ProbeConfig(timeout=30, retry_count=3, max_concurrent=5)),
        ("Thorough", ProbeConfig(timeout=60, retry_count=5, max_concurrent=2)),
        ("Cache Disabled", ProbeConfig(timeout=30, cache_enabled=False)),
    ]

    for name, config in configs:
        print(f"\n{name} Configuration:")
        print(f"  Timeout: {config.timeout}s")
        print(f"  Retry Count: {config.retry_count}")
        print(f"  Max Concurrent: {config.max_concurrent}")
        print(f"  Cache Enabled: {config.cache_enabled}")


async def demonstrate_error_handling(domain_name: str) -> None:
    """
    Demonstrate how probes handle various error conditions.

    Args:
        domain_name: Domain that might have issues
    """
    print(f"🚨 Error Handling Demo with: {domain_name}")

    domain = Domain(name=domain_name)

    # Test with very short timeout to trigger timeouts
    config = ProbeConfig(timeout=1, retry_count=1)

    probes = get_all_probes()

    for probe in probes:
        print(f"\n⏱️ Testing {probe.probe_id} with 1s timeout")
        try:
            result = await probe.check(domain, config)
            if result.error:
                print(f"   Handled Error: {result.error}")
            else:
                print(f"   Succeeded: {result.score:.2f}")
        except Exception as e:
            print(f"   Unhandled Exception: {e}")


async def main():
    """
    Main demonstration function.

    Shows various ways to test and understand DQIX probes:
    1. Test all probes for a single domain
    2. Test probes by category
    3. Compare multiple domains
    4. Configuration examples
    5. Error handling demonstration
    """
    print("🔬 DQIX Probe Testing Demo")
    print("=" * 50)

    # 1. Test all probes for a single domain
    print("\n1️⃣ All Probes Test")
    await test_all_probes_for_domain("google.com")

    # 2. Test by category
    print("\n2️⃣ Security Probes Test")
    await test_probes_by_category("github.com", ProbeCategory.SECURITY)

    # 3. Compare multiple domains
    print("\n3️⃣ Domain Comparison")
    comparison_domains = ["google.com", "example.com", "github.com"]
    await compare_domains(comparison_domains)

    # 4. Configuration examples
    print("\n4️⃣ Configuration Examples")
    demonstrate_probe_configuration()

    # 5. Error handling
    print("\n5️⃣ Error Handling Demo")
    await demonstrate_error_handling("nonexistent-domain-12345.com")

    print("\n✨ Probe demo completed!")
    print("\nKey Takeaways:")
    print("• Each probe tests a specific aspect of domain quality")
    print("• Scores range from 0.0 (worst) to 1.0 (best)")
    print("• Probes handle errors gracefully and return meaningful results")
    print("• Configuration can be tuned for different use cases")
    print("• Use ProbeCategory to filter probes by type")


if __name__ == "__main__":
    asyncio.run(main())
