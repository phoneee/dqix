#!/usr/bin/env python3
"""
Technical Details Demo - DQIX Enhanced Probe Analysis

This script demonstrates the comprehensive technical details
provided by the enhanced DQIX probes.

Usage:
    python examples/technical_details_demo.py
"""

import asyncio
import json
from typing import Dict, Any

from dqix.application.use_cases import AssessDomainCommand, AssessDomainUseCase
from dqix.domain.entities import ProbeConfig
from dqix.domain.services import AssessmentService, DomainValidationService, ScoringService
from dqix.infrastructure.repositories import FileAssessmentRepository, InMemoryCacheRepository
from dqix.infrastructure.probes import ProbeExecutor


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_subsection(title: str) -> None:
    """Print a formatted subsection header."""
    print(f"\n{'-'*40}")
    print(f"  {title}")
    print(f"{'-'*40}")


def format_technical_details(details: Dict[str, Any], max_depth: int = 3) -> str:
    """Format technical details for display with controlled depth."""
    def format_value(value: Any, depth: int = 0) -> str:
        if depth >= max_depth:
            return str(type(value).__name__)
        
        if isinstance(value, dict):
            if not value:
                return "{}"
            formatted_items = []
            for k, v in list(value.items())[:5]:  # Limit to first 5 items
                formatted_v = format_value(v, depth + 1)
                formatted_items.append(f"  {'  ' * depth}{k}: {formatted_v}")
            if len(value) > 5:
                formatted_items.append(f"  {'  ' * depth}... ({len(value) - 5} more items)")
            return "{\n" + "\n".join(formatted_items) + f"\n{'  ' * depth}}}"
        elif isinstance(value, list):
            if not value:
                return "[]"
            if len(value) <= 3:
                return str(value)
            return f"[{value[0]}, {value[1]}, ... ({len(value)} total)]"
        elif isinstance(value, str) and len(value) > 100:
            return f'"{value[:97]}..."'
        else:
            return str(value)
    
    return format_value(details)


async def demonstrate_technical_details():
    """Demonstrate enhanced technical details from DQIX probes."""
    print_section("DQIX Enhanced Technical Details Demonstration")
    
    # Create use case with dependencies
    probe_executor = ProbeExecutor()
    assessment_repo = FileAssessmentRepository()
    cache_repo = InMemoryCacheRepository()
    scoring_service = ScoringService()
    validation_service = DomainValidationService()
    assessment_service = AssessmentService(scoring_service, validation_service)
    
    use_case = AssessDomainUseCase(
        probe_executor=probe_executor,
        assessment_service=assessment_service,
        validation_service=validation_service,
        assessment_repo=assessment_repo,
        cache_repo=cache_repo
    )
    
    # Test domains with different characteristics
    test_domains = [
        "example.com",    # Well-configured domain
        "google.com",     # High-security domain
    ]
    
    for domain_name in test_domains:
        print_section(f"Technical Analysis for {domain_name}")
        
        try:
            config = ProbeConfig(timeout=30, cache_enabled=False, max_concurrent=10)
            command = AssessDomainCommand(domain_name=domain_name, probe_config=config)
            
            result = await use_case.execute(command)
            
            print(f"Overall Score: {result.overall_score:.2f}/100")
            print(f"Compliance Level: {result.compliance_level.value}")
            print(f"Assessment Time: {result.timestamp}")
            
            # Display detailed technical information for each probe
            for probe_result in result.probe_results:
                print_subsection(f"{probe_result.probe_id.upper()} Probe Analysis")
                
                print(f"Score: {probe_result.score:.2f}/100")
                print(f"Status: {'✅ Success' if probe_result.is_successful else '❌ Failed'}")
                print(f"Category: {probe_result.category.value}")
                
                if probe_result.error:
                    print(f"Error: {probe_result.error}")
                    continue
                
                if not probe_result.details:
                    print("No technical details available")
                    continue
                
                # Show enhanced technical details
                if probe_result.probe_id == "tls":
                    show_tls_technical_details(probe_result.details)
                elif probe_result.probe_id == "dns":
                    show_dns_technical_details(probe_result.details)
                elif probe_result.probe_id == "security_headers":
                    show_security_headers_technical_details(probe_result.details)
                else:
                    print("Technical Details:")
                    print(format_technical_details(probe_result.details))
        
        except Exception as e:
            print(f"❌ Error assessing {domain_name}: {e}")


def show_tls_technical_details(details: Dict[str, Any]) -> None:
    """Display TLS-specific technical details."""
    print("🔒 TLS/SSL Technical Analysis:")
    
    # Connection Analysis
    if "connection_analysis" in details:
        conn = details["connection_analysis"]
        print(f"  Protocol Version: {conn.get('protocol_version', 'Unknown')}")
        cipher = conn.get('cipher_suite', [])
        if cipher:
            print(f"  Cipher Suite: {cipher[0] if isinstance(cipher, list) else cipher}")
        print(f"  Compression: {conn.get('compression', 'None')}")
        
        # Supported versions
        if "supported_versions" in conn:
            print("  Supported TLS Versions:")
            for version, info in conn["supported_versions"].items():
                status = "✅" if info.get("supported") else "❌"
                print(f"    {version}: {status}")
    
    # Certificate Analysis
    if "certificate_analysis" in details:
        cert = details["certificate_analysis"]
        print("  Certificate Information:")
        
        if "subject" in cert:
            subject = cert["subject"]
            cn = subject.get("commonName", "Unknown")
            print(f"    Subject: {cn}")
        
        if "validity" in cert:
            validity = cert["validity"]
            print(f"    Expires: {validity.get('not_after', 'Unknown')}")
            print(f"    Days until expiry: {validity.get('days_until_expiry', 'Unknown')}")
            print(f"    Expired: {'Yes' if validity.get('is_expired') else 'No'}")
        
        if "public_key" in cert:
            pk = cert["public_key"]
            print(f"    Key Algorithm: {pk.get('algorithm', 'Unknown')}")
            print(f"    Key Size: {pk.get('size_bits', 'Unknown')} bits")
        
        if "signature" in cert:
            sig = cert["signature"]
            print(f"    Signature Algorithm: {sig.get('algorithm', 'Unknown')}")
            print(f"    Hash Algorithm: {sig.get('hash_algorithm', 'Unknown')}")
    
    # Security Assessment
    if "security_assessment" in details:
        security = details["security_assessment"]
        print("  Security Assessment:")
        
        if "vulnerabilities" in security:
            vuln_count = len(security["vulnerabilities"])
            print(f"    Vulnerabilities Found: {vuln_count}")
            if vuln_count > 0:
                for vuln in security["vulnerabilities"][:3]:  # Show first 3
                    print(f"      - {vuln}")
        
        if "overall_security_level" in security:
            level = security["overall_security_level"]
            print(f"    Security Level: {level}")
    
    # Technical Summary
    if "technical_summary" in details:
        summary = details["technical_summary"]
        print("  Technical Summary:")
        print(f"    Modern TLS: {'Yes' if summary.get('modern_tls') else 'No'}")
        print(f"    Secure Cipher: {'Yes' if summary.get('secure_cipher') else 'No'}")
        print(f"    Certificate Valid: {'Yes' if summary.get('certificate_valid') else 'No'}")
        print(f"    Security Score: {summary.get('security_score', 0):.1f}/100")


def show_dns_technical_details(details: Dict[str, Any]) -> None:
    """Display DNS-specific technical details."""
    print("🌐 DNS Technical Analysis:")
    
    # DNS Records Analysis
    if "dns_records_analysis" in details:
        dns_records = details["dns_records_analysis"]
        
        if "record_counts" in dns_records:
            counts = dns_records["record_counts"]
            print("  DNS Records:")
            for record_type, count in counts.items():
                if count > 0:
                    print(f"    {record_type.replace('_', ' ').title()}: {count}")
        
        if "ip_analysis" in dns_records:
            ip_analysis = dns_records["ip_analysis"]
            ipv4_count = ip_analysis.get("ipv4_addresses", 0)
            ipv6_count = ip_analysis.get("ipv6_addresses", 0)
            print(f"  IP Addresses: IPv4={ipv4_count}, IPv6={ipv6_count}")
    
    # Mail Security Analysis
    if "mail_security_analysis" in details:
        mail = details["mail_security_analysis"]
        print("  Mail Security:")
        print(f"    Security Score: {mail.get('security_score', 0)}/100")
        
        # SPF Analysis
        if "spf_analysis" in mail:
            spf = mail["spf_analysis"]
            print(f"    SPF Record: {'Found' if spf.get('record_found') else 'Not Found'}")
            if spf.get("record_found"):
                print(f"      Security Level: {spf.get('security_level', 'Unknown')}")
        
        # DMARC Analysis
        if "dmarc_analysis" in mail:
            dmarc = mail["dmarc_analysis"]
            print(f"    DMARC Record: {'Found' if dmarc.get('record_found') else 'Not Found'}")
            if dmarc.get("record_found"):
                print(f"      Policy: {dmarc.get('policy', 'Unknown')}")
                print(f"      Security Level: {dmarc.get('security_level', 'Unknown')}")
        
        # DKIM Analysis
        if "dkim_analysis" in mail:
            dkim = mail["dkim_analysis"]
            selectors_found = len(dkim.get("selectors_found", []))
            print(f"    DKIM Selectors: {selectors_found} found")
    
    # Security Features Analysis
    if "security_features_analysis" in details:
        security = details["security_features_analysis"]
        print("  Security Features:")
        caa_count = len(security.get("caa_records", []))
        print(f"    CAA Records: {caa_count}")
        print(f"    DNSSEC: {'Enabled' if security.get('dnssec_enabled') else 'Disabled'}")
        print(f"    Security Score: {security.get('security_score', 0)}/100")
    
    # Technical Assessment
    if "technical_assessment" in details:
        assessment = details["technical_assessment"]
        print("  Technical Assessment:")
        print(f"    IPv6 Support: {'Yes' if assessment.get('ipv6_support') else 'No'}")
        print(f"    Mail Configured: {'Yes' if assessment.get('mail_configured') else 'No'}")
        print(f"    Overall Health: {assessment.get('overall_health', 'Unknown')}")
        
        if "vulnerabilities" in assessment:
            vuln_count = len(assessment["vulnerabilities"])
            print(f"    Vulnerabilities: {vuln_count}")


def show_security_headers_technical_details(details: Dict[str, Any]) -> None:
    """Display Security Headers technical details."""
    print("🛡️ Security Headers Analysis:")
    
    headers = [
        ("strict-transport-security", "HSTS"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-xss-protection", "X-XSS-Protection"),
        ("content-security-policy", "Content Security Policy"),
        ("referrer-policy", "Referrer Policy"),
    ]
    
    for header_key, header_name in headers:
        value = details.get(header_key)
        status = "✅ Present" if value else "❌ Missing"
        print(f"  {header_name}: {status}")
        if value:
            print(f"    Value: {value}")


if __name__ == "__main__":
    print("Starting DQIX Technical Details Demonstration...")
    try:
        asyncio.run(demonstrate_technical_details())
        print("\n" + "="*60)
        print("  Technical Details Demonstration Complete")
        print("="*60)
    except KeyboardInterrupt:
        print("\n❌ Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc() 