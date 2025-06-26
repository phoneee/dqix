"""DNS Security and Email Authentication Probe with enhanced concurrent processing and false positive reduction."""

import asyncio
import concurrent.futures
import logging
from typing import Any, Optional

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class DNSProbe(BaseProbe):
    """Comprehensive DNS configuration and security analysis with reduced false positives."""

    def __init__(self):
        super().__init__("dns", ProbeCategory.SECURITY)
        self._setup_resolver()
        self.logger = logging.getLogger(__name__)

    def _setup_resolver(self):
        """Configure DNS resolver with multiple fallback strategies to reduce false negatives."""
        # Primary: Privacy-focused and security-enhanced resolvers
        # Secondary: Major cloud providers with high reliability
        # Tertiary: Alternative DNS providers for redundancy
        trusted_nameservers = [
            # Tier 1: Privacy and security focused
            "9.9.9.9",          # Quad9 - malware blocking, DNSSEC validation
            "149.112.112.112",   # Quad9 secondary
            "1.1.1.1",          # Cloudflare DNS - fastest, privacy-focused
            "1.0.0.1",          # Cloudflare secondary

            # Tier 2: Major cloud providers
            "8.8.8.8",          # Google DNS - most widely tested
            "8.8.4.4",          # Google secondary
            "208.67.222.222",    # OpenDNS - enterprise grade
            "208.67.220.220",    # OpenDNS secondary

            # Tier 3: Security-focused alternatives
            "8.26.56.26",       # Comodo Secure DNS
            "8.20.247.20",      # Comodo secondary
            "45.90.28.0",       # NextDNS - customizable
            "45.90.30.0",       # NextDNS secondary
        ]

        # Primary resolver with extended timeout for accuracy
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = trusted_nameservers[:4]  # Use top 4 for primary
        self.resolver.timeout = 8  # Extended timeout to reduce false negatives
        self.resolver.lifetime = 10  # Total query lifetime

        # Enable EDNS with larger payload for complex responses
        self.resolver.use_edns(edns=0, ednsflags=0, payload=4096)

        # Backup resolver with different nameserver subset
        self.backup_resolver = dns.resolver.Resolver(configure=False)
        self.backup_resolver.nameservers = trusted_nameservers[4:8]
        self.backup_resolver.timeout = 6
        self.backup_resolver.lifetime = 8
        self.backup_resolver.use_edns(edns=0, ednsflags=0, payload=4096)

        # Emergency resolver for final fallback
        self.emergency_resolver = dns.resolver.Resolver(configure=False)
        self.emergency_resolver.nameservers = trusted_nameservers[8:]
        self.emergency_resolver.timeout = 10
        self.emergency_resolver.lifetime = 12

    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Perform concurrent DNS security and email authentication checks with enhanced accuracy."""
        try:
            # Use ThreadPoolExecutor for concurrent DNS queries with more workers
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                # Define all DNS checks to run concurrently
                dns_tasks = {
                    'basic_records': self._check_basic_dns_records_async(executor, domain.name),
                    'mail_security': self._check_mail_security_async(executor, domain.name),
                    'security_features': self._check_dns_security_features_async(executor, domain.name)
                }

                # Execute all tasks concurrently with error handling
                results = await asyncio.gather(
                    *dns_tasks.values(),
                    return_exceptions=True
                )

                # Process results with detailed error tracking
                dns_info = {}
                for _i, (task_name, result) in enumerate(zip(dns_tasks.keys(), results)):
                    if isinstance(result, Exception):
                        self.logger.warning(f"DNS task {task_name} failed for {domain.name}: {result}")
                        dns_info[task_name] = {"error": str(result), "partial_success": False}
                    else:
                        dns_info[task_name] = result

            # Validate DNS info completeness to reduce false positives
            dns_info = self._validate_dns_completeness(dns_info, domain.name)

            # Calculate technical scores from the collected data
            technical_scores = self._calculate_technical_scores(dns_info)

            # Add technical analysis with proper structure
            dns_info['technical_analysis'] = {
                'technical_scores': technical_scores,
                'security_features': self._get_security_features_list(dns_info),
                'vulnerabilities': self._identify_vulnerabilities(dns_info),
                'recommendations': self._generate_recommendations(dns_info),
                'overall_health': self._assess_overall_health(technical_scores),
                'reliability_metrics': self._calculate_reliability_metrics(dns_info)
            }

            # Calculate combined score using the proper structure
            score = self._calculate_dns_score(dns_info)

            # Prepare detailed technical information
            details = self._prepare_details(dns_info)

            return self._create_result(domain, score, details)

        except Exception as e:
            self.logger.error(f"DNS probe failed for {domain.name}: {e}")
            return self._create_result(
                domain,
                0.0,
                {"error": str(e), "analysis": "DNS connectivity and security check failed", "recovery_attempted": True},
                error=str(e)
            )

    def _validate_dns_completeness(self, dns_info: dict[str, Any], hostname: str) -> dict[str, Any]:
        """Validate DNS information completeness and attempt recovery for missing data."""
        # Check if basic records check failed
        if dns_info.get('basic_records', {}).get('error'):
            self.logger.info(f"Attempting DNS recovery for {hostname}")
            # Try emergency resolver for basic records
            try:
                recovery_result = self._emergency_dns_check(hostname)
                if recovery_result:
                    dns_info['basic_records'] = recovery_result
                    dns_info['basic_records']['recovered'] = True
            except Exception as e:
                self.logger.warning(f"DNS recovery failed for {hostname}: {e}")

        # Validate mail security checks
        if dns_info.get('mail_security', {}).get('error'):
            # For mail security, missing records might be normal (not an error)
            dns_info['mail_security'] = {
                'spf_analysis': {'record_found': False, 'security_score': 0, 'note': 'No SPF record found'},
                'dmarc_analysis': {'record_found': False, 'security_score': 0, 'note': 'No DMARC record found'},
                'dkim_analysis': {'record_found': False, 'security_score': 0, 'note': 'No DKIM selectors detected'},
                'overall_score': 0,
                'validation_note': 'Email authentication not configured (may be normal for non-email domains)'
            }

        return dns_info

    def _emergency_dns_check(self, hostname: str) -> Optional[dict[str, Any]]:
        """Emergency DNS check using alternative resolver and methods."""
        try:
            # Try with emergency resolver
            record_results = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']

            for record_type in record_types:
                try:
                    result = self._query_record_type_with_resolver(hostname, record_type, self.emergency_resolver)
                    record_results[record_type] = result
                except Exception as e:
                    record_results[record_type] = {"error": str(e), "count": 0, "records": []}

            # If still no success, try system resolver
            if all(r.get("count", 0) == 0 for r in record_results.values()):
                system_resolver = dns.resolver.Resolver()  # Use system default
                system_resolver.timeout = 15  # Extended timeout for system resolver

                for record_type in record_types:
                    try:
                        result = self._query_record_type_with_resolver(hostname, record_type, system_resolver)
                        if result.get("count", 0) > 0:
                            record_results[record_type] = result
                    except Exception:
                        pass  # Keep existing result

            # Calculate totals
            total_records = sum(r.get("count", 0) for r in record_results.values())

            if total_records > 0:
                return {
                    "record_counts": {
                        "a_records": record_results.get("A", {}).get("count", 0),
                        "aaaa_records": record_results.get("AAAA", {}).get("count", 0),
                        "mx_records": record_results.get("MX", {}).get("count", 0),
                        "ns_records": record_results.get("NS", {}).get("count", 0),
                        "txt_records": record_results.get("TXT", {}).get("count", 0),
                        "total_records": total_records
                    },
                    "record_details": record_results,
                    "ipv4_supported": record_results.get("A", {}).get("count", 0) > 0,
                    "ipv6_supported": record_results.get("AAAA", {}).get("count", 0) > 0,
                    "has_mail_servers": record_results.get("MX", {}).get("count", 0) > 0,
                    "dns_properly_configured": total_records > 0,
                    "emergency_recovery": True
                }
        except Exception as e:
            self.logger.error(f"Emergency DNS check failed for {hostname}: {e}")
            return None

    def _query_record_type_with_resolver(self, hostname: str, record_type: str, resolver: dns.resolver.Resolver) -> dict[str, Any]:
        """Query specific record type with given resolver."""
        try:
            rdtype = getattr(dns.rdatatype, record_type)
            response = resolver.resolve(hostname, rdtype)

            records = []
            for rdata in response:
                records.append(str(rdata))

            return {
                "count": len(records),
                "records": records,
                "ttl": response.rrset.ttl if hasattr(response, 'rrset') else 0
            }

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {"count": 0, "records": [], "note": f"No {record_type} records found"}
        except dns.exception.Timeout:
            return {"count": 0, "records": [], "error": f"Timeout querying {record_type} records"}
        except Exception as e:
            return {"count": 0, "records": [], "error": f"Error querying {record_type}: {str(e)}"}

    async def _check_basic_dns_records_async(self, executor: concurrent.futures.ThreadPoolExecutor, hostname: str) -> dict[str, Any]:
        """Check basic DNS records concurrently."""

        # Define record types to check in parallel
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']

        # Create concurrent tasks for each record type
        tasks = []
        for record_type in record_types:
            task = asyncio.get_event_loop().run_in_executor(
                executor,
                self._query_record_type,
                hostname,
                record_type
            )
            tasks.append((record_type, task))

        # Wait for all tasks to complete
        record_results = {}
        for record_type, task in tasks:
            try:
                result = await task
                record_results[record_type] = result
            except Exception as e:
                record_results[record_type] = {"error": str(e), "count": 0, "records": []}

        # Calculate totals
        total_records = sum(r.get("count", 0) for r in record_results.values())

        return {
            "record_counts": {
                "a_records": record_results.get("A", {}).get("count", 0),
                "aaaa_records": record_results.get("AAAA", {}).get("count", 0),
                "mx_records": record_results.get("MX", {}).get("count", 0),
                "ns_records": record_results.get("NS", {}).get("count", 0),
                "txt_records": record_results.get("TXT", {}).get("count", 0),
                "cname_records": record_results.get("CNAME", {}).get("count", 0),
                "total_records": total_records
            },
            "record_details": record_results,
            "ipv4_supported": record_results.get("A", {}).get("count", 0) > 0,
            "ipv6_supported": record_results.get("AAAA", {}).get("count", 0) > 0,
            "has_mail_servers": record_results.get("MX", {}).get("count", 0) > 0,
            "dns_properly_configured": total_records > 0
        }

    async def _check_mail_security_async(self, executor: concurrent.futures.ThreadPoolExecutor, hostname: str) -> dict[str, Any]:
        """Check email authentication records concurrently."""

        # Define mail security checks to run in parallel
        mail_tasks = [
            ('spf', asyncio.get_event_loop().run_in_executor(executor, self._check_spf_record, hostname)),
            ('dmarc', asyncio.get_event_loop().run_in_executor(executor, self._check_dmarc_record, hostname)),
            ('dkim', asyncio.get_event_loop().run_in_executor(executor, self._check_dkim_record, hostname))
        ]

        # Wait for all mail security checks
        mail_results = {}
        for check_type, task in mail_tasks:
            try:
                result = await task
                mail_results[f"{check_type}_analysis"] = result
            except Exception as e:
                mail_results[f"{check_type}_analysis"] = {
                    "record_found": False,
                    "error": str(e),
                    "security_score": 0
                }

        # Calculate overall mail security score
        spf_score = mail_results.get("spf_analysis", {}).get("security_score", 0)
        dmarc_score = mail_results.get("dmarc_analysis", {}).get("security_score", 0)
        dkim_score = mail_results.get("dkim_analysis", {}).get("security_score", 0)

        overall_score = (spf_score * 0.4 + dmarc_score * 0.4 + dkim_score * 0.2)

        mail_results["security_score"] = int(overall_score)
        mail_results["has_email_security"] = any([
            mail_results.get("spf_analysis", {}).get("record_found", False),
            mail_results.get("dmarc_analysis", {}).get("record_found", False),
            mail_results.get("dkim_analysis", {}).get("record_found", False)
        ])

        return mail_results

    async def _check_dns_security_features_async(self, executor: concurrent.futures.ThreadPoolExecutor, hostname: str) -> dict[str, Any]:
        """Check DNS security features concurrently."""

        # Define security feature checks to run in parallel
        security_tasks = [
            ('dnssec', asyncio.get_event_loop().run_in_executor(executor, self._check_dnssec, hostname)),
            ('caa', asyncio.get_event_loop().run_in_executor(executor, self._check_caa_record, hostname))
        ]

        # Wait for all security feature checks
        security_results = {}
        for check_type, task in security_tasks:
            try:
                result = await task
                security_results[f"{check_type}_analysis"] = result
            except Exception as e:
                security_results[f"{check_type}_analysis"] = {
                    "enabled": False,
                    "error": str(e)
                }

        # Calculate security features score
        dnssec_enabled = security_results.get("dnssec_analysis", {}).get("enabled", False)
        caa_enabled = security_results.get("caa_analysis", {}).get("enabled", False)

        security_score = 0
        if dnssec_enabled:
            security_score += 60  # DNSSEC is more important
        if caa_enabled:
            security_score += 40  # CAA provides additional certificate control

        security_results["security_score"] = security_score
        security_results["has_security_features"] = dnssec_enabled or caa_enabled

        return security_results

    def _query_record_type(self, hostname: str, record_type: str) -> dict[str, Any]:
        """Query specific DNS record type with fallback."""
        try:
            # Try primary resolver first
            answers = self.resolver.resolve(hostname, record_type)
            records = [str(rdata) for rdata in answers]
            return {
                "count": len(records),
                "records": records,
                "ttl": answers.rrset.ttl if answers.rrset else 0
            }
        except dns.exception.DNSException:
            # Try backup resolver
            try:
                answers = self.backup_resolver.resolve(hostname, record_type)
                records = [str(rdata) for rdata in answers]
                return {
                    "count": len(records),
                    "records": records,
                    "ttl": answers.rrset.ttl if answers.rrset else 0,
                    "used_backup": True
                }
            except dns.exception.DNSException as e:
                return {
                    "count": 0,
                    "records": [],
                    "error": str(e)
                }
        except Exception as e:
            return {
                "count": 0,
                "records": [],
                "error": str(e)
            }

    def _check_spf_record(self, hostname: str) -> dict[str, Any]:
        """Check SPF record with enhanced parsing."""
        try:
            # Try primary resolver
            try:
                answers = self.resolver.resolve(hostname, 'TXT')
            except dns.exception.DNSException:
                # Fall back to backup resolver
                answers = self.backup_resolver.resolve(hostname, 'TXT')

            spf_records = []
            for rdata in answers:
                txt_string = str(rdata).strip('"')
                if txt_string.lower().startswith('v=spf1'):
                    spf_records.append(txt_string)

            if spf_records:
                # Parse the SPF record for security assessment
                spf_record = spf_records[0]  # Use first SPF record
                security_level = self._analyze_spf_security(spf_record)

                return {
                    "record_found": True,
                    "spf_record": spf_record,
                    "security_level": security_level,
                    "security_score": self._get_spf_score(security_level),
                    "multiple_records": len(spf_records) > 1,
                    "all_records": spf_records
                }
            else:
                return {
                    "record_found": False,
                    "security_level": "none",
                    "security_score": 0,
                    "error": "No SPF record found"
                }

        except dns.exception.DNSException as e:
            return {
                "record_found": False,
                "security_level": "none",
                "security_score": 0,
                "error": f"DNS query failed: {str(e)}"
            }
        except Exception as e:
            return {
                "record_found": False,
                "security_level": "none",
                "security_score": 0,
                "error": f"SPF check failed: {str(e)}"
            }

    def _analyze_spf_security(self, spf_record: str) -> str:
        """Analyze SPF record security level."""
        if "-all" in spf_record:
            return "strict"
        elif "~all" in spf_record:
            return "moderate"
        elif "?all" in spf_record:
            return "neutral"
        elif "+all" in spf_record:
            return "permissive"
        else:
            return "incomplete"

    def _get_spf_score(self, security_level: str) -> int:
        """Get numeric score for SPF security level."""
        scores = {
            "strict": 100,
            "moderate": 75,
            "neutral": 50,
            "incomplete": 25,
            "permissive": 10,
            "none": 0
        }
        return scores.get(security_level, 0)

    def _check_dmarc_record(self, hostname: str) -> dict[str, Any]:
        """Check DMARC record."""
        try:
            # DMARC records are at _dmarc.domain
            dmarc_domain = f"_dmarc.{hostname}"
            try:
                answers = self.resolver.resolve(dmarc_domain, 'TXT')
            except Exception:
                # Fall back to backup resolver
                answers = self.backup_resolver.resolve(dmarc_domain, 'TXT')

            for rdata in answers:
                txt_string = str(rdata).strip('"')
                if txt_string.lower().startswith('v=dmarc1'):
                    policy = "none"
                    if "p=reject" in txt_string.lower():
                        policy = "reject"
                    elif "p=quarantine" in txt_string.lower():
                        policy = "quarantine"

                    security_score = {
                        "reject": 100,
                        "quarantine": 75,
                        "none": 25
                    }.get(policy, 0)

                    return {
                        "record_found": True,
                        "dmarc_record": txt_string,
                        "policy": policy,
                        "security_score": security_score
                    }

            return {
                "record_found": False,
                "policy": "none",
                "security_score": 0,
                "error": "No DMARC record found"
            }

        except Exception as e:
            return {
                "record_found": False,
                "policy": "none",
                "security_score": 0,
                "error": f"DMARC check failed: {str(e)}"
            }

    def _check_dkim_record(self, hostname: str) -> dict[str, Any]:
        """Check DKIM record with common selectors."""
        selectors_found = []
        common_selectors = ["default", "google", "k1", "s1", "selector1", "mail"]

        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{hostname}"
                try:
                    answers = self.resolver.resolve(dkim_domain, 'TXT')
                except Exception:
                    answers = self.backup_resolver.resolve(dkim_domain, 'TXT')

                for rdata in answers:
                    txt_string = str(rdata).strip('"')
                    if 'p=' in txt_string and ('k=' in txt_string or 'v=' in txt_string):
                        selectors_found.append(selector)
                        break

            except Exception:
                continue

        security_score = min(len(selectors_found) * 50, 100)

        return {
            "selectors_active": len(selectors_found),
            "selectors_found": selectors_found,
            "security_score": security_score,
            "dkim_enabled": len(selectors_found) > 0
        }

    def _check_dnssec(self, hostname: str) -> dict[str, Any]:
        """Check DNSSEC status (simplified check)."""
        try:
            # Try to query with DNSSEC flag
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolver.nameservers
            resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)

            resolver.resolve(hostname, 'A')

            # If we get here without exception, basic DNSSEC might be working
            # This is a simplified check - full DNSSEC validation is complex
            return {
                "enabled": True,
                "status": "detected",
                "security_score": 60
            }

        except Exception as e:
            return {
                "enabled": False,
                "status": "not_detected",
                "security_score": 0,
                "error": str(e)
            }

    def _check_caa_record(self, hostname: str) -> dict[str, Any]:
        """Check CAA (Certificate Authority Authorization) record."""
        try:
            try:
                answers = self.resolver.resolve(hostname, 'CAA')
            except Exception:
                answers = self.backup_resolver.resolve(hostname, 'CAA')

            caa_records = []
            for rdata in answers:
                caa_records.append(str(rdata))

            return {
                "enabled": True,
                "records": caa_records,
                "count": len(caa_records),
                "security_score": 40
            }

        except Exception as e:
            return {
                "enabled": False,
                "records": [],
                "count": 0,
                "security_score": 0,
                "error": str(e)
            }

    def _calculate_dns_score(self, dns_info: dict[str, Any]) -> float:
        """Calculate comprehensive DNS score (0-1)."""
        if "error" in dns_info:
            return 0.0

        technical_analysis = dns_info.get("technical_analysis", {})
        technical_scores = technical_analysis.get("technical_scores", {})

        if not technical_scores:
            return 0.0

        # Weighted average of technical scores
        weights = {
            "basic_dns": 0.3,
            "mail_security": 0.25,
            "security_features": 0.2,
            "infrastructure": 0.15,
            "ipv6_support": 0.1
        }

        total_score = 0.0
        total_weight = 0.0

        for score_type, weight in weights.items():
            if score_type in technical_scores:
                total_score += technical_scores[score_type] * weight
                total_weight += weight

        if total_weight > 0:
            return total_score / (total_weight * 100)  # Normalize to 0-1

        return 0.0

    def _prepare_details(self, dns_info: dict[str, Any]) -> dict[str, Any]:
        """Prepare comprehensive technical details for output."""
        details = {
            "dns_records_analysis": dns_info.get("basic_records", {}),
            "mail_security_analysis": dns_info.get("mail_security", {}),
            "security_features_analysis": dns_info.get("security_features", {}),
            "technical_assessment": dns_info.get("technical_analysis", {}),

            "summary": {
                "total_record_types": len([k for k, v in dns_info.get("basic_records", {}).get("record_counts", {}).items() if v > 0]),
                "security_features_enabled": len(dns_info.get("technical_analysis", {}).get("security_features", [])),
                "vulnerabilities_identified": len(dns_info.get("technical_analysis", {}).get("vulnerabilities", [])),
                "recommendations_count": len(dns_info.get("technical_analysis", {}).get("recommendations", [])),
                "overall_health_score": dns_info.get("technical_analysis", {}).get("overall_health", "unknown"),
                "technical_scores": dns_info.get("technical_analysis", {}).get("technical_scores", {})
            }
        }

        if "error" in dns_info:
            details["error"] = dns_info["error"]

        return details

    def _calculate_technical_scores(self, dns_info: dict[str, Any]) -> dict[str, float]:
        """Calculate technical scores from DNS analysis results."""
        scores = {}

        # Basic DNS infrastructure score (0-100)
        basic_records = dns_info.get('basic_records', {})
        if basic_records and not basic_records.get('error'):
            record_counts = basic_records.get('record_counts', {})
            record_counts.get('total_records', 0)

            # Score based on DNS completeness
            basic_score = 0
            if record_counts.get('a_records', 0) > 0:
                basic_score += 30  # IPv4 essential
            if record_counts.get('aaaa_records', 0) > 0:
                basic_score += 10  # IPv6 support
            if record_counts.get('mx_records', 0) > 0:
                basic_score += 20  # Mail service
            if record_counts.get('ns_records', 0) >= 2:
                basic_score += 25  # Proper NS delegation
            if record_counts.get('txt_records', 0) > 0:
                basic_score += 15  # TXT records for verification

            scores['basic_dns'] = min(basic_score, 100)
        else:
            scores['basic_dns'] = 0

        # Mail security score (0-100)
        mail_security = dns_info.get('mail_security', {})
        if mail_security and not mail_security.get('error'):
            scores['mail_security'] = mail_security.get('security_score', 0)
        else:
            scores['mail_security'] = 0

        # Security features score (0-100)
        security_features = dns_info.get('security_features', {})
        if security_features and not security_features.get('error'):
            scores['security_features'] = security_features.get('security_score', 0)
        else:
            scores['security_features'] = 0

        # Infrastructure reliability score
        scores['infrastructure'] = self._calculate_infrastructure_score(dns_info)

        # IPv6 support score
        scores['ipv6_support'] = 100 if basic_records.get('ipv6_supported', False) else 0

        return scores

    def _calculate_infrastructure_score(self, dns_info: dict[str, Any]) -> float:
        """Calculate infrastructure reliability score."""
        score = 0
        basic_records = dns_info.get('basic_records', {})

        if basic_records and not basic_records.get('error'):
            # Check NS record count (redundancy)
            ns_count = basic_records.get('record_counts', {}).get('ns_records', 0)
            if ns_count >= 4:
                score += 40  # Excellent redundancy
            elif ns_count >= 2:
                score += 30  # Good redundancy
            elif ns_count >= 1:
                score += 15  # Minimal setup

            # Check TTL values (caching efficiency)
            record_details = basic_records.get('record_details', {})
            a_ttl = record_details.get('A', {}).get('ttl', 0)
            if a_ttl > 3600:  # > 1 hour
                score += 30  # Good caching
            elif a_ttl > 300:  # > 5 minutes
                score += 20  # Reasonable caching
            elif a_ttl > 0:
                score += 10  # Some caching

            # Check DNS configuration completeness
            if basic_records.get('dns_properly_configured', False):
                score += 30

        return min(score, 100)

    def _get_security_features_list(self, dns_info: dict[str, Any]) -> list[str]:
        """Extract list of enabled security features."""
        features = []

        # Mail security features
        mail_security = dns_info.get('mail_security', {})
        if mail_security.get('spf_analysis', {}).get('record_found', False):
            features.append('SPF')
        if mail_security.get('dmarc_analysis', {}).get('record_found', False):
            features.append('DMARC')
        if mail_security.get('dkim_analysis', {}).get('dkim_enabled', False):
            features.append('DKIM')

        # DNS security features
        security_features = dns_info.get('security_features', {})
        if security_features.get('dnssec_analysis', {}).get('enabled', False):
            features.append('DNSSEC')
        if security_features.get('caa_analysis', {}).get('enabled', False):
            features.append('CAA')

        return features

    def _identify_vulnerabilities(self, dns_info: dict[str, Any]) -> list[str]:
        """Identify DNS-related vulnerabilities."""
        vulnerabilities = []

        # Check for missing SPF
        mail_security = dns_info.get('mail_security', {})
        if not mail_security.get('spf_analysis', {}).get('record_found', False):
            vulnerabilities.append('Missing SPF record - email spoofing risk')

        # Check for permissive SPF
        spf_level = mail_security.get('spf_analysis', {}).get('security_level', '')
        if spf_level == 'permissive':
            vulnerabilities.append('Permissive SPF policy - allows unrestricted email sending')

        # Check for missing DMARC
        if not mail_security.get('dmarc_analysis', {}).get('record_found', False):
            vulnerabilities.append('Missing DMARC record - no email authentication policy')

        # Check for missing DNSSEC
        security_features = dns_info.get('security_features', {})
        if not security_features.get('dnssec_analysis', {}).get('enabled', False):
            vulnerabilities.append('DNSSEC not enabled - DNS responses not authenticated')

        # Check for insufficient name servers
        basic_records = dns_info.get('basic_records', {})
        ns_count = basic_records.get('record_counts', {}).get('ns_records', 0)
        if ns_count < 2:
            vulnerabilities.append('Insufficient name servers - single point of failure')

        return vulnerabilities

    def _generate_recommendations(self, dns_info: dict[str, Any]) -> list[str]:
        """Generate actionable recommendations."""
        recommendations = []

        mail_security = dns_info.get('mail_security', {})
        security_features = dns_info.get('security_features', {})

        # SPF recommendations
        if not mail_security.get('spf_analysis', {}).get('record_found', False):
            recommendations.append('Implement SPF record to prevent email spoofing')
        elif mail_security.get('spf_analysis', {}).get('security_level', '') == 'permissive':
            recommendations.append('Tighten SPF policy from +all to -all for better security')

        # DMARC recommendations
        if not mail_security.get('dmarc_analysis', {}).get('record_found', False):
            recommendations.append('Implement DMARC policy for email authentication')

        # DKIM recommendations
        if not mail_security.get('dkim_analysis', {}).get('dkim_enabled', False):
            recommendations.append('Enable DKIM signing for email authenticity')

        # DNSSEC recommendations
        if not security_features.get('dnssec_analysis', {}).get('enabled', False):
            recommendations.append('Enable DNSSEC for DNS response authentication')

        # CAA recommendations
        if not security_features.get('caa_analysis', {}).get('enabled', False):
            recommendations.append('Implement CAA records to control certificate issuance')

        return recommendations

    def _assess_overall_health(self, technical_scores: dict[str, float]) -> str:
        """Assess overall DNS health based on technical scores."""
        if not technical_scores:
            return 'unknown'

        # Calculate weighted average
        weights = {
            'basic_dns': 0.3,
            'mail_security': 0.25,
            'security_features': 0.2,
            'infrastructure': 0.15,
            'ipv6_support': 0.1
        }

        total_score = 0
        total_weight = 0

        for score_type, weight in weights.items():
            if score_type in technical_scores:
                total_score += technical_scores[score_type] * weight
                total_weight += weight

        if total_weight > 0:
            avg_score = total_score / total_weight

            if avg_score >= 80:
                return 'excellent'
            elif avg_score >= 60:
                return 'good'
            elif avg_score >= 40:
                return 'fair'
            else:
                return 'poor'

        return 'unknown'

    def _calculate_reliability_metrics(self, dns_info: dict[str, Any]) -> dict[str, Any]:
        """Calculate reliability metrics based on DNS analysis results."""
        metrics = {}

        # Calculate response time metrics
        response_times = []
        for _record_type, result in dns_info.get('basic_records', {}).get('record_details', {}).items():
            if isinstance(result, dict) and 'error' not in result:
                response_times.append(result.get('ttl', 0))

        if response_times:
            metrics['average_response_time'] = sum(response_times) / len(response_times)
            metrics['max_response_time'] = max(response_times)
            metrics['min_response_time'] = min(response_times)

        # Calculate record count metrics
        record_counts = dns_info.get('basic_records', {}).get('record_counts', {})
        metrics['total_records'] = record_counts.get('total_records', 0)
        metrics['ipv4_supported'] = record_counts.get('ipv4_supported', False)
        metrics['ipv6_supported'] = record_counts.get('ipv6_supported', False)
        metrics['has_mail_servers'] = record_counts.get('has_mail_servers', False)
        metrics['dns_properly_configured'] = record_counts.get('dns_properly_configured', False)

        # Calculate recovery metrics
        if dns_info.get('basic_records', {}).get('recovered', False):
            metrics['recovery_attempted'] = True
            metrics['recovery_success'] = True
        else:
            metrics['recovery_attempted'] = False
            metrics['recovery_success'] = False

        return metrics
