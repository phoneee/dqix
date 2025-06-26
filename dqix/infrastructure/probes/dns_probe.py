"""Enhanced DNS configuration probe with comprehensive technical analysis."""

import dns.resolver
import dns.reversename
import dns.flags
import socket
import re
from typing import Dict, Any, List, Optional

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class DNSProbe(BaseProbe):
    """Comprehensive DNS configuration and security analysis."""
    
    def __init__(self):
        super().__init__("dns", ProbeCategory.SECURITY)
    
    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Perform comprehensive DNS analysis for domain."""
        try:
            # Collect DNS information
            dns_info = await self._collect_dns_info(domain.name, config.timeout)
            
            # Calculate detailed score
            score = self._calculate_comprehensive_score(dns_info)
            
            # Prepare detailed technical information
            details = self._prepare_technical_details(dns_info)
            
            return self._create_result(domain, score, details)
            
        except Exception as e:
            return self._create_result(
                domain, 
                0.0, 
                {"error": str(e), "analysis": "DNS resolution failed"}, 
                error=str(e)
            )
    
    async def _collect_dns_info(self, hostname: str, timeout: int) -> Dict[str, Any]:
        """Collect comprehensive DNS information."""
        dns_info = {
            "basic_records": {},
            "mail_security": {},
            "security_features": {},
            "technical_analysis": {}
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            # Basic DNS records analysis
            dns_info["basic_records"] = self._get_basic_records(resolver, hostname)
            
            # Mail security comprehensive analysis
            dns_info["mail_security"] = self._analyze_mail_security(resolver, hostname)
            
            # Security features analysis
            dns_info["security_features"] = self._analyze_security_features(resolver, hostname)
            
            # Technical analysis and scoring
            dns_info["technical_analysis"] = self._perform_technical_analysis(dns_info)
            
        except Exception as e:
            dns_info["error"] = str(e)
        
        return dns_info
    
    def _get_basic_records(self, resolver: dns.resolver.Resolver, hostname: str) -> Dict[str, Any]:
        """Get basic DNS records with detailed analysis."""
        records = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "soa_record": {},
            "record_counts": {},
            "ip_analysis": {},
            "reverse_dns": {}
        }
        
        # A records (IPv4)
        try:
            answers = resolver.resolve(hostname, 'A')
            records["a_records"] = [str(rdata) for rdata in answers]
            records["ip_analysis"]["ipv4_addresses"] = len(records["a_records"])
            
            # Reverse DNS lookup for first IP
            if records["a_records"]:
                records["reverse_dns"]["ipv4"] = self._get_reverse_dns(records["a_records"][0])
        except Exception as e:
            records["a_records"] = []
            records["ip_analysis"] = {"ipv4_error": str(e)}
        
        # AAAA records (IPv6)
        try:
            answers = resolver.resolve(hostname, 'AAAA')
            records["aaaa_records"] = [str(rdata) for rdata in answers]
            records["ip_analysis"]["ipv6_addresses"] = len(records["aaaa_records"])
            
            # Reverse DNS lookup for first IPv6
            if records["aaaa_records"]:
                records["reverse_dns"]["ipv6"] = self._get_reverse_dns(records["aaaa_records"][0])
        except Exception as e:
            records["aaaa_records"] = []
            records["ip_analysis"]["ipv6_error"] = str(e)
        
        # MX records
        try:
            answers = resolver.resolve(hostname, 'MX')
            records["mx_records"] = [f"{getattr(rdata, 'preference', 0)} {getattr(rdata, 'exchange', rdata)}" for rdata in answers]
            records["mx_analysis"] = self._analyze_mx_records(answers)
        except Exception as e:
            records["mx_records"] = []
            records["mx_analysis"] = {"error": str(e)}
        
        # NS records
        try:
            answers = resolver.resolve(hostname, 'NS')
            records["ns_records"] = [str(rdata) for rdata in answers]
            records["ns_analysis"] = self._analyze_ns_records(records["ns_records"])
        except Exception as e:
            records["ns_records"] = []
            records["ns_analysis"] = {"error": str(e)}
        
        # TXT records
        try:
            answers = resolver.resolve(hostname, 'TXT')
            records["txt_records"] = [str(rdata) for rdata in answers]
            records["txt_analysis"] = self._analyze_txt_records(records["txt_records"])
        except Exception as e:
            records["txt_records"] = []
            records["txt_analysis"] = {"error": str(e)}
        
        # CNAME records (if applicable)
        try:
            answers = resolver.resolve(hostname, 'CNAME')
            records["cname_records"] = [str(rdata) for rdata in answers]
        except Exception:
            records["cname_records"] = []
        
        # SOA record
        try:
            answers = resolver.resolve(hostname, 'SOA')
            soa = answers[0]
            records["soa_record"] = {
                "mname": str(getattr(soa, 'mname', 'unknown')),
                "rname": str(getattr(soa, 'rname', 'unknown')),
                "serial": getattr(soa, 'serial', 0),
                "refresh": getattr(soa, 'refresh', 0),
                "retry": getattr(soa, 'retry', 0),
                "expire": getattr(soa, 'expire', 0),
                "minimum": getattr(soa, 'minimum', 0)
            }
        except Exception as e:
            records["soa_record"] = {"error": str(e)}
        
        # Record counts
        records["record_counts"] = {
            "a_records": len(records["a_records"]),
            "aaaa_records": len(records["aaaa_records"]),
            "mx_records": len(records["mx_records"]),
            "ns_records": len(records["ns_records"]),
            "txt_records": len(records["txt_records"]),
            "cname_records": len(records["cname_records"])
        }
        
        return records
    
    def _get_reverse_dns(self, ip_address: str) -> Dict[str, Any]:
        """Get reverse DNS information for IP address."""
        try:
            reverse_name = dns.reversename.from_address(ip_address)
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(reverse_name, 'PTR')
            return {
                "hostname": str(answers[0]),
                "resolved": True
            }
        except Exception as e:
            return {
                "hostname": None,
                "resolved": False,
                "error": str(e)
            }
    
    def _analyze_mx_records(self, mx_answers) -> Dict[str, Any]:
        """Analyze MX records for mail configuration."""
        analysis = {
            "count": len(mx_answers),
            "priorities": [],
            "mail_servers": [],
            "redundancy": False,
            "security_analysis": {}
        }
        
        for mx in mx_answers:
            analysis["priorities"].append(getattr(mx, 'preference', 0))
            analysis["mail_servers"].append(str(getattr(mx, 'exchange', mx)))
        
        # Check for redundancy
        analysis["redundancy"] = len(set(analysis["priorities"])) > 1
        
        # Security analysis
        analysis["security_analysis"] = {
            "multiple_servers": len(analysis["mail_servers"]) > 1,
            "priority_distribution": len(set(analysis["priorities"])) > 1,
            "external_providers": self._identify_mail_providers(analysis["mail_servers"])
        }
        
        return analysis
    
    def _identify_mail_providers(self, mail_servers: List[str]) -> List[str]:
        """Identify known mail service providers."""
        providers = []
        provider_patterns = {
            "Google": ["gmail", "google", "googlemail"],
            "Microsoft": ["outlook", "hotmail", "live", "office365"],
            "Yahoo": ["yahoo", "yahoomail"],
            "Amazon": ["amazonses", "amazon"],
            "Cloudflare": ["cloudflare"],
            "ProtonMail": ["protonmail"]
        }
        
        for server in mail_servers:
            server_lower = server.lower()
            for provider, patterns in provider_patterns.items():
                if any(pattern in server_lower for pattern in patterns):
                    providers.append(provider)
                    break
        
        return providers
    
    def _analyze_ns_records(self, ns_records: List[str]) -> Dict[str, Any]:
        """Analyze NS records for DNS configuration."""
        analysis = {
            "count": len(ns_records),
            "nameservers": ns_records,
            "redundancy": len(ns_records) >= 2,
            "diversity": {},
            "security_analysis": {}
        }
        
        # Check for diversity (different domains/providers)
        domains = set()
        for ns in ns_records:
            parts = ns.split('.')
            if len(parts) >= 2:
                domains.add('.'.join(parts[-2:]))
        
        analysis["diversity"] = {
            "unique_domains": len(domains),
            "has_diversity": len(domains) > 1,
            "domains": list(domains)
        }
        
        # Security analysis
        analysis["security_analysis"] = {
            "sufficient_nameservers": len(ns_records) >= 2,
            "provider_diversity": len(domains) > 1,
            "known_providers": self._identify_dns_providers(ns_records)
        }
        
        return analysis
    
    def _identify_dns_providers(self, ns_records: List[str]) -> List[str]:
        """Identify known DNS service providers."""
        providers = []
        provider_patterns = {
            "Cloudflare": ["cloudflare"],
            "Amazon Route 53": ["awsdns"],
            "Google Cloud DNS": ["googledomains", "google"],
            "Azure DNS": ["azure", "microsoft"],
            "Namecheap": ["namecheap"],
            "GoDaddy": ["godaddy"],
            "Quad9": ["quad9"]
        }
        
        for ns in ns_records:
            ns_lower = ns.lower()
            for provider, patterns in provider_patterns.items():
                if any(pattern in ns_lower for pattern in patterns):
                    providers.append(provider)
                    break
        
        return providers
    
    def _analyze_txt_records(self, txt_records: List[str]) -> Dict[str, Any]:
        """Analyze TXT records for various purposes."""
        analysis = {
            "count": len(txt_records),
            "record_types": {},
            "security_records": [],
            "verification_records": [],
            "other_records": []
        }
        
        for record in txt_records:
            record_str = record.strip('"')
            
            # Identify record types
            if record_str.startswith('v=spf1'):
                analysis["record_types"]["spf"] = record_str
                analysis["security_records"].append("SPF")
            elif record_str.startswith('v=DMARC1'):
                analysis["record_types"]["dmarc"] = record_str
                analysis["security_records"].append("DMARC")
            elif 'google-site-verification' in record_str:
                analysis["verification_records"].append("Google")
            elif 'facebook-domain-verification' in record_str:
                analysis["verification_records"].append("Facebook")
            elif 'MS=' in record_str:
                analysis["verification_records"].append("Microsoft")
            else:
                analysis["other_records"].append(record_str)
        
        return analysis
    
    def _analyze_mail_security(self, resolver: dns.resolver.Resolver, hostname: str) -> Dict[str, Any]:
        """Comprehensive mail security analysis."""
        mail_security = {
            "spf_analysis": {},
            "dmarc_analysis": {},
            "dkim_analysis": {},
            "security_score": 0,
            "recommendations": []
        }
        
        # SPF Analysis
        mail_security["spf_analysis"] = self._analyze_spf_record(resolver, hostname)
        
        # DMARC Analysis
        mail_security["dmarc_analysis"] = self._analyze_dmarc_record(resolver, hostname)
        
        # DKIM Analysis (check common selectors)
        mail_security["dkim_analysis"] = self._analyze_dkim_records(resolver, hostname)
        
        # Calculate mail security score
        mail_security["security_score"] = self._calculate_mail_security_score(mail_security)
        
        # Generate recommendations
        mail_security["recommendations"] = self._generate_mail_security_recommendations(mail_security)
        
        return mail_security
    
    def _analyze_spf_record(self, resolver: dns.resolver.Resolver, hostname: str) -> Dict[str, Any]:
        """Analyze SPF record comprehensively."""
        spf_analysis = {
            "record_found": False,
            "record_content": "",
            "version": "",
            "mechanisms": [],
            "qualifiers": [],
            "includes": [],
            "ip_addresses": [],
            "issues": [],
            "security_level": "none"
        }
        
        try:
            answers = resolver.resolve(hostname, 'TXT')
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith('v=spf1'):
                    spf_analysis["record_found"] = True
                    spf_analysis["record_content"] = record
                    spf_analysis.update(self._parse_spf_record(record))
                    break
        except Exception as e:
            spf_analysis["error"] = str(e)
        
        return spf_analysis
    
    def _parse_spf_record(self, spf_record: str) -> Dict[str, Any]:
        """Parse SPF record into components."""
        parsed = {
            "version": "spf1",
            "mechanisms": [],
            "qualifiers": [],
            "includes": [],
            "ip_addresses": [],
            "issues": [],
            "security_level": "basic"
        }
        
        # Split SPF record into parts
        parts = spf_record.split()
        
        for part in parts[1:]:  # Skip v=spf1
            if part.startswith('include:'):
                parsed["includes"].append(part[8:])
                parsed["mechanisms"].append(f"include:{part[8:]}")
            elif part.startswith('ip4:') or part.startswith('ip6:'):
                parsed["ip_addresses"].append(part)
                parsed["mechanisms"].append(part)
            elif part in ['+all', '-all', '~all', '?all']:
                parsed["qualifiers"].append(part)
                if part == '-all':
                    parsed["security_level"] = "strict"
                elif part == '~all':
                    parsed["security_level"] = "moderate"
                elif part == '+all':
                    parsed["issues"].append("Permissive +all qualifier allows any sender")
            elif part.startswith('a') or part.startswith('mx'):
                parsed["mechanisms"].append(part)
            else:
                parsed["mechanisms"].append(part)
        
        # Check for common issues
        if not parsed["qualifiers"]:
            parsed["issues"].append("No explicit all qualifier found")
        if len(parsed["includes"]) > 10:
            parsed["issues"].append("Too many includes (>10) may cause lookup failures")
        
        return parsed
    
    def _analyze_dmarc_record(self, resolver: dns.resolver.Resolver, hostname: str) -> Dict[str, Any]:
        """Analyze DMARC record comprehensively."""
        dmarc_analysis = {
            "record_found": False,
            "record_content": "",
            "policy": "",
            "subdomain_policy": "",
            "percentage": 100,
            "report_addresses": [],
            "forensic_addresses": [],
            "alignment": {},
            "issues": [],
            "security_level": "none"
        }
        
        try:
            # DMARC records are at _dmarc.domain
            dmarc_domain = f"_dmarc.{hostname}"
            answers = resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith('v=DMARC1'):
                    dmarc_analysis["record_found"] = True
                    dmarc_analysis["record_content"] = record
                    dmarc_analysis.update(self._parse_dmarc_record(record))
                    break
        except Exception as e:
            dmarc_analysis["error"] = str(e)
        
        return dmarc_analysis
    
    def _parse_dmarc_record(self, dmarc_record: str) -> Dict[str, Any]:
        """Parse DMARC record into components."""
        parsed = {
            "policy": "",
            "subdomain_policy": "",
            "percentage": 100,
            "report_addresses": [],
            "forensic_addresses": [],
            "alignment": {"dkim": "r", "spf": "r"},
            "issues": [],
            "security_level": "basic"
        }
        
        # Parse DMARC tags
        tags = {}
        for part in dmarc_record.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                tags[key.strip()] = value.strip()
        
        # Extract policy information
        parsed["policy"] = tags.get("p", "")
        parsed["subdomain_policy"] = tags.get("sp", parsed["policy"])
        
        # Set security level based on policy
        if parsed["policy"] == "reject":
            parsed["security_level"] = "strict"
        elif parsed["policy"] == "quarantine":
            parsed["security_level"] = "moderate"
        elif parsed["policy"] == "none":
            parsed["security_level"] = "monitoring"
        
        # Parse percentage
        try:
            parsed["percentage"] = int(tags.get("pct", "100"))
        except ValueError:
            parsed["issues"].append("Invalid percentage value")
        
        # Parse report addresses
        if "rua" in tags:
            parsed["report_addresses"] = [addr.strip() for addr in tags["rua"].split(',')]
        if "ruf" in tags:
            parsed["forensic_addresses"] = [addr.strip() for addr in tags["ruf"].split(',')]
        
        # Parse alignment
        parsed["alignment"]["dkim"] = tags.get("adkim", "r")
        parsed["alignment"]["spf"] = tags.get("aspf", "r")
        
        # Check for issues
        if parsed["policy"] == "none" and not parsed["report_addresses"]:
            parsed["issues"].append("Policy set to 'none' without report addresses")
        if parsed["percentage"] < 100:
            parsed["issues"].append(f"Policy only applies to {parsed['percentage']}% of messages")
        
        return parsed
    
    def _analyze_dkim_records(self, resolver: dns.resolver.Resolver, hostname: str) -> Dict[str, Any]:
        """Analyze DKIM records for common selectors."""
        dkim_analysis = {
            "selectors_found": [],
            "records": {},
            "total_selectors_checked": 0,
            "security_analysis": {}
        }
        
        # Common DKIM selectors to check
        common_selectors = [
            "default", "google", "k1", "k2", "s1", "s2", "dkim", "mail",
            "email", "selector1", "selector2", "key1", "key2"
        ]
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{hostname}"
                answers = resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    record = str(rdata).strip('"')
                    if 'k=' in record or 'p=' in record:  # DKIM record indicators
                        dkim_analysis["selectors_found"].append(selector)
                        dkim_analysis["records"][selector] = {
                            "record": record,
                            "parsed": self._parse_dkim_record(record)
                        }
                        break
            except Exception:
                pass
        
        dkim_analysis["total_selectors_checked"] = len(common_selectors)
        dkim_analysis["security_analysis"] = {
            "selectors_active": len(dkim_analysis["selectors_found"]),
            "multiple_selectors": len(dkim_analysis["selectors_found"]) > 1,
            "dkim_enabled": len(dkim_analysis["selectors_found"]) > 0
        }
        
        return dkim_analysis
    
    def _parse_dkim_record(self, dkim_record: str) -> Dict[str, Any]:
        """Parse DKIM record into components."""
        parsed = {
            "version": "",
            "key_type": "",
            "public_key": "",
            "hash_algorithms": [],
            "service_types": [],
            "flags": []
        }
        
        # Parse DKIM tags
        tags = {}
        for part in dkim_record.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                tags[key.strip()] = value.strip()
        
        parsed["version"] = tags.get("v", "")
        parsed["key_type"] = tags.get("k", "rsa")
        parsed["public_key"] = tags.get("p", "")[:50] + "..." if len(tags.get("p", "")) > 50 else tags.get("p", "")
        
        if "h" in tags:
            parsed["hash_algorithms"] = tags["h"].split(':')
        if "s" in tags:
            parsed["service_types"] = tags["s"].split(':')
        if "t" in tags:
            parsed["flags"] = tags["t"].split(':')
        
        return parsed
    
    def _calculate_mail_security_score(self, mail_security: Dict[str, Any]) -> int:
        """Calculate mail security score (0-100)."""
        score = 0
        
        # SPF scoring (40 points)
        spf = mail_security.get("spf_analysis", {})
        if spf.get("record_found"):
            score += 20
            if spf.get("security_level") == "strict":
                score += 20
            elif spf.get("security_level") == "moderate":
                score += 15
            elif spf.get("security_level") == "basic":
                score += 10
        
        # DMARC scoring (40 points)
        dmarc = mail_security.get("dmarc_analysis", {})
        if dmarc.get("record_found"):
            score += 20
            if dmarc.get("security_level") == "strict":
                score += 20
            elif dmarc.get("security_level") == "moderate":
                score += 15
            elif dmarc.get("security_level") == "monitoring":
                score += 10
        
        # DKIM scoring (20 points)
        dkim = mail_security.get("dkim_analysis", {})
        if dkim.get("security_analysis", {}).get("dkim_enabled"):
            score += 10
            if dkim.get("security_analysis", {}).get("multiple_selectors"):
                score += 10
            else:
                score += 5
        
        return min(score, 100)
    
    def _generate_mail_security_recommendations(self, mail_security: Dict[str, Any]) -> List[str]:
        """Generate mail security recommendations."""
        recommendations = []
        
        spf = mail_security.get("spf_analysis", {})
        dmarc = mail_security.get("dmarc_analysis", {})
        dkim = mail_security.get("dkim_analysis", {})
        
        if not spf.get("record_found"):
            recommendations.append("Implement SPF record to prevent email spoofing")
        elif spf.get("issues"):
            recommendations.append("Fix SPF record issues: " + ", ".join(spf["issues"][:2]))
        
        if not dmarc.get("record_found"):
            recommendations.append("Implement DMARC policy for email authentication")
        elif dmarc.get("policy") == "none":
            recommendations.append("Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")
        
        if not dkim.get("security_analysis", {}).get("dkim_enabled"):
            recommendations.append("Enable DKIM signing for email authentication")
        
        return recommendations
    
    def _analyze_security_features(self, resolver: dns.resolver.Resolver, hostname: str) -> Dict[str, Any]:
        """Analyze DNS security features."""
        security_features = {
            "caa_records": [],
            "dnssec_enabled": False,
            "security_score": 0,
            "recommendations": []
        }
        
        # CAA records
        try:
            answers = resolver.resolve(hostname, 'CAA')
            for rdata in answers:
                security_features["caa_records"].append(str(rdata))
        except Exception:
            security_features["caa_records"] = []
        
        # DNSSEC detection (simplified)
        try:
            # Try to resolve with DNSSEC validation
            resolver.use_edns(0, dns.flags.DO, 4096)
            answers = resolver.resolve(hostname, 'A')
            # If we get here without exception, DNSSEC might be working
            # This is a simplified check - full DNSSEC validation is complex
            security_features["dnssec_enabled"] = True
        except Exception:
            security_features["dnssec_enabled"] = False
        
        # Calculate security score
        score = 0
        if security_features["caa_records"]:
            score += 50
        if security_features["dnssec_enabled"]:
            score += 50
        security_features["security_score"] = score
        
        # Generate recommendations
        if not security_features["caa_records"]:
            security_features["recommendations"].append("Add CAA records to control certificate issuance")
        if not security_features["dnssec_enabled"]:
            security_features["recommendations"].append("Enable DNSSEC for DNS security")
        
        return security_features
    
    def _perform_technical_analysis(self, dns_info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive technical analysis."""
        analysis = {
            "ipv6_support": False,
            "mail_configured": False,
            "security_features": [],
            "vulnerabilities": [],
            "recommendations": [],
            "overall_health": "unknown",
            "technical_scores": {}
        }
        
        basic_records = dns_info.get("basic_records", {})
        mail_security = dns_info.get("mail_security", {})
        security_features = dns_info.get("security_features", {})
        
        # IPv6 support analysis
        if basic_records.get("aaaa_records"):
            analysis["ipv6_support"] = True
            analysis["security_features"].append("IPv6 support enabled")
        else:
            analysis["recommendations"].append("Consider adding IPv6 (AAAA) records for future compatibility")
        
        # Mail configuration analysis
        if basic_records.get("mx_records"):
            analysis["mail_configured"] = True
            analysis["security_features"].append("Mail exchange configured")
            
            # Check mail security
            mail_score = mail_security.get("security_score", 0)
            if mail_score < 50:
                analysis["vulnerabilities"].append("Insufficient mail security configuration")
        
        # Security features analysis
        if security_features.get("caa_records"):
            analysis["security_features"].append("CAA records present")
        else:
            analysis["recommendations"].append("Add CAA records to control certificate issuance")
        
        if security_features.get("dnssec_enabled"):
            analysis["security_features"].append("DNSSEC enabled")
        else:
            analysis["recommendations"].append("Enable DNSSEC for DNS security")
        
        # DNS infrastructure analysis
        ns_analysis = basic_records.get("ns_analysis", {})
        if not ns_analysis.get("redundancy", False):
            analysis["vulnerabilities"].append("Insufficient DNS redundancy")
            analysis["recommendations"].append("Configure multiple nameservers for redundancy")
        
        # Calculate technical scores
        analysis["technical_scores"] = {
            "basic_dns": self._calculate_basic_dns_score(basic_records),
            "mail_security": mail_security.get("security_score", 0),
            "security_features": security_features.get("security_score", 0),
            "ipv6_support": 100 if analysis["ipv6_support"] else 0,
            "infrastructure": self._calculate_infrastructure_score(basic_records)
        }
        
        # Determine overall health
        avg_score = sum(analysis["technical_scores"].values()) / len(analysis["technical_scores"])
        vuln_count = len(analysis["vulnerabilities"])
        
        if avg_score >= 80 and vuln_count == 0:
            analysis["overall_health"] = "excellent"
        elif avg_score >= 60 and vuln_count <= 2:
            analysis["overall_health"] = "good"
        elif avg_score >= 40 and vuln_count <= 4:
            analysis["overall_health"] = "fair"
        else:
            analysis["overall_health"] = "poor"
        
        return analysis
    
    def _calculate_basic_dns_score(self, basic_records: Dict[str, Any]) -> int:
        """Calculate basic DNS configuration score."""
        score = 0
        
        # A records (20 points)
        if basic_records.get("a_records"):
            score += 20
        
        # AAAA records (15 points)
        if basic_records.get("aaaa_records"):
            score += 15
        
        # NS records (25 points)
        ns_count = len(basic_records.get("ns_records", []))
        if ns_count >= 2:
            score += 25
        elif ns_count == 1:
            score += 15
        
        # MX records (20 points)
        if basic_records.get("mx_records"):
            score += 20
        
        # SOA record (10 points)
        if basic_records.get("soa_record") and "error" not in basic_records["soa_record"]:
            score += 10
        
        # Reverse DNS (10 points)
        reverse_dns = basic_records.get("reverse_dns", {})
        if reverse_dns.get("ipv4", {}).get("resolved") or reverse_dns.get("ipv6", {}).get("resolved"):
            score += 10
        
        return min(score, 100)
    
    def _calculate_infrastructure_score(self, basic_records: Dict[str, Any]) -> int:
        """Calculate DNS infrastructure score."""
        score = 0
        
        # Nameserver redundancy (40 points)
        ns_analysis = basic_records.get("ns_analysis", {})
        if ns_analysis.get("redundancy"):
            score += 40
        
        # Nameserver diversity (30 points)
        if ns_analysis.get("diversity", {}).get("has_diversity"):
            score += 30
        
        # MX redundancy (20 points)
        mx_analysis = basic_records.get("mx_analysis", {})
        if mx_analysis.get("redundancy"):
            score += 20
        
        # Known providers (10 points)
        if ns_analysis.get("security_analysis", {}).get("known_providers"):
            score += 10
        
        return min(score, 100)
    
    def _calculate_comprehensive_score(self, dns_info: Dict[str, Any]) -> float:
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
    
    def _prepare_technical_details(self, dns_info: Dict[str, Any]) -> Dict[str, Any]:
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