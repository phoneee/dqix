"""Enhanced Security Headers probe with comprehensive analysis and reduced false positives."""

import asyncio
import logging
import re
import ssl
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class SecurityHeadersProbe(BaseProbe):
    """Comprehensive HTTP security headers analysis with reduced false positives."""

    def __init__(self):
        super().__init__("security_headers", ProbeCategory.SECURITY)
        self.logger = logging.getLogger(__name__)

    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Perform comprehensive security headers analysis."""

        try:
            # Test multiple endpoints to reduce false positives
            endpoints = [
                f"https://{domain.name}",
                f"https://www.{domain.name}",
            ]

            best_result = None
            best_score = 0

            for endpoint in endpoints:
                try:
                    result = await self._analyze_endpoint(endpoint, config)
                    if result and result.score > best_score:
                        best_result = result
                        best_score = result.score
                except Exception as e:
                    self.logger.debug(f"Endpoint {endpoint} failed: {e}")
                    continue

            if best_result:
                return best_result

            # Fallback result if all endpoints fail
            return ProbeResult(
                probe_id=self.probe_id,
                domain=domain,
                status="failed",
                score=0.0,
                message="Unable to retrieve security headers from any endpoint",
                details={"error": "All endpoints failed"}
            )

        except Exception as e:
            self.logger.error(f"Security headers probe failed for {domain.name}: {e}")
            return ProbeResult(
                probe_id=self.probe_id,
                domain=domain,
                status="error",
                score=0.0,
                message=f"Security headers analysis failed: {str(e)}",
                details={"error": str(e)}
            )

    async def _analyze_endpoint(self, url: str, config: ProbeConfig) -> Optional[ProbeResult]:
        """Analyze security headers for a specific endpoint."""

        # Create SSL context for secure connections
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=10,
            limit_per_host=5,
            ttl_dns_cache=300,
            use_dns_cache=True
        )

        timeout = aiohttp.ClientTimeout(total=config.timeout)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'DQIX-Security-Scanner/1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        ) as session:

            try:
                async with session.get(url, allow_redirects=True) as response:
                    headers = dict(response.headers)

                    # Analyze security headers
                    security_analysis = await self._analyze_security_headers(headers)

                    # Calculate score
                    score = self._calculate_security_score(security_analysis)

                    # Determine status
                    status = "passed" if score >= 0.6 else "warning" if score >= 0.4 else "failed"

                    # Generate message
                    message = self._generate_analysis_message(security_analysis, score)

                    # Parse domain from URL
                    parsed_url = urlparse(url)
                    domain = Domain(parsed_url.netloc)

                    return ProbeResult(
                        probe_id=self.probe_id,
                        domain=domain,
                        status=status,
                        score=score,
                        message=message,
                        details={
                            "url_analyzed": url,
                            "security_headers": security_analysis,
                            "response_status": response.status,
                            "total_headers": len(headers)
                        }
                    )

            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout analyzing {url}")
                return None
            except Exception as e:
                self.logger.warning(f"Failed to analyze {url}: {e}")
                return None

    async def _analyze_security_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        """Comprehensive security headers analysis."""

        # Convert headers to lowercase for case-insensitive analysis
        lower_headers = {k.lower(): v for k, v in headers.items()}

        security_analysis = {}

        # HSTS Analysis
        security_analysis["hsts"] = self._analyze_hsts_header(lower_headers.get("strict-transport-security"))

        # CSP Analysis
        csp_value = lower_headers.get("content-security-policy")
        csp_report_only = lower_headers.get("content-security-policy-report-only")

        if csp_value or csp_report_only:
            actual_csp_value = csp_value or csp_report_only
            if actual_csp_value:
                security_analysis["csp"] = self._analyze_csp_header_enhanced(actual_csp_value)
        else:
            security_analysis["csp"] = {"has_csp": False, "score": 0}

        # X-Frame-Options Analysis
        security_analysis["x_frame_options"] = self._analyze_x_frame_options(lower_headers.get("x-frame-options"))

        # X-Content-Type-Options Analysis
        security_analysis["x_content_type_options"] = self._analyze_x_content_type_options(lower_headers.get("x-content-type-options"))

        # X-XSS-Protection Analysis
        security_analysis["x_xss_protection"] = self._analyze_x_xss_protection(lower_headers.get("x-xss-protection"))

        # Referrer Policy Analysis
        security_analysis["referrer_policy"] = self._analyze_referrer_policy(lower_headers.get("referrer-policy"))

        # Permissions Policy Analysis
        security_analysis["permissions_policy"] = self._analyze_permissions_policy(lower_headers.get("permissions-policy"))

        # Information disclosure analysis
        security_analysis["information_disclosure"] = {
            "server_disclosure": bool(lower_headers.get("server")),
            "powered_by_disclosure": bool(lower_headers.get("x-powered-by")),
            "version_disclosure": bool(lower_headers.get("x-aspnet-version"))
        }

        return security_analysis

    def _analyze_hsts_header(self, hsts_value: Optional[str]) -> dict[str, Any]:
        """Analyze HSTS header configuration."""

        if not hsts_value:
            return {
                "has_hsts": False,
                "score": 0,
                "issues": ["HSTS header not present"]
            }

        analysis = {
            "has_hsts": True,
            "raw_value": hsts_value,
            "issues": []
        }

        # Parse max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts_value.lower())
        if max_age_match:
            max_age = int(max_age_match.group(1))
            analysis["max_age"] = max_age

            if max_age < 31536000:  # Less than 1 year
                analysis["issues"].append("HSTS max-age should be at least 31536000 (1 year)")
        else:
            analysis["issues"].append("HSTS max-age directive missing")
            analysis["max_age"] = 0

        # Check for includeSubDomains
        analysis["include_subdomains"] = "includesubdomains" in hsts_value.lower()
        if not analysis["include_subdomains"]:
            analysis["issues"].append("Consider adding includeSubDomains directive")

        # Check for preload
        analysis["preload"] = "preload" in hsts_value.lower()
        if not analysis["preload"]:
            analysis["issues"].append("Consider adding preload directive for enhanced security")

        # Calculate score
        score = 0.4  # Base score for having HSTS
        if analysis.get("max_age", 0) >= 31536000:
            score += 0.3
        if analysis["include_subdomains"]:
            score += 0.2
        if analysis["preload"]:
            score += 0.1

        analysis["score"] = min(score, 1.0)

        return analysis

    def _analyze_csp_header_enhanced(self, csp_value: str) -> dict[str, Any]:
        """Enhanced CSP analysis with modern security practices."""

        analysis = {
            "has_csp": True,
            "raw_value": csp_value,
            "directives": {},
            "security_score": 0,
            "issues": [],
            "recommendations": []
        }

        # Parse directives
        directives = {}
        for directive in csp_value.split(';'):
            directive = directive.strip()
            if directive:
                parts = directive.split(None, 1)
                if len(parts) >= 1:
                    key = parts[0].lower()
                    value = parts[1] if len(parts) > 1 else ""
                    directives[key] = value

        analysis["directives"] = directives

        # Analyze critical directives
        critical_directives = ["default-src", "script-src", "object-src", "base-uri"]
        security_score = 0

        for directive in critical_directives:
            if directive in directives:
                security_score += 0.2

                # Check for unsafe directives
                directive_value = directives[directive].lower()
                if "'unsafe-inline'" in directive_value:
                    analysis["issues"].append(f"{directive} allows unsafe-inline")
                    security_score -= 0.1

                if "'unsafe-eval'" in directive_value:
                    analysis["issues"].append(f"{directive} allows unsafe-eval")
                    security_score -= 0.1

                if "*" in directive_value and directive != "img-src":
                    analysis["issues"].append(f"{directive} uses wildcard (*)")
                    security_score -= 0.05

                # Check for modern CSP features
                if "'nonce-" in directive_value:
                    analysis["recommendations"].append(f"{directive} uses nonce-based CSP (good)")
                    security_score += 0.05

                if "'strict-dynamic'" in directive_value:
                    analysis["recommendations"].append(f"{directive} uses strict-dynamic (excellent)")
                    security_score += 0.1
            else:
                analysis["issues"].append(f"Missing {directive} directive")

        # Check for frame-ancestors
        if "frame-ancestors" in directives:
            security_score += 0.1
        else:
            analysis["recommendations"].append("Consider adding frame-ancestors directive")

        # Check for upgrade-insecure-requests
        if "upgrade-insecure-requests" in directives:
            security_score += 0.1
            analysis["recommendations"].append("upgrade-insecure-requests directive present (good)")

        analysis["security_score"] = max(0, min(security_score, 1.0))

        return analysis

    def _analyze_x_frame_options(self, xfo_value: Optional[str]) -> dict[str, Any]:
        """Analyze X-Frame-Options header."""

        if not xfo_value:
            return {
                "has_header": False,
                "score": 0,
                "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN"
            }

        xfo_lower = xfo_value.lower()

        analysis = {
            "has_header": True,
            "value": xfo_value,
            "score": 0
        }

        if xfo_lower == "deny":
            analysis["score"] = 1.0
            analysis["assessment"] = "Excellent - Prevents all framing"
        elif xfo_lower == "sameorigin":
            analysis["score"] = 0.8
            analysis["assessment"] = "Good - Allows same-origin framing"
        elif xfo_lower.startswith("allow-from"):
            analysis["score"] = 0.6
            analysis["assessment"] = "Moderate - Allows specific origins"
            analysis["recommendation"] = "Consider using CSP frame-ancestors instead"
        else:
            analysis["score"] = 0.2
            analysis["assessment"] = "Poor - Invalid or weak configuration"

        return analysis

    def _analyze_x_content_type_options(self, xcto_value: Optional[str]) -> dict[str, Any]:
        """Analyze X-Content-Type-Options header."""

        if not xcto_value:
            return {
                "has_header": False,
                "score": 0,
                "recommendation": "Add X-Content-Type-Options: nosniff"
            }

        analysis = {
            "has_header": True,
            "value": xcto_value
        }

        if xcto_value.lower() == "nosniff":
            analysis["score"] = 1.0
            analysis["assessment"] = "Correct - Prevents MIME type sniffing"
        else:
            analysis["score"] = 0.3
            analysis["assessment"] = "Incorrect value - Should be 'nosniff'"

        return analysis

    def _analyze_x_xss_protection(self, xxp_value: Optional[str]) -> dict[str, Any]:
        """Analyze X-XSS-Protection header."""

        if not xxp_value:
            return {
                "has_header": False,
                "score": 0.5,  # Neutral score as this header is deprecated
                "note": "Header not present (acceptable - deprecated in favor of CSP)"
            }

        analysis = {
            "has_header": True,
            "value": xxp_value
        }

        xxp_lower = xxp_value.lower()

        if xxp_lower == "0":
            analysis["score"] = 0.8
            analysis["assessment"] = "Good - Disables legacy XSS filter"
        elif xxp_lower in ["1", "1; mode=block"]:
            analysis["score"] = 0.6
            analysis["assessment"] = "Acceptable but deprecated"
            analysis["recommendation"] = "Use Content Security Policy instead"
        else:
            analysis["score"] = 0.3
            analysis["assessment"] = "Poor configuration"

        return analysis

    def _analyze_referrer_policy(self, rp_value: Optional[str]) -> dict[str, Any]:
        """Analyze Referrer-Policy header."""

        if not rp_value:
            return {
                "has_header": False,
                "score": 0,
                "recommendation": "Add Referrer-Policy header"
            }

        analysis = {
            "has_header": True,
            "value": rp_value
        }

        rp_lower = rp_value.lower()

        # Score based on privacy and security
        policy_scores = {
            "no-referrer": 1.0,
            "same-origin": 0.9,
            "strict-origin": 0.9,
            "strict-origin-when-cross-origin": 0.8,
            "origin": 0.6,
            "origin-when-cross-origin": 0.5,
            "unsafe-url": 0.1,
            "no-referrer-when-downgrade": 0.4
        }

        analysis["score"] = policy_scores.get(rp_lower, 0.3)

        if analysis["score"] >= 0.8:
            analysis["assessment"] = "Good privacy protection"
        elif analysis["score"] >= 0.5:
            analysis["assessment"] = "Moderate privacy protection"
        else:
            analysis["assessment"] = "Weak privacy protection"

        return analysis

    def _analyze_permissions_policy(self, pp_value: Optional[str]) -> dict[str, Any]:
        """Analyze Permissions-Policy header."""

        if not pp_value:
            return {
                "has_header": False,
                "score": 0,
                "recommendation": "Consider adding Permissions-Policy header"
            }

        analysis = {
            "has_header": True,
            "value": pp_value,
            "score": 0.5,  # Base score for having the header
            "assessment": "Present - Helps control browser features"
        }

        # Check for common dangerous permissions
        dangerous_features = ["camera", "microphone", "geolocation", "payment"]
        restricted_count = 0

        for feature in dangerous_features:
            if f"{feature}=()" in pp_value.lower():
                restricted_count += 1

        # Bonus score for restricting dangerous features
        analysis["score"] += (restricted_count / len(dangerous_features)) * 0.3

        return analysis

    def _calculate_security_score(self, security_analysis: dict[str, Any]) -> float:
        """Calculate overall security score based on header analysis."""

        weights = {
            "hsts": 0.25,
            "csp": 0.30,
            "x_frame_options": 0.15,
            "x_content_type_options": 0.10,
            "x_xss_protection": 0.05,
            "referrer_policy": 0.10,
            "permissions_policy": 0.05
        }

        total_weight = 0
        weighted_score = 0

        for header, weight in weights.items():
            if header in security_analysis:
                header_score = security_analysis[header].get("score", 0)
                weighted_score += header_score * weight
                total_weight += weight

        # Penalty for information disclosure
        info_disclosure = security_analysis.get("information_disclosure", {})
        disclosure_penalty = 0
        if info_disclosure.get("server_disclosure"):
            disclosure_penalty += 0.02
        if info_disclosure.get("powered_by_disclosure"):
            disclosure_penalty += 0.02
        if info_disclosure.get("version_disclosure"):
            disclosure_penalty += 0.03

        final_score = (weighted_score / total_weight if total_weight > 0 else 0) - disclosure_penalty

        return max(0.0, min(1.0, final_score))

    def _generate_analysis_message(self, security_analysis: dict[str, Any], score: float) -> str:
        """Generate human-readable analysis message."""

        if score >= 0.8:
            return "Excellent security headers configuration"
        elif score >= 0.6:
            return "Good security headers with room for improvement"
        elif score >= 0.4:
            return "Basic security headers present, needs enhancement"
        else:
            return "Poor security headers configuration, immediate attention required"
