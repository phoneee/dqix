"""HTTPS Accessibility and Redirect Probe for basic web security checks."""

import asyncio
import ssl
import time
from typing import Any

import aiohttp

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class HTTPSProbe(BaseProbe):
    """HTTPS accessibility and HTTP redirect analysis probe."""

    def __init__(self):
        super().__init__("https", ProbeCategory.SECURITY)

    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Check HTTPS accessibility and HTTP-to-HTTPS redirects."""
        try:
            # Perform HTTPS checks with enhanced detection
            https_info = await self._check_https_accessibility(domain.name, config.timeout)

            # Calculate score based on HTTPS configuration
            score = self._calculate_https_score(https_info)

            # Prepare technical details
            details = self._prepare_details(https_info)

            return self._create_result(domain, score, details)

        except Exception as e:
            return self._create_result(
                domain,
                0.0,
                {"error": str(e), "analysis": "HTTPS connectivity check failed"},
                error=str(e)
            )

    async def _check_https_accessibility(self, hostname: str, timeout: int) -> dict[str, Any]:
        """Check HTTPS accessibility and HTTP redirect behavior with enhanced detection."""
        info = {
            "https_accessible": False,
            "https_status_code": None,
            "https_response_time_ms": 0,
            "https_final_url": None,
            "https_redirect_count": 0,
            "https_ssl_verified": False,
            "http_accessible": False,
            "http_status_code": None,
            "http_response_time_ms": 0,
            "http_redirects_to_https": False,
            "http_final_url": None,
            "http_redirect_count": 0,
            "redirect_chain": [],
            "www_variant_tested": False,
            "www_https_accessible": False,
            "security_assessment": {},
            "errors": []
        }

        # Enhanced timeout configuration
        timeout_config = aiohttp.ClientTimeout(
            total=timeout,
            connect=min(timeout, 10),
            sock_read=min(timeout, 15)
        )

        # Custom SSL context for better compatibility
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Custom connector for better error handling
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=10,
            limit_per_host=5,
            ttl_dns_cache=300,
            use_dns_cache=True,
            enable_cleanup_closed=True
        )

        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                connector=connector,
                headers={'User-Agent': 'DQIX-Security-Scanner/1.0'}
            ) as session:
                # Test primary domain variants
                await self._test_domain_variants(session, hostname, info)

                # Perform security assessment
                info["security_assessment"] = self._assess_https_security(info)

        except Exception as e:
            info["errors"].append(f"Connection setup error: {str(e)}")
        finally:
            if connector:
                await connector.close()

        return info

    async def _test_domain_variants(self, session: aiohttp.ClientSession, hostname: str, info: dict[str, Any]):
        """Test multiple domain variants for better coverage."""
        # Test primary domain
        await self._test_https_endpoint(session, hostname, info, is_primary=True)
        await self._test_http_redirect(session, hostname, info, is_primary=True)

        # Test www variant if primary domain fails or for comprehensive analysis
        if not info.get("https_accessible") or hostname.startswith("www."):
            www_hostname = f"www.{hostname}" if not hostname.startswith("www.") else hostname[4:]
            if www_hostname != hostname:
                info["www_variant_tested"] = True
                www_info = {}
                await self._test_https_endpoint(session, www_hostname, www_info, is_primary=False)

                # If www variant is accessible but primary isn't, update primary status
                if www_info.get("https_accessible") and not info.get("https_accessible"):
                    info["www_https_accessible"] = True
                    info["https_accessible"] = True
                    info["https_status_code"] = www_info.get("https_status_code")
                    info["https_response_time_ms"] = www_info.get("https_response_time_ms", 0)
                    info["https_final_url"] = www_info.get("https_final_url")
                    info["https_redirect_count"] = www_info.get("https_redirect_count", 0)

    async def _test_https_endpoint(self, session: aiohttp.ClientSession, hostname: str, info: dict[str, Any], is_primary: bool = True):
        """Test HTTPS endpoint accessibility with enhanced error handling."""
        result_key_prefix = "" if is_primary else "www_"

        url = f"https://{hostname}"

        try:
            start_time = time.time()

            async with session.get(url, allow_redirects=True, ssl=False) as response:
                end_time = time.time()

                if is_primary:
                    info["https_accessible"] = True
                    info["https_status_code"] = response.status
                    info["https_response_time_ms"] = int((end_time - start_time) * 1000)
                    info["https_final_url"] = str(response.url)
                    info["https_ssl_verified"] = True

                    # Count redirects
                    if hasattr(response, 'history'):
                        info["https_redirect_count"] = len(response.history)
                else:
                    info[f"{result_key_prefix}https_accessible"] = True
                    info[f"{result_key_prefix}https_status_code"] = response.status
                    info[f"{result_key_prefix}https_response_time_ms"] = int((end_time - start_time) * 1000)

        except aiohttp.ClientSSLError as e:
            # SSL errors - try without SSL verification
            try:
                async with session.get(url, allow_redirects=True, ssl=False) as response:
                    end_time = time.time()
                    if is_primary:
                        info["https_accessible"] = True
                        info["https_status_code"] = response.status
                        info["https_response_time_ms"] = int((end_time - start_time) * 1000)
                        info["https_final_url"] = str(response.url)
                        info["https_ssl_verified"] = False
                        info["errors"].append(f"SSL certificate issue: {str(e)}")
            except Exception as ssl_retry_e:
                if is_primary:
                    info["errors"].append(f"HTTPS SSL error: {str(e)}, Retry failed: {str(ssl_retry_e)}")
        except aiohttp.ClientConnectorError as e:
            if is_primary:
                info["errors"].append(f"HTTPS connection error: {str(e)}")
        except asyncio.TimeoutError:
            if is_primary:
                info["errors"].append(f"HTTPS timeout after {session.timeout.total}s")
        except Exception as e:
            if is_primary:
                info["errors"].append(f"HTTPS error: {str(e)}")

    async def _test_http_redirect(self, session: aiohttp.ClientSession, hostname: str, info: dict[str, Any], is_primary: bool = True):
        """Test HTTP endpoint and check for HTTPS redirect with enhanced detection."""
        if not is_primary:
            return

        url = f"http://{hostname}"

        try:
            start_time = time.time()

            # Use a custom session for HTTP to avoid SSL context issues
            http_connector = aiohttp.TCPConnector(
                limit=5,
                limit_per_host=3,
                ttl_dns_cache=300,
                use_dns_cache=True
            )

            async with aiohttp.ClientSession(
                connector=http_connector,
                timeout=session.timeout,
                headers={'User-Agent': 'DQIX-Security-Scanner/1.0'}
            ) as http_session:
                async with http_session.get(url, allow_redirects=True) as response:
                    end_time = time.time()

                    info["http_accessible"] = True
                    info["http_status_code"] = response.status
                    info["http_response_time_ms"] = int((end_time - start_time) * 1000)
                    info["http_final_url"] = str(response.url)

                    # Enhanced redirect analysis
                    if hasattr(response, 'history') and response.history:
                        info["http_redirect_count"] = len(response.history)
                        info["redirect_chain"] = []

                        # Build complete redirect chain
                        for redirect in response.history:
                            info["redirect_chain"].append({
                                "url": str(redirect.url),
                                "status": redirect.status,
                                "is_https": str(redirect.url).startswith("https://")
                            })

                        # Add final URL
                        info["redirect_chain"].append({
                            "url": str(response.url),
                            "status": response.status,
                            "is_https": str(response.url).startswith("https://")
                        })

                        # Check if any redirect or final URL is HTTPS
                        info["http_redirects_to_https"] = str(response.url).startswith("https://")
                    else:
                        # No redirects, check if somehow ended up on HTTPS
                        info["http_redirects_to_https"] = str(response.url).startswith("https://")
                        if info["http_redirects_to_https"]:
                            info["redirect_chain"] = [{
                                "url": str(response.url),
                                "status": response.status,
                                "is_https": True
                            }]

                await http_connector.close()

        except aiohttp.ClientConnectorError as e:
            info["errors"].append(f"HTTP connection error: {str(e)}")
        except asyncio.TimeoutError:
            info["errors"].append(f"HTTP timeout after {session.timeout.total}s")
        except Exception as e:
            info["errors"].append(f"HTTP error: {str(e)}")

    def _assess_https_security(self, info: dict[str, Any]) -> dict[str, Any]:
        """Assess overall HTTPS security configuration with enhanced scoring."""
        assessment = {
            "security_score": 0,
            "security_level": "poor",
            "findings": [],
            "recommendations": [],
            "compliance_status": {}
        }

        # HTTPS Accessibility (50 points - increased weight)
        if info.get("https_accessible"):
            base_score = 40
            if info.get("https_ssl_verified"):
                base_score += 10  # Bonus for verified SSL
                assessment["findings"].append("✅ HTTPS is accessible with valid SSL")
            else:
                assessment["findings"].append("⚠️ HTTPS is accessible but SSL has issues")

            assessment["security_score"] += base_score

            # Response time assessment
            response_time = info.get("https_response_time_ms", 0)
            if response_time < 1000:
                assessment["findings"].append(f"✅ Fast HTTPS response ({response_time}ms)")
            elif response_time < 3000:
                assessment["findings"].append(f"⚠️ Moderate HTTPS response time ({response_time}ms)")
            else:
                assessment["findings"].append(f"❌ Slow HTTPS response time ({response_time}ms)")

            # Check www variant accessibility
            if info.get("www_https_accessible"):
                assessment["findings"].append("✅ WWW variant also accessible via HTTPS")

        else:
            assessment["findings"].append("❌ HTTPS is not accessible")
            assessment["recommendations"].append("Enable HTTPS on your domain")

            # Check if www variant works
            if info.get("www_https_accessible"):
                assessment["security_score"] += 25  # Partial credit
                assessment["findings"].append("⚠️ HTTPS works for www variant only")
                assessment["recommendations"].append("Configure HTTPS for both domain and www variant")

        # HTTP to HTTPS Redirect (30 points)
        if info.get("http_redirects_to_https"):
            assessment["security_score"] += 30
            assessment["findings"].append("✅ HTTP redirects to HTTPS")

            # Analyze redirect efficiency
            redirect_count = info.get("http_redirect_count", 0)
            if redirect_count == 1:
                assessment["findings"].append("✅ Direct HTTP to HTTPS redirect")
            elif redirect_count > 1:
                assessment["findings"].append(f"⚠️ Multiple redirects ({redirect_count} hops)")
                assessment["recommendations"].append("Optimize redirect chain for better performance")

        else:
            if info.get("http_accessible"):
                assessment["findings"].append("❌ HTTP does not redirect to HTTPS")
                assessment["recommendations"].append("Configure HTTP to HTTPS redirect")
            else:
                assessment["findings"].append("⚠️ HTTP is not accessible")

        # Status Code Analysis (20 points)
        https_status = info.get("https_status_code")
        if https_status == 200:
            assessment["security_score"] += 20
            assessment["findings"].append("✅ HTTPS returns successful response (200)")
        elif https_status and 200 <= https_status < 300:
            assessment["security_score"] += 15
            assessment["findings"].append(f"✅ HTTPS returns success response ({https_status})")
        elif https_status and 300 <= https_status < 400:
            assessment["security_score"] += 10
            assessment["findings"].append(f"⚠️ HTTPS returns redirect response ({https_status})")
        elif https_status:
            assessment["findings"].append(f"❌ HTTPS returns error response ({https_status})")

        # Determine security level
        score = assessment["security_score"]
        if score >= 90:
            assessment["security_level"] = "excellent"
        elif score >= 70:
            assessment["security_level"] = "good"
        elif score >= 50:
            assessment["security_level"] = "fair"
        else:
            assessment["security_level"] = "poor"

        # Enhanced compliance status
        assessment["compliance_status"] = {
            "https_accessible": info.get("https_accessible", False),
            "ssl_verified": info.get("https_ssl_verified", False),
            "enforces_https": info.get("http_redirects_to_https", False),
            "www_support": info.get("www_https_accessible", False),
            "basic_security": info.get("https_accessible", False) and info.get("http_redirects_to_https", False)
        }

        return assessment

    def _calculate_https_score(self, info: dict[str, Any]) -> float:
        """Calculate HTTPS score (0.0 to 1.0)."""
        security_score = info.get("security_assessment", {}).get("security_score", 0)
        return min(1.0, security_score / 100.0)

    def _prepare_details(self, info: dict[str, Any]) -> dict[str, Any]:
        """Prepare detailed technical information."""
        return {
            "https_accessible": info.get("https_accessible", False),
            "https_status_code": info.get("https_status_code"),
            "https_response_time_ms": info.get("https_response_time_ms", 0),
            "http_redirects_to_https": info.get("http_redirects_to_https", False),
            "http_status_code": info.get("http_status_code"),
            "redirect_analysis": {
                "http_redirect_count": info.get("http_redirect_count", 0),
                "https_redirect_count": info.get("https_redirect_count", 0),
                "redirect_chain": info.get("redirect_chain", []),
                "final_urls": {
                    "http": info.get("http_final_url"),
                    "https": info.get("https_final_url")
                }
            },
            "security_assessment": info.get("security_assessment", {}),
            "performance": {
                "https_response_time_ms": info.get("https_response_time_ms", 0),
                "http_response_time_ms": info.get("http_response_time_ms", 0)
            },
            "errors": info.get("errors", [])
        }
