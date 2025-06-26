"""Enhanced Security Headers probe with comprehensive technical analysis."""

import aiohttp
import re
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class SecurityHeadersProbe(BaseProbe):
    """Comprehensive HTTP security headers analysis."""
    
    def __init__(self):
        super().__init__("security_headers", ProbeCategory.SECURITY)
    
    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Perform comprehensive security headers analysis."""
        try:
            # Collect security headers information from multiple endpoints
            headers_info = await self._collect_headers_info(domain.name, config.timeout)
            
            # Calculate detailed score
            score = self._calculate_comprehensive_score(headers_info)
            
            # Prepare detailed technical information
            details = self._prepare_technical_details(headers_info)
            
            return self._create_result(domain, score, details)
            
        except Exception as e:
            return self._create_result(
                domain, 
                0.0, 
                {"error": str(e), "analysis": "HTTP headers analysis failed"}, 
                error=str(e)
            )
    
    async def _collect_headers_info(self, hostname: str, timeout: int) -> Dict[str, Any]:
        """Collect comprehensive HTTP security headers information."""
        headers_info = {
            "https_response": {},
            "http_response": {},
            "security_headers": {},
            "header_analysis": {},
            "security_assessment": {},
            "recommendations": []
        }
        
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout_config) as session:
                # Test HTTPS endpoint
                headers_info["https_response"] = await self._test_endpoint(
                    session, f"https://{hostname}", "HTTPS"
                )
                
                # Test HTTP endpoint (to check for redirects)
                headers_info["http_response"] = await self._test_endpoint(
                    session, f"http://{hostname}", "HTTP"
                )
                
                # Analyze security headers from HTTPS response
                if headers_info["https_response"].get("headers"):
                    headers_info["security_headers"] = self._analyze_security_headers(
                        headers_info["https_response"]["headers"]
                    )
                    
                    # Perform comprehensive header analysis
                    headers_info["header_analysis"] = self._perform_header_analysis(
                        headers_info["https_response"]["headers"]
                    )
                    
                    # Generate security assessment
                    headers_info["security_assessment"] = self._assess_security_posture(
                        headers_info
                    )
                    
                    # Generate recommendations
                    headers_info["recommendations"] = self._generate_recommendations(
                        headers_info
                    )
                
        except Exception as e:
            headers_info["error"] = str(e)
        
        return headers_info
    
    async def _test_endpoint(self, session: aiohttp.ClientSession, url: str, protocol: str) -> Dict[str, Any]:
        """Test individual endpoint and collect response information."""
        endpoint_info = {
            "url": url,
            "protocol": protocol,
            "accessible": False,
            "status_code": None,
            "headers": {},
            "redirect_info": {},
            "response_time_ms": 0,
            "error": None
        }
        
        try:
            import time
            start_time = time.time()
            
            async with session.get(url, allow_redirects=True) as response:
                end_time = time.time()
                
                endpoint_info["accessible"] = True
                endpoint_info["status_code"] = response.status
                endpoint_info["headers"] = dict(response.headers)
                endpoint_info["response_time_ms"] = int((end_time - start_time) * 1000)
                
                # Analyze redirects
                if hasattr(response, 'history') and response.history:
                    endpoint_info["redirect_info"] = {
                        "redirected": True,
                        "redirect_count": len(response.history),
                        "final_url": str(response.url),
                        "redirect_chain": [str(r.url) for r in response.history]
                    }
                else:
                    endpoint_info["redirect_info"] = {"redirected": False}
                
        except Exception as e:
            endpoint_info["error"] = str(e)
        
        return endpoint_info
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze all security-related headers comprehensively."""
        # Normalize header names to lowercase for comparison
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        security_analysis = {}
        
        # HSTS (HTTP Strict Transport Security)
        security_analysis["hsts"] = self._analyze_hsts_header(
            lower_headers.get("strict-transport-security")
        )
        
        # Content Security Policy
        security_analysis["csp"] = self._analyze_csp_header(
            lower_headers.get("content-security-policy")
        )
        
        # X-Frame-Options
        security_analysis["x_frame_options"] = self._analyze_frame_options_header(
            lower_headers.get("x-frame-options")
        )
        
        # X-Content-Type-Options
        security_analysis["x_content_type_options"] = self._analyze_content_type_options_header(
            lower_headers.get("x-content-type-options")
        )
        
        # X-XSS-Protection
        security_analysis["x_xss_protection"] = self._analyze_xss_protection_header(
            lower_headers.get("x-xss-protection")
        )
        
        # Referrer Policy
        security_analysis["referrer_policy"] = self._analyze_referrer_policy_header(
            lower_headers.get("referrer-policy")
        )
        
        # Permissions Policy (formerly Feature Policy)
        security_analysis["permissions_policy"] = self._analyze_permissions_policy_header(
            lower_headers.get("permissions-policy")
        )
        
        # Additional security headers
        security_analysis["additional_headers"] = self._analyze_additional_security_headers(lower_headers)
        
        return security_analysis
    
    def _analyze_hsts_header(self, hsts_value: Optional[str]) -> Dict[str, Any]:
        """Analyze HSTS header in detail."""
        if not hsts_value:
            return {
                "present": False,
                "score": 0,
                "issues": ["HSTS header missing - site vulnerable to SSL stripping attacks"],
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
            }
        
        analysis = {
            "present": True,
            "raw_value": hsts_value,
            "parsed": {},
            "score": 0,
            "issues": [],
            "strengths": []
        }
        
        # Parse HSTS directives
        directives = [d.strip() for d in hsts_value.split(';')]
        max_age = 0
        include_subdomains = False
        preload = False
        
        for directive in directives:
            if directive.startswith('max-age='):
                try:
                    max_age = int(directive.split('=')[1])
                    analysis["parsed"]["max_age"] = max_age
                except ValueError:
                    analysis["issues"].append("Invalid max-age value")
            elif directive.lower() == 'includesubdomains':
                include_subdomains = True
                analysis["parsed"]["include_subdomains"] = True
            elif directive.lower() == 'preload':
                preload = True
                analysis["parsed"]["preload"] = True
        
        # Scoring and assessment
        if max_age > 0:
            analysis["score"] += 40
            if max_age >= 31536000:  # 1 year
                analysis["score"] += 30
                analysis["strengths"].append("Long max-age (1+ year)")
            elif max_age >= 2592000:  # 30 days
                analysis["score"] += 20
                analysis["strengths"].append("Reasonable max-age (30+ days)")
            else:
                analysis["issues"].append("Short max-age - consider longer duration")
        else:
            analysis["issues"].append("Missing or invalid max-age")
        
        if include_subdomains:
            analysis["score"] += 20
            analysis["strengths"].append("Includes subdomains")
        else:
            analysis["issues"].append("Missing includeSubDomains directive")
        
        if preload:
            analysis["score"] += 10
            analysis["strengths"].append("Preload directive present")
        
        analysis["security_level"] = self._get_security_level(analysis["score"])
        return analysis
    
    def _analyze_csp_header(self, csp_value: Optional[str]) -> Dict[str, Any]:
        """Analyze Content Security Policy header in detail."""
        if not csp_value:
            return {
                "present": False,
                "score": 0,
                "issues": ["CSP header missing - site vulnerable to XSS and injection attacks"],
                "recommendation": "Implement Content Security Policy to prevent XSS attacks"
            }
        
        analysis = {
            "present": True,
            "raw_value": csp_value,
            "directives": {},
            "score": 0,
            "issues": [],
            "strengths": [],
            "unsafe_directives": []
        }
        
        # Parse CSP directives
        directives = [d.strip() for d in csp_value.split(';') if d.strip()]
        
        for directive in directives:
            parts = directive.split()
            if parts:
                directive_name = parts[0]
                directive_values = parts[1:] if len(parts) > 1 else []
                analysis["directives"][directive_name] = directive_values
                
                # Check for unsafe directives
                if "'unsafe-inline'" in directive_values:
                    analysis["unsafe_directives"].append(f"{directive_name}: 'unsafe-inline'")
                if "'unsafe-eval'" in directive_values:
                    analysis["unsafe_directives"].append(f"{directive_name}: 'unsafe-eval'")
                if "*" in directive_values:
                    analysis["unsafe_directives"].append(f"{directive_name}: wildcard (*)")
        
        # Scoring based on directive presence and safety
        base_score = 50  # Base score for having CSP
        analysis["score"] = base_score
        
        important_directives = ["default-src", "script-src", "style-src", "img-src"]
        for directive in important_directives:
            if directive in analysis["directives"]:
                analysis["score"] += 10
                analysis["strengths"].append(f"{directive} directive defined")
        
        # Deduct points for unsafe directives
        analysis["score"] -= len(analysis["unsafe_directives"]) * 15
        
        if analysis["unsafe_directives"]:
            analysis["issues"].extend(analysis["unsafe_directives"])
        else:
            analysis["strengths"].append("No unsafe directives detected")
        
        analysis["security_level"] = self._get_security_level(analysis["score"])
        return analysis
    
    def _analyze_frame_options_header(self, frame_options_value: Optional[str]) -> Dict[str, Any]:
        """Analyze X-Frame-Options header."""
        if not frame_options_value:
            return {
                "present": False,
                "score": 0,
                "issues": ["X-Frame-Options header missing - site vulnerable to clickjacking"],
                "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'"
            }
        
        analysis = {
            "present": True,
            "raw_value": frame_options_value,
            "score": 0,
            "issues": [],
            "strengths": []
        }
        
        value = frame_options_value.upper().strip()
        
        if value == "DENY":
            analysis["score"] = 100
            analysis["strengths"].append("Completely blocks framing (DENY)")
        elif value == "SAMEORIGIN":
            analysis["score"] = 90
            analysis["strengths"].append("Allows same-origin framing (SAMEORIGIN)")
        elif value.startswith("ALLOW-FROM"):
            analysis["score"] = 70
            analysis["strengths"].append("Allows specific origin framing")
            analysis["issues"].append("ALLOW-FROM is deprecated in modern browsers")
        else:
            analysis["score"] = 30
            analysis["issues"].append("Unrecognized X-Frame-Options value")
        
        analysis["security_level"] = self._get_security_level(analysis["score"])
        return analysis
    
    def _analyze_content_type_options_header(self, content_type_value: Optional[str]) -> Dict[str, Any]:
        """Analyze X-Content-Type-Options header."""
        if not content_type_value:
            return {
                "present": False,
                "score": 0,
                "issues": ["X-Content-Type-Options header missing - vulnerable to MIME sniffing"],
                "recommendation": "Add 'X-Content-Type-Options: nosniff'"
            }
        
        analysis = {
            "present": True,
            "raw_value": content_type_value,
            "score": 0,
            "issues": [],
            "strengths": []
        }
        
        if content_type_value.lower().strip() == "nosniff":
            analysis["score"] = 100
            analysis["strengths"].append("MIME sniffing disabled (nosniff)")
        else:
            analysis["score"] = 30
            analysis["issues"].append("Unexpected X-Content-Type-Options value")
        
        analysis["security_level"] = self._get_security_level(analysis["score"])
        return analysis
    
    def _analyze_xss_protection_header(self, xss_value: Optional[str]) -> Dict[str, Any]:
        """Analyze X-XSS-Protection header."""
        if not xss_value:
            return {
                "present": False,
                "score": 0,
                "issues": ["X-XSS-Protection header missing"],
                "recommendation": "Add 'X-XSS-Protection: 1; mode=block' (though CSP is preferred)"
            }
        
        analysis = {
            "present": True,
            "raw_value": xss_value,
            "score": 0,
            "issues": [],
            "strengths": [],
            "note": "X-XSS-Protection is deprecated; use CSP instead"
        }
        
        value = xss_value.lower().strip()
        
        if "1; mode=block" in value:
            analysis["score"] = 80
            analysis["strengths"].append("XSS filter enabled with blocking mode")
        elif value.startswith("1"):
            analysis["score"] = 60
            analysis["strengths"].append("XSS filter enabled")
        elif value == "0":
            analysis["score"] = 20
            analysis["issues"].append("XSS protection explicitly disabled")
        else:
            analysis["score"] = 30
            analysis["issues"].append("Unrecognized X-XSS-Protection value")
        
        analysis["security_level"] = self._get_security_level(analysis["score"])
        return analysis
    
    def _analyze_referrer_policy_header(self, referrer_value: Optional[str]) -> Dict[str, Any]:
        """Analyze Referrer-Policy header."""
        if not referrer_value:
            return {
                "present": False,
                "score": 0,
                "issues": ["Referrer-Policy header missing - may leak sensitive URLs"],
                "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
            }
        
        analysis = {
            "present": True,
            "raw_value": referrer_value,
            "score": 0,
            "issues": [],
            "strengths": []
        }
        
        value = referrer_value.lower().strip()
        
        policy_scores = {
            "no-referrer": 100,
            "no-referrer-when-downgrade": 70,
            "origin": 80,
            "origin-when-cross-origin": 85,
            "same-origin": 90,
            "strict-origin": 95,
            "strict-origin-when-cross-origin": 90,
            "unsafe-url": 20
        }
        
        if value in policy_scores:
            analysis["score"] = policy_scores[value]
            if value == "unsafe-url":
                analysis["issues"].append("Unsafe referrer policy - sends full URL")
            else:
                analysis["strengths"].append(f"Good referrer policy: {value}")
        else:
            analysis["score"] = 30
            analysis["issues"].append("Unrecognized referrer policy")
        
        analysis["security_level"] = self._get_security_level(analysis["score"])
        return analysis
    
    def _analyze_permissions_policy_header(self, permissions_value: Optional[str]) -> Dict[str, Any]:
        """Analyze Permissions-Policy header."""
        if not permissions_value:
            return {
                "present": False,
                "score": 0,
                "issues": ["Permissions-Policy header missing"],
                "recommendation": "Consider adding Permissions-Policy to control browser features"
            }
        
        analysis = {
            "present": True,
            "raw_value": permissions_value,
            "directives": {},
            "score": 50,  # Base score for having the header
            "issues": [],
            "strengths": ["Permissions policy configured"]
        }
        
        # Parse permissions policy (simplified)
        try:
            directives = [d.strip() for d in permissions_value.split(',')]
            for directive in directives:
                if '=' in directive:
                    feature, allowlist = directive.split('=', 1)
                    analysis["directives"][feature.strip()] = allowlist.strip()
            
            analysis["score"] += min(len(analysis["directives"]) * 5, 50)
        except Exception:
            analysis["issues"].append("Could not parse permissions policy")
            analysis["score"] = 30
        
        analysis["security_level"] = self._get_security_level(analysis["score"])
        return analysis
    
    def _analyze_additional_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze additional security-related headers."""
        additional = {
            "server_header": self._analyze_server_header(headers.get("server")),
            "x_powered_by": self._analyze_powered_by_header(headers.get("x-powered-by")),
            "expect_ct": self._analyze_expect_ct_header(headers.get("expect-ct")),
            "cross_origin_headers": self._analyze_cross_origin_headers(headers)
        }
        
        return additional
    
    def _analyze_server_header(self, server_value: Optional[str]) -> Dict[str, Any]:
        """Analyze Server header for information disclosure."""
        if not server_value:
            return {
                "present": False,
                "score": 100,
                "strengths": ["Server header not disclosed (good for security)"]
            }
        
        return {
            "present": True,
            "raw_value": server_value,
            "score": 30,
            "issues": ["Server information disclosed - consider removing or obfuscating"],
            "recommendation": "Remove or obfuscate server header to reduce information disclosure"
        }
    
    def _analyze_powered_by_header(self, powered_by_value: Optional[str]) -> Dict[str, Any]:
        """Analyze X-Powered-By header for information disclosure."""
        if not powered_by_value:
            return {
                "present": False,
                "score": 100,
                "strengths": ["X-Powered-By header not disclosed (good for security)"]
            }
        
        return {
            "present": True,
            "raw_value": powered_by_value,
            "score": 20,
            "issues": ["Technology stack disclosed - consider removing"],
            "recommendation": "Remove X-Powered-By header to reduce information disclosure"
        }
    
    def _analyze_expect_ct_header(self, expect_ct_value: Optional[str]) -> Dict[str, Any]:
        """Analyze Expect-CT header."""
        if not expect_ct_value:
            return {
                "present": False,
                "score": 0,
                "note": "Expect-CT header missing (optional but recommended for CT monitoring)"
            }
        
        return {
            "present": True,
            "raw_value": expect_ct_value,
            "score": 80,
            "strengths": ["Certificate Transparency monitoring enabled"]
        }
    
    def _analyze_cross_origin_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze CORS and cross-origin related headers."""
        cors_headers = {}
        
        cors_related = [
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-allow-credentials",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "cross-origin-resource-policy"
        ]
        
        for header in cors_related:
            if header in headers:
                cors_headers[header] = {
                    "present": True,
                    "value": headers[header]
                }
                
                # Basic security assessment for dangerous CORS configs
                if header == "access-control-allow-origin" and headers[header] == "*":
                    cors_headers[header]["security_issue"] = "Wildcard CORS policy - potential security risk"
        
        return cors_headers
    
    def _perform_header_analysis(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Perform comprehensive header analysis."""
        analysis = {
            "total_headers": len(headers),
            "security_headers_count": 0,
            "information_disclosure": [],
            "missing_security_headers": [],
            "header_categories": {
                "security": [],
                "caching": [],
                "content": [],
                "server_info": [],
                "other": []
            }
        }
        
        # Categorize headers
        security_headers = [
            "strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options", "x-xss-protection", "referrer-policy",
            "permissions-policy", "expect-ct"
        ]
        
        caching_headers = [
            "cache-control", "expires", "etag", "last-modified", "vary"
        ]
        
        content_headers = [
            "content-type", "content-length", "content-encoding", "content-language"
        ]
        
        server_info_headers = [
            "server", "x-powered-by", "x-aspnet-version", "x-generator"
        ]
        
        for header_name in headers.keys():
            lower_header = header_name.lower()
            
            if lower_header in security_headers:
                analysis["header_categories"]["security"].append(header_name)
                analysis["security_headers_count"] += 1
            elif lower_header in caching_headers:
                analysis["header_categories"]["caching"].append(header_name)
            elif lower_header in content_headers:
                analysis["header_categories"]["content"].append(header_name)
            elif lower_header in server_info_headers:
                analysis["header_categories"]["server_info"].append(header_name)
                analysis["information_disclosure"].append(f"{header_name}: {headers[header_name]}")
            else:
                analysis["header_categories"]["other"].append(header_name)
        
        # Check for missing critical security headers
        for security_header in security_headers[:6]:  # First 6 are most critical
            if security_header not in [h.lower() for h in headers.keys()]:
                analysis["missing_security_headers"].append(security_header)
        
        return analysis
    
    def _assess_security_posture(self, headers_info: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall security posture based on headers."""
        assessment = {
            "overall_score": 0,
            "security_level": "poor",
            "critical_issues": [],
            "warnings": [],
            "strengths": [],
            "compliance_indicators": {}
        }
        
        if "security_headers" in headers_info:
            security_headers = headers_info["security_headers"]
            
            # Calculate weighted score
            weights = {
                "hsts": 0.25,
                "csp": 0.25,
                "x_frame_options": 0.15,
                "x_content_type_options": 0.15,
                "x_xss_protection": 0.10,
                "referrer_policy": 0.10
            }
            
            total_score = 0
            for header, weight in weights.items():
                if header in security_headers:
                    header_score = security_headers[header].get("score", 0)
                    total_score += (header_score / 100) * weight
            
            assessment["overall_score"] = min(100, int(total_score * 100))
            
            # Determine security level
            if assessment["overall_score"] >= 80:
                assessment["security_level"] = "excellent"
            elif assessment["overall_score"] >= 60:
                assessment["security_level"] = "good"
            elif assessment["overall_score"] >= 40:
                assessment["security_level"] = "fair"
            else:
                assessment["security_level"] = "poor"
            
            # Identify critical issues
            for header_name, header_data in security_headers.items():
                if not header_data.get("present", False):
                    if header_name in ["hsts", "csp"]:
                        assessment["critical_issues"].append(f"Missing critical header: {header_name}")
                    else:
                        assessment["warnings"].append(f"Missing security header: {header_name}")
                elif header_data.get("issues"):
                    assessment["warnings"].extend(header_data["issues"])
                
                if header_data.get("strengths"):
                    assessment["strengths"].extend(header_data["strengths"])
        
        return assessment
    
    def _generate_recommendations(self, headers_info: Dict[str, Any]) -> List[str]:
        """Generate specific recommendations for improving security headers."""
        recommendations = []
        
        if "security_headers" in headers_info:
            security_headers = headers_info["security_headers"]
            
            # HSTS recommendations
            if not security_headers.get("hsts", {}).get("present"):
                recommendations.append("Implement HSTS: Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'")
            
            # CSP recommendations
            if not security_headers.get("csp", {}).get("present"):
                recommendations.append("Implement CSP: Add Content-Security-Policy header to prevent XSS attacks")
            elif security_headers.get("csp", {}).get("unsafe_directives"):
                recommendations.append("Remove unsafe CSP directives like 'unsafe-inline' and 'unsafe-eval'")
            
            # Frame options
            if not security_headers.get("x_frame_options", {}).get("present"):
                recommendations.append("Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking")
            
            # Content type options
            if not security_headers.get("x_content_type_options", {}).get("present"):
                recommendations.append("Add X-Content-Type-Options: nosniff to prevent MIME sniffing")
            
            # Referrer policy
            if not security_headers.get("referrer_policy", {}).get("present"):
                recommendations.append("Add Referrer-Policy: strict-origin-when-cross-origin")
        
        # Information disclosure recommendations
        if "header_analysis" in headers_info:
            if headers_info["header_analysis"].get("information_disclosure"):
                recommendations.append("Remove or obfuscate server information headers (Server, X-Powered-By)")
        
        return recommendations
    
    def _get_security_level(self, score: int) -> str:
        """Convert numeric score to security level."""
        if score >= 90:
            return "excellent"
        elif score >= 70:
            return "good"
        elif score >= 50:
            return "fair"
        else:
            return "poor"
    
    def _calculate_comprehensive_score(self, headers_info: Dict[str, Any]) -> float:
        """Calculate comprehensive security headers score."""
        if "security_assessment" in headers_info:
            return headers_info["security_assessment"]["overall_score"] / 100.0
        return 0.0
    
    def _prepare_technical_details(self, headers_info: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare comprehensive technical details for output."""
        return {
            "https_accessible": headers_info.get("https_response", {}).get("accessible", False),
            "http_redirects_to_https": self._check_http_redirect(headers_info),
            "response_time_ms": headers_info.get("https_response", {}).get("response_time_ms", 0),
            "security_headers_analysis": headers_info.get("security_headers", {}),
            "header_statistics": headers_info.get("header_analysis", {}),
            "security_assessment": headers_info.get("security_assessment", {}),
            "recommendations": headers_info.get("recommendations", []),
            "raw_headers": headers_info.get("https_response", {}).get("headers", {})
        }
    
    def _check_http_redirect(self, headers_info: Dict[str, Any]) -> bool:
        """Check if HTTP redirects to HTTPS."""
        http_response = headers_info.get("http_response", {})
        if http_response.get("redirect_info", {}).get("redirected"):
            final_url = http_response["redirect_info"].get("final_url", "")
            return final_url.startswith("https://")
        return False 