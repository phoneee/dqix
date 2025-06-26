"""Enhanced TLS/SSL security probe with comprehensive technical details."""

import datetime
import socket
import ssl
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult
from .base import BaseProbe


class TLSProbe(BaseProbe):
    """Comprehensive TLS/SSL configuration analysis."""

    def __init__(self) -> None:
        super().__init__("tls", ProbeCategory.SECURITY)

    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Perform comprehensive TLS analysis for domain."""
        try:
            # Collect TLS information
            tls_info = await self._collect_tls_info(domain.name, config.timeout)

            # Calculate detailed score
            score = self._calculate_comprehensive_score(tls_info)

            # Prepare detailed technical information
            details = self._prepare_technical_details(tls_info)

            return self._create_result(domain, score, details)

        except Exception as e:
            return self._create_result(
                domain,
                0.0,
                {"error": str(e), "analysis": "TLS connection failed"},
                error=str(e)
            )

    async def _collect_tls_info(self, hostname: str, timeout: int) -> dict[str, Any]:
        """Collect comprehensive TLS information."""
        tls_info = {}

        try:
            # Test multiple TLS versions for comprehensive analysis
            tls_info["supported_versions"] = self._test_tls_versions(hostname, timeout)

            # Get detailed certificate information using best available TLS version
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Basic SSL connection info
                    tls_info["protocol_version"] = ssock.version()
                    tls_info["cipher_suite"] = ssock.cipher()
                    tls_info["compression"] = ssock.compression()

                    # Get certificate in both formats
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

                    # Parse certificate with cryptography library for detailed analysis
                    if cert_der and cert_dict:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        tls_info["certificate"] = self._analyze_certificate(cert, cert_dict)

                        # Certificate chain analysis
                        tls_info["certificate_chain"] = self._analyze_certificate_chain(ssock)

                        # Comprehensive security analysis
                        tls_info["security_analysis"] = self._analyze_security(tls_info)
                    else:
                        tls_info["certificate"] = {"error": "No certificate data available"}
                        tls_info["certificate_chain"] = {"error": "No certificate chain data"}
                        tls_info["security_analysis"] = {"error": "Cannot analyze without certificate"}

        except Exception as e:
            tls_info["error"] = str(e)

        return tls_info

    def _test_tls_versions(self, hostname: str, timeout: int) -> dict[str, Any]:
        """Test support for different TLS versions comprehensively."""
        version_results = {}

        # Define TLS versions to test
        tls_versions = [
            ("TLSv1.0", getattr(ssl, 'PROTOCOL_TLSv1', None)),
            ("TLSv1.1", getattr(ssl, 'PROTOCOL_TLSv1_1', None)),
            ("TLSv1.2", getattr(ssl, 'PROTOCOL_TLSv1_2', None)),
            ("TLSv1.3", None)  # Special handling for TLS 1.3
        ]

        for version_name, protocol in tls_versions:
            try:
                if version_name == "TLSv1.3":
                    # Test TLS 1.3 specifically
                    version_results[version_name] = self._test_tls13(hostname, timeout)
                elif protocol is not None:
                    # Test older TLS versions
                    version_results[version_name] = self._test_tls_version(hostname, timeout, protocol)
                else:
                    version_results[version_name] = {"supported": False, "reason": "Protocol not available"}
            except Exception as e:
                version_results[version_name] = {"supported": False, "error": str(e)}

        return version_results

    def _test_tls13(self, hostname: str, timeout: int) -> dict[str, Any]:
        """Test TLS 1.3 support specifically."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return {
                        "supported": True,
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "compression": ssock.compression()
                    }
        except Exception as e:
            return {"supported": False, "error": str(e)}

    def _test_tls_version(self, hostname: str, timeout: int, protocol) -> dict[str, Any]:
        """Test specific TLS version support."""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return {
                        "supported": True,
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "compression": ssock.compression()
                    }
        except Exception as e:
            return {"supported": False, "error": str(e)}

    def _analyze_certificate(self, cert: x509.Certificate, cert_dict: dict[str, Any]) -> dict[str, Any]:
        """Analyze certificate details comprehensively."""
        cert_info = {
            # Basic certificate information
            "subject": self._format_name(cert.subject),
            "issuer": self._format_name(cert.issuer),
            "serial_number": str(cert.serial_number),
            "version": cert.version.name,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),

            # Validity period analysis
            "validity": {
                "not_before": self._safe_datetime_format(cert.not_valid_before_utc),
                "not_after": self._safe_datetime_format(cert.not_valid_after_utc),
                "validity_period_days": self._safe_datetime_diff_days(cert.not_valid_after_utc, cert.not_valid_before_utc),
                "days_until_expiry": self._safe_datetime_diff_days(cert.not_valid_after_utc, datetime.datetime.now(datetime.timezone.utc)),
                "is_expired": self._safe_datetime_compare(datetime.datetime.now(datetime.timezone.utc), cert.not_valid_after_utc),
                "expires_soon": self._safe_datetime_diff_days(cert.not_valid_after_utc, datetime.datetime.now(datetime.timezone.utc)) < 30,
                "expires_very_soon": self._safe_datetime_diff_days(cert.not_valid_after_utc, datetime.datetime.now(datetime.timezone.utc)) < 7
            },

            # Public key information
            "public_key": {
                "algorithm": self._get_key_algorithm(cert.public_key()),
                "size_bits": self._get_key_size(cert.public_key()),
                "is_weak": self._has_weak_key(cert),
                "details": self._get_key_details(cert.public_key())
            },

            # Signature algorithm analysis
            "signature": {
                "algorithm": cert.signature_algorithm_oid._name,
                "is_weak": self._has_weak_signature(cert),
                "hash_algorithm": self._get_hash_algorithm(cert)
            },

            # Extensions analysis
            "extensions": self._analyze_extensions(cert),

            # Subject Alternative Names
            "subject_alternative_names": self._extract_san(cert),

            # Certificate validation
            "validation": {
                "self_signed": self._is_self_signed(cert),
                "ca_certificate": self._is_ca_certificate(cert),
                "wildcard_certificate": self._is_wildcard_certificate(cert),
                "extended_validation": self._is_extended_validation(cert)
            },

            # Security assessment
            "security_assessment": {
                "weak_signature": self._has_weak_signature(cert),
                "weak_key": self._has_weak_key(cert),
                "deprecated_features": self._find_deprecated_features(cert),
                "security_score": self._calculate_certificate_security_score(cert)
            }
        }

        return cert_info

    def _format_name(self, name) -> dict[str, str]:
        """Format X.509 name to dictionary."""
        result = {}
        try:
            for attr in name:
                result[attr.oid._name] = attr.value
        except Exception:
            result = {"error": "Could not parse name"}
        return result

    def _get_key_algorithm(self, public_key) -> str:
        """Get public key algorithm name."""
        key_type = type(public_key).__name__
        return key_type.replace("PublicKey", "").replace("_", " ").title()

    def _get_key_size(self, public_key) -> Optional[int]:
        """Get public key size."""
        try:
            if hasattr(public_key, 'key_size'):
                return public_key.key_size
            elif hasattr(public_key, 'curve') and hasattr(public_key.curve, 'key_size'):
                return public_key.curve.key_size
        except Exception:
            pass
        return None

    def _get_key_details(self, public_key) -> dict[str, Any]:
        """Get detailed public key information."""
        details = {}
        try:
            key_type = type(public_key).__name__
            if "RSA" in key_type:
                details["type"] = "RSA"
                details["modulus_size"] = getattr(public_key, 'key_size', 0)
                details["public_exponent"] = getattr(public_key.public_numbers(), 'e', 0) if hasattr(public_key, 'public_numbers') else 0
            elif "EC" in key_type:
                details["type"] = "Elliptic Curve"
                if hasattr(public_key, 'curve'):
                    details["curve"] = public_key.curve.name
                    details["key_size"] = getattr(public_key.curve, 'key_size', 0)
            elif "DSA" in key_type:
                details["type"] = "DSA"
                details["key_size"] = getattr(public_key, 'key_size', 0)
            else:
                details["type"] = key_type
        except Exception as e:
            details["error"] = str(e)
        return details

    def _get_hash_algorithm(self, cert: x509.Certificate) -> str:
        """Extract hash algorithm from signature algorithm."""
        try:
            sig_alg = cert.signature_algorithm_oid._name.lower()
            if "sha256" in sig_alg:
                return "SHA-256"
            elif "sha384" in sig_alg:
                return "SHA-384"
            elif "sha512" in sig_alg:
                return "SHA-512"
            elif "sha1" in sig_alg:
                return "SHA-1"
            elif "md5" in sig_alg:
                return "MD5"
            else:
                return sig_alg.upper()
        except Exception:
            return "Unknown"

    def _analyze_extensions(self, cert: x509.Certificate) -> dict[str, Any]:
        """Analyze certificate extensions comprehensively."""
        extensions = {}

        try:
            for ext in cert.extensions:
                ext_name = ext.oid._name
                ext_info = {
                    "critical": ext.critical,
                    "value": str(ext.value)[:500]  # Limit length for readability
                }

                # Special handling for important extensions
                if ext_name == "subjectAltName":
                    ext_info["parsed_values"] = [str(name) for name in ext.value]
                elif ext_name == "keyUsage":
                    ext_info["key_usage_details"] = self._parse_key_usage(ext.value)
                elif ext_name == "extendedKeyUsage":
                    ext_info["extended_key_usage_details"] = self._parse_extended_key_usage(ext.value)
                elif ext_name == "basicConstraints":
                    ext_info["basic_constraints_details"] = self._parse_basic_constraints(ext.value)

                extensions[ext_name] = ext_info
        except Exception as e:
            extensions["error"] = str(e)

        return extensions

    def _parse_key_usage(self, key_usage) -> dict[str, bool]:
        """Parse key usage extension."""
        usage_flags = {}
        try:
            usage_flags["digital_signature"] = key_usage.digital_signature
            usage_flags["key_encipherment"] = key_usage.key_encipherment
            usage_flags["key_agreement"] = key_usage.key_agreement
            usage_flags["key_cert_sign"] = key_usage.key_cert_sign
            usage_flags["crl_sign"] = key_usage.crl_sign
            usage_flags["content_commitment"] = key_usage.content_commitment
            usage_flags["data_encipherment"] = key_usage.data_encipherment
            usage_flags["encipher_only"] = key_usage.encipher_only
            usage_flags["decipher_only"] = key_usage.decipher_only
        except Exception:
            pass
        return usage_flags

    def _parse_extended_key_usage(self, ext_key_usage) -> list[str]:
        """Parse extended key usage extension."""
        try:
            return [str(usage) for usage in ext_key_usage]
        except Exception:
            return []

    def _parse_basic_constraints(self, basic_constraints) -> dict[str, Any]:
        """Parse basic constraints extension."""
        try:
            return {
                "ca": basic_constraints.ca,
                "path_length": basic_constraints.path_length
            }
        except Exception:
            return {}

    def _extract_san(self, cert: x509.Certificate) -> list[str]:
        """Extract Subject Alternative Names."""
        try:
            for ext in cert.extensions:
                if ext.oid._name == "subjectAltName":
                    return [str(name) for name in ext.value]
        except Exception:
            pass
        return []

    def _is_self_signed(self, cert: x509.Certificate) -> bool:
        """Check if certificate is self-signed."""
        return cert.subject == cert.issuer

    def _is_ca_certificate(self, cert: x509.Certificate) -> bool:
        """Check if certificate is a CA certificate."""
        try:
            for ext in cert.extensions:
                if ext.oid._name == "basicConstraints":
                    return ext.value.ca
        except Exception:
            pass
        return False

    def _is_wildcard_certificate(self, cert: x509.Certificate) -> bool:
        """Check if certificate is a wildcard certificate."""
        try:
            # Check subject common name
            for attr in cert.subject:
                if attr.oid._name == "commonName" and attr.value.startswith("*."):
                    return True

            # Check SAN entries
            for san in self._extract_san(cert):
                if san.startswith("*."):
                    return True
        except Exception:
            pass
        return False

    def _is_extended_validation(self, cert: x509.Certificate) -> bool:
        """Check if certificate is Extended Validation (EV)."""
        try:
            # EV certificates typically have specific OIDs in certificate policies
            for ext in cert.extensions:
                if ext.oid._name == "certificatePolicies":
                    # This is a simplified check - real EV detection is more complex
                    policies_str = str(ext.value).lower()
                    if "extended validation" in policies_str or "ev" in policies_str:
                        return True
        except Exception:
            pass
        return False

    def _has_weak_signature(self, cert: x509.Certificate) -> bool:
        """Check if certificate has weak signature algorithm."""
        weak_algorithms = ["md5", "sha1"]
        sig_alg = cert.signature_algorithm_oid._name.lower()
        return any(weak in sig_alg for weak in weak_algorithms)

    def _has_weak_key(self, cert: x509.Certificate) -> bool:
        """Check if certificate has weak public key."""
        try:
            public_key = cert.public_key()
            key_size = self._get_key_size(public_key)
            key_type = type(public_key).__name__

            if "RSA" in key_type and key_size and key_size < 2048:
                return True
            elif "DSA" in key_type and key_size and key_size < 2048:
                return True
            elif "EC" in key_type and key_size and key_size < 256:
                return True
        except Exception:
            pass
        return False

    def _find_deprecated_features(self, cert: x509.Certificate) -> list[str]:
        """Find deprecated features in certificate."""
        deprecated = []

        try:
            # Check for deprecated signature algorithms
            if self._has_weak_signature(cert):
                deprecated.append("Weak signature algorithm")

            # Check for weak keys
            if self._has_weak_key(cert):
                deprecated.append("Weak public key")

            # Check for deprecated extensions or values
            # This can be expanded based on current security standards

        except Exception:
            pass

        return deprecated

    def _calculate_certificate_security_score(self, cert: x509.Certificate) -> int:
        """Calculate security score for certificate (0-100)."""
        score = 100

        # Deduct points for security issues
        if self._has_weak_signature(cert):
            score -= 30
        if self._has_weak_key(cert):
            score -= 25
        if self._is_self_signed(cert):
            score -= 20
        if len(self._find_deprecated_features(cert)) > 0:
            score -= 15

        # Check expiry
        days_until_expiry = self._safe_datetime_diff_days(cert.not_valid_after_utc, datetime.datetime.now(datetime.timezone.utc))
        if days_until_expiry < 7:
            score -= 40
        elif days_until_expiry < 30:
            score -= 20

        return max(0, score)

    def _analyze_certificate_chain(self, ssock) -> dict[str, Any]:
        """Analyze certificate chain if available."""
        chain_info = {
            "chain_length": 0,
            "certificates": [],
            "root_ca_trusted": False,
            "intermediate_cas": []
        }

        try:
            # Get certificate chain
            cert_chain = ssock.getpeercert_chain()
            if cert_chain:
                chain_info["chain_length"] = len(cert_chain)

                for i, cert_der in enumerate(cert_chain):
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    cert_info = {
                        "position": i,
                        "subject": self._format_name(cert.subject),
                        "issuer": self._format_name(cert.issuer),
                        "is_ca": self._is_ca_certificate(cert),
                        "is_self_signed": self._is_self_signed(cert)
                    }
                    chain_info["certificates"].append(cert_info)

                    if i > 0 and i < len(cert_chain) - 1:  # Intermediate certificates
                        chain_info["intermediate_cas"].append(cert_info["subject"])
        except Exception as e:
            chain_info["error"] = str(e)

        return chain_info

    def _analyze_security(self, tls_info: dict[str, Any]) -> dict[str, Any]:
        """Perform comprehensive security analysis."""
        security = {
            "protocol_security": {},
            "cipher_security": {},
            "certificate_security": {},
            "vulnerabilities": [],
            "recommendations": [],
            "overall_security_level": "unknown"
        }

        # Protocol security analysis
        protocol_version = tls_info.get("protocol_version")
        if protocol_version:
            security["protocol_security"] = {
                "version": protocol_version,
                "is_modern": protocol_version in ["TLSv1.2", "TLSv1.3"],
                "is_deprecated": protocol_version in ["TLSv1.0", "TLSv1.1"],
                "security_level": self._get_protocol_security_level(protocol_version)
            }

            if protocol_version in ["TLSv1.0", "TLSv1.1"]:
                security["vulnerabilities"].append(f"Deprecated TLS version: {protocol_version}")
                security["recommendations"].append("Upgrade to TLS 1.2 or 1.3")

        # Cipher security analysis
        cipher_suite = tls_info.get("cipher_suite")
        if cipher_suite:
            security["cipher_security"] = {
                "cipher_name": cipher_suite[0] if cipher_suite else "Unknown",
                "is_secure": self._is_secure_cipher(cipher_suite),
                "key_exchange": self._get_key_exchange_method(cipher_suite),
                "encryption_algorithm": self._get_encryption_algorithm(cipher_suite),
                "mac_algorithm": self._get_mac_algorithm(cipher_suite),
                "security_level": self._get_cipher_security_level(cipher_suite)
            }

            if not self._is_secure_cipher(cipher_suite):
                security["vulnerabilities"].append("Weak cipher suite detected")
                security["recommendations"].append("Configure stronger cipher suites")

        # Certificate security analysis
        certificate = tls_info.get("certificate", {})
        if certificate and "error" not in certificate:
            cert_security = certificate.get("security_assessment", {})
            security["certificate_security"] = {
                "security_score": cert_security.get("security_score", 0),
                "has_weak_signature": cert_security.get("weak_signature", False),
                "has_weak_key": cert_security.get("weak_key", False),
                "deprecated_features": cert_security.get("deprecated_features", []),
                "expires_soon": certificate.get("validity", {}).get("expires_soon", False)
            }

            if cert_security.get("weak_signature"):
                security["vulnerabilities"].append("Certificate uses weak signature algorithm")
            if cert_security.get("weak_key"):
                security["vulnerabilities"].append("Certificate uses weak public key")
            if certificate.get("validity", {}).get("expires_soon"):
                security["vulnerabilities"].append("Certificate expires soon")
                security["recommendations"].append("Renew certificate before expiration")

        # Determine overall security level
        vuln_count = len(security["vulnerabilities"])
        if vuln_count == 0 and security["protocol_security"].get("is_modern", False):
            security["overall_security_level"] = "excellent"
        elif vuln_count <= 1 and security["protocol_security"].get("is_modern", False):
            security["overall_security_level"] = "good"
        elif vuln_count <= 3:
            security["overall_security_level"] = "fair"
        else:
            security["overall_security_level"] = "poor"

        return security

    def _get_protocol_security_level(self, protocol: str) -> str:
        """Get security level for TLS protocol version."""
        if protocol == "TLSv1.3":
            return "excellent"
        elif protocol == "TLSv1.2":
            return "good"
        elif protocol in ["TLSv1.1", "TLSv1.0"]:
            return "poor"
        else:
            return "unknown"

    def _get_cipher_security_level(self, cipher) -> str:
        """Get security level for cipher suite."""
        if not cipher:
            return "unknown"

        cipher_name = cipher[0] if isinstance(cipher, (tuple, list)) else str(cipher)
        cipher_name = cipher_name.upper()

        # Modern, secure ciphers
        if any(secure in cipher_name for secure in ["AES_256_GCM", "CHACHA20_POLY1305", "AES_128_GCM"]):
            return "excellent"
        elif any(good in cipher_name for good in ["AES_256", "AES_128"]):
            return "good"
        elif any(weak in cipher_name for weak in ["RC4", "DES", "NULL", "MD5"]):
            return "poor"
        else:
            return "fair"

    def _get_key_exchange_method(self, cipher) -> str:
        """Extract key exchange method from cipher suite."""
        if not cipher:
            return "Unknown"

        cipher_name = cipher[0] if isinstance(cipher, (tuple, list)) else str(cipher)
        cipher_name = cipher_name.upper()

        if "ECDHE" in cipher_name:
            return "ECDHE (Perfect Forward Secrecy)"
        elif "DHE" in cipher_name:
            return "DHE (Perfect Forward Secrecy)"
        elif "ECDH" in cipher_name:
            return "ECDH"
        elif "RSA" in cipher_name:
            return "RSA"
        else:
            return "Unknown"

    def _get_encryption_algorithm(self, cipher) -> str:
        """Extract encryption algorithm from cipher suite."""
        if not cipher:
            return "Unknown"

        cipher_name = cipher[0] if isinstance(cipher, (tuple, list)) else str(cipher)
        cipher_name = cipher_name.upper()

        if "AES_256_GCM" in cipher_name:
            return "AES-256-GCM"
        elif "AES_128_GCM" in cipher_name:
            return "AES-128-GCM"
        elif "CHACHA20" in cipher_name:
            return "ChaCha20-Poly1305"
        elif "AES_256" in cipher_name:
            return "AES-256"
        elif "AES_128" in cipher_name:
            return "AES-128"
        else:
            return "Unknown"

    def _get_mac_algorithm(self, cipher) -> str:
        """Extract MAC algorithm from cipher suite."""
        if not cipher:
            return "Unknown"

        cipher_name = cipher[0] if isinstance(cipher, (tuple, list)) else str(cipher)
        cipher_name = cipher_name.upper()

        if "GCM" in cipher_name or "POLY1305" in cipher_name:
            return "AEAD (Authenticated Encryption)"
        elif "SHA384" in cipher_name:
            return "SHA-384"
        elif "SHA256" in cipher_name:
            return "SHA-256"
        elif "SHA" in cipher_name:
            return "SHA-1"
        else:
            return "Unknown"

    def _calculate_comprehensive_score(self, tls_info: dict[str, Any]) -> float:
        """Calculate comprehensive TLS score (0-1)."""
        if "error" in tls_info:
            return 0.0

        score = 0.0
        max_score = 100.0

        # Protocol version scoring (30 points)
        protocol_version = tls_info.get("protocol_version")
        if protocol_version == "TLSv1.3":
            score += 30
        elif protocol_version == "TLSv1.2":
            score += 25
        elif protocol_version in ["TLSv1.1", "TLSv1.0"]:
            score += 10

        # Cipher suite scoring (20 points)
        cipher_suite = tls_info.get("cipher_suite")
        if cipher_suite:
            cipher_level = self._get_cipher_security_level(cipher_suite)
            if cipher_level == "excellent":
                score += 20
            elif cipher_level == "good":
                score += 15
            elif cipher_level == "fair":
                score += 10
            else:
                score += 5

        # Certificate scoring (30 points)
        certificate = tls_info.get("certificate", {})
        if certificate and "error" not in certificate:
            cert_score = certificate.get("security_assessment", {}).get("security_score", 0)
            score += (cert_score / 100) * 30

        # Security analysis scoring (20 points)
        security = tls_info.get("security_analysis", {})
        vuln_count = len(security.get("vulnerabilities", []))
        if vuln_count == 0:
            score += 20
        elif vuln_count <= 2:
            score += 15
        elif vuln_count <= 4:
            score += 10
        else:
            score += 5

        return min(score / max_score, 1.0)

    def _prepare_technical_details(self, tls_info: dict[str, Any]) -> dict[str, Any]:
        """Prepare comprehensive technical details for output."""
        details = {
            "connection_analysis": {
                "protocol_version": tls_info.get("protocol_version"),
                "cipher_suite": tls_info.get("cipher_suite"),
                "compression": tls_info.get("compression"),
                "supported_versions": tls_info.get("supported_versions", {})
            },

            "certificate_analysis": tls_info.get("certificate", {}),
            "certificate_chain_analysis": tls_info.get("certificate_chain", {}),
            "security_assessment": tls_info.get("security_analysis", {}),

            "technical_summary": {
                "connection_successful": "error" not in tls_info,
                "modern_tls": tls_info.get("protocol_version") in ["TLSv1.2", "TLSv1.3"],
                "secure_cipher": self._is_secure_cipher(tls_info.get("cipher_suite")),
                "certificate_valid": not tls_info.get("certificate", {}).get("validity", {}).get("is_expired", True),
                "vulnerabilities_found": len(tls_info.get("security_analysis", {}).get("vulnerabilities", [])),
                "security_score": self._calculate_comprehensive_score(tls_info) * 100
            }
        }

        if "error" in tls_info:
            details["error"] = tls_info["error"]

        return details

    def _is_secure_cipher(self, cipher) -> bool:
        """Check if cipher suite is considered secure."""
        if not cipher:
            return False

        cipher_name = cipher[0] if isinstance(cipher, (tuple, list)) else str(cipher)
        cipher_name = cipher_name.upper()

        # Consider modern, secure ciphers
        secure_indicators = ["AES_256_GCM", "AES_128_GCM", "CHACHA20", "POLY1305"]
        insecure_indicators = ["RC4", "DES", "NULL", "MD5", "SHA1"]

        has_secure = any(indicator in cipher_name for indicator in secure_indicators)
        has_insecure = any(indicator in cipher_name for indicator in insecure_indicators)

        return has_secure and not has_insecure

    def _safe_datetime_format(self, dt) -> str:
        """Safely format datetime to ISO string."""
        try:
            if hasattr(dt, 'isoformat'):
                return dt.isoformat()
            else:
                return str(dt)
        except Exception:
            return "unknown"

    def _safe_datetime_diff_days(self, dt1, dt2) -> int:
        """Safely calculate difference in days between two datetimes."""
        try:
            if hasattr(dt1, 'year') and hasattr(dt2, 'year'):
                diff = dt1 - dt2
                return diff.days
            else:
                return 0
        except Exception:
            return 0

    def _safe_datetime_compare(self, dt1, dt2) -> bool:
        """Safely compare two datetimes."""
        try:
            if hasattr(dt1, 'year') and hasattr(dt2, 'year'):
                return dt1 > dt2
            else:
                return False
        except Exception:
            return False
