"""
Test-Driven Development for DQIX Functional Core
Following functional programming principles with pure functions and no side effects
"""

from dataclasses import dataclass
from functools import reduce
from typing import Any, Callable, Union

import pytest


# Functional Domain Types (Pure Data Structures)
@dataclass(frozen=True)
class Domain:
    """Immutable domain representation"""
    name: str

    def __post_init__(self):
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Domain name must be a non-empty string")

@dataclass(frozen=True)
class ProbeResult:
    """Immutable probe result"""
    probe_id: str
    domain: Domain
    status: str  # "passed" | "failed" | "warning" | "error"
    score: float  # 0.0 to 1.0
    message: str
    details: dict[str, Any]

    def __post_init__(self):
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("Score must be between 0.0 and 1.0")

@dataclass(frozen=True)
class AssessmentResult:
    """Immutable assessment result"""
    domain: Domain
    probe_results: list[ProbeResult]
    overall_score: float
    compliance_level: str
    timestamp: float

# Functional Result Types (Maybe/Either pattern)
@dataclass(frozen=True)
class Success:
    """Success result container"""
    value: Any

    def map(self, func: Callable) -> 'Union[Success, Failure]':
        try:
            return Success(func(self.value))
        except Exception as e:
            return Failure(str(e))

    def flat_map(self, func: Callable) -> 'Union[Success, Failure]':
        try:
            result = func(self.value)
            return result if isinstance(result, (Success, Failure)) else Success(result)
        except Exception as e:
            return Failure(str(e))

    def is_success(self) -> bool:
        return True

    def get_or_else(self, default: Any) -> Any:
        return self.value

@dataclass(frozen=True)
class Failure:
    """Failure result container"""
    error: str

    def map(self, func: Callable) -> 'Failure':
        return self

    def flat_map(self, func: Callable) -> 'Failure':
        return self

    def is_success(self) -> bool:
        return False

    def get_or_else(self, default: Any) -> Any:
        return default

Result = Union[Success, Failure]

# Pure Functions for Domain Logic
def validate_domain(domain_name: str) -> Result:
    """Pure function to validate domain name"""
    if not domain_name:
        return Failure("Domain name cannot be empty")

    if not isinstance(domain_name, str):
        return Failure("Domain name must be a string")

    # Basic domain validation
    if "." not in domain_name:
        return Failure("Domain name must contain at least one dot")

    if len(domain_name) > 253:
        return Failure("Domain name too long")

    # Reject invalid patterns
    if domain_name in [".", "..", "..."]:
        return Failure("Invalid domain name")

    if domain_name.startswith(".") or domain_name.endswith("."):
        return Failure("Domain name cannot start or end with dot")

    if ".." in domain_name:
        return Failure("Domain name cannot contain consecutive dots")

    if " " in domain_name:
        return Failure("Domain name cannot contain spaces")

    # Must have at least one character before and after the dot
    parts = domain_name.split(".")
    if any(len(part) == 0 for part in parts):
        return Failure("Domain name parts cannot be empty")

    return Success(Domain(domain_name))

def calculate_probe_score(probe_data: dict[str, Any]) -> Result:
    """Pure function to calculate probe score"""
    try:
        # TLS scoring
        if probe_data.get("probe_type") == "tls":
            score = 0.0

            # Protocol version scoring
            protocol = probe_data.get("protocol_version", "")
            if "1.3" in protocol:
                score += 0.4
            elif "1.2" in protocol:
                score += 0.3
            elif "1.1" in protocol:
                score += 0.2

            # Certificate scoring
            cert_valid = probe_data.get("certificate_valid", False)
            if cert_valid:
                score += 0.3

            # Cipher strength
            cipher_strength = probe_data.get("cipher_strength", "")
            if cipher_strength == "strong":
                score += 0.3
            elif cipher_strength == "medium":
                score += 0.2

            return Success(min(score, 1.0))

        # DNS scoring
        elif probe_data.get("probe_type") == "dns":
            score = 0.0

            # Basic connectivity
            if probe_data.get("ipv4_records"):
                score += 0.2
            if probe_data.get("ipv6_records"):
                score += 0.1

            # Security features
            if probe_data.get("dnssec_enabled"):
                score += 0.3
            if probe_data.get("spf_record"):
                score += 0.2
            if probe_data.get("dmarc_record"):
                score += 0.2

            return Success(min(score, 1.0))

        # HTTPS scoring
        elif probe_data.get("probe_type") == "https":
            score = 0.0

            if probe_data.get("accessible"):
                score += 0.4
            if probe_data.get("secure_redirects"):
                score += 0.3
            if probe_data.get("hsts_enabled"):
                score += 0.3

            return Success(min(score, 1.0))

        # Security Headers scoring
        elif probe_data.get("probe_type") == "security_headers":
            score = 0.0

            headers = probe_data.get("headers", {})
            if headers.get("hsts"):
                score += 0.3
            if headers.get("csp"):
                score += 0.3
            if headers.get("x_frame_options"):
                score += 0.2
            if headers.get("x_content_type_options"):
                score += 0.2

            return Success(min(score, 1.0))

        else:
            return Failure(f"Unknown probe type: {probe_data.get('probe_type')}")

    except Exception as e:
        return Failure(f"Score calculation failed: {str(e)}")

def calculate_overall_score(probe_results: list[ProbeResult]) -> Result:
    """Pure function to calculate overall assessment score"""
    if not probe_results:
        return Failure("No probe results provided")

    try:
        # Weighted scoring based on probe importance
        weights = {
            "tls": 0.35,
            "https": 0.20,
            "dns": 0.25,
            "security_headers": 0.20
        }

        total_weighted_score = 0.0
        total_weight = 0.0

        for result in probe_results:
            weight = weights.get(result.probe_id, 0.1)
            total_weighted_score += result.score * weight
            total_weight += weight

        if total_weight == 0:
            return Failure("No valid probe results found")

        overall_score = total_weighted_score / total_weight
        return Success(overall_score)

    except Exception as e:
        return Failure(f"Overall score calculation failed: {str(e)}")

def determine_compliance_level(score: float) -> Result:
    """Pure function to determine compliance level"""
    if not 0.0 <= score <= 1.0:
        return Failure("Score must be between 0.0 and 1.0")

    if score >= 0.90:
        return Success("Excellent")
    elif score >= 0.80:
        return Success("Advanced")
    elif score >= 0.60:
        return Success("Standard")
    elif score >= 0.40:
        return Success("Basic")
    else:
        return Success("Poor")

def compose_assessment(domain: Domain, probe_results: list[ProbeResult], timestamp: float) -> Result:
    """Pure function to compose final assessment"""
    overall_score_result = calculate_overall_score(probe_results)

    return overall_score_result.flat_map(lambda score:
        determine_compliance_level(score).map(lambda level:
            AssessmentResult(
                domain=domain,
                probe_results=probe_results,
                overall_score=score,
                compliance_level=level,
                timestamp=timestamp
            )
        )
    )

# Higher-order functions for functional composition
def pipe(*functions):
    """Functional composition - pipe functions left to right"""
    return lambda x: reduce(lambda acc, f: f(acc), functions, x)

def compose(*functions):
    """Functional composition - compose functions right to left"""
    return lambda x: reduce(lambda acc, f: f(acc), reversed(functions), x)

def map_result(func: Callable) -> Callable[[Result], Result]:
    """Higher-order function to map over Result types"""
    def mapper(result: Result) -> Result:
        return result.map(func)
    return mapper

def flat_map_result(func: Callable) -> Callable[[Result], Result]:
    """Higher-order function to flat_map over Result types"""
    def mapper(result: Result) -> Result:
        return result.flat_map(func)
    return mapper

# Test Cases for TDD
class TestFunctionalCore:
    """Test-driven development for functional core"""

    def test_domain_validation_success(self):
        """Test successful domain validation"""
        result = validate_domain("example.com")
        assert result.is_success()
        assert result.value.name == "example.com"

    def test_domain_validation_failure_empty(self):
        """Test domain validation with empty string"""
        result = validate_domain("")
        assert not result.is_success()
        assert "empty" in result.error.lower()

    def test_domain_validation_failure_no_dot(self):
        """Test domain validation without dot"""
        result = validate_domain("example")
        assert not result.is_success()
        assert "dot" in result.error.lower()

    def test_tls_probe_score_calculation(self):
        """Test TLS probe score calculation"""
        probe_data = {
            "probe_type": "tls",
            "protocol_version": "TLS 1.3",
            "certificate_valid": True,
            "cipher_strength": "strong"
        }

        result = calculate_probe_score(probe_data)
        assert result.is_success()
        assert result.value == 1.0

    def test_dns_probe_score_calculation(self):
        """Test DNS probe score calculation"""
        probe_data = {
            "probe_type": "dns",
            "ipv4_records": True,
            "ipv6_records": True,
            "dnssec_enabled": True,
            "spf_record": True,
            "dmarc_record": True
        }

        result = calculate_probe_score(probe_data)
        assert result.is_success()
        assert result.value == 1.0

    def test_https_probe_score_calculation(self):
        """Test HTTPS probe score calculation"""
        probe_data = {
            "probe_type": "https",
            "accessible": True,
            "secure_redirects": True,
            "hsts_enabled": True
        }

        result = calculate_probe_score(probe_data)
        assert result.is_success()
        assert result.value == 1.0

    def test_security_headers_score_calculation(self):
        """Test security headers score calculation"""
        probe_data = {
            "probe_type": "security_headers",
            "headers": {
                "hsts": True,
                "csp": True,
                "x_frame_options": True,
                "x_content_type_options": True
            }
        }

        result = calculate_probe_score(probe_data)
        assert result.is_success()
        assert result.value == 1.0

    def test_overall_score_calculation(self):
        """Test overall score calculation"""
        domain = Domain("example.com")

        probe_results = [
            ProbeResult("tls", domain, "passed", 0.9, "Good TLS", {}),
            ProbeResult("dns", domain, "passed", 0.8, "Good DNS", {}),
            ProbeResult("https", domain, "passed", 0.7, "Good HTTPS", {}),
            ProbeResult("security_headers", domain, "passed", 0.6, "Basic headers", {})
        ]

        result = calculate_overall_score(probe_results)
        assert result.is_success()
        # Weighted average: 0.9*0.35 + 0.8*0.25 + 0.7*0.20 + 0.6*0.20 = 0.775
        assert abs(result.value - 0.775) < 0.001

    def test_compliance_level_determination(self):
        """Test compliance level determination"""
        test_cases = [
            (0.95, "Excellent"),
            (0.85, "Advanced"),
            (0.70, "Standard"),
            (0.50, "Basic"),
            (0.30, "Poor")
        ]

        for score, expected_level in test_cases:
            result = determine_compliance_level(score)
            assert result.is_success()
            assert result.value == expected_level

    def test_assessment_composition(self):
        """Test complete assessment composition"""
        domain = Domain("example.com")
        timestamp = 1640995200.0  # 2022-01-01 00:00:00 UTC

        probe_results = [
            ProbeResult("tls", domain, "passed", 0.9, "Good TLS", {}),
            ProbeResult("dns", domain, "passed", 0.8, "Good DNS", {})
        ]

        result = compose_assessment(domain, probe_results, timestamp)
        assert result.is_success()

        assessment = result.value
        assert assessment.domain == domain
        assert len(assessment.probe_results) == 2
        assert assessment.compliance_level in ["Excellent", "Advanced", "Standard", "Basic", "Poor"]
        assert assessment.timestamp == timestamp

    def test_functional_composition_pipe(self):
        """Test functional composition with pipe"""
        process_domain = pipe(
            validate_domain,
            map_result(lambda domain: domain.name.upper())
        )

        result = process_domain("example.com")
        assert result.is_success()
        assert result.value == "EXAMPLE.COM"

    def test_result_monad_map(self):
        """Test Result monad map operation"""
        success = Success(5)
        result = success.map(lambda x: x * 2)
        assert result.is_success()
        assert result.value == 10

        failure = Failure("error")
        result = failure.map(lambda x: x * 2)
        assert not result.is_success()
        assert result.error == "error"

    def test_result_monad_flat_map(self):
        """Test Result monad flat_map operation"""
        success = Success(5)
        result = success.flat_map(lambda x: Success(x * 2))
        assert result.is_success()
        assert result.value == 10

        # Test failure propagation
        result = success.flat_map(lambda x: Failure("error"))
        assert not result.is_success()
        assert result.error == "error"

    def test_immutability(self):
        """Test that all data structures are immutable"""
        domain = Domain("example.com")

        # Should not be able to modify domain
        with pytest.raises(AttributeError):
            domain.name = "modified.com"

        probe_result = ProbeResult("tls", domain, "passed", 0.9, "Good", {})

        # Should not be able to modify probe result
        with pytest.raises(AttributeError):
            probe_result.score = 0.5

# Property-based testing helpers
def generate_valid_domain_names():
    """Generate valid domain names for property testing"""
    return [
        "example.com",
        "test.org",
        "subdomain.example.com",
        "a.b.c.d.e.com",
        "xn--fsq.com",  # IDN domain
        "1.2.3.4.example.com"
    ]

def generate_invalid_domain_names():
    """Generate invalid domain names for property testing"""
    return [
        "",
        "example",
        ".",
        ".com",
        "example.",
        "a" * 254,  # Too long
        "ex ample.com",  # Space
        "example..com"  # Double dot
    ]

class TestPropertyBased:
    """Property-based tests for functional core"""

    def test_domain_validation_properties(self):
        """Property: Valid domains should always validate successfully"""
        for domain_name in generate_valid_domain_names():
            result = validate_domain(domain_name)
            assert result.is_success(), f"Failed for {domain_name}"
            assert result.value.name == domain_name

    def test_invalid_domain_validation_properties(self):
        """Property: Invalid domains should always fail validation"""
        for domain_name in generate_invalid_domain_names():
            result = validate_domain(domain_name)
            assert not result.is_success(), f"Should have failed for {domain_name}"

    def test_score_calculation_properties(self):
        """Property: Scores should always be between 0.0 and 1.0"""
        probe_types = ["tls", "dns", "https", "security_headers"]

        for probe_type in probe_types:
            probe_data = {"probe_type": probe_type}
            result = calculate_probe_score(probe_data)

            if result.is_success():
                assert 0.0 <= result.value <= 1.0, f"Score out of range for {probe_type}"

    def test_composition_properties(self):
        """Property: Function composition should be associative"""
        def f(x):
            return x + 1
        def g(x):
            return x * 2
        def h(x):
            return x - 1

        # (f ∘ g) ∘ h = f ∘ (g ∘ h)
        comp1 = compose(compose(f, g), h)
        comp2 = compose(f, compose(g, h))

        test_value = 5
        assert comp1(test_value) == comp2(test_value)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
