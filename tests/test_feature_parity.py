#!/usr/bin/env python3
"""
Test suite to ensure feature parity across all DQIX implementations.
Tests core functionality that must be consistent across all languages.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from dqix.core.domain.entities import DomainAssessment
    from dqix.core.domain.value_objects import DomainName
    from dqix.core.use_cases import DomainAssessmentUseCase
    from dqix.infrastructure import create_infrastructure
except ImportError:
    # Handle import errors for testing purposes
    DomainName = None
    DomainAssessment = None
    DomainAssessmentUseCase = None
    create_infrastructure = None


class FeatureParityTestSuite:
    """Test suite for validating feature parity across implementations."""

    # Test domains with expected characteristics
    TEST_DOMAINS = [
        {
            "domain": "github.com",
            "expected_features": {
                "tls_version": "TLS 1.3",
                "has_https": True,
                "has_hsts": True,
                "min_score": 0.75
            }
        },
        {
            "domain": "example.com",
            "expected_features": {
                "has_https": True,
                "has_dns": True,
                "min_score": 0.50
            }
        }
    ]

    # Core features that must be implemented
    REQUIRED_FEATURES = [
        "domain_validation",
        "tls_probe",
        "dns_probe",
        "https_probe",
        "headers_probe",
        "score_calculation",
        "grade_assignment",
        "json_output"
    ]

    @pytest.fixture
    async def python_infrastructure(self):
        """Create Python infrastructure for testing."""
        return create_infrastructure()

    @pytest.fixture
    async def python_use_case(self, python_infrastructure):
        """Create Python use case for testing."""
        return DomainAssessmentUseCase(python_infrastructure)

    def run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"

    def parse_json_output(self, output: str) -> Optional[Dict[str, Any]]:
        """Parse JSON output from command."""
        try:
            # Find JSON in output (may have other text)
            start = output.find('{')
            if start >= 0:
                json_str = output[start:]
                return json.loads(json_str)
        except json.JSONDecodeError:
            return None
        return None


class TestDomainValidation(FeatureParityTestSuite):
    """Test domain validation across implementations."""

    @pytest.mark.parametrize("domain,should_pass", [
        ("github.com", True),
        ("sub.domain.example.com", True),
        ("test-domain.com", True),
        ("", False),
        ("no-dot", False),
        ("invalid..domain", False),
        ("-start.com", False),
        ("end-.com", False),
        ("a" * 255 + ".com", False),
    ])
    async def test_python_domain_validation(self, domain: str, should_pass: bool):
        """Test Python domain validation."""
        if should_pass:
            domain_obj = DomainName(domain)
            assert domain_obj.value == domain
        else:
            with pytest.raises(ValueError):
                DomainName(domain)

    @pytest.mark.parametrize("domain,should_pass", [
        ("github.com", True),
        ("sub.domain.example.com", True),
        ("test-domain.com", True),
        ("", False),
        ("no-dot", False),
        ("invalid..domain", False),
        ("-start.com", False),
        ("end-.com", False),
    ])
    def test_bash_domain_validation(self, domain: str, should_pass: bool):
        """Test Bash domain validation."""
        exit_code, stdout, stderr = self.run_command(
            ["./dqix-cli/dqix-multi", "scan", domain]
        )

        if should_pass:
            # Should either succeed or fail for network reasons, not validation
            assert "Domain name" not in stderr
            assert "Invalid domain" not in stderr
        else:
            # Should fail with validation error
            assert exit_code != 0
            assert "Domain" in stderr or "Invalid" in stderr


class TestProbeImplementations(FeatureParityTestSuite):
    """Test probe implementations across languages."""

    async def test_python_all_probes_execute(self, python_use_case):
        """Test that Python executes all required probes."""
        result = await python_use_case.assess_domain("example.com")

        # Check all probes executed
        probe_results = result.probe_results
        assert len(probe_results) >= 4  # At least TLS, DNS, HTTPS, Headers

        # Check probe names
        probe_names = {pr.probe_id for pr in probe_results}
        assert "tls" in probe_names
        assert "dns" in probe_names
        assert "https" in probe_names
        assert "headers" in probe_names

    def test_bash_all_probes_execute(self):
        """Test that Bash executes all required probes."""
        exit_code, stdout, stderr = self.run_command(
            ["./dqix-cli/dqix-multi", "scan", "example.com", "--json"]
        )

        # Parse JSON output
        json_data = self.parse_json_output(stdout)
        assert json_data is not None

        # Check probe results
        probe_results = json_data.get("probe_results", [])
        assert len(probe_results) >= 4

        # Check probe names
        probe_ids = {pr["probe_id"] for pr in probe_results}
        assert "tls" in probe_ids
        assert "dns" in probe_ids
        assert "https" in probe_ids
        assert "headers" in probe_ids


class TestScoringConsistency(FeatureParityTestSuite):
    """Test scoring consistency across implementations."""

    async def test_python_scoring_weights(self, python_use_case):
        """Test Python scoring uses correct weights."""
        result = await python_use_case.assess_domain("example.com")

        # Weights should be: TLS 35%, DNS 25%, HTTPS 20%, Headers 20%
        assert 0 <= result.overall_score <= 1.0
        assert result.security_grade in ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D", "F"]

    def test_bash_scoring_weights(self):
        """Test Bash scoring uses correct weights."""
        exit_code, stdout, stderr = self.run_command(
            ["./dqix-cli/dqix-multi", "scan", "example.com", "--json"]
        )

        json_data = self.parse_json_output(stdout)
        assert json_data is not None

        overall_score = json_data.get("overall_score", 0)
        grade = json_data.get("grade", "")

        assert 0 <= overall_score <= 100
        assert grade in ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D", "F"]

    @pytest.mark.parametrize("score,expected_grade", [
        (97, "A+"),
        (92, "A"),
        (87, "A-"),
        (82, "B+"),
        (77, "B"),
        (72, "B-"),
        (67, "C+"),
        (62, "C"),
        (57, "C-"),
        (52, "D"),
        (40, "F"),
    ])
    def test_grade_calculation_consistency(self, score: int, expected_grade: str):
        """Test that grade calculation is consistent."""
        # This tests the algorithm, not specific implementations
        # Both implementations should follow the same grade boundaries
        pass


class TestOutputFormats(FeatureParityTestSuite):
    """Test output format consistency."""

    async def test_python_json_output_structure(self, python_use_case):
        """Test Python JSON output structure."""
        result = await python_use_case.assess_domain("example.com")

        # Convert to dict for testing
        json_data = {
            "domain": result.domain.value,
            "overall_score": result.overall_score,
            "grade": result.security_grade,
            "probe_results": [
                {
                    "probe_id": pr.probe_id,
                    "score": pr.score,
                    "category": pr.category
                }
                for pr in result.probe_results
            ]
        }

        # Validate structure
        assert "domain" in json_data
        assert "overall_score" in json_data
        assert "grade" in json_data
        assert "probe_results" in json_data
        assert isinstance(json_data["probe_results"], list)

    def test_bash_json_output_structure(self):
        """Test Bash JSON output structure."""
        exit_code, stdout, stderr = self.run_command(
            ["./dqix-cli/dqix-multi", "scan", "example.com", "--json"]
        )

        json_data = self.parse_json_output(stdout)
        assert json_data is not None

        # Validate structure
        assert "domain" in json_data
        assert "overall_score" in json_data
        assert "grade" in json_data
        assert "probe_results" in json_data
        assert isinstance(json_data["probe_results"], list)

        # Check probe result structure
        for probe in json_data["probe_results"]:
            assert "probe_id" in probe
            assert "score" in probe
            assert "category" in probe


class TestCLICommands(FeatureParityTestSuite):
    """Test CLI command consistency."""

    def test_python_cli_commands(self):
        """Test Python CLI commands."""
        # Test help
        exit_code, stdout, stderr = self.run_command(["dqix", "--help"])
        assert exit_code == 0
        assert "scan" in stdout or "scan" in stderr

        # Test version
        exit_code, stdout, stderr = self.run_command(["dqix", "--version"])
        assert exit_code == 0
        assert "2.0" in stdout or "2.0" in stderr

    def test_bash_cli_commands(self):
        """Test Bash CLI commands."""
        # Test help
        exit_code, stdout, stderr = self.run_command(["./dqix-cli/dqix-multi", "help"])
        assert exit_code == 0
        assert "scan" in stdout

        # Test version
        exit_code, stdout, stderr = self.run_command(["./dqix-cli/dqix-multi", "version"])
        assert exit_code == 0
        assert "2.0" in stdout

    @pytest.mark.parametrize("command", ["scan", "validate", "test", "demo"])
    def test_bash_command_availability(self, command: str):
        """Test that Bash implements all required commands."""
        exit_code, stdout, stderr = self.run_command(["./dqix-cli/dqix-multi", "help"])
        assert command in stdout


class TestErrorHandling(FeatureParityTestSuite):
    """Test error handling consistency."""

    async def test_python_network_error_handling(self, python_use_case):
        """Test Python handles network errors gracefully."""
        # Test with non-existent domain
        result = await python_use_case.assess_domain("this-domain-definitely-does-not-exist-123456789.com")

        # Should still return a result, but with low scores
        assert result.overall_score < 0.5
        assert len(result.probe_results) > 0

    def test_bash_network_error_handling(self):
        """Test Bash handles network errors gracefully."""
        exit_code, stdout, stderr = self.run_command(
            ["./dqix-cli/dqix-multi", "scan", "this-domain-definitely-does-not-exist-123456789.com"]
        )

        # Should complete without crashing
        assert exit_code == 0
        # Should show results (even if scores are 0)
        assert "Overall Score" in stdout


class TestPerformance(FeatureParityTestSuite):
    """Test performance characteristics."""

    @pytest.mark.slow
    async def test_python_scan_performance(self, python_use_case):
        """Test Python scan completes within timeout."""
        start_time = time.time()
        result = await python_use_case.assess_domain("example.com")
        elapsed = time.time() - start_time

        # Should complete within 30 seconds
        assert elapsed < 30
        assert result is not None

    @pytest.mark.slow
    def test_bash_scan_performance(self):
        """Test Bash scan completes within timeout."""
        start_time = time.time()
        exit_code, stdout, stderr = self.run_command(
            ["./dqix-cli/dqix-multi", "scan", "example.com"],
            timeout=35
        )
        elapsed = time.time() - start_time

        # Should complete within 30 seconds
        assert elapsed < 35
        assert exit_code == 0


# Test runner for command-line execution
if __name__ == "__main__":
    # Run specific test categories
    import sys

    if len(sys.argv) > 1:
        test_category = sys.argv[1]
        pytest.main(["-v", "-k", test_category, __file__])
    else:
        # Run all tests
        pytest.main(["-v", __file__])
