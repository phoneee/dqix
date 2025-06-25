"""Integration tests for DQIX."""

import unittest
from unittest.mock import patch

# Import probes to trigger registration
from dqix.core.levels import load_level
from dqix.core.probes import PROBES, Probe, register
from dqix.core.scoring import domain_score


class TestIntegration(unittest.TestCase):
    """Test the integration of DQIX components."""

    def test_probe_registration(self):
        """Test that probes are registered correctly."""
        # Import probes module to ensure registration

        # Check that some probes are registered
        assert "dns_basic" in PROBES
        assert "tls" in PROBES
        assert "headers" in PROBES
        assert "csp" in PROBES

    def test_load_level(self):
        """Test loading probes for different levels."""
        # Import probes module to ensure registration

        # Level 1 should have basic probes
        level1_probes = load_level(1)
        assert isinstance(level1_probes, dict)
        assert len(level1_probes) > 0

        # Level 3 should have more probes than level 1
        level3_probes = load_level(3)
        assert isinstance(level3_probes, dict)
        assert len(level3_probes) >= len(level1_probes)

    @patch("dqix.utils.dns.query_records")
    def test_domain_score(self, mock_query):
        """Test scoring a domain."""
        # Mock DNS responses
        mock_query.return_value = ["192.0.2.1"]  # Mock A record

        # Get level 1 probes
        probes = load_level(1)

        # Score a domain
        score, details = domain_score("example.com", probes)

        # Check results
        assert isinstance(score, (int, float))
        assert score >= 0
        assert score <= 100
        assert isinstance(details, dict)

    def test_custom_probe_registration(self):
        """Test registering a custom probe."""
        # Save current PROBES state
        original_probes = PROBES.copy()

        try:
            # Create a custom probe
            @register
            class TestProbe(Probe):
                id = "test_integration_probe"
                weight = 0.1

                def run(self, domain):
                    return 1.0, {"test": True}

            # Check it's registered
            assert "test_integration_probe" in PROBES

            # Test running it
            probe_class = PROBES["test_integration_probe"]
            probe = probe_class()
            score, details = probe.run("example.com")
            assert score == 1.0
            assert details == {"test": True}
        finally:
            # Restore original PROBES state
            PROBES.clear()
            PROBES.update(original_probes)


if __name__ == "__main__":
    unittest.main()
