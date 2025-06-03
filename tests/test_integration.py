"""Integration tests for DQIX."""

import unittest
from unittest.mock import patch, MagicMock

# Import probes to trigger registration
import dqix.probes

from dqix.core import PROBES, register
from dqix.core.probes import Probe
from dqix.core.levels import load_level
from dqix.core.scoring import domain_score


class TestIntegration(unittest.TestCase):
    """Test the integration of DQIX components."""
    
    def test_probe_registration(self):
        """Test that probes are registered correctly."""
        # Check that some probes are registered
        self.assertIn("dns_basic", PROBES)
        self.assertIn("tls", PROBES)
        self.assertIn("headers", PROBES)
        self.assertIn("csp", PROBES)
    
    def test_load_level(self):
        """Test loading probes for different levels."""
        # Level 1 should have basic probes
        level1_probes = load_level(1)
        self.assertIsInstance(level1_probes, dict)
        self.assertGreater(len(level1_probes), 0)
        
        # Level 3 should have more probes than level 1
        level3_probes = load_level(3)
        self.assertIsInstance(level3_probes, dict)
        self.assertGreaterEqual(len(level3_probes), len(level1_probes))
    
    @patch('dqix.utils.dns.query_records')
    def test_domain_score(self, mock_query):
        """Test scoring a domain."""
        # Mock DNS responses
        mock_query.return_value = ["192.0.2.1"]  # Mock A record
        
        # Get level 1 probes
        probes = load_level(1)
        
        # Score a domain
        score, details = domain_score("example.com", probes)
        
        # Check results
        self.assertIsInstance(score, (int, float))
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertIsInstance(details, dict)
    
    def test_custom_probe_registration(self):
        """Test registering a custom probe."""
        # Create a custom probe
        @register
        class TestProbe(Probe):
            id = "test_integration_probe"
            weight = 0.1
            
            def run(self, domain):
                return 1.0, {"test": True}
        
        # Check it's registered
        self.assertIn("test_integration_probe", PROBES)
        
        # Test running it
        probe_class = PROBES["test_integration_probe"]
        probe = probe_class()
        score, details = probe.run("example.com")
        self.assertEqual(score, 1.0)
        self.assertEqual(details, {"test": True})


if __name__ == "__main__":
    unittest.main() 