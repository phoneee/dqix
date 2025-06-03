"""Tests for refactored DQIX components."""

import unittest
from unittest.mock import MagicMock, patch

from dqix.core.probes import Probe, register, PROBES
from dqix.core.mixins import CacheMixin, DomainValidationMixin, DNSRecordMixin, ErrorHandlingMixin


class TestMixins(unittest.TestCase):
    """Test the refactored mixins."""
    
    def test_domain_validation_mixin(self):
        """Test domain validation functionality."""
        mixin = DomainValidationMixin()
        
        # Valid domains
        self.assertTrue(mixin._validate_domain("example.com"))
        self.assertTrue(mixin._validate_domain("sub.example.com"))
        self.assertTrue(mixin._validate_domain("test-domain.org"))
        
        # Invalid domains
        self.assertFalse(mixin._validate_domain(""))
        self.assertFalse(mixin._validate_domain("invalid"))
        self.assertFalse(mixin._validate_domain("-invalid.com"))
        self.assertFalse(mixin._validate_domain("invalid-.com"))
        self.assertFalse(mixin._validate_domain("a" * 256))  # Too long
    
    def test_dns_record_mixin(self):
        """Test DNS record parsing functionality."""
        mixin = DNSRecordMixin()
        
        # Test finding records
        records = ["v=spf1 include:_spf.google.com ~all", "v=DKIM1; k=rsa; p=..."]
        spf_record = mixin._find_record(records, "v=spf1")
        self.assertEqual(spf_record, "v=spf1 include:_spf.google.com ~all")
        
        dkim_record = mixin._find_record(records, "v=DKIM1")
        self.assertEqual(dkim_record, "v=DKIM1; k=rsa; p=...")
        
        # Test parsing records
        parsed = mixin._parse_record("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA")
        expected = {"v": "DKIM1", "k": "rsa", "p": "MIGfMA0GCSqGSIb3DQEBAQUAA"}
        self.assertEqual(parsed, expected)
    
    def test_cache_mixin(self):
        """Test cache functionality."""
        mock_cache = MagicMock()
        
        class TestClass(CacheMixin):
            id = "test"
        
        obj = TestClass(cache=mock_cache)
        
        # Test getting cached data
        mock_cache.get.return_value = {"test": "data"}
        result = obj._get_cached_data("example.com")
        self.assertEqual(result, {"test": "data"})
        mock_cache.get.assert_called_with("test", "example.com")
        
        # Test caching data
        test_data = MagicMock()
        test_data.__dict__ = {"test": "data"}
        obj._cache_data("example.com", test_data)
        mock_cache.set.assert_called_with("test", "example.com", {"test": "data"})
    
    def test_error_handling_mixin(self):
        """Test error handling functionality."""
        class TestClass(ErrorHandlingMixin):
            def __init__(self):
                self.logger = MagicMock()
        
        obj = TestClass()
        
        # Test with object that has __dict__
        class TestData:
            def __init__(self):
                self.value = "test"
        
        data = TestData()
        error = Exception("Test error")
        result = obj._handle_probe_error("example.com", error, data)
        
        self.assertEqual(result.error, "Test error")
        obj.logger.error.assert_called()


class TestProbeRegistration(unittest.TestCase):
    """Test probe registration system."""
    
    def setUp(self):
        """Clear probe registry before each test."""
        PROBES.clear()
    
    def test_probe_registration(self):
        """Test that probes can be registered."""
        @register
        class TestProbe(Probe):
            id = "test_probe"
            
            def run(self, domain):
                return 1.0, {"test": True}
        
        self.assertIn("test_probe", PROBES)
        self.assertEqual(PROBES["test_probe"], TestProbe)
    
    def test_probe_registration_without_id(self):
        """Test that probes without id raise error."""
        with self.assertRaises(ValueError):
            @register
            class BadProbe(Probe):
                def run(self, domain):
                    return 1.0, {}


class TestRefactoredProbePattern(unittest.TestCase):
    """Test the refactored probe pattern."""
    
    def test_probe_with_mixins(self):
        """Test probe using multiple mixins."""
        @register
        class TestProbe(Probe, CacheMixin, DomainValidationMixin, ErrorHandlingMixin):
            id = "test_mixed_probe"
            weight = 0.1
            category = "test"
            
            def __init__(self, cache=None):
                # Initialize Probe first
                Probe.__init__(self)
                # Then initialize mixins
                CacheMixin.__init__(self, cache=cache)
                self.logger = MagicMock()
            
            def run(self, domain):
                if not self._validate_domain(domain):
                    return 0.0, {"error": "Invalid domain"}
                
                # Check cache
                cached = self._get_cached_data(domain)
                if cached:
                    return 1.0, cached
                
                # Simulate data collection
                data = {"test": True, "domain": domain}
                self._cache_data(domain, data)
                
                return 1.0, data
        
        # Test with valid domain
        probe = TestProbe()
        score, details = probe.run("example.com")
        self.assertEqual(score, 1.0)
        self.assertEqual(details["domain"], "example.com")
        
        # Test with invalid domain
        score, details = probe.run("invalid")
        self.assertEqual(score, 0.0)
        self.assertIn("error", details)


class TestCLIRefactoring(unittest.TestCase):
    """Test CLI refactoring functions."""
    
    def test_cli_functions_exist(self):
        """Test that refactored CLI functions exist and are importable."""
        from dqix.cli import (
            _configure_verbosity_and_tls,
            _load_and_validate_probes,
            _expand_and_validate_targets,
            _save_csv_results,
            _save_json_results,
            _display_single_domain_table
        )
        
        # Just test that they're callable
        self.assertTrue(callable(_configure_verbosity_and_tls))
        self.assertTrue(callable(_load_and_validate_probes))
        self.assertTrue(callable(_expand_and_validate_targets))
        self.assertTrue(callable(_save_csv_results))
        self.assertTrue(callable(_save_json_results))
        self.assertTrue(callable(_display_single_domain_table))


if __name__ == "__main__":
    unittest.main() 