"""End-to-end tests for DQIX."""

import pytest
from dqix.runner import Runner
from dqix.core.probes import PROBES
from dqix.plugins.loader import load_plugins
from dqix.core.exceptions import ProbeError

def test_plugin_loading():
    """Test plugin loading and registration."""
    # Clear existing probes
    PROBES.clear()
    
    # Load all plugins
    load_plugins()
    
    # Verify required plugins are loaded
    required_plugins = ["whois", "sri"]
    for plugin in required_plugins:
        assert plugin in PROBES, f"Plugin {plugin} not loaded"
        assert hasattr(PROBES[plugin], "run"), f"Plugin {plugin} missing run method"
        assert hasattr(PROBES[plugin], "weight"), f"Plugin {plugin} missing weight"

def test_runner_with_valid_domain():
    """Test runner with valid domain."""
    runner = Runner()
    domain = "example.com"
    
    # Run scan with all probes
    results = runner.run(domain)
    
    # Verify results structure
    assert isinstance(results, dict), "Results should be a dictionary"
    assert "score" in results, "Results missing score"
    assert "details" in results, "Results missing details"
    assert isinstance(results["score"], float), "Score should be float"
    assert 0 <= results["score"] <= 1, "Score should be between 0 and 1"
    
    # Verify probe results
    details = results["details"]
    assert "whois" in details, "WHOIS results missing"
    assert "sri" in details, "SRI results missing"
    
    # Verify WHOIS results
    whois_results = details["whois"]
    assert isinstance(whois_results["score"], float), "WHOIS score should be float"
    assert 0 <= whois_results["score"] <= 1, "WHOIS score should be between 0 and 1"
    assert isinstance(whois_results["details"], dict), "WHOIS details should be dict"
    assert "registrar" in whois_results["details"], "WHOIS details missing registrar"
    
    # Verify SRI results
    sri_results = details["sri"]
    assert isinstance(sri_results["score"], float), "SRI score should be float"
    assert 0 <= sri_results["score"] <= 1, "SRI score should be between 0 and 1"
    assert isinstance(sri_results["details"], dict), "SRI details should be dict"
    assert "scripts" in sri_results["details"], "SRI details missing scripts"

def test_runner_with_invalid_domain():
    """Test runner with invalid domain."""
    runner = Runner()
    domain = "invalid-domain-that-does-not-exist.com"
    
    # Run scan with all probes
    results = runner.run(domain)
    
    # Verify error handling
    assert isinstance(results, dict), "Results should be a dictionary"
    assert "score" in results, "Results missing score"
    assert "details" in results, "Results missing details"
    assert results["score"] == 0.0, "Invalid domain should have score 0"
    
    # Verify error details
    details = results["details"]
    assert "whois" in details, "WHOIS results missing"
    assert "sri" in details, "SRI results missing"
    
    # Verify WHOIS error
    whois_results = details["whois"]
    assert whois_results["score"] == 0.0, "WHOIS should have score 0 for invalid domain"
    assert "error" in whois_results["details"], "WHOIS should have error details"
    
    # Verify SRI error
    sri_results = details["sri"]
    assert sri_results["score"] == 0.0, "SRI should have score 0 for invalid domain"
    assert "error" in sri_results["details"], "SRI should have error details"

def test_runner_with_timeout():
    """Test runner with timeout."""
    runner = Runner(timeout=0.1)  # Set very short timeout
    domain = "example.com"
    
    # Run scan with all probes
    results = runner.run(domain)
    
    # Verify timeout handling
    assert isinstance(results, dict), "Results should be a dictionary"
    assert "score" in results, "Results missing score"
    assert "details" in results, "Results missing details"
    assert results["score"] == 0.0, "Timeout should have score 0"
    
    # Verify timeout details
    details = results["details"]
    for probe_name in ["whois", "sri"]:
        assert probe_name in details, f"{probe_name} results missing"
        probe_results = details[probe_name]
        assert probe_results["score"] == 0.0, f"{probe_name} should have score 0"
        assert "error" in probe_results["details"], f"{probe_name} should have error details"
        assert "timeout" in probe_results["details"]["error"].lower(), f"{probe_name} should have timeout error" 