"""Test WHOIS plugin."""

import pytest
from dqix.plugins.whois import WHOISProbe, WHOISPlugin
from dqix.core.exceptions import ProbeError

def test_whois_plugin():
    """Test WHOIS plugin registration."""
    plugin = WHOISPlugin()
    
    # Test plugin attributes
    assert plugin.name == "whois"
    assert plugin.version == "1.0.0"
    assert plugin.description == "WHOIS probe for DQIX"
    
    # Test probe registration
    probes = plugin.get_probes()
    assert len(probes) == 1
    assert probes[0] == WHOISProbe
    
    # Test probe attributes
    probe = WHOISProbe()
    assert probe.id == "whois"
    assert isinstance(probe.weight, float)
    assert 0 <= probe.weight <= 1

def test_whois_probe_valid_domain():
    """Test WHOIS probe with valid domain."""
    probe = WHOISProbe()
    domain = "example.com"
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify score
    assert isinstance(score, float)
    assert 0 <= score <= 1
    
    # Verify details
    assert isinstance(details, dict)
    assert "registrar" in details
    assert "creation_date" in details
    assert "expiration_date" in details
    assert "name_servers" in details
    
    # Verify data types
    assert isinstance(details["registrar"], str)
    assert isinstance(details["creation_date"], str)
    assert isinstance(details["expiration_date"], str)
    assert isinstance(details["name_servers"], list)

def test_whois_probe_invalid_domain():
    """Test WHOIS probe with invalid domain."""
    probe = WHOISProbe()
    domain = "invalid-domain-that-does-not-exist.com"
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify error handling
    assert score == 0.0
    assert isinstance(details, dict)
    assert "error" in details
    assert isinstance(details["error"], str)

def test_whois_probe_malformed_domain():
    """Test WHOIS probe with malformed domain."""
    probe = WHOISProbe()
    domain = "not-a-valid-domain"
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify error handling
    assert score == 0.0
    assert isinstance(details, dict)
    assert "error" in details
    assert isinstance(details["error"], str)

def test_whois_probe_empty_domain():
    """Test WHOIS probe with empty domain."""
    probe = WHOISProbe()
    domain = ""
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify error handling
    assert score == 0.0
    assert isinstance(details, dict)
    assert "error" in details
    assert isinstance(details["error"], str)

def test_whois_probe_none_domain():
    """Test WHOIS probe with None domain."""
    probe = WHOISProbe()
    
    # Run probe
    with pytest.raises(TypeError):
        probe.run(None)
