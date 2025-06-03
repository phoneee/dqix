"""Test SRI plugin."""

import pytest
from dqix.plugins.sri import SRIProbe, SRIPlugin
from dqix.core.exceptions import ProbeError

def test_sri_plugin():
    """Test SRI plugin registration."""
    plugin = SRIPlugin()
    
    # Test plugin attributes
    assert plugin.name == "sri"
    assert plugin.version == "1.0.0"
    assert plugin.description == "SRI probe for DQIX"
    
    # Test probe registration
    probes = plugin.get_probes()
    assert len(probes) == 1
    assert probes[0] == SRIProbe
    
    # Test probe attributes
    probe = SRIProbe()
    assert probe.id == "sri"
    assert isinstance(probe.weight, float)
    assert 0 <= probe.weight <= 1

def test_sri_probe_valid_domain():
    """Test SRI probe with valid domain."""
    probe = SRIProbe()
    domain = "example.com"
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify score
    assert isinstance(score, float)
    assert 0 <= score <= 1
    
    # Verify details
    assert isinstance(details, dict)
    assert "scripts" in details
    assert "styles" in details
    
    # Verify data types
    assert isinstance(details["scripts"], list)
    assert isinstance(details["styles"], list)
    
    # Verify script details
    for script in details["scripts"]:
        assert isinstance(script, dict)
        assert "src" in script
        assert "integrity" in script
        assert isinstance(script["src"], str)
        assert isinstance(script["integrity"], str)
    
    # Verify style details
    for style in details["styles"]:
        assert isinstance(style, dict)
        assert "href" in style
        assert "integrity" in style
        assert isinstance(style["href"], str)
        assert isinstance(style["integrity"], str)

def test_sri_probe_invalid_domain():
    """Test SRI probe with invalid domain."""
    probe = SRIProbe()
    domain = "invalid-domain-that-does-not-exist.com"
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify error handling
    assert score == 0.0
    assert isinstance(details, dict)
    assert "error" in details
    assert isinstance(details["error"], str)

def test_sri_probe_malformed_domain():
    """Test SRI probe with malformed domain."""
    probe = SRIProbe()
    domain = "not-a-valid-domain"
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify error handling
    assert score == 0.0
    assert isinstance(details, dict)
    assert "error" in details
    assert isinstance(details["error"], str)

def test_sri_probe_empty_domain():
    """Test SRI probe with empty domain."""
    probe = SRIProbe()
    domain = ""
    
    # Run probe
    score, details = probe.run(domain)
    
    # Verify error handling
    assert score == 0.0
    assert isinstance(details, dict)
    assert "error" in details
    assert isinstance(details["error"], str)

def test_sri_probe_none_domain():
    """Test SRI probe with None domain."""
    probe = SRIProbe()
    
    # Run probe
    with pytest.raises(TypeError):
        probe.run(None) 