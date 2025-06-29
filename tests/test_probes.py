"""Tests for DQIX probes."""

from unittest.mock import MagicMock, patch

import pytest
from dqix.core.scoring import ProbeResult
from dqix.probes.email.bimi import BIMIProbe
from dqix.probes.email.dkim import DKIMProbe
from dqix.probes.email.dmarc import DMARCProbe
from dqix.probes.email.mx import MXProbe
from dqix.probes.email.spf import SPFProbe


@pytest.fixture
def mock_dns():
    """Mock DNS resolver."""
    with patch("dqix.utils.dns.get_txt_records") as mock_txt, \
         patch("dqix.utils.dns.get_mx_records") as mock_mx:
        yield mock_txt, mock_mx


def test_bimi_probe(mock_dns):
    """Test BIMI probe."""
    mock_txt, _ = mock_dns
    mock_txt.return_value = ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"]

    probe = BIMIProbe()
    result = probe.run("example.com")

    assert isinstance(result, ProbeResult)
    assert result.probe_id == "bimi"
    assert result.score > 0
    assert "bimi_record" in result.details
    assert result.details["category"] == "email"


def test_dkim_probe(mock_dns):
    """Test DKIM probe."""
    mock_txt, _ = mock_dns
    mock_txt.return_value = ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA"]

    probe = DKIMProbe()
    result = probe.run("example.com")

    assert isinstance(result, ProbeResult)
    assert result.probe_id == "dkim"
    assert result.score > 0
    assert "dkim_record" in result.details
    assert result.details["category"] == "email"


def test_dmarc_probe(mock_dns):
    """Test DMARC probe."""
    mock_txt, _ = mock_dns
    mock_txt.return_value = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]

    probe = DMARCProbe()
    result = probe.run("example.com")

    assert isinstance(result, ProbeResult)
    assert result.probe_id == "dmarc"
    assert result.score > 0
    assert "dmarc_record" in result.details
    assert result.details["category"] == "email"


def test_mx_probe(mock_dns):
    """Test MX probe."""
    _, mock_mx = mock_dns
    mock_mx.return_value = [
        MagicMock(host="mail1.example.com", priority=10),
        MagicMock(host="mail2.example.com", priority=20),
    ]

    probe = MXProbe()
    result = probe.run("example.com")

    assert isinstance(result, ProbeResult)
    assert result.probe_id == "mx"
    assert result.score > 0
    assert "mx_records" in result.details
    assert result.details["category"] == "email"


def test_spf_probe(mock_dns):
    """Test SPF probe."""
    mock_txt, _ = mock_dns
    mock_txt.return_value = ["v=spf1 include:_spf.google.com ~all"]

    probe = SPFProbe()
    result = probe.run("example.com")

    assert isinstance(result, ProbeResult)
    assert result.probe_id == "spf"
    assert result.score > 0
    assert "spf_record" in result.details
    assert result.details["category"] == "email"


def test_probe_error_handling(mock_dns):
    """Test probe error handling."""
    mock_txt, _ = mock_dns
    mock_txt.side_effect = Exception("DNS error")

    # Test BIMI probe
    probe = BIMIProbe()
    result = probe.run("example.com")

    assert isinstance(result, ProbeResult)
    assert result.probe_id == "bimi"
    assert result.score == 0.0
    assert "error" in result.details
    assert result.details["category"] == "email"


def test_probe_weight_validation():
    """Test probe weight validation."""
    # Test BIMI probe
    probe = BIMIProbe()
    assert 0 < probe.weight <= 1.0

    # Test DKIM probe
    probe = DKIMProbe()
    assert 0 < probe.weight <= 1.0

    # Test DMARC probe
    probe = DMARCProbe()
    assert 0 < probe.weight <= 1.0

    # Test MX probe
    probe = MXProbe()
    assert 0 < probe.weight <= 1.0

    # Test SPF probe
    probe = SPFProbe()
    assert 0 < probe.weight <= 1.0
