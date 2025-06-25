"""Tests for the DQIX engine."""

from unittest.mock import MagicMock

import pytest

from dqix.core.engine import CheckEngine
from dqix.core.probes import Probe
from dqix.core.scoring import ProbeResult
from dqix.probes.tls import TLSProbe


class MockProbe(Probe):
    """Mock probe for testing."""

    id = "mock"
    weight = 1.0
    description = "Mock probe for testing"
    category = "test"

    def run(self, domain: str) -> ProbeResult:
        """Mock run method."""
        return ProbeResult(
            probe_id=self.id,
            score=0.8,
            details={"status": "ok"},
            weight=self.weight,
            category=self.category,
        )


@pytest.mark.asyncio
async def test_check_domain():
    """Test checking a single domain."""
    # Create engine with mock probe
    probe = MockProbe()
    engine = CheckEngine(probes=[probe])

    # Check domain
    result = await engine.check_domain("example.com")

    # Verify result
    assert result.domain == "example.com"
    assert result.score == 0.8
    assert result.details == {"mock": {"status": "ok"}}
    assert not result.errors


@pytest.mark.asyncio
async def test_check_domains():
    """Test checking multiple domains."""
    # Create engine with mock probe
    probe = MockProbe()
    engine = CheckEngine(probes=[probe])

    # Check domains
    results = await engine.check_domains(["example.com", "test.com"])

    # Verify results
    assert len(results) == 2
    for result in results:
        assert result.score == 0.8
        assert result.details == {"mock": {"status": "ok"}}
        assert not result.errors


@pytest.mark.asyncio
async def test_probe_error():
    """Test handling probe errors."""
    # Create probe that raises an error
    probe = MockProbe()
    probe.run = MagicMock(side_effect=Exception("Test error"))

    # Create engine
    engine = CheckEngine(probes=[probe])

    # Check domain
    result = await engine.check_domain("example.com")

    # Verify error handling
    assert result.domain == "example.com"
    assert result.score == 0.0
    assert not result.details
    assert len(result.errors) == 1
    assert "Test error" in result.errors[0]


@pytest.mark.asyncio
async def test_caching():
    """Test result caching."""
    # Create engine with mock probe
    probe = MockProbe()
    probe.run = MagicMock(return_value=ProbeResult(
        probe_id="mock",
        score=1.0,
        details={"test": True},
        weight=1.0,
        category="test",
    ))
    engine = CheckEngine(probes=[probe])

    # First check
    result1 = await engine.check_domain("example.com", use_cache=True)

    # Second check (should use cache)
    result2 = await engine.check_domain("example.com", use_cache=True)

    # Verify caching
    assert result1 == result2
    assert probe.run.call_count == 1


@pytest.mark.asyncio
async def test_tls_probe():
    """Test TLS probe."""
    # Create engine with TLS probe
    engine = CheckEngine(probes=[TLSProbe()])

    # Check domain
    result = await engine.check_domain("example.com")

    # Verify result structure
    assert result.domain == "example.com"
    assert isinstance(result.score, float)
    assert isinstance(result.details, dict)
    assert isinstance(result.errors, list)
