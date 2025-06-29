"""Tests for DQIX components."""


import pytest
from dqix.core.mixins import ProbeUtils
from dqix.core.probes import PROBES, Probe, ProbeConfig, register
from dqix.core.scoring import CategoryScorer, ProbeResult, WeightedScorer


def test_domain_validation():
    """Test domain validation functionality."""
    # Valid domains
    assert ProbeUtils.validate_domain("example.com")
    assert ProbeUtils.validate_domain("sub.example.com")
    assert ProbeUtils.validate_domain("test-domain.org")

    # Invalid domains
    assert not ProbeUtils.validate_domain("")
    assert not ProbeUtils.validate_domain("invalid")
    assert not ProbeUtils.validate_domain("-invalid.com")
    assert not ProbeUtils.validate_domain("invalid-.com")
    assert not ProbeUtils.validate_domain("a" * 256)  # Too long


def test_dns_record_functions():
    """Test DNS record parsing functionality."""
    # Test finding records
    records = ["v=spf1 include:_spf.google.com ~all", "v=DKIM1; k=rsa; p=..."]
    spf_record = ProbeUtils.find_dns_record(records, "v=spf1")
    assert spf_record == "v=spf1 include:_spf.google.com ~all"

    dkim_record = ProbeUtils.find_dns_record(records, "v=DKIM1")
    assert dkim_record == "v=DKIM1; k=rsa; p=..."

    # Test parsing records
    parsed = ProbeUtils.parse_txt_record("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA")
    expected = {"v": "DKIM1", "k": "rsa", "p": "MIGfMA0GCSqGSIb3DQEBAQUAA"}
    assert parsed == expected


@pytest.fixture
def reset_probes():
    """Reset PROBES registry before and after each test."""
    original_probes = PROBES.copy()
    yield
    PROBES.clear()
    PROBES.update(original_probes)


def test_probe_registration(reset_probes):
    """Test that probes can be registered."""
    @register
    class TestProbe(Probe):
        id = "test_probe"

        def run(self, domain):
            return ProbeResult(
                probe_id=self.id,
                score=1.0,
                details={"test": True},
                weight=1.0,
            )

    assert "test_probe" in PROBES
    assert PROBES["test_probe"] == TestProbe


def test_probe_registration_without_id(reset_probes):
    """Test that probes without id raise error."""
    with pytest.raises(ValueError):
        @register
        class BadProbe(Probe):
            def run(self, domain):
                return ProbeResult(
                    probe_id="bad",
                    score=1.0,
                    details={},
                    weight=1.0,
                )


def test_basic_probe(reset_probes):
    """Test basic probe functionality."""
    @register
    class TestProbe(Probe):
        id = "test_basic_probe"
        weight = 0.1

        def run(self, domain):
            self.validate_domain(domain)

            # Simulate probe logic
            return ProbeResult(
                probe_id=self.id,
                score=1.0,
                details={"test": True, "domain": domain},
                weight=self.weight,
            )

    # Test with valid domain
    probe = TestProbe()
    result = probe.run("example.com")
    assert result.score == 1.0
    assert result.details["domain"] == "example.com"

    # Test with invalid domain
    with pytest.raises(ValueError):
        probe.run("invalid")


def test_probe_with_config(reset_probes):
    """Test probe with configuration."""
    @register
    class TestProbe(Probe):
        id = "test_config_probe"

        def run(self, domain):
            self._report_progress(f"Testing {domain}")
            return ProbeResult(
                probe_id=self.id,
                score=1.0,
                details={"verbosity": self.config.verbosity},
                weight=1.0,
            )

    # Test with custom config
    config = ProbeConfig(verbosity=2)
    probe = TestProbe(config=config)
    result = probe.run("example.com")
    assert result.details["verbosity"] == 2

    # Test with default config
    probe = TestProbe()
    result = probe.run("example.com")
    assert result.details["verbosity"] == 0


def test_weighted_scorer():
    """Test weighted scoring."""
    scorer = WeightedScorer()

    results = [
        ProbeResult("probe1", 0.8, {}, 0.5),
        ProbeResult("probe2", 0.6, {}, 0.5),
    ]

    score = scorer.calculate_score(results)
    assert score == 0.7  # (0.8 * 0.5 + 0.6 * 0.5) / (0.5 + 0.5)


def test_category_scorer():
    """Test category-based scoring."""
    scorer = CategoryScorer({
        "email": 0.6,
        "dns": 0.4,
    })

    results = [
        ProbeResult("probe1", 0.8, {}, 1.0, "email"),
        ProbeResult("probe2", 0.6, {}, 1.0, "dns"),
    ]

    score = scorer.calculate_score(results)
    assert score == 0.72  # (0.8 * 0.6 + 0.6 * 0.4)


def test_cli_functions_exist():
    """Test that CLI functions exist and are importable."""
    from dqix.cli.main import bulk, check, display_results, load_domains, save_results

    # Just test that they're callable
    assert callable(load_domains)
    assert callable(save_results)
    assert callable(display_results)
    assert callable(check)
    assert callable(bulk)
