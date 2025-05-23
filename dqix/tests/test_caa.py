import pytest
from dqix.core.probes import CAAProbe

def test_caa_restricts(monkeypatch):
    monkeypatch.setattr(
        "dqix.utils.dns.get_caa_records",
        lambda domain: ["0 issue \"letsencrypt.org\""]
    )
    score, details = CAAProbe().run("example.com")
    assert score == 1.0
    assert details["caa_found"] is True
    assert details["restricts"] is True

def test_caa_found_but_not_restrict(monkeypatch):
    monkeypatch.setattr(
        "dqix.utils.dns.get_caa_records",
        lambda domain: ["0 iodef \"mailto:admin@example.com\""]
    )
    score, details = CAAProbe().run("example.com")
    assert score == 0.5
    assert details["caa_found"] is True
    assert details["restricts"] is False

def test_caa_not_found(monkeypatch):
    monkeypatch.setattr("dqix.utils.dns.get_caa_records", lambda domain: [])
    score, details = CAAProbe().run("example.com")
    assert score == 0.0
    assert details["caa_found"] is False 