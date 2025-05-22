from dqix.core.probes import WHOISProbe


def test_whois_transparent(monkeypatch, example_domain):
    monkeypatch.setattr("whois.whois", lambda d: {"org": "Bank of Thailand"})
    score, _ = WHOISProbe().run(example_domain)
    assert score == 1.0
