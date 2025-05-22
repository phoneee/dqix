from dqix.core.probes import TLSProbe


def test_tls_local_ok(monkeypatch, example_domain):
    # Patch TLSProbe handshake to True
    monkeypatch.setattr(TLSProbe, "_handshake_ok", lambda self, d: True)
    monkeypatch.setattr(TLSProbe, "_grade_from_sslyze", lambda self, d: None)
    monkeypatch.setattr(TLSProbe, "_grade_api", lambda self, d: None)
    score, detail = TLSProbe().run(example_domain)
    assert score == 1.0
    assert detail["tls_ok"] is True
