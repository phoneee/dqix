from dqix.core.probes import DKIMProbe


def test_dkim_found(monkeypatch) -> None:
    def fake_get_txt_records(name):
        if name.startswith("default._domainkey."):
            return ["v=DKIM1; k=rsa; p=abc123"]
        return []
    monkeypatch.setattr("dqix.utils.dns.get_txt_records", fake_get_txt_records)
    score, details = DKIMProbe().run("example.com")
    assert score == 1.0
    assert details["dkim_found"] is True
    assert details["selector"] == "default"

def test_dkim_not_found(monkeypatch) -> None:
    monkeypatch.setattr("dqix.utils.dns.get_txt_records", lambda name: [])
    score, details = DKIMProbe().run("example.com")
    assert score == 0.0
    assert details["dkim_found"] is False
