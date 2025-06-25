from dqix.core.probes import DNSSECProbe


def test_dnssec_unsigned(monkeypatch, example_domain) -> None:
    fake_resp = {"Status": 0, "AD": False}

    # mock requests.get.json
    class FakeResponse:
        def json(self):
            return fake_resp

    monkeypatch.setattr("requests.get", lambda *a, **k: FakeResponse())
    score, _ = DNSSECProbe().run(example_domain)
    assert score == 0.0
