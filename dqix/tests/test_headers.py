from dqix.core.probes import HeaderProbe


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


def test_hsts_csp_present(monkeypatch, example_domain):
    hdrs = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
    }
    monkeypatch.setattr("requests.get", lambda *a, **k: FakeResponse(hdrs))
    score, detail = HeaderProbe().run(example_domain)
    assert score == 1.0
    assert detail["hsts"] and detail["csp"]
