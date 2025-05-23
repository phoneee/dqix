import pytest
from dqix.core.probes import WCAGUsabilityProbe

class FakeResp:
    def __init__(self, text):
        self.text = text

@pytest.mark.parametrize("html,expected_score,expected_details", [
    ("""
    <html><head><meta name='viewport' content='width=device-width'></head><body style='font-size:16px;'>
    <a href='#maincontent'>Skip to main</a>
    <a href='about.html'>About us</a>
    <a href='contact.html'>Contact</a>
    </body></html>
    """, 1.0, {"font_ok": True, "viewport_ok": True, "skip_ok": True, "link_text_ok": True, "link_count": 3}),
    ("""
    <html><head></head><body>
    <a href='#'>Click here</a>
    <a href='about.html'>About</a>
    </body></html>
    """, 0.0, {"font_ok": False, "viewport_ok": False, "skip_ok": False, "link_text_ok": False, "link_count": 2}),
    ("""
    <html><head><meta name='viewport' content='width=device-width'></head><body>
    <a href='about.html'>About us</a>
    </body></html>
    """, 0.5, {"font_ok": False, "viewport_ok": True, "skip_ok": False, "link_text_ok": True, "link_count": 1}),
])
def test_wcag_usability_probe(monkeypatch, html, expected_score, expected_details):
    def fake_get(url, timeout):
        return FakeResp(html)
    monkeypatch.setattr("requests.get", fake_get)
    score, details = WCAGUsabilityProbe().run("example.com")
    assert abs(score - expected_score) < 0.01
    for k, v in expected_details.items():
        assert details[k] == v 