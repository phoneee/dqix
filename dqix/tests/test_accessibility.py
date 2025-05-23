import pytest
from dqix.core.probes import AccessibilityProbe

class FakeResp:
    def __init__(self, text):
        self.text = text

@pytest.mark.parametrize("html,expected_score,expected_details", [
    ("""
    <html><head><title>Test</title></head><body>
    <img src='a.png' alt='desc'>
    <form><label for='x'>X</label><input id='x'></form>
    </body></html>
    """, 1.0, {"has_title": True, "img_count": 1, "img_missing_alt": 0, "input_count": 1, "inputs_without_label": 0}),
    ("""
    <html><head></head><body>
    <img src='a.png'>
    <form><input id='x'></form>
    </body></html>
    """, 0.0, {"has_title": False, "img_count": 1, "img_missing_alt": 1, "input_count": 1, "inputs_without_label": 1}),
    ("""
    <html><head><title>Test</title></head><body>
    </body></html>
    """, 1.0, {"has_title": True, "img_count": 0, "img_missing_alt": 0, "input_count": 0, "inputs_without_label": 0}),
])
def test_accessibility_probe(monkeypatch, html, expected_score, expected_details):
    def fake_get(url, timeout):
        return FakeResp(html)
    monkeypatch.setattr("requests.get", fake_get)
    score, details = AccessibilityProbe().run("example.com")
    assert abs(score - expected_score) < 0.01
    for k, v in expected_details.items():
        assert details[k] == v 