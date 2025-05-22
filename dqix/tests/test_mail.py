from dqix.core.probes import MailProbe


def make_txt(text):
    return [text]


def test_mail_spf_only(monkeypatch, example_domain):
    # SPF present, no DMARC
    monkeypatch.setattr(
        MailProbe,
        "_txt",
        lambda self, name: make_txt("v=spf1 -all") if name == example_domain else [],
    )
    score, _ = MailProbe().run(example_domain)
    assert score == 0.5
