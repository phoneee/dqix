from dqix.core.probes import MailProbe


def make_txt(text):
    return [text]


def test_mail_spf_only(monkeypatch, example_domain):
    # SPF present, no DMARC
    monkeypatch.setattr(
        "dqix.utils.dns.get_txt_records",
        lambda name: make_txt("v=spf1 -all") if name == example_domain else [],
    )
    score, details = MailProbe().run(example_domain)
    assert score == 0.5
    assert details["spf_present"] is True
    assert details["dmarc_policy"] == "none"
