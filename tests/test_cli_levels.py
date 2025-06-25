from dqix.cli import load_level


def test_level1_contains_only_tls_dnssec() -> None:
    probes = load_level(1)
    assert set(probes.keys()) == {"tls", "dnssec"}
