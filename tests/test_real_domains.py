"""Tests using real domains to verify probe functionality."""

import unittest

# Import probes to trigger registration
from dqix.core.levels import load_level
from dqix.core.probes import PROBES
from dqix.core.scoring import domain_score


class TestRealDomains(unittest.TestCase):
    """Test probes against real domains with known characteristics."""

    def setUp(self):
        """Set up test environment."""
        # Import probes module to ensure registration
        self.level1_probes = load_level(1)
        self.level3_probes = load_level(3)

    def test_high_compliance_domains(self):
        """Test domains known to have high security compliance."""
        high_compliance_domains = [
            "cloudflare.com",  # Known for excellent security practices
            "google.com",      # High security standards
            "github.com",      # Good security practices
        ]

        for domain in high_compliance_domains:
            with self.subTest(domain=domain):
                score, details = domain_score(domain, self.level3_probes)

                # These domains should score above 70%
                assert score > 70, f"{domain} scored {score}%, expected >70%. Details: {details}"

                # Check specific security features we expect
                if "tls" in details:
                    assert details["tls"].get("score", 0) > 0.8, f"{domain} should have good TLS score"

                if "dnssec" in details:
                    # These domains should have DNSSEC
                    assert details["dnssec"].get("details", {}).get("ad_flag", False), f"{domain} should have DNSSEC validation"

    def test_medium_compliance_domains(self):
        """Test domains with medium security compliance."""
        medium_compliance_domains = [
            "wikipedia.org",   # Good but not perfect security
            "apache.org",      # Open source project site
            "python.org",      # Python official site
        ]

        for domain in medium_compliance_domains:
            with self.subTest(domain=domain):
                score, details = domain_score(domain, self.level3_probes)

                # These domains should score between 40-80%
                assert score > 40, f"{domain} scored {score}%, expected >40%. Details: {details}"
                assert score < 90, f"{domain} scored {score}%, expected <90%. Details: {details}"

    def test_government_domains(self):
        """Test government domains which should have good compliance."""
        gov_domains = [
            "usa.gov",         # US government portal
            "gov.uk",          # UK government portal
            "canada.ca",       # Canadian government portal
        ]

        for domain in gov_domains:
            with self.subTest(domain=domain):
                score, details = domain_score(domain, self.level3_probes)

                # Government domains should score above 60%
                assert score > 60, f"{domain} scored {score}%, expected >60%. Details: {details}"

                # Check for HTTPS/TLS
                if "tls" in details:
                    assert details["tls"].get("score", 0) > 0.7, f"Government domain {domain} should have good TLS"

    def test_educational_domains(self):
        """Test educational institution domains."""
        edu_domains = [
            "mit.edu",         # MIT
            "stanford.edu",    # Stanford University
            "ox.ac.uk",        # Oxford University
        ]

        for domain in edu_domains:
            with self.subTest(domain=domain):
                score, details = domain_score(domain, self.level3_probes)

                # Educational domains typically score 50-80%
                assert score > 50, f"{domain} scored {score}%, expected >50%. Details: {details}"

    def test_dns_basic_probe(self):
        """Test DNS basic probe with real domains."""
        dns_probe = PROBES.get("dns_basic")
        if not dns_probe:
            self.skipTest("DNS basic probe not found")

        probe = dns_probe()

        # Test a well-configured domain
        score, details = probe.run("cloudflare.com")
        assert score > 0.8, "Cloudflare should have good DNS configuration"
        assert details.get("a_present", False), "Should have A records"
        assert details.get("ns_count", 0) > 1, "Should have multiple NS records"

        # Test a domain that might not have MX records
        score, details = probe.run("example.com")
        assert score > 0.5, "example.com should have basic DNS"

    def test_tls_probe(self):
        """Test TLS probe with real domains."""
        tls_probe = PROBES.get("tls")
        if not tls_probe:
            self.skipTest("TLS probe not found")

        probe = tls_probe()

        # Test domains with known good TLS
        good_tls_domains = ["cloudflare.com", "google.com", "github.com"]

        for domain in good_tls_domains:
            with self.subTest(domain=domain):
                score, details = probe.run(domain)
                assert score > 0.8, f"{domain} should have excellent TLS score. Details: {details}"

                # Check for modern TLS features
                grade = details.get("tls_grade", "")
                if isinstance(grade, str) and grade not in ["local_handshake", "Error"]:
                    assert grade[0] in ["A", "B"], f"{domain} should have A or B grade TLS"

    def test_dnssec_probe(self):
        """Test DNSSEC probe with real domains."""
        dnssec_probe = PROBES.get("dnssec")
        if not dnssec_probe:
            self.skipTest("DNSSEC probe not found")

        probe = dnssec_probe()

        # Domains known to have DNSSEC
        dnssec_domains = ["cloudflare.com", "google.com", "nic.cz"]

        for domain in dnssec_domains:
            with self.subTest(domain=domain):
                score, details = probe.run(domain)

                # These domains should have DNSSEC enabled
                assert score > 0.5, f"{domain} should have DNSSEC. Score: {score}, Details: {details}"

                # Check for AD flag (authenticated data)
                assert details.get("ad_flag", False) or details.get("chain_valid", False), f"{domain} should have validated DNSSEC chain"

    def test_probe_error_handling(self):
        """Test probe error handling with non-existent domains."""
        non_existent = "this-domain-definitely-does-not-exist-12345.com"

        score, details = domain_score(non_existent, self.level1_probes)

        # Should return low score for non-existent domain
        assert score < 20, f"Non-existent domain should score low. Score: {score}"

        # Check that probes handled the error gracefully
        for probe_id, probe_details in details.items():
            if isinstance(probe_details, dict):
                # Probe should either have error or very low score
                if "error" in probe_details:
                    assert probe_details["error"] is not None
                else:
                    assert probe_details.get("score", 1) < 0.5, f"Probe {probe_id} should score low for non-existent domain"


if __name__ == "__main__":
    unittest.main()
