from __future__ import annotations
import unittest
from unittest.mock import patch, MagicMock
import datetime

from dqix.probes.network.dns import DNSProbe, DNSData
from dqix.probes.network.tls import TLSProbe, TLSData
from dqix.probes.network.http import HTTPProbe, HTTPData
from dqix.probes.network.ip import IPProbe, IPData
from dqix.probes.exceptions import ProbeError

class TestDNSProbe(unittest.TestCase):
    """Test DNS probe."""
    
    def setUp(self):
        self.probe = DNSProbe()
        self.domain = "example.com"
        
    @patch('dns.resolver.resolve')
    def test_collect_data_success(self, mock_resolve):
        """Test successful data collection."""
        # Mock DNS responses
        mock_resolve.side_effect = [
            MagicMock(),  # A record
            MagicMock(),  # AAAA record
            MagicMock(),  # MX record
            MagicMock(),  # TXT record
            MagicMock(),  # NS record
            MagicMock(),  # DNSKEY record
        ]
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, DNSData)
        self.assertEqual(data.domain, self.domain)
        self.assertTrue(data.has_a_record)
        self.assertTrue(data.has_aaaa_record)
        self.assertTrue(data.has_mx_record)
        self.assertTrue(data.has_txt_record)
        self.assertTrue(data.has_dnssec)
        self.assertIsNone(data.error)
        
    @patch('dns.resolver.resolve')
    def test_collect_data_failure(self, mock_resolve):
        """Test failed data collection."""
        mock_resolve.side_effect = Exception("DNS error")
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, DNSData)
        self.assertEqual(data.domain, self.domain)
        self.assertFalse(data.has_a_record)
        self.assertFalse(data.has_aaaa_record)
        self.assertFalse(data.has_mx_record)
        self.assertFalse(data.has_txt_record)
        self.assertFalse(data.has_dnssec)
        self.assertIsNotNone(data.error)

class TestTLSProbe(unittest.TestCase):
    """Test TLS probe."""
    
    def setUp(self):
        self.probe = TLSProbe()
        self.domain = "example.com"
        
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_collect_data_success(self, mock_context, mock_connect):
        """Test successful data collection."""
        # Mock SSL context and socket
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_connect.return_value = mock_sock
        mock_context.return_value.wrap_socket.return_value = mock_ssock
        
        # Mock certificate data
        mock_ssock.getpeercert.return_value = b"cert_data"
        mock_ssock.version.return_value = "TLSv1.2"
        mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", None)
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, TLSData)
        self.assertEqual(data.domain, self.domain)
        self.assertTrue(data.has_certificate)
        self.assertTrue(data.is_valid)
        self.assertIsNotNone(data.issuer)
        self.assertIsNotNone(data.expiry_date)
        self.assertIsNotNone(data.days_until_expiry)
        self.assertEqual(data.protocol_version, "TLSv1.2")
        self.assertEqual(data.cipher_suite, "ECDHE-RSA-AES256-GCM-SHA384")
        self.assertIsNone(data.error)
        
    @patch('socket.create_connection')
    def test_collect_data_failure(self, mock_connect):
        """Test failed data collection."""
        mock_connect.side_effect = Exception("Connection error")
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, TLSData)
        self.assertEqual(data.domain, self.domain)
        self.assertFalse(data.has_certificate)
        self.assertFalse(data.is_valid)
        self.assertIsNone(data.issuer)
        self.assertIsNone(data.expiry_date)
        self.assertIsNone(data.days_until_expiry)
        self.assertIsNone(data.protocol_version)
        self.assertIsNone(data.cipher_suite)
        self.assertIsNotNone(data.error)

class TestHTTPProbe(unittest.TestCase):
    """Test HTTP probe."""
    
    def setUp(self):
        self.probe = HTTPProbe()
        self.domain = "example.com"
        
    @patch('requests.get')
    def test_collect_data_success(self, mock_get):
        """Test successful data collection."""
        # Mock response
        mock_response = MagicMock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()"
        }
        mock_get.return_value = mock_response
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, HTTPData)
        self.assertEqual(data.domain, self.domain)
        self.assertTrue(data.has_strict_transport_security)
        self.assertTrue(data.has_content_security_policy)
        self.assertTrue(data.has_x_frame_options)
        self.assertTrue(data.has_x_content_type_options)
        self.assertTrue(data.has_xss_protection)
        self.assertTrue(data.has_referrer_policy)
        self.assertTrue(data.has_permissions_policy)
        self.assertIsNone(data.error)
        
    @patch('requests.get')
    def test_collect_data_failure(self, mock_get):
        """Test failed data collection."""
        mock_get.side_effect = Exception("Request error")
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, HTTPData)
        self.assertEqual(data.domain, self.domain)
        self.assertFalse(data.has_strict_transport_security)
        self.assertFalse(data.has_content_security_policy)
        self.assertFalse(data.has_x_frame_options)
        self.assertFalse(data.has_x_content_type_options)
        self.assertFalse(data.has_xss_protection)
        self.assertFalse(data.has_referrer_policy)
        self.assertFalse(data.has_permissions_policy)
        self.assertIsNotNone(data.error)

class TestIPProbe(unittest.TestCase):
    """Test IP probe."""
    
    def setUp(self):
        self.probe = IPProbe()
        self.domain = "example.com"
        
    @patch('socket.gethostbyname')
    def test_collect_data_success(self, mock_gethostbyname):
        """Test successful data collection."""
        mock_gethostbyname.return_value = "93.184.216.34"
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, IPData)
        self.assertEqual(data.domain, self.domain)
        self.assertEqual(data.ip_address, "93.184.216.34")
        self.assertFalse(data.is_blacklisted)
        self.assertEqual(data.blacklist_sources, [])
        self.assertIsNotNone(data.reputation_score)
        self.assertIsNone(data.error)
        
    @patch('socket.gethostbyname')
    def test_collect_data_failure(self, mock_gethostbyname):
        """Test failed data collection."""
        mock_gethostbyname.side_effect = Exception("Resolution error")
        
        data = self.probe.collect_data(self.domain)
        
        self.assertIsInstance(data, IPData)
        self.assertEqual(data.domain, self.domain)
        self.assertIsNone(data.ip_address)
        self.assertFalse(data.is_blacklisted)
        self.assertEqual(data.blacklist_sources, [])
        self.assertIsNone(data.reputation_score)
        self.assertIsNotNone(data.error)

if __name__ == '__main__':
    unittest.main() 