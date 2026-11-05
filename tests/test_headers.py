import unittest
from ciberpt.core.models import Severity
from ciberpt.modules.web.headers import HeaderScanner


class TestHeaderScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = HeaderScanner()

    def test_ideal_secure_headers(self):
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=(), geolocation=()",
            "server": "cloudflare",
        }
        findings = self.scanner.audit_headers(headers, "https://exemplo.pt")
        self.assertEqual(len(findings), 0)

    def test_missing_hsts_on_https(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        }
        findings = self.scanner.audit_headers(headers, "https://exemplo.pt")
        hsts_findings = [f for f in findings if f.id == "SEC-HDR-HSTS-MISSING"]
        self.assertEqual(len(hsts_findings), 1)
        self.assertEqual(hsts_findings[0].severity, Severity.HIGH)

    def test_weak_csp_unsafe_inline(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self' 'unsafe-inline'",
            "x-content-type-options": "nosniff",
        }
        findings = self.scanner.audit_headers(headers, "https://exemplo.pt")
        weak_csp = [f for f in findings if f.id == "SEC-HDR-CSP-WEAK-DIRECTIVES"]
        self.assertEqual(len(weak_csp), 1)
        self.assertEqual(weak_csp[0].severity, Severity.MEDIUM)

    def test_server_version_disclosure(self):
        headers = {
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
        }
        findings = self.scanner.audit_headers(headers, "http://exemplo.pt")
        server_leak = [f for f in findings if f.id == "SEC-LEAK-SERVER-VERSION"]
        powered_leak = [f for f in findings if f.id == "SEC-LEAK-POWERED-BY"]
        self.assertEqual(len(server_leak), 1)
        self.assertEqual(len(powered_leak), 1)


if __name__ == "__main__":
    unittest.main()
