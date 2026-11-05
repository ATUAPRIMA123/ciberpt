import unittest
from ciberpt.core.models import Severity
from ciberpt.modules.web.cookies import CookieScanner


class TestCookieScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CookieScanner()

    def test_secure_cookie(self):
        cookie_header = "session_id=xyz123; Secure; HttpOnly; SameSite=Strict; Path=/"
        findings = self.scanner.audit_cookie_string(cookie_header, is_https=True)
        self.assertEqual(len(findings), 0)

    def test_missing_secure_on_https(self):
        cookie_header = "session_id=xyz123; HttpOnly; SameSite=Lax"
        findings = self.scanner.audit_cookie_string(cookie_header, is_https=True)
        missing_sec = [f for f in findings if f.id == "SEC-COOKIE-MISSING-SECURE"]
        self.assertEqual(len(missing_sec), 1)
        self.assertEqual(missing_sec[0].severity, Severity.MEDIUM)

    def test_missing_httponly_on_auth_cookie(self):
        cookie_header = "auth_token=abc456; Secure; SameSite=Strict"
        findings = self.scanner.audit_cookie_string(cookie_header, is_https=True)
        missing_httponly = [f for f in findings if f.id == "SEC-COOKIE-MISSING-HTTPONLY"]
        self.assertEqual(len(missing_httponly), 1)
        self.assertEqual(missing_httponly[0].severity, Severity.MEDIUM)

    def test_samesite_none_without_secure(self):
        cookie_header = "tracking_id=track789; SameSite=None"
        findings = self.scanner.audit_cookie_string(cookie_header, is_https=True)
        samesite_insecure = [f for f in findings if f.id == "SEC-COOKIE-SAMESITE-NONE-INSECURE"]
        self.assertEqual(len(samesite_insecure), 1)
        self.assertEqual(samesite_insecure[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
