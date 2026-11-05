import unittest
from ciberpt.core.models import Severity
from ciberpt.modules.web.dns import DNSScanner


class TestDNSScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = DNSScanner()

    def test_missing_spf(self):
        records = ["google-site-verification=abc"]
        findings = self.scanner.audit_spf(records, "exemplo.pt")
        missing = [f for f in findings if f.id == "SEC-DNS-SPF-MISSING"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0].severity, Severity.MEDIUM)

    def test_permissive_spf_all(self):
        records = ['"v=spf1 ip4:192.168.1.1 +all"']
        findings = self.scanner.audit_spf(records, "exemplo.pt")
        permissive = [f for f in findings if f.id == "SEC-DNS-SPF-PERMISSIVE-ALL"]
        self.assertEqual(len(permissive), 1)
        self.assertEqual(permissive[0].severity, Severity.HIGH)

    def test_secure_spf(self):
        records = ['"v=spf1 include:_spf.google.com ~all"']
        findings = self.scanner.audit_spf(records, "exemplo.pt")
        self.assertEqual(len(findings), 0)

    def test_missing_dmarc(self):
        records = []
        findings = self.scanner.audit_dmarc(records, "exemplo.pt")
        missing = [f for f in findings if f.id == "SEC-DNS-DMARC-MISSING"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0].severity, Severity.MEDIUM)

    def test_dmarc_policy_none(self):
        records = ['"v=DMARC1; p=none; sp=none; rua=mailto:dmarc@exemplo.pt"']
        findings = self.scanner.audit_dmarc(records, "exemplo.pt")
        none_pol = [f for f in findings if f.id == "SEC-DNS-DMARC-POLICY-NONE"]
        self.assertEqual(len(none_pol), 1)
        self.assertEqual(none_pol[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()
