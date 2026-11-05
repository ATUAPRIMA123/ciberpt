import unittest
from ciberpt.core.models import Severity
from ciberpt.modules.sca.dependency_scanner import DependencyScanner


class TestDependencyScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = DependencyScanner()

    def test_parse_requirements_txt(self):
        content = """
        # Comentarios
        requests==2.25.0
        flask~=1.1.2
        urllib3>=1.26.0
        jinja2==2.11.2
        """
        packages = self.scanner._parse_requirements_txt(content)
        self.assertEqual(len(packages), 3)  # requests, flask, jinja2
        names = [p[0] for p in packages]
        self.assertIn("requests", names)
        self.assertIn("flask", names)
        self.assertIn("jinja2", names)

    def test_parse_npm_package_json(self):
        content = """{
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "4.17.20"
            }
        }"""
        packages = self.scanner._parse_npm_manifest(content, "package.json")
        self.assertEqual(len(packages), 2)
        pkg_dict = {p[0]: p[1] for p in packages}
        self.assertEqual(pkg_dict["express"], "4.17.1")
        self.assertEqual(pkg_dict["lodash"], "4.17.20")

    def test_format_finding_with_cve_and_cvss(self):
        vuln_mock = {
            "id": "GHSA-test-123",
            "aliases": ["CVE-2024-99999"],
            "summary": "Mock vulnerability for testing",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            "affected": [
                {
                    "ranges": [
                        {
                            "events": [{"introduced": "0"}, {"fixed": "2.26.0"}]
                        }
                    ]
                }
            ]
        }
        finding = self.scanner._format_finding(
            vuln_mock, "test-pkg", "2.25.0", "PyPI", "requirements.txt"
        )
        self.assertEqual(finding.cve_id, "CVE-2024-99999")
        self.assertEqual(finding.cvss_score, 9.8)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertIn("2.26.0", finding.remediation)


if __name__ == "__main__":
    unittest.main()
