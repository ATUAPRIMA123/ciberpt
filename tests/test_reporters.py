import tempfile
import unittest
from pathlib import Path
from ciberpt.core.models import Finding, ScanResult, Severity
from ciberpt.reporters.html_reporter import HTMLReporter
from ciberpt.reporters.json_reporter import JSONReporter


class TestReporters(unittest.TestCase):
    def setUp(self):
        self.result = ScanResult(scan_id="test-scan-123", target="https://exemplo.pt")
        self.result.findings.append(Finding(
            id="SEC-TEST-001",
            module="web.headers",
            severity=Severity.HIGH,
            title="Cabecalho de teste ausente",
            description="Descricao tecnica detalhada do achado.",
            remediation="Aplicar configuracao recomendada.",
            evidence="Header: missing",
        ))
        self.result.calculate_score()

    def test_json_reporter(self):
        rendered = JSONReporter.render(self.result)
        self.assertIn("test-scan-123", rendered)
        self.assertIn("SEC-TEST-001", rendered)
        self.assertIn('"score": 70', rendered)

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f_path = Path(f.name)
        try:
            JSONReporter.save(self.result, str(f_path))
            self.assertTrue(f_path.exists())
            content = f_path.read_text(encoding="utf-8")
            self.assertIn("SEC-TEST-001", content)
        finally:
            f_path.unlink()

    def test_html_reporter(self):
        rendered = HTMLReporter.render(self.result)
        self.assertIn("<!DOCTYPE html>", rendered)
        self.assertIn("https://exemplo.pt", rendered)
        self.assertIn("SEC-TEST-001", rendered)
        self.assertIn("Cabecalho de teste ausente", rendered)
        self.assertIn("Header: missing", rendered)
        self.assertIn("70", rendered)

        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
            f_path = Path(f.name)
        try:
            HTMLReporter.save(self.result, str(f_path))
            self.assertTrue(f_path.exists())
            content = f_path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("ciberpt - Relatorio de Auditoria", content)
        finally:
            f_path.unlink()


if __name__ == "__main__":
    unittest.main()
