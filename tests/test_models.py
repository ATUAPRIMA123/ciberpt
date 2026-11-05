import unittest
from ciberpt.core.models import Finding, ScanResult, Severity


class TestModels(unittest.TestCase):
    def test_score_calculation_with_penalties(self):
        result = ScanResult(scan_id="test-1", target="https://exemplo.pt")
        self.assertEqual(result.calculate_score(), 100)

        # Adicionar achado HIGH (-30) e MEDIUM (-15) -> 100 - 45 = 55
        result.findings.append(Finding(
            id="SEC-1",
            module="test",
            severity=Severity.HIGH,
            title="High severity test",
            description="",
            remediation="",
        ))
        result.findings.append(Finding(
            id="SEC-2",
            module="test",
            severity=Severity.MEDIUM,
            title="Medium severity test",
            description="",
            remediation="",
        ))
        self.assertEqual(result.calculate_score(), 55)

    def test_score_does_not_go_below_zero(self):
        result = ScanResult(scan_id="test-2", target="https://exemplo.pt")
        for i in range(5):
            result.findings.append(Finding(
                id=f"SEC-{i}",
                module="test",
                severity=Severity.CRITICAL,
                title="Critical test",
                description="",
                remediation="",
            ))
        # 5 x 50 = 250 de penalidade -> limite inferior deve ser 0
        self.assertEqual(result.calculate_score(), 0)

    def test_serialization_dict(self):
        result = ScanResult(scan_id="test-3", target="https://exemplo.pt")
        result.findings.append(Finding(
            id="SEC-INFO-1",
            module="test",
            severity=Severity.INFO,
            title="Info test",
            description="desc",
            remediation="rem",
        ))
        d = result.to_dict()
        self.assertEqual(d["scan_id"], "test-3")
        self.assertEqual(len(d["findings"]), 1)
        self.assertEqual(d["findings"][0]["severity"], "INFO")


if __name__ == "__main__":
    unittest.main()
