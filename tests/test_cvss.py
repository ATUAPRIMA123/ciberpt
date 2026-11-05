import unittest
from ciberpt.core.cvss import CVSSCalculator
from ciberpt.core.models import Severity


class TestCVSSCalculator(unittest.TestCase):
    def test_critical_cvss_vector(self):
        # Log4j / RCE classico: Network, Low Complexity, None PR, None UI, Unchanged Scope, High CIA -> 9.8
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = CVSSCalculator.calculate_base_score(vector)
        self.assertEqual(score, 9.8)
        self.assertEqual(CVSSCalculator.score_to_severity(score), Severity.CRITICAL)

    def test_high_cvss_vector(self):
        # Network, Low Complexity, None PR, None UI, Unchanged Scope, High C, None I, None A -> 7.5
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        score = CVSSCalculator.calculate_base_score(vector)
        self.assertEqual(score, 7.5)
        self.assertEqual(CVSSCalculator.score_to_severity(score), Severity.HIGH)

    def test_medium_cvss_vector(self):
        # Reflected XSS: Network, Low Complexity, None PR, Required UI, Changed Scope, Low C, Low I, None A -> 6.1
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        score = CVSSCalculator.calculate_base_score(vector)
        self.assertEqual(score, 6.1)
        self.assertEqual(CVSSCalculator.score_to_severity(score), Severity.MEDIUM)

    def test_invalid_vector_handling(self):
        self.assertIsNone(CVSSCalculator.calculate_base_score(""))
        self.assertIsNone(CVSSCalculator.calculate_base_score("INVALID_STRING"))


if __name__ == "__main__":
    unittest.main()
