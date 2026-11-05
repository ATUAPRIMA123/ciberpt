import math
from typing import Optional
from ciberpt.core.models import Severity


class CVSSCalculator:
    AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_MAP = {"L": 0.77, "H": 0.44}
    UI_MAP = {"N": 0.85, "R": 0.62}
    CIA_MAP = {"N": 0.0, "L": 0.22, "H": 0.56}

    @classmethod
    def calculate_base_score(cls, vector: str) -> Optional[float]:
        try:
            clean_vector = vector.strip()
            if not clean_vector:
                return None

            if "AV:" not in clean_vector or "AC:" not in clean_vector or "PR:" not in clean_vector:
                return None

            parts = dict(
                p.split(":")
                for p in clean_vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
                if ":" in p
            )

            s = parts.get("S", "U")
            scope_changed = (s == "C")

            pr = parts.get("PR", "N")
            if not scope_changed:
                pr_val = {"N": 0.85, "L": 0.62, "H": 0.27}.get(pr, 0.85)
            else:
                pr_val = {"N": 0.85, "L": 0.68, "H": 0.50}.get(pr, 0.85)

            av = cls.AV_MAP.get(parts.get("AV", "N"), 0.85)
            ac = cls.AC_MAP.get(parts.get("AC", "L"), 0.77)
            ui = cls.UI_MAP.get(parts.get("UI", "N"), 0.85)
            c = cls.CIA_MAP.get(parts.get("C", "N"), 0.0)
            i = cls.CIA_MAP.get(parts.get("I", "N"), 0.0)
            a = cls.CIA_MAP.get(parts.get("A", "N"), 0.0)

            iss = 1 - ((1 - c) * (1 - i) * (1 - a))
            if not scope_changed:
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

            exploitability = 8.22 * av * ac * pr_val * ui

            if impact <= 0:
                return 0.0

            if not scope_changed:
                score = min(impact + exploitability, 10.0)
            else:
                score = min(1.08 * (impact + exploitability), 10.0)

            return math.ceil(round(score, 4) * 10) / 10
        except Exception:
            return None

    @classmethod
    def score_to_severity(cls, score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0.0:
            return Severity.LOW
        return Severity.INFO
