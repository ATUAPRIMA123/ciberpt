import json
from typing import Optional
from ciberpt.core.models import ScanResult


class JSONReporter:
    @staticmethod
    def render(result: ScanResult) -> str:
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)

    @staticmethod
    def save(result: ScanResult, filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(JSONReporter.render(result))
