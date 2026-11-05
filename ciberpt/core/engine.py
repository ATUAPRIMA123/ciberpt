import uuid
from typing import List, Optional

from ciberpt.core.models import Finding, ScanResult
from ciberpt.modules.base import BaseScanner
from ciberpt.modules.web.headers import HeaderScanner
from ciberpt.modules.web.tls import TLSScanner


class AuditEngine:
    AVAILABLE_MODULES = {
        "web.headers": HeaderScanner,
        "web.tls": TLSScanner,
    }

    MODULE_GROUPS = {
        "web": ["web.headers", "web.tls"],
        "all": ["web.headers", "web.tls"],
    }

    def __init__(self, modules: Optional[List[str]] = None, timeout: int = 10):
        self.timeout = timeout
        self.scanners: List[BaseScanner] = []
        self._load_scanners(modules or ["all"])

    def _load_scanners(self, requested: List[str]) -> None:
        module_keys = set()
        for item in requested:
            if item in self.MODULE_GROUPS:
                module_keys.update(self.MODULE_GROUPS[item])
            elif item in self.AVAILABLE_MODULES:
                module_keys.add(item)
            else:
                raise ValueError(f"Modulo desconhecido: '{item}'")

        for key in sorted(module_keys):
            scanner_cls = self.AVAILABLE_MODULES[key]
            self.scanners.append(scanner_cls())

    def run(self, target: str) -> ScanResult:
        scan_id = f"ciberpt-{uuid.uuid4().hex[:8]}"
        result = ScanResult(scan_id=scan_id, target=target)

        all_findings: List[Finding] = []
        for scanner in self.scanners:
            findings = scanner.scan(target, timeout=self.timeout)
            all_findings.extend(findings)

        result.findings = all_findings
        result.calculate_score()
        return result
