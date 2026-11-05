import os
import uuid
from pathlib import Path
from typing import List, Optional

from ciberpt.core.models import Finding, ScanResult
from ciberpt.modules.base import BaseScanner
from ciberpt.modules.web.headers import HeaderScanner
from ciberpt.modules.web.tls import TLSScanner
from ciberpt.modules.web.dns import DNSScanner
from ciberpt.modules.web.cors import CORSScanner
from ciberpt.modules.web.cookies import CookieScanner
from ciberpt.modules.appsec.php_upload import PHPUploadScanner


class AuditEngine:
    AVAILABLE_MODULES = {
        "web.headers": HeaderScanner,
        "web.tls": TLSScanner,
        "web.dns": DNSScanner,
        "web.cors": CORSScanner,
        "web.cookies": CookieScanner,
        "appsec.php_upload": PHPUploadScanner,
    }

    MODULE_GROUPS = {
        "web": ["web.headers", "web.tls", "web.dns", "web.cors", "web.cookies"],
        "appsec": ["appsec.php_upload"],
        "all": ["web.headers", "web.tls", "web.dns", "web.cors", "web.cookies", "appsec.php_upload"],
    }

    def __init__(self, modules: Optional[List[str]] = None, timeout: int = 10):
        self.timeout = timeout
        self.requested_modules = modules or ["all"]
        self.scanners: List[BaseScanner] = []

    def _resolve_scanners(self, target: str) -> List[BaseScanner]:
        module_keys = set()
        is_local_target = Path(target).exists()

        for item in self.requested_modules:
            if item == "all":
                # Se for alvo local existente (pasta/ficheiro), executar modulos de AppSec
                # Se for alvo remoto (URL/dominio), executar modulos Web
                if is_local_target:
                    module_keys.update(self.MODULE_GROUPS["appsec"])
                else:
                    module_keys.update(self.MODULE_GROUPS["web"])
            elif item in self.MODULE_GROUPS:
                module_keys.update(self.MODULE_GROUPS[item])
            elif item in self.AVAILABLE_MODULES:
                module_keys.add(item)
            else:
                raise ValueError(f"Modulo desconhecido: '{item}'")

        scanners = []
        for key in sorted(module_keys):
            scanner_cls = self.AVAILABLE_MODULES[key]
            scanners.append(scanner_cls())
        return scanners

    def run(self, target: str) -> ScanResult:
        scan_id = f"ciberpt-{uuid.uuid4().hex[:8]}"
        result = ScanResult(scan_id=scan_id, target=target)

        active_scanners = self._resolve_scanners(target)
        all_findings: List[Finding] = []

        for scanner in active_scanners:
            findings = scanner.scan(target, timeout=self.timeout)
            all_findings.extend(findings)

        result.findings = all_findings
        result.calculate_score()
        return result
