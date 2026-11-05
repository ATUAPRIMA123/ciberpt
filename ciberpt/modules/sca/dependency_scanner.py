import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import requests

from ciberpt.core.cvss import CVSSCalculator
from ciberpt.core.models import Finding, Severity
from ciberpt.modules.base import BaseScanner


class DependencyScanner(BaseScanner):
    OSV_ENDPOINT = "https://api.osv.dev/v1/query"

    @property
    def name(self) -> str:
        return "sca.dependencies"

    @property
    def description(self) -> str:
        return "Auditoria de Software Composition Analysis (SCA) para deteccao de CVEs e pontuacoes CVSS em dependencias"

    def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Finding]:
        target_path = Path(target)
        findings: List[Finding] = []

        if not target_path.exists():
            return findings

        # Caso seja ficheiro especifico
        if target_path.is_file():
            findings.extend(self._audit_single_manifest(target_path, timeout))
            return findings

        # Caso seja diretorio
        for root, _, files in os.walk(target_path):
            if any(ignored in root.replace("\\", "/").split("/") for ignored in ["node_modules", "vendor", ".git", ".venv", "venv"]):
                continue

            for file in files:
                file_path = Path(root) / file
                if file in ["requirements.txt", "package.json", "package-lock.json", "composer.json", "composer.lock"]:
                    findings.extend(self._audit_single_manifest(file_path, timeout))

        return findings

    def _audit_single_manifest(self, file_path: Path, timeout: int) -> List[Finding]:
        packages: List[Tuple[str, str, str]] = []  # (nome, versao, ecossistema)

        filename = file_path.name.lower()
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        if filename == "requirements.txt":
            packages.extend(self._parse_requirements_txt(content))
        elif filename in ["package.json", "package-lock.json"]:
            packages.extend(self._parse_npm_manifest(content, filename))
        elif filename in ["composer.json", "composer.lock"]:
            packages.extend(self._parse_composer_manifest(content, filename))

        findings: List[Finding] = []
        for name, version, ecosystem in packages:
            vulns = self.query_osv_vulnerabilities(name, version, ecosystem, timeout=timeout)
            for v in vulns:
                findings.append(self._format_finding(v, name, version, ecosystem, str(file_path)))

        return findings

    def query_osv_vulnerabilities(
        self, package_name: str, version: str, ecosystem: str, timeout: int = 10
    ) -> List[dict]:
        payload = {
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
        }
        try:
            resp = requests.post(self.OSV_ENDPOINT, json=payload, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
        except requests.exceptions.RequestException:
            pass
        return []

    def _format_finding(
        self, vuln: dict, package_name: str, version: str, ecosystem: str, file_path: str
    ) -> Finding:
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        vuln_id = cve_id or vuln.get("id", "VULN-UNKNOWN")

        # Extrair CVSS v3/v4 se disponivel
        cvss_score = None
        cvss_vector = None
        severities = vuln.get("severity", [])
        for sev in severities:
            score_str = sev.get("score", "")
            if "CVSS:3" in score_str:
                cvss_vector = score_str
                cvss_score = CVSSCalculator.calculate_base_score(score_str)
                break

        # Fallback de severidade se nao houver vetor CVSS calculado
        if cvss_score is not None:
            severity = CVSSCalculator.score_to_severity(cvss_score)
        else:
            # Fallback generico
            severity = Severity.HIGH

        summary = vuln.get("summary") or vuln.get("details", "")[:120] or "Vulnerabilidade conhecida em componente de terceiro."
        summary = summary.strip().rstrip(".")

        # Procura versao corrigida recomendada
        fixed_version = self._extract_fixed_version(vuln)
        remediation = (
            f"Atualizar o pacote '{package_name}' para a versao {fixed_version} ou superior."
            if fixed_version
            else f"Atualizar o pacote '{package_name}' para uma versao estavel que mitigue {vuln_id}."
        )

        cvss_info = f" [CVSS {cvss_score}]" if cvss_score is not None else ""
        title = f"{vuln_id}{cvss_info}: Vulnerabilidade no pacote {package_name} ({version})"

        return Finding(
            id=f"SEC-SCA-{vuln_id}",
            module=self.name,
            severity=severity,
            title=title,
            description=f"{summary} Identificado no ficheiro '{file_path}'.",
            remediation=remediation,
            evidence={
                "package": package_name,
                "current_version": version,
                "ecosystem": ecosystem,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "manifest_file": file_path,
            },
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
        )

    def _extract_fixed_version(self, vuln: dict) -> Optional[str]:
        try:
            affected = vuln.get("affected", [])
            for aff in affected:
                ranges = aff.get("ranges", [])
                for r in ranges:
                    events = r.get("events", [])
                    for ev in events:
                        if "fixed" in ev:
                            return ev["fixed"]
        except Exception:
            pass
        return None

    def _parse_requirements_txt(self, content: str) -> List[Tuple[str, str, str]]:
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Padrao: package==1.2.3 ou package~=1.2.3
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|~=)\s*([0-9a-zA-Z\.\-]+)", line)
            if match:
                pkg_name, pkg_version = match.group(1), match.group(2)
                packages.append((pkg_name, pkg_version, "PyPI"))
        return packages

    def _parse_npm_manifest(self, content: str, filename: str) -> List[Tuple[str, str, str]]:
        packages = []
        try:
            data = json.loads(content)
            if filename == "package-lock.json":
                # package-lock v2/v3
                packages_dict = data.get("packages", {})
                for pkg_path, info in packages_dict.items():
                    if not pkg_path:
                        continue
                    pkg_name = pkg_path.replace("node_modules/", "")
                    version = info.get("version")
                    if version and not version.startswith("file:"):
                        packages.append((pkg_name, version, "npm"))
            else:
                deps = data.get("dependencies", {})
                for pkg, ver in deps.items():
                    clean_ver = re.sub(r"^[\^~>=<]", "", ver).strip()
                    if clean_ver and clean_ver[0].isdigit():
                        packages.append((pkg, clean_ver, "npm"))
        except Exception:
            pass
        return packages

    def _parse_composer_manifest(self, content: str, filename: str) -> List[Tuple[str, str, str]]:
        packages = []
        try:
            data = json.loads(content)
            if filename == "composer.lock":
                for pkg in data.get("packages", []):
                    name = pkg.get("name")
                    ver = pkg.get("version", "").lstrip("v")
                    if name and ver:
                        packages.append((name, ver, "Packagist"))
            else:
                reqs = data.get("require", {})
                for name, ver in reqs.items():
                    clean_ver = re.sub(r"^[\^~>=<]", "", ver).strip().lstrip("v")
                    if clean_ver and clean_ver[0].isdigit():
                        packages.append((name, clean_ver, "Packagist"))
        except Exception:
            pass
        return packages
