from typing import List, Optional
from urllib.parse import urlparse
import requests

from ciberpt.core.models import Finding, Severity
from ciberpt.modules.base import BaseScanner


class CORSScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "web.cors"

    @property
    def description(self) -> str:
        return "Auditoria defensiva de configuracoes de Cross-Origin Resource Sharing (CORS)"

    def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Finding]:
        url = self._normalize_url(target)
        findings: List[Finding] = []

        findings.extend(self._test_origin_reflection(url, "https://ciberpt-audit-origin.test", timeout))
        findings.extend(self._test_null_origin(url, timeout))

        return findings

    def _test_origin_reflection(self, url: str, test_origin: str, timeout: int) -> List[Finding]:
        findings: List[Finding] = []
        headers = {
            "Origin": test_origin,
            "User-Agent": "ciberpt-audit-scanner/0.1.0",
        }

        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            acao = resp.headers.get("access-control-allow-origin")
            acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            if not acao:
                return findings

            if acao == "*":
                if acac:
                    findings.append(Finding(
                        id="SEC-CORS-WILDCARD-WITH-CREDS",
                        module=self.name,
                        severity=Severity.HIGH,
                        title="Configuracao CORS invalida e insegura: Wildcard com Credenciais",
                        description="O servidor combina 'Access-Control-Allow-Origin: *' com 'Access-Control-Allow-Credentials: true'. Esta combinacao e rejeitada por navegadores e indica erro critico de politica de seguranca.",
                        remediation="Definir uma lista explicita de origens permitidas (whitelist) em vez de wildcard.",
                        evidence={"acao": acao, "acac": acac},
                    ))
            elif acao == test_origin:
                if acac:
                    findings.append(Finding(
                        id="SEC-CORS-ARBITRARY-ORIGIN-WITH-CREDS",
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="Vulnerabilidade de CORS: Reflexao de origem arbitraria com credenciais",
                        description=f"O servidor reflete cegamente qualquer origem recebida no cabecalho Origin ('{test_origin}') e autoriza credenciais de sessao ('Access-Control-Allow-Credentials: true'). Isto permite a qualquer site malicioso extrair dados autenticados do utilizador.",
                        remediation="Restringir as origens autorizadas exclusivamente a dominios e subdominios confiaveis.",
                        evidence={"origin_tested": test_origin, "reflected_acao": acao, "credentials_allowed": acac},
                    ))
                else:
                    findings.append(Finding(
                        id="SEC-CORS-ARBITRARY-ORIGIN-NO-CREDS",
                        module=self.name,
                        severity=Severity.LOW,
                        title="Reflexao de origem arbitraria no cabecalho CORS",
                        description=f"O servidor reflete a origem arbitraria '{test_origin}' no cabecalho Access-Control-Allow-Origin, embora sem partilha de credenciais.",
                        remediation="Validar a origem contra uma lista restrita de clientes autorizados.",
                        evidence=acao,
                    ))
        except requests.exceptions.RequestException:
            pass

        return findings

    def _test_null_origin(self, url: str, timeout: int) -> List[Finding]:
        findings: List[Finding] = []
        headers = {
            "Origin": "null",
            "User-Agent": "ciberpt-audit-scanner/0.1.0",
        }

        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            acao = resp.headers.get("access-control-allow-origin")
            acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            if acao == "null":
                if acac:
                    findings.append(Finding(
                        id="SEC-CORS-NULL-ORIGIN-WITH-CREDS",
                        module=self.name,
                        severity=Severity.HIGH,
                        title="Aceitacao da origem 'null' com credenciais no CORS",
                        description="O servidor autoriza a origem 'null' juntamente com credenciais. Atacantes podem forjar pedidos a partir de sandboxed iframes para burlar restricoes de mesma origem.",
                        remediation="Remover 'null' da lista de origens autorizadas.",
                        evidence={"acao": acao, "acac": acac},
                    ))
                else:
                    findings.append(Finding(
                        id="SEC-CORS-NULL-ORIGIN-ALLOWED",
                        module=self.name,
                        severity=Severity.MEDIUM,
                        title="Aceitacao da origem 'null' no cabecalho CORS",
                        description="O servidor autoriza a origem 'null' em Access-Control-Allow-Origin.",
                        remediation="Evitar a utilizacao de 'null' como valor valido no CORS.",
                        evidence=acao,
                    ))
        except requests.exceptions.RequestException:
            pass

        return findings

    def _normalize_url(self, target: str) -> str:
        if not target.startswith("http://") and not target.startswith("https://"):
            return f"https://{target}"
        return target
