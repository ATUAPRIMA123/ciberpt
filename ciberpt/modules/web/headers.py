from typing import Dict, List, Optional
import requests
from urllib.parse import urlparse

from ciberpt.core.models import Finding, Severity
from ciberpt.modules.base import BaseScanner


class HeaderScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "web.headers"

    @property
    def description(self) -> str:
        return "Auditoria de presenca e conformidade de cabecalhos de seguranca HTTP"

    def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Finding]:
        url = self._normalize_url(target)
        findings: List[Finding] = []

        try:
            session = requests.Session()
            session.headers.update({
                "User-Agent": "ciberpt-audit-scanner/0.1.0 (+https://github.com/ATUAPRIMA123/ciberpt)"
            })
            response = session.get(url, timeout=timeout, allow_redirects=True, verify=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            findings.extend(self.audit_headers(headers, url))
        except requests.exceptions.SSLError as e:
            findings.append(Finding(
                id="SEC-TLS-HANDSHAKE-FAILED",
                module=self.name,
                severity=Severity.HIGH,
                title="Falha na negociacao SSL/TLS durante requisicao HTTP",
                description=f"Nao foi possivel estabelecer sessao TLS segura: {str(e)}",
                remediation="Verificar a validade do certificado e a cadeia de confianca configurada no servidor web.",
                evidence=str(e),
            ))
        except requests.exceptions.RequestException as e:
            findings.append(Finding(
                id="SEC-NET-UNREACHABLE",
                module=self.name,
                severity=Severity.MEDIUM,
                title="Destino inacessivel durante auditoria de cabecalhos",
                description=f"Falha de ligacao de rede ao tentar aceder a {url}: {str(e)}",
                remediation="Assegurar conectividade de rede, resolucao de DNS e disponibilidade da porta 80/443.",
                evidence=str(e),
            ))

        return findings

    def audit_headers(self, headers: Dict[str, str], url: str) -> List[Finding]:
        findings: List[Finding] = []
        is_https = url.startswith("https://")

        # 1. Strict-Transport-Security (HSTS)
        if is_https:
            hsts = headers.get("strict-transport-security")
            if not hsts:
                findings.append(Finding(
                    id="SEC-HDR-HSTS-MISSING",
                    module=self.name,
                    severity=Severity.HIGH,
                    title="Cabecalho Strict-Transport-Security (HSTS) ausente",
                    description="A ausencia de HSTS permite ataques de rebaixamento de protocolo (SSL-stripping) e intercecao man-in-the-middle.",
                    remediation="Configurar o cabecalho 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                    evidence=None,
                ))
            else:
                if "max-age" in hsts:
                    try:
                        parts = [p.strip() for p in hsts.split(";")]
                        max_age_part = next((p for p in parts if p.startswith("max-age=")), None)
                        if max_age_part:
                            age = int(max_age_part.split("=")[1])
                            if age < 10886400:  # Menor que 126 dias
                                findings.append(Finding(
                                    id="SEC-HDR-HSTS-SHORT-MAXAGE",
                                    module=self.name,
                                    severity=Severity.LOW,
                                    title="Valor de max-age no HSTS inferior ao recomendado",
                                    description=f"O valor atual de max-age ({age} segundos) e inferior ao periodo minimo recomendado de 1 ano (31536000 segundos).",
                                    remediation="Aumentar max-age para 31536000 segundos no cabecalho HSTS.",
                                    evidence=hsts,
                                ))
                    except Exception:
                        pass

        # 2. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(Finding(
                id="SEC-HDR-CSP-MISSING",
                module=self.name,
                severity=Severity.HIGH,
                title="Cabecalho Content-Security-Policy (CSP) ausente",
                description="Sem politica de seguranca de conteudo definida, a aplicacao web fica suscetivel a ataques de Cross-Site Scripting (XSS) e injecao de dados.",
                remediation="Definir uma politica CSP restritiva iniciando por 'default-src \\'self\\' ; frame-ancestors \\'none\\''.",
                evidence=None,
            ))
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append(Finding(
                id="SEC-HDR-CSP-WEAK-DIRECTIVES",
                module=self.name,
                severity=Severity.MEDIUM,
                title="Diretivas frageis identificadas no Content-Security-Policy",
                description="O uso de 'unsafe-inline' ou 'unsafe-eval' atenua substancialmente as garantias de mitigacao de XSS proporcionadas pelo CSP.",
                remediation="Substituir scripts inline por nonces ou hashes criptograficos sha256.",
                evidence=csp,
            ))

        # 3. X-Frame-Options
        xfo = headers.get("x-frame-options")
        if not xfo and not (csp and "frame-ancestors" in csp):
            findings.append(Finding(
                id="SEC-HDR-XFO-MISSING",
                module=self.name,
                severity=Severity.MEDIUM,
                title="Cabecalho X-Frame-Options ausente",
                description="A ausencia de protecao de enquadramento permite a renderizacao em iframe malicioso, facilitando ataques de Clickjacking.",
                remediation="Adicionar 'X-Frame-Options: DENY' ou 'X-Frame-Options: SAMEORIGIN'.",
                evidence=None,
            ))

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append(Finding(
                id="SEC-HDR-XCTO-MISSING",
                module=self.name,
                severity=Severity.LOW,
                title="Cabecalho X-Content-Type-Options ausente ou inadequado",
                description="Sem a diretiva 'nosniff', navegadores podem inferir o MIME-type de respostas de modo divergente do especificado pelo servidor.",
                remediation="Definir 'X-Content-Type-Options: nosniff' nas respostas HTTP.",
                evidence=xcto,
            ))

        # 5. Referrer-Policy
        ref_pol = headers.get("referrer-policy")
        if not ref_pol:
            findings.append(Finding(
                id="SEC-HDR-REFERRER-MISSING",
                module=self.name,
                severity=Severity.LOW,
                title="Cabecalho Referrer-Policy ausente",
                description="A ausencia explicita de politica de Referrer pode expor caminhos internos de URLs ou tokens sensiveis em requisicoes para terceiros.",
                remediation="Adicionar 'Referrer-Policy: strict-origin-when-cross-origin'.",
                evidence=None,
            ))

        # 6. Permissions-Policy
        perm_pol = headers.get("permissions-policy")
        if not perm_pol:
            findings.append(Finding(
                id="SEC-HDR-PERMISSIONS-MISSING",
                module=self.name,
                severity=Severity.INFO,
                title="Cabecalho Permissions-Policy ausente",
                description="Permite que recursos sensiveis do navegador (camara, microfone, geolocalizacao) sejam requisitados sem restricao predefinida.",
                remediation="Definir 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
                evidence=None,
            ))

        # 7. Divulgacao de informacao de software (Server / X-Powered-By)
        server_header = headers.get("server")
        if server_header and any(char.isdigit() for char in server_header):
            findings.append(Finding(
                id="SEC-LEAK-SERVER-VERSION",
                module=self.name,
                severity=Severity.LOW,
                title="Divulgacao de versao de software no cabecalho Server",
                description=f"O servidor divulga versoes especificas do software ('{server_header}'), facilitando a deteccao de vulnerabilidades conhecidas por atacantes.",
                remediation="Ocultar ou ofuscar a assinatura da versao do servidor web.",
                evidence=server_header,
            ))

        x_powered = headers.get("x-powered-by")
        if x_powered:
            findings.append(Finding(
                id="SEC-LEAK-POWERED-BY",
                module=self.name,
                severity=Severity.LOW,
                title="Cabecalho de informacao tecnologica X-Powered-By exposto",
                description=f"A exposicao do cabecalho X-Powered-By ('{x_powered}') divulga a stack de desenvolvimento em uso.",
                remediation="Desativar a emissao de X-Powered-By na configuracao da aplicacao ou servidor reverso.",
                evidence=x_powered,
            ))

        return findings

    def _normalize_url(self, target: str) -> str:
        if not target.startswith("http://") and not target.startswith("https://"):
            return f"https://{target}"
        return target
