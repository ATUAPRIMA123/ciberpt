import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from ciberpt.core.models import Finding, Severity
from ciberpt.modules.base import BaseScanner


try:
    import certifi
    CAFILE = certifi.where()
except ImportError:
    CAFILE = None


class TLSScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "web.tls"

    @property
    def description(self) -> str:
        return "Inspecao de certificados X.509 e versao negociada de protocolo TLS"

    def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Finding]:
        hostname, port = self._parse_target(target)
        findings: List[Finding] = []

        context = ssl.create_default_context(cafile=CAFILE) if CAFILE else ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    findings.extend(self._audit_certificate(cert, hostname))
                    findings.extend(self._audit_tls_version(tls_version))
        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                id="SEC-TLS-CERT-INVALID",
                module=self.name,
                severity=Severity.CRITICAL,
                title="Certificado SSL/TLS invalido ou nao confiavel",
                description=f"O certificado apresentado por {hostname} falhou na verificacao de confianca: {str(e)}",
                remediation="Instalar um certificado emitido por autoridade certificadora (CA) publica valida.",
                evidence=str(e),
            ))
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            findings.append(Finding(
                id="SEC-TLS-CONN-FAILED",
                module=self.name,
                severity=Severity.MEDIUM,
                title="Incapaz de estabelecer ligacao de socket TLS",
                description=f"Nao foi possivel concluir o handshake TLS em {hostname}:{port} - {str(e)}",
                remediation="Assegurar que a porta TLS (443) esta aberta e acessivel no destino.",
                evidence=str(e),
            ))

        return findings

    def _audit_certificate(self, cert: dict, hostname: str) -> List[Finding]:
        findings: List[Finding] = []
        if not cert:
            return findings

        # Formato de data de validade no certificado: 'May 10 12:00:00 2026 GMT'
        not_after_str = cert.get("notAfter")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = not_after - now
                days_left = delta.days

                if days_left < 0:
                    findings.append(Finding(
                        id="SEC-TLS-CERT-EXPIRED",
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="Certificado SSL/TLS expirado",
                        description=f"O certificado para {hostname} expirou ha {abs(days_left)} dias (em {not_after_str}).",
                        remediation="Renovar o certificado SSL/TLS de imediato junto da Autoridade Certificadora.",
                        evidence={"not_after": not_after_str, "days_expired": abs(days_left)},
                    ))
                elif days_left < 15:
                    findings.append(Finding(
                        id="SEC-TLS-CERT-EXPIRING-SOON",
                        module=self.name,
                        severity=Severity.HIGH,
                        title="Certificado SSL/TLS proximo da data de expiracao",
                        description=f"O certificado expira em {days_left} dias (em {not_after_str}).",
                        remediation="Proceder a renovacao atempada do certificado para evitar indisponibilidade do servico.",
                        evidence={"not_after": not_after_str, "days_left": days_left},
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        id="SEC-TLS-CERT-EXPIRING-NOTICE",
                        module=self.name,
                        severity=Severity.LOW,
                        title="Aviso de expiracao de certificado SSL/TLS",
                        description=f"O certificado expira em {days_left} dias.",
                        remediation="Agendar processo de renovacao automatizada (ex: Let's Encrypt / Certbot).",
                        evidence={"not_after": not_after_str, "days_left": days_left},
                    ))
            except Exception:
                pass

        return findings

    def _audit_tls_version(self, tls_version: Optional[str]) -> List[Finding]:
        findings: List[Finding] = []
        if not tls_version:
            return findings

        obsolete_versions = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
        if tls_version in obsolete_versions:
            findings.append(Finding(
                id="SEC-TLS-OBSOLETE-PROTOCOL",
                module=self.name,
                severity=Severity.HIGH,
                title=f"Protocolo TLS obsoleto negociado: {tls_version}",
                description="Versoes de TLS inferiores a 1.2 possuem vulnerabilidades estruturais (ex: BEAST, POODLE) e sao descontinuadas por normas internacionais.",
                remediation="Desativar TLS 1.0 e TLS 1.1 na configuracao do servidor e impor suporte minimo a TLS 1.2 e TLS 1.3.",
                evidence=tls_version,
            ))

        return findings

    def _parse_target(self, target: str) -> tuple[str, int]:
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port or 443
        else:
            if ":" in target:
                parts = target.split(":")
                host = parts[0]
                port = int(parts[1])
            else:
                host = target
                port = 443
        return host, port
