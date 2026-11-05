from http.cookies import SimpleCookie
from typing import List, Optional
import requests

from ciberpt.core.models import Finding, Severity
from ciberpt.modules.base import BaseScanner


class CookieScanner(BaseScanner):
    AUTH_COOKIE_PATTERNS = [
        "sess", "token", "auth", "jwt", "sid", "id", "login", "user", "csrf", "xsrf"
    ]

    @property
    def name(self) -> str:
        return "web.cookies"

    @property
    def description(self) -> str:
        return "Inspecao de atributos de seguranca em cookies HTTP (Secure, HttpOnly, SameSite)"

    def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Finding]:
        url = self._normalize_url(target)
        findings: List[Finding] = []

        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "ciberpt-audit-scanner/0.1.0"},
                allow_redirects=True,
            )
            # Analisar os cabecalhos brutos de Set-Cookie
            raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
            if not raw_cookies and "set-cookie" in resp.headers:
                raw_cookies = [resp.headers["set-cookie"]]

            for cookie_header in raw_cookies:
                findings.extend(self.audit_cookie_string(cookie_header, url.startswith("https://")))
        except requests.exceptions.RequestException:
            pass

        return findings

    def audit_cookie_string(self, cookie_str: str, is_https: bool) -> List[Finding]:
        findings: List[Finding] = []
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_str)
        except Exception:
            return findings

        for cookie_name, morsel in cookie.items():
            name_lower = cookie_name.lower()
            is_potential_auth = any(p in name_lower for p in self.AUTH_COOKIE_PATTERNS)

            # 1. Atributo Secure
            if is_https and not morsel["secure"]:
                findings.append(Finding(
                    id="SEC-COOKIE-MISSING-SECURE",
                    module=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Atributo 'Secure' ausente no cookie '{cookie_name}'",
                    description=f"O cookie '{cookie_name}' foi emitido em canal HTTPS sem o atributo 'Secure', permitindo a sua transmissao inadvertida em texto claro caso ocorra um pedido HTTP.",
                    remediation=f"Configurar a diretiva 'Secure' ao emitir o cookie '{cookie_name}'.",
                    evidence=cookie_str,
                ))

            # 2. Atributo HttpOnly
            if not morsel["httponly"] and is_potential_auth:
                findings.append(Finding(
                    id="SEC-COOKIE-MISSING-HTTPONLY",
                    module=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Atributo 'HttpOnly' ausente em cookie sensivel '{cookie_name}'",
                    description=f"O cookie '{cookie_name}' apresenta indicativos de controlo de sessao/autenticacao mas nao define 'HttpOnly', ficando acessivel via JavaScript (document.cookie) e vulneravel a roubo em ataques de XSS.",
                    remediation=f"Adicionar a flag 'HttpOnly' na definicao do cookie '{cookie_name}'.",
                    evidence=cookie_str,
                ))

            # 3. Atributo SameSite
            samesite = morsel["samesite"]
            if not samesite:
                findings.append(Finding(
                    id="SEC-COOKIE-MISSING-SAMESITE",
                    module=self.name,
                    severity=Severity.LOW,
                    title=f"Atributo 'SameSite' nao definido no cookie '{cookie_name}'",
                    description=f"A ausencia de 'SameSite' no cookie '{cookie_name}' delega o comportamento ao padrao do navegador, aumentando a exposicao a Cross-Site Request Forgery (CSRF).",
                    remediation=f"Definir 'SameSite=Lax' ou 'SameSite=Strict' no cookie '{cookie_name}'.",
                    evidence=cookie_str,
                ))
            else:
                samesite_lower = str(samesite).lower()
                if samesite_lower == "none" and not morsel["secure"]:
                    findings.append(Finding(
                        id="SEC-COOKIE-SAMESITE-NONE-INSECURE",
                        module=self.name,
                        severity=Severity.HIGH,
                        title=f"Inconsistencia critica no cookie '{cookie_name}': SameSite=None sem flag Secure",
                        description=f"A diretiva 'SameSite=None' exige obrigatoriamente a flag 'Secure'. Navegadores modernos rejeitarao este cookie.",
                        remediation=f"Adicionar o atributo 'Secure' ao cookie '{cookie_name}' sempre que 'SameSite=None' for utilizado.",
                        evidence=cookie_str,
                    ))

        return findings

    def _normalize_url(self, target: str) -> str:
        if not target.startswith("http://") and not target.startswith("https://"):
            return f"https://{target}"
        return target
