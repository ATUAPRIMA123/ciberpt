from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests

from ciberpt.core.models import Finding, Severity
from ciberpt.modules.base import BaseScanner


class DNSScanner(BaseScanner):
    DOH_ENDPOINT = "https://dns.google/resolve"

    @property
    def name(self) -> str:
        return "web.dns"

    @property
    def description(self) -> str:
        return "Auditoria defensiva de registos DNS de seguranca de e-mail (SPF, DMARC e MX)"

    def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Finding]:
        domain = self._extract_domain(target)
        findings: List[Finding] = []

        txt_records = self._query_dns(domain, "TXT", timeout=timeout)
        dmarc_records = self._query_dns(f"_dmarc.{domain}", "TXT", timeout=timeout)

        findings.extend(self.audit_spf(txt_records, domain))
        findings.extend(self.audit_dmarc(dmarc_records, domain))

        return findings

    def audit_spf(self, records: List[str], domain: str) -> List[Finding]:
        findings: List[Finding] = []
        spf_records = [r for r in records if r.strip('"').startswith("v=spf1")]

        if not spf_records:
            findings.append(Finding(
                id="SEC-DNS-SPF-MISSING",
                module=self.name,
                severity=Severity.MEDIUM,
                title="Registo SPF (Sender Policy Framework) ausente",
                description=f"O dominio {domain} nao possui registo SPF configurado no DNS, permitindo que servidores de e-mail nao autorizados emitam mensagens forjadas em nome deste dominio.",
                remediation="Adicionar um registo TXT para o dominio especificando servidores autorizados, ex: 'v=spf1 include:_spf.google.com ~all'.",
                evidence=None,
            ))
            return findings

        for spf in spf_records:
            cleaned = spf.strip('"').strip()
            if "+all" in cleaned:
                findings.append(Finding(
                    id="SEC-DNS-SPF-PERMISSIVE-ALL",
                    module=self.name,
                    severity=Severity.HIGH,
                    title="Registo SPF excessivamente permissivo (+all)",
                    description="A diretiva '+all' autoriza qualquer servidor na Internet a enviar e-mails em nome do dominio, anulando a protecao contra spoofing.",
                    remediation="Substituir '+all' por restricoes '~all' (SoftFail) ou '-all' (HardFail).",
                    evidence=cleaned,
                ))
            elif "?all" in cleaned:
                findings.append(Finding(
                    id="SEC-DNS-SPF-NEUTRAL-ALL",
                    module=self.name,
                    severity=Severity.LOW,
                    title="Registo SPF com politica neutra (?all)",
                    description="A diretiva '?all' nao impõe restricao nem reprovacao explicita a servidores nao autorizados.",
                    remediation="Evoluir a diretiva para '~all' ou '-all' apos validar os enderecos IP emissores.",
                    evidence=cleaned,
                ))

        return findings

    def audit_dmarc(self, records: List[str], domain: str) -> List[Finding]:
        findings: List[Finding] = []
        dmarc_records = [r for r in records if "v=DMARC1" in r.strip('"')]

        if not dmarc_records:
            findings.append(Finding(
                id="SEC-DNS-DMARC-MISSING",
                module=self.name,
                severity=Severity.MEDIUM,
                title="Registo DMARC ausente",
                description=f"O dominio _dmarc.{domain} nao possui registo DMARC. Sem DMARC, nao ha orientacao aos servidores de destino para rejeitar ou colocar em quarentena e-mails que falhem o SPF ou DKIM.",
                remediation="Adicionar registo TXT em '_dmarc." + domain + "' com politica minima de quarentena ou rejeicao, ex: 'v=DMARC1; p=reject; rua=mailto:dmarc@" + domain + "'.",
                evidence=None,
            ))
            return findings

        for dmarc in dmarc_records:
            cleaned = dmarc.strip('"').strip()
            if "p=none" in cleaned:
                findings.append(Finding(
                    id="SEC-DNS-DMARC-POLICY-NONE",
                    module=self.name,
                    severity=Severity.LOW,
                    title="Politica DMARC configurada apenas para monitorizacao (p=none)",
                    description="Com 'p=none', os servidores destinatarios nao bloqueiam e-mails fraudulentos, limitando-se a enviar relatorios.",
                    remediation="Apos o periodo de monitorizacao, atualizar a politica para 'p=quarantine' ou 'p=reject'.",
                    evidence=cleaned,
                ))

        return findings

    def _query_dns(self, name: str, record_type: str, timeout: int = 10) -> List[str]:
        try:
            params = {"name": name, "type": record_type}
            resp = requests.get(self.DOH_ENDPOINT, params=params, timeout=timeout)
            if resp.status_code != 200:
                return []
            data = resp.json()
            answers = data.get("Answer", [])
            results = []
            for ans in answers:
                data_field = ans.get("data", "")
                if data_field:
                    results.append(data_field)
            return results
        except Exception:
            return []

    def _extract_domain(self, target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
        else:
            host = target.split("/")[0].split(":")[0]
        return host
