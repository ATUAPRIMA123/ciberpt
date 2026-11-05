import html
from typing import Optional
from ciberpt import __version__
from ciberpt.core.models import ScanResult, Severity


class HTMLReporter:
    @classmethod
    def render(cls, result: ScanResult) -> str:
        score = result.score
        if score >= 80:
            score_color = "#10b981"  # Verde
            score_label = "Conforme / Risco Reduzido"
        elif score >= 50:
            score_color = "#f59e0b"  # Ambar
            score_label = "Atencao / Risco Moderado"
        else:
            score_color = "#ef4444"  # Vermelho
            score_label = "Critico / Postura Vulneravel"

        counts = {
            Severity.CRITICAL: sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
            Severity.HIGH: sum(1 for f in result.findings if f.severity == Severity.HIGH),
            Severity.MEDIUM: sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
            Severity.LOW: sum(1 for f in result.findings if f.severity == Severity.LOW),
            Severity.INFO: sum(1 for f in result.findings if f.severity == Severity.INFO),
        }

        severity_colors = {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#d97706",
            Severity.LOW: "#2563eb",
            Severity.INFO: "#4b5563",
        }

        findings_html = []
        if not result.findings:
            findings_html.append(
                """<div class="empty-state">
                    <h3>Nenhum achado de seguranca identificado</h3>
                    <p>O alvo analisado encontra-se em conformidade com as politicas avaliadas pelos modulos ativos.</p>
                </div>"""
            )
        else:
            for f in result.findings:
                sev_color = severity_colors.get(f.severity, "#4b5563")
                evidence_block = ""
                if f.evidence is not None:
                    evidence_str = html.escape(str(f.evidence))
                    evidence_block = f"""
                    <div class="evidence-block">
                        <strong>Evidencia Factual:</strong>
                        <pre><code>{evidence_str}</code></pre>
                    </div>
                    """

                remediation_block = ""
                if f.remediation:
                    rem_str = html.escape(f.remediation)
                    remediation_block = f"""
                    <div class="remediation-block">
                        <strong>Mitigacao Recomendada:</strong>
                        <p>{rem_str}</p>
                    </div>
                    """

                cve_badge = ""
                if f.cve_id:
                    cve_badge = f"""<span class="cve-tag">{html.escape(f.cve_id)}</span>"""

                cvss_badge = ""
                if f.cvss_score is not None:
                    cvss_badge = f"""<span class="cvss-tag">CVSS {f.cvss_score}</span>"""

                card = f"""
                <article class="finding-card" style="border-left-color: {sev_color};">
                    <div class="finding-header">
                        <span class="badge" style="background-color: {sev_color};">{f.severity.value}</span>
                        {cve_badge}
                        {cvss_badge}
                        <span class="module-tag">{html.escape(f.module)}</span>
                        <span class="finding-id">{html.escape(f.id)}</span>
                    </div>
                    <h3 class="finding-title">{html.escape(f.title)}</h3>
                    <p class="finding-desc">{html.escape(f.description)}</p>
                    {evidence_block}
                    {remediation_block}
                </article>
                """
                findings_html.append(card)

            findings_content = "\n".join(findings_html)

        html_template = f"""<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ciberpt - Relatorio de Auditoria: {html.escape(result.target)}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-family);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 1.5rem;
        }}
        .header-meta h1 {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
        }}
        .meta-line {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-bottom: 0.25rem;
        }}
        .score-box {{
            text-align: center;
            min-width: 180px;
            padding: 1rem 1.5rem;
            background: rgba(15, 23, 42, 0.6);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .score-value {{
            font-size: 3rem;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 0.25rem;
            color: {score_color};
        }}
        .score-label {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}
        .stat-num {{
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}
        .stat-label {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .finding-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left-width: 5px;
            border-radius: 6px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }}
        .finding-header {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.75rem;
        }}
        .badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 0.03em;
        }}
        .module-tag {{
            background: #334155;
            color: #cbd5e1;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
        }}
        .cve-tag {{
            background: #0284c7;
            color: #ffffff;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            font-family: monospace;
        }}
        .cvss-tag {{
            background: #7c3aed;
            color: #ffffff;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            font-family: monospace;
        }}
        .finding-id {{
            color: var(--text-secondary);
            font-size: 0.8rem;
            font-family: monospace;
        }}
        .finding-title {{
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}
        .finding-desc {{
            color: #cbd5e1;
            font-size: 0.95rem;
            margin-bottom: 1rem;
        }}
        .evidence-block, .remediation-block {{
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid #334155;
            border-radius: 4px;
            padding: 0.75rem 1rem;
            margin-top: 0.75rem;
            font-size: 0.9rem;
        }}
        .evidence-block strong, .remediation-block strong {{
            display: block;
            margin-bottom: 0.25rem;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-secondary);
        }}
        pre {{
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.85rem;
            color: #e2e8f0;
            margin-top: 0.25rem;
        }}
        .empty-state {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 3rem;
            text-align: center;
        }}
        footer {{
            margin-top: 3rem;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.8rem;
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-meta">
                <h1>ciberpt - Relatorio de Auditoria</h1>
                <div class="meta-line"><strong>Alvo:</strong> {html.escape(result.target)}</div>
                <div class="meta-line"><strong>Data/Hora de Auditoria:</strong> {html.escape(result.timestamp)}</div>
                <div class="meta-line"><strong>ID da Sessao:</strong> {html.escape(result.scan_id)}</div>
            </div>
            <div class="score-box">
                <div class="score-value">{score}</div>
                <div class="score-label">{score_label}</div>
            </div>
        </header>

        <section class="summary-grid">
            <div class="stat-card" style="border-top: 3px solid #dc2626;">
                <div class="stat-num" style="color: #dc2626;">{counts[Severity.CRITICAL]}</div>
                <div class="stat-label">Critico</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #ea580c;">
                <div class="stat-num" style="color: #ea580c;">{counts[Severity.HIGH]}</div>
                <div class="stat-label">Alto</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #d97706;">
                <div class="stat-num" style="color: #d97706;">{counts[Severity.MEDIUM]}</div>
                <div class="stat-label">Medio</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #2563eb;">
                <div class="stat-num" style="color: #2563eb;">{counts[Severity.LOW]}</div>
                <div class="stat-label">Baixo</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #4b5563;">
                <div class="stat-num" style="color: #94a3b8;">{counts[Severity.INFO]}</div>
                <div class="stat-label">Informativo</div>
            </div>
        </section>

        <section>
            <div class="section-title">
                <h2>Achados Identificados</h2>
                <span>Total: {len(result.findings)}</span>
            </div>
            {findings_content}
        </section>

        <footer>
            Gerado automaticamente por ciberpt v{__version__} - Ferramenta modular de auditoria e seguranca defensiva.
        </footer>
    </div>
</body>
</html>
"""
        return html_template

    @classmethod
    def save(cls, result: ScanResult, filepath: str) -> None:
        content = cls.render(result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
