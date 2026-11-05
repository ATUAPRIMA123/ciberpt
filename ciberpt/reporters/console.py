from typing import Optional
from ciberpt.core.models import ScanResult, Severity

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class ConsoleReporter:
    SEVERITY_COLORS = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim white",
    }

    @classmethod
    def render(cls, result: ScanResult, min_severity: Optional[Severity] = None) -> None:
        min_rank = min_severity.rank if min_severity else 0
        filtered_findings = [f for f in result.findings if f.severity.rank >= min_rank]

        if HAS_RICH:
            cls._render_rich(result, filtered_findings)
        else:
            cls._render_plain(result, filtered_findings)

    @classmethod
    def _render_rich(cls, result: ScanResult, findings: list) -> None:
        console = Console()

        score_color = "green" if result.score >= 80 else ("yellow" if result.score >= 50 else "red")
        header_text = (
            f"[bold]Alvo:[/bold] {result.target}\n"
            f"[bold]Data/Hora:[/bold] {result.timestamp}\n"
            f"[bold]Indice de Postura (Security Score):[/bold] [{score_color}]{result.score}/100[/{score_color}]\n"
            f"[bold]Total de Achados:[/bold] {len(result.findings)} (Exibidos: {len(findings)})"
        )
        console.print(Panel(header_text, title="ciberpt - Relatorio de Auditoria", expand=False))

        if not findings:
            console.print("[green]Nenhuma conformidade violada para os filtros selecionados.[/green]")
            return

        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=box.ASCII,
        )
        table.add_column("Severidade", style="bold", width=12, no_wrap=True)
        table.add_column("Modulo", width=14, no_wrap=True)
        table.add_column("Identificador / Titulo", min_width=25)
        table.add_column("Mitigacao Recomendada", min_width=35)

        for f in findings:
            color = cls.SEVERITY_COLORS.get(f.severity, "white")
            sev_text = f"[{color}]{f.severity.value}[/{color}]"
            title_text = f"[bold]{f.id}[/bold]\n{f.title}"
            table.add_row(sev_text, f.module, title_text, f.remediation)

        console.print(table)

    @classmethod
    def _render_plain(cls, result: ScanResult, findings: list) -> None:
        print("=" * 70)
        print("ciberpt - Relatorio de Auditoria")
        print(f"Alvo: {result.target}")
        print(f"Data/Hora: {result.timestamp}")
        print(f"Indice de Postura: {result.score}/100")
        print(f"Total de Achados: {len(result.findings)} (Exibidos: {len(findings)})")
        print("=" * 70)

        for f in findings:
            print(f"[{f.severity.value}] [{f.module}] {f.id} - {f.title}")
            print(f"  Descricao: {f.description}")
            print(f"  Mitigacao: {f.remediation}")
            if f.evidence:
                print(f"  Evidencia: {f.evidence}")
            print("-" * 70)
